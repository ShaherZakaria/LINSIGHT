# -*- coding: utf-8 -*-
"""The btrfs reader.

openSUSE and Fedora put root on btrfs, so a workstation image is a normal
thing to be handed. It is the most involved of the three readers here, for a
reason worth stating: btrfs has no fixed layout. Every structure lives at a
logical address that only the chunk tree can turn into a physical one, so
before a single inode can be read the chunk tree has to be bootstrapped out of
an array in the superblock and then read through itself.

After that it is one shape repeated. Everything is a B-tree of the same node
format, keyed by (objectid, type, offset), and a filesystem is:

    chunk tree     logical address -> physical offset
    root tree      which tree holds what, and where each subvolume hangs
    fs tree        one per subvolume: inodes, directory entries, extents

Subvolumes matter here in a way they do not on ext or XFS. On openSUSE the
root filesystem is a subvolume and /var, /home, /srv and the rest are separate
ones, so a reader that walks only the top-level tree returns a handful of
names and an empty /var - which reads as a host with no logs at all. Every
subvolume the tree above it names is therefore walked, at the path it names.

Lookups descend by key rather than scanning. That is not an optimisation
detail: a walk of a million-file filesystem does a million inode lookups, and
scanning the tree for each of them is the difference between a minute and a
week.
"""

from __future__ import annotations

import io
import struct
import zlib

from .fsbase import (
    ExtentFile, Filesystem, FsNode, KIND_BY_MODE, S_IFMT, utc)

BTRFS_MAGIC = b"_BHRfS_M"
SUPER_OFFSETS = (0x10000, 0x4000000, 0x4000000000)

# key types
INODE_ITEM = 1
INODE_REF = 12
XATTR_ITEM = 24
DIR_ITEM = 84
DIR_INDEX = 96
EXTENT_DATA = 108
ROOT_ITEM = 132
ROOT_REF = 156
CHUNK_ITEM = 228

# well-known object ids
ROOT_TREE = 1
EXTENT_TREE = 2
CHUNK_TREE = 3
DEV_TREE = 4
FS_TREE = 5
FIRST_FREE = 256

# EXTENT_DATA types
EXTENT_INLINE = 0
EXTENT_REGULAR = 1
EXTENT_PREALLOC = 2

COMPRESS_NONE = 0
COMPRESS_ZLIB = 1
COMPRESS_LZO = 2
COMPRESS_ZSTD = 3
COMP_NAMES = {COMPRESS_ZLIB: "zlib", COMPRESS_LZO: "lzo", COMPRESS_ZSTD: "zstd"}

# block group flags: which of these mean the data is interleaved across
# devices, and therefore cannot be read from one image
BG_RAID0 = 1 << 3
BG_RAID1 = 1 << 4
BG_DUP = 1 << 5
BG_RAID10 = 1 << 6
BG_RAID5 = 1 << 7
BG_RAID6 = 1 << 8
BG_STRIPED = BG_RAID0 | BG_RAID10 | BG_RAID5 | BG_RAID6

KIND_BY_DIRTYPE = {1: "f", 2: "d", 3: "c", 4: "b", 5: "p", 6: "s", 7: "l"}

# btrfs_header: csum(32) fsid(16) bytenr(8) flags(8) chunk_uuid(16)
#               generation(8) owner(8) nritems(4) level(1)
NODE_HEADER = 101
KEY_SIZE = 17
ITEM_SIZE = 25        # key(17) data offset(4) data size(4)
KEY_PTR = 33          # key(17) blockptr(8) generation(8)

MAX_KEY = (0xFFFFFFFFFFFFFFFF, 0xFF, 0xFFFFFFFFFFFFFFFF)


class BtrfsError(Exception):
    pass


class BtrfsFilesystem(Filesystem):
    """A btrfs filesystem on a volume."""

    kind = "btrfs"

    def __init__(self, volume):
        Filesystem.__init__(self, volume)
        sb = self._read_super(volume)
        self._sb = sb
        self.uuid = _bt_uuid(sb[0x20:0x30])
        self.generation = _bt_u64(sb, 0x48)
        self.root_tree_addr = _bt_u64(sb, 0x50)
        self.chunk_root_addr = _bt_u64(sb, 0x58)
        self.total_bytes = _bt_u64(sb, 0x70)
        self.sector_size = _bt_u32(sb, 0x90)
        self.node_size = _bt_u32(sb, 0x94)
        sys_chunk_size = _bt_u32(sb, 0xA0)
        self.incompat = _bt_u64(sb, 0xBC)
        self.label = sb[0x12B:0x12B + 256].split(b"\x00", 1)[0].decode(
            "utf-8", "replace")
        self.block_size = self.node_size
        self.size = self.total_bytes
        if not (512 <= self.node_size <= 262144):
            raise BtrfsError("implausible btrfs node size %d" % self.node_size)

        # Nothing at all can be read before the chunk tree: every other
        # address on this filesystem is logical. The superblock carries just
        # enough of it, in an array, to find the rest.
        self._chunks = []
        self._node_cache = {}
        self._read_sys_chunks(sb[0x32B:0x32B + min(sys_chunk_size, 2048)])
        if not self._chunks:
            raise BtrfsError("the btrfs system chunk array is empty")
        self._read_chunk_tree()

        self.roots = {}                 # subvolume id -> tree root address
        self._root_refs = {}            # subvolume id -> (parent, dirid, name)
        self._read_root_tree()
        if FS_TREE not in self.roots:
            raise BtrfsError("no FS tree in the btrfs root tree")
        self._inode_cache = {}
        self.subvolumes = self._subvolume_paths()
        if len(self.subvolumes) > 1:
            self.notes.append(
                "%d subvolume(s) besides the top level; each is walked at the "
                "path the tree above it gives"% (len(self.subvolumes) - 1))
        root = self.root_node()
        if root is not None:
            self.last_write = root.mtime
            self.created = root.crtime

    # -- superblock ---------------------------------------------------------
    @staticmethod
    def _read_super(volume):
        """The newest valid superblock of the copies btrfs keeps.

        There are up to three, and a filesystem interrupted mid-commit can
        hold one older than another. Taking the first that parses can mean
        reading trees that have since moved, so the highest generation wins.
        """
        best = None
        for offset in SUPER_OFFSETS:
            if volume.size and offset + 4096 > volume.size:
                continue
            raw = volume.read(offset, 4096)
            if len(raw) < 4096 or raw[0x40:0x48] != BTRFS_MAGIC:
                continue
            generation = _bt_u64(raw, 0x48)
            if best is None or generation > best[0]:
                best = (generation, raw)
        if best is None:
            raise BtrfsError("no btrfs superblock")
        return best[1]

    # -- the chunk tree: logical -> physical --------------------------------
    def _read_sys_chunks(self, blob):
        at = 0
        while at + KEY_SIZE + 48 <= len(blob):
            _objectid, ktype, offset = _bt_key(blob, at)
            at += KEY_SIZE
            if ktype != CHUNK_ITEM:
                break
            used = self._add_chunk(offset, blob, at)
            if used <= 0:
                break
            at += used

    def _add_chunk(self, logical, blob, at):
        """One chunk item: a logical run, and the stripes holding it."""
        if at + 48 > len(blob):
            return 0
        length = _bt_u64(blob, at)
        stripe_len = _bt_u64(blob, at + 16)
        stype = _bt_u64(blob, at + 24)
        num_stripes = _bt_u16(blob, at + 44)
        if not num_stripes or num_stripes > 128:
            return 0
        if at + 48 + num_stripes * 32 > len(blob):
            return 0
        stripes = [(_bt_u64(blob, at + 48 + i * 32),
                    _bt_u64(blob, at + 48 + i * 32 + 8))
                   for i in range(num_stripes)]
        if length:
            self._chunks.append((logical, length, stripe_len, stype, stripes))
            self._chunks.sort()
        return 48 + num_stripes * 32

    def _read_chunk_tree(self):
        for key, blob in self._range(self.chunk_root_addr,
                                     (0, CHUNK_ITEM, 0), MAX_KEY):
            if key[1] == CHUNK_ITEM:
                self._add_chunk(key[2], blob, 0)

    def logical_to_physical(self, logical):
        """(offset on this volume, bytes readable there) for a logical address.

        RAID1 and DUP write the same bytes to every stripe, so the first
        stripe is a complete copy and is read. RAID0, RAID10, RAID5 and RAID6
        interleave, and reading the first stripe of one returns real bytes
        from the wrong offsets - which is worse than an error, so it is one.
        """
        lo, hi = 0, len(self._chunks)
        while lo < hi:
            mid = (lo + hi) // 2
            if self._chunks[mid][0] <= logical:
                lo = mid + 1
            else:
                hi = mid
        if not lo:
            return None, 0
        start, length, _stripe_len, stype, stripes = self._chunks[lo - 1]
        if not (start <= logical < start + length):
            return None, 0
        if stype & BG_STRIPED and len(stripes) > 1:
            _bt_note(self, "part of this filesystem is on a striped (RAID0/10/5/6) "
                        "chunk spanning %d devices; it cannot be read from one "
                        "image and is returned as zeroes" % len(stripes))
            return None, 0
        within = logical - start
        return stripes[0][1] + within, length - within

    def read_logical(self, logical, length):
        out = bytearray()
        while len(out) < length:
            phys, room = self.logical_to_physical(logical + len(out))
            if phys is None or room <= 0:
                out += b"\x00" * (length - len(out))
                break
            take = min(length - len(out), room)
            out += self.volume.read(phys, take)
        return bytes(out)

    # -- B-trees ------------------------------------------------------------
    def _node(self, addr):
        cached = self._node_cache.get(addr)
        if cached is not None:
            return cached
        raw = self.read_logical(addr, self.node_size)
        if len(self._node_cache) < 8192:
            self._node_cache[addr] = raw
        return raw

    def _range(self, root_addr, lo_key, hi_key):
        """Yield (key, data) for every item with lo_key <= key <= hi_key.

        A descent, not a scan: at an interior node only the children whose key
        span can overlap the wanted range are followed. Every lookup in this
        reader goes through here, which is what keeps a walk linear in the
        number of files rather than quadratic.
        """
        if not root_addr:
            return
        stack = [root_addr]
        seen = set()
        while stack:
            addr = stack.pop()
            if addr in seen:
                continue
            if len(seen) > (1 << 21):
                self.errors += 1
                return
            seen.add(addr)
            node = self._node(addr)
            if len(node) < NODE_HEADER or len(node) < self.node_size:
                self.errors += 1
                continue
            nritems = _bt_u32(node, 96)
            level = node[100]
            if level:
                if nritems > (len(node) - NODE_HEADER) // KEY_PTR:
                    self.errors += 1
                    continue
                keys = [_bt_key(node, NODE_HEADER + i * KEY_PTR)
                        for i in range(nritems)]
                # follow child i when [keys[i], keys[i+1]) can hold the range
                for i in range(nritems - 1, -1, -1):
                    if keys[i] > hi_key:
                        continue
                    if i + 1 < nritems and keys[i + 1] <= lo_key:
                        continue
                    stack.append(_bt_u64(node, NODE_HEADER + i * KEY_PTR + KEY_SIZE))
                continue
            if nritems > (len(node) - NODE_HEADER) // ITEM_SIZE:
                self.errors += 1
                continue
            for i in range(nritems):
                at = NODE_HEADER + i * ITEM_SIZE
                key = _bt_key(node, at)
                if key < lo_key:
                    continue
                if key > hi_key:
                    break
                data_off = _bt_u32(node, at + KEY_SIZE)
                data_len = _bt_u32(node, at + KEY_SIZE + 4)
                start = NODE_HEADER + data_off
                if start + data_len > len(node):
                    self.errors += 1
                    continue
                yield key, node[start:start + data_len]

    def _items(self, root_addr, objectid, ktype):
        """Every item of one type belonging to one object."""
        return self._range(root_addr, (objectid, ktype, 0),
                           (objectid, ktype, 0xFFFFFFFFFFFFFFFF))

    # -- the root tree ------------------------------------------------------
    def _read_root_tree(self):
        for key, blob in self._range(self.root_tree_addr, (0, 0, 0), MAX_KEY):
            objectid, ktype, offset = key
            if ktype == ROOT_ITEM and len(blob) >= 184:
                # a root item begins with an inode item; the tree's own block
                # pointer is the field after it
                self.roots.setdefault(objectid, _bt_u64(blob, 176))
            elif ktype == ROOT_REF and len(blob) >= 18:
                namelen = _bt_u16(blob, 16)
                name = blob[18:18 + namelen].decode("utf-8", "surrogateescape")
                self._root_refs[offset] = (objectid, _bt_u64(blob, 0), name)

    def _subvolume_paths(self):
        """subvolume id -> the path it is mounted at, for the reachable ones.

        A subvolume is named by a directory entry in its parent, so the path
        is the parent's path plus that name, resolved up to the FS tree. This
        is what puts openSUSE's /var where the host had it instead of at the
        top of the tree.
        """
        out = {FS_TREE: ""}
        pending = [s for s in sorted(self.roots) if s >= FIRST_FREE]
        for _round in range(64):
            progressed = False
            for subvol in list(pending):
                ref = self._root_refs.get(subvol)
                if ref is None:
                    continue
                parent, dirid, name = ref
                if parent not in out:
                    continue
                base = out[parent]
                inner = self._inode_path(self.roots.get(parent), dirid)
                path = (base + inner).rstrip("/") + "/" + name
                out[subvol] = path
                pending.remove(subvol)
                progressed = True
            if not progressed:
                break
        return out

    def _inode_path(self, root_addr, ino):
        """The path of a directory inode within its own subvolume."""
        if not root_addr or ino in (0, FIRST_FREE):
            return ""
        parts = []
        cur = ino
        for _ in range(64):
            if cur == FIRST_FREE:
                break
            found = None
            for key, blob in self._items(root_addr, cur, INODE_REF):
                if len(blob) >= 10:
                    namelen = _bt_u16(blob, 8)
                    found = (key[2], blob[10:10 + namelen].decode(
                        "utf-8", "surrogateescape"))
                break
            if not found:
                return ""
            parts.append(found[1])
            cur = found[0]
        return ("/" + "/".join(reversed(parts))) if parts else ""

    # -- inodes -------------------------------------------------------------
    def _inode_item(self, root, ino):
        cached = self._inode_cache.get((root, ino))
        if cached is not None:
            return cached
        for _key_tuple, blob in self._items(root, ino, INODE_ITEM):
            if len(self._inode_cache) < 65536:
                self._inode_cache[(root, ino)] = blob
            return blob
        return b""

    def node_at(self, ref, path, hint=""):
        """`ref` is (tree root address, inode number)."""
        root, ino = ref
        blob = self._inode_item(root, ino)
        if len(blob) < 160:
            return None
        mode = _bt_u32(blob, 0x34)
        kind = KIND_BY_MODE.get(mode & S_IFMT, hint or "f")
        node = FsNode(
            path=path, inode=ino, kind=kind, size=_bt_u64(blob, 0x10), mode=mode,
            uid=_bt_u32(blob, 0x2C), gid=_bt_u32(blob, 0x30),
            nlink=_bt_u32(blob, 0x28),
            atime=_bt_time(blob, 0x70), ctime=_bt_time(blob, 0x7C),
            mtime=_bt_time(blob, 0x88), crtime=_bt_time(blob, 0x94),
            fs=self, ref=(root, ino))
        if kind == "l":
            node.target = self.read(node).decode("utf-8", "replace")
        return node

    def root_node(self):
        return self.node_at((self.roots[FS_TREE], FIRST_FREE), "", "d")

    # -- file content -------------------------------------------------------
    def _extents(self, node):
        cached = node._map_cache
        if cached is not None:
            return cached
        root, ino = node._ref
        out = []
        for key, blob in self._items(root, ino, EXTENT_DATA):
            if len(blob) < 21:
                continue
            offset = key[2]
            ram_bytes = _bt_u64(blob, 8)
            compression = blob[16]
            etype = blob[20]
            if etype == EXTENT_INLINE:
                out.append((offset, None, blob[21:], compression, ram_bytes))
            elif len(blob) >= 53:
                out.append((offset,
                            (_bt_u64(blob, 21), _bt_u64(blob, 29), _bt_u64(blob, 37),
                             _bt_u64(blob, 45)),
                            None, compression, ram_bytes))
        out.sort(key=lambda e: e[0])
        node._map_cache = out
        return out

    def read(self, node, limit=None):
        size = node.size if limit is None else min(node.size, limit)
        return self._fetch(node, 0, size) if size > 0 else b""

    def _fetch(self, node, offset, length):
        """`length` bytes at `offset`; a hole, or an unmapped extent, is zero."""
        length = min(length, max(0, node.size - offset))
        if length <= 0:
            return b""
        out = bytearray(length)
        end = offset + length
        for start, regular, inline, compression, ram in self._extents(node):
            if regular is None:
                data = _bt_decompress(inline, compression, ram, self)
                span = len(data)
                if start >= end or start + span <= offset:
                    continue
                lo = max(offset, start)
                hi = min(end, start + span)
                out[lo - offset:hi - offset] = data[lo - start:hi - start]
                continue
            disk_bytenr, disk_num, extent_offset, num_bytes = regular
            if start >= end or start + num_bytes <= offset:
                continue
            if not disk_bytenr:                    # a hole
                continue
            lo = max(offset, start)
            hi = min(end, start + num_bytes)
            if compression:
                raw = self.read_logical(disk_bytenr, disk_num)
                whole = _bt_decompress(raw, compression, ram, self)
                piece = whole[extent_offset + (lo - start):
                              extent_offset + (hi - start)]
            else:
                piece = self.read_logical(
                    disk_bytenr + extent_offset + (lo - start), hi - lo)
            out[lo - offset:lo - offset + len(piece)] = piece
        return bytes(out)

    def open(self, node):
        return ExtentFile(lambda o, n: self._fetch(node, o, n), node.size)

    # -- directories --------------------------------------------------------
    def dir_entries(self, node):
        root, ino = node._ref
        out = []
        for _key_tuple, blob in self._items(root, ino, DIR_ITEM):
            at = 0
            # one DIR_ITEM key can carry several entries: names that hash to
            # the same value share a key and are stored end to end
            while at + 30 <= len(blob):
                child_id, child_type, _child_off = _bt_key(blob, at)
                data_len = _bt_u16(blob, at + 25)
                name_len = _bt_u16(blob, at + 27)
                dtype = blob[at + 29]
                name_at = at + 30
                if name_len == 0 or name_at + name_len > len(blob):
                    break
                name = blob[name_at:name_at + name_len].decode(
                    "utf-8", "surrogateescape")
                if child_type == ROOT_ITEM:
                    sub = self.roots.get(child_id)
                    if sub:
                        out.append((name, (sub, FIRST_FREE), "d"))
                elif child_type == INODE_ITEM and name not in (".", ".."):
                    out.append((name, (root, child_id),
                                KIND_BY_DIRTYPE.get(dtype, "")))
                at = name_at + name_len + data_len
        return out

    # -- the walk -----------------------------------------------------------
    def walk(self, max_nodes=0, on_error=None):
        root = self.root_node()
        if root is None:
            raise BtrfsError("the btrfs FS tree root inode is unreadable")
        stack = [(root, "")]
        seen = {root._ref}
        count = 0
        while stack:
            node, prefix = stack.pop()
            try:
                entries = self.dir_entries(node)
            except Exception as exc:
                self.errors += 1
                if on_error:
                    on_error(prefix or "/", exc)
                continue
            for name, ref, hint in sorted(entries, key=lambda e: e[0],
                                          reverse=True):
                path = prefix + "/" + name
                child = self.node_at(ref, path, hint)
                if child is None:
                    self.errors += 1
                    continue
                yield child
                count += 1
                if max_nodes and count >= max_nodes:
                    return
                if child.is_dir and ref not in seen:
                    seen.add(ref)
                    stack.append((child, path))

    def describe(self):
        bits = ["btrfs"]
        if self.label:
            bits.append("'%s'" % self.label)
        bits.append("%d-byte nodes" % self.node_size)
        if len(self.subvolumes) > 1:
            bits.append("%d subvolume(s)" % (len(self.subvolumes) - 1))
        if self.uuid:
            bits.append(self.uuid)
        return ", ".join(bits)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _bt_u16(b, o=0):
    return struct.unpack_from("<H", b, o)[0]


def _bt_u32(b, o=0):
    return struct.unpack_from("<I", b, o)[0]


def _bt_u64(b, o=0):
    return struct.unpack_from("<Q", b, o)[0]


def _bt_key(b, o=0):
    """A btrfs key: objectid (u64), type (u8), offset (u64)."""
    return (_bt_u64(b, o), b[o + 8], _bt_u64(b, o + 9))


def _bt_time(blob, at):
    """A btrfs timespec: seconds (signed 64) then nanoseconds (u32)."""
    if len(blob) < at + 12:
        return None
    return utc(struct.unpack_from("<q", blob, at)[0], _bt_u32(blob, at + 8))


def _bt_uuid(raw):
    if len(raw) != 16 or raw == b"\x00" * 16:
        return ""
    h = raw.hex()
    return "%s-%s-%s-%s-%s" % (h[0:8], h[8:12], h[12:16], h[16:20], h[20:32])


def _bt_note(fs, text):
    if text not in fs.notes:
        fs.notes.append(text)


def _bt_decompress(raw, compression, expected, fs):
    """Undo whatever the extent was compressed with.

    A file that cannot be decompressed is not quietly returned as zeroes: a
    note goes on the filesystem, so the report says "this needs an lzo
    decompressor" rather than showing an empty /etc/passwd.
    """
    if compression == COMPRESS_NONE:
        return raw
    try:
        if compression == COMPRESS_ZLIB:
            return zlib.decompress(raw)
        if compression == COMPRESS_ZSTD:
            return _bt_zstd(raw)
        if compression == COMPRESS_LZO:
            return _lzo_extent(raw, expected)
    except Exception as exc:
        _bt_note(fs, "an extent compressed with %s could not be decompressed (%s)"
                  % (COMP_NAMES.get(compression, compression), exc))
        return b"\x00" * (expected or len(raw))
    _bt_note(fs, "btrfs compression type %d is not implemented" % compression)
    return b"\x00" * (expected or len(raw))


def _bt_zstd(raw):
    try:
        from compression import zstd                # Python 3.14+
        return zstd.decompress(raw)
    except ImportError:
        pass
    try:
        import zstandard
        return zstandard.ZstdDecompressor().decompressobj().decompress(raw)
    except ImportError:
        raise RuntimeError("no zstd decompressor is available - Python 3.14 "
                           "has one in the standard library, or install "
                           "'zstandard'")


def _lzo_extent(raw, expected):
    """btrfs lzo framing: a total length, then one compressed page per segment."""
    if len(raw) < 4:
        raise ValueError("short lzo extent")
    total = _bt_u32(raw, 0)
    out = bytearray()
    at = 4
    limit = min(total or len(raw), len(raw))
    while at + 4 <= limit:
        seg_len = _bt_u32(raw, at)
        at += 4
        if seg_len == 0 or at + seg_len > len(raw):
            break
        out += lzo1x_decompress(raw[at:at + seg_len])
        at += seg_len
        # a segment header never straddles a page boundary within the extent
        if (at % 4096) + 4 > 4096:
            at = (at + 4095) & ~4095
    return bytes(out[:expected]) if expected else bytes(out)


def lzo1x_decompress(src):
    """LZO1X block decompression - the variant btrfs and the kernel use.

    Written out rather than depended on, because the evidence workstation that
    needs it is the one that cannot install a package. The control flow
    follows the reference decoder exactly, labels and all, including the two
    bits of state carried out of a match into the literals that follow it -
    which is the part a from-memory reimplementation gets wrong, and gets
    wrong in the way that decodes the first few kilobytes correctly.
    """
    out = bytearray()
    n = len(src)
    if n < 3:
        raise ValueError("lzo block too short")
    ip = 0

    def need(count):
        if ip + count > n:
            raise ValueError("lzo input overrun")

    def copy_match(distance, length):
        if distance <= 0 or distance > len(out):
            raise ValueError("lzo back-reference before the start of output")
        at = len(out) - distance
        for i in range(length):
            out.append(out[at + i])

    def long_length(base):
        """A zero length field means 'add 255 per zero byte, then one more'."""
        nonlocal ip
        length = base
        while True:
            need(1)
            b = src[ip]
            ip += 1
            if b:
                return length + b
            length += 255

    label = "top"
    t = 0
    while True:
        if label == "top":
            if src[ip] > 17:
                t = src[ip] - 17
                ip += 1
                if t < 4:
                    label = "match_next"
                    continue
                need(t)
                out += src[ip:ip + t]
                ip += t
                label = "first_literal_run"
                continue
            label = "literal"

        if label == "literal":
            if ip >= n:
                return bytes(out)
            t = src[ip]
            ip += 1
            if t >= 16:
                label = "match"
                continue
            t = long_length(15) if t == 0 else t
            need(t + 3)
            out += src[ip:ip + t + 3]
            ip += t + 3
            label = "first_literal_run"

        if label == "first_literal_run":
            if ip >= n:
                return bytes(out)
            t = src[ip]
            ip += 1
            if t >= 16:
                label = "match"
            else:
                need(1)
                # M2_MAX_OFFSET is 0x0800: the first match after a literal run
                # reaches further back than the same encoding does later
                copy_match(1 + 0x0800 + (t >> 2) + (src[ip] << 2), 3)
                ip += 1
                label = "match_done"

        # the inner loop: match, then the state literals, then match again
        while label in ("match", "match_done", "match_next"):
            if label == "match":
                if t >= 64:
                    need(1)
                    distance = 1 + ((t >> 2) & 7) + (src[ip] << 3)
                    ip += 1
                    copy_match(distance, (t >> 5) + 1)
                elif t >= 32:
                    length = (t & 31) or long_length(31)
                    need(2)
                    pair = src[ip] | (src[ip + 1] << 8)
                    ip += 2
                    copy_match(1 + (pair >> 2), length + 2)
                elif t >= 16:
                    high = (t & 8) << 11
                    length = (t & 7) or long_length(7)
                    need(2)
                    pair = src[ip] | (src[ip + 1] << 8)
                    ip += 2
                    back = high + (pair >> 2)
                    if back == 0:
                        return bytes(out)          # the end-of-stream marker
                    copy_match(back + 0x4000, length + 2)
                else:
                    need(1)
                    distance = 1 + (t >> 2) + (src[ip] << 2)
                    ip += 1
                    copy_match(distance, 2)
                label = "match_done"

            if label == "match_done":
                # the state is the low two bits of the byte two back, which is
                # the instruction byte or the first half of the offset pair
                t = src[ip - 2] & 3
                if t == 0:
                    label = "literal"
                    break
                label = "match_next"

            if label == "match_next":
                need(t)
                out += src[ip:ip + t]
                ip += t
                if ip >= n:
                    return bytes(out)
                t = src[ip]
                ip += 1
                label = "match"

    return bytes(out)


def probe_btrfs(volume):
    """A BtrfsFilesystem on this volume, or None."""
    try:
        return BtrfsFilesystem(volume)
    except (BtrfsError, struct.error, ValueError, KeyError, IndexError):
        return None
