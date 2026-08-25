# -*- coding: utf-8 -*-
"""The ext2 / ext3 / ext4 reader.

Debian and Ubuntu put root on ext4, so this is the filesystem most Linux
images arrive as, and it repays being read rather than mounted. Three things
come out of here that a mount does not give you:

  crtime      ext4 records file creation and the kernel does not expose it. A
              binary whose crtime is inside the incident window and whose
              mtime reads 2019 is a timestomp - stated, not suspected.
  deleted     an inode with a deletion time and no links still carries its
              size, its owner and, until the blocks are reused, its content.
  no mount    reading the structures directly needs no loop device, no root,
              and no kernel that trusts the image - which matters, because
              mounting evidence is how evidence gets modified.

Both block-mapping schemes are implemented: the extent tree ext4 uses, and the
indirect-block chain ext2 and ext3 use. A reader that implements only extents
returns nothing at all for every file on an older image, and returns it
silently, which is exactly the failure this tool exists to not have.
"""

from __future__ import annotations

import struct

from .fsbase import (
    ExtentFile, Filesystem, FsNode, KIND_BY_MODE, S_IFMT, utc)

EXT_MAGIC = 0xEF53
EXT_SB_OFFSET = 1024
ROOT_INO = 2

INCOMPAT_FILETYPE = 0x0002
INCOMPAT_META_BG = 0x0010
INCOMPAT_EXTENTS = 0x0040
INCOMPAT_64BIT = 0x0080
INCOMPAT_INLINE_DATA = 0x8000
INCOMPAT_ENCRYPT = 0x10000
INCOMPAT_CASEFOLD = 0x20000

COMPAT_HAS_JOURNAL = 0x0004
RO_COMPAT_METADATA_CSUM = 0x0400
RO_COMPAT_BIGALLOC = 0x0200

FL_EXTENTS = 0x00080000
FL_INLINE_DATA = 0x10000000
FL_ENCRYPTED = 0x00000800

KIND_BY_FILETYPE = {1: "f", 2: "d", 3: "c", 4: "b", 5: "p", 6: "s", 7: "l"}

EXTENT_MAGIC = 0xF30A

#: Directories never walked into. /proc and /sys are kernel interfaces that
#: exist as empty mountpoints on a dead disk; a full recursion into a
#: container's overlay store, on the other hand, is real content - so only the
#: ones that are empty on disk by definition are skipped, and nothing is
#: skipped for being merely large.
SKIP_DIRS = ()


class ExtError(Exception):
    pass


class ExtFilesystem(Filesystem):
    """An ext2/3/4 filesystem on a volume."""

    def __init__(self, volume):
        Filesystem.__init__(self, volume)
        sb = volume.read(EXT_SB_OFFSET, 1024)
        if len(sb) < 1024 or struct.unpack_from("<H", sb, 0x38)[0] != EXT_MAGIC:
            raise ExtError("no ext superblock")
        self._sb = sb

        self.inodes_count = _ext_u32(sb, 0x00)
        blocks_lo = _ext_u32(sb, 0x04)
        self.log_block_size = _ext_u32(sb, 0x18)
        self.block_size = 1024 << self.log_block_size
        self.first_data_block = _ext_u32(sb, 0x14)
        self.blocks_per_group = _ext_u32(sb, 0x20)
        self.inodes_per_group = _ext_u32(sb, 0x28)
        self.rev_level = _ext_u32(sb, 0x4C)
        self.inode_size = _ext_u16(sb, 0x58) if self.rev_level else 128
        self.compat = _ext_u32(sb, 0x5C)
        self.incompat = _ext_u32(sb, 0x60)
        self.ro_compat = _ext_u32(sb, 0x64)
        self.uuid = _ext_uuid(sb[0x68:0x78])
        self.label = sb[0x78:0x88].split(b"\x00", 1)[0].decode("utf-8", "replace")
        self.last_mounted = sb[0x88:0xC8].split(b"\x00", 1)[0].decode("utf-8", "replace")
        self.desc_size = _ext_u16(sb, 0xFE) if self.incompat & INCOMPAT_64BIT else 32
        if self.desc_size < 32:
            self.desc_size = 32
        blocks_hi = _ext_u32(sb, 0x150) if self.incompat & INCOMPAT_64BIT else 0
        self.blocks_count = blocks_lo | (blocks_hi << 32)
        self.size = self.blocks_count * self.block_size
        self.first_ino = _ext_u32(sb, 0x54) if self.rev_level else 11

        self.last_mount = utc(_ext_u32(sb, 0x2C))
        self.last_write = utc(_ext_u32(sb, 0x30))
        self.last_check = utc(_ext_u32(sb, 0x40))
        self.created = utc(_ext_u32(sb, 0x108))
        self.mount_count = _ext_u16(sb, 0x34)
        self.state = _ext_u16(sb, 0x3A)

        if self.incompat & INCOMPAT_EXTENTS or self.incompat & INCOMPAT_64BIT:
            self.kind = "ext4"
        elif self.compat & COMPAT_HAS_JOURNAL:
            self.kind = "ext3"
        else:
            self.kind = "ext2"

        if self.state & 0x1 == 0:
            self.notes.append(
                "the filesystem was not cleanly unmounted - the journal holds "
                "changes not yet in the tree, so metadata may lag the last "
                "writes made to this host")
        if self.incompat & INCOMPAT_ENCRYPT:
            self.notes.append(
                "some directories on this filesystem use ext4 encryption; "
                "their names and contents cannot be recovered without the key")
        unknown = self.incompat & ~(
            INCOMPAT_FILETYPE | INCOMPAT_META_BG | INCOMPAT_EXTENTS |
            INCOMPAT_64BIT | INCOMPAT_INLINE_DATA | INCOMPAT_ENCRYPT |
            INCOMPAT_CASEFOLD | 0x1 | 0x8 | 0x100 | 0x200 | 0x400 | 0x1000 |
            0x2000 | 0x4000)
        if unknown:
            self.notes.append("unrecognised ext incompat features 0x%x - some "
                              "structures may not be read" % unknown)
        if self.ro_compat & RO_COMPAT_BIGALLOC:
            self.notes.append("bigalloc is enabled; block addressing is by "
                              "cluster and file content may read short")

        self.group_count = max(1, (self.blocks_count - self.first_data_block +
                                   self.blocks_per_group - 1) //
                               self.blocks_per_group)
        self._groups = self._read_group_descriptors()
        self._block_cache = {}
        self._inode_cache = {}

    # -- primitives ---------------------------------------------------------
    def block(self, number, count=1):
        if number <= 0:
            return b"\x00" * (self.block_size * count)
        return self.volume.read(number * self.block_size,
                                self.block_size * count)

    def _read_group_descriptors(self):
        gd_block = self.first_data_block + 1
        raw = self.block(gd_block,
                         max(1, (self.group_count * self.desc_size +
                                 self.block_size - 1) // self.block_size))
        groups = []
        for i in range(self.group_count):
            at = i * self.desc_size
            if at + 32 > len(raw):
                break
            table_lo = _ext_u32(raw, at + 0x08)
            table_hi = _ext_u32(raw, at + 0x28) if self.desc_size >= 64 else 0
            flags = _ext_u16(raw, at + 0x12)
            groups.append((table_lo | (table_hi << 32), flags))
        return groups

    # -- inodes -------------------------------------------------------------
    def inode(self, number):
        """Raw inode bytes for inode `number` (1-based), or b''."""
        if number < 1 or number > self.inodes_count:
            return b""
        cached = self._inode_cache.get(number)
        if cached is not None:
            return cached
        group = (number - 1) // self.inodes_per_group
        index = (number - 1) % self.inodes_per_group
        if group >= len(self._groups):
            return b""
        table = self._groups[group][0]
        if not table:
            return b""
        at = table * self.block_size + index * self.inode_size
        raw = self.volume.read(at, self.inode_size)
        if len(self._inode_cache) < 65536:
            self._inode_cache[number] = raw
        return raw

    def node_from_inode(self, number, path="", kind_hint=""):
        raw = self.inode(number)
        if len(raw) < 128:
            return None
        mode = _ext_u16(raw, 0x00)
        kind = KIND_BY_MODE.get(mode & S_IFMT, kind_hint or "f")
        size = _ext_u32(raw, 0x04)
        if kind == "f" and len(raw) >= 0x70:
            size |= _ext_u32(raw, 0x6C) << 32
        # the high halves of uid and gid are in osd2, which a 128-byte inode
        # does have - but a truncated read of one must not take the walk down
        wide = len(raw) >= 0x80
        uid = _ext_u16(raw, 0x02) | ((_ext_u16(raw, 0x78) << 16) if wide else 0)
        gid = _ext_u16(raw, 0x18) | ((_ext_u16(raw, 0x7A) << 16) if wide else 0)
        nlink = _ext_u16(raw, 0x1A)
        extra = _ext_u16(raw, 0x80) if len(raw) >= 0x82 else 0
        node = FsNode(
            path=path, inode=number, kind=kind, size=size, mode=mode,
            uid=uid, gid=gid, nlink=nlink,
            atime=self._time(raw, 0x08, 0x8C, extra),
            ctime=self._time(raw, 0x0C, 0x84, extra),
            mtime=self._time(raw, 0x10, 0x88, extra),
            # crtime lives past the 128-byte inode entirely, so it is only
            # asked for when the inode is big enough to hold it
            crtime=(self._time(raw, 0x90, 0x94, extra, need=0x1C)
                    if len(raw) >= 0x98 else None),
            dtime=utc(_ext_u32(raw, 0x14)),
            fs=self, ref=raw)
        if kind == "l":
            node.target = self._symlink_target(node, raw)
        return node

    def _time(self, raw, base, extra_at, extra_isize, need=0x18):
        """A timestamp, with the ext4 extra-precision bits when they exist.

        The extra field is only present when i_extra_isize says the inode is
        big enough to hold it. Reading it unconditionally on a 128-byte inode
        reads the next inode's mode as a nanosecond count, which produces
        timestamps decades out and a timeline that cannot be trusted.

        The base field can be absent too. A 128-byte inode - which is what
        ext2 and ext3 use, and what an ext4 filesystem made with
        '-I 128' uses - has no crtime at all: offset 0x90 is past its end.
        Every read here is therefore bounds-checked rather than assumed, and
        a field that is not there comes back as no time rather than as an
        exception in the middle of a filesystem walk.
        """
        if len(raw) < base + 4:
            return None
        seconds = _ext_u32(raw, base)
        if not seconds:
            return None
        nanos = 0
        if extra_isize >= need and len(raw) >= extra_at + 4:
            extra = _ext_u32(raw, extra_at)
            seconds |= (extra & 0x3) << 32
            nanos = extra >> 2
        return utc(seconds, nanos)

    def _symlink_target(self, node, raw):
        if node.size < 60 and not _ext_u32(raw, 0x1C):
            return raw[0x28:0x28 + node.size].decode("utf-8", "replace")
        try:
            return self.read(node).decode("utf-8", "replace")
        except Exception:
            return ""

    # -- block mapping ------------------------------------------------------
    def _map(self, node):
        """[(logical block, physical block, count)], in logical order."""
        raw = node._ref
        flags = _ext_u32(raw, 0x20)
        if flags & FL_INLINE_DATA:
            return []
        if flags & FL_EXTENTS:
            out = []
            self._walk_extents(raw[0x28:0x28 + 60], out, 0)
            out.sort()
            return out
        return self._indirect_map(raw)

    def _walk_extents(self, block, out, depth):
        if depth > 8 or len(block) < 12:
            self.errors += 1
            return
        magic, entries, _max, tree_depth = struct.unpack_from("<HHHH", block, 0)
        if magic != EXTENT_MAGIC:
            self.errors += 1
            return
        for i in range(entries):
            at = 12 + i * 12
            if at + 12 > len(block):
                break
            if tree_depth == 0:
                logical = _ext_u32(block, at)
                length = _ext_u16(block, at + 4)
                start = _ext_u32(block, at + 8) | (_ext_u16(block, at + 6) << 32)
                if length > 32768:            # uninitialised: allocated, unwritten
                    length -= 32768
                if length:
                    out.append((logical, start, length))
            else:
                logical = _ext_u32(block, at)
                leaf = _ext_u32(block, at + 4) | (_ext_u16(block, at + 8) << 32)
                self._walk_extents(self.block(leaf), out, depth + 1)

    def _indirect_map(self, raw):
        """ext2/ext3 block pointers: 12 direct, then one, two and three deep."""
        per = self.block_size // 4
        out = []
        blocks = struct.unpack_from("<15I", raw, 0x28)
        for i in range(12):
            if blocks[i]:
                out.append((i, blocks[i], 1))
        logical = 12
        if blocks[12]:
            logical = self._indirect(blocks[12], 1, logical, out, per)
        else:
            logical += per
        if blocks[13]:
            logical = self._indirect(blocks[13], 2, logical, out, per)
        else:
            logical += per * per
        if blocks[14]:
            self._indirect(blocks[14], 3, logical, out, per)
        return out

    def _indirect(self, block, depth, logical, out, per):
        raw = self.block(block)
        entries = struct.unpack_from("<%dI" % per, raw, 0)
        for entry in entries:
            if depth == 1:
                if entry:
                    out.append((logical, entry, 1))
                logical += 1
            else:
                if entry:
                    logical = self._indirect(entry, depth - 1, logical, out, per)
                else:
                    logical += per ** (depth - 1)
        return logical

    # -- reading ------------------------------------------------------------
    def _inline_data(self, node):
        """The 60 bytes of i_block, for a file small enough to live in it."""
        return node._ref[0x28:0x28 + min(node.size, 60)]

    def read(self, node, limit=None):
        size = node.size if limit is None else min(node.size, limit)
        if size <= 0:
            return b""
        if _ext_u32(node._ref, 0x20) & FL_INLINE_DATA:
            return self._inline_data(node)[:size]
        return self._read_range(node, 0, size)

    def _read_range(self, node, offset, length):
        """`length` bytes at `offset` within the file, holes read as zeroes."""
        length = min(length, max(0, node.size - offset))
        if length <= 0:
            return b""
        mapping = self._mapping_of(node)
        out = bytearray()
        pos = offset
        end = offset + length
        bs = self.block_size
        while pos < end:
            lblock = pos // bs
            within = pos % bs
            phys, run = _ext_lookup(mapping, lblock)
            take = min(end - pos, bs * run - within)
            if phys is None:
                out += b"\x00" * take
            else:
                out += self.volume.read(phys * bs + within, take)
            pos += take
        return bytes(out)

    def _mapping_of(self, node):
        cached = getattr(node, "_map_cache", None)
        if cached is None:
            cached = self._map(node)
            try:
                node._map_cache = cached
            except AttributeError:
                pass                       # __slots__ - recompute next time
        return cached

    def open(self, node):
        if _ext_u32(node._ref, 0x20) & FL_INLINE_DATA:
            import io
            return io.BytesIO(self._inline_data(node)[:node.size])
        mapping = self._map(node)

        def fetch(offset, length):
            length = min(length, max(0, node.size - offset))
            if length <= 0:
                return b""
            out = bytearray()
            pos = offset
            end = offset + length
            bs = self.block_size
            while pos < end:
                phys, run = _ext_lookup(mapping, pos // bs)
                within = pos % bs
                take = min(end - pos, bs * run - within)
                if phys is None:
                    out += b"\x00" * take
                else:
                    out += self.volume.read(phys * bs + within, take)
                pos += take
            return bytes(out)

        return ExtentFile(fetch, node.size)

    # -- directories --------------------------------------------------------
    def root_node(self):
        return self.node_from_inode(ROOT_INO, "", "d")

    def node_at(self, ref, path, hint=""):
        return self.node_from_inode(ref, path, hint)

    def dir_entries(self, node):
        return self._dir_entries(node)

    def _dir_entries(self, node):
        """(name, inode, kind) for every entry in a directory.

        One linear pass over every data block of the directory covers htree
        directories too: an htree interior node is written as a single dirent
        with inode 0 spanning the block, so it is skipped by the same rule
        that skips the deleted entries and the checksum tail.
        """
        raw = node._ref
        if _ext_u32(raw, 0x20) & FL_INLINE_DATA:
            return self._inline_dir(node)
        out = []
        has_filetype = bool(self.incompat & INCOMPAT_FILETYPE)
        blocks = self._map(node)
        seen = 0
        for logical, phys, count in blocks:
            for i in range(count):
                if seen * self.block_size >= node.size and node.size:
                    break
                out.extend(self._parse_dir_block(self.block(phys + i),
                                                 has_filetype))
                seen += 1
        return out

    def _parse_dir_block(self, data, has_filetype):
        out = []
        at = 0
        end = len(data)
        while at + 8 <= end:
            ino = _ext_u32(data, at)
            rec_len = _ext_u16(data, at + 4)
            if rec_len < 8 or at + rec_len > end:
                break
            if has_filetype:
                name_len = data[at + 6]
                ftype = data[at + 7]
            else:
                name_len = _ext_u16(data, at + 6)
                ftype = 0
            if ino and name_len and at + 8 + name_len <= end:
                name = data[at + 8:at + 8 + name_len]
                if name not in (b".", b".."):
                    out.append((name.decode("utf-8", "surrogateescape"), ino,
                                KIND_BY_FILETYPE.get(ftype, "")))
            at += rec_len
        return out

    def _inline_dir(self, node):
        """An ext4 inline directory: parent inode, then ordinary dirents."""
        raw = node._ref[0x28:0x28 + 60]
        out = []
        at = 4
        has_filetype = bool(self.incompat & INCOMPAT_FILETYPE)
        while at + 8 <= len(raw):
            ino = _ext_u32(raw, at)
            rec_len = _ext_u16(raw, at + 4)
            if rec_len < 8 or at + rec_len > len(raw):
                break
            name_len = raw[at + 6] if has_filetype else _ext_u16(raw, at + 6)
            ftype = raw[at + 7] if has_filetype else 0
            if ino and name_len and at + 8 + name_len <= len(raw):
                name = raw[at + 8:at + 8 + name_len]
                if name not in (b".", b".."):
                    out.append((name.decode("utf-8", "surrogateescape"), ino,
                                KIND_BY_FILETYPE.get(ftype, "")))
            at += rec_len
        return out

    # -- the walk -----------------------------------------------------------
    def walk(self, max_nodes=0, on_error=None):
        """Every name in the filesystem, depth first from the root inode.

        Inodes already visited are not descended into again. A directory hard
        link is not supposed to exist, but a corrupt or hostile filesystem can
        carry one, and a walker that trusts the tree to be a tree recurses
        until it runs out of memory on evidence that was crafted to make it.
        """
        root = self.root_node()
        if root is None:
            raise ExtError("root inode is unreadable")
        stack = [(root, "")]
        seen_dirs = {ROOT_INO}
        count = 0
        while stack:
            node, prefix = stack.pop()
            try:
                entries = self._dir_entries(node)
            except Exception as exc:
                self.errors += 1
                if on_error:
                    on_error(prefix or "/", exc)
                continue
            for name, ino, hint in sorted(entries, reverse=True):
                path = prefix + "/" + name
                child = self.node_from_inode(ino, path, hint)
                if child is None:
                    self.errors += 1
                    continue
                yield child
                count += 1
                if max_nodes and count >= max_nodes:
                    return
                if child.is_dir and ino not in seen_dirs:
                    seen_dirs.add(ino)
                    stack.append((child, path))

    # -- deleted ------------------------------------------------------------
    def deleted(self, max_nodes=0):
        """Inodes with a deletion time and no remaining links.

        The name is gone - it lived in the directory entry, which was
        overwritten - so what comes back is an inode number, a size, an owner
        and a set of times. That is still enough to answer "was something
        removed from /tmp during the window", which is a question a mounted
        filesystem cannot answer at all.
        """
        count = 0
        table_bytes = self.inodes_per_group * self.inode_size
        for group, (table, flags) in enumerate(self._groups):
            if not table:
                continue
            # ext4 marks a group whose inode table was never written, and
            # reading it back is megabytes of zeroes per group - on a mostly
            # empty terabyte disk that is most of the scan
            if flags & 0x1:                        # EXT4_BG_INODE_UNINIT
                continue
            base = group * self.inodes_per_group + 1
            # a whole group's inode table at a time, in slices: one read per
            # inode turns this into millions of seeks on a real disk, and this
            # scan is already the slowest part of loading one
            at = 0
            while at < table_bytes:
                span = min(4 << 20, table_bytes - at)
                chunk = self.volume.read(table * self.block_size + at, span)
                for off in range(0, len(chunk) - self.inode_size + 1,
                                 self.inode_size):
                    number = base + (at + off) // self.inode_size
                    if number < self.first_ino or number > self.inodes_count:
                        continue
                    raw = chunk[off:off + self.inode_size]
                    if _ext_u32(raw, 0x14) == 0:   # dtime: never deleted
                        continue
                    if _ext_u16(raw, 0x1A):        # still linked
                        continue
                    if not _ext_u16(raw, 0x00):    # never allocated
                        continue
                    node = self.node_from_inode(
                        number, "/<deleted>/inode-%d" % number)
                    if node is None:
                        continue
                    node.deleted = True
                    yield node
                    count += 1
                    if max_nodes and count >= max_nodes:
                        return
                at += span

    def describe(self):
        bits = ["%s '%s'" % (self.kind, self.label) if self.label else self.kind,
                "%d-byte blocks" % self.block_size,
                "%s inodes" % format(self.inodes_count, ",")]
        if self.uuid:
            bits.append(self.uuid)
        return ", ".join(bits)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _ext_u16(b, o=0):
    return struct.unpack_from("<H", b, o)[0]


def _ext_u32(b, o=0):
    return struct.unpack_from("<I", b, o)[0]


def _ext_uuid(raw):
    if len(raw) != 16 or raw == b"\x00" * 16:
        return ""
    h = raw.hex()
    return "%s-%s-%s-%s-%s" % (h[0:8], h[8:12], h[12:16], h[16:20], h[20:32])


def _ext_lookup(mapping, lblock):
    """(physical block, run length) for a logical block; (None, 1) for a hole.

    `mapping` is sorted by logical block, so this is a bisect rather than a
    scan - a 4 GB file on 4 KiB blocks has a million logical blocks and a
    linear lookup per block turns a read into a quadratic one.
    """
    lo, hi = 0, len(mapping)
    while lo < hi:
        mid = (lo + hi) // 2
        if mapping[mid][0] <= lblock:
            lo = mid + 1
        else:
            hi = mid
    if lo:
        logical, phys, count = mapping[lo - 1]
        if logical <= lblock < logical + count:
            return phys + (lblock - logical), count - (lblock - logical)
    return None, 1


def probe_ext(volume):
    """An ExtFilesystem on this volume, or None."""
    try:
        return ExtFilesystem(volume)
    except (ExtError, struct.error, ValueError):
        return None
