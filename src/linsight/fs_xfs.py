# -*- coding: utf-8 -*-
"""The XFS reader.

RHEL, CentOS, Rocky and Alma have defaulted to XFS since RHEL 7, so on
enterprise Linux this is the filesystem, not the alternative. A disk reader
that handles only ext reads an Ubuntu laptop and reports an empty disk for
every server image in the case - which is why this is here rather than on a
list of things to add later.

XFS differs from ext in the two ways that matter to a reader. Everything is
big-endian. And an inode does not have one layout: its data fork is either
inline (a short directory, a short symlink), a packed list of 128-bit extent
records, or a B+tree whose root sits in the fork and whose blocks live out on
the disk. All three are implemented, because which one a file uses depends on
how big it is, and the big files are the logs.

Directories are the other half. A directory is inline while it is small, then
becomes a set of data blocks addressed inside the file's own logical space -
with the leaf and free index living above 32 GB so they never collide with the
data. The reader walks only the data blocks, which is what makes one loop work
for the block, leaf and node directory forms alike.
"""

from __future__ import annotations

import struct

from .fsbase import (
    ExtentFile, Filesystem, FsNode, KIND_BY_MODE, S_IFMT, utc)

XFS_SB_MAGIC = b"XFSB"
XFS_DINODE_MAGIC = b"IN"

# data fork formats
FMT_DEV = 0
FMT_LOCAL = 1
FMT_EXTENTS = 2
FMT_BTREE = 3

# directory block magics: v4 then v5
DIR_BLOCK = (b"XD2B", b"XDB3")        # single-block directory
DIR_DATA = (b"XD2D", b"XDD3")         # data block of a bigger directory
BMBT_MAGIC = (b"BMAP", b"BMA3")
SYMLINK_MAGIC = b"XSLM"

# v5 (crc) headers are longer than v4 ones by exactly the block header
DIR3_DATA_HDR = 64
DIR2_DATA_HDR = 16
BMBT3_HDR = 72
BMBT_HDR = 24
SYMLINK_HDR = 56

#: Directory content lives below 32 GB of the file's logical space; the leaf
#: index sits at 32 GB and the free index at 64 GB. Walking only what is below
#: the first boundary is what lets one loop read every directory form.
DIR_LEAF_OFFSET = 32 * 1024 * 1024 * 1024

KIND_BY_FTYPE = {1: "f", 2: "d", 3: "c", 4: "b", 5: "p", 6: "s", 7: "l"}

#: XFS bigtime counts nanoseconds from 1901-12-13 20:45:52 UTC, which is
#: 2^31 seconds before the Unix epoch.
BIGTIME_OFFSET = 1 << 31

FEAT_INCOMPAT_FTYPE = 0x1
#: XFS_SB_FEAT_INCOMPAT_NREXT64. With it, an inode's data-fork extent count is
#: a 64-bit field at 0x18 and 0x4c holds the *attribute* fork's count instead.
#: mkfs.xfs turns this on by default from 6.x, so a reader that always looks
#: at 0x4c finds zero extents on a freshly made image and returns every file
#: as zeroes - which is what it looks like when this is missed.
FEAT_INCOMPAT_NREXT64 = 0x20
FLAGS2_BIGTIME = 0x8

ROOT_ONLINK_V4 = 0


class XfsError(Exception):
    pass


class XfsFilesystem(Filesystem):
    """An XFS filesystem on a volume."""

    kind = "xfs"

    def __init__(self, volume):
        Filesystem.__init__(self, volume)
        sb = volume.read(0, 512)
        if len(sb) < 512 or sb[:4] != XFS_SB_MAGIC:
            raise XfsError("no XFS superblock")
        self.block_size = _xfs_u32(sb, 0x04)
        if not (512 <= self.block_size <= 65536):
            raise XfsError("implausible XFS block size %d" % self.block_size)
        self.dblocks = _xfs_u64(sb, 0x08)
        self.uuid = _xfs_uuid(sb[0x20:0x30])
        self.root_ino = _xfs_u64(sb, 0x38)
        self.ag_blocks = _xfs_u32(sb, 0x54)
        self.ag_count = _xfs_u32(sb, 0x58)
        self.version = _xfs_u16(sb, 0x64)
        self.sector_size = _xfs_u16(sb, 0x66)
        self.inode_size = _xfs_u16(sb, 0x68)
        self.inopblock = _xfs_u16(sb, 0x6A)
        self.label = sb[0x6C:0x78].split(b"\x00", 1)[0].decode("utf-8", "replace")
        self.blocklog = sb[0x78]
        self.inodelog = sb[0x7A]
        self.inopblog = sb[0x7B]
        self.agblklog = sb[0x7C]
        self.icount = _xfs_u64(sb, 0x80)
        self.dirblklog = sb[0xC0]
        self.dir_block_size = self.block_size << self.dirblklog
        self.size = self.dblocks * self.block_size

        version_num = self.version & 0xF
        self.v5 = version_num == 5
        self.features_incompat = _xfs_u32(sb, 0xD8) if self.v5 else 0
        self.nrext64 = bool(self.features_incompat & FEAT_INCOMPAT_NREXT64)
        self.has_ftype = bool(self.features_incompat & FEAT_INCOMPAT_FTYPE) \
            or bool(self.v5)
        if not self.v5:
            # v4 records ftype in the directory only when the feature bit says
            # so, and reading a name one byte long when it is not there
            # truncates every filename on the filesystem by one character
            features2 = _xfs_u32(sb, 0xC8)
            self.has_ftype = bool(features2 & 0x200)

        self.kind = "xfs"
        # XFS has no superblock timestamp; the root inode's mtime is the best
        # statement of when this filesystem was last written to
        self._inode_cache = {}
        root = self.root_node()
        if root is None:
            raise XfsError("XFS root inode %d is unreadable" % self.root_ino)
        self.last_write = root.mtime
        self.created = root.crtime
        if self.ag_count == 0 or self.ag_blocks == 0:
            raise XfsError("XFS superblock describes no allocation groups")
        if not self.v5:
            self.notes.append(
                "this is a v4 XFS (no metadata checksums); file creation "
                "times are not recorded by v4 and will be empty")

    # -- inodes -------------------------------------------------------------
    def inode_offset(self, ino):
        """Byte offset of inode `ino` on the volume.

        The inode number is not an index: it packs the allocation group, the
        block within it and the slot within the block into one integer, and
        the widths come from the superblock. Treating it as an index reads
        somewhere plausible and entirely wrong.
        """
        agno = ino >> (self.agblklog + self.inopblog)
        agbno = (ino >> self.inopblog) & ((1 << self.agblklog) - 1)
        slot = ino & ((1 << self.inopblog) - 1)
        if agno >= self.ag_count:
            return -1
        return ((agno * self.ag_blocks + agbno) * self.block_size
                + slot * self.inode_size)

    def inode(self, ino):
        cached = self._inode_cache.get(ino)
        if cached is not None:
            return cached
        at = self.inode_offset(ino)
        if at < 0:
            return b""
        raw = self.volume.read(at, self.inode_size)
        if raw[:2] != XFS_DINODE_MAGIC:
            return b""
        if len(self._inode_cache) < 65536:
            self._inode_cache[ino] = raw
        return raw

    def _fork_offset(self, raw):
        """Where the data fork starts inside the inode."""
        return 176 if raw[4] >= 3 else 100

    def nextents(self, raw):
        """How many extent records the data fork holds.

        Which field that is depends on a feature flag, not on the inode
        version: with NREXT64 the count is 64 bits wide at 0x18, and the field
        at 0x4c that used to hold it holds the attribute fork's count. Reading
        the old place on a new filesystem gives 0 and every file reads empty.
        """
        if self.nrext64 and raw[4] >= 3:
            return _xfs_u64(raw, 0x18)
        return _xfs_u32(raw, 0x4C)

    def _fork_size(self, raw):
        """How much room the data fork has, before the attribute fork."""
        start = self._fork_offset(raw)
        forkoff = raw[0x52]
        if forkoff:
            return forkoff * 8
        return self.inode_size - start

    def _time(self, raw, offset, bigtime):
        if bigtime:
            value = _xfs_u64(raw, offset)
            if not value:
                return None
            return utc(value // 1000000000 - BIGTIME_OFFSET,
                       value % 1000000000)
        return utc(_xfs_u32(raw, offset), _xfs_u32(raw, offset + 4))

    def node_at(self, ino, path, hint=""):
        raw = self.inode(ino)
        if len(raw) < 100:
            return None
        mode = _xfs_u16(raw, 0x02)
        version = raw[4]
        kind = KIND_BY_MODE.get(mode & S_IFMT, hint or "f")
        flags2 = _xfs_u64(raw, 0x78) if version >= 3 and len(raw) >= 0x80 else 0
        bigtime = bool(flags2 & FLAGS2_BIGTIME)
        node = FsNode(
            path=path, inode=ino, kind=kind, size=_xfs_u64(raw, 0x38), mode=mode,
            uid=_xfs_u32(raw, 0x08), gid=_xfs_u32(raw, 0x0C), nlink=_xfs_u32(raw, 0x10),
            atime=self._time(raw, 0x20, bigtime),
            mtime=self._time(raw, 0x28, bigtime),
            ctime=self._time(raw, 0x30, bigtime),
            crtime=self._time(raw, 0x90, bigtime)
            if version >= 3 and len(raw) >= 0x98 else None,
            fs=self, ref=raw)
        if version < 3 and _xfs_u16(raw, 0x06) and not node.nlink:
            node.nlink = _xfs_u16(raw, 0x06)      # v1 inodes keep links in di_onlink
        if kind == "l":
            node.target = self._symlink_target(node)
        return node

    def root_node(self):
        return self.node_at(self.root_ino, "", "d")

    # -- the data fork ------------------------------------------------------
    def _extents(self, node):
        """[(logical block, physical block, count)] for a file's data fork."""
        cached = node._map_cache
        if cached is not None:
            return cached
        raw = node._ref
        fmt = raw[0x05]
        start = self._fork_offset(raw)
        out = []
        if fmt == FMT_EXTENTS:
            count = self.nextents(raw)
            room = self._fork_size(raw) // 16
            for i in range(min(count, room)):
                rec = raw[start + i * 16:start + i * 16 + 16]
                if len(rec) < 16:
                    break
                out.append(_xfs_extent(rec))
        elif fmt == FMT_BTREE:
            self._btree_extents(raw[start:start + self._fork_size(raw)], out, 0,
                                root=True)
        out = [e for e in out if e is not None]
        out.sort()
        node._map_cache = out
        return out

    def _btree_extents(self, block, out, depth, root=False):
        """Walk a bmap B+tree, collecting the extent records in its leaves."""
        if depth > 16 or len(block) < 4:
            self.errors += 1
            return
        if root:
            level = _xfs_u16(block, 0)
            numrecs = _xfs_u16(block, 2)
            # the root's pointers sit at the far end of the fork, after a key
            # array sized for the room available rather than for numrecs
            maxrecs = (len(block) - 4) // 16
            ptr_at = 4 + maxrecs * 8
            pointers = [_xfs_u64(block, ptr_at + i * 8)
                        for i in range(min(numrecs, maxrecs))]
        else:
            magic = block[:4]
            if magic not in BMBT_MAGIC:
                self.errors += 1
                return
            hdr = BMBT3_HDR if magic == b"BMA3" else BMBT_HDR
            level = _xfs_u16(block, 4)
            numrecs = _xfs_u16(block, 6)
            if level == 0:
                for i in range(numrecs):
                    at = hdr + i * 16
                    if at + 16 > len(block):
                        break
                    out.append(_xfs_extent(block[at:at + 16]))
                return
            maxrecs = (len(block) - hdr) // 16
            ptr_at = hdr + maxrecs * 8
            pointers = [_xfs_u64(block, ptr_at + i * 8)
                        for i in range(min(numrecs, maxrecs))]
        for fsb in pointers:
            if not fsb:
                continue
            self._btree_extents(self.fsblock(fsb), out, depth + 1)

    def fsb_to_offset(self, fsb):
        """A filesystem block number is (ag, block) packed, like an inode."""
        agno = fsb >> self.agblklog
        agbno = fsb & ((1 << self.agblklog) - 1)
        return (agno * self.ag_blocks + agbno) * self.block_size

    def fsblock(self, fsb, count=1):
        return self.volume.read(self.fsb_to_offset(fsb),
                                self.block_size * count)

    # -- reading ------------------------------------------------------------
    def _local_data(self, node):
        raw = node._ref
        start = self._fork_offset(raw)
        return raw[start:start + min(node.size, self._fork_size(raw))]

    def read(self, node, limit=None):
        size = node.size if limit is None else min(node.size, limit)
        if size <= 0:
            return b""
        if node._ref[0x05] == FMT_LOCAL:
            return self._local_data(node)[:size]
        return self._fetch(node, 0, size)

    def _fetch(self, node, offset, length):
        length = min(length, max(0, node.size - offset))
        if length <= 0:
            return b""
        extents = self._extents(node)
        bs = self.block_size
        out = bytearray()
        pos = offset
        end = offset + length
        while pos < end:
            lblock = pos // bs
            within = pos % bs
            phys, run = _xfs_lookup(extents, lblock)
            take = min(end - pos, bs * run - within)
            if phys is None:
                out += b"\x00" * take
            else:
                out += self.volume.read(self.fsb_to_offset(phys) + within, take)
            pos += take
        return bytes(out)

    def open(self, node):
        if node._ref[0x05] == FMT_LOCAL:
            import io
            return io.BytesIO(self._local_data(node)[:node.size])
        return ExtentFile(lambda o, n: self._fetch(node, o, n), node.size)

    def _symlink_target(self, node):
        raw = node._ref
        if raw[0x05] == FMT_LOCAL:
            return self._local_data(node).decode("utf-8", "replace")
        extents = self._extents(node)
        if not extents:
            return ""
        block = self.fsblock(extents[0][1])
        if block[:4] == SYMLINK_MAGIC:
            block = block[SYMLINK_HDR:]
        return block[:node.size].decode("utf-8", "replace")

    # -- directories --------------------------------------------------------
    def dir_entries(self, node):
        raw = node._ref
        fmt = raw[0x05]
        if fmt == FMT_LOCAL:
            return self._shortform_dir(node)
        return self._block_dir(node)

    def _shortform_dir(self, node):
        """A directory small enough to live inside its own inode."""
        raw = node._ref
        start = self._fork_offset(raw)
        data = raw[start:start + self._fork_size(raw)]
        if len(data) < 2:
            return []
        count = data[0]
        i8 = data[1]
        # i8count is the number of entries needing a 64-bit inode number; when
        # it is non-zero every number in this directory is 8 bytes wide
        wide = i8 > 0
        at = 2 + (8 if wide else 4)          # past the parent inode
        if i8 and not count:
            count = i8
        out = []
        for _ in range(count):
            if at + 3 > len(data):
                break
            namelen = data[at]
            at += 1
            at += 2                          # the offset field, not needed here
            name = data[at:at + namelen]
            at += namelen
            ftype = 0
            if self.has_ftype:
                if at >= len(data):
                    break
                ftype = data[at]
                at += 1
            width = 8 if wide else 4
            if at + width > len(data):
                break
            ino = _xfs_u64(data, at) if wide else _xfs_u32(data, at)
            at += width
            if name:
                out.append((name.decode("utf-8", "surrogateescape"), ino,
                            KIND_BY_FTYPE.get(ftype, "")))
        return out

    def _block_dir(self, node):
        """A directory whose entries live in data blocks of its own extents.

        Only the blocks below the 32 GB leaf boundary hold entries; the leaf
        and free indexes above it are addressed in the same logical space and
        would parse as nonsense. One loop then covers the block, leaf and node
        directory forms, because they differ in the index, not the data.
        """
        out = []
        limit = DIR_LEAF_OFFSET // self.block_size
        per_dir_block = max(1, self.dir_block_size // self.block_size)
        for logical, phys, count in self._extents(node):
            if logical >= limit:
                break
            i = 0
            while i < count:
                if logical + i >= limit:
                    break
                take = min(per_dir_block, count - i)
                block = self.fsblock(phys + i, take)
                magic = block[:4]
                if magic in DIR_DATA or magic in DIR_BLOCK:
                    hdr = DIR3_DATA_HDR if magic in (b"XDD3", b"XDB3") \
                        else DIR2_DATA_HDR
                    end = len(block)
                    if magic in DIR_BLOCK:
                        # a single-block directory keeps its leaf index and a
                        # tail at the end of the same block; entries stop
                        # where the leaf entries begin
                        tail_count = _xfs_u32(block, len(block) - 8)
                        if 0 <= tail_count < len(block) // 8:
                            end = len(block) - 8 - tail_count * 8
                    out.extend(self._parse_dir_block(block, hdr, end))
                i += take
        return out

    def _parse_dir_block(self, block, hdr, end):
        out = []
        at = hdr
        while at + 12 <= end:
            if _xfs_u16(block, at) == 0xFFFF:       # an unused run, with its length
                length = _xfs_u16(block, at + 2)
                if length < 4:
                    break
                at += length
                continue
            ino = _xfs_u64(block, at)
            namelen = block[at + 8]
            if namelen == 0 or at + 9 + namelen > end:
                break
            name = block[at + 9:at + 9 + namelen]
            ftype = 0
            after = at + 9 + namelen
            if self.has_ftype:
                if after >= end:
                    break
                ftype = block[after]
                after += 1
            after += 2                          # the tag
            after = (after + 7) & ~7            # entries are 8-byte aligned
            if name not in (b".", b".."):
                out.append((name.decode("utf-8", "surrogateescape"), ino,
                            KIND_BY_FTYPE.get(ftype, "")))
            if after <= at:
                break
            at = after
        return out

    # -- the walk -----------------------------------------------------------
    def walk(self, max_nodes=0, on_error=None):
        root = self.root_node()
        if root is None:
            raise XfsError("XFS root inode is unreadable")
        stack = [(root, "")]
        seen = {self.root_ino}
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
            for name, ino, hint in sorted(entries, reverse=True):
                path = prefix + "/" + name
                child = self.node_at(ino, path, hint)
                if child is None:
                    self.errors += 1
                    continue
                yield child
                count += 1
                if max_nodes and count >= max_nodes:
                    return
                if child.is_dir and ino not in seen:
                    seen.add(ino)
                    stack.append((child, path))

    def describe(self):
        bits = ["xfs v%d" % (5 if self.v5 else 4)]
        if self.nrext64:
            bits.append("nrext64")
        if self.label:
            bits.append("'%s'" % self.label)
        bits.append("%d-byte blocks" % self.block_size)
        bits.append("%d AG" % self.ag_count)
        if self.uuid:
            bits.append(self.uuid)
        return ", ".join(bits)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _xfs_u16(b, o=0):
    return struct.unpack_from(">H", b, o)[0]


def _xfs_u32(b, o=0):
    return struct.unpack_from(">I", b, o)[0]


def _xfs_u64(b, o=0):
    return struct.unpack_from(">Q", b, o)[0]


def _xfs_uuid(raw):
    if len(raw) != 16 or raw == b"\x00" * 16:
        return ""
    h = raw.hex()
    return "%s-%s-%s-%s-%s" % (h[0:8], h[8:12], h[12:16], h[16:20], h[20:32])


def _xfs_extent(rec):
    """A 128-bit packed XFS extent record.

    Nothing in it is byte-aligned: 1 flag bit, 54 bits of logical offset, 52
    of physical block and 21 of length, packed into two big-endian 64-bit
    halves. Reading it as four fields of convenient widths gives extents that
    are plausible and wrong.
    """
    hi, lo = struct.unpack_from(">QQ", rec, 0)
    startoff = (hi >> 9) & ((1 << 54) - 1)
    startblock = ((hi & 0x1FF) << 43) | (lo >> 21)
    count = lo & ((1 << 21) - 1)
    if not count:
        return None
    return (startoff, startblock, count)


def _xfs_lookup(extents, lblock):
    lo, hi = 0, len(extents)
    while lo < hi:
        mid = (lo + hi) // 2
        if extents[mid][0] <= lblock:
            lo = mid + 1
        else:
            hi = mid
    if lo:
        logical, phys, count = extents[lo - 1]
        if logical <= lblock < logical + count:
            return phys + (lblock - logical), count - (lblock - logical)
    return None, 1


def probe_xfs(volume):
    """An XfsFilesystem on this volume, or None."""
    try:
        return XfsFilesystem(volume)
    except (XfsError, struct.error, ValueError):
        return None
