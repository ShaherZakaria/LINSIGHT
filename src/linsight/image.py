# -*- coding: utf-8 -*-
"""Disk images: whatever the imager wrote, as one addressable run of bytes.

Everything above this module asks the same question - give me `n` bytes at
offset `o` of the disk - and gets the same answer whether those bytes are
sitting in a dd file, spread over sixty E01 segments, deflated inside a qcow2
cluster, or on the physical drive still plugged into the workstation. Which
container it was is a fact for the report, not a branch in the parser.

The formats here are the ones an image actually arrives in:

  raw / dd     one file, a split set (.001/.002, .aa/.ab, .dd.1), or a device
  E01 / EWF    EnCase, including multi-segment sets and compressed chunks
  qcow2        QEMU/KVM and libvirt, v2 and v3, backing files and compression
  vmdk         VMware, both the sparse binary form and a text descriptor
                 pointing at flat or split extents
  vhdx / vhd   Hyper-V, dynamic and fixed

A format that is recognised but cannot be read faithfully raises rather than
returning something plausible. A disk image that silently reads as zeroes
past the first gigabyte produces an examination that finds nothing, and
"found nothing" is the one answer a triage tool must never invent.

Reads go through a chunk cache sized to whatever the container's own unit is -
a qcow2 cluster, an EWF chunk - so walking a filesystem, which reads the same
few metadata blocks thousands of times, decompresses each of them once.
"""

from __future__ import annotations

import os
import re
import struct
import sys
import zlib
from collections import OrderedDict


class ImageError(Exception):
    """The container could not be opened, or cannot be read faithfully."""


def _u32le(b, o=0):
    return struct.unpack_from("<I", b, o)[0]


def _u64le(b, o=0):
    return struct.unpack_from("<Q", b, o)[0]


# ---------------------------------------------------------------------------
# the interface everything above this module sees
# ---------------------------------------------------------------------------

class Image:
    """Random access to the bytes of a disk, however they are stored.

    Subclasses implement `_read_raw`, which is handed a chunk-aligned offset
    and must return exactly that chunk (short only at the end of the disk).
    `read` does the rest: cache, assembly, and zero-fill past the end.

    `chunk` is set by the subclass to the container's own unit. Matching it
    means one cache entry is one decompression, never a fraction of one.
    """

    #: sector size to assume when nothing in the container says otherwise
    sector_size = 512
    #: bytes per cache entry
    chunk = 1 << 16
    #: how many chunks to keep - 512 x 64 KiB is 32 MiB, which is the working
    #: set of a filesystem walk with room to spare
    cache_entries = 512

    def __init__(self, path, size=0, description=""):
        self.path = path
        self.size = size
        self.description = description or self.__class__.__name__
        self.parts = [path]           # every file the image is made of
        self._cache = OrderedDict()

    # -- subclass hook ------------------------------------------------------
    def _read_raw(self, offset, length):
        raise NotImplementedError

    # -- reading ------------------------------------------------------------
    def _chunk_at(self, base):
        try:
            return self._cache[base]
        except KeyError:
            pass
        data = self._read_raw(base, self.chunk)
        if len(data) < self.chunk:
            data = data + b"\x00" * (self.chunk - len(data))
        self._cache[base] = data
        if len(self._cache) > self.cache_entries:
            self._cache.popitem(last=False)
        return data

    def read(self, offset, length):
        """`length` bytes at `offset`, zero-filled past the end of the disk."""
        if length <= 0 or offset < 0:
            return b""
        if self.size and offset >= self.size:
            return b"\x00" * length
        out = bytearray()
        end = offset + length
        pos = offset
        while pos < end:
            base = pos - (pos % self.chunk)
            data = self._chunk_at(base)
            start = pos - base
            take = min(self.chunk - start, end - pos)
            out += data[start:start + take]
            pos += take
        return bytes(out)

    def close(self):
        self._cache.clear()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def __repr__(self):
        return "<%s %s %d bytes>" % (self.__class__.__name__,
                                     os.path.basename(self.path), self.size)


class _FileImage(Image):
    """Base for the containers that read from files on disk."""

    def __init__(self, path, size=0, description=""):
        Image.__init__(self, path, size, description)
        self._fh = None

    def _file(self):
        if self._fh is None:
            self._fh = open(self.path, "rb")
        return self._fh

    def close(self):
        Image.close(self)
        if self._fh is not None:
            try:
                self._fh.close()
            finally:
                self._fh = None


# ---------------------------------------------------------------------------
# raw: one file, a split set, or a live device
# ---------------------------------------------------------------------------

class RawImage(Image):
    """A dd image: one file, or a set of segments read as one run of bytes.

    Segments are concatenated in the order given, and the boundary between
    two of them is invisible to the caller - a read that spans it is one read
    here and one read to whoever asked. That is the whole point: a filesystem
    structure does not stop at the point the imager's output hit 2 GB.
    """

    def __init__(self, paths, description=""):
        paths = [paths] if isinstance(paths, str) else list(paths)
        if not paths:
            raise ImageError("no image file given")
        self._spans = []              # (start, end, path)
        total = 0
        for p in paths:
            n = os.path.getsize(p)
            self._spans.append((total, total + n, p))
            total += n
        Image.__init__(self, paths[0], total,
                       description or ("raw image" if len(paths) == 1
                                       else "raw image, %d segments" % len(paths)))
        self.parts = paths
        self._open = {}

    def _handle(self, path):
        fh = self._open.get(path)
        if fh is None:
            fh = self._open[path] = open(path, "rb")
        return fh

    def _read_raw(self, offset, length):
        out = bytearray()
        end = offset + length
        for start, stop, path in self._spans:
            if stop <= offset or start >= end:
                continue
            fh = self._handle(path)
            fh.seek(offset + len(out) - start)
            want = min(stop, end) - (offset + len(out))
            got = fh.read(want)
            out += got
            if len(got) < want:
                break
        return bytes(out)

    def close(self):
        Image.close(self)
        for fh in self._open.values():
            try:
                fh.close()
            except Exception:
                pass
        self._open.clear()


class DeviceImage(Image):
    """A block device or physical drive, read directly.

    Reads on a Windows physical drive have to be sector-aligned in both offset
    and length or the handle returns nothing at all, so every read is widened
    to the chunk grid and trimmed afterwards - which the chunk cache was doing
    anyway. `chunk` is therefore a multiple of the sector size by construction.
    """

    def __init__(self, path):
        self._fh = open(path, "rb", buffering=0)
        self.read_errors = 0
        size = self._device_size(path, self._fh)
        Image.__init__(self, path, size, "device %s" % path)

    @staticmethod
    def _device_size(path, fh):
        try:
            return os.lseek(fh.fileno(), 0, os.SEEK_END)
        except OSError:
            pass
        if sys.platform == "win32":
            size = _win_drive_length(path)
            if size:
                return size
        raise ImageError("cannot determine the size of %s - open it as "
                         "Administrator/root, or image it to a file first" % path)

    def _read_raw(self, offset, length):
        if self.size:
            length = min(length, max(0, self.size - offset))
        if not length:
            return b""
        try:
            os.lseek(self._fh.fileno(), offset, os.SEEK_SET)
            return os.read(self._fh.fileno(), length)
        except OSError:
            # A bad sector is a fact about the disk, not a reason to stop -
            # the rest of the filesystem is still evidence. The count is kept
            # so the report can say how much of the disk would not read,
            # rather than presenting the zeroes as if they were content.
            self.read_errors += 1
            return b"\x00" * length

    def close(self):
        Image.close(self)
        try:
            self._fh.close()
        except Exception:
            pass


def _win_drive_length(path):
    """IOCTL_DISK_GET_LENGTH_INFO, for a \\\\.\\PhysicalDriveN that will not seek."""
    try:
        import ctypes
        from ctypes import wintypes
    except ImportError:
        return 0
    GENERIC_READ = 0x80000000
    FILE_SHARE = 0x00000003
    OPEN_EXISTING = 3
    IOCTL_DISK_GET_LENGTH_INFO = 0x0007405C
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateFileW.restype = wintypes.HANDLE
    handle = k32.CreateFileW(path, GENERIC_READ, FILE_SHARE, None,
                             OPEN_EXISTING, 0, None)
    if handle == wintypes.HANDLE(-1).value:
        return 0
    try:
        buf = ctypes.create_string_buffer(8)
        got = wintypes.DWORD(0)
        ok = k32.DeviceIoControl(handle, IOCTL_DISK_GET_LENGTH_INFO, None, 0,
                                 buf, 8, ctypes.byref(got), None)
        return _u64le(buf.raw) if ok else 0
    finally:
        k32.CloseHandle(handle)


# ---------------------------------------------------------------------------
# EWF / E01
# ---------------------------------------------------------------------------

EWF_SIG = b"EVF\x09\x0d\x0a\xff\x00"
EWF_L_SIG = b"LVF\x09\x0d\x0a\xff\x00"
EWF2_SIG = b"EVF2\x0d\x0a\x81\x00"


class E01Image(Image):
    """An EnCase evidence file set.

    A segment is a chain of sections; the ones that matter are `volume`/`disk`,
    which say how big the disk is and how it is cut into chunks, and the
    `sectors`/`table` pairs, which say where each chunk landed and whether it
    was deflated on the way in. Chunks are numbered across the whole set, so
    the segments are read in order and their tables appended.

    The compressed length of a chunk is not stored anywhere: it is the
    distance to the next chunk's offset, which is why the table is kept as a
    list of (offset, compressed) with a sentinel end rather than a dict.
    """

    def __init__(self, paths):
        paths = [paths] if isinstance(paths, str) else list(paths)
        self._segments = []
        self._offsets = []            # (segment index, file offset, compressed)
        self._ends = []               # end offset of each chunk in its segment
        self.sectors_per_chunk = 0
        self.bytes_per_sector = 512
        self.chunk_count = 0
        media_size = 0
        compressed_chunks = 0

        for idx, path in enumerate(paths):
            fh = open(path, "rb")
            self._segments.append(fh)
            sig = fh.read(8)
            if sig == EWF2_SIG:
                raise ImageError(
                    "%s is Ex01 (EnCase 7 format), which this reader does not "
                    "parse. Convert it with ewfexport, or image to raw."
                    % os.path.basename(path))
            if sig not in (EWF_SIG, EWF_L_SIG):
                raise ImageError("%s is not an EWF segment"
                                 % os.path.basename(path))
            if sig == EWF_L_SIG:
                raise ImageError(
                    "%s is a logical evidence file (L01): it holds selected "
                    "files, not a disk. Point --file at their export instead."
                    % os.path.basename(path))
            media_size = self._read_segment(fh, idx, media_size)

        for _seg, _off, comp in self._offsets:
            compressed_chunks += 1 if comp else 0
        if not self._offsets:
            raise ImageError("no chunk table found in the E01 set")
        self.chunk = self.sectors_per_chunk * self.bytes_per_sector or (1 << 16)
        Image.__init__(self, paths[0], media_size,
                       "E01, %d segment(s), %d chunk(s)%s"
                       % (len(paths), len(self._offsets),
                          ", %d%% compressed"
                          % (100 * compressed_chunks // len(self._offsets))
                          if compressed_chunks else ", uncompressed"))
        self.parts = paths

    # -- segment parsing ----------------------------------------------------
    def _read_segment(self, fh, idx, media_size):
        fh.seek(0, os.SEEK_END)
        seg_size = fh.tell()
        offset = 13                   # signature(8) + start-of-fields(1) + segno(2) + pad(2)
        seen = set()
        pending_sectors = None        # (start, end) of the last `sectors` section
        while 0 < offset < seg_size and offset not in seen:
            seen.add(offset)
            fh.seek(offset)
            desc = fh.read(76)
            if len(desc) < 76:
                break
            stype = desc[:16].split(b"\x00", 1)[0].decode("ascii", "replace")
            nxt = _u64le(desc, 16)
            size = _u64le(desc, 24)
            body_at = offset + 76
            body_len = max(0, int(size) - 76)

            if stype in ("volume", "disk"):
                fh.seek(body_at)
                media_size = self._read_volume(fh.read(min(body_len, 1052)),
                                               media_size)
            elif stype == "sectors":
                pending_sectors = (body_at, offset + int(size))
            elif stype in ("table", "table2"):
                if stype == "table":
                    fh.seek(body_at)
                    self._read_table(fh, idx, body_at, body_len,
                                     pending_sectors)
            elif stype in ("next", "done"):
                break
            if nxt == offset or nxt == 0:
                break
            offset = nxt
        return media_size

    def _read_volume(self, body, media_size):
        """How big the disk is, and how it was cut into chunks.

        The SMART and EnCase forms of this section put the counts in the same
        four places; they differ in what comes after, which nothing here needs.
        The sector count is the one field whose width changed: EnCase 5 and
        earlier wrote 4 bytes with 4 of padding behind them, EnCase 6 widened
        it to 8. Reading 8 covers both - the padding is zero - unless the
        result is absurd, which is what says the extra bytes are not padding.
        """
        chunk_count = _u32le(body, 4)
        spc = _u32le(body, 8)
        bps = _u32le(body, 12)
        sectors = _u64le(body, 16) if len(body) >= 24 else _u32le(body, 16)
        if sectors > (1 << 48):                # not a disk; the field is 32-bit
            sectors = _u32le(body, 16)
        if spc:
            self.sectors_per_chunk = spc
        if bps:
            self.bytes_per_sector = bps
        if chunk_count:
            self.chunk_count = chunk_count
        if sectors:
            return sectors * (bps or 512)
        # no sector count: the chunk table still says how much was acquired
        if chunk_count and spc and bps:
            return chunk_count * spc * bps
        return media_size

    def _read_table(self, fh, idx, body_at, body_len, pending_sectors):
        head = fh.read(24)
        if len(head) < 24:
            return
        count = _u32le(head, 0)
        base = _u64le(head, 8)
        if count <= 0 or count > 4 * 1024 * 1024:
            return
        raw = fh.read(4 * count)
        if len(raw) < 4 * count:
            return
        entries = struct.unpack("<%dI" % count, raw)
        # the length of a compressed chunk is the gap to the next one; the last
        # one runs to the end of the `sectors` section it lives in
        seg_end = pending_sectors[1] if pending_sectors else body_at + body_len
        starts = [base + (e & 0x7FFFFFFF) for e in entries]
        for i, e in enumerate(entries):
            start = starts[i]
            end = starts[i + 1] if i + 1 < count else seg_end
            if end <= start:
                end = start + self.sectors_per_chunk * self.bytes_per_sector + 4
            self._offsets.append((idx, start, bool(e & 0x80000000)))
            self._ends.append(end)

    # -- reading ------------------------------------------------------------
    def _read_raw(self, offset, length):
        index = offset // self.chunk
        if index >= len(self._offsets):
            return b""
        seg, start, compressed = self._offsets[index]
        end = self._ends[index]
        fh = self._segments[seg]
        fh.seek(start)
        raw = fh.read(max(0, end - start))
        if compressed:
            try:
                data = zlib.decompress(raw)
            except zlib.error:
                try:
                    data = zlib.decompressobj().decompress(raw)
                except zlib.error:
                    return b"\x00" * self.chunk
        else:
            data = raw[:self.chunk]
        return data[:self.chunk]

    def close(self):
        Image.close(self)
        for fh in self._segments:
            try:
                fh.close()
            except Exception:
                pass
        self._segments = []


# ---------------------------------------------------------------------------
# qcow2
# ---------------------------------------------------------------------------

QCOW_MAGIC = b"QFI\xfb"

# qcow2 v3 incompatible feature bits. A bit not named here changes how clusters
# are addressed, so an image carrying one is refused rather than read through a
# mapping that no longer describes it.
QCOW_INCOMPAT_DIRTY = 0x1
QCOW_INCOMPAT_CORRUPT = 0x2
QCOW_INCOMPAT_DATA_FILE = 0x4
QCOW_INCOMPAT_COMPRESSION = 0x8


class QCow2Image(_FileImage):
    """A QEMU qcow2 image, v2 or v3.

    Two levels of table map a virtual offset onto a cluster in the file, and
    an unmapped cluster falls through to the backing file - which is opened
    recursively, because a VM snapshot chain is the normal case and reading
    only the top layer of one gives a filesystem with holes in it rather than
    an error.
    """

    def __init__(self, path, _depth=0):
        _FileImage.__init__(self, path)
        fh = self._file()
        head = fh.read(104)
        if head[:4] != QCOW_MAGIC:
            raise ImageError("%s is not a qcow2 image" % os.path.basename(path))
        (version, backing_off, backing_size, cluster_bits, size,
         crypt) = struct.unpack_from(">IQIIQI", head, 4)
        if version not in (2, 3):
            raise ImageError("qcow version %d is not supported" % version)
        if crypt:
            raise ImageError(
                "%s is an encrypted qcow2 image. Decrypt it with qemu-img "
                "first - this reader will not guess at the key."
                % os.path.basename(path))
        self.version = version
        self.cluster_bits = cluster_bits
        self.chunk = 1 << cluster_bits
        self.l2_bits = cluster_bits - 3
        self.l1_size, self.l1_offset = struct.unpack_from(">IQ", head, 36)
        self.size = size
        self.compression = "zlib"
        self.dirty = False
        if version == 3:
            incompat = struct.unpack_from(">Q", head, 72)[0]
            header_len = struct.unpack_from(">I", head, 100)[0]
            # v3 incompatible bits: 1 dirty, 2 corrupt, 4 external data file,
            # 8 compression type, 16 extended L2 entries
            if incompat & QCOW_INCOMPAT_COMPRESSION and header_len > 104:
                fh.seek(104)
                self.compression = "zstd" if fh.read(1) == b"\x01" else "zlib"
            if incompat & QCOW_INCOMPAT_DATA_FILE:
                raise ImageError(
                    "%s keeps its data in an external file named in the "
                    "header, which this reader does not follow - "
                    "'qemu-img convert' it to a plain image first."
                    % os.path.basename(path))
            unknown = incompat & ~(QCOW_INCOMPAT_DIRTY | QCOW_INCOMPAT_CORRUPT
                                   | QCOW_INCOMPAT_DATA_FILE
                                   | QCOW_INCOMPAT_COMPRESSION)
            if unknown:
                raise ImageError(
                    "%s uses qcow2 incompatible features 0x%x that this reader "
                    "does not implement - reading it would return plausible "
                    "wrong bytes, so it is refused."
                    % (os.path.basename(path), unknown))
            # dirty and corrupt are facts about the image, not reasons to
            # refuse it: an image pulled from a host mid-write is exactly the
            # kind that gets examined, and saying so beats declining to look
            self.dirty = bool(incompat & (QCOW_INCOMPAT_DIRTY
                                          | QCOW_INCOMPAT_CORRUPT))
        # the L1 table is small and read once
        fh.seek(self.l1_offset)
        raw = fh.read(8 * self.l1_size)
        self.l1 = struct.unpack(">%dQ" % (len(raw) // 8), raw) if raw else ()
        self._l2_cache = OrderedDict()

        self.backing = None
        if backing_off and backing_size:
            fh.seek(backing_off)
            name = fh.read(backing_size).decode("utf-8", "replace")
            self.backing = self._open_backing(path, name, _depth)

        parts = [path] + (list(self.backing.parts) if self.backing else [])
        self.parts = parts
        self.description = ("qcow2 v%d, %d KiB clusters%s%s%s"
                            % (version, self.chunk // 1024,
                               ", %s compression" % self.compression
                               if self.compression != "zlib" else "",
                               ", backed by %s" % os.path.basename(
                                   self.backing.path) if self.backing else "",
                               ", marked dirty" if self.dirty else ""))

    @staticmethod
    def _open_backing(path, name, depth):
        if depth > 16:
            raise ImageError("qcow2 backing chain is more than 16 deep")
        cand = name if os.path.isabs(name) else \
            os.path.join(os.path.dirname(os.path.abspath(path)), name)
        if not os.path.exists(cand):
            raise ImageError(
                "%s is backed by %s, which is not beside it. A qcow2 overlay "
                "without its backing file is a disk with holes in it, so this "
                "is refused rather than read." % (os.path.basename(path), name))
        with open(cand, "rb") as bh:
            magic = bh.read(4)
        if magic == QCOW_MAGIC:
            return QCow2Image(cand, depth + 1)
        return RawImage([cand])

    def _l2_table(self, offset):
        table = self._l2_cache.get(offset)
        if table is None:
            fh = self._file()
            fh.seek(offset)
            raw = fh.read(self.chunk)
            n = len(raw) // 8
            table = struct.unpack(">%dQ" % n, raw[:n * 8]) if n else ()
            self._l2_cache[offset] = table
            if len(self._l2_cache) > 64:
                self._l2_cache.popitem(last=False)
        return table

    def _read_raw(self, offset, length):
        l1_index = offset >> (self.cluster_bits + self.l2_bits)
        if l1_index >= len(self.l1):
            return self._from_backing(offset)
        l1e = self.l1[l1_index] & 0x00FFFFFFFFFFFE00
        if not l1e:
            return self._from_backing(offset)
        l2 = self._l2_table(l1e)
        l2_index = (offset >> self.cluster_bits) & ((1 << self.l2_bits) - 1)
        if l2_index >= len(l2):
            return self._from_backing(offset)
        entry = l2[l2_index]
        if entry & (1 << 62):
            return self._read_compressed(entry)
        host = entry & 0x00FFFFFFFFFFFE00
        if not host:
            return self._from_backing(offset)
        if entry & 1:                              # all-zeroes cluster
            return b"\x00" * self.chunk
        fh = self._file()
        fh.seek(host)
        return fh.read(self.chunk)

    def _read_compressed(self, entry):
        bits = 62 - (self.cluster_bits - 8)
        host = entry & ((1 << bits) - 1)
        sectors = ((entry >> bits) & ((1 << (62 - bits)) - 1)) + 1
        fh = self._file()
        fh.seek(host)
        # the run may start mid-sector, so read one sector more than the count
        raw = fh.read(sectors * 512 + 512)
        try:
            if self.compression == "zstd":
                return _zstd(raw)[:self.chunk]
            return zlib.decompressobj(-zlib.MAX_WBITS).decompress(raw)[:self.chunk]
        except Exception:
            return b"\x00" * self.chunk

    def _from_backing(self, offset):
        if self.backing is None:
            return b"\x00" * self.chunk
        return self.backing.read(offset, self.chunk)

    def close(self):
        _FileImage.close(self)
        if self.backing is not None:
            self.backing.close()


def _zstd(raw):
    try:
        from compression import zstd                # Python 3.14+
        return zstd.decompress(raw)
    except ImportError:
        pass
    try:
        import zstandard
        return zstandard.ZstdDecompressor().decompressobj().decompress(raw)
    except ImportError:
        raise ImageError("this image uses zstd compression and no zstd "
                         "decompressor is available (Python 3.14+, or the "
                         "zstandard package)")


# ---------------------------------------------------------------------------
# vmdk
# ---------------------------------------------------------------------------

VMDK_SPARSE_MAGIC = b"KDMV"


class VmdkImage(Image):
    """A VMware virtual disk.

    Two things arrive called .vmdk. One is a text descriptor listing extents
    that live in other files - which is what VMware writes for a flat or a
    2 GB-split disk, and where the bytes are in those other files. The other
    is the sparse binary format, with a grain directory and grain tables.
    Both end up here as one addressable disk, and a descriptor whose extents
    are themselves sparse nests one inside the other.
    """

    def __init__(self, path):
        self._extents = []            # (start, end, Image, offset within it)
        self._owned = []
        with open(path, "rb") as fh:
            head = fh.read(4)
        if head == VMDK_SPARSE_MAGIC:
            inner = _VmdkSparse(path)
            self._owned.append(inner)
            self._extents.append((0, inner.size, inner, 0))
            total = inner.size
            desc = "vmdk sparse, %d KiB grains" % (inner.chunk // 1024)
        else:
            total, desc = self._from_descriptor(path)
        Image.__init__(self, path, total, desc)
        self.parts = [path] + [p for img in self._owned for p in img.parts]
        self.chunk = min((img.chunk for _s, _e, img, _o in self._extents),
                         default=1 << 16)

    def _from_descriptor(self, path):
        with open(path, "rb") as fh:
            text = fh.read(1 << 20).decode("utf-8", "replace")
        if "# Disk DescriptorFile" not in text and "createType" not in text:
            raise ImageError("%s is neither a sparse vmdk nor a vmdk "
                             "descriptor" % os.path.basename(path))
        base = os.path.dirname(os.path.abspath(path))
        total = 0
        kinds = set()
        for line in text.splitlines():
            m = re.match(r'^\s*(RW|RDONLY|NOACCESS)\s+(\d+)\s+(\w+)\s+"([^"]+)"'
                         r'(?:\s+(\d+))?', line)
            if not m:
                continue
            sectors, kind, name, skip = (int(m.group(2)), m.group(3).upper(),
                                         m.group(4), int(m.group(5) or 0))
            length = sectors * 512
            kinds.add(kind)
            if kind in ("ZERO",):
                self._extents.append((total, total + length, None, 0))
                total += length
                continue
            target = name if os.path.isabs(name) else os.path.join(base, name)
            if not os.path.exists(target):
                raise ImageError(
                    "%s lists the extent %s, which is not beside it - a split "
                    "vmdk has to be kept together"
                    % (os.path.basename(path), name))
            if kind == "SPARSE":
                img = _VmdkSparse(target)
                self._owned.append(img)
                self._extents.append((total, total + img.size, img, 0))
                total += img.size
            else:                                  # FLAT / VMFS / VMFSRAW
                img = RawImage([target])
                self._owned.append(img)
                self._extents.append((total, total + length, img, skip * 512))
                total += length
        if not self._extents:
            raise ImageError("%s lists no extents" % os.path.basename(path))
        return total, ("vmdk descriptor, %d extent(s) (%s)"
                       % (len(self._extents), "/".join(sorted(kinds)).lower()))

    def _read_raw(self, offset, length):
        out = bytearray()
        end = offset + length
        for start, stop, img, skew in self._extents:
            if stop <= offset or start >= end:
                continue
            here = offset + len(out)
            want = min(stop, end) - here
            if img is None:
                out += b"\x00" * want
            else:
                out += img.read(here - start + skew, want)
        return bytes(out)

    def close(self):
        Image.close(self)
        for img in self._owned:
            img.close()


class _VmdkSparse(_FileImage):
    """One monolithicSparse / twoGbMaxExtentSparse / streamOptimized extent."""

    def __init__(self, path):
        _FileImage.__init__(self, path)
        fh = self._file()
        head = fh.read(80)
        if head[:4] != VMDK_SPARSE_MAGIC:
            raise ImageError("%s is not a sparse vmdk extent"
                             % os.path.basename(path))
        (version, flags, capacity, grain_size, desc_off, desc_size,
         gte_per_gt, rgd_off, gd_off, overhead) = struct.unpack_from(
            "<IIQQQQIQQQ", head, 4)
        self.size = capacity * 512
        self.chunk = max(512, grain_size * 512)
        self.gte_per_gt = gte_per_gt or 512
        self.compressed = bool(flags & (1 << 16))
        self._gd = []
        table_off = gd_off or rgd_off
        if table_off in (0, 0xFFFFFFFFFFFFFFFF):
            # streamOptimized keeps the directory at the end, pointed at by the
            # footer - the last sector before the end-of-stream marker
            table_off = self._stream_gd(fh)
        if table_off:
            entries = (self.size + self.chunk * self.gte_per_gt - 1) // \
                      (self.chunk * self.gte_per_gt)
            fh.seek(table_off * 512)
            raw = fh.read(4 * entries)
            self._gd = struct.unpack("<%dI" % (len(raw) // 4), raw)
        self._gt_cache = OrderedDict()
        self.description = "vmdk sparse v%d" % version

    def _stream_gd(self, fh):
        fh.seek(0, os.SEEK_END)
        end = fh.tell()
        # footer marker: the second-to-last sector holds a copy of the header
        for back in (1024, 1536, 512):
            if end < back:
                continue
            fh.seek(end - back)
            blob = fh.read(512)
            if blob[:4] == VMDK_SPARSE_MAGIC:
                return struct.unpack_from("<Q", blob, 56)[0]
        return 0

    def _grain_table(self, sector):
        table = self._gt_cache.get(sector)
        if table is None:
            fh = self._file()
            fh.seek(sector * 512)
            raw = fh.read(4 * self.gte_per_gt)
            table = struct.unpack("<%dI" % (len(raw) // 4), raw)
            self._gt_cache[sector] = table
            if len(self._gt_cache) > 64:
                self._gt_cache.popitem(last=False)
        return table

    def _read_raw(self, offset, length):
        grain = offset // self.chunk
        gd_index = grain // self.gte_per_gt
        if gd_index >= len(self._gd) or not self._gd[gd_index]:
            return b"\x00" * self.chunk
        table = self._grain_table(self._gd[gd_index])
        gt_index = grain % self.gte_per_gt
        if gt_index >= len(table) or not table[gt_index]:
            return b"\x00" * self.chunk
        fh = self._file()
        at = table[gt_index] * 512
        if not self.compressed:
            fh.seek(at)
            return fh.read(self.chunk)
        fh.seek(at)
        marker = fh.read(12)
        if len(marker) < 12:
            return b"\x00" * self.chunk
        size = _u32le(marker, 8)
        raw = fh.read(size)
        try:
            return zlib.decompress(raw)[:self.chunk]
        except zlib.error:
            return b"\x00" * self.chunk


# ---------------------------------------------------------------------------
# vhdx / vhd
# ---------------------------------------------------------------------------

VHDX_SIG = b"vhdxfile"
VHD_COOKIE = b"conectix"

_BAT_GUID = b"\x66\x77\xC2\x2D\x23\xF6\x00\x42\x9D\x64\x11\x5E\x9B\xFD\x4A\x08"
_META_GUID = b"\x06\xA2\x7C\x8B\x90\x47\x9A\x4B\xB8\xFE\x57\x5F\x05\x0F\x88\x6E"
_M_SIZE = b"\x24\x42\xA5\x2F\x1B\xCD\x76\x48\xB2\x11\x5D\xBE\xD8\x3B\xF4\xB8"
_M_SECTOR = b"\x1D\xBF\x41\x81\x6F\xA9\x09\x47\xBA\x47\xF2\x33\xA8\xFA\xAB\x5F"
_M_PARAMS = b"\x37\x67\xA1\xCA\x36\xFA\x43\x4D\xB3\xB6\x33\xF0\xAA\x44\xE7\x6B"


class VhdxImage(_FileImage):
    """A Hyper-V VHDX, dynamic or fixed.

    The block allocation table interleaves payload entries with sector-bitmap
    entries at a ratio the metadata gives, so the index of a block is not the
    index of its BAT entry - getting that wrong reads a bitmap as data every
    few hundred megabytes, which looks like scattered corruption rather than
    like a bug.
    """

    def __init__(self, path):
        _FileImage.__init__(self, path)
        fh = self._file()
        if fh.read(8) != VHDX_SIG:
            raise ImageError("%s is not a VHDX" % os.path.basename(path))
        regions = self._read_regions(fh)
        if _BAT_GUID not in regions or _META_GUID not in regions:
            raise ImageError("%s has no BAT or metadata region"
                             % os.path.basename(path))
        meta = self._read_metadata(fh, regions[_META_GUID][0])
        self.size = meta.get("size", 0)
        self.sector_size = meta.get("sector", 512)
        self.chunk = meta.get("block", 2 * 1024 * 1024)
        if meta.get("has_parent"):
            raise ImageError(
                "%s is a differencing VHDX and its parent is not read by this "
                "reader. Merge it with Convert-VHD or qemu-img first."
                % os.path.basename(path))
        self.chunk_ratio = max(1, (1 << 23) * self.sector_size // self.chunk)
        bat_off, bat_len = regions[_BAT_GUID]
        fh.seek(bat_off)
        raw = fh.read(bat_len)
        self._bat = struct.unpack("<%dQ" % (len(raw) // 8), raw[:len(raw) // 8 * 8])
        self.description = ("vhdx, %d MiB blocks, %d sector"
                            % (self.chunk // (1 << 20), self.sector_size))

    @staticmethod
    def _read_regions(fh):
        out = {}
        for at in (0x30000, 0x40000):
            fh.seek(at)
            head = fh.read(16)
            if head[:4] != b"regi":
                continue
            count = _u32le(head, 8)
            raw = fh.read(32 * min(count, 2047))
            for i in range(len(raw) // 32):
                guid = raw[i * 32:i * 32 + 16]
                off = _u64le(raw, i * 32 + 16)
                length = _u32le(raw, i * 32 + 24)
                out.setdefault(guid, (off, length))
            if out:
                break
        return out

    @staticmethod
    def _read_metadata(fh, offset):
        fh.seek(offset)
        head = fh.read(32)
        if head[:8] != b"metadata":
            return {}
        count = struct.unpack_from("<H", head, 10)[0]
        raw = fh.read(32 * min(count, 2047))
        out = {}
        for i in range(len(raw) // 32):
            item = raw[i * 32:i * 32 + 16]
            at = _u32le(raw, i * 32 + 16)
            length = _u32le(raw, i * 32 + 20)
            fh.seek(offset + at)
            body = fh.read(length)
            if item == _M_SIZE and len(body) >= 8:
                out["size"] = _u64le(body)
            elif item == _M_SECTOR and len(body) >= 4:
                out["sector"] = _u32le(body)
            elif item == _M_PARAMS and len(body) >= 8:
                out["block"] = _u32le(body)
                out["has_parent"] = bool(_u32le(body, 4) & 0x2)
        return out

    def _read_raw(self, offset, length):
        block = offset // self.chunk
        index = block + block // self.chunk_ratio
        if index >= len(self._bat):
            return b"\x00" * self.chunk
        entry = self._bat[index]
        state = entry & 0x7
        if state != 6:                # anything but FULLY_PRESENT reads as zero
            return b"\x00" * self.chunk
        at = ((entry >> 20) & ((1 << 44) - 1)) * (1 << 20)
        fh = self._file()
        fh.seek(at)
        return fh.read(self.chunk)


class VhdImage(_FileImage):
    """A pre-VHDX Hyper-V/Virtual PC disk, fixed or dynamic."""

    def __init__(self, path):
        _FileImage.__init__(self, path)
        fh = self._file()
        fh.seek(0, os.SEEK_END)
        end = fh.tell()
        fh.seek(max(0, end - 512))
        footer = fh.read(512)
        if footer[:8] != VHD_COOKIE:
            fh.seek(0)
            footer = fh.read(512)
            if footer[:8] != VHD_COOKIE:
                raise ImageError("%s is not a VHD" % os.path.basename(path))
        self.size = struct.unpack_from(">Q", footer, 48)[0]
        disk_type = struct.unpack_from(">I", footer, 60)[0]
        self._bat = ()
        self.chunk = 1 << 21
        if disk_type == 2:                          # fixed
            self.description = "vhd, fixed"
            self.chunk = 1 << 16
            self._flat = True
            return
        if disk_type == 4:
            raise ImageError("%s is a differencing VHD; merge it first"
                             % os.path.basename(path))
        self._flat = False
        head_off = struct.unpack_from(">Q", footer, 16)[0]
        fh.seek(head_off)
        dyn = fh.read(1024)
        if dyn[:8] != b"cxsparse":
            raise ImageError("%s has no dynamic disk header"
                             % os.path.basename(path))
        bat_off = struct.unpack_from(">Q", dyn, 16)[0]
        max_entries = struct.unpack_from(">I", dyn, 28)[0]
        self.chunk = struct.unpack_from(">I", dyn, 32)[0] or (1 << 21)
        fh.seek(bat_off)
        raw = fh.read(4 * max_entries)
        self._bat = struct.unpack(">%dI" % (len(raw) // 4), raw)
        # the sector bitmap in front of each block is padded to a sector
        self._bitmap = ((self.chunk // 512 // 8) + 511) // 512 * 512
        self.description = "vhd, dynamic, %d KiB blocks" % (self.chunk // 1024)

    def _read_raw(self, offset, length):
        fh = self._file()
        if self._flat:
            fh.seek(offset)
            return fh.read(self.chunk)
        index = offset // self.chunk
        if index >= len(self._bat) or self._bat[index] == 0xFFFFFFFF:
            return b"\x00" * self.chunk
        fh.seek(self._bat[index] * 512 + self._bitmap)
        return fh.read(self.chunk)


# ---------------------------------------------------------------------------
# what is this file, and what else belongs with it
# ---------------------------------------------------------------------------

# A split raw set, by how the imager numbered it. The pattern has to name the
# whole set from any one member, because an analyst points at whichever
# segment they happened to click on.
SPLIT_PATTERNS = (
    re.compile(r"^(?P<stem>.+?)\.(?P<n>\d{3})$"),          # image.001
    re.compile(r"^(?P<stem>.+?\.(?:dd|raw|img|bin))\.(?P<n>\d+)$"),
    re.compile(r"^(?P<stem>.+?)\.(?P<n>[a-z]{2})$"),        # split -b: .aa .ab
)

E01_SEG = re.compile(r"^(?P<stem>.+)\.(?P<n>[Ee][0-9A-Za-z]{2})$")


def _split_set(path):
    """Every segment of a split raw set that `path` belongs to, in order."""
    directory, name = os.path.split(os.path.abspath(path))
    for rx in SPLIT_PATTERNS:
        m = rx.match(name)
        if not m:
            continue
        stem, width = m.group("stem"), len(m.group("n"))
        alpha = m.group("n").isalpha()
        found = []
        for other in os.listdir(directory or "."):
            om = rx.match(other)
            if om and om.group("stem") == stem and len(om.group("n")) == width \
                    and om.group("n").isalpha() == alpha:
                found.append(other)
        if len(found) > 1:
            found.sort()
            return [os.path.join(directory, f) for f in found]
    return [os.path.abspath(path)]


def e01_set(path):
    """Every segment of an E01 set, in EnCase's own ordering.

    EnCase counts E01..E99 and then rolls over into EAA..ZZZ, so a plain
    lexical sort puts EAA before E02 and the disk reads as a few gigabytes
    followed by nonsense. Numeric segments sort before alphabetic ones and
    each group sorts within itself.
    """
    directory, name = os.path.split(os.path.abspath(path))
    m = E01_SEG.match(name)
    if not m:
        return [os.path.abspath(path)]
    stem = m.group("stem")
    found = []
    for other in os.listdir(directory or "."):
        om = E01_SEG.match(other)
        if om and om.group("stem") == stem:
            found.append(other)
    if not found:
        return [os.path.abspath(path)]

    def key(fn):
        tag = E01_SEG.match(fn).group("n")[1:]
        return (0, int(tag)) if tag.isdigit() else (1, tag.upper())

    found.sort(key=key)
    return [os.path.join(directory, f) for f in found]


#: extensions that say "this is a disk", used when sniffing cannot
DISK_EXTENSIONS = (".dd", ".raw", ".img", ".bin", ".e01", ".ex01", ".s01",
                   ".qcow2", ".qcow", ".qed", ".vmdk", ".vhdx", ".vhd",
                   ".vdi", ".001")


def sniff(path):
    """What kind of container is this? A name, or '' if it is not a disk."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(2048)
    except OSError:
        return ""
    if head[:8] in (EWF_SIG, EWF_L_SIG) or head[:8] == EWF2_SIG:
        return "e01"
    if head[:4] == QCOW_MAGIC:
        return "qcow2"
    if head[:4] == VMDK_SPARSE_MAGIC:
        return "vmdk"
    if head[:8] == VHDX_SIG:
        return "vhdx"
    if head[:8] == VHD_COOKIE:
        return "vhd"
    if head[:21] == b"# Disk DescriptorFile" or b"createType=" in head[:2048]:
        return "vmdk"
    if head[:4] == b"<<< ":                        # VirtualBox VDI
        return "vdi"
    # a VHD footer lives at the end, and a fixed VHD has nothing at the front
    try:
        with open(path, "rb") as fh:
            fh.seek(-512, os.SEEK_END)
            if fh.read(8) == VHD_COOKIE:
                return "vhd"
    except OSError:
        pass
    return "raw" if _looks_like_a_disk(head) else ""


def _looks_like_a_disk(head):
    """Whether a headerless file starts with something a disk starts with.

    A raw image has no magic of its own, so the question is whether the first
    sector is a partition table or a filesystem superblock. Anything else is
    someone's tarball and should be routed to the collection reader instead.
    """
    if len(head) < 1082:
        return False
    if head[510:512] == b"\x55\xaa":               # MBR / protective MBR
        return True
    if head[512:520] == b"EFI PART":               # GPT with a 512 sector
        return True
    if head[1024 + 56:1024 + 58] == b"\x53\xef":   # ext superblock magic
        return True
    if head[:4] == b"XFSB":
        return True
    return False


class VdiUnsupported(ImageError):
    pass


def open_image(path, quiet=False):
    """Open whatever kind of disk container `path` is.

    Split sets and E01 segment sets are gathered here: an analyst points at
    one file and gets the whole disk, because pointing at `image.003` and
    quietly examining a third of a disk is the failure this has to prevent.
    """
    path = os.path.abspath(path)
    if _is_device(path):
        return DeviceImage(path)
    if not os.path.exists(path):
        raise ImageError("%s does not exist" % path)

    kind = sniff(path)
    if kind == "e01":
        return E01Image(e01_set(path))
    if kind == "qcow2":
        return QCow2Image(path)
    if kind == "vmdk":
        return VmdkImage(path)
    if kind == "vhdx":
        return VhdxImage(path)
    if kind == "vhd":
        return VhdImage(path)
    if kind == "vdi":
        raise VdiUnsupported(
            "%s is a VirtualBox VDI, which this reader does not parse. "
            "'VBoxManage clonemedium disk %s out.raw --format RAW' converts it."
            % (os.path.basename(path), os.path.basename(path)))
    segments = _split_set(path)
    if kind == "raw" or len(segments) > 1 or \
            os.path.splitext(path)[1].lower() in DISK_EXTENSIONS:
        return RawImage(segments)
    raise ImageError("%s does not look like a disk image - no partition table, "
                     "no filesystem superblock, no container header"
                     % os.path.basename(path))


def _is_device(path):
    if path.replace("/", "\\").upper().startswith("\\\\.\\"):
        return True
    try:
        import stat
        mode = os.stat(path).st_mode
        return stat.S_ISBLK(mode) or stat.S_ISCHR(mode)
    except (OSError, AttributeError):
        return False


def looks_like_disk(path):
    """Cheap yes/no, for deciding whether to route an argument here at all."""
    if _is_device(path):
        return True
    if not os.path.isfile(path):
        return False
    if os.path.splitext(path)[1].lower() in DISK_EXTENSIONS:
        return True
    return bool(sniff(path))
