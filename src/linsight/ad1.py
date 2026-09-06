# -*- coding: utf-8 -*-
"""AccessData logical images: AD1, as a collection.

An AD1 is what FTK Imager writes when someone acquires files rather than a
disk - "Custom Content Image", the everyday output of "give me /etc, /var/log
and the home directories off this box". It arrives constantly in Linux cases,
and it is a tree of files with their metadata, which is exactly what the
collection layer above this module already takes.

So an AD1 is a fifth backend, beside the directory, tar, zip and disk ones.
Every analyzer, every table, Sigma, YARA, the timeline and the console run
over one unchanged, because from where they sit it is a set of paths.

What the format gives, and this reader keeps:

  four timestamps   atime, mtime, ctime and crtime per entry, so BODYFILE and
                    the timeline carry creation times off a logical image the
                    same way they do off a disk
  stored hashes     FTK records MD5 and SHA-1 for every file as it acquires
                    it. Those go into FILE_HASHES, which means a VT-ready
                    hash list comes out of an AD1 with nothing else run.
  owner and mode    uid, gid and the mode string, straight from the source
                    filesystem rather than from whatever unpacked it

The stored hashes are also how this reader is tested: every file it extracts
is checked against the MD5 and SHA-1 the imager wrote next to it. A container
format that carries its own per-file checksums can be verified rather than
eyeballed, which is a better position than most of the disk formats allow.

The layout, which is not documented by the vendor and was read off real
images:

  segment header   'ADSEGMENTEDFILE\\0', then the header size and the number
                   of segments. The logical stream is every segment's body,
                   in order, with each header skipped - so a set split across
                   .ad1/.ad2/.ad3 reads as one run of bytes and every offset
                   below indexes into that, not into any one file.
  image header     'ADLOGICALIMAGE\\0\\0', the chunk size, and the offset of
                   the root entry
  entry            next sibling, first child, attribute list, data, size,
                   type, name - then the parent, which is what makes the tree
                   walkable in both directions
  attributes       a linked list of (id, value) pairs, values as text
  data             a chunk count, then count+1 offsets, then deflated chunks
"""

from __future__ import annotations

import hashlib
import io
import os
import re
import struct
import zlib
from collections import OrderedDict
from datetime import datetime, timezone

from .term import status
from .fsbase import ExtentFile, GeneratedLines, epoch_seconds
from .collect import Collection

AD1_SEGMENT_MAGIC = b"ADSEGMENTEDFILE\x00"
AD1_LOGICAL_MAGIC = b"ADLOGICALIMAGE\x00\x00"
AD1_CRYPT_MAGIC = b"ADCRYPTEDFILE\x00"

#: Entry type codes. The mode string is the authority on what an entry is -
#: it comes from the source filesystem - so these are only a fallback for an
#: entry that has no mode recorded.
TYPE_FILE = 0
TYPE_DIR = 5

#: Attribute ids, as they appear on a Linux acquisition.
#:
#: The four timestamps are not labelled in the format, and getting them wrong
#: silently rewrites the timeline, so they were not guessed. Two invariants
#: the source filesystem cannot break decide it: ctime is updated whenever
#: mtime is, so ctime >= mtime; and a file cannot be changed before it is
#: created, so crtime <= ctime. Tried against every pairing over a real
#: acquisition, only one assignment survives both - and it agrees with the
#: independent evidence that a distribution-packaged file keeps the package's
#: build date as its mtime and the install date as its crtime.
A_LOGICAL_SIZE = 0x3
A_PHYSICAL_SIZE = 0x4
A_START_BLOCK = 0x6
A_ATIME = 0x7
A_CRTIME = 0x8
A_MTIME = 0x9
A_ALLOCATED = 0x1E
A_MODE = 0x2001
A_UID = 0x2002
A_GID = 0x2003
A_MD5 = 0x5001
A_SHA1 = 0x5002
A_INODE = 0xC001
A_CTIME = 0xC003

#: Names FTK gives the synthetic top level of an acquisition. A child of the
#: image root called this is a filesystem root, and its children are host
#: absolute paths; anything else is a folder someone selected and keeps its
#: own name in the path.
ROOT_MARKERS = ("[root]", "[Root]", "/")

TIMESTAMP_RE = re.compile(r"^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})")


class Ad1Error(Exception):
    pass


# ---------------------------------------------------------------------------
# the byte stream under the format
# ---------------------------------------------------------------------------

class _Stream(object):
    """The logical bytes of an AD1 set, with every segment header skipped.

    An AD1 split across .ad1/.ad2/.ad3 numbers its structures against the
    concatenation of the segment bodies, not against any one file. Reading
    only the first segment therefore works perfectly until the first offset
    past its end, and then returns whatever happens to be at the wrong place -
    which is the failure this class exists to make impossible.
    """

    def __init__(self, paths, header_size):
        self._files = []
        self._spans = []                 # (logical start, logical end, index)
        total = 0
        for path in paths:
            size = os.path.getsize(path)
            body = max(0, size - header_size)
            self._spans.append((total, total + body, len(self._files)))
            self._files.append([path, None, header_size])
            total += body
        self.size = total
        self.parts = list(paths)

    def _handle(self, index):
        slot = self._files[index]
        if slot[1] is None:
            slot[1] = open(slot[0], "rb")
        return slot[1], slot[2]

    def read(self, offset, length):
        if length <= 0 or offset < 0:
            return b""
        out = bytearray()
        end = offset + length
        for start, stop, index in self._spans:
            if stop <= offset or start >= end:
                continue
            fh, skew = self._handle(index)
            here = offset + len(out)
            fh.seek(skew + (here - start))
            want = min(stop, end) - here
            got = fh.read(want)
            out += got
            if len(got) < want:
                break
        return bytes(out)

    def close(self):
        for slot in self._files:
            if slot[1] is not None:
                try:
                    slot[1].close()
                except Exception:
                    pass
                slot[1] = None


def _u32(b, o=0):
    return struct.unpack_from("<I", b, o)[0]


def _u64(b, o=0):
    return struct.unpack_from("<Q", b, o)[0]


def ad1_segments(path):
    """Every segment of the AD1 set `path` belongs to, in order.

    FTK numbers the segments .ad1, .ad2, .ad3 and keeps counting past .ad9
    into .ad10, so they are ordered numerically rather than lexically - a
    lexical sort puts .ad10 between .ad1 and .ad2 and reads the image in the
    wrong order without ever failing.
    """
    directory, name = os.path.split(os.path.abspath(path))
    m = re.match(r"^(?P<stem>.+)\.ad(?P<n>\d+)$", name, re.I)
    if not m:
        return [os.path.abspath(path)]
    stem = m.group("stem")
    found = []
    for other in os.listdir(directory or "."):
        om = re.match(r"^(?P<stem>.+)\.ad(?P<n>\d+)$", other, re.I)
        if om and om.group("stem").lower() == stem.lower():
            found.append((int(om.group("n")), other))
    if not found:
        return [os.path.abspath(path)]
    found.sort()
    return [os.path.join(directory, f) for _n, f in found]


def looks_like_ad1(path):
    """Cheap yes/no for the command line."""
    try:
        with open(path, "rb") as fh:
            return fh.read(16) == AD1_SEGMENT_MAGIC
    except OSError:
        return False


# ---------------------------------------------------------------------------
# the tree
# ---------------------------------------------------------------------------

class Ad1Entry(object):
    """One item in an AD1: a file, a directory, or whatever the mode says."""

    __slots__ = ("path", "name", "offset", "size", "type", "attrs",
                 "data_offset", "child", "next", "kind", "mode", "uid", "gid",
                 "inode", "atime", "mtime", "ctime", "crtime", "md5", "sha1",
                 "on_disk_size")

    def __init__(self):
        self.path = ""
        self.name = ""
        self.offset = 0
        self.size = 0
        self.type = 0
        self.attrs = {}
        self.data_offset = 0
        self.child = 0
        self.next = 0
        self.kind = "f"
        self.mode = ""
        self.uid = ""
        self.gid = ""
        self.inode = ""
        self.atime = None
        self.mtime = None
        self.ctime = None
        self.crtime = None
        self.md5 = ""
        self.sha1 = ""
        self.on_disk_size = ""

    def __repr__(self):
        return "<Ad1Entry %s %s %d>" % (self.kind, self.path, self.size)


def _parse_time(text):
    """'20190314T031653' -> an aware datetime, or None.

    FTK writes these in UTC. A value that does not match the shape is dropped
    rather than coerced: a timestamp guessed wrong is worse than one missing,
    because the missing one is visible.
    """
    if not text:
        return None
    m = TIMESTAMP_RE.match(text.strip())
    if not m:
        return None
    try:
        return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)),
                        int(m.group(4)), int(m.group(5)), int(m.group(6)),
                        tzinfo=timezone.utc)
    except ValueError:
        return None


class Ad1Reader(object):
    """Random access to the entries and file content of an AD1 set."""

    def __init__(self, paths):
        paths = [paths] if isinstance(paths, str) else list(paths)
        head = open(paths[0], "rb").read(64)
        if head[:14] == AD1_CRYPT_MAGIC[:14]:
            raise Ad1Error(
                "%s is an encrypted AccessData image. Decrypt it in FTK "
                "Imager first - this reader will not guess at the key."
                % os.path.basename(paths[0]))
        if head[:16] != AD1_SEGMENT_MAGIC:
            raise Ad1Error("%s is not an AD1" % os.path.basename(paths[0]))
        self.segment_count = _u32(head, 0x1C) or 1
        header_size = _u32(head, 0x28) or 512
        if not (16 <= header_size <= 65536):
            raise Ad1Error("implausible AD1 header size %d" % header_size)
        self.header_size = header_size
        if len(paths) < self.segment_count:
            raise Ad1Error(
                "%s is segment 1 of %d and only %d %s here. An AD1 set has to "
                "be kept together: the offsets inside it run across the whole "
                "set, so a missing segment is not a shorter image, it is a "
                "wrong one."
                % (os.path.basename(paths[0]), self.segment_count, len(paths),
                   "is" if len(paths) == 1 else "are"))
        self.stream = _Stream(paths[:self.segment_count], header_size)
        self.parts = self.stream.parts

        image = self.stream.read(0, 64)
        if image[:16] != AD1_LOGICAL_MAGIC:
            raise Ad1Error("%s has no AD1 logical image header"
                           % os.path.basename(paths[0]))
        self.version = _u32(image, 0x10)
        self.chunk_size = _u32(image, 0x18) or 65536
        self.root_offset = _u64(image, 0x24)
        if self.version not in (2, 3, 4):
            raise Ad1Error(
                "%s is AD1 version %d, which this reader has not been shown. "
                "Export its contents with FTK Imager instead."
                % (os.path.basename(paths[0]), self.version))
        self._entry_cache = OrderedDict()
        self.image_name = self.entry(self.root_offset).name

    # -- structures ---------------------------------------------------------
    def entry(self, offset):
        cached = self._entry_cache.get(offset)
        if cached is not None:
            return cached
        raw = self.stream.read(offset, 48)
        if len(raw) < 48:
            raise Ad1Error("truncated AD1 entry at %d" % offset)
        e = Ad1Entry()
        e.offset = offset
        e.next = _u64(raw, 0)
        e.child = _u64(raw, 8)
        attr_list = _u64(raw, 16)
        e.data_offset = _u64(raw, 24)
        e.size = _u64(raw, 32)
        e.type = _u32(raw, 40)
        name_len = _u32(raw, 44)
        if name_len > 65535:
            raise Ad1Error("implausible AD1 name length %d at %d"
                           % (name_len, offset))
        e.name = self.stream.read(offset + 48, name_len).decode(
            "utf-8", "surrogateescape")
        e.attrs = self._attributes(attr_list)
        self._decorate(e)
        if len(self._entry_cache) < 4096:
            self._entry_cache[offset] = e
        return e

    def _attributes(self, list_offset):
        """The linked list of (id -> text) an entry hangs its metadata on."""
        if not list_offset:
            return {}
        first = _u64(self.stream.read(list_offset, 8), 0)
        out = {}
        at = first
        seen = set()
        while at and at not in seen and len(out) < 256:
            seen.add(at)
            head = self.stream.read(at, 20)
            if len(head) < 20:
                break
            nxt, _kind, aid, length = (_u64(head, 0), _u32(head, 8),
                                       _u32(head, 12), _u32(head, 16))
            if length > (1 << 20):
                break
            out[aid] = self.stream.read(at + 20, length).decode(
                "utf-8", "surrogateescape")
            at = nxt
        return out

    def _decorate(self, e):
        """Turn the attribute text into the fields everything above wants."""
        a = e.attrs
        e.mode = a.get(A_MODE, "")
        e.uid = a.get(A_UID, "")
        e.gid = a.get(A_GID, "")
        e.inode = a.get(A_INODE, "")
        e.md5 = a.get(A_MD5, "")
        e.sha1 = a.get(A_SHA1, "")
        e.atime = _parse_time(a.get(A_ATIME))
        e.crtime = _parse_time(a.get(A_CRTIME))
        e.mtime = _parse_time(a.get(A_MTIME))
        e.ctime = _parse_time(a.get(A_CTIME))
        # the mode string is the source filesystem's own answer, so it decides
        # what this is; the type code is only consulted when there is no mode
        if e.mode:
            e.kind = {"d": "d", "l": "l", "b": "b", "c": "c", "p": "p",
                      "s": "s"}.get(e.mode[0], "f")
        else:
            e.kind = "d" if e.type == TYPE_DIR else "f"
        # The size on the entry is the one the chunk table describes, and it
        # is the one to trust. Attribute 0x3 usually agrees, but on a sparse
        # file it reports the blocks actually allocated - a 128 MB tdb with
        # 12 KB on disk says 12288 there and 134230016 here, and taking the
        # attribute would read one chunk of a two-thousand-chunk file and
        # call it the whole thing.
        e.on_disk_size = a.get(A_LOGICAL_SIZE, "")

    # -- content ------------------------------------------------------------
    def chunk_table(self, e):
        """[(offset, compressed length)] for one entry's data chunks."""
        if not e.data_offset or e.size <= 0:
            return []
        head = self.stream.read(e.data_offset, 8)
        if len(head) < 8:
            return []
        count = _u64(head, 0)
        expected = (e.size + self.chunk_size - 1) // self.chunk_size
        if count != expected or count > (1 << 24):
            # the entry's data pointer does not describe its size; reading it
            # would return content belonging to a different file
            raise Ad1Error("%s: chunk table says %d chunks, its size needs %d"
                           % (e.path or e.name, count, expected))
        raw = self.stream.read(e.data_offset + 8, 8 * (count + 1))
        if len(raw) < 8 * (count + 1):
            raise Ad1Error("%s: truncated chunk table" % (e.path or e.name))
        offsets = struct.unpack("<%dQ" % (count + 1), raw)
        return [(offsets[i], offsets[i + 1] - offsets[i]) for i in range(count)]

    def _chunk(self, offset, length, want):
        raw = self.stream.read(offset, length)
        try:
            return zlib.decompress(raw)
        except zlib.error:
            # AD1 can store a chunk verbatim when deflating it would not help
            if len(raw) == want:
                return raw
            try:
                return zlib.decompressobj().decompress(raw)
            except zlib.error:
                raise Ad1Error("a data chunk at %d would not decompress"
                               % offset)

    def read(self, e, limit=None):
        size = e.size if limit is None else min(e.size, limit)
        if size <= 0:
            return b""
        out = bytearray()
        for offset, length in self.chunk_table(e):
            want = min(self.chunk_size, size - len(out))
            out += self._chunk(offset, length, want)[:want]
            if len(out) >= size:
                break
        return bytes(out[:size])

    def open(self, e):
        """A seekable stream, so a multi-gigabyte log is not materialised."""
        table = self.chunk_table(e)
        size = e.size
        chunk_size = self.chunk_size

        def fetch(offset, length):
            length = min(length, max(0, size - offset))
            if length <= 0:
                return b""
            out = bytearray()
            pos = offset
            end = offset + length
            while pos < end:
                index = pos // chunk_size
                if index >= len(table):
                    break
                base = index * chunk_size
                data = self._chunk(table[index][0], table[index][1],
                                   min(chunk_size, size - base))
                start = pos - base
                take = min(len(data) - start, end - pos)
                if take <= 0:
                    break
                out += data[start:start + take]
                pos += take
            return bytes(out)

        return ExtentFile(fetch, size)

    # -- the walk -----------------------------------------------------------
    def walk(self, max_entries=0):
        """Every entry under the image root, depth first, with full paths.

        Iterative rather than recursive: an acquisition of a source tree a few
        hundred levels deep is unusual but not impossible, and a reader that
        blows the Python stack on one has failed on evidence that is merely
        awkward.
        """
        root = self.entry(self.root_offset)
        stack = []
        if root.child:
            stack.append((root.child, ""))
        seen = set()
        count = 0
        while stack:
            offset, prefix = stack.pop()
            while offset:
                if offset in seen:
                    break                    # a cycle; the tree is not a tree
                seen.add(offset)
                e = self.entry(offset)
                e.path = prefix + "/" + e.name
                yield e
                count += 1
                if max_entries and count >= max_entries:
                    return
                if e.child:
                    stack.append((e.child, e.path))
                offset = e.next

    def close(self):
        self.stream.close()


# ---------------------------------------------------------------------------
# the collection backend
# ---------------------------------------------------------------------------

class Ad1Collection(Collection):
    """An AD1 read as a collection, its members at the paths the host had."""

    def __init__(self, path, quiet=False, max_files=0):
        paths = ad1_segments(path)
        self.path = os.path.abspath(paths[0])
        self.kind = "ad1"
        self._tar = None
        self._zip = None
        self._sizes = {}
        self._mtimes = {}
        self._names = {}
        self._raw = {}
        self.prefix = ""
        # the members are named the way UAC names a copied filesystem, which
        # is what lets every parser above find them without knowing this is
        # an AD1; display_layout is what the report prints instead
        self.layout = "uac"
        self.display_layout = "AD1 logical image"
        self.rootfs_dirs = ["[root]"]
        self.velo = None
        self.time_hint = None
        self.time_hint_note = ""

        self._entries = {}            # member -> Ad1Entry
        self._virtual = {}
        self.notes = []
        self.sources = []             # the top-level trees the image holds
        self.stored_hashes = {}       # host path -> {'md5':..., 'sha1':...}
        self.verified = 0             # files checked against their own hashes

        self.reader = Ad1Reader(paths)
        if not quiet:
            status("[*] %s: AD1 v%d, %d segment(s), %d KiB chunks - %s"
                   % (os.path.basename(self.path), self.reader.version,
                      len(self.reader.parts), self.reader.chunk_size // 1024,
                      self.reader.image_name))
        self._mount(quiet, max_files)
        if not self._names:
            raise Ad1Error("%s holds no files" % os.path.basename(self.path))
        self._self_check(quiet)
        self._add_bodyfile()

    # -- proving the reader on this image ------------------------------------
    def _self_check(self, quiet, sample=8):
        """Read a few files and check them against the hashes FTK stored.

        The AD1 format is not documented by its vendor, and this reader was
        written from the images that were available. The risk that carries is
        not that an unseen variant fails loudly - it is that it parses, walks,
        and returns content from slightly the wrong offsets, producing an
        examination of a host that never existed.

        The format defends against exactly that: FTK records an MD5 and a
        SHA-1 beside every file it acquires. Reading a handful and comparing
        turns "wrong on a variant we have never seen" into a statement made
        before any analyzer runs. It costs a few small files.
        """
        candidates = []
        for member, e in self._entries.items():
            if e.kind == "f" and 0 < e.size <= (1 << 20) and (e.md5 or e.sha1):
                candidates.append((e.size, member, e))
                if len(candidates) >= sample * 4:
                    break
        candidates.sort()
        checked = failed = 0
        first = ""
        for _size, member, e in candidates[:sample]:
            try:
                data = self.reader.read(e)
            except Exception as exc:
                failed += 1
                first = first or "%s: %s" % (self.host_path(member), exc)
                continue
            wrong = []
            if len(data) != e.size:
                wrong.append("read %d of %d bytes" % (len(data), e.size))
            if e.md5 and _md5(data) != e.md5.lower():
                wrong.append("md5")
            if e.sha1 and _sha1(data) != e.sha1.lower():
                wrong.append("sha1")
            if wrong:
                failed += 1
                first = first or "%s: %s" % (self.host_path(member),
                                             ", ".join(wrong))
            else:
                checked += 1
        self.verified = checked
        if failed and not checked:
            raise Ad1Error(
                "%s does not read correctly: every one of %d files sampled "
                "failed the MD5/SHA-1 the imager stored beside it (%s).\n"
                "    This is an AD1 shape this reader has not been shown. It "
                "is refused rather than parsed, because the alternative is a "
                "report about a host that never existed.\n"
                "    Export its contents with FTK Imager and use --file."
                % (os.path.basename(self.path), failed, first))
        if failed:
            self.notes.append(
                "%d of %d files sampled did not match the MD5/SHA-1 stored "
                "with them (first: %s) - treat this image's contents as "
                "unreliable" % (failed, checked + failed, first))
        elif checked and not quiet:
            status("[*] %d sampled file(s) match the MD5/SHA-1 FTK stored with "
                   "them" % checked)

    # -- mounting -----------------------------------------------------------
    def _mount(self, quiet, max_files):
        """Place every entry at the path the acquired host had for it.

        FTK puts a synthetic level at the top of each acquired source - the
        partition root is '[root]', a selected folder keeps its own name. The
        first is stripped, because its children already are host absolute
        paths; the second is kept, because dropping it would merge two
        selections that were deliberately separate.
        """
        newest = None
        count = 0
        skipped = 0
        for e in self.reader.walk(max_entries=max_files):
            parts = [p for p in e.path.split("/") if p]
            if not parts:
                continue
            top = parts[0]
            if top not in self.sources:
                self.sources.append(top)
            if top in ROOT_MARKERS:
                rest = parts[1:]
            else:
                rest = parts
            if not rest:
                continue                       # the synthetic level itself
            member = "[root]/" + "/".join(rest)
            key = member.lower()
            if key in self._names:
                skipped += 1
                continue
            self._names[key] = key if key == member else member
            self._sizes[key] = e.size
            self._entries[member] = e
            if e.md5 or e.sha1:
                self.stored_hashes["/" + "/".join(rest)] = {
                    "md5": e.md5, "sha1": e.sha1}
            for when in (e.mtime, e.ctime, e.crtime):
                if when and (newest is None or when > newest):
                    newest = when
            count += 1

        if skipped:
            self.notes.append(
                "%d entr%s appeared twice at the same path and the second was "
                "dropped - this image holds more than one acquisition of the "
                "same tree" % (skipped, "y" if skipped == 1 else "ies"))
        if len(self.sources) > 1:
            self.notes.append(
                "this image holds %d acquired sources: %s"
                % (len(self.sources), ", ".join(self.sources)))
        # An AD1 records no acquisition time of its own that this reader
        # trusts, and a syslog stamp carries no year - so without an anchor
        # every 'Mar 24 22:11' lands in 1900. The newest recorded time in the
        # image is the best statement of when this evidence was current.
        if newest:
            self.time_hint = newest
            self.time_hint_note = (
                "newest timestamp recorded in the AD1 - a logical image "
                "carries no collection time, so this is the anchor for every "
                "'recent' window below")
        if not quiet:
            status("[*] mounted %s file(s) from %s"
                   % (format(count, ","),
                      ", ".join(self.sources) or "the image root"))
            for note in self.notes:
                status("[!] %s" % note)

    # -- the synthetic bodyfile ---------------------------------------------
    def _add_bodyfile(self):
        member = "bodyfile/bodyfile.txt"
        low = member.lower()
        self._names[low] = low if low == member else member
        self._sizes[member.lower()] = len(self._entries) * 120
        self._virtual[member] = None

    def _bodyfile_lines(self):
        """mactime: md5|name|inode|mode|uid|gid|size|atime|mtime|ctime|crtime.

        The md5 column is the one FTK recorded as it acquired the file, which
        is what that column is for and is not otherwise available anywhere in
        a collection.
        """
        for member in sorted(self._entries):
            e = self._entries[member]
            host = self.host_path(member)
            yield ("%s|%s|%s|%s|%s|%s|%d|%d|%d|%d|%d\n"
                   % (e.md5 or "0", host, e.inode or "0", e.mode,
                      e.uid or "0", e.gid or "0", e.size,
                      epoch_seconds(e.atime), epoch_seconds(e.mtime), epoch_seconds(e.ctime),
                      epoch_seconds(e.crtime))).encode("utf-8", "surrogateescape")

    # -- reading ------------------------------------------------------------
    def _open(self, real):
        if real in self._virtual:
            if real == "bodyfile/bodyfile.txt":
                return GeneratedLines(self._bodyfile_lines)
            return io.BytesIO(self._virtual[real] or b"")
        e = self._entries.get(real)
        if e is None:
            raise IOError("no such member: %s" % real)
        if e.kind == "d":
            return io.BytesIO(b"")
        return self.reader.open(e)

    def read_bytes(self, rel, limit=None):
        real = self.resolve(rel)
        if real is None:
            return None
        e = self._entries.get(real)
        if e is not None:
            if e.kind == "d":
                return b""
            try:
                return self.reader.read(e, limit)
            except Ad1Error as exc:
                self.notes.append(str(exc))
                return None
            except Exception:
                return None
        try:
            with self._open(real) as fh:
                return fh.read() if limit is None else fh.read(limit)
        except Exception:
            return None

    time_source = "the AD1's recorded metadata"

    def member_kind(self, rel):
        e = self._entries.get(self.resolve(rel) or "")
        return e.kind if e is not None else ""

    def member_time(self, rel):
        """All four times, as FTK recorded them from the source filesystem."""
        e = self._entries.get(self.resolve(rel) or "")
        if e is None:
            return ("", "", "", "")
        return (_stamp_ad1(e.mtime), _stamp_ad1(e.atime), _stamp_ad1(e.ctime),
                _stamp_ad1(e.crtime))

    def entry(self, rel):
        """The Ad1Entry behind a collection-relative path, or None."""
        return self._entries.get(self.resolve(rel) or "")

    # -- reporting ----------------------------------------------------------
    def meta_rows(self):
        out = OrderedDict()
        out["AD1 image"] = self.path
        out["AD1 name"] = self.reader.image_name
        out["AD1 version"] = "v%d, %d KiB chunks" % (self.reader.version,
                                                     self.reader.chunk_size // 1024)
        if len(self.reader.parts) > 1:
            out["AD1 segments"] = "%d files" % len(self.reader.parts)
        out["AD1 sources"] = ", ".join(self.sources)
        out["Files in image"] = format(len(self._entries), ",")
        out["Stored hashes"] = ("%s file(s) carry the MD5/SHA-1 FTK recorded "
                                "at acquisition" % format(len(self.stored_hashes), ","))
        for i, note in enumerate(self.notes, 1):
            out["AD1 note %d" % i] = note
        return out

    def close(self):
        self.reader.close()


def _md5(data):
    return hashlib.md5(data).hexdigest()


def _sha1(data):
    return hashlib.sha1(data).hexdigest()


def _stamp_ad1(when):
    if not when:
        return ""
    try:
        return when.strftime("%Y-%m-%d %H:%M:%S")
    except (AttributeError, ValueError):
        return ""
