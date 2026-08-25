# -*- coding: utf-8 -*-
"""What every filesystem reader has to answer, and nothing more.

Three readers live above this - ext, XFS, btrfs - and the layer above them
must not be able to tell which one it is talking to. That is not tidiness: the
whole value of reading a disk is that /etc/passwd is /etc/passwd whichever
filesystem the installer happened to pick, and every analyzer, every table and
every Sigma rule in this tool already works on paths.

So a reader answers exactly two questions. What is in this tree - `walk`,
which yields a FsNode per name. And what is in this file - `read`, or `open`
for the ones too big to hold. Everything else a filesystem knows is metadata
hung on the node, where an empty field means "this filesystem does not record
that" rather than "this file does not have it".
"""

from __future__ import annotations

import io
import stat as statmod
from datetime import datetime, timezone


#: The file-type field of a mode word, and the one-character kind each value
#: means. Every reader needs these and they are the same on every filesystem,
#: so they live here rather than being restated three times.
S_IFMT = 0o170000
KIND_BY_MODE = {0o100000: "f", 0o040000: "d", 0o120000: "l", 0o060000: "b",
                0o020000: "c", 0o010000: "p", 0o140000: "s"}


def utc(seconds, nanos=0):
    """A filesystem timestamp as an aware datetime, or None.

    0 is not a time. Every filesystem here writes 0 into a field it never
    filled in, and 1970-01-01 in a timeline is a lie that sorts to the top.
    """
    if not seconds:
        return None
    try:
        return datetime.fromtimestamp(seconds + (nanos / 1e9 if nanos else 0),
                                      timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def epoch_seconds(when):
    """A datetime as whole seconds since 1970, or 0 for 'not recorded'.

    0 rather than an empty string because that is what a mactime bodyfile
    wants in a time column it has nothing for, and every backend that builds
    one is writing the same format.
    """
    if not when:
        return 0
    try:
        return int(when.timestamp())
    except (OverflowError, OSError, ValueError, AttributeError):
        return 0


class GeneratedLines(io.RawIOBase):
    """A read-only stream over lines produced on demand.

    The bodyfile of a full server filesystem is a few hundred megabytes of
    text that exists only because this tool wants to read it back. Building it
    in memory to hand to a reader that consumes it a line at a time is how a
    4 GB machine becomes a swapping one, so it is produced as it is read.
    """

    def __init__(self, make_lines):
        io.RawIOBase.__init__(self)
        self._iter = make_lines()
        self._buf = b""
        self._done = False

    def readable(self):
        return True

    def readinto(self, buf):
        want = len(buf)
        while len(self._buf) < want and not self._done:
            try:
                self._buf += next(self._iter)
            except StopIteration:
                self._done = True
        take = min(want, len(self._buf))
        buf[:take] = self._buf[:take]
        self._buf = self._buf[take:]
        return take


class FsNode(object):
    """One name in a filesystem, with whatever that filesystem knows about it.

    `path` is absolute within the filesystem and always uses '/', on any host.
    `kind` is one character - f d l b c p s - so that the caller can filter
    without importing a stat module or knowing the reader's own constants.
    """

    __slots__ = ("path", "name", "inode", "kind", "size", "mode", "uid", "gid",
                 "nlink", "atime", "mtime", "ctime", "crtime", "dtime",
                 "target", "deleted", "fs", "_ref", "_map_cache")

    def __init__(self, path="", inode=0, kind="f", size=0, mode=0, uid=0,
                 gid=0, nlink=0, atime=None, mtime=None, ctime=None,
                 crtime=None, dtime=None, target="", deleted=False, fs=None,
                 ref=None):
        self.path = path
        self.name = path.rsplit("/", 1)[-1]
        self.inode = inode
        self.kind = kind
        self.size = size
        self.mode = mode
        self.uid = uid
        self.gid = gid
        self.nlink = nlink
        self.atime = atime
        self.mtime = mtime
        self.ctime = ctime
        self.crtime = crtime
        self.dtime = dtime
        self.target = target
        self.deleted = deleted
        self.fs = fs
        self._ref = ref            # whatever the reader needs to find the data
        self._map_cache = None     # the reader's block map, once computed

    @property
    def is_file(self):
        return self.kind == "f"

    @property
    def is_dir(self):
        return self.kind == "d"

    @property
    def is_link(self):
        return self.kind == "l"

    def mode_string(self):
        """'-rwxr-xr-x', the way a bodyfile wants it."""
        if not self.mode:
            return ""
        try:
            return statmod.filemode(self.mode)
        except (ValueError, TypeError):
            return ""

    def read(self, limit=None):
        return self.fs.read(self, limit) if self.fs else b""

    def open(self):
        return self.fs.open(self) if self.fs else io.BytesIO(b"")

    def __repr__(self):
        return "<FsNode %s %s %d>" % (self.kind, self.path, self.size)


class Filesystem(object):
    """The interface the disk backend is written against."""

    #: 'ext4', 'xfs', 'btrfs' - what goes in the report
    kind = ""

    def __init__(self, volume):
        self.volume = volume
        self.label = ""
        self.uuid = ""
        self.block_size = 0
        self.size = 0
        self.created = None
        self.last_mount = None
        self.last_write = None
        self.notes = []            # anything the examiner should know
        self.errors = 0            # structures that would not parse

    # -- what is in the tree ------------------------------------------------
    def walk(self, max_nodes=0, on_error=None):
        """Yield a FsNode for every name in the filesystem, depth first."""
        raise NotImplementedError

    def root_node(self):
        """The FsNode for '/', without walking anything."""
        raise NotImplementedError

    def dir_entries(self, node):
        """[(name, ref, kind hint)] for a directory node.

        `ref` is whatever this reader needs to turn a name back into a node -
        an inode number, a key in a tree - and is only ever handed back to
        `node_at`. Nothing above the reader looks inside it.
        """
        raise NotImplementedError

    def node_at(self, ref, path, hint=""):
        """The FsNode a `dir_entries` ref points at."""
        raise NotImplementedError

    def deleted(self, max_nodes=0):
        """Yield a FsNode per recoverable deleted entry. May yield nothing."""
        return iter(())

    # -- what is in a file --------------------------------------------------
    def read(self, node, limit=None):
        raise NotImplementedError

    def open(self, node):
        """A read-only binary file object over `node`.

        The default holds the whole file in memory, which is right for the
        overwhelming majority of artifacts and wrong for a 40 GB log. A reader
        that can seek its own extents overrides this with something that does.
        """
        return io.BytesIO(self.read(node))

    def describe(self):
        bits = [self.kind]
        if self.label:
            bits.append("'%s'" % self.label)
        if self.block_size:
            bits.append("%d-byte blocks" % self.block_size)
        if self.uuid:
            bits.append(self.uuid)
        return ", ".join(bits)


class ExtentFile(io.RawIOBase):
    """A seekable stream over a file whose reader can map ranges lazily.

    `fetch(offset, length)` is the reader's own random access into the file's
    content. Everything a text wrapper does on top of this - readline over a
    600 MB journal - then costs one mapped read per buffer instead of one
    materialised copy of the whole file.
    """

    def __init__(self, fetch, size):
        io.RawIOBase.__init__(self)
        self._fetch = fetch
        self._size = size
        self._pos = 0

    def readable(self):
        return True

    def seekable(self):
        return True

    def seek(self, offset, whence=io.SEEK_SET):
        if whence == io.SEEK_SET:
            self._pos = offset
        elif whence == io.SEEK_CUR:
            self._pos += offset
        else:
            self._pos = self._size + offset
        self._pos = max(0, self._pos)
        return self._pos

    def tell(self):
        return self._pos

    def readinto(self, buf):
        want = min(len(buf), max(0, self._size - self._pos))
        if not want:
            return 0
        data = self._fetch(self._pos, want)
        n = len(data)
        buf[:n] = data
        self._pos += n
        return n

    def read(self, size=-1):
        if size is None or size < 0:
            size = max(0, self._size - self._pos)
        data = self._fetch(self._pos, size)
        self._pos += len(data)
        return data

    def readall(self):
        return self.read(-1)
