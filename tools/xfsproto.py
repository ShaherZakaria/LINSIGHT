#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Write an mkfs.xfs proto file describing a directory tree.

mkfs.xfs has no --rootdir. What it has is -p, which takes a proto file: a
nested description of a tree, with each regular file naming a source path to
copy in. That is enough to build a populated XFS image with no root, no loop
device and no mount, which is what the fixtures need.

    python3 tools/xfsproto.py <rootdir> > proto
    mkfs.xfs -p proto -f image.img

The format, one line per entry:

    <name> <type><3 perm digits> <uid> <gid> [<source file> | <link target>]

with 'd' for a directory (whose children follow, ending in a line holding
only '$'), '-' for a regular file, and 'l' for a symlink.
"""

import os
import stat
import sys


def perms(mode):
    """The proto format's mode string, minus the leading type character.

    mkfs.xfs wants exactly this shape: a setuid slot, a setgid slot, then the
    octal permissions - 'd--755', '-u-755'. A dash is not optional padding,
    it is the "not set" value for that slot, and leaving it out is the
    "bad format string" mkfs rejects the whole proto file over.
    """
    return "%s%s%03o" % ("u" if mode & stat.S_ISUID else "-",
                         "g" if mode & stat.S_ISGID else "-",
                         mode & 0o777)


def emit(path, name, out, depth):
    pad = "\t" * depth
    st = os.lstat(path)
    uid, gid = st.st_uid, st.st_gid
    if stat.S_ISDIR(st.st_mode):
        out.append("%s%s d%s %d %d" % (pad, name, perms(st.st_mode), uid, gid))
        for child in sorted(os.listdir(path)):
            emit(os.path.join(path, child), child, out, depth + 1)
        out.append("%s$" % pad)
    elif stat.S_ISLNK(st.st_mode):
        out.append("%s%s l%s %d %d %s"
                   % (pad, name, perms(st.st_mode), uid, gid,
                      os.readlink(path)))
    elif stat.S_ISREG(st.st_mode):
        out.append("%s%s -%s %d %d %s"
                   % (pad, name, perms(st.st_mode), uid, gid,
                      os.path.abspath(path)))
    # sockets, fifos and devices are skipped: the fixture has none, and a
    # proto file that names one mkfs cannot create fails the whole build


def main(argv):
    if len(argv) != 2:
        sys.stderr.write("usage: xfsproto.py <rootdir>\n")
        return 2
    root = argv[1]
    out = ["DUMMY", "0 0"]
    st = os.lstat(root)
    out.append("d%s %d %d" % (perms(st.st_mode), st.st_uid, st.st_gid))
    for child in sorted(os.listdir(root)):
        emit(os.path.join(root, child), child, out, 1)
    out.append("$")
    sys.stdout.write("\n".join(out) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
