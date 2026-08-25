#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Test the disk stack against real images, built by the tools that own them.

    python tests/test_disk.py                 # against src/linsight
    python tests/test_disk.py --built         # against the built linsight.py
    python tests/test_disk.py --list          # what is covered, and what is not

Fixtures are built by tools/mkfixtures.sh, tools/mkcontainers.sh and
tools/mklvm.py. They are not committed - a few gigabytes of disk images do not
belong in a repository - so anything missing is skipped by name rather than
quietly passing. A run that skips everything says so and fails, because a test
suite that reports success because it tested nothing is worse than no suite.

Three kinds of assertion, in the order they matter:

  containers   every format must reproduce the raw image byte for byte. This
               is the only test that can prove a container reader is right
               rather than merely self-consistent, because the raw image it is
               compared against was made by a different program.
  filesystems  the same planted tree must come back off ext2, ext3, ext4, XFS
               v4 and v5, and btrfs, with the same content, the same modes and
               the same symlink targets. Six readers, one expected answer.
  refusals     a VirtualBox VDI and a LUKS container must fail by name. The
               failure this suite exists to prevent is a disk that reads as
               empty, so "refused loudly" is a passing result and "read as
               nothing" is not.
"""

import argparse
import hashlib
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIXTURES = os.path.join(HERE, "fixtures")


def load(built):
    """Import the package, or the built single file, as `L`."""
    if built:
        import importlib.util
        path = os.path.join(ROOT, "linsight.py")
        if not os.path.exists(path):
            raise SystemExit("[!] %s does not exist - run tools/build.py" % path)
        spec = importlib.util.spec_from_file_location("linsight_built", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    sys.path.insert(0, os.path.join(ROOT, "src"))
    import linsight.image, linsight.volume, linsight.disk        # noqa
    import linsight.fs_ext, linsight.fs_xfs, linsight.fs_btrfs   # noqa
    import linsight.ad1                                          # noqa

    class Flat(object):
        pass

    flat = Flat()
    for mod in (linsight.image, linsight.volume, linsight.disk, linsight.ad1,
                linsight.fs_ext, linsight.fs_xfs, linsight.fs_btrfs):
        for name in dir(mod):
            if not name.startswith("__"):
                setattr(flat, name, getattr(mod, name))
    return flat


# ---------------------------------------------------------------------------
# what the planted tree must look like, whichever filesystem it came off
# ---------------------------------------------------------------------------

#: (path, kind, size, mode string, symlink target). These are the artifacts
#: the fixture plants for the analyzers to find, plus the ones that exercise a
#: reader's harder paths: a file too big for one extent, a directory too wide
#: for one block, a symlink too long to live in the inode.
EXPECTED = [
    ("/etc/passwd", "f", 169, "-rw-r--r--", ""),
    ("/etc/shadow", "f", None, "-rw-r--r--", ""),
    ("/etc/crontab", "f", None, "-rw-r--r--", ""),
    ("/etc/ld.so.preload", "f", None, "-rw-r--r--", ""),
    ("/etc/systemd/system/telemetry.service", "f", None, "-rw-r--r--", ""),
    ("/root/.bash_history", "f", 152, "-rw-r--r--", ""),
    ("/root/.ssh/authorized_keys", "f", None, "-rw-r--r--", ""),
    ("/home/analyst/.bash_history", "f", None, "-rw-r--r--", ""),
    ("/var/log/auth.log", "f", None, "-rw-r--r--", ""),
    ("/var/log/big.bin", "f", 6291456, "-rw-r--r--", ""),
    ("/var/log/many/logfile-0.log", "f", 8, "-rw-r--r--", ""),
    ("/var/log/many/logfile-399.log", "f", 10, "-rw-r--r--", ""),
    ("/dev/shm/.update", "f", 46, "-rwxr-xr-x", ""),
    ("/tmp/.x", "f", 20, "-rwsr-xr-x", ""),
    ("/etc/auth-link", "l", None, "lrwxrwxrwx", "/var/log/auth.log"),
    ("/etc/long-link", "l", 276, "lrwxrwxrwx", None),   # target checked by length
]

#: How many names the fixture tree holds. A reader that returns a plausible
#: subset - shortform directories only, say - is the failure mode that looks
#: most like success, so the count is asserted rather than eyeballed.
EXPECTED_NODES = 445

FILESYSTEM_FIXTURES = [
    ("ext4.img", "ext4"),
    ("ext4-64bit.img", "ext4"),
    ("ext3.img", "ext3"),
    ("ext2.img", "ext2"),
    ("xfs.img", "xfs"),
    ("xfs-v4.img", "xfs"),
    ("xfs-1k.img", "xfs"),
    ("btrfs.img", "btrfs"),
    ("btrfs-zstd.img", "btrfs"),
    ("mbr-ext4.dd", "ext4"),
    ("gpt-ext4.dd", "ext4"),
    ("gpt-luks.dd", "ext4"),
    ("split.dd.000", "ext4"),
    ("split.dd.002", "ext4"),
    ("lvm-ext4.dd", "ext4"),
]

#: Containers, compared byte for byte against the raw image they were made
#: from. This is the reference: it was written by mkfs and sfdisk, and each
#: container by qemu-img or ewfacquire, so agreement here is agreement with
#: three programs that have never seen this code.
CONTAINER_REFERENCE = "mbr-ext4.dd"
CONTAINER_FIXTURES = [
    "disk.qcow2", "disk-v2.qcow2", "disk-compressed.qcow2",
    "disk-overlay.qcow2",
    "disk.vmdk", "disk-stream.vmdk", "disk-split.vmdk", "disk-flat.vmdk",
    "disk.vhdx", "disk.vhd", "disk-fixed.vhd",
    "disk.E01", "disk-split.E01", "disk-raw.E01",
    "split.dd.000",
]

#: Fixtures that must be refused, and the words the refusal has to contain.
REFUSALS = [
    ("disk.vdi", "VDI"),
]


class Results(object):
    def __init__(self):
        self.passed = 0
        self.failed = []
        self.skipped = []

    def ok(self, what):
        self.passed += 1
        print("  ok      %s" % what)

    def fail(self, what, why):
        self.failed.append((what, why))
        print("  FAIL    %s: %s" % (what, why))

    def skip(self, what, why):
        self.skipped.append((what, why))
        print("  skip    %s (%s)" % (what, why))


def fixture(name):
    path = os.path.join(FIXTURES, name)
    return path if os.path.exists(path) else ""


def digest(image, upto=None, step=1 << 20):
    end = min(image.size, upto) if upto else image.size
    h = hashlib.sha256()
    at = 0
    while at < end:
        h.update(image.read(at, min(step, end - at)))
        at += step
    return h.hexdigest()


# ---------------------------------------------------------------------------
# the checks
# ---------------------------------------------------------------------------

def check_containers(L, res):
    print("\ncontainers - each must reproduce the raw image byte for byte")
    ref_path = fixture(CONTAINER_REFERENCE)
    if not ref_path:
        res.skip("containers", "%s not built" % CONTAINER_REFERENCE)
        return
    ref = L.open_image(ref_path)
    try:
        want = digest(ref)
        ref_size = ref.size
    finally:
        ref.close()

    for name in CONTAINER_FIXTURES:
        path = fixture(name)
        if not path:
            res.skip(name, "not built")
            continue
        try:
            image = L.open_image(path)
        except Exception as exc:
            res.fail(name, "would not open: %s" % exc)
            continue
        try:
            # A VHD is padded up to a CHS geometry boundary by the writer, so
            # the container is legitimately longer than the disk it holds. The
            # bytes of the disk still have to match exactly.
            if image.size < ref_size:
                res.fail(name, "reads %d bytes, the disk is %d"
                               % (image.size, ref_size))
                continue
            got = digest(image, upto=ref_size)
            if got == want:
                extra = (" (+%d bytes of geometry padding)"
                         % (image.size - ref_size)) if image.size > ref_size else ""
                res.ok("%-22s %s%s" % (name, image.__class__.__name__, extra))
            else:
                res.fail(name, "content differs from the raw image")
        except Exception as exc:
            res.fail(name, "read failed: %s" % exc)
        finally:
            image.close()


def check_filesystems(L, res):
    print("\nfilesystems - the same planted tree off every reader")
    for name, want_kind in FILESYSTEM_FIXTURES:
        path = fixture(name)
        if not path:
            res.skip(name, "not built")
            continue
        try:
            col = L.DiskCollection(path, quiet=True)
        except Exception as exc:
            res.fail(name, "would not open: %s" % exc)
            continue
        try:
            problems = check_tree(L, col, want_kind)
            if problems:
                res.fail(name, problems[0] +
                         ("" if len(problems) == 1
                          else " (and %d more)" % (len(problems) - 1)))
            else:
                fs = col.mounts[0][2]
                res.ok("%-16s %s" % (name, fs.describe()))
        finally:
            col.close()


def check_tree(L, col, want_kind):
    """Every disagreement between what came off the disk and what was planted."""
    problems = []
    if not col.mounts:
        return ["nothing was mounted"]
    fs = col.mounts[0][2]
    if fs.kind != want_kind:
        problems.append("read as %s, expected %s" % (fs.kind, want_kind))

    nodes = {}
    for member, node in col._nodes.items():
        nodes[node.path] = node
    if len(nodes) != EXPECTED_NODES:
        problems.append("%d names, expected %d" % (len(nodes), EXPECTED_NODES))

    for path, kind, size, mode, target in EXPECTED:
        node = nodes.get(path)
        if node is None:
            problems.append("%s is missing" % path)
            continue
        if node.kind != kind:
            problems.append("%s is %s, expected %s" % (path, node.kind, kind))
        if size is not None and node.size != size:
            problems.append("%s is %d bytes, expected %d"
                            % (path, node.size, size))
        if mode and node.mode_string() != mode:
            problems.append("%s is %s, expected %s"
                            % (path, node.mode_string(), mode))
        if target and node.target != target:
            problems.append("%s points at %r, expected %r"
                            % (path, node.target, target))
        if kind == "l" and target is None and len(node.target) != size:
            problems.append("%s target is %d chars, expected %d"
                            % (path, len(node.target), size))
        if not node.mtime:
            problems.append("%s has no mtime" % path)

    # content, not just metadata: a reader can produce a perfect directory
    # listing and return zeroes for every file, which is the failure that
    # looks most like success
    passwd = col.read_bytes("[root]/etc/passwd") or b""
    if not passwd.startswith(b"root:x:0:0:root:/root:/bin/bash"):
        problems.append("/etc/passwd content is wrong: %r" % passwd[:40])
    if b"backup2:x:0:0" not in passwd:
        problems.append("/etc/passwd is truncated - the uid-0 account is missing")

    history = col.read_bytes("[root]/root/.bash_history") or b""
    if b"useradd -o -u 0 -g 0 backup2" not in history:
        problems.append("/root/.bash_history content is wrong")

    # the multi-extent file, read whole and through the streaming path, which
    # are different code and have to agree
    big = nodes.get("/var/log/big.bin")
    if big is not None:
        whole = fs.read(big)
        if len(whole) != big.size:
            problems.append("big.bin read %d bytes of %d" % (len(whole), big.size))
        elif whole == b"\x00" * len(whole):
            problems.append("big.bin read as all zeroes")
        else:
            with fs.open(big) as fh:
                fh.seek(4 * 1024 * 1024)
                piece = fh.read(65536)
            if piece != whole[4 * 1024 * 1024:4 * 1024 * 1024 + 65536]:
                problems.append("big.bin streams differently than it reads")

    # the synthetic bodyfile, which is what the table layer consumes
    lines = list(col.iter_lines("bodyfile/bodyfile.txt"))
    if len(lines) < EXPECTED_NODES:
        problems.append("bodyfile has %d lines, expected at least %d"
                        % (len(lines), EXPECTED_NODES))
    elif not any(ln.split("|")[1] == "/etc/passwd" for ln in lines
                 if len(ln.split("|")) > 1):
        problems.append("bodyfile does not name /etc/passwd")
    return problems


#: Filesystems whose fixture carries creation times, and the ones whose does
#: not. ext4 and XFS v5 record crtime whenever a file is made. btrfs records
#: otime the same way, but `mkfs.btrfs --rootdir` builds the tree offline and
#: leaves the field zero - so this fixture cannot prove the reader gets it, and
#: asserting it would be asserting a fact about mkfs rather than about this
#: code. XFS v4 has no creation time at all.
CRTIME_EXPECTED = ("ext4.img", "ext4-64bit.img", "xfs.img")
CRTIME_ABSENT = (
    ("xfs-v4.img", "v4 XFS has no creation time field"),
    ("btrfs.img", "mkfs.btrfs --rootdir does not write otime"),
)


def check_crtime_and_deleted(L, res):
    print("\nwhat only a disk gives - creation times and deleted inodes")
    for name in CRTIME_EXPECTED:
        path = fixture(name)
        if not path:
            res.skip("crtime %s" % name, "not built")
            continue
        col = L.DiskCollection(path, quiet=True)
        try:
            node = col.node("[root]/etc/passwd")
            if node is None:
                res.fail("crtime %s" % name, "/etc/passwd not found")
            elif node.crtime is None:
                res.fail("crtime %s" % name, "no creation time recorded")
            elif abs((node.crtime - node.mtime).total_seconds()) > 86400:
                # Not an ordering check. crtime legitimately runs *ahead* of
                # mtime on these fixtures: mkfs stamps the inode as it creates
                # it and copies mtime from the source file, which is a second
                # older - the same shape a restored backup has. What a crtime
                # read from the wrong offset looks like is 1970, or 2106, or a
                # date a century out, so distance is what is asserted.
                res.fail("crtime %s" % name,
                         "created %s but modified %s - a day apart or more "
                         "means the field is being read from the wrong offset"
                         % (node.crtime, node.mtime))
            else:
                res.ok("crtime %-14s /etc/passwd created %s"
                       % (name, node.crtime.strftime("%Y-%m-%d %H:%M:%S")))
        finally:
            col.close()

    # The other half of the same assertion. Where a filesystem records no
    # creation time, the column has to come out empty - a reader that invents
    # 1970 there puts every file at the top of a timeline sorted by crtime.
    for name, why in CRTIME_ABSENT:
        path = fixture(name)
        if not path:
            res.skip("crtime %s" % name, "not built")
            continue
        col = L.DiskCollection(path, quiet=True)
        try:
            node = col.node("[root]/etc/passwd")
            if node is not None and node.crtime is not None:
                res.fail("crtime %s" % name,
                         "a creation time appeared where there is none to read")
            else:
                res.ok("crtime %-14s empty, as it should be (%s)" % (name, why))
        finally:
            col.close()

    # only ext keeps a deleted inode's metadata; the fixture unlinks one file
    # with debugfs after the image is built
    for name in ("ext4.img", "ext3.img", "ext2.img"):
        path = fixture(name)
        if not path:
            res.skip("deleted %s" % name, "not built")
            continue
        col = L.DiskCollection(path, quiet=True)
        try:
            found = col.deleted_nodes
            if not found:
                res.fail("deleted %s" % name,
                         "no deleted inode found - the fixture unlinks one")
            elif not any(n.dtime for n in found):
                res.fail("deleted %s" % name, "no deletion time on any of them")
            else:
                res.ok("deleted %-14s %d inode(s), first dtime %s"
                       % (name, len(found), found[0].dtime))
        finally:
            col.close()


def check_refusals(L, res):
    print("\nrefusals - what must fail by name rather than read as empty")
    for name, word in REFUSALS:
        path = fixture(name)
        if not path:
            res.skip(name, "not built")
            continue
        try:
            image = L.open_image(path)
            image.close()
            res.fail(name, "opened, and should have been refused")
        except L.ImageError as exc:
            if word.lower() in str(exc).lower():
                res.ok("%-22s refused: %s" % (name, str(exc).split(".")[0]))
            else:
                res.fail(name, "refused without naming %s: %s" % (word, exc))
        except Exception as exc:
            res.fail(name, "failed with the wrong error: %r" % exc)

    for name in ("luks1.img", "luks2.img"):
        path = fixture(name)
        if not path:
            res.skip(name, "not built")
            continue
        image = L.open_image(path)
        try:
            volumes, notes, _scheme = L.scan(image)
            if not volumes or volumes[0].fstype != "luks":
                res.fail(name, "not identified as LUKS")
            elif not any("encrypted" in n for n in notes):
                res.fail(name, "identified, but the scan said nothing about it")
            else:
                res.ok("%-22s %s" % (name, volumes[0].detail))
        finally:
            image.close()

    # and the case that matters most: a disk where one partition is readable
    # and another is locked. The report has to carry both facts.
    path = fixture("gpt-luks.dd")
    if not path:
        res.skip("gpt-luks.dd", "not built")
        return
    col = L.DiskCollection(path, quiet=True)
    try:
        locked = [v for v in col.volumes if v.fstype == "luks"]
        if not locked:
            res.fail("gpt-luks.dd", "the encrypted partition was not seen")
        elif not col.mounts:
            res.fail("gpt-luks.dd", "the readable partition was not mounted")
        else:
            rows = col.report()
            unmounted = [r for r in rows if r["filesystem"] == "luks"
                         and not r["mounted_at"]]
            if not unmounted:
                res.fail("gpt-luks.dd", "DISK_LAYOUT does not carry the "
                                        "encrypted volume as unmounted")
            else:
                res.ok("gpt-luks.dd           %d volume(s), %d mounted, "
                       "%d encrypted and reported"
                       % (len(rows), len(col.mounts), len(unmounted)))
    finally:
        col.close()


def check_lvm(L, res):
    print("\nlvm - the filesystem is only reachable through the volume group")
    path = fixture("lvm-ext4.dd")
    if not path:
        res.skip("lvm-ext4.dd", "not built")
        return
    image = L.open_image(path)
    try:
        volumes, _notes, scheme = L.scan(image)
        pvs = [v for v in volumes if v.fstype == "lvm2-pv"]
        lvs = [v for v in volumes if getattr(v, "scheme", "") == "lvm"]
        if not pvs:
            res.fail("lvm-ext4.dd", "no physical volume found")
        elif not lvs:
            res.fail("lvm-ext4.dd", "the volume group produced no logical volume")
        elif lvs[0].fstype != "ext4":
            res.fail("lvm-ext4.dd", "the logical volume holds %r, expected ext4"
                                    % lvs[0].fstype)
        else:
            res.ok("lvm-ext4.dd           %s -> %s" % (scheme, lvs[0].describe()))
    finally:
        image.close()


def check_ad1(L, res):
    """Every AD1 in the fixture directory, verified against its own hashes.

    This one does not need a fixture that ships with the project. FTK records
    an MD5 and a SHA-1 for every file as it acquires it, so any AD1 anyone
    drops into tests/fixtures carries its own answer key: extract each file,
    hash it, and compare with what the imager wrote. A reader that has the
    format even slightly wrong cannot produce 1,860 matching digests.

    So the way to check this reader against a new image is to put that image
    here and run this.
    """
    print("\nad1 - each file checked against the MD5/SHA-1 FTK stored")
    images = []
    if os.path.isdir(FIXTURES):
        for name in sorted(os.listdir(FIXTURES)):
            if name.lower().endswith(".ad1"):
                images.append(os.path.join(FIXTURES, name))
    if not images:
        res.skip("ad1", "no .ad1 in tests/fixtures - drop one in to cover it")
        return
    for path in images:
        name = os.path.basename(path)
        try:
            reader = L.Ad1Reader(L.ad1_segments(path))
        except Exception as exc:
            res.fail(name, "would not open: %s" % exc)
            continue
        try:
            ok = bad = nohash = dirs = 0
            first_bad = ""
            for e in reader.walk():
                if e.kind == "d":
                    dirs += 1
                    continue
                if not (e.md5 or e.sha1):
                    nohash += 1
                    continue
                try:
                    data = reader.read(e)
                except Exception as exc:
                    bad += 1
                    first_bad = first_bad or "%s: %s" % (e.path, exc)
                    continue
                why = []
                if len(data) != e.size:
                    why.append("read %d of %d bytes" % (len(data), e.size))
                if e.md5 and hashlib.md5(data).hexdigest() != e.md5.lower():
                    why.append("md5")
                if e.sha1 and hashlib.sha1(data).hexdigest() != e.sha1.lower():
                    why.append("sha1")
                if why:
                    bad += 1
                    first_bad = first_bad or "%s: %s" % (e.path, ", ".join(why))
                else:
                    ok += 1
            if bad:
                res.fail(name, "%d of %d files did not match - %s"
                               % (bad, ok + bad, first_bad))
            elif not ok:
                res.fail(name, "no file in it carried a stored hash to check")
            else:
                res.ok("%-22s %d files verified, %d directories%s"
                       % (name, ok, dirs,
                          ", %d without a stored hash" % nohash if nohash else ""))

            # the streaming path and the whole-file path are different code
            # and have to agree, or a large log reads differently than a
            # small one and nothing says so
            checked = 0
            differed = ""
            for e in reader.walk():
                if e.kind == "d" or e.size < 100000:
                    continue
                whole = reader.read(e)
                with reader.open(e) as fh:
                    fh.seek(50000)
                    piece = fh.read(20000)
                if piece != whole[50000:70000]:
                    differed = e.path
                    break
                checked += 1
                if checked >= 10:
                    break
            if differed:
                res.fail(name, "%s streams differently than it reads" % differed)
            elif checked:
                res.ok("%-22s streaming agrees with whole-file on %d files"
                       % (name, checked))
        finally:
            reader.close()

    # and the collection view: the paths the host had, and a bodyfile
    for path in images:
        name = os.path.basename(path)
        try:
            col = L.Ad1Collection(path, quiet=True)
        except Exception as exc:
            res.fail(name + " (collection)", "would not mount: %s" % exc)
            continue
        try:
            problems = []
            if not col._entries:
                problems.append("mounted nothing")
            for member in list(col._entries)[:200]:
                if not member.startswith("[root]/"):
                    problems.append("%s is not under [root]" % member)
                    break
            lines = list(col.iter_lines("bodyfile/bodyfile.txt"))
            if len(lines) < len(col._entries):
                problems.append("bodyfile has %d lines for %d entries"
                                % (len(lines), len(col._entries)))
            timed = sum(1 for ln in lines
                        if len(ln.split("|")) > 10 and ln.split("|")[10] != "0")
            if not timed:
                problems.append("no entry in the bodyfile carries a crtime")
            if problems:
                res.fail(name + " (collection)", problems[0])
            else:
                res.ok("%-22s %d members, %d bodyfile lines, %d with crtime"
                       % (name + " (coll)", len(col._entries), len(lines), timed))
        finally:
            col.close()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--built", action="store_true",
                    help="test the built linsight.py instead of src/linsight")
    ap.add_argument("--list", action="store_true",
                    help="list the fixtures this suite wants, and say which "
                         "are present")
    opts = ap.parse_args(argv)

    if opts.list:
        wanted = ([n for n, _k in FILESYSTEM_FIXTURES] + CONTAINER_FIXTURES
                  + [n for n, _w in REFUSALS] + ["luks1.img", "luks2.img",
                                                 "gpt-luks.dd", "lvm-ext4.dd"])
        for name in sorted(set(wanted)):
            print("  %-24s %s" % (name, "present" if fixture(name) else "MISSING"))
        print("\nbuild them with:")
        print("  sh tools/mkfixtures.sh tests/fixtures")
        print("  sh tools/mkcontainers.sh tests/fixtures")
        print("  python3 tools/mklvm.py tests/fixtures/ext4.img "
              "tests/fixtures/lvm-ext4.dd")
        return 0

    L = load(opts.built)
    print("testing %s" % ("the built linsight.py" if opts.built
                          else "src/linsight"))
    res = Results()
    check_containers(L, res)
    check_filesystems(L, res)
    check_crtime_and_deleted(L, res)
    check_lvm(L, res)
    check_refusals(L, res)
    check_ad1(L, res)

    print("\n%d passed, %d failed, %d skipped"
          % (res.passed, len(res.failed), len(res.skipped)))
    if res.failed:
        print("\nfailures:")
        for what, why in res.failed:
            print("  %s: %s" % (what, why))
        return 1
    if not res.passed:
        print("\n[!] nothing ran - no fixtures are built. Run "
              "'python tests/test_disk.py --list' to see what is wanted.")
        return 1
    if res.skipped:
        print("[*] %d skipped for want of a fixture; --list says which"
              % len(res.skipped))
    return 0


if __name__ == "__main__":
    sys.exit(main())
