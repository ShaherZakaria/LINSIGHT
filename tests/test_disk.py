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
    import linsight.ad1, linsight.distro, linsight.common        # noqa
    import linsight.hosttz, linsight.fsbase                      # noqa
    import linsight.tables                                       # noqa

    class Flat(object):
        pass

    flat = Flat()
    for mod in (linsight.image, linsight.volume, linsight.disk, linsight.ad1,
                linsight.distro, linsight.common, linsight.hosttz,
                linsight.fsbase, linsight.tables,
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
    ("/etc/timezone", "f", 14, "-rw-r--r--", ""),
    ("/etc/localtime", "l", None, "lrwxrwxrwx",
     "/usr/share/zoneinfo/Europe/Berlin"),
    ("/etc/long-link", "l", 276, "lrwxrwxrwx", None),   # target checked by length
]

#: How many names the fixture tree holds. A reader that returns a plausible
#: subset - shortform directories only, say - is the failure mode that looks
#: most like success, so the count is asserted rather than eyeballed. Change
#: it only alongside tools/mkfixtures.sh, and only once the arithmetic works
#: out: the last move was 445 -> 451 for /etc/timezone, /etc/localtime, one
#: compiled zone and the three directories above it.
EXPECTED_NODES = 451

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


def check_distribution(L, res):
    """The distribution must be named, and named from the right source.

    The fixtures carry an /etc/os-release saying Ubuntu 22.04, so the easy
    path is covered. What matters more is the hard path: an image with no
    /etc at all still has to answer, from the package manager and the kernel.
    That case is checked against whatever AD1 is present, because the logical
    image this was built for holds only /boot, /root and /var.
    """
    print("\ndistribution - what the host was, and how we know")
    for name in ("ext4.img", "xfs.img", "btrfs.img", "lvm-ext4.dd"):
        path = fixture(name)
        if not path:
            res.skip("distro %s" % name, "not built")
            continue
        col = L.DiskCollection(path, quiet=True)
        try:
            info = L.identify_distro(col)
            label = L.describe_distro(info)
            if "ubuntu" not in label.lower():
                res.fail("distro %s" % name,
                         "read as %r, the fixture is Ubuntu" % label)
            elif info["family"] != "debian":
                res.fail("distro %s" % name,
                         "family %r, expected debian" % info["family"])
            elif not info["version"].startswith("22.04"):
                res.fail("distro %s" % name,
                         "version %r, expected 22.04" % info["version"])
            elif info["conflict"]:
                res.fail("distro %s" % name,
                         "a conflict was raised where the sources agree: %s"
                         % info["conflict"])
            else:
                res.ok("distro %-14s %s from %s"
                       % (name, label, info["source"]))
        finally:
            col.close()

    # the hard path: no /etc, so the answer has to come from somewhere else
    images = []
    if os.path.isdir(FIXTURES):
        images = [os.path.join(FIXTURES, n) for n in sorted(os.listdir(FIXTURES))
                  if n.lower().endswith(".ad1")]
    if not images:
        res.skip("distro from an /etc-less image", "no .ad1 in tests/fixtures")
        return
    for path in images:
        name = os.path.basename(path)
        col = L.Ad1Collection(path, quiet=True)
        try:
            info = L.identify_distro(col)
            label = L.describe_distro(info)
            has_etc = bool(col.rootfs("/etc/os-release"))
            if not (label or info["family"]):
                res.fail("distro %s" % name, "nothing named the distribution")
            elif not info["family"]:
                res.fail("distro %s" % name, "no family was established")
            else:
                res.ok("distro %-14s %s (%s family)%s"
                       % (name, label or "unnamed", info["family"],
                          "" if has_etc else " - with no /etc in the image"))
            if info["kernel"] and not info["evidence"]:
                res.fail("distro %s" % name,
                         "a kernel was found but produced no evidence")
        finally:
            col.close()

#: (path, must a tool name be found?) - the boundary cases that decide whether
#: a downloaded tool on disk is seen at all. The underscore ones are the bug
#: this table exists for: '_' is a word character, so the strict boundary
#: could not see the tool in 'mimikatz_name.zip'.
TOOL_NAME_CASES = (
    ("/root/mimikatz_name.zip", "mimikatz"),
    ("/tmp/linpeas_linux_amd64", "linpeas"),
    ("/opt/metasploit-framework/msfconsole", "metasploit"),
    ("/home/u/.mimikatz", "mimikatz"),
    ("/home/u/AzureHound/.all-contributorsrc", "azurehound"),
    ("/usr/local/bin/pspy64", "pspy"),
    # and the ones that must stay quiet: a letter may never follow
    ("/home/x/johnson_report.txt", None),
    ("/usr/bin/cdkit", None),
    ("/srv/mimikatzx", None),
    ("/var/lib/lazagnette", None),
)

#: (path, must it be reported as sensitive?) - the same shape for filenames
#: that name their own contents, plus the distribution paths that must not
#: turn into a page of noise.
SENSITIVE_CASES = (
    ("/home/u/.ssh/id_rsa", True),
    ("/root/db_secrets.txt", True),
    ("/home/u/my_passwords.csv", True),
    ("/etc/openvpn/private/ca.key", True),
    ("/home/u/vault.kdbx", True),
    ("/root/.aws/credentials", True),
    ("/tmp/shadow.bak", True),
    # normal, and on every host there is
    ("/etc/passwd", False),
    ("/etc/shadow-", False),
    ("/etc/pam.d/common-password", False),
    ("/usr/lib/python3.11/secrets.py", False),
    ("/etc/ssl/certs/ca-bundle.pem", False),
    ("/boot/grub/i386-pc/password.mod", False),
    ("/usr/share/doc/x/password.txt", False),
)


def check_filename_hunts(L, res):
    """The two questions answered from a filename alone.

    Neither needs a fixture: they are decisions about a string, and the cases
    that matter are the boundary ones. Both are checked here rather than
    through a whole run because a run only proves the paths that happen to be
    in the evidence, and what broke was the paths that were not.
    """
    print("\nfilename hunts - tool names and credential material")
    wrong = []
    for path, want in TOOL_NAME_CASES:
        m = L.HACKTOOL_PATH_RE.search(path.lower())
        got = m.group(1) if m else None
        if got != want:
            wrong.append("%s -> %r, expected %r" % (path, got, want))
    if wrong:
        res.fail("tool names in filenames", wrong[0] +
                 ("" if len(wrong) == 1 else " (and %d more)" % (len(wrong) - 1)))
    else:
        res.ok("tool names in filenames    %d cases, underscores and all"
               % len(TOOL_NAME_CASES))

    wrong = []
    for path, want in SENSITIVE_CASES:
        hit = False
        if not L.SENSITIVE_FILE_BENIGN.search(path) and                 not L.SENSITIVE_FILE_EXPECTED.match(path) and                 not (L.PUBLIC_CERT_DIR.search(path)
                     and not L.PRIVATE_KEY_DIR.search(path)):
            hit = any(rx.search(path) for rx, _w, _s, _y in L.SENSITIVE_FILE_RE)
        if hit != want:
            wrong.append("%s -> %s, expected %s" % (path, hit, want))
    if wrong:
        res.fail("credential material by name", wrong[0] +
                 ("" if len(wrong) == 1 else " (and %d more)" % (len(wrong) - 1)))
    else:
        res.ok("credential material by name %d cases, noise excluded"
               % len(SENSITIVE_CASES))


# (timestamp, syslog ident, pid, event, user, message) as AUTH_LOG holds them.
# The order is the order the rows arrive in, which is not time order: auth.log
# is read alongside its rotated auth.log.1 and auth.log.*.gz, and the glob
# returns them by name. The live file is listed first here, and it is newer.
AUTH_SESSION_ROWS = (
    # --- auth.log, the live file -------------------------------------------
    # dave's session began before the rotation, so its open is in the older
    # file below and only its close is here. Pairing the rows as they arrive
    # drops this close on an empty stack and leaves the open dangling.
    ("2026-07-25 08:00:00", "sshd", "5555", "session closed", "dave",
     "pam_unix(sshd:session): session closed for user dave"),
    # two sudo sessions by different users, overlapping. sudo writes no pid at
    # all, so the user is the only thing that tells them apart.
    ("2026-07-25 10:00:00", "sudo", "", "session opened", "root",
     "pam_unix(sudo:session): session opened for user root by alice(uid=1000)"),
    ("2026-07-25 10:01:00", "sudo", "", "session opened", "bob",
     "pam_unix(sudo:session): session opened for user bob by alice(uid=1000)"),
    ("2026-07-25 10:02:00", "sudo", "", "session closed", "root",
     "pam_unix(sudo:session): session closed for user root"),
    ("2026-07-25 10:03:00", "sudo", "", "session closed", "bob",
     "pam_unix(sudo:session): session closed for user bob"),
    # nested sudo by one user: the inner session closes first, so a close has
    # to take the most recent open rather than replacing it.
    ("2026-07-25 11:00:00", "sudo", "", "session opened", "root",
     "pam_unix(sudo:session): session opened for user root by alice(uid=1000)"),
    ("2026-07-25 11:00:30", "sudo", "", "session opened", "root",
     "pam_unix(sudo:session): session opened for user root by alice(uid=1000)"),
    ("2026-07-25 11:00:40", "sudo", "", "session closed", "root",
     "pam_unix(sudo:session): session closed for user root"),
    ("2026-07-25 11:10:00", "sudo", "", "session closed", "root",
     "pam_unix(sudo:session): session closed for user root"),
    # a close whose open is in a file that has already been deleted must not
    # invent a session
    ("2026-07-25 12:00:00", "cron", "4444", "session closed", "root",
     "pam_unix(cron:session): session closed for user root"),

    # --- auth.log.1, rotated, and older -------------------------------------
    ("2026-07-24 17:00:00", "sshd", "1111", "session opened", "alice",
     "pam_unix(sshd:session): session opened for user alice(uid=1000) by (uid=0)"),
    ("2026-07-24 18:00:00", "sshd", "1111", "session closed", "alice",
     "pam_unix(sshd:session): session closed for user alice"),
    # overlapping ssh sessions for one user, told apart only by pid
    ("2026-07-24 19:00:00", "sshd", "2222", "session opened", "bob",
     "pam_unix(sshd:session): session opened for user bob(uid=1001) by (uid=0)"),
    ("2026-07-24 19:05:00", "sshd", "3333", "session opened", "bob",
     "pam_unix(sshd:session): session opened for user bob(uid=1001) by (uid=0)"),
    ("2026-07-24 19:06:00", "sshd", "2222", "session closed", "bob",
     "pam_unix(sshd:session): session closed for user bob"),
    # 3333 is never closed - the log ends first
    # GDM's syslog ident really is 'gdm-password]' and systemd's user manager
    # is '(systemd)'. PAM's own message is where the service name is clean.
    ("2026-07-24 20:00:00", "gdm-password]", "", "session opened", "carol",
     "pam_unix(gdm-password:session): session opened for user carol(uid=1002) by (uid=0)"),
    ("2026-07-24 20:30:00", "gdm-password]", "", "session closed", "carol",
     "pam_unix(gdm-password:session): session closed for user carol"),
    ("2026-07-24 21:00:00", "(systemd)", "", "session opened", "carol",
     "pam_unix(systemd-user:session): session opened for user carol(uid=1002) by (uid=0)"),
    # dave's open, one file older than its close at the top
    ("2026-07-24 23:50:00", "sshd", "5555", "session opened", "dave",
     "pam_unix(sshd:session): session opened for user dave(uid=1003) by (uid=0)"),
)

STILL_OPEN = "still open at the end of this log"

AUTH_SESSION_WANT = (
    # (user, service, pid, start, end, state)
    ("alice", "sshd", "1111", "2026-07-24 17:00:00", "2026-07-24 18:00:00", "closed"),
    ("bob", "sshd", "2222", "2026-07-24 19:00:00", "2026-07-24 19:06:00", "closed"),
    ("bob", "sshd", "3333", "2026-07-24 19:05:00", "", STILL_OPEN),
    ("carol", "gdm-password", "", "2026-07-24 20:00:00", "2026-07-24 20:30:00", "closed"),
    ("carol", "systemd-user", "", "2026-07-24 21:00:00", "", STILL_OPEN),
    ("dave", "sshd", "5555", "2026-07-24 23:50:00", "2026-07-25 08:00:00", "closed"),
    ("root", "sudo", "", "2026-07-25 10:00:00", "2026-07-25 10:02:00", "closed"),
    ("bob", "sudo", "", "2026-07-25 10:01:00", "2026-07-25 10:03:00", "closed"),
    ("root", "sudo", "", "2026-07-25 11:00:00", "2026-07-25 11:10:00", "closed"),
    ("root", "sudo", "", "2026-07-25 11:00:30", "2026-07-25 11:00:40", "closed"),
)


class _TablesOnly(object):
    """Just enough of TableBuilder for _auth_sessions, which reads only this."""

    def __init__(self, tables):
        self.tables = tables


def check_auth_sessions(L, res):
    """PAM's session opened/closed pairs, which is where sudo and cron live.

    No fixture: this is a decision about a list of log lines, and the cases
    that matter are the ones a real auth.log made hard - rotated files
    arriving out of order, services that log no pid, and a close whose open
    was in a file that has already been deleted.
    """
    print("\nauth.log sessions - PAM's own record of a login")
    cols = ["timestamp_utc", "timestamp_raw", "host", "process", "pid",
            "event", "event_class", "user", "target_user", "target_group",
            "source_ip", "port", "tty", "pwd", "command", "result",
            "message", "source"]
    auth = L.Table("AUTH_LOG", "auth", cols)
    for ts, proc, pid, event, user, msg in AUTH_SESSION_ROWS:
        auth.add_dict({"timestamp_utc": ts, "process": proc, "pid": pid,
                       "event": event, "user": user, "message": msg,
                       "source": "[root]/var/log/auth.log"})
    got = L.TableBuilder._auth_sessions(_TablesOnly([auth]))
    got = sorted((s["user"], s["service"], s["pid"], s["start"], s["end"],
                  s["state"]) for s in got)
    want = sorted(AUTH_SESSION_WANT)
    if got != want:
        extra = [g for g in got if g not in want]
        missing = [w for w in want if w not in got]
        why = []
        if extra:
            why.append("unexpected %r" % (extra[0],))
        if missing:
            why.append("missing %r" % (missing[0],))
        res.fail("auth.log session pairing", "; ".join(why) or
                 "%d sessions, expected %d" % (len(got), len(want)))
    else:
        res.ok("auth.log session pairing  %d sessions, rotated order and "
               "pidless services" % len(got))

    # A session that ends before it starts is the signature of pairing the
    # rows in the order the files were read. It is worth its own assertion
    # because the pairing still looks plausible per row when it happens.
    backwards = [s for s in L.TableBuilder._auth_sessions(_TablesOnly([auth]))
                 if s["end"] and s["end"] < s["start"]]
    if backwards:
        res.fail("auth.log session order",
                 "%s session ends %s, before it starts %s"
                 % (backwards[0]["service"], backwards[0]["end"],
                    backwards[0]["start"]))
    else:
        res.ok("auth.log session order    no session ends before it starts")

    # No AUTH_LOG at all is the common case, not an error.
    if L.TableBuilder._auth_sessions(_TablesOnly([])) != []:
        res.fail("auth.log absent", "sessions invented with no AUTH_LOG")
    else:
        res.ok("auth.log absent           no table, no sessions")


def check_inventory_times(L, res):
    """FILE_INVENTORY has to carry times, and say where they came from."""
    print("\nfile inventory - times, and what they mean")
    for name in ("gpt-ext4.dd",):
        path = fixture(name)
        if not path:
            res.skip("times %s" % name, "not built")
            continue
        col = L.DiskCollection(path, quiet=True)
        try:
            rel = "[root]/etc/passwd"
            times = col.member_time(rel)
            if not times[0]:
                res.fail("times %s" % name, "no mtime for /etc/passwd")
            elif not (times[1] and times[2] and times[3]):
                res.fail("times %s" % name,
                         "a filesystem backend gave only some of the four "
                         "times: %r" % (times,))
            elif col.time_source != "filesystem":
                res.fail("times %s" % name,
                         "time_source is %r" % col.time_source)
            else:
                res.ok("times %-16s all four, from the %s"
                       % (name, col.time_source))
        finally:
            col.close()

    images = []
    if os.path.isdir(FIXTURES):
        images = [os.path.join(FIXTURES, n) for n in sorted(os.listdir(FIXTURES))
                  if n.lower().endswith(".ad1")]
    for path in images[:1]:
        col = L.Ad1Collection(path, quiet=True)
        try:
            member = next((m for m in col._entries
                           if col._entries[m].kind == "f"), "")
            # member_time takes a collection-relative path, which is what the
            # member already is - the host path is what comes back out of it
            times = col.member_time(member) if member else ()
            if not member:
                res.fail("times ad1", "nothing to check")
            elif not all(times):
                res.fail("times ad1", "expected all four, got %r" % (times,))
            else:
                res.ok("times %-16s all four, from %s"
                       % (os.path.basename(path), col.time_source))
        finally:
            col.close()

#: (zone, January offset, July offset). Read from this machine's own
#: /usr/share/zoneinfo, so no fixture is needed - and the point of the table
#: is the pair: a reader that returns a single fixed offset per zone passes
#: the January column and fails July, which is exactly the bug that puts a
#: summer log line an hour out.
TZ_CASES = (
    ("Europe/Berlin", "+01:00", "+02:00"),
    ("America/New_York", "-05:00", "-04:00"),
    ("Asia/Tokyo", "+09:00", "+09:00"),
    ("Australia/Sydney", "+11:00", "+10:00"),
    ("UTC", "+00:00", "+00:00"),
)

def zoneinfo_roots():
    """Where a compiled zone might be readable from, best first.

    Python's own zoneinfo knows where the platform keeps tzdata, which beats
    guessing at paths that do not exist on Windows at all.
    """
    roots = []
    try:
        import zoneinfo
        roots.extend(zoneinfo.TZPATH)
    except Exception:
        pass
    roots.extend(("/usr/share/zoneinfo", "/usr/lib/zoneinfo",
                  "C:/Program Files/Git/usr/share/zoneinfo"))
    return [r for r in roots if r and os.path.isdir(r)]


def check_timezone(L, res):
    """The compiled zone reader, and the zone name wherever it is written."""
    print("\nhost time zone - the offset in force, not the offset now")
    from datetime import datetime, timezone as _tz
    zones = {}                       # name -> the compiled TZif bytes
    for root in zoneinfo_roots():
        for zone, _j, _u in TZ_CASES:
            if zone in zones:
                continue
            path = os.path.join(root, *zone.split("/"))
            if os.path.exists(path):
                with open(path, "rb") as fh:
                    zones[zone] = fh.read()
    if not zones:
        # No tzdata on this machine - but the disk fixture carries a compiled
        # zone of its own, put there for exactly this. Reading it back out
        # tests the reader against a real file without needing the analysis
        # box to have one.
        path = fixture("ext4.img")
        if path:
            col = L.DiskCollection(path, quiet=True)
            try:
                raw = col.read_bytes("[root]/usr/share/zoneinfo/Europe/Berlin")
                if raw and raw[:4] == b"TZif":
                    zones["Europe/Berlin"] = raw
            finally:
                col.close()
    if not zones:
        res.skip("tzif reader", "no compiled zone available to read")
    else:
        wrong = []
        for zone, want_jan, want_jul in TZ_CASES:
            raw = zones.get(zone)
            if raw is None:
                continue
            jan = L.format_offset(L.tzif_offset(
                raw, datetime(2024, 1, 15, tzinfo=_tz.utc)))
            jul = L.format_offset(L.tzif_offset(
                raw, datetime(2024, 7, 15, tzinfo=_tz.utc)))
            if (jan, jul) != (want_jan, want_jul):
                wrong.append("%s -> %s/%s, expected %s/%s"
                             % (zone, jan, jul, want_jan, want_jul))
        if wrong:
            res.fail("tzif reader", wrong[0])
        else:
            res.ok("tzif reader           %d zone(s), summer and winter both"
                   % len(zones))

    # a symlink target is the zone name, which is how a disk or an AD1 answers
    wrong = []
    for target, want in (("/usr/share/zoneinfo/Europe/Berlin", "Europe/Berlin"),
                         ("../usr/share/zoneinfo/Asia/Tokyo", "Asia/Tokyo"),
                         ("/usr/share/zoneinfo/posix/UTC", "UTC"),
                         ("/etc/localtime", "")):
        got = L._zone_from_target(target)
        if got != want:
            wrong.append("%s -> %r, expected %r" % (target, got, want))
    for name, want in (("Europe/Berlin", True), ("UTC", True),
                       ("America/Argentina/Buenos_Aires", True),
                       ("Etc/GMT+5", True), ("", False),
                       ("garbage here", False), ("#comment", False)):
        if L.valid_zone(name) != want:
            wrong.append("valid_zone(%r) != %s" % (name, want))
    if wrong:
        res.fail("zone names", wrong[0])
    else:
        res.ok("zone names            symlink targets and validation")

    # and end to end, where the fixture carries one
    for name in ("ext4.img", "xfs.img", "btrfs.img"):
        path = fixture(name)
        if not path:
            res.skip("timezone %s" % name, "not built")
            continue
        col = L.DiskCollection(path, quiet=True)
        try:
            info = L.resolve_hosttz(col, None)
            if not info["zone"]:
                res.fail("timezone %s" % name,
                         "the fixture sets /etc/timezone and /etc/localtime "
                         "and neither was read")
            elif info["zone"] != "Europe/Berlin":
                res.fail("timezone %s" % name,
                         "read as %r" % info["zone"])
            else:
                res.ok("timezone %-14s %s from %s"
                       % (name, L.describe_hosttz(info), info["zone_source"]))
        finally:
            col.close()

def check_robustness(L, res):
    """Truncated and corrupted structures must degrade, never raise.

    This is the test for the *class* of bug that a real image found, rather
    than for the one instance of it. An ext2 /boot with 128-byte inodes read
    crtime from offset 0x90 - past the end of the inode - and took the whole
    run down with a struct.error. The fix was three bounds checks; the reason
    it happened at all is that every reader here parses structures whose size
    and contents come from the evidence, and the evidence is a decade of
    different mkfs defaults plus whatever an attacker left behind.

    So the readers are fed short buffers, zeroed buffers and random ones, and
    the assertion is only that nothing escapes as an exception. A reader may
    return nothing, and should; it may not raise.
    """
    print("\nrobustness - truncated and corrupt input must not raise")
    import random
    rng = random.Random(20260825)

    # inode-shaped buffers at every size a real filesystem has used, plus the
    # ones no filesystem uses
    problems = []
    path = fixture("ext4.img")
    if not path:
        res.skip("robustness", "ext4.img not built")
        return
    col = L.DiskCollection(path, quiet=True)
    try:
        fs = col.mounts[0][2]
        real = fs.inode(2)
        for size in (0, 1, 16, 64, 127, 128, 129, 160, 255, 256, 512):
            for label, raw in (("truncated", real[:size]),
                               ("zeroed", b"\x00" * size),
                               ("random", bytes(rng.randrange(256)
                                                for _ in range(size)))):
                try:
                    # the path a walk takes for every entry it meets
                    n = L.FsNode()
                    n._ref = raw
                    if len(raw) >= 128:
                        fs._time(raw, 0x08, 0x8C, 0)
                        fs._time(raw, 0x90, 0x94, 0, need=0x1C)
                        fs._map(n)
                        fs._dir_entries(n)
                except Exception as exc:
                    problems.append("%s inode of %d bytes: %s: %s"
                                    % (label, size, exc.__class__.__name__, exc))
    finally:
        col.close()
    if problems:
        res.fail("ext inode structures", problems[0] +
                 ("" if len(problems) == 1
                  else " (and %d more)" % (len(problems) - 1)))
    else:
        res.ok("ext inode structures  short, zeroed and random buffers")

    # a volume of garbage must be refused by every reader rather than crash
    problems = []
    for name, size in (("zeros", 1 << 20), ("random", 1 << 20), ("tiny", 512)):
        if name == "zeros":
            data = b"\x00" * size
        elif name == "tiny":
            data = b"\x00" * size
        else:
            data = bytes(rng.randrange(256) for _ in range(size))
        vol = _MemoryVolume(L, data)
        for probe_name in ("probe_ext", "probe_xfs", "probe_btrfs"):
            probe = getattr(L, probe_name, None)
            if probe is None:
                continue
            try:
                got = probe(vol)
            except Exception as exc:
                problems.append("%s on %s: %s: %s"
                                % (probe_name, name, exc.__class__.__name__, exc))
                continue
            if got is not None:
                problems.append("%s claimed to open %s bytes of %s"
                                % (probe_name, size, name))
    if problems:
        res.fail("filesystem probes", problems[0])
    else:
        res.ok("filesystem probes     zeros, random and truncated volumes")

    # and the containers: a file that is not the format it claims
    problems = []
    import tempfile
    for magic, ext in ((b"QFI\xfb" + b"\x00" * 200, ".qcow2"),
                       (b"KDMV" + b"\x00" * 200, ".vmdk"),
                       (b"vhdxfile" + b"\x00" * 200, ".vhdx"),
                       (b"EVF\x09\x0d\x0a\xff\x00" + b"\x00" * 200, ".E01")):
        fh = tempfile.NamedTemporaryFile(suffix=ext, delete=False)
        try:
            fh.write(magic)
            fh.close()
            try:
                img = L.open_image(fh.name)
                img.read(0, 4096)
                img.close()
            except L.ImageError:
                pass                    # refused by name, which is correct
            except Exception as exc:
                problems.append("%s header: %s: %s"
                                % (ext, exc.__class__.__name__, exc))
        finally:
            try:
                os.unlink(fh.name)
            except OSError:
                pass
    if problems:
        res.fail("container headers", problems[0])
    else:
        res.ok("container headers     truncated qcow2/vmdk/vhdx/E01")


class _MemoryVolume(object):
    """A volume backed by a bytes object, for feeding readers rubbish."""

    def __init__(self, L, data):
        self.data = data
        self.size = len(data)
        self.chunk = 1 << 16
        self.path = "memory"
        self.fstype = ""
        self.label = ""
        self.scheme = "whole"
        self.detail = ""

    def read(self, offset, length):
        if offset < 0 or length <= 0:
            return b""
        return self.data[offset:offset + length]


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
    check_distribution(L, res)
    check_filename_hunts(L, res)
    check_auth_sessions(L, res)
    check_inventory_times(L, res)
    check_timezone(L, res)
    check_robustness(L, res)

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
