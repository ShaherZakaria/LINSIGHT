# -*- coding: utf-8 -*-
"""The disk backend: a filesystem on a disk, presented as a collection.

Everything above the collection layer asks for artifacts by path - /etc/passwd,
/var/log/auth.log*, /home/*/.bash_history. A disk image holds those paths. So
supporting disks is not a second set of parsers and not a second tool: it is a
fourth backend, whose members are the files on the imaged filesystem, mounted
where they already live.

That is the whole design, and it is what makes the feature worth having. The
147 analyzers, the 88 tables, the Sigma and YARA engines, the timeline, the
IOC extraction and the console all run over a disk image unchanged, because
from where they sit a disk image and a UAC collection are the same thing.

Two things a disk gives that a triage collection cannot:

  the whole filesystem      A UAC profile collects what it was told to. A disk
                            has everything, including the file the profile did
                            not know to ask for.
  a real bodyfile           Built here from the inodes rather than parsed from
                            one the collector ran mktime to produce - so it
                            carries crtime, and it carries deleted inodes.

And one it cannot: nothing that only existed in RAM. There is no process list
on a dead disk, no socket table, no loaded-module list. Those tables come out
empty, and the report says why rather than leaving an empty table to be read
as a host that had no processes.
"""

from __future__ import annotations

import io
import os
import re
from collections import OrderedDict
from datetime import datetime, timezone

from .term import status
from .fsbase import GeneratedLines, epoch_seconds
from .collect import Collection
from .image import ImageError, open_image
from .volume import READABLE_FS, scan
from .fs_ext import probe_ext
from .fs_xfs import probe_xfs
from .fs_btrfs import probe_btrfs

#: Which reader opens a volume the volume layer has already identified. The
#: identification is done from the superblock magic, so this maps a name that
#: is already certain - it never guesses, and a filesystem with no entry here
#: is reported by name and left unread rather than fed to the wrong reader.
FS_PROBES = {
    "ext2": probe_ext, "ext3": probe_ext, "ext4": probe_ext,
    "xfs": probe_xfs, "btrfs": probe_btrfs,
}

#: How many names to take off one disk before stopping. A server root
#: filesystem is a few hundred thousand; a build host with node_modules can be
#: several million, and every one of them is an object held for the run. The
#: cap exists so that the failure is a stated truncation rather than a machine
#: that swaps to death four minutes in.
DEFAULT_MAX_FILES = 3000000


class DiskError(Exception):
    pass


class DiskCollection(Collection):
    """A disk image, or a live disk, read as a collection.

    Members are named the way a UAC collection names them - the copied
    filesystem under [root], so [root]/etc/passwd - which is what lets every
    parser above this class work without knowing a disk is involved.
    """

    def __init__(self, path, quiet=False, max_files=DEFAULT_MAX_FILES,
                 want_volume=None, deleted_limit=200000):
        self.path = os.path.abspath(path) if not _is_device_path(path) else path
        self.kind = "disk"
        self._tar = None
        self._zip = None
        self._sizes = {}
        self._mtimes = {}
        self._names = {}
        self._raw = {}
        self.prefix = ""
        # 'uac' is where the parsers look for a copied filesystem, so it is the
        # layout the members are named for. display_layout is what the report
        # prints, because a disk image did not come out of UAC and saying so
        # would misdescribe the evidence on the first line of every report.
        self.layout = "uac"
        self.display_layout = "disk image"
        self.rootfs_dirs = ["[root]"]
        self.velo = None
        self.time_hint = None
        self.time_hint_note = ""

        self._nodes = {}              # member -> FsNode
        self._virtual = {}            # member -> bytes
        self.notes = []
        self.volumes = []             # every volume found, for the report
        self.mounts = []              # (mountpoint, volume, filesystem)
        self.deleted_nodes = []
        self.scheme = "none"
        self.image = None

        self.image = open_image(self.path)
        self.volumes, notes, self.scheme = scan(self.image)
        self.display_layout = "%s, %s partitioning" % (self.image.description,
                                                       self.scheme)
        self.notes.extend(notes)
        if not quiet:
            status("[*] %s: %s, %s partitioning, %d volume(s)"
                   % (os.path.basename(self.path), self.image.description,
                      self.scheme, len(self.volumes)))
            for vol in self.volumes:
                status("      %s" % vol.describe())
            for note in notes:
                status("[!] %s" % note)

        self._mount(quiet, max_files, want_volume)
        # checked before the bodyfile is registered, because registering it
        # would put one member in _names and turn "nothing on this disk could
        # be read" into a run that produces empty tables
        if not self._names:
            raise DiskError(
                "no readable Linux filesystem on %s. Volumes found: %s"
                % (os.path.basename(self.path),
                   "; ".join(v.describe() for v in self.volumes) or "none"))
        self._collect_deleted(deleted_limit, quiet)
        self._add_bodyfile()

    # -- mounting -----------------------------------------------------------
    def _mount(self, quiet, max_files, want_volume):
        candidates = [v for v in self.volumes
                      if v.fstype in READABLE_FS and v.fstype in FS_PROBES]
        if want_volume:
            candidates = [v for v in candidates
                          if want_volume in (v.name, v.label,
                                             getattr(v, "lv_name", None))]
            if not candidates:
                raise DiskError("no volume called '%s' on this disk - the ones "
                                "here are: %s"
                                % (want_volume,
                                   ", ".join(v.name for v in self.volumes)))
        opened = []
        for vol in candidates:
            probe = FS_PROBES.get(vol.fstype)
            fs = probe(vol) if probe else None
            if fs is None:
                self.notes.append("%s says it is %s but its superblock would "
                                  "not parse" % (vol.name, vol.fstype))
                continue
            opened.append((vol, fs))
            self.notes.extend("%s: %s" % (vol.name, n) for n in fs.notes)

        if not opened:
            return
        root_vol, root_fs = self._pick_root(opened)
        layout = self._fstab_layout(root_fs)
        placed = [("/", root_vol, root_fs)]
        for vol, fs in opened:
            if fs is root_fs:
                continue
            point = self._mountpoint_for(vol, fs, layout)
            if point:
                placed.append((point, vol, fs))
            else:
                self.notes.append(
                    "%s (%s%s) is a Linux filesystem that /etc/fstab does not "
                    "place - it was not merged into the tree"
                    % (vol.name, fs.kind, ", '%s'" % fs.label if fs.label else ""))
        placed.sort(key=lambda p: p[0].count("/"))

        budget = max_files
        for point, vol, fs in placed:
            if budget <= 0:
                self.notes.append("stopped before mounting %s: the %s-name cap "
                                  "was reached" % (point, format(max_files, ",")))
                break
            taken = self._walk_into(fs, point, budget, quiet)
            budget -= taken
            self.mounts.append((point, vol, fs))
            if not quiet:
                status("[*] %s  %s on %s: %s name(s)"
                       % (point.ljust(6), fs.describe(), vol.name,
                          format(taken, ",")))
        if budget <= 0:
            self.notes.append(
                "the walk stopped at %s names; this disk holds more. Findings "
                "and tables cover what was read, which is not the whole disk - "
                "raise --disk-max-files to take all of it."
                % format(max_files, ","))

    def _pick_root(self, opened):
        """Which of the readable filesystems is the operating system's root.

        Asked of the filesystem rather than of the partition table, because a
        partition's type says what it was meant for and its content says what
        it is. A /boot partition and a root partition are both 'linux' in the
        GPT and only one of them has /etc/passwd in it.
        """
        best = None
        for vol, fs in opened:
            score = 0
            for probe_path in ("/etc/passwd", "/etc/shadow", "/etc/fstab",
                               "/etc/os-release", "/var/log", "/usr/bin",
                               "/root", "/etc/hostname"):
                if _exists(fs, probe_path):
                    score += 1
            if best is None or score > best[0] or \
                    (score == best[0] and fs.size > best[2].size):
                best = (score, vol, fs)
        if best[0] == 0:
            # nothing looks like a root; take the largest and say so
            self.notes.append(
                "no filesystem on this disk holds /etc - the largest one was "
                "read as the root, so paths may not be where the parsers "
                "expect them")
        return best[1], best[2]

    def _fstab_layout(self, root_fs):
        """{uuid or label or device -> mountpoint}, from the root's /etc/fstab.

        This is how a second partition gets mounted where it belongs. Guessing
        instead - '/boot because it is small and has vmlinuz in it' - puts
        files at paths the host never had, and a path is what every rule in
        this tool matches on.
        """
        out = {}
        node = _find(root_fs, "/etc/fstab")
        if node is None:
            return out
        try:
            text = root_fs.read(node).decode("utf-8", "replace")
        except Exception:
            return out
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) < 2 or not parts[1].startswith("/"):
                continue
            spec, point = parts[0], parts[1]
            if point == "/":
                continue
            key = spec
            if spec.upper().startswith("UUID="):
                key = "uuid:" + spec[5:].strip('"').lower()
            elif spec.upper().startswith("LABEL="):
                key = "label:" + spec[6:].strip('"')
            elif spec.startswith("/dev/"):
                key = "dev:" + spec
            out[key] = point
        return out

    def _mountpoint_for(self, vol, fs, layout):
        if fs.uuid and ("uuid:" + fs.uuid.lower()) in layout:
            return layout["uuid:" + fs.uuid.lower()]
        if fs.label and ("label:" + fs.label) in layout:
            return layout["label:" + fs.label]
        if getattr(vol, "scheme", "") == "lvm":
            vg, lv = vol.vg_name, vol.lv_name
            for spec in ("dev:/dev/mapper/%s-%s" % (vg.replace("-", "--"),
                                                    lv.replace("-", "--")),
                         "dev:/dev/mapper/%s-%s" % (vg, lv),
                         "dev:/dev/%s/%s" % (vg, lv)):
                if spec in layout:
                    return layout[spec]
        return ""

    def _walk_into(self, fs, mountpoint, budget, quiet):
        """Add every name in `fs` to the collection, under `mountpoint`."""
        prefix = "" if mountpoint == "/" else mountpoint.rstrip("/")
        count = 0
        newest = None
        for node in fs.walk(max_nodes=budget):
            path = prefix + node.path
            node.path = path
            member = "[root]" + path
            key = member.lower()
            self._names[key] = member
            self._sizes[key] = node.size
            self._nodes[member] = node
            count += 1
            if node.mtime and (newest is None or node.mtime > newest):
                newest = node.mtime
            if count >= budget:
                break
        # A disk carries no statement of when it was imaged, and a syslog line
        # carries no year, so without an anchor every 'Mar 24 22:11' lands in
        # 1900 and the timeline is worthless. The filesystem's own last write
        # is a better anchor than the newest mtime - it is the last moment the
        # host touched this filesystem, including the writes made by whatever
        # was happening at the end.
        anchor = fs.last_write or newest
        if anchor and (self.time_hint is None or anchor > self.time_hint):
            self.time_hint = anchor
            self.time_hint_note = (
                "last write to the %s filesystem on %s - a disk image carries "
                "no collection time, so this is the anchor for every 'recent' "
                "window below" % (fs.kind, mountpoint))
        return count

    # -- deleted ------------------------------------------------------------
    def _collect_deleted(self, limit, quiet):
        # 0 means --no-deleted, and has to short-circuit here: passing it down
        # as max_nodes would read as "no limit" and run the whole sweep, which
        # is the one thing the flag exists to avoid
        if limit <= 0:
            self.deleted_nodes = []
            return
        found = []
        for point, _vol, fs in self.mounts:
            try:
                for node in fs.deleted(max_nodes=limit - len(found)):
                    node.path = ("" if point == "/" else point.rstrip("/")) + \
                                node.path
                    found.append(node)
                    if len(found) >= limit:
                        break
            except Exception as exc:
                self.notes.append("scanning %s for deleted inodes failed: %s"
                                  % (point, exc))
            if len(found) >= limit:
                break
        self.deleted_nodes = found
        if found and not quiet:
            status("[*] %s deleted inode(s) still carry metadata"
                   % format(len(found), ","))

    # -- the synthetic bodyfile ---------------------------------------------
    def _add_bodyfile(self):
        """Register bodyfile/bodyfile.txt, generated from the inodes.

        UAC runs a collector to produce this file; here the same information
        is already in hand, so the member is registered and its content is
        produced line by line when something reads it. The table layer, the
        timeline and every analyzer that consults the bodyfile then work on a
        disk image with no changes at all - and get a better one, because this
        carries crtime and the deleted inodes.
        """
        member = "bodyfile/bodyfile.txt"
        self._names[member.lower()] = member
        # an estimate: the table layer only uses it for progress and reporting
        self._sizes[member.lower()] = (len(self._nodes) +
                                       len(self.deleted_nodes)) * 120
        self._virtual[member] = None          # generated, see _open

    def _bodyfile_lines(self):
        """mactime format: md5|name|inode|mode|uid|gid|size|atime|mtime|ctime|crtime."""
        for member in sorted(self._nodes):
            node = self._nodes[member]
            name = node.path
            if node.target:
                name = "%s -> %s" % (name, node.target)
            yield ("0|%s|%d|%s|%d|%d|%d|%d|%d|%d|%d\n"
                   % (name, node.inode, node.mode_string(), node.uid, node.gid,
                      node.size, epoch_seconds(node.atime), epoch_seconds(node.mtime),
                      epoch_seconds(node.ctime), epoch_seconds(node.crtime))
                   ).encode("utf-8", "surrogateescape")
        for node in self.deleted_nodes:
            yield ("0|%s (deleted)|%d|%s|%d|%d|%d|%d|%d|%d|%d\n"
                   % (node.path, node.inode, node.mode_string(), node.uid,
                      node.gid, node.size, epoch_seconds(node.atime),
                      epoch_seconds(node.mtime), epoch_seconds(node.ctime),
                      epoch_seconds(node.crtime))
                   ).encode("utf-8", "surrogateescape")

    # -- reading ------------------------------------------------------------
    def _open(self, real):
        if real in self._virtual:
            if real == "bodyfile/bodyfile.txt":
                return GeneratedLines(self._bodyfile_lines)
            return io.BytesIO(self._virtual[real] or b"")
        node = self._nodes.get(real)
        if node is None:
            raise IOError("no such member: %s" % real)
        if node.kind != "f":
            # a symlink's "content" is its target, which is what a parser
            # reading /etc/localtime through a link should get
            if node.kind == "l":
                return io.BytesIO(node.target.encode("utf-8", "replace"))
            return io.BytesIO(b"")
        return node.fs.open(node)

    def read_bytes(self, rel, limit=None):
        real = self.resolve(rel)
        if real is None:
            return None
        node = self._nodes.get(real)
        if node is not None and node.kind == "f":
            try:
                return node.fs.read(node, limit)
            except Exception:
                return None
        try:
            with self._open(real) as fh:
                return fh.read() if limit is None else fh.read(limit)
        except Exception:
            return None

    time_source = "filesystem"

    def member_kind(self, rel):
        node = self._nodes.get(self.resolve(rel) or "")
        return node.kind if node is not None else ""

    def member_time(self, rel):
        """All four times, read from the inode rather than from a container."""
        node = self._nodes.get(self.resolve(rel) or "")
        if node is None:
            return ("", "", "", "")
        return (_stamp(node.mtime), _stamp(node.atime), _stamp(node.ctime),
                _stamp(node.crtime))

    def node(self, rel):
        """The FsNode behind a collection-relative path, or None."""
        return self._nodes.get(self.resolve(rel) or "")

    # -- reporting ----------------------------------------------------------
    def report(self):
        """Rows for the DISK_LAYOUT table: one per volume, mounted or not."""
        rows = []
        mounted = {id(v): p for p, v, _f in self.mounts}
        for vol in self.volumes:
            fs = None
            for _p, v, f in self.mounts:
                if v is vol:
                    fs = f
                    break
            rows.append({
                "volume": vol.name,
                "scheme": vol.scheme,
                "label": vol.label or (fs.label if fs else ""),
                "type": vol.type_name,
                "filesystem": vol.fstype or "",
                "uuid": fs.uuid if fs else "",
                "offset": getattr(vol, "offset", ""),
                "size": vol.size,
                "mounted_at": mounted.get(id(vol), ""),
                "detail": vol.detail or (fs.describe() if fs else ""),
            })
        return rows

    def meta_rows(self):
        """(key, value) pairs describing the disk, for METADATA."""
        out = OrderedDict()
        out["Disk image"] = self.path
        out["Disk container"] = self.image.description if self.image else ""
        if self.image and len(self.image.parts) > 1:
            out["Disk segments"] = "%d files" % len(self.image.parts)
        out["Disk size"] = "%d bytes" % (self.image.size if self.image else 0)
        out["Partitioning"] = self.scheme
        out["Volumes"] = "%d found, %d mounted" % (len(self.volumes),
                                                   len(self.mounts))
        for point, vol, fs in self.mounts:
            out["Mounted %s" % point] = "%s on %s%s" % (
                fs.describe(), vol.name,
                " (uuid %s)" % fs.uuid if fs.uuid else "")
        if self.deleted_nodes:
            out["Deleted inodes"] = "%d recovered from inode tables" % \
                len(self.deleted_nodes)
        for i, note in enumerate(self.notes, 1):
            out["Disk note %d" % i] = note
        return out

    def close(self):
        if self.image is not None:
            self.image.close()


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _find(fs, path):
    """Resolve one absolute path without walking the whole filesystem.

    Asked before the walk, to decide which filesystem is the root one and to
    read its /etc/fstab. The walk is the expensive part and the answer here is
    a handful of directory reads, so the question has to be answerable without
    paying for it.
    """
    node = fs.root_node()
    if node is None:
        return None
    walked = ""
    parts = [p for p in path.split("/") if p]
    for i, part in enumerate(parts):
        found = None
        for name, ref, hint in fs.dir_entries(node):
            if name == part:
                found = (ref, hint)
                break
        if found is None:
            return None
        walked += "/" + part
        node = fs.node_at(found[0], walked, found[1])
        if node is None:
            return None
        if i < len(parts) - 1 and not node.is_dir:
            return None
    return node


def _exists(fs, path):
    try:
        return _find(fs, path) is not None
    except Exception:
        return False


def _is_device_path(path):
    return path.replace("/", "\\").upper().startswith("\\\\.\\")


def looks_like_disk_arg(path):
    """Whether this command-line argument should go to the disk backend."""
    from .image import looks_like_disk
    try:
        return looks_like_disk(path)
    except Exception:
        return False


def _stamp(when):
    """A filesystem time as the string every table prints, or ''."""
    if not when:
        return ""
    try:
        return when.strftime("%Y-%m-%d %H:%M:%S")
    except (AttributeError, ValueError):
        return ""
