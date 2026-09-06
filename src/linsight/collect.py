# -*- coding: utf-8 -*-
from __future__ import annotations

from datetime import datetime
from datetime import timezone
import fnmatch
import io
import json
import os
import re
import sys
import tarfile
import urllib.parse
import zipfile

from .term import status



# ---------------------------------------------------------------------------
# collection access (directory / tar / zip backends)
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# loose files: --file, for when there is no collection at all
# ---------------------------------------------------------------------------
#
# Where a loose file has to sit for the parsers to find it. Every entry is
# (basename pattern, destination). A destination starting with '/' is a host
# absolute path and is mounted under the synthetic [root]; one that does not
# is a collection-relative command-output path, which is where UAC puts the
# artifacts that never existed as files on the host at all.
#
# '{name}' keeps the file's own name, and that is what makes rotations work:
# the parsers glob '/var/log/auth.log*', so auth.log.1 and auth.log.2.gz have
# to arrive under their own names instead of being flattened onto auth.log. A
# literal destination is used in the two cases where the name is not free -
# where a parser wants one exact path (/etc/passwd), and where the name has to
# match a command glob it would not otherwise match ('ps*.txt').
#
# Most log-shaped files need no entry more specific than the directory: the
# sweep in _log_files() hands everything under /var/log to VAR_LOG, JOURNAL,
# LOGIN_RECORDS, LASTLOG and WTMPDB, which pick their own by basename. The
# entries below exist for the files that would otherwise be routed somewhere
# useless, not to re-state that routing.
ARTIFACT_ROUTES = (
    # -- /var/log ----------------------------------------------------------
    (r"^auth\.log", "/var/log/{name}"),
    (r"^secure($|[._-])", "/var/log/{name}"),
    (r"^syslog", "/var/log/{name}"),
    (r"^messages($|[._-])", "/var/log/{name}"),
    (r"^kern\.log", "/var/log/{name}"),
    (r"^daemon\.log", "/var/log/{name}"),
    (r"^debug($|[._-])", "/var/log/{name}"),
    (r"^cron($|[._-])", "/var/log/{name}"),
    (r"^boot\.log", "/var/log/{name}"),
    (r"^(mail\.log|maillog)", "/var/log/{name}"),
    (r"^ufw\.log", "/var/log/{name}"),
    (r"^dpkg\.log", "/var/log/{name}"),
    (r"^(yum|dnf)\.log", "/var/log/{name}"),
    (r"^audit\.log", "/var/log/audit/{name}"),
    # apt writes both of these; neither name says 'apt' on its own
    (r"^history\.log", "/var/log/apt/{name}"),
    (r"^term\.log", "/var/log/apt/{name}"),
    (r"\.journal($|[~.])", "/var/log/journal/local/{name}"),
    # -- binary login records ----------------------------------------------
    # wtmpdb is a SQLite file and is read from its own path, not /var/log
    (r"^(wtmpdb|wtmp\.db)$", "/var/lib/wtmpdb/wtmp.db"),
    (r"^wtmp", "/var/log/{name}"),
    (r"^btmp", "/var/log/{name}"),
    (r"^utmp", "/var/run/{name}"),
    (r"^lastlog", "/var/log/{name}"),
    (r"^faillog", "/var/log/{name}"),
    # -- web logs ----------------------------------------------------------
    # the parser's own '/var/log/*access*log*' fallbacks catch these by name,
    # so they only need to land in /var/log; the server column stays empty
    # because a loose file does not say which daemon wrote it
    (r"(access|error)[._-]?log", "/var/log/{name}"),
    (r"^ssl_(request|access|error)", "/var/log/{name}"),
    # -- accounts and configuration ----------------------------------------
    (r"^passwd-$", "/etc/passwd-"),
    (r"^passwd$", "/etc/passwd"),
    (r"^shadow$", "/etc/shadow"),
    (r"^group$", "/etc/group"),
    (r"^gshadow$", "/etc/gshadow"),
    (r"^sudoers$", "/etc/sudoers"),
    (r"^sudoers[._-]", "/etc/sudoers.d/{name}"),
    (r"^sshd_config$", "/etc/ssh/sshd_config"),
    (r"^ssh_config$", "/etc/ssh/ssh_config"),
    (r"^authorized_keys2?$", "/root/.ssh/{name}"),
    (r"^known_hosts$", "/root/.ssh/known_hosts"),
    (r"^crontab$", "/etc/crontab"),
    (r"^anacrontab$", "/etc/anacrontab"),
    (r"^ld\.so\.preload$", "/etc/ld.so.preload"),
    (r"^ld\.so\.conf$", "/etc/ld.so.conf"),
    (r"^fstab$", "/etc/fstab"),
    (r"^hosts$", "/etc/hosts"),
    (r"^hostname$", "/etc/hostname"),
    (r"^os-release$", "/etc/os-release"),
    (r"^machine-id$", "/etc/machine-id"),
    (r"^resolv\.conf$", "/etc/resolv.conf"),
    (r"^localtime$", "/etc/localtime"),
    (r"^environment$", "/etc/environment"),
    (r"^rc\.local$", "/etc/rc.local"),
    (r"^modules$", "/etc/modules"),
    (r"\.(service|timer|socket)$", "/etc/systemd/system/{name}"),
    # -- shell history -----------------------------------------------------
    # the parser globs '**/.bash_history', so the leading dot is not optional
    # and the destination cannot keep a dotless name
    (r"^\.?bash_history$", "/.bash_history"),
    (r"^\.?zsh_history$", "/.zsh_history"),
    (r"^\.?sh_history$", "/.sh_history"),
    (r"^\.?ksh_history$", "/.ksh_history"),
    (r"^\.?python_history$", "/.python_history"),
    (r"^\.?mysql_history$", "/.mysql_history"),
    (r"^\.?psql_history$", "/.psql_history"),
    (r"^\.?viminfo$", "/.viminfo"),
    # -- command output ----------------------------------------------------
    # these never existed as files on the host, so they go where UAC's runner
    # would have written them - and under a name the extractor's glob matches
    (r"^ps($|[._-])|^ps_?(aux|ef|axjf)", "live_response/process/ps_aux.txt"),
    (r"^pstree", "live_response/process/pstree_-a.txt"),
    (r"^top($|[._-])", "live_response/process/top.txt"),
    (r"^lsof", "live_response/network/lsof_-nPli.txt"),
    (r"^netstat", "live_response/network/netstat_-anp.txt"),
    (r"^ss($|[._-])", "live_response/network/ss_-anp.txt"),
    (r"^lsmod", "live_response/system/lsmod.txt"),
    (r"^ip6?tables", "live_response/network/iptables_-L.txt"),
    (r"^nft", "live_response/network/nft_list_ruleset.txt"),
    (r"^ifconfig", "live_response/network/ifconfig_-a.txt"),
    (r"^ip_?addr|^ip_a$", "live_response/network/ip_addr_show.txt"),
    (r"^(ip_?)?route", "live_response/network/ip_route_show.txt"),
    (r"^arp", "live_response/network/arp_-an.txt"),
    (r"^dmesg", "live_response/hardware/dmesg.txt"),
)
ARTIFACT_ROUTES = tuple((re.compile(p, re.I), d) for p, d in ARTIFACT_ROUTES)

# A loose path whose first segment is one of these is already shaped like a
# host tree, so it is mounted as it stands rather than routed by name. This is
# what makes '--file ./extracted/etc/passwd' and '--file ./rootfs-copy/' work
# without a rule per file.
HOST_ANCHORS = ("etc", "var", "usr", "root", "home", "run", "opt", "srv",
                "boot", "lib", "lib64", "proc", "sys", "tmp", "mnt", "media")

# Where an unidentified file goes when it decodes as text. /var/log is swept
# wholesale by VAR_LOG, which splits syslog-shaped lines into columns and keeps
# anything else verbatim - so an unknown log still gets parsed, dated and
# hunted rather than being dropped for want of a rule.
TEXT_FALLBACK = "/var/log/{name}"


def _zip_time(zi):
    """A zip member's mtime as an epoch, or 0.

    Zip stores local time with no zone and two-second resolution, so this is
    the host's clock rather than UTC. It is still the collector's own record
    of when the file was last written, which is worth more than nothing - and
    the table that prints it says where it came from.
    """
    try:
        return datetime(*zi.date_time).timestamp()
    except (ValueError, TypeError, OverflowError, OSError):
        return 0


def route_artifact(name, rel=None, is_text=True):
    """Loose file -> (destination, how it was decided).

    `rel` is the path the file was given under, which is consulted before the
    name: a file that arrives as 'etc/passwd' says what it is more reliably
    than any pattern can guess.
    """
    parts = [x for x in (rel or "").replace("\\", "/").split("/") if x and x != "."]
    if len(parts) > 1 and parts[0].lower() in HOST_ANCHORS:
        return "/" + "/".join(parts), "path"
    for rx, dest in ARTIFACT_ROUTES:
        if rx.search(name):
            return dest.replace("{name}", name), "name"
    if is_text:
        return TEXT_FALLBACK.replace("{name}", name), "text fallback"
    return None, "unidentified"


class Collection:
    """Uniform read access to a triage collection, extracted or archived.

    Layout - which tool produced the collection, and therefore where its
    command output and its filesystem copy live - is detected here and nowhere
    else. Everything above this class asks for artifacts by collection-relative
    path or by host absolute path and does not know the difference.
    """

    def __init__(self, path):
        self.path = os.path.abspath(path)
        self.kind = None
        self._tar = None
        self._zip = None
        self._sizes = {}
        self._mtimes = {}         # lowercase relative name -> epoch, where known
        self._names = {}          # lowercase relative name -> the same name, cased
        self._raw = {}            # lowercase relative name -> archive member name
        self._owners = {}         # lowercase relative name -> tar uname/uid
        self.prefix = ""          # archive dir that holds the layout's marker
        self.mounted_root = False # the collection root IS the host filesystem
        self.layout = "uac"       # 'uac' or 'velociraptor'; see _find_prefix
        self._load()
        self._find_prefix()
        self._mount_host_tree()
        self.rootfs_dirs = self._find_rootfs_dirs()
        self.velo = VelociraptorResults(self) if self.layout == "velociraptor" else None

    # -- loading ------------------------------------------------------------
    @staticmethod
    def _norm_member(name):
        """Archive member name -> collection-relative path.

        Two things had to stop happening here.

        `tar -C dir -cf out.tar .` writes every member as './[root]/etc/passwd',
        and the old code kept that raw name as the value in _names while keying
        on the stripped one. glob() then returned './[root]/...', which
        resolve() could not look up, so read_bytes() returned None for every
        artifact found by glob - silently. Findings reached by an exact path
        (/etc/passwd) still fired, so the collection looked parsed while every
        log matched by a pattern had vanished.

        And the strip itself was lstrip('./'), a character class rather than a
        prefix: './.bash_history' came out as 'bash_history' and './.ssh/x' as
        '.ssh/x' only by luck of the next character. Dotfiles are exactly the
        persistence artifacts this tool exists to find.
        """
        n = (name or "").replace("\\", "/")
        while n.startswith("./"):
            n = n[2:]
        return n.lstrip("/")

    def _add_member(self, rel, raw, size, mtime=None):
        """Record one file under its normalised name.

        _names carries the normalised name so that everything a glob or a walk
        hands back can be fed straight to read_bytes(); _raw carries whatever
        the archive actually calls it, which only _open() needs.

        `mtime` is what the container says about the file's modification time,
        as an epoch. On a tar or a zip of a copied filesystem that is the
        host's own mtime, preserved by the collector - which makes it evidence
        rather than bookkeeping, and is why it is kept for every member rather
        than looked up later for the few that get parsed.
        """
        key = rel.lower()
        # One object where the two are equal. `.lower()` always builds a new
        # string, so a path that is already lowercase - most of a Linux
        # filesystem - was stored twice: measured 228 bytes per name against
        # 157 when the pair is shared, which is 685 MB against 472 MB at the
        # three million names --disk-max-files allows.
        self._names[key] = key if key == rel else rel
        self._sizes[key] = size
        if mtime:
            self._mtimes[key] = mtime
        if raw != rel:
            self._raw[key] = raw

    def member_kind(self, rel):
        """'f', 'd', 'l' or '' - what this member is, where the backend knows.

        A directory listing backend has only files in it, so the base answer
        is 'f'. The backends that read a filesystem know better and say so.
        """
        return "f"

    #: What a member time means for this backend, said out loud because it
    #: differs and the difference matters. Overridden by the backends that
    #: read the source filesystem's own metadata.
    time_source = "archive"

    def member_owner(self, rel):
        """Who the container says owns this file, or '' where it says nothing.

        A tar written by the collector on the host carries the host's own
        uname and gname in every header, which makes it the same kind of
        evidence as the mtime beside it - weaker than an inode read but the
        only answer a collection with no bodyfile has. A zip has no POSIX
        owner to carry, and the owner of an extracted directory is whoever
        ran tar -x, so both answer nothing rather than answering wrongly.
        """
        return self._owners.get((self.prefix + rel.lstrip("/")).lower(), "")

    def member_time(self, rel):
        """(mtime, atime, ctime, crtime) for a member, as UTC strings.

        Only mtime is knowable from an archive or a directory listing. The
        backends that read a filesystem themselves - a disk, an AD1 - override
        this and answer all four.
        """
        key = (self.prefix + rel.lstrip("/")).lower()
        stamp = self._mtimes.get(key)
        if not stamp:
            return ("", "", "", "")
        try:
            return (datetime.fromtimestamp(stamp, timezone.utc)
                    .strftime("%Y-%m-%d %H:%M:%S"), "", "", "")
        except (OverflowError, OSError, ValueError):
            return ("", "", "", "")

    def _load(self):
        if os.path.isdir(self.path):
            self.kind = "dir"
            base = self.path
            for dirpath, _dirnames, filenames in os.walk(base):
                for fn in filenames:
                    full = os.path.join(dirpath, fn)
                    rel = os.path.relpath(full, base).replace(os.sep, "/")
                    try:
                        size = os.path.getsize(full)
                    except OSError:
                        size = 0
                    try:
                        mtime = os.path.getmtime(full)
                    except OSError:
                        mtime = 0
                    self._add_member(rel, rel, size, mtime)
        elif zipfile.is_zipfile(self.path):
            self.kind = "zip"
            self._zip = zipfile.ZipFile(self.path)
            encrypted = 0
            for zi in self._zip.infolist():
                if zi.is_dir():
                    continue
                if zi.flag_bits & 0x1:
                    encrypted += 1
                rel = self._norm_member(zi.filename)
                if not rel:
                    continue
                self._add_member(rel, zi.filename, zi.file_size,
                                 _zip_time(zi))
            self._check_sealed(encrypted)
        else:
            self._check_foreign()
            self.kind = "tar"
            try:
                self._tar = tarfile.open(self.path, "r:*")
            except OSError as exc:
                raise SystemExit("[!] cannot open %s: %s" % (self.path, exc))
            except (tarfile.TarError, EOFError):
                # tarfile's own message is a list of the compressors it is
                # not, which says nothing about what the file is. What the
                # analyst needs here is the set of things that would work.
                raise SystemExit(
                    "[!] %s is not something linsight reads.\n"
                    "    It is not a directory, a tar, a zip, or a disk image "
                    "this reader recognises.\n"
                    "    Expected one of:\n"
                    "      a UAC or Velociraptor collection - a directory, "
                    ".tar, .tar.gz or .zip\n"
                    "      a disk - .dd/.raw, .E01, .qcow2, .vmdk, .vhdx, "
                    ".vhd, or a device\n"
                    "      loose files - pass them with --file instead\n"
                    "    If it IS a disk image whose header is damaged or "
                    "missing, force it with --disk."
                    % os.path.basename(self.path))
            for ti in self._tar.getmembers():
                if not ti.isfile():
                    continue
                rel = self._norm_member(ti.name)
                if not rel:
                    continue
                self._add_member(rel, ti.name, ti.size, ti.mtime)
                # Interned: a host has a handful of distinct owners and a
                # collection has thousands of files, so the dict holds one
                # pointer per member rather than one string. uname where the
                # header carries it, the numeric uid where it does not -
                # which is what a tar written on a host with no matching
                # passwd entry looks like, and is itself worth seeing.
                own = ti.uname or (str(ti.uid) if ti.uid is not None else "")
                if own:
                    self._owners[rel.lower()] = sys.intern(own)
        if not self._names:
            raise SystemExit("[!] no readable files found in %s" % self.path)

    # Containers that are evidence, and are not a collection this tool reads.
    # Each is named rather than guessed at: an analyst who points linsight at
    # an AD1 needs to be told it is an AD1 and what turns it into something
    # readable. "not a gzip file" is a true statement and the wrong answer.
    #
    # (magic, what it is, what to do about it)
    FOREIGN = (
        # AD1 itself is read by the ad1 module and never reaches here; what
        # does reach here is one whose set is broken up, so say that rather
        # than "not a gzip file"
        (b"ADCRYPTEDFILE\x00", "an encrypted AccessData image",
         "Decrypt it in FTK Imager first."),
        (b"7z\xbc\xaf\x27\x1c", "a 7-Zip archive",
         "Extract it, then point linsight at the result."),
        (b"Rar!\x1a\x07", "a RAR archive",
         "Extract it, then point linsight at the result."),
        (b"SQLite format 3\x00", "a SQLite database",
         "That is one artifact, not a collection - pass it with --file."),
        (b"\x89PNG\r\n\x1a\n", "a PNG image", "That is not evidence this "
         "tool parses."),
        (b"%PDF-", "a PDF", "That is not evidence this tool parses."),
    )

    def _check_foreign(self):
        """Stop on a container that is recognisable and is not a collection.

        This runs before the tar backend is tried, because tarfile's own
        failure is a list of the compressors it is not, which says nothing
        about what the file actually is. A wrong tool for the evidence should
        end with the name of the evidence and the way forward.
        """
        try:
            with open(self.path, "rb") as fh:
                head = fh.read(64)
        except OSError as exc:
            raise SystemExit("[!] cannot read %s: %s" % (self.path, exc))
        for magic, what, advice in self.FOREIGN:
            if head.startswith(magic):
                raise SystemExit(
                    "[!] %s is %s.\n"
                    "    linsight reads UAC and Velociraptor collections, disk "
                    "images, and loose files.\n"
                    "    %s"
                    % (os.path.basename(self.path), what, advice))
        # a lone compressed file, rather than a compressed tar: that is one
        # artifact and --file is what parses one artifact
        for magic, name in ((b"\x1f\x8b", "gzip"), (b"BZh", "bzip2"),
                            (b"\xfd7zXZ\x00", "xz"), (b"\x28\xb5\x2f\xfd",
                                                      "zstd")):
            if head.startswith(magic):
                try:
                    tarfile.open(self.path, "r:*").close()
                except Exception:
                    raise SystemExit(
                        "[!] %s is %s-compressed but is not a tar archive.\n"
                        "    If it is one artifact - a rotated log, a copied "
                        "database - pass it with --file,\n"
                        "    which decompresses it and parses it as itself:\n"
                        "      python linsight.py --file %s"
                        % (os.path.basename(self.path), name,
                           os.path.basename(self.path)))
                break

    def _check_sealed(self, encrypted):
        """Stop on a collection whose contents cannot actually be read.

        Both of these open, list their members and then return nothing from
        every one of them, so without this the run completes and exports a set
        of empty tables - which reads as a host with no evidence on it. An
        unreadable collection has to fail loudly at the point it is opened.
        """
        if encrypted and encrypted == len(self._names):
            raise SystemExit(
                "[!] every member of %s is encrypted.\n"
                "    Velociraptor's offline collector can seal a collection "
                "with a password or an X509 key.\n"
                "    Decrypt or unpack it first, then point this tool at the "
                "result." % os.path.basename(self.path))
        inner = [n for n in self._names if n.endswith(".zip")]
        if "metadata.json" in self._names and len(self._names) <= 3 and inner:
            raise SystemExit(
                "[!] %s looks like a sealed Velociraptor container: it holds "
                "%s and metadata.json\n"
                "    rather than a collection. Unpack the inner archive and "
                "point this tool at that."
                % (os.path.basename(self.path), self._names[inner[0]]))

    # A file that identifies the producing tool, and by its position the
    # collection root.
    LAYOUT_MARKERS = (
        ("velociraptor", "collection_context.json"),
        ("velociraptor", "uploads.json"),
        ("uac", "uac.log"),
    )
    # No marker file - fall back to the top-level tree each layout owns.
    LAYOUT_DIRS = (
        ("uac", "live_response/"),
        ("velociraptor", "results/"),
        ("velociraptor", "uploads/"),
    )

    def _find_prefix(self):
        """Locate the collection root, and with it which tool produced it.

        Depth decides, not the order of the marker list. Both of these are
        real and they pull opposite ways: a UAC collection copies the whole
        filesystem, so a host that had ever run Velociraptor carries an
        uploads.json somewhere under [root] - and a Velociraptor collection
        that uploaded a UAC output directory carries a uac.log under uploads/.
        In both cases the marker at the top of the tree is the collection's own
        and the deep one belongs to the evidence. Picking by list order instead
        would read a Velociraptor collection as a UAC one rooted five
        directories inside the filesystem copy, which hides everything above
        it - and hides it silently, as an export of empty tables.
        """
        best = None                       # (depth, list rank, prefix, layout)
        for rank, (layout, marker) in enumerate(self.LAYOUT_MARKERS):
            for low in self._names:
                if low == marker or low.endswith("/" + marker):
                    cand = (low.count("/"), rank, low[: -len(marker)], layout)
                    if best is None or cand[:2] < best[:2]:
                        best = cand
        if best is None:
            for rank, (layout, d) in enumerate(self.LAYOUT_DIRS):
                for low in self._names:
                    idx = low.find(d)
                    if idx < 0:
                        continue
                    cand = (low[:idx].count("/"), rank, low[:idx], layout)
                    if best is None or cand[:2] < best[:2]:
                        best = cand
        if best is not None:
            self.prefix, self.layout = best[2], best[3]

    # Velociraptor names an uploads subdirectory for the VFS accessor that read
    # the file. Only these two carry real host paths on Linux; a Windows
    # accessor in a mixed collection would put registry keys in the rootfs.
    VELO_ROOTFS_ACCESSORS = ("file", "auto")

    def _find_rootfs_dirs(self):
        """Where the copied host filesystem lives, per layout.

        UAC stores it under [root] (or [<mountpoint>]). Velociraptor stores it
        under uploads/<accessor>/. Which accessors a collection used depends on
        the artifacts it ran, so they are discovered, not assumed - naming one
        that this collection did not use costs every filesystem table silently.
        """
        found = []
        plen = len(self.prefix)
        if self.layout == "velociraptor":
            for low in self._names:
                if not low.startswith(self.prefix):
                    continue
                seg = low[plen:].split("/")
                if len(seg) >= 3 and seg[0] == "uploads" and \
                        seg[1] in self.VELO_ROOTFS_ACCESSORS:
                    acc = "uploads/" + seg[1]
                    if acc not in found:
                        found.append(acc)
            return found or ["uploads/file"]
        for low in self._names:
            if not low.startswith(self.prefix):
                continue
            rest = low[plen:]
            if rest.startswith("["):
                top = rest.split("/", 1)[0]
                if top not in found:
                    found.append(top)
        return found or ["[root]"]

    #: A directory whose top level holds this many of the anchors below is a
    #: host filesystem rather than a collection. Two is deliberate: /etc alone
    #: could be a copied-out fragment, and demanding four would miss the
    #: minimal container images that have /etc, /usr and nothing else.
    HOST_TREE_MIN = 2

    def _mount_host_tree(self):
        """Re-key a host filesystem root as though it were a copied one.

        This is what an analyst gets by mounting an image - with a forensic
        mounter, losetup, or by plugging the disk in - and pointing linsight
        at the mountpoint. Read as an ordinary collection it produced a report
        with no users, no logs and no cron in it: every parser asks for
        /etc/passwd under the filesystem copy, and /etc/passwd was sitting
        right there at the top with no prefix at all. An empty report reads as
        a host with nothing on it, which is the one answer this tool must
        never invent.

        The fix is not a special case downstream. The members are renamed to
        the [root]/... the parsers already look for, and _raw keeps what they
        are really called on disk - which is the same mechanism that already
        maps './[root]/etc/passwd' inside a tar back to its member name. From
        here on this is indistinguishable from a UAC collection.
        """
        if self.prefix or not self._looks_like_host_tree():
            return
        names, sizes, mtimes, raw = {}, {}, {}, {}
        for low, real in self._names.items():
            member = "[root]/" + real.lstrip("/")
            key = member.lower()
            names[key] = member
            sizes[key] = self._sizes.get(low, 0)
            if low in self._mtimes:
                mtimes[key] = self._mtimes[low]
            raw[key] = self._raw.get(low, real)
        self._names, self._sizes, self._mtimes, self._raw =             names, sizes, mtimes, raw
        self.mounted_root = True

    def _looks_like_host_tree(self):
        """Whether the collection root is itself a host filesystem root."""
        tops = set()
        plen = len(self.prefix)
        for low in self._names:
            if not low.startswith(self.prefix):
                continue
            rest = low[plen:]
            if "/" in rest:
                tops.add(rest.split("/", 1)[0])
        hits = tops & set(HOST_ANCHORS)
        # /etc is what every parser here actually needs; a tree without it is
        # not one this would gain anything from being read as
        return len(hits) >= self.HOST_TREE_MIN and "etc" in hits

    # -- lookup -------------------------------------------------------------
    def resolve(self, rel):
        """Collection-relative path -> real member name, or None."""
        if rel is None:
            return None
        key = (self.prefix + rel.lstrip("/")).lower()
        return self._names.get(key)

    def exists(self, rel):
        return self.resolve(rel) is not None

    def size(self, rel):
        key = (self.prefix + rel.lstrip("/")).lower()
        return self._sizes.get(key, 0)

    def rootfs(self, abspath):
        """Absolute path on the collected host -> collection-relative path."""
        p = abspath.lstrip("/")
        for rd in self.rootfs_dirs:
            cand = "%s/%s" % (rd, p)
            if self.exists(cand):
                return cand
        return None

    @staticmethod
    def escape_glob(text):
        """Quote fnmatch metacharacters in a literal path fragment.

        UAC names its filesystem copy '[root]', which fnmatch would otherwise
        read as the character class [rot] and match nothing.
        """
        # single pass - chained str.replace would re-escape the brackets it just
        # inserted and produce a pattern that matches nothing
        return "".join("[[]" if ch == "[" else "[]]" if ch == "]" else ch for ch in text)

    @staticmethod
    def _match_path(name, pattern):
        """fnmatch, but '*' stops at a path separator - like a real shell.

        Plain fnmatch lets '*' cross '/', so '/home/*/.*history*' also matched
        '/home/u/.config/Code/User/History/oGyX.py'.  Segments are matched one
        at a time; '**' is the explicit opt-in for spanning directories.
        """
        pseg = pattern.split("/")
        nseg = name.split("/")
        if "**" not in pseg:
            if len(pseg) != len(nseg):
                return False
            return all(fnmatch.fnmatchcase(n, p) for n, p in zip(nseg, pseg))
        i = pseg.index("**")
        head, tail = pseg[:i], pseg[i + 1:]
        if len(nseg) < len(head) + len(tail):
            return False
        return (all(fnmatch.fnmatchcase(n, p) for n, p in zip(nseg, head))
                and all(fnmatch.fnmatchcase(n, p)
                        for n, p in zip(nseg[len(nseg) - len(tail):], tail)))

    #: Characters that make a path fragment a pattern rather than a literal.
    GLOB_META = "*?["

    def _dir_index(self):
        """{parent directory -> [lowercased name]}, built once.

        glob() used to walk all of _names for every pattern. That is fine for
        a handful of patterns and ruinous for the extractors that build one
        per home directory: t_history asks for eleven filenames under every
        home /etc/passwd declares, which on a host with twenty accounts is
        220 full passes over 85,000 names - and measured 19.8s of a 143s run
        for 366 rows of output.

        Bucketing by parent directory turns the common case - a pattern whose
        directory part is literal - into one dict lookup and a handful of
        fnmatch calls. A pattern with a wildcard in the directory part still
        has to try each directory, but there are far fewer directories than
        files, so even that is an order of magnitude less work.

        The buckets hold the key alone and the real name is looked up from
        _names, because a list of (key, name) pairs costs a tuple per file on
        top of the index it is indexing: measured at 73 bytes per name against
        9 for the key alone, which is 218 MB against 26 MB at the three
        million names --disk-max-files allows. The lookup it saves is one dict
        hit on a dict that has to be in memory anyway.
        """
        idx = getattr(self, "_dirs_cache", None)
        if idx is None:
            idx = {}
            for low in self._names:
                cut = low.rfind("/")
                idx.setdefault(low[:cut] if cut >= 0 else "", []).append(low)
            self._dirs_cache = idx
        return idx

    def glob(self, pattern):
        """Shell-style match over collection-relative names (case-insensitive)."""
        pat = (self.escape_glob(self.prefix) + pattern.lstrip("/")).lower()
        plen = len(self.prefix)
        out = []

        # '**' spans directories, so the bucket a name sits in says nothing
        # about whether it matches - that case keeps the full scan.
        if "**" in pat.split("/"):
            for low, real in self._names.items():
                if self._match_path(low, pat):
                    out.append(real[plen:])
            return sorted(out)

        cut = pat.rfind("/")
        dirpat, basepat = (pat[:cut], pat[cut + 1:]) if cut >= 0 else ("", pat)
        index = self._dir_index()
        if any(ch in dirpat for ch in self.GLOB_META):
            buckets = [v for d, v in index.items()
                       if self._match_path(d, dirpat)]
        else:
            buckets = [index.get(dirpat, ())]
        names = self._names
        for bucket in buckets:
            for low in bucket:
                if fnmatch.fnmatchcase(low[low.rfind("/") + 1:], basepat):
                    out.append(names[low][plen:])
        return sorted(out)

    def rootfs_glob(self, pattern):
        """fnmatch over host absolute paths, e.g. '/etc/cron.d/*'."""
        out = []
        for rd in self.rootfs_dirs:
            out.extend(self.glob("%s/%s" % (self.escape_glob(rd), pattern.lstrip("/"))))
        return sorted(set(out))

    def host_path(self, rel):
        """Collection-relative [root]/... path -> host absolute path."""
        for rd in self.rootfs_dirs:
            if not rd:
                # the collection root is the host root, so the member name is
                # already the host path bar its leading slash
                return "/" + rel.lstrip("/")
            if rel.lower().startswith(rd + "/"):
                return "/" + rel[len(rd) + 1:]
        return rel

    # -- reading ------------------------------------------------------------
    def _open(self, real):
        if self.kind == "dir":
            # _raw carries what the file is really called under self.path,
            # which differs from its member name when a mounted filesystem
            # root was re-keyed under [root]/
            return open(os.path.join(self.path,
                                     self._raw.get(real.lower(), real)), "rb")
        # back to whatever the archive calls it - './[root]/etc/passwd' where
        # the rest of the tool says '[root]/etc/passwd'
        member = self._raw.get(real.lower(), real)
        if self.kind == "zip":
            return self._zip.open(member, "r")
        f = self._tar.extractfile(member)
        if f is None:
            raise IOError("not a regular file: %s" % member)
        return f

    def read_bytes(self, rel, limit=None):
        real = self.resolve(rel)
        if real is None:
            return None
        try:
            with self._open(real) as fh:
                return fh.read() if limit is None else fh.read(limit)
        except Exception:
            return None

    def text(self, rel, limit=None):
        raw = self.read_bytes(rel, limit)
        if raw is None:
            return None
        # a UTF-8 BOM would otherwise ride along on the first line and stop it
        # matching any comment marker or timestamp anchor
        if raw[:3] == b"\xef\xbb\xbf":
            raw = raw[3:]
        return raw.decode("utf-8", "replace")

    def lines(self, rel, limit=None):
        txt = self.text(rel, limit)
        if txt is None:
            return []
        return [ln.rstrip("\r\n") for ln in txt.splitlines()]

    def iter_lines(self, rel):
        """Streaming line iteration - use for the multi-hundred-MB artifacts."""
        real = self.resolve(rel)
        if real is None:
            return
        try:
            fh = self._open(real)
        except Exception:
            return
        try:
            for raw in io.TextIOWrapper(fh, encoding="utf-8", errors="replace"):
                yield raw.rstrip("\r\n")
        finally:
            try:
                fh.close()
            except Exception:
                pass


class FilesCollection(Collection):
    """A collection assembled from loose files, for --file.

    The parsers never ask 'which tool produced this collection'. They ask for
    /etc/passwd, for /var/log/auth.log*, for live_response/process/ps*.txt -
    and Collection answers, whatever the container underneath happens to be.
    So the way to parse a single auth.log is not a second set of parsers: it
    is a fourth backend, one whose members are loose files mounted at the
    paths those questions already name.

    Everything above this class then works unchanged - the analyzers, the 90
    tables, Sigma and YARA, the findings, the console. A file that routes to
    /var/log/auth.log is parsed by exactly the code that parses an auth.log
    out of a UAC tar, because it IS that code.

    The trade is stated rather than hidden: routing is a guess about what a
    file is, made from its name, and a wrong guess is a file parsed as the
    wrong artifact. Every decision is reported at load time and recorded in
    METADATA, and 'path:/host/path' on the command line overrides it.
    """

    def __init__(self, specs, quiet=False):
        self.path = "loose files"
        self.kind = "files"
        self.time_source = "collected file"
        self._tar = None
        self._zip = None
        self._sizes = {}
        self._mtimes = {}
        self._names = {}
        self._raw = {}             # unused here - members are already normalised
        self._owners = {}          # a loose file's owner is the analyst's
        self._disk = {}            # synthetic member name -> real path on disk
        self.prefix = ""
        self.layout = "uac"
        self.rootfs_dirs = ["[root]"]
        self.velo = None
        self.routed = []           # (source, member, how) - for METADATA
        self.skipped = []          # (source, why)
        # Loose files have no uac.log to say when the capture ran, and a
        # syslog stamp carries no year - without an anchor every 'Nov 11
        # 03:02:14' lands in 1900 and the whole timeline is wrong. The newest
        # mtime of the files themselves is the best statement available of
        # when this evidence was current.
        self.time_hint = None
        self._mount(specs, quiet)
        if not self._names:
            raise SystemExit("[!] --file: nothing could be identified as an "
                             "artifact - pass 'path:/host/path' to say what a "
                             "file is")

    # -- mounting -----------------------------------------------------------
    def _sources(self, specs):
        """(real path, path it was given under, explicit destination or None)."""
        out = []
        for raw, dest in specs:
            if os.path.isdir(raw):
                if dest:
                    raise SystemExit("[!] --file: '%s' is a directory, so it "
                                     "cannot be mapped to the single path %s"
                                     % (raw, dest))
                for dirpath, _dirs, files in os.walk(raw):
                    for fn in sorted(files):
                        full = os.path.join(dirpath, fn)
                        rel = os.path.relpath(full, raw).replace(os.sep, "/")
                        out.append((full, rel, None))
            else:
                out.append((raw, os.path.basename(raw), dest))
        return out

    def _mount(self, specs, quiet=False):
        for real, rel, dest in self._sources(specs):
            try:
                size = os.path.getsize(real)
                mtime = datetime.fromtimestamp(os.path.getmtime(real),
                                               timezone.utc)
            except OSError as e:
                self.skipped.append((real, str(e)))
                continue
            if dest:
                how = "given"
            else:
                dest, how = route_artifact(os.path.basename(real), rel,
                                           self._looks_text(real))
            if not dest:
                self.skipped.append((real, "not identified as a known artifact"))
                continue
            member = self._member(dest)
            low = member.lower()
            self._names[low] = low if low == member else member
            self._sizes[member.lower()] = size
            # the loose file's own mtime, which is the host's when the file
            # was copied off with its metadata and the copy's when it was not
            try:
                self._mtimes[member.lower()] = os.path.getmtime(real)
            except OSError:
                pass
            self._disk[member] = real
            self.routed.append((real, member, how))
            if self.time_hint is None or mtime > self.time_hint:
                self.time_hint = mtime
        if not quiet:
            for real, member, how in self.routed:
                status("[*] --file %s -> %s (%s)"
                       % (os.path.basename(real), self.host_path(member), how))
            for real, why in self.skipped:
                status("[!] --file %s skipped: %s" % (os.path.basename(real), why))

    def _member(self, dest):
        """Destination -> a member name nothing else has taken.

        A collision is two files that genuinely share a name - two hosts'
        auth.log, say - which is an ambiguous input, not a routing mistake. The
        duplicate keeps its own basename under a numbered directory rather
        than being renamed: '/var/log/auth.log' and '/var/log/dup2/auth.log'
        are both swept by _log_files(), and the second is still recognisably
        an auth.log rather than an 'auth.log.2' invented here.
        """
        base = ("[root]/" + dest.lstrip("/")) if dest.startswith("/") else dest
        if base.lower() not in self._names:
            return base
        head, _, tail = base.rpartition("/")
        for i in range(2, 500):
            cand = "%s/dup%d/%s" % (head, i, tail)
            if cand.lower() not in self._names:
                return cand
        raise SystemExit("[!] --file: too many files named %s" % tail)

    @staticmethod
    def _looks_text(path):
        """Whether an unidentified file is worth handing to the /var/log sweep."""
        try:
            with open(path, "rb") as fh:
                head = fh.read(4096)
        except OSError:
            return False
        if not head:
            return False
        if b"\x00" in head:
            return False
        try:
            head.decode("utf-8")
        except UnicodeDecodeError:
            # a rotation of a text log can split a multibyte character at the
            # read boundary; that is not a binary file
            try:
                head[:-4].decode("utf-8")
            except UnicodeDecodeError:
                return False
        return True

    # -- reading ------------------------------------------------------------
    def _open(self, real):
        return open(self._disk[real], "rb")


def parse_file_spec(raw):
    """'path' or 'path:/host/path' -> (path, destination or None).

    The colon is also a drive separator on Windows, so an existing path is
    never split, and a split is only accepted when what follows looks like a
    destination - a host absolute path, or a collection-relative command path.
    """
    if os.path.exists(raw):
        return raw, None
    head, sep, tail = raw.rpartition(":")
    if not sep or len(head) < 2:                  # 'C:/logs/auth.log'
        return raw, None
    if tail.startswith("/") or tail.startswith("live_response/"):
        return head, tail
    return raw, None


class VelociraptorResults:
    """The JSONL result sets in a Velociraptor collection.

    Velociraptor writes one file per artifact source under results/, named for
    the artifact with '/' percent-encoded, holding one JSON object per line.

    Nothing here assumes a given artifact exists. Which artifacts a collection
    holds is a property of the collector someone built, not of Velociraptor, so
    the set is discovered and an unmapped artifact is reported rather than
    dropped. Names are matched case-insensitively and with the source suffix
    optional, because 'Linux.Sys.Pslist' and 'Linux.Sys.Pslist/All' are the same
    artifact written by two versions.
    """

    RESULT_EXTS = (".json", ".jsonl")
    # written alongside the results as a seek index; binary, no evidence in it
    SIDECAR_EXTS = (".json.index", ".idx")

    def __init__(self, col):
        self.col = col
        self.files = []            # every results/ member, collection-relative
        self.by_name = {}          # normalised artifact name -> [rel, ...]
        self.names = {}            # rel -> artifact name as Velociraptor spelt it
        self.counts = {}           # rel -> rows read (see t_velo_artifacts)
        self.bad_rows = {}         # rel -> lines that were not JSON
        self.claimed = {}          # rel -> table its rows fed
        self._scan()

    # -- naming -------------------------------------------------------------
    @staticmethod
    def artifact_name(rel):
        """results/Linux.Sys.Pslist%2FAll.json -> 'Linux.Sys.Pslist/All'.

        Both spellings occur: older collectors percent-encode the source into
        one filename, newer ones nest it in a directory. Decoding one and
        joining the other gives a single name to match on.
        """
        base = rel.split("/", 1)[1] if "/" in rel else rel
        for ext in VelociraptorResults.RESULT_EXTS:
            if base.lower().endswith(ext):
                base = base[: -len(ext)]
                break
        try:
            base = urllib.parse.unquote(base)
        except Exception:
            pass
        return base.replace("\\", "/").strip("/")

    @staticmethod
    def _keys(name):
        """The lookup keys one artifact answers to: full name, and base name."""
        low = name.lower()
        return (low, low.split("/", 1)[0]) if "/" in low else (low,)

    def _scan(self):
        for rel in self.col.glob("results/**"):
            low = rel.lower()
            if low.endswith(self.SIDECAR_EXTS) or not low.endswith(self.RESULT_EXTS):
                continue
            name = self.artifact_name(rel)
            if not name:
                continue
            self.files.append(rel)
            self.names[rel] = name
            for k in self._keys(name):
                self.by_name.setdefault(k, [])
                if rel not in self.by_name[k]:
                    self.by_name[k].append(rel)
        self.files.sort()

    # -- reading ------------------------------------------------------------
    def has(self, *artifacts):
        return any(a.lower() in self.by_name for a in artifacts)

    def sources(self, *artifacts):
        """The result files backing these artifact names, deduplicated."""
        out = []
        for a in artifacts:
            for rel in self.by_name.get(a.lower(), ()):
                if rel not in out:
                    out.append(rel)
        return out

    def rows(self, *artifacts):
        """Yield (rel, row_dict) for every row of the named artifacts.

        A row that is not a JSON object is counted into bad_rows rather than
        raising: one truncated line at the end of a result file is the normal
        shape of a collection that was interrupted, and it must not cost the
        rows before it.
        """
        for rel in self.sources(*artifacts):
            yield from self.rows_of(rel)

    def rows_of(self, rel):
        n, bad = 0, 0
        for ln in self.col.iter_lines(rel):
            if not ln.strip():
                continue
            try:
                row = json.loads(ln)
            except ValueError:
                bad += 1
                continue
            if isinstance(row, dict):
                n += 1
                yield rel, row
            else:
                bad += 1
        self.counts[rel] = n
        if bad:
            self.bad_rows[rel] = bad

    def claim(self, artifacts, table_name):
        """Record that an artifact fed a table, for VELO_ARTIFACTS.

        One result file answers to both its full name and its base name, so a
        set that lists both spellings resolves to the same file twice; the
        table is recorded once regardless.
        """
        for rel in self.sources(*artifacts):
            prev = self.claimed.get(rel)
            if not prev:
                self.claimed[rel] = table_name
            elif table_name not in prev.split("; "):
                self.claimed[rel] = "%s; %s" % (prev, table_name)


def velo_get(row, *names, default=""):
    """First present, non-empty value among these column names.

    Velociraptor column names drift between artifact versions and between the
    artifact and its Exchange fork - Pid vs pid, CommandLine vs Cmdline,
    Username vs User - so every read names the spellings it accepts instead of
    betting on one.
    """
    lowered = None
    for n in names:
        if n in row and row[n] not in (None, ""):
            return row[n]
    for n in names:
        if lowered is None:
            lowered = {str(k).lower(): v for k, v in row.items()}
        v = lowered.get(n.lower())
        if v not in (None, ""):
            return v
    return default


def _velo_cell(value):
    """A JSON value -> one cell.

    Velociraptor rows nest freely - a Laddr is an object, a UsedBy is a list -
    and a table cell is a string. Compact JSON keeps the structure readable and
    greppable in the CSV instead of flattening it away to str(dict).
    """
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"),
                          default=str)
    except (TypeError, ValueError):
        return str(value)


def _velo_table_name(artifact, used):
    """'Linux.Sys.Pslist/All' -> a unique VELO_LINUX_SYS_PSLIST_ALL.

    Excel truncates a sheet name at 31 characters, so two long artifact names
    can collide there even when the table names differ. Dedup on the truncated
    form, which is the one that has to be unique.
    """
    base = re.sub(r"[^A-Za-z0-9]+", "_", artifact).strip("_").upper()
    base = re.sub(r"^(LINUX|WINDOWS|GENERIC|EXCHANGE)_", "", base) or "ARTIFACT"
    name = ("VELO_" + base)[:31].rstrip("_")
    if name not in used:
        return name
    for i in range(2, 1000):
        cand = "%s_%d" % (name[: 31 - len(str(i)) - 1].rstrip("_"), i)
        if cand not in used:
            return cand
    return name


def velo_time(value):
    """A Velociraptor timestamp in any of its shapes -> aware UTC datetime.

    Results carry RFC3339 strings, collection_context.json carries an integer
    epoch whose unit changed across releases. Guessing the unit from magnitude
    is safe here because the alternatives are ~50000 years apart.
    """
    if value in (None, ""):
        return None
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        if s.replace(".", "", 1).replace("-", "", 1).isdigit():
            try:
                value = float(s)
            except ValueError:
                return None
        else:
            s = s.replace("Z", "+00:00")
            # fromisoformat is strict about sub-second digits before 3.11
            s = re.sub(r"\.(\d{6})\d+", r".\1", s)
            try:
                dt = datetime.fromisoformat(s)
            except ValueError:
                return None
            return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(
                tzinfo=timezone.utc)
    try:
        v = float(value)
    except (TypeError, ValueError):
        return None
    if v <= 0:
        return None
    # a contemporary epoch is ~1.7e9 s, and each finer unit is 1000x that, so
    # the candidate ranges sit decades apart and cannot be confused
    for threshold, divisor in ((1e17, 1e9), (1e14, 1e6), (1e11, 1e3)):
        if v >= threshold:
            v /= divisor
            break
    try:
        return datetime.fromtimestamp(v, timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None
