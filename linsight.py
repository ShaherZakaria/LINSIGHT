#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
linsight.py - parse a Linux triage collection and highlight the critical /
interesting events.

Two collection layouts are understood, detected from the collection itself:

  UAC           (Unix-like Artifacts Collector) - command output under
                live_response/, the copied filesystem under [root]
  Velociraptor  offline collector - artifact results as JSONL under results/,
                the copied filesystem under uploads/<accessor>/

Works on an extracted collection directory OR directly on the .tar / .tar.gz /
.zip either tool produced. Pure standard library, Python 3.8+.

    python linsight.py <collection>                      # console report
    python linsight.py <collection> --html report.html   # + HTML report
    python linsight.py <collection> --json out.json --timeline tl.csv
    python linsight.py <collection> --min-severity HIGH  # only the loud stuff
    python linsight.py <collection> --pivot /dev/shm/kit # cross-artifact hunt
    python linsight.py <collection> --deep               # scan memory strings
    python linsight.py <collection> --update-sigma       # fetch SigmaHQ, hunt
    python linsight.py <collection> --sigma-cached       # ... offline, cached

Two output layers:

  findings  - the analyzers' severity-ranked conclusions (console/--html/--json)
  tables    - every interesting artifact normalised into a browsable grid, one
              table per artifact type, written as one CSV and one JSON per
              table plus an HTML browser:

    python linsight.py <collection> --export ./out     # csv/ json/ browser
    python linsight.py <collection> --csv-dir ./csv    # just the CSVs

The table layer can be narrowed to half the collection with --scope:

    --scope live      the volatile snapshot - process table, sockets, open
                      files, loaded modules, live sessions. State that existed
                      only while the host was running.
    --scope offline   what a dead-box examination recovers - the filesystem
                      copy, its configuration, its logs, persistence, bodyfile.
    --scope full      both (the default).

Findings, the timeline and the IOC list always run over the whole collection:
they exist to correlate across the two halves, so narrowing them would cost
answers rather than time. What --scope saves is the table build, which is where
the minutes go.

Design: every analyzer and every table extractor is independent and
failure-tolerant. A missing or malformed artifact degrades that one check,
never the run. Nothing is silently dropped: FILE_INVENTORY records which table
parsed each collected file, and UNPARSED_FILES lists whatever nothing claimed.

Three tables exist to make that accounting honest rather than merely true:

  COLLECTION_ERRORS  the .stderr UAC saved for each command, so an artifact
                     that is absent says whether the tool was missing, the
                     command was denied, or the profile never ran it
  UNPARSED_FILES     what no extractor claimed, with a reason - the rows that
                     read 'no extractor for this artifact' are the real
                     residue, the rest are classified (distribution reference
                     data, vendored source, application state)
  FILE_INVENTORY     one row per collected file naming the table that took it

UAC's own layout moves between profile generations - suid/sgid and the
filesystem surveys live under system/ in recent profiles and
live_response/system/ in the 2021 ones - so the extractors glob for artifacts
rather than naming a single path. A path spelled out in full silently produces
an empty table on the other profile, which reads as "this host had none of
that" and is a wrong answer, not a missing one.

The same rule drives Velociraptor support. Which artifacts a Velociraptor
collection holds is decided by whoever built the collector, so the artifact set
is discovered from results/ rather than assumed: an artifact this parser maps
lands in the matching table, and one it does not still reaches the export as
its own VELO_* table. VELO_ARTIFACTS lists every artifact found, its row count
and where it went, so 'no mapping for this artifact' is a visible line rather
than a missing table. The copied filesystem is read identically under either
layout, so /etc, /var/log, persistence, the histories and the YARA scan do not
care which tool collected them.
"""

from __future__ import annotations

import argparse
import atexit
import base64
import bz2
import csv
import fnmatch
import gzip
import html as htmllib
import io
import ipaddress
import itertools
import json
import lzma
import os
import re
import shutil
import sqlite3
import struct
import sys
import time
import tarfile
import tempfile
import urllib.parse
import zipfile
from collections import defaultdict
from datetime import datetime, timedelta, timezone

VERSION = "1.0"
AUTHOR = "Shaher Elrobaa"

# Two mastheads, because a Windows console still running a legacy code page
# raises UnicodeEncodeError on block characters and a masthead that can abort
# the run is worse than no masthead. The block form is used only when the
# stream says it can encode it; print_banner() checks rather than guesses, so
# the failure is never a half-written line.
BANNER_BLOCK = """\
 ██╗     ██╗███╗   ██╗███████╗██╗ ██████╗ ██╗  ██╗████████╗
 ██║     ██║████╗  ██║██╔════╝██║██╔════╝ ██║  ██║╚══██╔══╝
 ██║     ██║██╔██╗ ██║███████╗██║██║  ███╗███████║   ██║
 ██║     ██║██║╚██╗██║╚════██║██║██║   ██║██╔══██║   ██║
 ███████╗██║██║ ╚████║███████║██║╚██████╔╝██║  ██║   ██║
 ╚══════╝╚═╝╚═╝  ╚═══╝╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝
"""

BANNER_ASCII = r"""
 _ _           _       _     _
| (_)_ __  ___(_) __ _| |__ | |_
| | | '_ \/ __| |/ _` | '_ \| __|
| | | | | \__ \ | (_| | | | | |_
|_|_|_| |_|___/_|\__, |_| |_|\__|
                 |___/
"""

# The severity scale, drawn - the same ranking the report is built on, and the
# same palette the HTML report and the logo use.
SCALE_BLOCK = "███"
SCALE_ASCII = "==="

# ---------------------------------------------------------------------------
# severity / finding model
# ---------------------------------------------------------------------------

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

COLORS = {
    "CRITICAL": "\033[1;97;41m",
    "HIGH": "\033[1;31m",
    "MEDIUM": "\033[1;33m",
    "LOW": "\033[1;36m",
    "INFO": "\033[0;37m",
    "head": "\033[1;36m",
    "dim": "\033[2m",
    "bold": "\033[1m",
    "reset": "\033[0m",
}


class Finding:
    """One triage observation, with when it was seen and how often.

    first_seen / last_seen are the span of the dated occurrences behind the
    finding, normalised to UTC by the analyzer that raised it and never
    re-derived from the evidence text here: a line the parser wrote is already
    UTC while a line copied out of a log is host-local wall clock, and once
    both are strings in the same list nothing tells them apart.

    count is how many occurrences the finding covers, which is not
    len(evidence) - evidence is capped for readability, so "6204 files
    modified" is a count of 6204 carrying 60 lines. An undated artifact (a
    config file, a group membership) leaves the span empty rather than
    borrowing the collection time.
    """

    __slots__ = ("severity", "category", "title", "detail", "evidence",
                 "source", "mitre", "first_seen", "last_seen", "count")

    def __init__(self, severity, category, title, detail="", evidence=None,
                 source="", mitre="", first_seen="", last_seen="", count=None):
        self.severity = severity
        self.category = category
        self.title = title
        self.detail = detail
        self.evidence = list(evidence or [])
        self.source = source
        self.mitre = mitre
        self.first_seen = first_seen
        self.last_seen = last_seen
        self.count = len(self.evidence) if count is None else count

    def as_dict(self):
        return {
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "detail": self.detail,
            "evidence": self.evidence,
            "source": self.source,
            "mitre": self.mitre,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "count": self.count,
        }

    def seen_text(self):
        """'45 occurrence(s), 2026-06-11 10:02:14 .. 2026-06-11 11:40:03 UTC'."""
        parts = []
        if self.count:
            parts.append("%d occurrence(s)" % self.count)
        if self.first_seen and self.last_seen and self.first_seen != self.last_seen:
            parts.append("%s .. %s UTC" % (self.first_seen, self.last_seen))
        elif self.first_seen or self.last_seen:
            parts.append("%s UTC" % (self.first_seen or self.last_seen))
        return ", ".join(parts)


class Event:
    __slots__ = ("ts", "category", "description", "severity", "source")

    def __init__(self, ts, category, description, severity="INFO", source=""):
        self.ts = ts                      # aware datetime (UTC)
        self.category = category
        self.description = description
        self.severity = severity
        self.source = source

    def as_dict(self):
        return {
            "timestamp": self.ts.strftime("%Y-%m-%d %H:%M:%S UTC") if self.ts else "",
            "category": self.category,
            "description": self.description,
            "severity": self.severity,
            "source": self.source,
        }


# ---------------------------------------------------------------------------
# collection access (directory / tar / zip backends)
# ---------------------------------------------------------------------------

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
        self._names = {}          # lowercase relative name -> real member name
        self.prefix = ""          # archive dir that holds the layout's marker
        self.layout = "uac"       # 'uac' or 'velociraptor'; see _find_prefix
        self._load()
        self._find_prefix()
        self.rootfs_dirs = self._find_rootfs_dirs()
        self.velo = VelociraptorResults(self) if self.layout == "velociraptor" else None

    # -- loading ------------------------------------------------------------
    def _load(self):
        if os.path.isdir(self.path):
            self.kind = "dir"
            base = self.path
            for dirpath, _dirnames, filenames in os.walk(base):
                for fn in filenames:
                    full = os.path.join(dirpath, fn)
                    rel = os.path.relpath(full, base).replace(os.sep, "/")
                    self._names[rel.lower()] = rel
                    try:
                        self._sizes[rel.lower()] = os.path.getsize(full)
                    except OSError:
                        self._sizes[rel.lower()] = 0
        elif zipfile.is_zipfile(self.path):
            self.kind = "zip"
            self._zip = zipfile.ZipFile(self.path)
            encrypted = 0
            for zi in self._zip.infolist():
                if zi.is_dir():
                    continue
                if zi.flag_bits & 0x1:
                    encrypted += 1
                rel = zi.filename.lstrip("./")
                self._names[rel.lower()] = zi.filename
                self._sizes[rel.lower()] = zi.file_size
            self._check_sealed(encrypted)
        else:
            self.kind = "tar"
            self._tar = tarfile.open(self.path, "r:*")
            for ti in self._tar.getmembers():
                if not ti.isfile():
                    continue
                rel = ti.name.lstrip("./")
                self._names[rel.lower()] = ti.name
                self._sizes[rel.lower()] = ti.size
        if not self._names:
            raise SystemExit("[!] no readable files found in %s" % self.path)

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

    def glob(self, pattern):
        """Shell-style match over collection-relative names (case-insensitive)."""
        pat = (self.escape_glob(self.prefix) + pattern.lstrip("/")).lower()
        plen = len(self.prefix)
        out = []
        for low, real in self._names.items():
            if self._match_path(low, pat):
                out.append(real[plen:])
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
            if rel.lower().startswith(rd + "/"):
                return "/" + rel[len(rd) + 1:]
        return rel

    # -- reading ------------------------------------------------------------
    def _open(self, real):
        if self.kind == "dir":
            return open(os.path.join(self.path, real), "rb")
        if self.kind == "zip":
            return self._zip.open(real, "r")
        f = self._tar.extractfile(real)
        if f is None:
            raise IOError("not a regular file: %s" % real)
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


# ---------------------------------------------------------------------------
# shared knowledge / heuristics
# ---------------------------------------------------------------------------

TMPFS_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/", "/dev/mqueue/")
SYSTEM_BIN_DIRS = ("/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/local/bin/",
                   "/usr/local/sbin/", "/usr/lib/", "/lib/", "/lib64/", "/usr/lib64/")
SYSTEM_CFG_DIRS = ("/etc/", "/boot/", "/usr/lib/systemd/", "/lib/systemd/")

# ports commonly used by implants / handlers
SUSPICIOUS_PORTS = {
    23: "telnet", 1080: "socks proxy", 1337: "common backdoor", 2323: "telnet alt",
    3333: "common backdoor/miner", 4444: "metasploit default", 4445: "metasploit alt",
    5555: "common backdoor/adb", 6666: "IRC bot / backdoor", 6667: "IRC",
    7777: "common backdoor", 8888: "common backdoor/proxy", 9001: "tor / backdoor",
    9050: "tor socks", 9051: "tor control", 12345: "netbus/backdoor",
    31337: "elite/backdoor", 54321: "backdoor", 14444: "miner pool",
    3332: "miner pool", 5900: "vnc",
}

# baseline of SUID/SGID binaries shipped by mainstream Linux distributions
BASELINE_SUID = {
    "/usr/bin/sudo", "/usr/bin/su", "/usr/bin/passwd", "/usr/bin/gpasswd",
    "/usr/bin/chfn", "/usr/bin/chsh", "/usr/bin/newgrp", "/usr/bin/mount",
    "/usr/bin/umount", "/usr/bin/pkexec", "/usr/bin/fusermount", "/usr/bin/fusermount3",
    "/usr/bin/ntfs-3g", "/usr/bin/at", "/usr/bin/crontab", "/usr/bin/expiry",
    "/usr/bin/chage", "/usr/bin/wall", "/usr/bin/write", "/usr/bin/screen",
    "/usr/bin/dotlockfile", "/usr/bin/ssh-agent", "/usr/bin/bwrap",
    "/usr/bin/vmware-user-suid-wrapper", "/usr/bin/staprun", "/usr/bin/mount.nfs",
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper", "/usr/lib/xorg/Xorg.wrap",
    "/usr/lib/openssh/ssh-keysign", "/usr/lib/polkit-1/polkit-agent-helper-1",
    "/usr/lib/eject/dmcrypt-get-device", "/usr/lib/snapd/snap-confine",
    "/usr/lib/x86_64-linux-gnu/utempter/utempter",
    "/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic",
    "/usr/libexec/camel-lock-helper-1.2", "/usr/libexec/dbus-1/dbus-daemon-launch-helper",
    "/usr/libexec/openssh/ssh-keysign", "/usr/libexec/polkit-agent-helper-1",
    "/usr/libexec/utempter/utempter", "/usr/libexec/spice-gtk-x86_64/spice-client-glib-usb-acl-helper",
    "/usr/sbin/pppd", "/usr/sbin/unix_chkpwd", "/usr/sbin/mount.nfs",
    "/usr/sbin/pam_timestamp_check", "/usr/sbin/usernetctl", "/usr/sbin/exim4",
    "/usr/sbin/postdrop", "/usr/sbin/postqueue", "/usr/sbin/grub2-set-bootflag",
    "/bin/su", "/bin/mount", "/bin/umount", "/bin/ping", "/bin/ping6",
    "/bin/fusermount", "/sbin/unix_chkpwd", "/sbin/mount.nfs", "/sbin/pam_timestamp_check",
    "/usr/bin/ping", "/usr/bin/ping6", "/usr/bin/traceroute6.iputils",
    "/usr/bin/arping", "/usr/bin/mtr-packet", "/usr/bin/kismet_cap_linux_bluetooth",
}

# interpreters / living-off-the-land binaries that must never be SUID
DANGEROUS_SUID_NAMES = {
    "bash", "sh", "dash", "zsh", "ksh", "csh", "tcsh", "python", "python2",
    "python3", "perl", "ruby", "php", "lua", "node", "awk", "gawk", "mawk",
    "find", "vim", "vi", "nano", "emacs", "less", "more", "man", "cp", "mv",
    "dd", "tar", "zip", "unzip", "rsync", "nmap", "env", "docker", "systemctl",
    "openssl", "socat", "nc", "ncat", "netcat", "busybox", "strace", "gdb",
}

# command fragments that are interesting in cron jobs, units, histories
SUSPICIOUS_CMD_PATTERNS = [
    (r"/dev/tcp/", "bash reverse shell primitive", "HIGH"),
    (r"\bnc\b\s+(-[a-z]*e|.*\s-e\b)", "netcat with -e (reverse shell)", "CRITICAL"),
    (r"\b(ncat|netcat|socat)\b", "netcat/socat usage", "HIGH"),
    (r"\bbash\s+-i\b", "interactive shell spawn", "HIGH"),
    (r"base64\s+(-d|--decode)", "base64 decoding of payload", "HIGH"),
    (r"\becho\s+[A-Za-z0-9+/=]{40,}", "long encoded blob", "HIGH"),
    (r"(curl|wget)[^|;\n]*\|\s*(ba)?sh", "download piped to shell", "CRITICAL"),
    (r"\b(curl|wget)\b", "remote download", "MEDIUM"),
    (r"python[0-9.]*\s+-c\b", "inline python", "HIGH"),
    (r"perl\s+-e\b", "inline perl", "HIGH"),
    # only the modes that matter: +x, world-writable 777, and setuid/setgid.
    # 0755/0700 appear all over stock init scripts.
    (r"\bchmod\s+(-R\s+)?(\+x|a\+x|u\+s|g\+s|0?777|[24][0-7]{3})\b",
     "granting execute / world-write / setuid", "MEDIUM"),
    (r"\bchattr\s+[+-]i\b", "immutable attribute change", "HIGH"),
    (r"history\s+-c|>\s*~?/?\.bash_history|unset\s+HISTFILE|HISTFILE=/dev/null",
     "shell history tampering", "HIGH"),
    (r"\bshred\b|\bwipe\b|\bsrm\b", "secure deletion utility", "HIGH"),
    (r"\bcrontab\s+-r\b", "crontab wipe", "HIGH"),
    (r"\b(setenforce\s+0|systemctl\s+(stop|disable|mask)\s+(auditd|rsyslog|firewalld|ufw))",
     "security control disabled", "HIGH"),
    (r"iptables\s+-F|nft\s+flush", "firewall rules flushed", "HIGH"),
    (r"\bldd\b.*ld\.so\.preload|ld\.so\.preload", "LD_PRELOAD persistence", "CRITICAL"),
    (r"LD_PRELOAD=", "LD_PRELOAD injection", "CRITICAL"),
    (r"\binsmod\b|\bmodprobe\b\s+[^-]", "kernel module load", "MEDIUM"),
    (r"\bxmrig\b|stratum\+tcp|\bminerd\b|cryptonight", "cryptominer indicator", "CRITICAL"),
    (r"\.onion\b|\btor2web\b|\bngrok\b|\bpastebin\.com\b|\btransfer\.sh\b",
     "anonymising / paste service", "HIGH"),
    # a temp path only matters when it is being *run*; distro scripts mention
    # /tmp constantly in tests and variable assignments
    (r"(?:^|[;&|`]\s*|\$\(\s*|\b(?:exec|source|\.|sh|bash|dash|zsh|sudo|nohup|setsid|python[0-9.]*|perl)\s+)"
     r"(?:/tmp/|/var/tmp/|/dev/shm/|/run/shm/)\S+",
     "execution from a world-writable dir", "HIGH"),
    (r"\bnohup\b.*&|\bsetsid\b|\bdisown\b", "detached background execution", "MEDIUM"),
    (r"\bssh\b.*-[fNL]\s|-R\s+\d+:", "ssh tunnel / port forward", "HIGH"),
    (r"\bsshpass\b", "non-interactive ssh password use", "HIGH"),
    (r"\buseradd\b|\badduser\b|\busermod\b.*-G", "account manipulation", "HIGH"),
    (r"authorized_keys", "ssh key persistence", "HIGH"),
]
COMPILED_CMD_PATTERNS = [(re.compile(p, re.I), d, s) for p, d, s in SUSPICIOUS_CMD_PATTERNS]

# Named offensive tooling, by what its presence would mean. ROOTKIT_NAMES below
# covers kernel implants; this covers the userland toolkit an operator brings.
#
# Split into two tiers on purpose. UNAMBIGUOUS names are not words anyone uses
# for anything else, so a hit anywhere - a log line, a filename, a package - is
# worth reporting. AMBIGUOUS names are ordinary English or common binaries
# ('john', 'empire', 'beacon', 'havoc', 'sliver'), and matching those in free
# log text produces noise, not findings; they are only ever matched in a
# command line or a path, where the word is naming something executable.
HACKTOOL_UNAMBIGUOUS = {
    "credential access": [
        "mimikatz", "mimipenguin", "mimidump", "lazagne", "secretsdump",
        "gosecretsdump", "hashdump", "pypykatz", "kerberoast", "asreproast",
        "dumpert", "nanodump", "procdump", "keethief", "lsassy", "hekatomb",
        "certipy", "gettgtpkinit", "krbrelayx", "ticketer", "getnpusers",
        "getuserspns", "dcsync", "ntdsutil", "ntds.dit", "creddump7",
        "chntpw", "unshadow", "hashcat", "johntheripper",
    ],
    "privilege escalation enumeration": [
        "linpeas", "winpeas", "linenum", "lse.sh", "linux-smart-enumeration",
        "unix-privesc-check", "linux-exploit-suggester", "les.sh", "pspy",
        "gtfoblookup", "beroot", "privesccheck", "suid3num", "traitor",
        "sudo_killer", "sudokiller",
    ],
    "active directory attack": [
        "bloodhound", "sharphound", "azurehound", "rusthound", "soaphound",
        "crackmapexec", "netexec", "smbmap", "smbexec", "wmiexec", "psexec",
        "atexec", "dcomexec", "evil-winrm", "kerbrute", "rubeus", "impacket",
        "responder", "ntlmrelayx", "mitm6", "petitpotam", "printnightmare",
        "zerologon", "noPac", "adidnsdump", "windapsearch", "ldapdomaindump",
    ],
    "command and control": [
        "meterpreter", "msfvenom", "msfconsole", "metasploit", "cobaltstrike",
        "cobalt strike", "teamserver", "beacon.dll", "sliver-client",
        "sliver-server", "mythic", "poshc2", "covenant", "brute ratel",
        "bruteratel", "havoc-client", "merlin", "koadic", "pupy", "villain",
        "hoaxshell", "chisel", "ligolo", "revsocks", "gost", "frpc", "frps",
        "sshuttle", "ngrok", "cloudflared tunnel", "pivotnacci", "reGeorg",
        "neo-regeorg", "tunna",
    ],
    "scanning and exploitation": [
        "masscan", "zmap", "nuclei", "gobuster", "feroxbuster", "dirbuster",
        "wfuzz", "sqlmap", "nikto", "wpscan", "joomscan", "commix", "xsstrike",
        "searchsploit", "exploitdb", "routersploit", "arachni", "whatweb",
        "enum4linux", "smbclient -N", "onesixtyone", "snmpwalk -c public",
    ],
    "webshell": [
        "c99shell", "r57shell", "b374k", "weevely", "wso shell", "antsword",
        "behinder", "godzilla webshell", "chinachopper", "china chopper",
        "phpspy", "wsomanager", "indoxploit", "alfashell", "marijuana shell",
    ],
    "cryptomining": [
        "xmrig", "minerd", "cpuminer", "nbminer", "phoenixminer", "ethminer",
        "lolminer", "t-rex miner", "nanominer", "xmr-stak", "cgminer",
    ],
    "container escape": [
        "deepce", "amicontained", "cdk-team", "botb ", "break-out-the-box",
        "kubeletctl", "peirates",
    ],
    "exfiltration staging": [
        "rclone copy", "megatools", "transfer.sh", "filebin", "0x0.st",
        "termbin", "oshi.at",
    ],
}
# ordinary words that are also tool names - command/path context only
HACKTOOL_AMBIGUOUS = {
    "credential access": ["john", "hydra", "medusa", "patator", "crowbar",
                          "cewl", "ophcrack"],
    "active directory attack": ["certify", "seatbelt", "sharpview"],
    "command and control": ["empire", "sliver", "havoc", "merlin", "beacon",
                            "silenttrinity", "quasar"],
    "scanning and exploitation": ["nmap", "dirb", "ffuf", "amass", "subfinder",
                                  "arjun", "dalfox"],
    "container escape": ["cdk"],
}


def _tool_regex(groups):
    """One alternation for the whole tier, so a cell costs a single pass.

    This is what the function always claimed to do and did not: it compiled one
    alternation *per category*, so every cell was scanned nine times for the
    unambiguous tier and five for the ambiguous one. Nine passes over a web
    server's three million log rows is 213 seconds to produce 38 findings -
    over half the entire run. The cost driver is the number of cells, never the
    number of tool names, which is the same lesson --pivot already learned when
    it compiled 400 indicators into one alternation.

    Returns (regex, name -> category), because the category can no longer come
    from which pattern matched.
    """
    cats = {}
    for cat, names in groups.items():
        for n in names:
            cats.setdefault(n.lower(), cat)
    alt = "|".join(sorted((re.escape(n) for n in cats), key=len, reverse=True))
    # Case-sensitive against already-lowercased names, with the caller
    # lowercasing the cell once. re.I is not a free flag: it case-folds at
    # every position of every alternative, and measured on this collection's
    # log lines it costs 78us per line against 19us for one str.lower() plus a
    # case-sensitive scan - the single biggest cost in the whole run.
    #
    # not preceded/followed by a word character, so 'john' does not fire on
    # 'johnson' and 'cdk' does not fire on 'cdkit'; a leading '/' or '-' is
    # fine because that is how these appear in paths and argv
    return re.compile(r"(?<![\w.])(%s)(?![\w-])" % alt), cats


HACKTOOL_RE, HACKTOOL_CAT = _tool_regex(HACKTOOL_UNAMBIGUOUS)
HACKTOOL_CTX_RE, HACKTOOL_CTX_CAT = _tool_regex(HACKTOOL_AMBIGUOUS)
# how bad a name is, before the context it was found in is considered
HACKTOOL_SEVERITY = {
    "credential access": "CRITICAL", "active directory attack": "HIGH",
    "command and control": "CRITICAL", "privilege escalation enumeration": "HIGH",
    "scanning and exploitation": "HIGH", "webshell": "CRITICAL",
    "cryptomining": "CRITICAL", "container escape": "HIGH",
    "exfiltration staging": "HIGH",
}

# known Linux rootkit / offensive tool module and file names
ROOTKIT_NAMES = [
    "diamorphine", "reptile", "suterusu", "adore", "adore-ng", "knark", "modhide",
    "kbeast", "enyelkm", "sebek", "phalanx", "jynx", "azazel", "beurk", "vlany",
    "bedevil", "bdvl", "umbreon", "rkduck", "syslogk", "pinkit", "khook",
    "brootus", "nurupo", "wukong", "hiddenwasp", "drovorub", "symbiote",
    "medusa", "tinyshell", "bpfdoor", "ebpfkit", "boopkit", "tripleCross",
]

BENIGN_HIDDEN = re.compile(
    r"(^|/)\.(placeholder|updated|pwd\.lock|X11-unix|ICE-unix|XIM-unix|font-unix|"
    r"Test-unix|cache|config|local|gnupg|ssh|profile|bashrc|bash_logout|bash_profile|"
    r"face|face\.icon|nosearch|gsd-[a-z-]+\.settings-ported|os-release-stage|"
    r"registry|features|dbus-keyrings|Xauthority|ICEauthority|wget-hsts|selected_editor|"
    r"lesshst|viminfo|python_history|sudo_as_admin_successful|motd\.legacy)($|/)")

def norm_ip(ip):
    """Canonical text form so /proc/net, ss and lsof addresses compare equal."""
    if ip is None:
        return ""
    ip = ip.strip().strip("[]")
    if ip in ("*", ""):
        return "0.0.0.0"
    if "%" in ip:                       # scope id, e.g. fe80::1%eth0
        ip = ip.split("%")[0]
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return ip


def is_private_ip(ip):
    """True for anything that is not a routable public address."""
    ip = norm_ip(ip)
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True                     # hostnames / '*' - not evidence of egress
    return not addr.is_global


def hexip_to_str(hexip):
    """/proc/net/{tcp,udp} address (little-endian hex) -> canonical IP string."""
    try:
        if len(hexip) == 8:
            raw = bytes.fromhex(hexip)[::-1]
            return str(ipaddress.IPv4Address(raw))
        if len(hexip) == 32:
            words = [bytes.fromhex(hexip[i:i + 8])[::-1] for i in range(0, 32, 8)]
            return str(ipaddress.IPv6Address(b"".join(words)))
    except Exception:
        pass
    return hexip


def split_hostport(addr):
    """'127.0.0.1:3333' / '[::1]:22' / '*:22' -> (canonical host, port|None)."""
    addr = (addr or "").strip()
    if addr.startswith("["):
        host, sep, port = addr.rpartition("]:")
        if not sep:
            return norm_ip(addr), None
        return norm_ip(host), _port(port)
    host, sep, port = addr.rpartition(":")
    if not sep:
        return norm_ip(addr), None
    if host.count(":") >= 2:            # bare IPv6 without brackets
        return norm_ip(addr), None
    return norm_ip(host), _port(port)


def _port(p):
    try:
        return int(p)
    except (TypeError, ValueError):
        return None


MONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}


def parse_lstart(s):
    """'Tue Mar 24 19:25:30 2026' -> naive-UTC-tagged datetime (host local clock)."""
    m = re.match(r"\w{3}\s+(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})", s.strip())
    if not m:
        return None
    mon = MONTHS.get(m.group(1))
    if not mon:
        return None
    try:
        return datetime(int(m.group(6)), mon, int(m.group(2)), int(m.group(3)),
                        int(m.group(4)), int(m.group(5)), tzinfo=timezone.utc)
    except ValueError:
        return None


def epoch(ts):
    try:
        # auditd stamps are 'seconds.milliseconds', so parse as float and let
        # int() drop the fraction rather than rejecting the whole timestamp
        v = int(float(ts))
    except (TypeError, ValueError):
        return None
    if v <= 0:
        return None
    try:
        return datetime.fromtimestamp(v, timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def _printable(raw):
    """Matched bytes rendered for a report: printable ASCII kept, rest hexed.

    A YARA hit is often binary, and pasting raw bytes into a CSV produces a
    cell no tool can display and some can't even quote. This keeps the part a
    human can read and makes the rest explicit rather than mangled.
    """
    if isinstance(raw, str):
        raw = raw.encode("utf-8", "replace")
    out = []
    for b in raw:
        out.append(chr(b) if 32 <= b < 127 else "\\x%02x" % b)
    return "".join(out)


def trunc(s, n=180):
    s = s.strip()
    return s if len(s) <= n else s[: n - 3] + "..."


# Groups whose membership is equivalent to root on most systems: sudo/wheel by
# definition, docker/lxd because the daemon runs as root, disk/shadow because
# they read the raw device and the hashes.
PRIVILEGED_GROUPS = frozenset((
    "sudo", "wheel", "admin", "adm", "root", "docker", "lxd", "lxc",
    "disk", "shadow", "video", "kvm", "libvirt", "systemd-journal",
    "sys", "staff", "operator"))


# The daemons whose messages are privilege use. Matched against the syslog
# identifier as well as the text, because a sudo record names the command it
# ran but never the word "sudo".
PRIV_HINT_RE = re.compile(
    r"\b(sudo|su|pkexec|polkit|usermod|useradd|userdel|groupadd|groupdel|"
    r"gpasswd|chage|passwd|visudo|run0)\b", re.I)


# Message shapes that mean "authentication did not succeed", with the reason
# named. FOR577 opens its account-attack section with "check for large numbers
# of failed logins", so these feed both the FAILED_LOGINS table and the
# brute-force analyzer and live at module scope for both to share.
FAILED_LOGIN_RULES = [
    ("bad password", re.compile(
        r"Failed (?P<method>password) for (?:invalid user )?(?P<user>\S+)"
        r" from (?P<ip>\S+)(?: port (?P<port>\d+))?")),
    ("bad key", re.compile(
        r"Failed (?P<method>publickey|none|keyboard-interactive\S*) for "
        r"(?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)"
        r"(?: port (?P<port>\d+))?")),
    ("unknown account", re.compile(
        r"Invalid user (?P<user>\S*)\s*from (?P<ip>\S+)"
        r"(?: port (?P<port>\d+))?")),
    ("unknown account", re.compile(
        r"(?:check pass; user unknown|"
        r"illegal user (?P<user>\S+) from (?P<ip>\S+))")),
    ("pam authentication failure", re.compile(
        r"authentication failure;")),
    ("too many attempts", re.compile(
        r"(?:maximum authentication attempts exceeded|"
        r"Too many authentication failures)(?: for (?P<user>\S+))?"
        r"(?: from (?P<ip>\S+))?(?: port (?P<port>\d+))?")),
    ("root login refused", re.compile(
        r"(?:ROOT LOGIN REFUSED|Root login rejected|"
        r"User root from (?P<ip>\S+) not allowed)")),
    ("account not permitted", re.compile(
        r"(?:User (?P<user>\S+) from (?P<ip>\S+) not allowed because|"
        r"Authentication refused|pam_access\(.*\): access denied)")),
    ("aborted before authenticating", re.compile(
        r"(?:Connection closed by (?:authenticating|invalid) user "
        r"(?P<user>\S+) (?P<ip>\S+)(?: port (?P<port>\d+))?|"
        r"Received disconnect from (?P<ip2>\S+).*\[preauth\])")),
    ("sudo password failure", re.compile(
        r"^\s*(?P<user>\S+)\s*:\s*(?P<detail>\d+ incorrect password "
        r"attempts?)")),
    ("sudo not permitted", re.compile(
        r"^\s*(?P<user>\S+)\s*:\s*(?P<detail>user NOT in sudoers|"
        r"command not allowed)")),
    ("su failure", re.compile(
        r"FAILED su(?: \(to (?P<target>\S+)\))?(?: for (?P<target2>\S+))?"
        r"(?: by (?P<user>\S+))?")),
    ("failed login", re.compile(
        r"(?:FAILED LOGIN|LOGIN FAILURE|authentication error)"
        r"(?:.*?FROM (?P<ip>\S+))?(?:.*?FOR (?P<user>\S+))?")),
]


def match_failed_login(proc, msg):
    """One log message -> (kind, user, ip, port, method, detail), or None."""
    for label, erx in FAILED_LOGIN_RULES:
        em = erx.search(msg)
        if not em:
            continue
        if label.startswith("sudo") and "sudo" not in (proc or "").lower():
            continue
        g = em.groupdict()
        pick = lambda *k: next((g[x].strip() for x in k
                                if g.get(x) and g[x].strip()), "")
        return (label, pick("user", "target", "target2"),
                pick("ip", "ip2"), pick("port"), pick("method"),
                pick("detail"))
    return None


# 'Accepted publickey for bob from 1.2.3.4 port 51004 ssh2'
ACCEPTED_LOGIN_RE = re.compile(
    r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+)"
    r"(?: port (?P<port>\d+))?")


# every timestamp shape that turns up in a /var/log text file
_TS_ISO_RE = re.compile(r"^(\d{4})-(\d\d)-(\d\d)[T ]\s*(\d\d):(\d\d):(\d\d)"
                        r"(?:[.,]\d+)?\s*(Z|[+-]\d\d:?\d\d)?$")
_TS_SYSLOG_RE = re.compile(r"^(\w{3})\s+(\d{1,2})\s+(\d\d):(\d\d):(\d\d)$")
_TS_CLF_RE = re.compile(r"^(\d\d)/(\w{3})/(\d{4}):(\d\d):(\d\d):(\d\d)"
                        r"\s*([+-]\d{4})?$")
_TS_BANNER_RE = re.compile(r"^\w{3}\s+(\w{3})\s+(\d{1,2})\s+(\d\d):(\d\d):(\d\d)"
                           r"\s+(?:\S+\s+)?(\d{4})$")


def _tz_delta(z):
    """'+0200' / '-04:00' / 'Z' -> timedelta of that offset from UTC."""
    if not z or z == "Z":
        return timedelta(0)
    z = z.replace(":", "")
    try:
        sign = -1 if z[0] == "-" else 1
        return sign * timedelta(hours=int(z[1:3]), minutes=int(z[3:5]))
    except (ValueError, IndexError):
        return timedelta(0)


_TS_SPAN_RE = re.compile(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$")


def _ts_text(v):
    """A datetime, an epoch or an already-UTC string -> 'YYYY-MM-DD HH:MM:SS'."""
    if v is None or v == "":
        return ""
    if isinstance(v, datetime):
        return v.strftime("%Y-%m-%d %H:%M:%S")
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        # only a plausible epoch: a bare small integer reaching a finding is a
        # count, a pid or a port far more often than it is a time
        if v < 100000000 or v > 4102444800:
            return ""
        try:
            return datetime.fromtimestamp(v, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        except (OverflowError, OSError, ValueError):
            return ""
    s = str(v).strip().replace("T", " ")
    if s.endswith("Z"):
        s = s[:-1].strip()
    return s[:19] if _TS_SPAN_RE.match(s[:19]) else ""


_IOC_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_IOC_IPV4_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
_IOC_IPV6_RE = re.compile(r"^[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}$")
_IOC_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)"
                            r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
                            r"[A-Za-z]{2,24}$")
_HASH_BY_LEN = {32: "md5", 40: "sha1", 64: "sha256"}


def ioc_type(value):
    """What kind of thing an indicator is - 'ipv4', 'sha256', 'path', ...

    Shape only, and deliberately so: an indicator arrives as a bare string
    from a --pivot list or from an analyzer, with nothing else to go on. The
    point is a column an analyst can filter on, so an unrecognised shape says
    'string' rather than being forced into a category it does not fit.
    """
    s = str(value or "").strip()
    if not s:
        return ""
    low = s.lower()
    for prefix, kind in (("port:", "port"), ("pid:", "pid")):
        if low.startswith(prefix):
            return kind
    if "://" in s:
        return "url"
    if s.startswith("/"):
        return "path"
    if s.isdigit():
        return "number"
    if _IOC_HEX_RE.match(s):
        # a hash is one of three lengths; anything else all-hex is only worth
        # naming when it is long enough not to be an ordinary short word, and
        # 'dead', 'added' and 'beef' are all valid hex
        kind = _HASH_BY_LEN.get(len(s)) or ("hex string" if len(s) >= 16 else "")
        if kind:
            return kind
    m = _IOC_IPV4_RE.match(s)
    if m and all(int(g) < 256 for g in m.groups()):
        return "ipv4"
    if ":" in s and _IOC_IPV6_RE.match(s):
        return "ipv6"
    if "@" in s and _IOC_DOMAIN_RE.match(s.rsplit("@", 1)[-1]):
        return "email"
    if _IOC_DOMAIN_RE.match(s):
        return "domain"
    if "." in s and " " not in s and "/" not in s:
        return "filename"
    return "string"


# Why an indicator was extracted -> the technique that makes it worth chasing.
# Keyed on the provenance labels Triage.ioc() records, which is the only thing
# that knows why a term is in the list at all: the term itself is a string. A
# label with no entry - a plain --pivot value, a path a table happened to
# mention - contributes nothing rather than a guessed technique.
IOC_TECHNIQUES = (
    ("/etc/ld.so.preload", "T1574.006 Hijack Execution Flow: LD_PRELOAD"),
    ("hidden_pids", "T1564 Hide Artifacts / T1014 Rootkit"),
    ("hidden ", "T1564.001 Hidden Files and Directories"),
    ("regular file under /dev", "T1564 Hide Artifacts"),
    ("bodyfile (executable in tmpfs)", "T1036 Masquerading"),
    ("running process pid", "T1059 Command and Scripting Interpreter"),
    ("running-process hash", "T1070.004 Indicator Removal: File Deletion"),
    ("hash mismatch", "T1554 Compromise Host Software Binary"),
    ("listening socket", "T1571 Non-Standard Port"),
    ("network connection", "T1071 Application Layer Protocol"),
    ("outbound admin protocol", "T1021 Remote Services"),
    ("authorized_keys", "T1098.004 SSH Authorized Keys"),
    ("interactive login", "T1078 Valid Accounts"),
    ("failed authentication source", "T1110 Brute Force"),
    ("password spraying source", "T1110.003 Password Spraying"),
    ("systemd unit", "T1543.002 Systemd Service"),
    ("suid", "T1548.001 Setuid and Setgid"),
    ("sgid", "T1548.001 Setuid and Setgid"),
    ("hacktool:", "T1588.002 Obtain Capabilities: Tool"),
)


def ioc_mitre(labels):
    """ATT&CK technique(s) implied by where an indicator was picked up."""
    out = []
    for label in sorted(labels or ()):
        for prefix, tech in IOC_TECHNIQUES:
            if label.startswith(prefix):
                if tech not in out:
                    out.append(tech)
                break
    return "; ".join(out)


def span_add(span, ts):
    """Fold one timestamp into a mutable ['first', 'last'] pair, in place.

    The counterpart to span_of for the sweeps: a pivot term or a noisy Sigma
    rule can match six figures of rows, and only the two ends are ever wanted.
    """
    if ts:
        if not span[0] or ts < span[0]:
            span[0] = ts
        if not span[1] or ts > span[1]:
            span[1] = ts
    return span


# Distinct reference strings kept per tool per table before the tail is folded
# into one overflow row. A tool named in BODYFILE matches a different path on
# nearly every row it hits, and an unbounded dict there is a copy of the
# filesystem in memory; 200 is already past the point a breakdown reads.
HACKTOOL_VARIANT_CAP = 200
HACKTOOL_VARIANT_OTHER = "(further distinct references, not itemised)"


def variant_add(bag, val, column, ts):
    """Fold one hit into a {reference text: [count, span, columns]} bag.

    The per-hit rows keep twelve samples per table, so they cannot be counted
    after the fact - and the count is the point: masscan/1.0 and masscan/1.3
    are two scanners wearing one tool name, and how often each was seen is
    only knowable while every row is still going past.
    """
    text = trunc(str(val), 200)
    rec = bag.get(text)
    if rec is None:
        if len(bag) >= HACKTOOL_VARIANT_CAP:
            text = HACKTOOL_VARIANT_OTHER
            rec = bag.get(text)
        if rec is None:
            rec = bag[text] = [0, ["", ""], set()]
    rec[0] += 1
    span_add(rec[1], ts)
    if column:
        rec[2].add(column)
    return bag


def span_of(times):
    """(first, last) as 'YYYY-MM-DD HH:MM:SS' UTC over a bag of timestamps.

    Everything an analyzer holds is already UTC - the datetimes it puts on the
    timeline are aware, its strings came back from norm_log_ts - so the span is
    a plain min/max and no conversion happens here. Unparseable entries drop
    out instead of skewing the span, and an empty input gives an empty span,
    which every renderer prints as nothing at all.
    """
    vals = sorted(v for v in (_ts_text(t) for t in (times or [])) if v)
    return (vals[0], vals[-1]) if vals else ("", "")


def norm_log_ts(text, tz_offset=None, year_hint=None):
    """Any log timestamp -> 'YYYY-MM-DD HH:MM:SS' UTC, or '' if unparseable.

    A stamp that carries its own offset is converted with it.  A naive stamp is
    the host's local wall clock, so tz_offset (host local - UTC) is subtracted -
    the same normalisation the timeline already applies.  Syslog's 'Mar 24
    15:47:28' carries no year; year_hint supplies one so rotations do not all
    collapse onto 1900.
    """
    s = (text or "").strip()
    if not s:
        return ""
    off = tz_offset or timedelta(0)
    m = _TS_ISO_RE.match(s)
    if m:
        try:
            dt = datetime(*(int(m.group(i)) for i in range(1, 7)),
                          tzinfo=timezone.utc)
        except ValueError:
            return ""
        dt -= _tz_delta(m.group(7)) if m.group(7) else off
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    m = _TS_CLF_RE.match(s)
    if m:
        mon = MONTHS.get(m.group(2))
        if not mon:
            return ""
        try:
            dt = datetime(int(m.group(3)), mon, int(m.group(1)), int(m.group(4)),
                          int(m.group(5)), int(m.group(6)), tzinfo=timezone.utc)
        except ValueError:
            return ""
        return (dt - _tz_delta(m.group(7))).strftime("%Y-%m-%d %H:%M:%S")
    m = _TS_BANNER_RE.match(s)
    if m:
        mon = MONTHS.get(m.group(1))
        if not mon:
            return ""
        try:
            dt = datetime(int(m.group(6)), mon, int(m.group(2)), int(m.group(3)),
                          int(m.group(4)), int(m.group(5)), tzinfo=timezone.utc)
        except ValueError:
            return ""
        return (dt - off).strftime("%Y-%m-%d %H:%M:%S")
    m = _TS_SYSLOG_RE.match(s)
    if m:
        mon = MONTHS.get(m.group(1))
        if not mon or not year_hint:
            return ""
        try:
            dt = datetime(int(year_hint), mon, int(m.group(2)), int(m.group(3)),
                          int(m.group(4)), int(m.group(5)), tzinfo=timezone.utc)
        except ValueError:
            return ""
        return (dt - off).strftime("%Y-%m-%d %H:%M:%S")
    return ""


# ---------------------------------------------------------------------------
# detection rules: a YARA subset and a Sigma subset, both pure stdlib
#
# The point of this tool is that it runs from one file with nothing installed,
# on a machine that may be an evidence workstation with no package manager
# access. yara-python and pysigma are therefore not dependencies - these are
# self-contained engines covering the constructs that Linux IR rules actually
# use. Where a real library is importable it wins: PyYAML is used for Sigma
# when present, because a real parser beats a good-enough one.
#
# Both engines share one rule: anything they cannot represent faithfully is
# REJECTED with a reason and reported in RULE_ERRORS, never partially applied.
# A detection rule that silently matches nothing is worse than one that was
# never loaded, because it looks like a clean result.
# ---------------------------------------------------------------------------

# YARA
class RuleError(Exception):
    pass


# ---------------------------------------------------------------------------
# string compilation
# ---------------------------------------------------------------------------

WORD = rb"A-Za-z0-9_"


def _wide(raw):
    """Interleave NUL bytes the way YARA's 'wide' modifier does.

    Runs on the raw bytes and is escaped afterwards, never the other way round:
    interleaving into an already-escaped pattern would drop NULs inside the
    escape sequences themselves. Slicing rather than iterating because
    iterating a bytes object yields ints.
    """
    return b"".join(raw[i:i + 1] + b"\x00" for i in range(len(raw)))


def _hex_to_regex(body):
    """'{ 4D 5A ?? [0-4] 90 ( AA | BB ) }' -> a bytes regex."""
    toks = re.findall(r"\[\s*\d*\s*-?\s*\d*\s*\]|\(|\)|\||[0-9A-Fa-f?]{2}|\S", body)
    out = []
    for t in toks:
        if t == "(":
            out.append(b"(?:")
        elif t == ")":
            out.append(b")")
        elif t == "|":
            out.append(b"|")
        elif t.startswith("["):
            inner = t[1:-1].strip()
            if inner in ("-", ""):
                out.append(b".*?")            # unbounded jump
            elif "-" in inner:
                lo, hi = [p.strip() for p in inner.split("-", 1)]
                lo = lo or "0"
                out.append(("." + "{%s,%s}" % (lo, hi or "")).encode())
            else:
                out.append(("." + "{%s}" % inner).encode())
        elif len(t) == 2 and re.match(r"^[0-9A-Fa-f?]{2}$", t):
            if t == "??":
                out.append(b".")
            elif t[1] == "?":                 # high nibble fixed: 4? -> [\x40-\x4f]
                hi = int(t[0], 16)
                out.append(("[\\x%02x-\\x%02x]" % (hi * 16, hi * 16 + 15)).encode())
            elif t[0] == "?":                 # low nibble fixed: ?A -> one of 16
                lo = int(t[1], 16)
                out.append(b"[" + b"".join(
                    ("\\x%02x" % (h * 16 + lo)).encode() for h in range(16)) + b"]")
            else:
                out.append(("\\x%02x" % int(t, 16)).encode())
        else:
            raise RuleError("unsupported hex token %r" % t)
    return b"".join(out)


class YString:
    """One '$id = ...' definition, compiled to one or more bytes patterns."""

    def __init__(self, ident, kind, raw, mods):
        self.ident = ident
        self.kind = kind
        self.raw = raw
        self.mods = mods
        self.patterns = self._compile()

    def _compile(self):
        flags = re.DOTALL
        if "nocase" in self.mods:
            flags |= re.IGNORECASE
        pats = []
        if self.kind == "text":
            body = self.raw.encode("utf-8", "surrogateescape")
            forms = []
            # 'wide' alone means UTF-16LE only; 'wide ascii' means either
            if "wide" in self.mods:
                forms.append(re.escape(_wide(body)))
            if "wide" not in self.mods or "ascii" in self.mods:
                forms.append(re.escape(body))
            for f in forms:
                if "fullword" in self.mods:
                    f = b"(?<![" + WORD + b"])" + f + b"(?![" + WORD + b"])"
                pats.append(re.compile(f, flags))
        elif self.kind == "hex":
            pats.append(re.compile(_hex_to_regex(self.raw), re.DOTALL))
        elif self.kind == "regex":
            body = self.raw.encode("utf-8", "surrogateescape")
            if "wide" in self.mods:
                raise RuleError("wide regex strings are not supported")
            pats.append(re.compile(body, flags))
        return pats

    def find(self, data):
        out = []
        for p in self.patterns:
            for m in p.finditer(data):
                out.append((m.start(), m.group(0)))
                if len(out) > 64:
                    return out          # a rule needs counts, not every hit
        return out


# ---------------------------------------------------------------------------
# condition parsing - a small recursive-descent parser over a token list
# ---------------------------------------------------------------------------

COND_TOKEN = re.compile(r"""
    \s*(
      \(|\)|,
    | \#[A-Za-z_][A-Za-z0-9_]*
    | \$[A-Za-z0-9_]*\*?
    | <=|>=|==|!=|<|>
    | \b(?:and|or|not|all|any|of|them|filesize|true|false|at|in)\b
    | \b(?:uint8|uint16|uint32|int8|int16|int32)\b
    | 0x[0-9A-Fa-f]+ | \d+(?:KB|MB|GB)? | \.\.
    | \S
    )""", re.X)


def _tokenize_cond(text):
    toks, pos = [], 0
    for m in COND_TOKEN.finditer(text):
        toks.append(m.group(1))
    return toks


class Cond:
    """Condition AST node. kind drives eval; children/value carry the operands."""

    def __init__(self, kind, **kw):
        self.kind = kind
        self.__dict__.update(kw)


class CondParser:
    def __init__(self, toks, idents):
        self.t = toks
        self.i = 0
        self.idents = idents

    def peek(self):
        return self.t[self.i] if self.i < len(self.t) else None

    def take(self, expect=None):
        v = self.peek()
        if v is None:
            raise RuleError("condition ended early")
        if expect and v != expect:
            raise RuleError("expected %r, found %r" % (expect, v))
        self.i += 1
        return v

    def parse(self):
        node = self.or_expr()
        if self.peek() is not None:
            raise RuleError("unparsed condition tail at %r" % self.peek())
        return node

    def or_expr(self):
        n = self.and_expr()
        while self.peek() == "or":
            self.take()
            n = Cond("or", a=n, b=self.and_expr())
        return n

    def and_expr(self):
        n = self.unary()
        while self.peek() == "and":
            self.take()
            n = Cond("and", a=n, b=self.unary())
        return n

    def unary(self):
        if self.peek() == "not":
            self.take()
            return Cond("not", a=self.unary())
        return self.primary()

    def _num(self, tok):
        mult = 1
        for suf, m in (("KB", 1024), ("MB", 1024 ** 2), ("GB", 1024 ** 3)):
            if tok.endswith(suf):
                tok, mult = tok[: -len(suf)], m
                break
        return int(tok, 16) if tok.lower().startswith("0x") else int(tok) * mult

    def _expand(self, pat):
        """'$a*' -> every declared identifier with that prefix."""
        if pat == "them" or pat == "$*":
            return list(self.idents)
        if pat.endswith("*"):
            pre = pat[1:-1]
            return [i for i in self.idents if i.startswith(pre)]
        return [pat[1:]] if pat[1:] in self.idents else []

    def _set(self):
        """'them' or '( $a*, $b )' after an 'of'."""
        if self.peek() == "them":
            self.take()
            return list(self.idents)
        self.take("(")
        names = []
        while True:
            tok = self.take()
            if tok.startswith("$"):
                names.extend(self._expand(tok))
            elif tok == ")":
                break
            elif tok == ",":
                continue
            else:
                raise RuleError("unexpected %r in string set" % tok)
        return names

    def primary(self):
        tok = self.peek()
        if tok == "(":
            self.take()
            n = self.or_expr()
            self.take(")")
            return n
        if tok in ("true", "false"):
            self.take()
            return Cond("const", value=(tok == "true"))
        if tok in ("all", "any"):
            self.take()
            self.take("of")
            names = self._set()
            return Cond("of", n=(len(names) if tok == "all" else 1), names=names)
        if tok and re.match(r"^\d+(KB|MB|GB)?$|^0x", tok) and \
                self.i + 1 < len(self.t) and self.t[self.i + 1] == "of":
            n = self._num(self.take())
            self.take("of")
            return Cond("of", n=n, names=self._set())
        if tok and tok.startswith("#"):
            self.take()
            name = tok[1:]
            op = self.take()
            if op not in ("<", ">", "<=", ">=", "==", "!="):
                raise RuleError("expected a comparison after #%s" % name)
            return Cond("count", name=name, op=op, value=self._num(self.take()))
        if tok == "filesize":
            self.take()
            op = self.take()
            return Cond("filesize", op=op, value=self._num(self.take()))
        if tok in ("uint8", "uint16", "uint32", "int8", "int16", "int32"):
            self.take()
            self.take("(")
            off = self._num(self.take())
            self.take(")")
            op = self.take()
            return Cond("uint", size=int(re.sub(r"\D", "", tok)) // 8,
                        off=off, op=op, value=self._num(self.take()))
        if tok and tok.startswith("$"):
            self.take()
            names = self._expand(tok)
            if tok.endswith("*"):
                return Cond("of", n=1, names=names)
            if not names:
                raise RuleError("condition references undeclared %s" % tok)
            # '$a at 0' / '$a in (0..100)'
            if self.peek() == "at":
                self.take()
                return Cond("at", name=names[0], off=self._num(self.take()))
            if self.peek() == "in":
                self.take()
                self.take("(")
                lo = self._num(self.take())
                self.take("..")
                hi = self._num(self.take())
                self.take(")")
                return Cond("in", name=names[0], lo=lo, hi=hi)
            return Cond("str", name=names[0])
        raise RuleError("unsupported condition token %r" % tok)


_CMP = {"<": lambda a, b: a < b, ">": lambda a, b: a > b,
        "<=": lambda a, b: a <= b, ">=": lambda a, b: a >= b,
        "==": lambda a, b: a == b, "!=": lambda a, b: a != b}


def eval_cond(node, hits, data):
    k = node.kind
    if k == "const":
        return node.value
    if k == "and":
        return eval_cond(node.a, hits, data) and eval_cond(node.b, hits, data)
    if k == "or":
        return eval_cond(node.a, hits, data) or eval_cond(node.b, hits, data)
    if k == "not":
        return not eval_cond(node.a, hits, data)
    if k == "str":
        return bool(hits.get(node.name))
    if k == "of":
        return sum(1 for n in node.names if hits.get(n)) >= node.n
    if k == "count":
        return _CMP[node.op](len(hits.get(node.name, [])), node.value)
    if k == "filesize":
        return _CMP[node.op](len(data), node.value)
    if k == "at":
        return any(off == node.off for off, _ in hits.get(node.name, []))
    if k == "in":
        return any(node.lo <= off <= node.hi for off, _ in hits.get(node.name, []))
    if k == "uint":
        if node.off + node.size > len(data):
            return False
        v = int.from_bytes(data[node.off:node.off + node.size], "little")
        return _CMP[node.op](v, node.value)
    raise RuleError("cannot evaluate %s" % k)


# ---------------------------------------------------------------------------
# rule file parsing
# ---------------------------------------------------------------------------

RULE_HEAD = re.compile(r"\brule\s+([A-Za-z_]\w*)\s*(:\s*[^\{]+)?\{", re.S)
STRING_DEF = re.compile(r"""
    (\$[A-Za-z0-9_]*)\s*=\s*
    (?: "((?:[^"\\]|\\.)*)"        # text
      | \{([^}]*)\}                # hex
      | /((?:[^/\\\n]|\\.)+)/      # regex
    )([ \t]*[A-Za-z0-9 \t]*)""", re.X)
MODULE_USE = re.compile(r"\b(pe|elf|math|hash|cuckoo|magic|dotnet|time)\s*\.")


class YRule:
    def __init__(self, name, tags, meta, strings, cond_src, cond, source):
        self.name = name
        self.tags = tags
        self.meta = meta
        self.strings = strings
        self.cond_src = cond_src
        self.cond = cond
        self.source = source

    def match(self, data):
        hits = {}
        for s in self.strings:
            found = s.find(data)
            if found:
                hits[s.ident] = found
        try:
            if eval_cond(self.cond, hits, data):
                return hits
        except RuleError:
            return None
        return None


def _split_blocks(text):
    """Yield (name, tags, body) for each rule, brace-balanced."""
    for m in RULE_HEAD.finditer(text):
        depth, i = 1, m.end()
        while i < len(text) and depth:
            c = text[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
            elif c == '"':                       # skip string literals
                i += 1
                while i < len(text) and text[i] != '"':
                    i += 2 if text[i] == "\\" else 1
            i += 1
        tags = (m.group(2) or "").lstrip(":").split()
        yield m.group(1), tags, text[m.end():i - 1]


def parse_yara(text, source=""):
    """-> (rules, errors). Errors are per rule, never fatal for the file."""
    rules, errors = [], []
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    text = re.sub(r"(?m)//.*$", "", text)
    for name, tags, body in _split_blocks(text):
        try:
            mcond = re.search(r"\bcondition\s*:(.*)$", body, re.S)
            if not mcond:
                raise RuleError("no condition section")
            cond_src = mcond.group(1).strip()
            if MODULE_USE.search(cond_src):
                raise RuleError("uses a YARA module (%s) - not supported"
                                % MODULE_USE.search(cond_src).group(1))
            meta = {}
            mmeta = re.search(r"\bmeta\s*:(.*?)(?=\bstrings\s*:|\bcondition\s*:)",
                              body, re.S)
            if mmeta:
                for km in re.finditer(r'(\w+)\s*=\s*(?:"([^"]*)"|(\S+))',
                                      mmeta.group(1)):
                    meta[km.group(1)] = km.group(2) if km.group(2) is not None \
                        else km.group(3)
            strings = []
            mstr = re.search(r"\bstrings\s*:(.*?)(?=\bcondition\s*:)", body, re.S)
            if mstr:
                for sm in STRING_DEF.finditer(mstr.group(1)):
                    ident = sm.group(1)[1:]
                    mods = (sm.group(5) or "").split()
                    bad = [m for m in mods if m not in
                           ("nocase", "wide", "ascii", "fullword", "private")]
                    if bad:
                        raise RuleError("unsupported string modifier %s" % bad[0])
                    if sm.group(2) is not None:
                        raw = sm.group(2).encode().decode("unicode_escape")
                        strings.append(YString(ident, "text", raw, mods))
                    elif sm.group(3) is not None:
                        strings.append(YString(ident, "hex", sm.group(3), mods))
                    else:
                        strings.append(YString(ident, "regex", sm.group(4), mods))
            idents = [s.ident for s in strings]
            cond = CondParser(_tokenize_cond(cond_src), idents).parse()
            rules.append(YRule(name, tags, meta, strings, cond_src, cond, source))
        except RuleError as e:
            errors.append((name, str(e)))
        except Exception as e:                    # a malformed rule is data
            errors.append((name, "%s: %s" % (type(e).__name__, e)))
    return rules, errors

# SIGMA
try:                                    # a real parser when one is installed
    import yaml as _yaml
except Exception:
    _yaml = None




# ---------------------------------------------------------------------------
# minimal YAML subset loader
# ---------------------------------------------------------------------------

def _scalar(text):
    t = text.strip()
    if t in ("~", "null", "Null", "NULL", ""):
        return None
    if t in ("true", "True", "TRUE", "yes"):
        return True
    if t in ("false", "False", "FALSE", "no"):
        return False
    if len(t) >= 2 and t[0] == t[-1] and t[0] in "'\"":
        body = t[1:-1]
        return body.replace('\\"', '"') if t[0] == '"' else body.replace("''", "'")
    if re.match(r"^-?\d+$", t):
        return int(t)
    if re.match(r"^-?\d+\.\d+$", t):
        return float(t)
    return t


def _strip_comment(line):
    """Drop a trailing '#' comment that is not inside quotes."""
    out, q = [], None
    for ch in line:
        if q:
            out.append(ch)
            if ch == q:
                q = None
        elif ch in "'\"":
            q = ch
            out.append(ch)
        elif ch == "#" and (not out or out[-1] in " \t"):
            break
        else:
            out.append(ch)
    return "".join(out).rstrip()


def load_yaml(text):
    """Parse the YAML subset Sigma uses. Returns a list of documents."""
    if _yaml is not None:
        return [d for d in _yaml.safe_load_all(text) if d is not None]
    docs, cur = [], []
    for raw in text.splitlines():
        if raw.strip() in ("---", "..."):
            if cur:
                docs.append(cur)
            cur = []
            continue
        cur.append(raw)
    if cur:
        docs.append(cur)
    return [_parse_block(_clean(d), 0)[0] for d in docs if any(l.strip() for l in d)]


def _clean(lines):
    out = []
    for raw in lines:
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        line = _strip_comment(raw)
        if line.strip():
            out.append(line)
    return out


def _indent(line):
    return len(line) - len(line.lstrip(" "))


def _parse_block(lines, i, base=None):
    """Parse one mapping or sequence starting at lines[i]. -> (value, next_i)."""
    if i >= len(lines):
        return None, i
    if base is None:
        base = _indent(lines[i])
    if lines[i].lstrip().startswith("- "):
        seq = []
        while i < len(lines) and _indent(lines[i]) == base and \
                lines[i].lstrip().startswith("- "):
            item = lines[i].lstrip()[2:].strip()
            if item and ":" in item and not item.startswith(("'", '"')) and \
                    re.match(r"^[\w|.\-]+\s*:", item):
                # '- field: value' opens a mapping inside the sequence
                sub = [" " * (base + 2) + lines[i].lstrip()[2:]]
                j = i + 1
                while j < len(lines) and _indent(lines[j]) > base:
                    sub.append(lines[j])
                    j += 1
                val, _ = _parse_block(sub, 0, base + 2)
                seq.append(val)
                i = j
            elif item:
                seq.append(_scalar(item))
                i += 1
            else:
                sub, j = [], i + 1
                while j < len(lines) and _indent(lines[j]) > base:
                    sub.append(lines[j])
                    j += 1
                val, _ = _parse_block(sub, 0)
                seq.append(val)
                i = j
        return seq, i
    mapping = {}
    while i < len(lines) and _indent(lines[i]) == base:
        line = lines[i].strip()
        m = re.match(r"^(.+?)\s*:\s*(.*)$", line)
        if not m:
            raise RuleError("cannot parse YAML line %r" % line)
        key, rest = _scalar(m.group(1)), m.group(2)
        if rest in ("|", ">", "|-", ">-", "|+", ">+"):
            block, j = [], i + 1
            while j < len(lines) and _indent(lines[j]) > base:
                block.append(lines[j].strip())
                j += 1
            mapping[key] = ("\n" if rest[0] == "|" else " ").join(block)
            i = j
        elif rest == "":
            j = i + 1
            if j < len(lines) and _indent(lines[j]) > base:
                val, j = _parse_block(lines, j, _indent(lines[j]))
                mapping[key] = val
            elif j < len(lines) and _indent(lines[j]) == base and \
                    lines[j].lstrip().startswith("- "):
                val, j = _parse_block(lines, j, base)
                mapping[key] = val
            else:
                mapping[key] = None
            i = j
        elif rest.startswith("[") and rest.endswith("]"):
            inner = rest[1:-1].strip()
            mapping[key] = [_scalar(p) for p in inner.split(",")] if inner else []
            i += 1
        else:
            mapping[key] = _scalar(rest)
            i += 1
    return mapping, i


# ---------------------------------------------------------------------------
# value matching
# ---------------------------------------------------------------------------

SUPPORTED_MODS = {"contains", "startswith", "endswith", "re", "all", "cased",
                  "base64", "base64offset", "windash", "expand"}
# modifiers whose semantics this engine cannot honour - reject, never ignore
REJECT_MODS = {"cidr", "fieldref", "exists", "gt", "gte", "lt", "lte",
               "utf16", "utf16le", "utf16be", "wide"}


def _anchored(inner, at_start, at_end, flags):
    """Compile a Sigma value, with anchors in the pattern rather than the call.

    A '*' at an end that is not anchored is redundant, and leaving it in is the
    single biggest performance trap here: '.*foo.*' matched with search() makes
    the engine retry from every offset in the subject and backtrack inside each
    attempt, which on a 12,000-character log line is quadratic. Stripping those
    wildcards changes nothing about what matches - search already scans - and
    took a run that had not finished in twenty minutes down to seconds.
    """
    while not at_start and inner.startswith(".*"):
        inner = inner[2:]
    while not at_end and inner.endswith(".*"):
        inner = inner[:-2]
    return re.compile(("^" if at_start else "") + inner +
                      ("$" if at_end else ""), flags)


def _wildcard_re(pat, cased):
    """Sigma value with * and ? wildcards -> compiled regex."""
    out, i = [], 0
    while i < len(pat):
        c = pat[i]
        if c == "\\" and i + 1 < len(pat) and pat[i + 1] in "*?\\":
            out.append(re.escape(pat[i + 1]))
            i += 2
            continue
        out.append(".*" if c == "*" else "." if c == "?" else re.escape(c))
        i += 1
    return re.compile("^" + "".join(out) + "$",
                      0 if cased else re.IGNORECASE)


# Sigma's field names come from a mostly Windows-shaped taxonomy; the tables
# here are Linux artifacts. A rule that says Image means the executable path,
# which this export calls exe on one table and comm on another. Each name is
# tried in order against the row and the first one the row actually has wins,
# so one rule works across PROCESSES, AUDIT_LOG and PROCESS_MASTER without
# being rewritten. A field that resolves to nothing simply does not match -
# never a fallback to searching the whole row, which would turn a precise
# field rule into a keyword rule and invent hits.
SIGMA_FIELD_SYNONYMS = {
    "image": ["exe", "comm", "path"],
    "processname": ["comm", "exe"],
    "originalfilename": ["comm", "exe"],
    "commandline": ["args", "proctitle", "command", "text"],
    "parentimage": ["parent_exe", "ppid_exe"],
    "parentcommandline": ["parent_args"],
    "user": ["user", "acct", "owner", "username"],
    "targetusername": ["acct", "target_user", "user"],
    "targetuser": ["target_user", "acct"],
    "logonuser": ["user", "acct"],
    "currentdirectory": ["cwd"],
    "processid": ["pid"],
    "parentprocessid": ["ppid"],
    "sourceip": ["remote_ip", "client_ip", "addr", "remote_host"],
    "destinationip": ["remote_addr", "peer", "addr"],
    "destinationport": ["remote_port", "port"],
    "c-uri": ["resource"], "cs-uri-query": ["resource"],
    "c-useragent": ["user_agent"], "sc-status": ["status"],
    "cs-method": ["method"], "cs-ip": ["client_ip"],
    "message": ["message", "text", "detail", "proctitle"],
    "cmd": ["command", "args", "proctitle"],
    "type": ["record_type", "rtype", "type", "kind"],
    "comm": ["comm", "exe"],
    "exe": ["exe", "comm", "path"],
    "name": ["name", "path", "file"],
    "path": ["path", "name", "file"],
    "syscall": ["syscall"], "key": ["key"], "auid": ["auid"], "uid": ["uid"],
}


class Matcher:
    """One 'field|mods: value(s)' entry from a detection block."""

    def __init__(self, field, mods, values):
        self.field = field
        # the declared name first, then the synonyms, then the raw name again
        self.candidates = [field] + [c for c in
                                     SIGMA_FIELD_SYNONYMS.get(field, [])
                                     if c != field]
        self.mods = mods
        bad = [m for m in mods if m in REJECT_MODS]
        if bad:
            raise RuleError("modifier '%s' is not supported" % bad[0])
        unknown = [m for m in mods if m not in SUPPORTED_MODS]
        if unknown:
            raise RuleError("unknown modifier '%s'" % unknown[0])
        self.all = "all" in mods
        self.cased = "cased" in mods
        self.values = values if isinstance(values, list) else [values]
        self.tests = [self._compile(v) for v in self.values]

    def _compile(self, v):
        if v is None:
            return None                       # 'field: null' -> field absent
        s = str(v)
        if "base64offset" in self.mods:
            forms = []
            for off in (0, 1, 2):
                enc = base64.b64encode((" " * off + s).encode()).decode()
                trim = enc[off and 2 or 0:len(enc) - 3 if off else len(enc)]
                forms.append(re.compile(re.escape(trim.rstrip("=")),
                                        0 if self.cased else re.IGNORECASE))
            return ("any", forms)
        if "base64" in self.mods:
            s = base64.b64encode(s.encode()).decode()
        flags = 0 if self.cased else re.IGNORECASE
        if "re" in self.mods:
            # a user-supplied regex: its own casing is meaningful, so it keeps
            # the flag rather than being lowercased
            return ("re", re.compile(s, flags))
        # Case-insensitive Sigma values are matched by lowering both sides
        # instead of setting re.IGNORECASE. The flag case-folds at every
        # position of every attempt, and profiling this run put 22.4s of 88s in
        # re.Pattern.search at ~8us a call; the values here are re.escape'd
        # literals plus wildcards, so lowering the source is equivalent. Same
        # fix as the hacktool sweep and the Sigma keyword blocks.
        low = not self.cased
        src = s.lower() if low else s
        inner = _wildcard_re(src, True).pattern[1:-1]          # drop ^ and $
        kind = "re_low" if low else "re"
        cflags = 0
        if "contains" in self.mods:
            return (kind, _anchored(inner, False, False, cflags))
        if "startswith" in self.mods:
            return (kind, _anchored(inner, True, False, cflags))
        if "endswith" in self.mods:
            return (kind, _anchored(inner, False, True, cflags))
        return (kind, _anchored(inner, True, True, cflags))

    def test(self, row):
        got = None
        for cand in self.candidates:
            if cand in row:
                got = row[cand]
                break
        results = []
        hay_low = None                      # lowered once, shared by the tests
        for t in self.tests:
            if t is None:
                results.append(got in (None, ""))
                continue
            if got in (None, ""):
                results.append(False)
                continue
            hay = str(got)
            kind, pat = t
            # anchors live in the pattern, so every form is a plain search
            if kind == "any":
                results.append(any(p.search(hay) for p in pat))
            elif kind == "re_low":
                if hay_low is None:
                    hay_low = hay.lower()
                results.append(bool(pat.search(hay_low)))
            else:
                results.append(bool(pat.search(hay)))
            if not self.all and results[-1]:
                return True                    # OR: stop at the first hit
            if self.all and not results[-1]:
                return False                   # AND: stop at the first miss
        return all(results) if self.all else any(results)


class Row(dict):
    """A row dict that caches the strings every rule on a table re-derives.

    Sigma tests each rule mapped to a table against each row, and two subjects
    are the same for all of those rules: the whole-row keyword haystack, and
    the log/process/unit string a service filter reads. Building them inside
    the rule's test made them per (row, rule) instead of per row - on VAR_LOG
    that is 1.19M joins multiplied by the rule count, for one join's worth of
    information. A dict subclass keeps `cand in row` and `row[cand]` working
    unchanged for every field matcher.
    """

    __slots__ = ("_hay", "_hayl", "_where")

    def hay(self):
        try:
            return self._hay
        except AttributeError:
            self._hay = " ".join(str(v) for k, v in self.items()
                                 if v not in (None, "")
                                 and k not in Keywords.PROVENANCE)
            return self._hay

    def hay_lower(self):
        try:
            return self._hayl
        except AttributeError:
            self._hayl = self.hay().lower()
            return self._hayl

    def where(self):
        try:
            return self._where
        except AttributeError:
            self._where = ("%s %s %s" % (self.get("log", ""),
                                         self.get("process", ""),
                                         self.get("unit", ""))).lower()
            return self._where


class Keywords:
    """A bare list under detection - matched against the whole row."""

    def __init__(self, values, mods=()):
        self.values = values if isinstance(values, list) else [values]
        # Two costs removed here, both measured on a real SigmaHQ ruleset over
        # this export's log tables, where every planned rule turned out to be a
        # keyword rule at 6.4us per row per rule:
        #
        #   re.IGNORECASE case-folds at every position of the whole-row
        #   haystack, the longest subject in the export. These patterns are
        #   re.escape'd literals plus wildcards, so lowering the pattern source
        #   and matching a lowered haystack is equivalent and far cheaper.
        #
        #   One alternation per keyword block, so a rule listing ten keywords
        #   costs one pass over the haystack rather than ten.
        inners, always = [], False
        for v in self.values:
            inner = _wildcard_re(str(v).lower(), True).pattern[1:-1]
            # same wildcard-stripping as _anchored: an unanchored leading or
            # trailing .* is redundant under search() and is the quadratic
            # backtracking trap
            while inner.startswith(".*"):
                inner = inner[2:]
            while inner.endswith(".*"):
                inner = inner[:-2]
            if inner:
                inners.append(inner)
            else:
                always = True       # a bare '*' keyword matches any row
        self.always = always
        self.pat = (None if always or not inners else
                    re.compile("|".join("(?:%s)" % i for i in inners)))


    # Columns this export adds to say where a row came from. They are not part
    # of the event, and folding them into the keyword haystack invents matches:
    # a row from /var/log/syslog gained the literal text '/var/log/syslog', so
    # a rule hunting 'rm /var/log/syslog' fired on 'SIGTERM /var/log/syslog'
    # - case-insensitively, SIGTE-RM. Field matchers can still name these
    # columns explicitly; only the whole-row keyword search skips them.
    PROVENANCE = frozenset(("log", "source", "source_file", "file", "rule_file",
                            "line_no", "timestamp_raw", "path"))

    def test(self, row):
        if self.always:
            return True
        if self.pat is None:
            return False
        hay = (row.hay_lower() if isinstance(row, Row) else
               " ".join(str(v) for k, v in row.items()
                        if v not in (None, "") and k not in self.PROVENANCE).lower())
        return self.pat.search(hay) is not None


class Selection:
    """A named detection block: a map of matchers (AND), or a list of maps (OR)."""

    def __init__(self, spec, alias):
        self.groups = []
        if isinstance(spec, list):
            if spec and not isinstance(spec[0], dict):
                self.groups = [[Keywords(spec)]]
                return
            blocks = spec
        else:
            blocks = [spec]
        for blk in blocks:
            if not isinstance(blk, dict):
                raise RuleError("unsupported detection block %r" % type(blk).__name__)
            grp = []
            for key, val in blk.items():
                parts = str(key).split("|")
                field = alias(parts[0])
                grp.append(Matcher(field, [p.lower() for p in parts[1:]], val))
            self.groups.append(grp)

    def test(self, row):
        # list-of-maps is OR across blocks, AND within a block
        return any(all(m.test(row) for m in grp) for grp in self.groups)


# ---------------------------------------------------------------------------
# condition expression
# ---------------------------------------------------------------------------

COND_TOK = re.compile(r"\s*(\(|\)|\band\b|\bor\b|\bnot\b|\bof\b|\bthem\b|"
                      r"\ball\b|\d+|[A-Za-z_][\w]*\*?)")


class SigmaCond:
    def __init__(self, kind, **kw):
        self.kind = kind
        self.__dict__.update(kw)


class SigmaCondParser:
    def __init__(self, text, names):
        self.t = [m.group(1) for m in COND_TOK.finditer(text)]
        self.i = 0
        self.names = names

    def peek(self):
        return self.t[self.i] if self.i < len(self.t) else None

    def take(self, expect=None):
        v = self.peek()
        if v is None:
            raise RuleError("condition ended early")
        if expect and v != expect:
            raise RuleError("expected %r, found %r" % (expect, v))
        self.i += 1
        return v

    def parse(self):
        n = self.or_expr()
        if self.peek() is not None:
            raise RuleError("unparsed condition tail %r" % self.peek())
        return n

    def or_expr(self):
        n = self.and_expr()
        while self.peek() == "or":
            self.take()
            n = SigmaCond("or", a=n, b=self.and_expr())
        return n

    def and_expr(self):
        n = self.unary()
        while self.peek() == "and":
            self.take()
            n = SigmaCond("and", a=n, b=self.unary())
        return n

    def unary(self):
        if self.peek() == "not":
            self.take()
            return SigmaCond("not", a=self.unary())
        return self.primary()

    def _expand(self, pat):
        if pat == "them":
            return list(self.names)
        if pat.endswith("*"):
            return [n for n in self.names if n.startswith(pat[:-1])]
        return [pat] if pat in self.names else []

    def primary(self):
        tok = self.peek()
        if tok == "(":
            self.take()
            n = self.or_expr()
            self.take(")")
            return n
        if tok == "all":
            self.take()
            self.take("of")
            names = self._expand(self.take())
            return SigmaCond("of", n=len(names), names=names)
        if tok and tok.isdigit():
            n = int(self.take())
            self.take("of")
            names = self._expand(self.take())
            return SigmaCond("of", n=n, names=names)
        if tok:
            self.take()
            names = self._expand(tok)
            if not names:
                raise RuleError("condition references unknown selection %r" % tok)
            if tok.endswith("*") or tok == "them":
                return SigmaCond("of", n=1, names=names)
            return SigmaCond("sel", name=names[0])
        raise RuleError("empty condition")


def eval_sigma(node, sels, row):
    k = node.kind
    if k == "and":
        return eval_sigma(node.a, sels, row) and eval_sigma(node.b, sels, row)
    if k == "or":
        return eval_sigma(node.a, sels, row) or eval_sigma(node.b, sels, row)
    if k == "not":
        return not eval_sigma(node.a, sels, row)
    if k == "sel":
        return sels[node.name].test(row)
    if k == "of":
        return sum(1 for n in node.names if sels[n].test(row)) >= node.n
    raise RuleError("cannot evaluate %s" % k)


# ---------------------------------------------------------------------------
# rules
# ---------------------------------------------------------------------------

LEVEL_SEVERITY = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
                  "low": "LOW", "informational": "INFO"}


class SigmaRule:
    def __init__(self, doc, alias, source=""):
        self.source = source
        self.title = str(doc.get("title") or "untitled")
        self.id = str(doc.get("id") or "")
        self.level = str(doc.get("level") or "medium").lower()
        self.severity = LEVEL_SEVERITY.get(self.level, "MEDIUM")
        self.status = str(doc.get("status") or "")
        self.description = str(doc.get("description") or "")
        ls = doc.get("logsource") or {}
        self.product = str(ls.get("product") or "")
        self.service = str(ls.get("service") or "")
        self.category = str(ls.get("category") or "")
        tags = doc.get("tags") or []
        self.tags = [str(t) for t in tags] if isinstance(tags, list) else [str(tags)]
        self.mitre = ", ".join(t.split(".", 1)[1].upper() for t in self.tags
                               if t.lower().startswith("attack.t"))
        det = doc.get("detection")
        if not isinstance(det, dict):
            raise RuleError("no detection block")
        cond = det.get("condition")
        if cond is None:
            raise RuleError("no condition")
        if isinstance(cond, list):
            cond = " or ".join("(%s)" % c for c in cond)
        self.condition_src = str(cond)
        if "|" in self.condition_src:
            raise RuleError("aggregation conditions are not supported")
        self.selections = {}
        for name, spec in det.items():
            if name == "condition":
                continue
            self.selections[name] = Selection(spec, alias)
        self.cond = SigmaCondParser(self.condition_src,
                                    list(self.selections)).parse()

    def test(self, row):
        return eval_sigma(self.cond, self.selections, row)


def parse_sigma(text, alias=lambda f: f.lower(), source=""):
    """-> (rules, errors); one YAML file may hold several documents."""
    rules, errors = [], []
    try:
        docs = load_yaml(text)
    except Exception as e:
        return [], [(source or "?", "YAML: %s" % e)]
    for doc in docs:
        if not isinstance(doc, dict) or "detection" not in doc:
            continue
        title = str(doc.get("title") or doc.get("id") or "untitled")
        try:
            rules.append(SigmaRule(doc, alias, source))
        except RuleError as e:
            errors.append((title, str(e)))
        except Exception as e:
            errors.append((title, "%s: %s" % (type(e).__name__, e)))
    return rules, errors


# ---------------------------------------------------------------------------
# keeping the Sigma ruleset current
#
# --sigma points at rule files, and rule files go stale: SigmaHQ merges rules
# every week, so hunting with the copy someone downloaded once, six months ago,
# is a clean result that means nothing. --update-sigma refreshes a local cache,
# and that cache is nothing but a directory of .yml files, so everything past
# the fetch is the ordinary --sigma path with no special case in it.
#
# This is the only place the tool touches the network, it only does so when
# asked, and it is substitutable: --sigma-source takes a local .zip or a
# directory, which is how an evidence workstation with no route out still gets
# this week's rules off a USB stick.
# ---------------------------------------------------------------------------

SIGMA_SOURCE = "https://codeload.github.com/SigmaHQ/sigma/zip/refs/heads/master"

# Directories in the SigmaHQ repo that are not rules to hunt with: deprecated
# and unsupported are kept for reference only, the placeholders match on
# %placeholder% values a real environment is meant to fill in, and the rest is
# the repo's own test and documentation material.
SIGMA_SKIP_TREES = frozenset((
    "deprecated", "unsupported", "unsupported_rules", "rules-placeholder",
    "tests", "regression_data", "documentation", "images", "other", ".github",
))

_SIGMA_LOGSOURCE = re.compile(r"(?m)^logsource:[ \t]*\r?\n((?:[ \t]+[^\n]*\r?\n?)+)")
_SIGMA_LS_FIELD = re.compile(
    r"""(?m)^[ \t]+(product|category|service)[ \t]*:[ \t]*['"]?([^'"\r\n#]*)""")


def sigma_logsource(text):
    """{product, category, service} read straight out of a rule's text.

    Deliberately not a YAML parse: this only decides which of 4,200 files are
    worth keeping, and the regex does that in 0.2s where parsing every document
    takes 9s to reach the same answer.
    """
    m = _SIGMA_LOGSOURCE.search(text)
    if not m:
        return {}
    return dict((k, v.strip().lower())
                for k, v in _SIGMA_LS_FIELD.findall(m.group(1)))


def sigma_rule_wanted(text):
    """Could this rule ever be routed to a table this tool builds?

    The cache is filtered when it is fetched rather than when it is loaded
    because SigmaHQ is 4,200 rules and 3,000 of them read Windows event logs.
    Keeping those costs a slower load on every run and fills RULE_ERRORS with
    rejected Windows constructs that bury the rejections worth reading.
    """
    ls = sigma_logsource(text)
    if ls.get("product", "") not in ("", "linux", "unix"):
        return False
    want = ls.get("service") or ls.get("category") or ""
    if not want:                        # a bare 'product: linux' rule
        return True
    for _tname, aliases, _ts in TableBuilder.SIGMA_STREAMS:
        for alias in aliases:
            if want == alias or want in alias or alias in want:
                return True
    return False


def sigma_cache_dir(explicit=None):
    """Where the fetched ruleset lives - outside any collection, by design."""
    path = explicit or os.environ.get("LINSIGHT_SIGMA_DIR")
    if path:
        return os.path.abspath(os.path.expanduser(path))
    return os.path.join(os.path.expanduser("~"), ".linsight", "sigma")


def sigma_cache_manifest(dest):
    """What the last --update-sigma wrote there, or {}."""
    try:
        with open(os.path.join(dest, "manifest.json"), "r", encoding="utf-8") as fh:
            m = json.load(fh)
        return m if isinstance(m, dict) else {}
    except (OSError, ValueError):
        return {}


def sigma_cache_count(dest):
    """Rules currently cached, counted from the files rather than the manifest."""
    n = 0
    for _root, _dirs, files in os.walk(dest):
        n += sum(1 for f in files if f.lower().endswith((".yml", ".yaml")))
    return n


def _sigma_safe_rel(name):
    """Archive member -> a relative path safe to join, or None.

    An archive is untrusted input even when the name it came from is trusted,
    and a member called ../../.ssh/authorized_keys is the whole reason to look.
    """
    parts = []
    for part in name.replace("\\", "/").split("/"):
        if not part or part == ".":
            continue
        if part == ".." or ":" in part:
            return None
        parts.append(part)
    return "/".join(parts) if parts else None


def _win_long(path):
    r"""Windows caps a path at 260 characters unless it is spelled \\?\.

    SigmaHQ nests rules five directories deep under names like
    rules-emerging-threats/2023/TA/UNC4841-Barracuda-ESG-Zero-Day-Exploitation,
    so a cache anywhere but the shortest home directory loses a handful of
    rules to the cap - and they are the emerging-threat ones, which is what a
    fresh ruleset was fetched for.
    """
    if os.name != "nt" or path.startswith("\\\\?\\"):
        return path
    full = os.path.abspath(path)
    return "\\\\?\\" + full if len(full) > 240 else path


def _rename_retry(src, dst, tries=5):
    """os.rename, retried - Windows refuses one over a tree just written.

    Renaming a directory of 4,000 second-old files comes back as access denied
    often enough to matter: whatever holds the handle (Defender, the indexer)
    lets go in a moment, and the alternative is losing a good fetch to it.
    """
    for i in range(tries):
        try:
            os.rename(src, dst)
            return
        except PermissionError:
            if i == tries - 1:
                raise
            time.sleep(0.2 * (i + 1))


def _sigma_fetch(url, etag=None, timeout=60, quiet=False):
    """-> (data, etag). data is None when the server says 'not modified'."""
    import urllib.error
    import urllib.request

    req = urllib.request.Request(url, headers={
        "User-Agent": "linsight/%s" % VERSION,
        "Accept": "application/zip, */*",
    })
    if etag:
        req.add_header("If-None-Match", etag)
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
    except urllib.error.HTTPError as e:
        if e.code == 304:                       # cache already holds this one
            return None, etag
        raise SystemExit("[!] sigma update failed: HTTP %s %s\n    %s"
                         % (e.code, e.reason, url))
    except Exception as e:
        raise SystemExit(
            "[!] sigma update failed: %s: %s\n    %s\n"
            "    no route out? fetch the ruleset elsewhere and pass the zip:\n"
            "      --update-sigma --sigma-source ./sigma-master.zip"
            % (type(e).__name__, e, url))
    with resp:
        total = int(resp.headers.get("Content-Length") or 0)
        show = (not quiet) and sys.stderr.isatty()
        chunks, got = [], 0
        while True:
            chunk = resp.read(65536)
            if not chunk:
                break
            chunks.append(chunk)
            got += len(chunk)
            if show:
                sys.stderr.write("\r[*] sigma: downloading %s%s   "
                                 % (human_size(got),
                                    " of %s" % human_size(total) if total else ""))
                sys.stderr.flush()
        if show:
            sys.stderr.write("\r" + " " * 60 + "\r")
        return b"".join(chunks), (resp.headers.get("ETag") or etag)


def _sigma_members(data, source_dir):
    """(relative path, text) for every rule file in the source.

    The zip GitHub serves wraps everything in one sigma-master/ directory; that
    prefix is dropped so a cached rule reads rules/linux/... - the path it has
    in the repo, which is what makes SIGMA_MATCHES.rule_file traceable.
    """
    if source_dir:
        for root, _dirs, files in os.walk(source_dir):
            for f in sorted(files):
                if not f.lower().endswith((".yml", ".yaml")):
                    continue
                full = os.path.join(root, f)
                rel = os.path.relpath(full, source_dir).replace(os.sep, "/")
                try:
                    with open(_win_long(full), "r", encoding="utf-8",
                              errors="replace") as fh:
                        yield rel, fh.read()
                except OSError:
                    continue
        return
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        names = [n for n in z.namelist() if n.lower().endswith((".yml", ".yaml"))]
        roots = set(n.split("/")[0] for n in z.namelist() if "/" in n)
        strip = (roots.pop() + "/") if len(roots) == 1 else ""
        for name in sorted(names):
            rel = _sigma_safe_rel(name[len(strip):]
                                  if strip and name.startswith(strip) else name)
            if not rel:
                continue
            try:
                yield rel, z.read(name).decode("utf-8", "replace")
            except Exception:                   # one unreadable member, not a run
                continue


def update_sigma_rules(dest, source=None, keep_all=False, timeout=60, quiet=False):
    """Refresh the cached Sigma ruleset in dest. -> rules cached.

    Written to a staging directory and swapped in at the end, so a fetch that
    dies half way leaves the previous ruleset intact rather than a directory
    holding a third of one.
    """
    source = source or SIGMA_SOURCE
    url = source if re.match(r"^https?://", source) else ""
    local = "" if url else os.path.abspath(os.path.expanduser(source))
    data, source_dir, etag = None, "", ""

    if url:
        have, old = sigma_cache_count(dest), sigma_cache_manifest(dest)
        # Only claim to hold this ruleset when the rules are still on disk: an
        # etag from a manifest whose directory was emptied means a 304 and no
        # rules, which is the one outcome an update must never produce.
        prev = old.get("etag") if have and old.get("url") == url else None
        status("[*] sigma: fetching %s" % url)
        data, etag = _sigma_fetch(url, prev, timeout, quiet)
        if data is None:
            status("[*] sigma: cache is already current - %d rule(s) in %s"
                   % (have, dest))
            return have
        if not zipfile.is_zipfile(io.BytesIO(data)):
            # A captive portal or a proxy login page answers 200 with HTML,
            # and the only honest reading of that is "no ruleset was fetched"
            raise SystemExit(
                "[!] sigma update failed: %s answered with %s of %s, not a zip"
                % (url, human_size(len(data)),
                   "HTML - a proxy or portal login page?"
                   if data.lstrip()[:1] == b"<" else "something else"))
    elif os.path.isdir(local):
        status("[*] sigma: reading rules from %s" % local)
        source_dir = local
    elif os.path.isfile(local):
        status("[*] sigma: reading rules from %s" % local)
        try:
            with open(local, "rb") as fh:
                data = fh.read()
        except OSError as e:
            raise SystemExit("[!] sigma update failed: %s" % e)
        if not zipfile.is_zipfile(io.BytesIO(data)):
            raise SystemExit("[!] --sigma-source file is not a zip: %s" % local)
    else:
        raise SystemExit("[!] --sigma-source is neither a URL, a zip nor a "
                         "directory: %s" % source)

    staging = dest.rstrip("/\\") + ".new"
    shutil.rmtree(_win_long(staging), ignore_errors=True)
    kept = seen = 0
    try:
        for rel, text in _sigma_members(data, source_dir):
            seen += 1
            if rel.split("/")[0] in SIGMA_SKIP_TREES:
                continue
            if not keep_all and not sigma_rule_wanted(text):
                continue
            out = _win_long(os.path.join(staging, rel.replace("/", os.sep)))
            try:
                os.makedirs(os.path.dirname(out), exist_ok=True)
                with open(out, "w", encoding="utf-8") as fh:
                    fh.write(text)
            except OSError as e:
                status("[!] sigma: cannot write %s: %s" % (out, e))
                continue
            kept += 1
        if not kept:
            raise SystemExit(
                "[!] sigma update found no rules this tool can route in %s\n"
                "    a ruleset for another platform is still worth caching - "
                "add --sigma-all" % source)
        manifest = {
            "source": source,
            "url": url,
            "etag": etag or "",
            "fetched_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            "rules": kept,
            "considered": seen,
            "filtered": not keep_all,
            "tool_version": VERSION,
        }
        with open(os.path.join(staging, "manifest.json"), "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2, sort_keys=True)

        # swap: the old ruleset stays readable until the new one is complete
        backup = dest.rstrip("/\\") + ".old"
        shutil.rmtree(_win_long(backup), ignore_errors=True)
        parent = os.path.dirname(os.path.abspath(dest))
        if parent:
            os.makedirs(parent, exist_ok=True)
        if os.path.isdir(dest):
            _rename_retry(dest, backup)
        try:
            _rename_retry(staging, dest)
        except OSError:
            if os.path.isdir(backup) and not os.path.exists(dest):
                os.rename(backup, dest)         # put the old ruleset back
            raise
        shutil.rmtree(_win_long(backup), ignore_errors=True)
    finally:
        shutil.rmtree(_win_long(staging), ignore_errors=True)

    status("[+] sigma: %d rule(s) cached in %s%s"
           % (kept, dest,
              " (of %d in the source; the rest target a platform this tool "
              "builds no table for)" % seen if kept < seen else ""))
    return kept


# ---------------------------------------------------------------------------
# the triage engine
# ---------------------------------------------------------------------------

class Triage:
    def __init__(self, col, opts):
        self.col = col
        self.opts = opts
        self.findings = []
        self.events = []
        self.meta = {}
        self.processes = {}          # pid -> dict
        self.hidden_pids = set()
        self.sockets = []            # parsed ss entries
        self.users = {}              # name -> passwd fields
        self.uids = {}               # uid -> name
        self.groups = {}             # name -> (gid, members)
        self.gids = set()
        self.collection_time = None   # true UTC instant the collection finished
        self.tz_offset = timedelta(0)  # host local clock - UTC
        self.iocs = defaultdict(set)  # ioc string -> set of artifact mentions
        self.ww_paths = set()         # world-writable paths confirmed from the bodyfile
        self.bodyfile_seen = False
        self.auto_pivot = set()       # indicators worth chasing across every artifact
        self.pivot_hits = []          # (term, artifact, line_no, line) for IOC_HITS
        self.pivot_stats = {}         # term -> (count, first_utc, last_utc)
        self._journal_procs = None    # lazily built pid -> exe map from the journal
        self._journal_scan = None     # one-pass journal projections, see journal_scan
        self._unit_execs = None       # lazily built unit name -> ExecStart binary
        self._dmesg_base = None       # lazily resolved boot instant for dmesg stamps

    # -- helpers ------------------------------------------------------------
    def add(self, severity, category, title, detail="", evidence=None,
            source="", mitre="", times=None, count=None):
        """Raise a finding.

        `times` is any iterable of the occurrence timestamps behind it - aware
        datetimes or normalised UTC strings, unordered, holes allowed - reduced
        here to a first/last span. `count` is how many occurrences there were,
        which matters whenever the evidence list is capped; omitted, it falls
        back to the number of evidence lines.
        """
        first, last = span_of(times)
        self.findings.append(Finding(severity, category, title, detail,
                                     evidence, source, mitre, first, last, count))

    def event(self, ts, category, description, severity="INFO", source=""):
        if ts is not None:
            self.events.append(Event(ts, category, description, severity, source))

    def ioc(self, value, where):
        if value:
            self.iocs[value].add(where)

    def log_ts(self, text):
        """Log timestamp -> UTC string, using the host's offset and clock year.

        Syslog stamps carry no year. The collection year is the only anchor a
        collection gives us, so a month later than the collection month is read
        as the previous year rather than being silently mis-dated forward.
        """
        ct = self.collection_time
        hint = ct.year if ct else None
        out = norm_log_ts(text, self.tz_offset, hint)
        if out and ct and hint and out[:10] > ct.strftime("%Y-%m-%d"):
            m = _TS_SYSLOG_RE.match((text or "").strip())
            if m:                       # year-less stamp that landed in the future
                out = norm_log_ts(text, self.tz_offset, hint - 1)
        return out

    def proc_times(self, pids):
        """Start times of the given pids, for dating a finding by its processes.

        A socket, an open file or a hidden pid has no timestamp of its own -
        the collection caught it in one instant - but the process holding it
        does, and that is the time an analyst actually wants: when the thing
        that owns this evidence began running.
        """
        return [self.processes.get(str(p), {}).get("start") for p in pids or []]

    def window_start(self):
        if self.collection_time:
            return self.collection_time - timedelta(hours=self.opts.window)
        return None

    def local_to_utc(self, dt):
        """Host-local wall-clock timestamp -> true UTC instant."""
        return dt - self.tz_offset if dt else dt

    # -- 1. collection metadata --------------------------------------------
    def _tzif_offset(self, raw, at):
        """UTC offset in effect at `at`, read out of a TZif /etc/localtime.

        zoneinfo needs a tzdata database, which an evidence workstation running
        Windows does not have, and the offset is the one piece of collection
        metadata every host-local log timestamp depends on. The file itself
        carries the answer, so read it there rather than guess UTC and mis-date
        every syslog line by the host's offset.
        """
        if not raw or raw[:4] != b"TZif":
            return None
        try:
            isutcnt, isstdcnt, leapcnt, timecnt, typecnt, charcnt = struct.unpack(
                ">6L", raw[20:44])
        except struct.error:
            return None
        if not typecnt:
            return None
        base = 44
        need = base + timecnt * 5 + typecnt * 6
        if len(raw) < need:
            return None
        try:
            times = struct.unpack(">%dl" % timecnt, raw[base:base + timecnt * 4]) \
                if timecnt else ()
            idx = raw[base + timecnt * 4:base + timecnt * 5]
            toff = base + timecnt * 5
            types = [struct.unpack(">lBB", raw[toff + i * 6:toff + i * 6 + 6])
                     for i in range(typecnt)]
        except struct.error:
            return None
        epoch = int(at.timestamp()) if at else 0
        chosen = None
        for i, t in enumerate(times):
            if t <= epoch and i < len(idx):
                chosen = idx[i]
            elif t > epoch:
                break
        if chosen is None or chosen >= typecnt:
            # no transition at or before this instant: the first non-DST type is
            # what the zone uses, which is the right answer for a fixed zone
            std = [t for t in types if not t[1]]
            return timedelta(seconds=(std or types)[0][0])
        return timedelta(seconds=types[chosen][0])

    def _velo_host_tz(self):
        """(offset, zone name, how we know) from the collected filesystem."""
        name = ""
        for path in ("/etc/timezone",):
            rel = self.col.rootfs(path)
            txt = (self.col.text(rel) or "").strip() if rel else ""
            first = txt.splitlines()[0].strip() if txt else ""
            if first and "/" in first:
                name = first
                break
        if not name:
            rel = self.col.rootfs("/etc/sysconfig/clock")
            for ln in (self.col.lines(rel) if rel else []):
                m = re.match(r'\s*ZONE\s*=\s*"?([^"\s]+)"?', ln)
                if m:
                    name = m.group(1)
                    break
        rel = self.col.rootfs("/etc/localtime")
        raw = self.col.read_bytes(rel, 512 * 1024) if rel else None
        off = self._tzif_offset(raw, self.collection_time)
        if off is not None:
            return off, name, "/etc/localtime"
        if name:
            try:
                from zoneinfo import ZoneInfo
                at = self.collection_time or datetime.now(timezone.utc)
                return at.astimezone(ZoneInfo(name)).utcoffset(), name, "/etc/timezone"
            except Exception:
                pass
        return None, name, ""

    def _velo_context(self):
        """collection_context.json, whichever shape this release wrote."""
        txt = self.col.text("collection_context.json")
        if not txt:
            return {}
        try:
            obj = json.loads(txt)
        except ValueError:
            obj = None
            for ln in txt.splitlines():          # written as JSONL by some builds
                if ln.strip():
                    try:
                        obj = json.loads(ln)
                    except ValueError:
                        continue
                    break
        return obj if isinstance(obj, dict) else {}

    def analyze_velociraptor_collection(self):
        """The Velociraptor equivalent of reading uac.log.

        A Velociraptor collection states far less about itself than UAC does -
        there is no hostname, OS or timezone in its own metadata - so the facts
        the rest of the run depends on are recovered from the artifacts and the
        filesystem copy, and each one records where it came from. Guessing here
        is not cheap: collection_time anchors every 'recent activity' window and
        supplies the year that year-less syslog stamps are read against.
        """
        src = "collection_context.json"
        ctx = self._velo_context()
        velo = self.col.velo
        info = {}
        if ctx:
            for key, label in (("client_id", "Client ID"),
                               ("session_id", "Session ID"),
                               ("status", "Collection status"),
                               ("total_collected_rows", "Rows collected"),
                               ("total_uploaded_files", "Files uploaded"),
                               ("total_expected_uploaded_bytes", "Bytes expected")):
                if ctx.get(key) not in (None, ""):
                    info[label] = str(ctx[key])
            arts = ctx.get("artifacts_with_results") or []
            req = ctx.get("request") or {}
            if isinstance(req, dict):
                spec = req.get("artifacts") or req.get("Artifacts") or []
                if isinstance(spec, list) and spec:
                    info["Artifacts requested"] = ", ".join(str(a) for a in spec)
            if isinstance(arts, list) and arts:
                info["Artifacts with results"] = ", ".join(str(a) for a in arts)

        start = velo_time(ctx.get("start_time") or ctx.get("create_time"))
        end = velo_time(ctx.get("active_time")) or start
        if end:
            self.collection_time = end
            info["Collection started"] = (start.strftime("%Y-%m-%d %H:%M:%S UTC")
                                          if start else "")
            info["Collection finished"] = end.strftime("%Y-%m-%d %H:%M:%S UTC")

        # host identity: the artifact says it best, the filesystem next, and the
        # archive name last - it is a filename, not evidence, so it is labelled
        if velo:
            for _rel, row in velo.rows("Generic.Client.Info",
                                       "Generic.Client.Info/BasicInformation"):
                for keys, label in ((("Hostname", "Host"), "Hostname"),
                                    (("Fqdn",), "FQDN"),
                                    (("OS", "Platform"), "Operating system"),
                                    (("Release", "PlatformVersion"), "OS release"),
                                    (("Architecture",), "System architecture"),
                                    (("Version",), "Velociraptor version")):
                    val = velo_get(row, *keys)
                    if val and label not in info:
                        info[label] = str(val)
        if "Hostname" not in info:
            rel = self.col.rootfs("/etc/hostname")
            txt = (self.col.text(rel) or "").strip() if rel else ""
            if txt:
                info["Hostname"] = txt.splitlines()[0].strip()
        if "Hostname" not in info:
            m = re.match(r"(?i)^collection-(.+?)-\d{4}-\d{2}-\d{2}",
                         os.path.basename(self.col.path))
            if m:
                info["Hostname (from archive name)"] = m.group(1)
        if "Operating system" not in info:
            for path in ("/etc/os-release", "/usr/lib/os-release"):
                rel = self.col.rootfs(path)
                for ln in (self.col.lines(rel) if rel else []):
                    if ln.startswith("PRETTY_NAME="):
                        info["Operating system"] = ln.split("=", 1)[1].strip().strip('"')
                        break
                if "Operating system" in info:
                    break

        off, zone, how = self._velo_host_tz()
        if zone:
            info["Time zone"] = zone
        if off is not None:
            self.tz_offset = off
            info["Host UTC offset"] = "%+03d:%02d" % (
                off.total_seconds() // 3600, abs(off.total_seconds() % 3600) // 60)
            info["Host UTC offset source"] = how
        else:
            # said out loud, because every host-local log stamp below is now
            # being read as UTC and a wrong offset is a wrong timeline
            info["Host UTC offset"] = "unknown - host-local log stamps read as UTC"

        info["Collection format"] = "Velociraptor offline collector"
        if velo:
            info["Artifact result files"] = str(len(velo.files))
        self.meta.update({k: v for k, v in info.items() if v not in (None, "")})

        detail = "\n".join("%-24s %s" % (k + ":", v)
                           for k, v in self.meta.items() if v)
        self.add("INFO", "Collection", "Collection metadata", detail, source=src,
                 times=[start, end])
        self.analyze_velociraptor_log()

    VELO_LOG_FILES = ("log.json", "logs.json")

    def analyze_velociraptor_log(self):
        """Velociraptor's own run log - the equivalent of UAC's ERR/WRN lines."""
        errors, warnings = [], []
        err_ts, warn_ts = [], []
        for rel in self.VELO_LOG_FILES:
            if not self.col.exists(rel):
                continue
            for ln in self.col.iter_lines(rel):
                if not ln.strip():
                    continue
                try:
                    row = json.loads(ln)
                except ValueError:
                    continue
                if not isinstance(row, dict):
                    continue
                lvl = str(velo_get(row, "level", "Level")).upper()
                msg = str(velo_get(row, "message", "Message", "msg")).strip()
                if not msg:
                    continue
                when = velo_time(velo_get(row, "timestamp", "Timestamp",
                                          "time", "Time", "_ts"))
                if lvl.startswith("ERR") or lvl == "FATAL":
                    errors.append(msg)
                    err_ts.append(when)
                elif lvl.startswith("WARN"):
                    warnings.append(msg)
                    warn_ts.append(when)
        src = "log.json"
        if errors:
            self.add("LOW", "Collection",
                     "%d collection error(s) - artifacts may be incomplete" % len(errors),
                     "Velociraptor logged errors while collecting. Findings that "
                     "depend on the affected artifacts may be incomplete.",
                     [trunc(e) for e in errors[:15]], source=src,
                     times=err_ts, count=len(errors))
        if warnings:
            self.add("INFO", "Collection", "%d collection warning(s)" % len(warnings),
                     evidence=[trunc(w) for w in warnings[:10]], source=src,
                     times=warn_ts, count=len(warnings))

    def analyze_collection(self):
        if self.col.layout == "velociraptor":
            return self.analyze_velociraptor_collection()
        src = "uac.log"
        lines = self.col.lines(src)
        info = {}
        errors, warnings = [], []
        err_ts, warn_ts = [], []
        first_ts = last_ts = None
        ts_re = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) ([+-]\d{4}) (\w{3}) (.*)$")
        for ln in lines:
            m = ts_re.match(ln)
            if not m:
                continue
            stamp, off, level, msg = m.groups()
            # UAC logs the host's local wall clock plus its UTC offset; everything
            # downstream (bodyfile epochs) is UTC, so normalise here once.
            try:
                sign = -1 if off[0] == "-" else 1
                self.tz_offset = sign * timedelta(hours=int(off[1:3]), minutes=int(off[3:5]))
            except (ValueError, IndexError):
                pass
            try:
                dt = datetime.strptime(stamp, "%Y-%m-%d %H:%M:%S").replace(
                    tzinfo=timezone.utc) - self.tz_offset
            except ValueError:
                dt = None
            if dt:
                first_ts = first_ts or dt
                last_ts = dt
            if level == "ERR":
                errors.append(msg)
                err_ts.append(dt)
            elif level == "WRN":
                warnings.append(msg)
                warn_ts.append(dt)
            for key in ("Hostname", "Operating system", "System architecture",
                        "Command line", "Running as", "UAC version", "Profile",
                        "Mount point", "Output format"):
                if msg.startswith(key + ":"):
                    info[key] = msg.split(":", 1)[1].strip()
        self.meta.update(info)
        if last_ts:
            self.collection_time = last_ts
            self.meta["Collection started"] = (
                first_ts.strftime("%Y-%m-%d %H:%M:%S UTC") if first_ts else "")
            self.meta["Collection finished"] = last_ts.strftime("%Y-%m-%d %H:%M:%S UTC")
            self.meta["Host UTC offset"] = "%+03d:%02d" % (
                self.tz_offset.total_seconds() // 3600,
                abs(self.tz_offset.total_seconds() % 3600) // 60)

        # host clock / OS from live_response as a cross-check
        for rel, key in (("live_response/system/uname_-a.txt", "uname"),
                         ("live_response/system/date.txt", "Host date at collection"),
                         ("live_response/system/uptime.txt", "uptime"),
                         ("live_response/system/uptime_-s.txt", "Booted at"),
                         ("live_response/network/hostname.txt", "hostname"),
                         ("live_response/system/timedatectl_status.txt", "timedatectl")):
            txt = self.col.text(rel)
            if txt:
                if key == "timedatectl":
                    for ln in txt.splitlines():
                        if "Time zone" in ln:
                            self.meta["Time zone"] = ln.split(":", 1)[1].strip()
                else:
                    self.meta[key] = txt.strip().splitlines()[0] if txt.strip() else ""

        if not self.collection_time:
            # The 2021 profile writes a uac.log this parser cannot date, so
            # `date` on the host is the only statement of when the collection
            # ran - and without it every incident-window check silently does
            # nothing. The capture already starts with the weekday, so the
            # "Xxx " that used to be prepended here handed parse_lstart a
            # second one, it read 'Wed' as the month and returned None: the
            # fallback existed but had never once produced a time. The
            # timezone word is optional because not every `date` prints one.
            hd = self.meta.get("Host date at collection", "")
            m = re.search(r"(\w{3}\s+\w{3}\s+\d+\s+\d\d:\d\d:\d\d)"
                          r"(?:\s+\S+)?\s+(\d{4})", hd)
            if m:
                self.collection_time = self.local_to_utc(
                    parse_lstart("%s %s" % (m.group(1), m.group(2))))
                if self.collection_time:
                    self.meta["Collection finished"] = (
                        self.collection_time.strftime("%Y-%m-%d %H:%M:%S UTC")
                        + " (from `date` on the host)")

        if "Host UTC offset" not in self.meta:
            # said out loud, the same way the Velociraptor path does: uac.log is
            # where a UAC collection states its offset, and without one every
            # host-local stamp below is being read as UTC
            self.meta["Host UTC offset"] = ("unknown - uac.log carried none, "
                                            "host-local log stamps read as UTC")

        detail = "\n".join("%-24s %s" % (k + ":", v) for k, v in self.meta.items() if v)
        # a profile whose uac.log this parser cannot date still knows when it
        # ran, from `date` on the host; the finding should say so either way
        self.add("INFO", "Collection", "Collection metadata", detail, source=src,
                 times=[first_ts or self.collection_time,
                        last_ts or self.collection_time])

        if errors:
            self.add("LOW", "Collection",
                     "%d collection error(s) - artifacts may be incomplete" % len(errors),
                     "UAC logged errors while collecting. Findings that depend on the "
                     "affected artifacts may be incomplete.",
                     [trunc(e) for e in errors[:15]], source=src,
                     times=err_ts, count=len(errors))
        if warnings:
            self.add("INFO", "Collection", "%d collection warning(s)" % len(warnings),
                     evidence=[trunc(w) for w in warnings[:10]], source=src,
                     times=warn_ts, count=len(warnings))

    # -- 2. kernel state ----------------------------------------------------
    TAINT_BITS = [
        (1 << 0, "proprietary module loaded", "LOW"),
        (1 << 1, "module force-loaded", "HIGH"),
        (1 << 2, "unsafe SMP / kernel running on out-of-spec CPU config", "INFO"),
        (1 << 3, "module force-unloaded", "HIGH"),
        (1 << 4, "machine check exception", "LOW"),
        (1 << 5, "bad page", "LOW"),
        (1 << 6, "user forced taint", "MEDIUM"),
        (1 << 7, "kernel died (oops/BUG)", "MEDIUM"),
        (1 << 8, "ACPI table overridden", "LOW"),
        (1 << 9, "kernel warning issued", "INFO"),
        (1 << 10, "staging driver loaded", "INFO"),
        (1 << 11, "firmware bug workaround", "INFO"),
        (1 << 12, "OUT-OF-TREE module loaded", "MEDIUM"),
        (1 << 13, "UNSIGNED module loaded", "HIGH"),
        (1 << 14, "soft lockup", "LOW"),
        (1 << 15, "kernel live-patched", "MEDIUM"),
        (1 << 16, "auxiliary taint", "LOW"),
        (1 << 17, "struct randomisation plugin", "INFO"),
    ]

    def analyze_kernel_taint(self):
        src = "live_response/system/cat_proc_sys_kernel_tainted.txt"
        txt = (self.col.text(src) or "").strip()
        if not txt.isdigit():
            return
        val = int(txt)
        if val == 0:
            self.add("INFO", "Kernel", "Kernel not tainted (0)", source=src)
            return
        flags, worst = [], "INFO"
        for bit, desc, sev in self.TAINT_BITS:
            if val & bit:
                flags.append("bit %-6s %s" % (bit, desc))
                if SEV_RANK[sev] < SEV_RANK[worst]:
                    worst = sev
        self.add(worst if worst != "INFO" else "LOW", "Kernel",
                 "Kernel taint flags set (value %d)" % val,
                 "Out-of-tree / unsigned / force-loaded modules are how most Linux "
                 "kernel rootkits arrive. Correlate with the loaded module list.",
                 flags, source=src, mitre="T1014 Rootkit")

    # -- 3. LD_PRELOAD ------------------------------------------------------
    def analyze_ld_preload(self):
        entries = []
        for src in ("chkrootkit/etc_ld_so_preload.txt",
                    "live_response/system/etc_ld_so_preload.txt"):
            for ln in self.col.lines(src):
                if ln.strip():
                    entries.append((ln.strip(), src))
        rel = self.col.rootfs("/etc/ld.so.preload")
        if rel:
            for ln in self.col.lines(rel):
                if ln.strip():
                    entries.append((ln.strip(), rel))
        if entries:
            ev = []
            for path, src in entries:
                ev.append("%s   (from %s)" % (path, src))
                self.ioc(path, "/etc/ld.so.preload")
                # chase the library by name: the preload path is usually a symlink
                # (/lib/... -> /usr/lib/...), so the basename finds every mention.
                # It is recorded as an indicator in its own right, not only as a
                # search term, so its rows in IOC_HITS carry the technique that
                # put it there rather than reading as an unexplained filename.
                if os.path.basename(path):
                    self.auto_pivot.add(os.path.basename(path))
                    self.ioc(os.path.basename(path), "/etc/ld.so.preload")
            self.add("CRITICAL", "Rootkit", "/etc/ld.so.preload is populated",
                     "Every dynamically linked process on this host loads these shared "
                     "objects before libc. This is the classic userland-rootkit "
                     "persistence and hooking mechanism (hides files, processes, "
                     "connections and its own presence). Treat the listed .so as "
                     "malicious until proven otherwise, and note that any tool run on "
                     "the live host - including this collection's ps/ss/ls output - "
                     "was subject to those hooks.",
                     ev, source=entries[0][1], mitre="T1574.006 Hijack Execution Flow: LD_PRELOAD")

        # LD_PRELOAD / LD_LIBRARY_PATH through the environment
        for src in ("live_response/system/env.txt", "live_response/system/printenv.txt"):
            for ln in self.col.lines(src):
                if ln.startswith(("LD_PRELOAD=", "LD_LIBRARY_PATH=", "LD_AUDIT=")) and ln.split("=", 1)[1].strip():
                    self.add("HIGH", "Rootkit", "Loader environment variable set: %s" % ln.split("=")[0],
                             evidence=[ln], source=src,
                             mitre="T1574.006 Hijack Execution Flow")
        rel = self.col.rootfs("/etc/environment")
        for ln in self.col.lines(rel) if rel else []:
            if "LD_PRELOAD" in ln or "LD_AUDIT" in ln:
                self.add("CRITICAL", "Rootkit", "LD_PRELOAD set system-wide in /etc/environment",
                         evidence=[ln], source=rel, mitre="T1574.006")

        # ld.so.conf.d entries pointing at writable locations
        for rel in self.col.rootfs_glob("/etc/ld.so.conf.d/*"):
            for ln in self.col.lines(rel):
                s = ln.strip()
                if s and not s.startswith("#") and s.startswith(TMPFS_DIRS + ("/home/",)):
                    self.add("HIGH", "Rootkit", "Library search path in a writable directory",
                             evidence=[ln], source=rel, mitre="T1574.006")

    # -- 4. hidden processes -----------------------------------------------
    def analyze_hidden_pids(self):
        src = "live_response/process/hidden_pids_for_ps_command.txt"
        pids = [ln.strip() for ln in self.col.lines(src) if ln.strip().isdigit()]
        if not pids:
            return
        self.hidden_pids = set(pids)
        ev = []
        for pid in pids:
            p = self.processes.get(pid, {})
            desc = "PID %-7s" % pid
            if p.get("exe"):
                desc += " exe=%s" % p["exe"]
            if p.get("args"):
                desc += " args=%s" % trunc(p["args"], 90)
            if p.get("user"):
                desc += " user=%s" % p["user"]
            if not p:
                desc += " (no /proc metadata recovered - process fully hidden)"
            ev.append(desc)
            self.ioc("pid:" + pid, "hidden_pids")
        self.add("CRITICAL", "Rootkit",
                 "%d hidden process(es): present in /proc but absent from ps output" % len(pids),
                 "UAC compares the PIDs visible under /proc against the PIDs reported "
                 "by ps. A mismatch means something is filtering the process list - a "
                 "loaded kernel module, an LD_PRELOAD library hooking readdir(), or a "
                 "patched ps binary. These PIDs are the highest-priority pivot in this "
                 "collection.",
                 ev, source=src, mitre="T1564 Hide Artifacts / T1014 Rootkit",
                 times=self.proc_times(pids))

    # -- 5. processes -------------------------------------------------------
    # exe paths the kernel or a runtime reported, as opposed to ones the
    # process told us about itself. Checks that compare exe against argv[0]
    # are only evidence when the exe side came from this set.
    OBSERVED_EXE_SOURCES = frozenset((
        "/proc/<pid>/exe link", "/proc/<pid>/exe capture",
        "lsof txt descriptor", "first executable mapping in maps",
        "journal _EXE (same boot)",
        "Velociraptor Exe (/proc/<pid>/exe)"))

    def journal_files(self):
        out = []
        for pat in ("/var/log/journal/**", "/run/log/journal/**",
                    "/var/run/log/journal/**"):
            for rel in self.col.rootfs_glob(pat):
                if ".journal" in os.path.basename(rel).lower():
                    out.append(rel)
        return sorted(set(out), key=str.lower)

    # message shapes worth keeping out of the journal. Everything else is
    # dropped during the scan so the whole journal never has to be held.
    # Paired with PRIV_HINT_RE against the syslog identifier - see journal_scan.
    JOURNAL_KEEP_RE = re.compile(
        r"\b(sudo|su|pkexec|polkit|usermod|useradd|userdel|groupadd|groupdel|"
        r"gpasswd|chage|passwd|visudo|run0)\b"
        r"|Failed (?:password|publickey|none|keyboard-interactive)"
        r"|Invalid user|authentication failure|incorrect password attempt"
        r"|NOT in sudoers|maximum authentication attempts|"
        r"Too many authentication failures|LOGIN FAILURE|FAILED LOGIN"
        r"|ROOT LOGIN REFUSED|check pass; user unknown"
        r"|SRC=\S+.*DST=", re.I)

    def journal_scan(self):
        """Walk every journal file once and keep only the projections we need.

        The journal is the single largest artifact in a modern collection and
        four different tables want something from it. Parsing it once per table
        meant re-decoding hundreds of thousands of compressed entries four
        times; this keeps one pass and a few thousand small tuples instead of
        the whole thing.
        """
        if self._journal_scan is not None:
            return self._journal_scan
        # pid -> {exe: (realtime, boot, cmdline, comm)}. Keeping one candidate
        # per exe rather than only the newest entry matters twice over: a PID is
        # reused within a single boot, and systemd logs an exec transition under
        # the new process's comm while _EXE still names the executor.
        cand = defaultdict(dict)
        newest = (0, "")               # (realtime, boot_id) seen anywhere
        events = []                    # (ts, ident, msg, hostname, tty, source)
        for rel in self.journal_files():
            raw = self.col.read_bytes(rel)
            if not raw or raw[:8] != JOURNAL_MAGIC:
                continue
            try:
                entries, _ = parse_journal(raw)
            except Exception:
                continue
            host_path = self.col.host_path(rel)
            for e in entries:
                rt = e.get("__REALTIME") or 0
                boot = e.get("_BOOT_ID", "")
                if rt > newest[0]:
                    newest = (rt, boot)
                pid = e.get("_PID")
                exe = e.get("_EXE")
                if pid and exe:
                    slot = cand[pid].get(exe)
                    if slot is None or rt > slot[0]:
                        cand[pid][exe] = (rt, boot, e.get("_CMDLINE", ""),
                                          e.get("_COMM", ""))
                msg = e.get("MESSAGE", "")
                if not msg:
                    continue
                # the daemon name is in the identifier, not the text: a sudo
                # record reads '  bob : TTY=... ; COMMAND=...' and contains the
                # word "sudo" nowhere, so filtering on the message alone drops
                # almost every privilege event
                ident = e.get("SYSLOG_IDENTIFIER", "") or e.get("_COMM", "")
                if not (self.JOURNAL_KEEP_RE.search(msg)
                        or (ident and PRIV_HINT_RE.search(ident))):
                    continue
                try:
                    ts = datetime.fromtimestamp(rt / 1e6, timezone.utc) \
                        .strftime("%Y-%m-%d %H:%M:%S")
                except (OverflowError, OSError, ValueError):
                    ts = ""
                events.append((ts, ident, msg, e.get("_HOSTNAME", ""),
                               e.get("_TTY", ""), host_path))
            del entries
        boot_id = newest[1]
        procs = {}
        for pid, byexe in cand.items():
            rows = [(rt, exe, cmdline, comm)
                    for exe, (rt, boot, cmdline, comm) in byexe.items()
                    if not boot_id or boot == boot_id]
            if not rows:
                continue
            rows.sort(reverse=True)     # newest candidate first
            procs[pid] = [{"exe": e, "cmdline": c, "comm": cm}
                          for _rt, e, c, cm in rows]
        self._journal_scan = {"procs": procs, "events": events,
                              "boot_id": boot_id}
        self._journal_procs = procs
        return self._journal_scan

    def journal_proc_map(self):
        """pid -> {exe, cmdline, comm} for the boot the collection was taken in.

        systemd stamps _EXE and _CMDLINE on every message, so the journal knows
        the full binary path of anything that ever logged - which is the only
        surviving source when the profile did not capture /proc/<pid>/exe.

        PIDs are reused across boots and the journal spans months, so an entry
        only counts if it belongs to the newest boot in the collection; without
        that filter a PID picks up whatever unrelated process held the number
        weeks earlier.
        """
        return self.journal_scan()["procs"]

    @staticmethod
    def _name_akin(a, b):
        """Loose name comparison: comm is truncated to 15 bytes and decorated."""
        a = (a or "").strip("[]():").strip()
        b = (b or "").strip("[]():").strip()
        if not a or not b:
            return False
        return a[:15] == b[:15] or a in b or b in a

    @classmethod
    def _journal_exe_ok(cls, comm, exe, args):
        """Is this journal candidate the binary ps saw on that PID?

        Two independent checks, both required:

        internal   - the entry's own _COMM must match its _EXE. systemd logs the
                     exec transition for a unit under the new process's comm
                     while _EXE still names systemd-executor, and that entry is
                     the newest one on the PID, so without this check smbd is
                     reported as /usr/lib/systemd/systemd-executor.
        vs ps      - the entry must also match what ps observed, because a PID
                     is reused within one boot and the newest entry can belong
                     to an entirely earlier process.
        """
        cand = os.path.basename(exe or "")
        if comm and cand and not cls._name_akin(comm, cand):
            return False
        base = os.path.basename((args or "").split()[0]) if args and args.split() \
            else ""
        if not base:
            return True                 # ps told us nothing to disagree with
        return cls._name_akin(comm, base) or cls._name_akin(cand, base)

    # Velociraptor's pslist() reads /proc/<pid>/exe itself, so its Exe column is
    # a kernel-reported link target and not a restatement of argv[0]. That
    # distinction is the whole basis of the masquerade check, which is why the
    # source is named rather than folded into the UAC label.
    VELO_EXE_SOURCE = "Velociraptor Exe (/proc/<pid>/exe)"

    VELO_PROCESS_ARTIFACTS = ("Linux.Sys.Pslist", "Linux.Sys.Pslist/All",
                              "Exchange.Linux.Sys.Pslist", "Generic.System.Pstree")

    def _parse_velo_processes(self, procs):
        """Process table from Velociraptor results, in UAC's shape."""
        velo = self.col.velo
        if not velo:
            return
        for _rel, row in velo.rows(*self.VELO_PROCESS_ARTIFACTS):
            # str(...), never `or ""`: a Ppid of 0 is the kernel and is the
            # correct parent of pid 1, but it is also falsey, and `or ""` threw
            # it away and left the top of the process tree unrooted
            pid = str(velo_get(row, "Pid", "pid", "ProcessId")).strip()
            if not pid.isdigit():
                continue
            p = procs.setdefault(pid, {})
            ppid = str(velo_get(row, "Ppid", "ppid", "ParentPid")).strip()
            if ppid.isdigit():
                p.setdefault("ppid", ppid)
            user = velo_get(row, "Username", "User", "Uid", "uid")
            if user not in (None, ""):
                p.setdefault("user", str(user))
            args = velo_get(row, "CommandLine", "Cmdline", "Commandline", "Args")
            if isinstance(args, list):
                args = " ".join(str(a) for a in args)
            name = velo_get(row, "Name", "Comm")
            if args:
                p.setdefault("args", str(args).strip())
            elif name:
                # a kernel thread has no command line; UAC's ps prints it
                # bracketed and several checks key off that shape
                p.setdefault("args", "[%s]" % str(name).strip("[]"))
            exe = velo_get(row, "Exe", "ExePath", "Executable")
            if exe:
                p.setdefault("exe", str(exe).strip())
                p.setdefault("exe_source", self.VELO_EXE_SOURCE)
            cwd = velo_get(row, "Cwd", "CurrentDirectory")
            if cwd:
                p.setdefault("cwd", str(cwd).strip())
                p.setdefault("cwd_source", "Velociraptor Cwd (/proc/<pid>/cwd)")
            start = velo_time(velo_get(row, "CreateTime", "StartTime", "Started",
                                       "CreatedTime"))
            if start and not p.get("start"):
                p["start"] = start

    def _parse_process_tables(self):
        procs = {}
        self._parse_velo_processes(procs)

        # UAC ran this as `ps -eo` until 2022 and `ps -axo` after it, and the
        # columns are identical either way: reading only the modern spelling
        # cost an older collection every start time it had actually captured.
        for src in ("live_response/process/ps_-axo_pid_user_lstart_args.txt",
                    "live_response/process/ps_-eo_pid_user_lstart_args.txt"):
            for ln in self.col.lines(src)[1:]:
                m = re.match(r"\s*(\d+)\s+(\S+)\s+(\w{3}\s+\w{3}\s+\d+\s+\d\d:\d\d:\d\d\s+\d{4})\s+(.*)$", ln)
                if m:
                    pid, user, start, args = m.groups()
                    procs.setdefault(pid, {})["user"] = user
                    procs[pid]["args"] = args.strip()
                    procs[pid]["start"] = self.local_to_utc(parse_lstart(start))

        if not procs:
            src = "live_response/process/ps_auxwww.txt"
            for ln in self.col.lines(src)[1:]:
                f = ln.split(None, 10)
                if len(f) >= 11 and f[1].isdigit():
                    procs.setdefault(f[1], {})
                    procs[f[1]].update({"user": f[0], "args": f[10].strip()})

        if not procs:
            src = "live_response/process/ps_-ef.txt"
            for ln in self.col.lines(src)[1:]:
                f = ln.split(None, 7)
                if len(f) >= 8 and f[1].isdigit():
                    procs.setdefault(f[1], {})
                    procs[f[1]].update({"user": f[0], "args": f[7].strip(), "ppid": f[2]})

        # ppid from ps -ef when we primarily used lstart output
        for ln in self.col.lines("live_response/process/ps_-ef.txt")[1:]:
            f = ln.split(None, 7)
            if len(f) >= 8 and f[1].isdigit():
                procs.setdefault(f[1], {}).setdefault("ppid", f[2])

        # /proc/<pid>/exe targets, plus owner/group columns from ls -l
        ls_re = re.compile(r"^(\S+)\s+\d+\s+(\S+)\s+(\S+)\s+\d+\s+\S+\s+\S+\s+\S+\s+"
                           r"/proc/(\d+)/exe(?:\s+->\s+(.*))?$")
        for src2 in ("live_response/process/running_processes_full_paths.txt",
                     "live_response/process/ls_-l_proc_pid_exe.txt"):
            for ln in self.col.lines(src2):
                m = ls_re.match(ln.strip())
                if not m:
                    continue
                _mode, owner, group, pid, target = m.groups()
                p = procs.setdefault(pid, {})
                p["owner"] = owner
                p["group"] = group
                if target:
                    p["exe"] = target.strip()

        for src2 in ("live_response/process/ls_-l_proc_pid_cwd.txt",
                     "live_response/process/running_processes_cwd.txt"):
            for ln in self.col.lines(src2):
                m = re.search(r"/proc/(\d+)/cwd\s+->\s+(.*)$", ln.strip())
                if m:
                    procs.setdefault(m.group(1), {})["cwd"] = m.group(2).strip()
        # a constant label, not one containing the pid - the pid is already the
        # row's key, and a per-row source string cannot be grouped or filtered
        for p in procs.values():
            # setdefault, not assignment: a source set above this point named a
            # different artifact, and overwriting it would credit the ls -l
            # output for a link this collection never captured that way
            if p.get("exe"):
                p.setdefault("exe_source", "/proc/<pid>/exe link")
            if p.get("cwd"):
                p.setdefault("cwd_source", "/proc/<pid>/cwd link")

        # per-PID captures, when the profile stored the links individually
        for rel in self.col.glob("live_response/process/proc/*/exe*.txt"):
            pid = rel.split("/")[-2]
            txt = (self.col.text(rel) or "").strip()
            m = re.search(r"->\s*(.+)$", txt) or re.match(r"^(/\S.*)$", txt)
            if m and not procs.setdefault(pid, {}).get("exe"):
                procs[pid]["exe"] = m.group(1).strip()
                procs[pid]["exe_source"] = "/proc/<pid>/exe capture"
        for rel in self.col.glob("live_response/process/proc/*/cwd*.txt"):
            pid = rel.split("/")[-2]
            txt = (self.col.text(rel) or "").strip()
            m = re.search(r"->\s*(.+)$", txt) or re.match(r"^(/\S.*)$", txt)
            if m and not procs.setdefault(pid, {}).get("cwd"):
                procs[pid]["cwd"] = m.group(1).strip()
                procs[pid]["cwd_source"] = "/proc/<pid>/cwd capture"

        self._fill_exe_from_lsof(procs)
        self._fill_exe_from_maps(procs)
        self._fill_exe_from_journal(procs)
        self._fill_exe_from_argv(procs)
        self._fill_exe_from_cgroup(procs)
        self.processes = procs

    def unit_exec_map(self):
        """systemd unit name -> the binary its ExecStart runs."""
        if self._unit_execs is not None:
            return self._unit_execs
        out = {}
        plen = len(self.col.prefix)
        rootfs = tuple(rd.lower() + "/" for rd in self.col.rootfs_dirs)
        for low, real in self.col._names.items():
            if not low.startswith(self.col.prefix):
                continue
            rel = real[plen:]
            rl = rel.lstrip("/").lower()
            if not rl.startswith(rootfs) or "/systemd/" not in rl:
                continue
            if not rl.endswith((".service", ".socket", ".mount", ".scope")):
                continue
            name = os.path.basename(rel)
            if name in out:
                continue
            for ln in self.col.lines(rel):
                m = re.match(r"^\s*ExecStart\s*=\s*(.*)$", ln)
                if not m:
                    continue
                cmd = m.group(1).strip()
                # strip systemd's '-', '@', '+', '!' exec prefixes
                cmd = cmd.lstrip("-@+!:").strip()
                first = cmd.split()[0] if cmd.split() else ""
                if first.startswith("/"):
                    out[name] = first
                break
        self._unit_execs = out
        return out

    def _fill_exe_from_cgroup(self, procs):
        """A process's cgroup names the unit that started it.

        This is an inference, not an observation: the unit's ExecStart is the
        binary systemd was told to run, and a process can have exec'd something
        else since. It is labelled accordingly, but for a service whose argv[0]
        was rewritten - smbd and inetsim rename themselves - it is the only
        thing left that points at a path on disk.
        """
        units = self.unit_exec_map()
        cg = {}
        for rel in ("live_response/process/ps_-axo_pid_user_cgroup.txt",
                    "live_response/process/ps_-axo_pid_cgroup.txt",
                    "live_response/process/ps_-eo_pid_user_cgroup.txt"):
            for ln in self.col.lines(rel)[1:]:
                f = ln.split()
                if len(f) >= 2 and f[0].isdigit():
                    cg[f[0]] = f[-1]
        for pid, p in procs.items():
            path = cg.get(pid, "")
            if not path or path == "-":
                continue
            p["cgroup"] = path
            # a container's processes are visible from the host PID namespace,
            # but their exe path is inside the container's filesystem - naming
            # the container is the honest answer, not a host path
            m = re.search(r"/(?:docker|libpod|crio)-([0-9a-f]{12,64})\.scope", path)
            if m:
                p["container"] = m.group(1)[:12]
            if p.get("exe"):
                continue
            args = (p.get("args") or "").strip()
            if args.startswith("["):
                continue
            if p.get("container"):
                continue
            for seg in reversed(path.split("/")):
                if seg.endswith((".service", ".socket", ".mount", ".scope")) \
                        and seg in units:
                    p["exe"] = units[seg]
                    p["exe_source"] = "ExecStart of %s via cgroup (inferred)" % seg
                    break

    def _fill_exe_from_lsof(self, procs):
        """lsof names the running binary as the process's 'txt' descriptor."""
        for rel in ("live_response/process/lsof_-nPl.txt",
                    "live_response/process/lsof.txt",
                    "live_response/process/lsof_-nP.txt"):
            if not self.col.exists(rel):
                continue
            for ln in self.col.iter_lines(rel):
                f = ln.split(None, 8)
                if len(f) < 9 or not f[1].isdigit():
                    continue
                pid, fd, name = f[1], f[3], f[8].strip()
                p = procs.setdefault(pid, {})
                if fd == "txt" and not p.get("exe") and name.startswith("/"):
                    # the first txt mapping is the executable; later ones are
                    # the shared libraries it pulled in
                    p["exe"] = name
                    p["exe_source"] = "lsof txt descriptor"
                elif fd == "cwd" and not p.get("cwd") and name.startswith("/"):
                    p["cwd"] = name
                    p["cwd_source"] = "lsof cwd descriptor"

    def _fill_exe_from_maps(self, procs):
        """The first executable mapping in /proc/<pid>/maps is the binary."""
        for rel in self.col.glob("live_response/process/proc/*/maps.txt"):
            pid = rel.split("/")[-2]
            p = procs.setdefault(pid, {})
            if p.get("exe"):
                continue
            for ln in self.col.lines(rel):
                m = re.match(r"^[0-9a-f]+-[0-9a-f]+\s+r.x\S*\s+\S+\s+\S+\s+"
                             r"(\d+)\s+(/\S.*)$", ln)
                if m and m.group(1) != "0":
                    p["exe"] = m.group(2).strip()
                    p["exe_source"] = "first executable mapping in maps"
                    break

    def _fill_exe_from_journal(self, procs):
        """systemd recorded _EXE for anything that logged during this boot."""
        jmap = self.journal_proc_map()
        if not jmap:
            return
        for pid, p in procs.items():
            if p.get("exe"):
                continue
            cands = jmap.get(pid) or []
            if not cands:
                continue
            args = p.get("args", "")
            if args.startswith("[") and args.rstrip().endswith("]"):
                continue                # kernel thread: it has no binary
            hit = next((j for j in cands
                        if self._journal_exe_ok(j.get("comm"), j["exe"], args)),
                       None)
            if hit is None:
                # Every candidate describes a different program than ps saw.
                # Keep the newest rather than dropping it silently: a genuine
                # identity change is worth an analyst's attention.
                p["journal_exe"] = cands[0]["exe"]
                continue
            p["exe"] = hit["exe"]
            p["exe_source"] = "journal _EXE (same boot)"
            if not p.get("args") and hit.get("cmdline"):
                p["args"] = hit["cmdline"]

    def _fill_exe_from_argv(self, procs):
        """argv[0], when the process did not rewrite it, is the path it was run by.

        This is the weakest source and is labelled as such: argv[0] is entirely
        attacker-controlled and need not match the binary actually executing.
        """
        for pid, p in procs.items():
            if p.get("exe"):
                continue
            args = (p.get("args") or "").strip()
            if not args or args.startswith("["):
                continue                # kernel threads have no exe link
            first = args.split()[0]
            if first.startswith("/"):
                p["exe"] = first
                p["exe_source"] = (
                    "argv[0] (self-reported); journal recorded %s for this pid"
                    % p["journal_exe"] if p.get("journal_exe")
                    else "argv[0] (self-reported, unverified)")
                continue
            # daemons that rewrite argv[0] into a status string often still
            # carry their own path further along it, e.g.
            # 'sshd: /usr/sbin/sshd [listener] 0 of 10-100 startups'
            stem = re.split(r"[:\s]", first, maxsplit=1)[0].strip("()")
            for tok in args.split()[1:]:
                if tok.startswith("/") and stem and \
                        os.path.basename(tok).startswith(stem[:8]):
                    p["exe"] = tok
                    p["exe_source"] = "path found in argv (self-reported)"
                    break

    @property
    def process_source(self):
        """What the merged process table was actually read from.

        The findings below cite their artifact, and citing a UAC path on a
        Velociraptor collection would send an analyst looking for a file that
        is not in the evidence. The provenance has to follow the layout for the
        same reason exe_source does.
        """
        if self.col.layout == "velociraptor" and self.col.velo:
            got = self.col.velo.sources(*self.VELO_PROCESS_ARTIFACTS)
            if got:
                return ", ".join(got)
        return "live_response/process/running_processes_full_paths.txt"

    def analyze_processes(self):
        self._parse_process_tables()
        if not self.processes:
            return
        src = self.process_source
        deleted, tmpexec, homeexec, kthread_fake, badown, oddcwd = [], [], [], [], [], []
        # start times per bucket: a process finding is dated by when the
        # processes it names actually started, not by when the collection ran
        starts = defaultdict(list)

        for pid, p in sorted(self.processes.items(), key=lambda kv: int(kv[0])):
            exe = p.get("exe", "")
            args = p.get("args", "")
            esrc = p.get("exe_source", "")
            observed = esrc in self.OBSERVED_EXE_SOURCES
            base_exe = os.path.basename(exe.split(" (deleted)")[0]) if exe else ""
            # the provenance rides along in the evidence: a path the kernel
            # reported and a path the process claimed are not the same evidence
            line = "PID %-7s %-10s %-38s %s%s" % (
                pid, trunc(p.get("user") or p.get("owner") or "?", 10),
                trunc(exe or "(no exe link)", 38), trunc(args, 80),
                "" if observed or not exe else "   [exe from %s]" % esrc)

            if exe.endswith("(deleted)"):
                deleted.append(line)
                starts["deleted"].append(p.get("start"))
                self.ioc(exe.replace(" (deleted)", ""), "running process pid " + pid)
            if exe.startswith(TMPFS_DIRS):
                tmpexec.append(line)
                starts["tmpexec"].append(p.get("start"))
                self.ioc(exe.split(" (deleted)")[0], "running process pid " + pid)
            elif exe.startswith(("/home/", "/root/", "/var/www/", "/srv/")) and \
                    not exe.startswith("/root/uac"):
                homeexec.append(line)
                starts["homeexec"].append(p.get("start"))
            # kernel threads have no exe link; anything in [brackets] that has one is faking it
            if args.startswith("[") and args.rstrip().endswith("]") and exe:
                kthread_fake.append(line)
                starts["kthread_fake"].append(p.get("start"))
            # numeric owner/group means no matching passwd/group entry
            for fld in ("owner", "group"):
                val = p.get(fld)
                if val and val.isdigit():
                    if (fld == "owner" and int(val) not in self.uids) or \
                       (fld == "group" and int(val) not in self.gids):
                        badown.append("%s  (unresolvable %s id %s)" % (line, fld, val))
                        starts["badown"].append(p.get("start"))
                        break
            cwd = p.get("cwd", "")
            if cwd.startswith(TMPFS_DIRS) or cwd.endswith("(deleted)"):
                oddcwd.append("PID %-7s cwd=%s  %s" % (pid, cwd, trunc(args, 70)))
                starts["oddcwd"].append(p.get("start"))
            # Masquerade: process advertises one binary, runs another. Only
            # meaningful when exe was observed independently - if exe was
            # derived from argv[0] the comparison is a tautology and would
            # silently retire the check.
            if exe and args and observed and not args.startswith("["):
                argv0 = args.split()[0]
                b0 = os.path.basename(argv0)
                if b0 and base_exe and b0 != base_exe and not argv0.startswith("(") \
                        and exe.startswith(TMPFS_DIRS + ("/home/", "/var/tmp/")):
                    kthread_fake.append(line + "   [argv0 %s != exe %s]" % (b0, base_exe))
                    starts["kthread_fake"].append(p.get("start"))
            if p.get("start"):
                self.event(p["start"], "Process", "start: pid %s %s (%s)" %
                           (pid, trunc(args or base_exe, 90), p.get("user", "?")),
                           "HIGH" if (exe.startswith(TMPFS_DIRS) or exe.endswith("(deleted)")) else "INFO",
                           src)

        if tmpexec:
            self.add("CRITICAL", "Process", "%d process(es) executing from a world-writable directory" % len(tmpexec),
                     "Binaries under /tmp, /var/tmp, /dev/shm or /run are the standard "
                     "staging location for dropped payloads. Legitimate services do not "
                     "run from these paths.",
                     tmpexec, source=src, mitre="T1059 / T1036 Masquerading",
                     times=starts["tmpexec"])
        if deleted:
            self.add("CRITICAL" if any(d for d in deleted if any(t in d for t in TMPFS_DIRS)) else "HIGH",
                     "Process", "%d process(es) running a deleted binary" % len(deleted),
                     "The on-disk file was unlinked while the process kept running - a "
                     "deliberate anti-forensic pattern. The executable can still be "
                     "recovered from /proc/<pid>/exe on the live host or from the memory "
                     "image in this collection.",
                     deleted, source=src, mitre="T1070.004 Indicator Removal: File Deletion",
                     times=starts["deleted"])
        if kthread_fake:
            self.add("HIGH", "Process", "%d process(es) masquerading as another binary" % len(kthread_fake),
                     "Either a userland process disguised as a kernel thread (kernel "
                     "threads never have an exe link) or argv[0] that does not match the "
                     "real executable.",
                     kthread_fake, source=src, mitre="T1036 Masquerading",
                     times=starts["kthread_fake"])
        if homeexec:
            self.add("MEDIUM", "Process", "%d process(es) executing from a user/web directory" % len(homeexec),
                     evidence=homeexec, source=src, times=starts["homeexec"])
        if badown:
            self.add("HIGH", "Process", "%d process(es) owned by an unresolvable uid/gid" % len(badown),
                     "The numeric id has no entry in /etc/passwd or /etc/group. This is "
                     "typical of a rootkit that filters those files, or of a process "
                     "started by a deleted account.",
                     badown, source=src, mitre="T1564 Hide Artifacts",
                     times=starts["badown"])
        if oddcwd:
            self.add("MEDIUM", "Process", "%d process(es) with a suspicious working directory" % len(oddcwd),
                     evidence=oddcwd, source="live_response/process/ls_-l_proc_pid_cwd.txt",
                     times=starts["oddcwd"])

        # processes started inside the analysis window
        ws = self.window_start()
        if ws:
            recent = [(p["start"], pid, p) for pid, p in self.processes.items()
                      if p.get("start") and p["start"] >= ws]
            recent.sort()
            if recent:
                ev = ["%s  pid %-7s %-10s %s" % (t.strftime("%Y-%m-%d %H:%M:%S"), pid,
                                                 trunc(p.get("user", "?"), 10), trunc(p.get("args", ""), 90))
                      for t, pid, p in recent[-40:]]
                self.add("INFO", "Process",
                         "%d process(es) started within %dh of collection" % (len(recent), self.opts.window),
                         evidence=ev, source=src,
                         times=[t for t, _pid, _p in recent], count=len(recent))

    # -- 6. network ---------------------------------------------------------
    SS_STATES = {"LISTEN", "ESTAB", "TIME-WAIT", "SYN-SENT", "SYN-RECV", "FIN-WAIT-1",
                 "FIN-WAIT-2", "CLOSE-WAIT", "LAST-ACK", "CLOSING", "CLOSED", "UNCONN",
                 "ESTABLISHED"}

    def _parse_ss(self):
        entries = []
        seen = set()
        proc_re = re.compile(r'\("([^"]+)",pid=(\d+),fd=(\d+)\)')
        for src in ("live_response/network/ss_-anp.txt",
                    "live_response/network/ss_-tanp.txt",
                    "live_response/network/ss_-uanp.txt",
                    "live_response/network/ss_-tlnp.txt",
                    "live_response/network/ss_-ulnp.txt"):
            for ln in self.col.lines(src):
                f = ln.split()
                if len(f) < 5:
                    continue
                netid = None
                if f[0] not in self.SS_STATES:
                    if f[0] in ("tcp", "udp", "nl", "u_str", "u_dgr", "u_seq", "raw",
                                "p_raw", "p_dgr", "icmp6", "vsock", "sctp", "Netid"):
                        netid = f.pop(0)
                    else:
                        continue
                if not f or f[0] not in self.SS_STATES:
                    continue
                state = f[0]
                local, peer = (f[3], f[4]) if len(f) >= 5 else ("", "")
                rest = " ".join(f[5:])
                procs = proc_re.findall(rest)
                key = (netid, state, local, peer)
                if key in seen:
                    continue
                seen.add(key)
                entries.append({"netid": netid or ("tcp" if "-t" in src else "?"),
                                "state": state, "local": local, "peer": peer,
                                "procs": procs, "src": src, "raw": ln.strip()})
        self.sockets = entries
        return entries

    def analyze_network(self):
        entries = self._parse_ss()
        orphan_listen, orphan_conn, susp_listen, external, lateral = [], [], [], [], []
        exposed = []
        # ss is a snapshot, so a socket has no time of its own; the process
        # holding it does, and that start time is what dates these findings
        spids = defaultdict(list)

        for e in entries:
            if e["netid"] not in ("tcp", "udp", "?", "sctp"):
                continue
            lhost, lport = split_hostport(e["local"])
            rhost, rport = split_hostport(e["peer"])
            has_proc = bool(e["procs"])
            epids = [q for _n, q, _fd in e["procs"]]
            pdesc = ", ".join("%s(pid %s)" % (n, p) for n, p, _ in e["procs"]) or "NO PROCESS"
            line = "%-6s %-11s %-24s %-24s %s" % (e["netid"], e["state"], e["local"], e["peer"], pdesc)

            if e["state"] == "LISTEN":
                if not has_proc:
                    orphan_listen.append(line)
                if lport in SUSPICIOUS_PORTS:
                    susp_listen.append("%s   [%s]" % (line, SUSPICIOUS_PORTS[lport]))
                    spids["susp"].extend(epids)
                    self.ioc("port:%s" % lport, "listening socket")
                if lhost in ("0.0.0.0", "*", "::") and lport not in (22, 53, 67, 68, 123, 631, 5353):
                    exposed.append(line)
                    spids["exposed"].extend(epids)
            elif e["state"] in ("ESTAB", "ESTABLISHED", "SYN-SENT"):
                if not has_proc:
                    orphan_conn.append(line)
                if rhost and not is_private_ip(rhost):
                    external.append(line)
                    spids["external"].extend(epids)
                    self.ioc(rhost, "network connection")
                if rport in (22, 23, 445, 3389, 5985, 5986) and rhost and rhost not in ("127.0.0.1", "::1"):
                    lateral.append("%s   [outbound to %s/%d]" % (line, rhost, rport))
                    spids["lateral"].extend(epids)
                    self.ioc(rhost, "outbound admin protocol")
                if rport in SUSPICIOUS_PORTS or lport in SUSPICIOUS_PORTS:
                    susp_listen.append("%s   [%s]" % (
                        line, SUSPICIOUS_PORTS.get(rport) or SUSPICIOUS_PORTS.get(lport)))
                    spids["susp"].extend(epids)

        # UAC runs ss several times with different flags, so the same socket
        # arrives once per variant. Counting it once per file inflated every
        # "N socket(s)" headline and printed each line two or three times.
        def uniq(seq):
            out, seen = [], set()
            for s in seq:
                if s not in seen:
                    seen.add(s)
                    out.append(s)
            return out

        orphan_listen = uniq(orphan_listen)
        orphan_conn = uniq(orphan_conn)
        susp_listen = uniq(susp_listen)
        external = uniq(external)
        lateral = uniq(lateral)
        exposed = uniq(exposed)

        srcn = "live_response/network/ss_-anp.txt"
        if orphan_listen:
            self.add("CRITICAL", "Network",
                     "%d listening socket(s) with no owning process" % len(orphan_listen),
                     "ss could not attribute these listeners to any PID. Running as root, "
                     "that should not happen - it means the owning process is hidden from "
                     "/proc enumeration. A listening port with no visible owner is a "
                     "backdoor until proven otherwise.",
                     orphan_listen, source=srcn, mitre="T1564 Hide Artifacts / T1571")
        if orphan_conn:
            self.add("CRITICAL", "Network",
                     "%d established connection(s) with no owning process" % len(orphan_conn),
                     "Active sessions that cannot be attributed to a visible process - "
                     "same hiding mechanism as above, and these show the live C2 or "
                     "lateral-movement channel.",
                     orphan_conn, source=srcn, mitre="T1564 / T1071")
        if susp_listen:
            self.add("HIGH", "Network", "Socket(s) on ports associated with implants",
                     evidence=susp_listen, source=srcn, mitre="T1571 Non-Standard Port",
                     times=self.proc_times(spids["susp"]))
        if lateral:
            self.add("HIGH", "Network", "Outbound administrative protocol session(s)",
                     "Connections leaving this host towards SSH/RDP/SMB/WinRM on another "
                     "system - the shape of hands-on lateral movement.",
                     lateral, source=srcn, mitre="T1021 Remote Services",
                     times=self.proc_times(spids["lateral"]))
        if external:
            self.add("MEDIUM", "Network", "%d connection(s) to non-RFC1918 addresses" % len(external),
                     evidence=external[:40], source=srcn, mitre="T1071 Application Layer Protocol",
                     times=self.proc_times(spids["external"]), count=len(external))
        if exposed:
            self.add("LOW", "Network", "Service(s) listening on all interfaces",
                     evidence=exposed, source=srcn,
                     times=self.proc_times(spids["exposed"]))

        self._analyze_proc_net()
        self._analyze_link_state()

    def _analyze_proc_net(self):
        """Compare raw /proc/net tables against ss output; decode both."""
        # ss and /proc/net spell the same socket differently ('*' vs 0.0.0.0,
        # compressed vs expanded IPv6), so compare canonical endpoints only.
        ss_full, ss_local = set(), set()
        for e in self.sockets:
            lh, lp = split_hostport(e["local"])
            rh, rp = split_hostport(e["peer"])
            ss_full.add((lh, lp, rh, rp))
            ss_local.add((lh, lp))

        hidden = []
        inode_map = {}
        for src, proto in (("live_response/network/proc_net_tcp.txt", "tcp"),
                           ("live_response/network/proc_net_tcp6.txt", "tcp6"),
                           ("live_response/network/proc_net_udp.txt", "udp"),
                           ("live_response/network/proc_net_udp6.txt", "udp6")):
            for ln in self.col.lines(src)[1:]:
                f = ln.split()
                if len(f) < 10 or ":" not in f[1]:
                    continue
                lh_hex, lp_hex = f[1].split(":")
                rh_hex, rp_hex = f[2].split(":")
                lh, lp = norm_ip(hexip_to_str(lh_hex)), int(lp_hex, 16)
                rh, rp = norm_ip(hexip_to_str(rh_hex)), int(rp_hex, 16)
                st = f[3]
                uid, inode = f[7], f[9]
                inode_map[inode] = (proto, lh, lp, rh, rp, st, uid)
                listening = (st == "0A" or rp == 0)
                known = ((lh, lp) in ss_local) if listening else ((lh, lp, rh, rp) in ss_full)
                if not known:
                    hidden.append("%-5s %s:%d -> %s:%d state=%s uid=%s inode=%s"
                                  % (proto, lh, lp, rh, rp, st, uid, inode))
        if hidden:
            self.add("HIGH", "Network",
                     "%d socket(s) in /proc/net not reported by ss" % len(hidden),
                     "The kernel's own socket table lists connections that the userland "
                     "tool did not print - a strong indicator that ss/netstat or the "
                     "libc it links against is hooked.",
                     hidden[:40], source="live_response/network/proc_net_tcp.txt",
                     mitre="T1564 Hide Artifacts", count=len(hidden))

        # try to attribute orphan sockets by socket inode via lsof
        if inode_map:
            want = {}
            for e in self.sockets:
                if e["procs"]:
                    continue
                lh, lp = split_hostport(e["local"])
                for ino, (proto, ilh, ilp, irh, irp, st, uid) in inode_map.items():
                    if ilh == lh and ilp == lp:
                        want[ino] = (e["local"], e["peer"])
            if want:
                hits = []
                pat = re.compile(r"\b(%s)\b" % "|".join(re.escape(i) for i in list(want)[:200]))
                for ln in self.col.iter_lines("live_response/process/lsof_-nPl.txt"):
                    if pat.search(ln):
                        hits.append(trunc(ln, 200))
                if hits:
                    self.add("HIGH", "Network", "Owner recovered for unattributed socket(s) via lsof inode",
                             "Matching the socket inode from /proc/net against lsof output "
                             "identifies the process ss refused to name.",
                             hits[:20], source="live_response/process/lsof_-nPl.txt",
                             count=len(hits))

    def _analyze_link_state(self):
        src = "live_response/network/ip_link_show.txt"
        for ln in self.col.lines(src):
            if "PROMISC" in ln:
                self.add("HIGH", "Network", "Interface in promiscuous mode",
                         "Promiscuous mode is set by packet sniffers.",
                         [ln.strip()], source=src, mitre="T1040 Network Sniffing")

    # -- 7. suid / sgid / capabilities --------------------------------------
    def analyze_suid_sgid(self):
        for src, kind in (("system/suid.txt", "SUID"), ("system/sgid.txt", "SGID")):
            paths = [ln.strip() for ln in self.col.lines(src) if ln.strip().startswith("/")]
            if not paths:
                continue
            critical, unusual = [], []
            for p in paths:
                name = os.path.basename(p)
                if p.startswith(TMPFS_DIRS + ("/home/", "/srv/", "/var/www/", "/opt/")):
                    critical.append("%s   [in a writable / non-system location]" % p)
                    self.ioc(p, kind.lower())
                elif name in DANGEROUS_SUID_NAMES:
                    critical.append("%s   [%s must never be %s]" % (p, name, kind))
                    self.ioc(p, kind.lower())
                elif p not in BASELINE_SUID:
                    unusual.append(p)
            if critical:
                self.add("CRITICAL", "Privilege", "%s binary that grants a root shell" % kind,
                         "A shell, interpreter or file utility carrying the %s bit is a "
                         "ready-made privilege escalation path and a common backdoor left "
                         "behind after a compromise." % kind,
                         critical, source=src, mitre="T1548.001 Setuid and Setgid")
            if unusual:
                self.add("MEDIUM", "Privilege", "%d %s binar(ies) outside the common distro baseline" % (len(unusual), kind),
                         "Not necessarily malicious - vendor agents and some desktop "
                         "packages ship extra %s files - but each should be accounted for." % kind,
                         unusual, source=src, mitre="T1548.001")
            if not critical and not unusual:
                self.add("INFO", "Privilege",
                         "%d %s binar(ies), all matching the expected distro baseline" % (len(paths), kind),
                         evidence=paths, source=src)

        src = "system/getcap.txt"
        caps = [ln.strip() for ln in self.col.lines(src) if ln.strip()]
        risky = [c for c in caps if re.search(r"cap_(sys_admin|sys_ptrace|sys_module|dac_read_search|dac_override|setuid|setgid|sys_rawio|net_raw)", c)]
        if risky:
            self.add("MEDIUM", "Privilege", "File capabilities that enable privilege escalation",
                     evidence=risky, source=src, mitre="T1548 Abuse Elevation Control")
        elif caps:
            self.add("INFO", "Privilege", "%d file(s) with capabilities" % len(caps),
                     evidence=caps[:20], source=src)

    # -- 8. accounts --------------------------------------------------------
    def analyze_accounts(self):
        rel = self.col.rootfs("/etc/passwd")
        if rel:
            uid0, sysshell = [], []
            seen_uid = defaultdict(list)
            for ln in self.col.lines(rel):
                f = ln.split(":")
                if len(f) < 7:
                    continue
                name, _pw, uid, gid, gecos, home, shell = f[:7]
                self.users[name] = {"uid": uid, "gid": gid, "home": home, "shell": shell,
                                    "gecos": gecos}
                try:
                    self.uids[int(uid)] = name
                except ValueError:
                    pass
                seen_uid[uid].append(name)
                if uid == "0" and name != "root":
                    uid0.append(ln)
                try:
                    if 0 < int(uid) < 1000 and not re.search(
                            r"(nologin|/bin/false|/bin/sync|/usr/sbin/shutdown|/bin/halt)$", shell):
                        sysshell.append(ln)
                except ValueError:
                    pass
            if uid0:
                self.add("CRITICAL", "Account", "Non-root account(s) with uid 0",
                         "A second uid-0 entry is root access hidden in plain sight.",
                         uid0, source=rel, mitre="T1136 Create Account")
            dupes = ["uid %s shared by: %s" % (u, ", ".join(n)) for u, n in seen_uid.items() if len(n) > 1]
            if dupes:
                self.add("HIGH", "Account", "Duplicate uid(s) in /etc/passwd",
                         evidence=dupes, source=rel, mitre="T1136")
            if sysshell:
                self.add("MEDIUM", "Account", "System account(s) with an interactive shell",
                         "Service accounts normally have nologin/false. An interactive "
                         "shell on a low uid is a quiet persistence trick.",
                         sysshell, source=rel, mitre="T1136")

            # diff against the /etc/passwd- backup to spot recently added accounts
            relb = self.col.rootfs("/etc/passwd-")
            if relb:
                old = {ln.split(":")[0] for ln in self.col.lines(relb) if ":" in ln}
                new = [n for n in self.users if n not in old]
                if new:
                    self.add("MEDIUM", "Account", "Account(s) present in /etc/passwd but not in the backup copy",
                             "/etc/passwd- is the previous version written on the last "
                             "account change; names appearing only in the live file were "
                             "added most recently. Package installs create service accounts "
                             "this way too, so check the name against the software inventory "
                             "before treating it as attacker activity.",
                             ["%s:%s" % (n, self.users[n]["uid"]) for n in new],
                             source=rel, mitre="T1136 Create Account")

        rel = self.col.rootfs("/etc/group")
        if rel:
            priv = []
            for ln in self.col.lines(rel):
                f = ln.split(":")
                if len(f) < 4:
                    continue
                self.groups[f[0]] = (f[2], f[3])
                try:
                    self.gids.add(int(f[2]))
                except ValueError:
                    pass
                if f[0] in PRIVILEGED_GROUPS and f[3].strip():
                    priv.append(ln)
            if priv:
                self.add("MEDIUM", "Account", "Membership of privileged groups",
                         "sudo/wheel/docker/lxd/disk/shadow membership is equivalent to "
                         "root on most systems - confirm every member is expected.",
                         priv, source=rel, mitre="T1098 Account Manipulation")

        rel = self.col.rootfs("/etc/shadow")
        if rel:
            empty, recent, recent_ts = [], [], []
            for ln in self.col.lines(rel):
                f = ln.split(":")
                if len(f) < 3:
                    continue
                name, pw, lastchg = f[0], f[1], f[2]
                if pw == "":
                    empty.append("%s has an EMPTY password" % name)
                elif pw.startswith("$") and lastchg.isdigit() and self.collection_time:
                    changed = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(days=int(lastchg))
                    if (self.collection_time - changed).days <= max(7, self.opts.window // 24):
                        recent.append("%s password last changed %s" % (name, changed.strftime("%Y-%m-%d")))
                        recent_ts.append(changed)
                        self.event(changed, "Account", "password changed for %s" % name, "MEDIUM", rel)
            if empty:
                self.add("CRITICAL", "Account", "Account(s) with an empty password hash",
                         evidence=empty, source=rel, mitre="T1098")
            if recent:
                self.add("MEDIUM", "Account", "Password change(s) close to the incident window",
                         evidence=recent, source=rel, mitre="T1098", times=recent_ts)

        # sudoers
        sudo_files = [self.col.rootfs("/etc/sudoers")] + self.col.rootfs_glob("/etc/sudoers.d/*")
        for rel in [s for s in sudo_files if s]:
            for ln in self.col.lines(rel):
                s = ln.strip()
                if not s or s.startswith("#"):
                    continue
                if re.search(r"NOPASSWD\s*:\s*(ALL|/)", s) or "!authenticate" in s:
                    sev = "HIGH" if "ALL" in s.upper() else "MEDIUM"
                    self.add(sev, "Privilege", "Passwordless sudo rule",
                             "Anyone matching this rule escalates to root without a "
                             "password prompt.",
                             ["%s: %s" % (self.col.host_path(rel), s)], source=rel,
                             mitre="T1548.003 Sudo and Sudo Caching")

        # authorized_keys anywhere in the collection
        keyfiles = []
        for pat in ("**/.ssh/authorized_keys", "**/.ssh/authorized_keys2",
                    "**/authorized_keys", "**/etc/ssh/authorized_keys*"):
            keyfiles.extend(self.col.glob(pat))
        keyfiles = sorted(set(keyfiles))
        if keyfiles:
            ev = []
            for rel in keyfiles:
                host = self.col.host_path(rel)
                for ln in self.col.lines(rel):
                    if ln.strip() and not ln.strip().startswith("#"):
                        parts = ln.split()
                        comment = parts[-1] if len(parts) > 2 else "(no comment)"
                        ktype = parts[0] if parts else "?"
                        ev.append("%s : %s ... %s" % (host, ktype, comment))
                        self.ioc(comment, "authorized_keys")
            if ev:
                self.add("HIGH", "Persistence", "SSH authorized_keys entries present",
                         "Each key is standing remote access. Verify every entry against "
                         "the expected administrators, especially keys in root's home.",
                         ev, source=keyfiles[0], mitre="T1098.004 SSH Authorized Keys")

    # -- 9. logins ----------------------------------------------------------
    # 'last -F' dates a row as 'Wed Aug 13 10:04:11 2026'; the plain 'last'
    # format drops the year and the seconds, and there is no honest way to
    # date those rows, so they simply carry no time.
    LAST_TS_RE = re.compile(r"\w{3}\s+\w{3}\s+\d{1,2}\s+\d\d:\d\d:\d\d(?:\s+\w+)?\s+\d{4}")

    def last_row_time(self, line):
        """Login instant out of a `last -F` row, normalised to UTC, or ''."""
        m = self.LAST_TS_RE.search(line)
        return norm_log_ts(m.group(0), self.tz_offset) if m else ""

    def analyze_logins(self):
        ext, roots, reboots, allrows = [], [], [], []
        src_used = ""
        for src in ("live_response/system/last_-a_-F.txt", "live_response/system/last_-i.txt",
                    "live_response/system/last.txt"):
            rows = [ln for ln in self.col.lines(src) if ln.strip() and not ln.startswith("wtmp begins")]
            if not rows:
                continue
            src_used = src
            for ln in rows:
                allrows.append(ln.strip())
                f = ln.split()
                if not f:
                    continue
                user = f[0]
                ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", ln)
                if user == "reboot":
                    reboots.append(ln.strip())
                    continue
                for ip in ips:
                    if not is_private_ip(ip):
                        ext.append(ln.strip())
                        self.ioc(ip, "interactive login")
                if user == "root" and ips:
                    roots.append(ln.strip())
            break

        if ext:
            uniq_ext = sorted(set(ext))
            self.add("HIGH", "Authentication", "Interactive login(s) from a public IP address",
                     evidence=uniq_ext[:40], source=src_used,
                     mitre="T1078 Valid Accounts / T1021.004 SSH",
                     times=[self.last_row_time(r) for r in uniq_ext],
                     count=len(uniq_ext))
        if roots:
            uniq_roots = sorted(set(roots))
            self.add("MEDIUM", "Authentication", "Remote root login(s) recorded",
                     "Direct root logins bypass the sudo audit trail.",
                     uniq_roots[:30], source=src_used, mitre="T1078",
                     times=[self.last_row_time(r) for r in uniq_roots],
                     count=len(uniq_roots))
        if allrows:
            still = [r for r in allrows if "still logged in" in r or "still running" in r]
            self.add("INFO", "Authentication", "%d session record(s) in wtmp" % len(allrows),
                     "Active sessions at collection time are listed first.",
                     (still + allrows[:25]), source=src_used,
                     times=[self.last_row_time(r) for r in allrows],
                     count=len(allrows))
        if reboots:
            crashes = [r for r in reboots if "crash" in r]
            if crashes:
                self.add("LOW", "System", "%d boot(s) ended without a clean shutdown" % len(crashes),
                         "Unclean shutdowns can be routine, or can mark a kernel module "
                         "load gone wrong or a deliberate reboot to load an implant.",
                         crashes[:15], source=src_used,
                         times=[self.last_row_time(r) for r in crashes],
                         count=len(crashes))

        self.analyze_failed_logins()

        for rel in self.col.glob("live_response/system/loginctl*"):
            txt = self.col.text(rel)
            if txt and txt.strip():
                self.add("INFO", "Authentication", "logind session detail: %s" % os.path.basename(rel),
                         evidence=[trunc(l, 160) for l in txt.splitlines()[:20]], source=rel,
                         count=len(txt.splitlines()))

        who = [l for l in self.col.lines("live_response/system/who_-T.txt") if l.strip()]
        if who:
            self.add("INFO", "Authentication", "Users logged in at collection time",
                     evidence=who, source="live_response/system/who_-T.txt")

    BRUTE_FORCE_THRESHOLD = 10        # failures from one source before it counts
    SPRAY_USER_THRESHOLD = 5          # distinct accounts one source tried

    def collect_failed_logins(self):
        """(ts, kind, user, ip, service, origin) for every failed auth found.

        Reads btmp, auth.log/secure and the journal. Deliberately not auditd or
        faillog: those duplicate the same attempts, and a count that mixes
        sources overstates how much actually happened.
        """
        out = []
        for rel in self.col.rootfs_glob("/var/log/btmp*"):
            raw = decompress_bytes(rel, self.col.read_bytes(rel))
            if not raw:
                continue
            for r in parse_utmp(raw):
                out.append((r["time"], "failed login", r["user"],
                            r["ip"] or r["host"], "btmp", "btmp"))
        rx = re.compile(r"^(\w{3}\s+\d+\s+[\d:]+|\S+T\S+|\d{4}-\d\d-\d\d \S+)\s+"
                        r"(\S+)\s+([^\s:]+?)(?:\[(\d+)\])?:\s*(.*)$")
        for pat in ("/var/log/auth.log*", "/var/log/secure*"):
            for rel in self.col.rootfs_glob(pat):
                raw = decompress_bytes(rel, self.col.read_bytes(rel))
                if raw is None:
                    continue
                for ln in raw.decode("utf-8", "replace").splitlines():
                    m = rx.match(ln)
                    if not m:
                        continue
                    raw_ts, _h, proc, _pid, msg = m.groups()
                    hit = match_failed_login(proc, msg)
                    if not hit:
                        continue
                    kind, user, ip, _port, _meth, _detail = hit
                    if not ip:
                        rm = re.search(r"\brhost=([^\s]+)", msg)
                        ip = rm.group(1) if rm and rm.group(1) != "-" else ""
                    if not user:
                        um = re.search(r"\buser=([^\s]+)", msg)
                        user = um.group(1) if um else ""
                    out.append((self._parse_any_ts(raw_ts), kind, user, ip,
                                proc, "auth.log"))
        for ts, ident, msg, _hn, _tty, _src in self.journal_scan()["events"]:
            hit = match_failed_login(ident, msg)
            if not hit:
                continue
            kind, user, ip, _port, _meth, _detail = hit
            if not ip:
                rm = re.search(r"\brhost=([^\s]+)", msg)
                ip = rm.group(1) if rm and rm.group(1) != "-" else ""
            if not user:
                um = re.search(r"\buser=([^\s]+)", msg)
                user = um.group(1) if um else ""
            # journal_scan already formatted __REALTIME as UTC, so this one
            # is read as-is. Passing it through _parse_any_ts subtracted the
            # host offset a second time, which put every journal-sourced
            # failure a full offset late - four hours, and past the end of the
            # collection, on a host at UTC-04:00. The auth.log branch above is
            # the opposite case: that text really is the host's local clock.
            out.append((self._utc_ts(ts), kind, user, ip, ident,
                        "journal"))
        return out

    @staticmethod
    def _utc_ts(text):
        """An already-normalised 'YYYY-MM-DD HH:MM:SS' UTC string -> datetime.

        The counterpart to _parse_any_ts, for sources that did their own
        normalisation. Which of the two a caller wants is a property of the
        artifact, not of the string, so it cannot be decided here.
        """
        try:
            return datetime.strptime(str(text)[:19], "%Y-%m-%d %H:%M:%S").replace(
                tzinfo=timezone.utc)
        except (TypeError, ValueError):
            return None

    def _parse_any_ts(self, text):
        """Log timestamp -> datetime, using the collection's own clock rules.

        For host-local text - syslog, auth.log, secure - where the stamp has to
        be moved onto UTC. A source that already normalised its own timestamps
        wants _utc_ts instead.
        """
        ct = self.collection_time
        s = norm_log_ts(text, self.tz_offset, ct.year if ct else None)
        if not s:
            return None
        try:
            return datetime.strptime(s, "%Y-%m-%d %H:%M:%S").replace(
                tzinfo=timezone.utc)
        except ValueError:
            return None

    def analyze_failed_logins(self):
        """FOR577: 'Check for large numbers of failed logins'."""
        rows = self.collect_failed_logins()
        if not rows:
            return
        by_ip = defaultdict(list)
        by_user = defaultdict(list)
        for ts, kind, user, ip, svc, origin in rows:
            if ip and ip not in ("-", "?"):
                by_ip[ip].append((ts, user, kind, svc, origin))
            if user:
                by_user[user].append((ts, ip, kind, svc, origin))

        # a source that failed many times, and one that tried many accounts
        brute, spray = [], []
        brute_ts, spray_ts = [], []
        for ip, hits in sorted(by_ip.items(), key=lambda kv: -len(kv[1])):
            users = {u for _t, u, _k, _s, _o in hits if u}
            times = sorted(t for t, *_ in hits if t)
            span = ("%s .. %s" % (times[0].strftime("%Y-%m-%d %H:%M:%S"),
                                  times[-1].strftime("%Y-%m-%d %H:%M:%S"))
                    if times else "no timestamps")
            line = ("%-40s %5d failure(s) against %d account(s): %s   [%s]"
                    % (ip, len(hits), len(users),
                       trunc(", ".join(sorted(users)) or "(unnamed)", 60), span))
            if len(hits) >= self.BRUTE_FORCE_THRESHOLD:
                brute.append(line)
                brute_ts.extend(times)
                self.ioc(ip, "failed authentication source")
            if len(users) >= self.SPRAY_USER_THRESHOLD:
                spray.append(line)
                spray_ts.extend(times)
                self.ioc(ip, "password spraying source")
            for t, *_ in hits:
                if t:
                    self.event(t, "Authentication",
                               "failed authentication from %s" % ip,
                               "MEDIUM", "failed login records")

        if brute:
            worst = max(len(v) for v in by_ip.values())
            self.add("HIGH" if worst >= 50 else "MEDIUM", "Authentication",
                     "%d source address(es) with %d+ failed logins"
                     % (len(brute), self.BRUTE_FORCE_THRESHOLD),
                     "Repeated authentication failure from one address is "
                     "password guessing. Check whether any of these addresses "
                     "later appears in a successful login - that is the "
                     "difference between a failed attack and a breach.",
                     brute[:30], source="/var/log/btmp, auth.log, journal",
                     mitre="T1110 Brute Force", times=brute_ts,
                     count=sum(len(v) for ip, v in by_ip.items()
                               if len(v) >= self.BRUTE_FORCE_THRESHOLD))
        if spray:
            self.add("HIGH", "Authentication",
                     "%d source address(es) tried %d+ different accounts"
                     % (len(spray), self.SPRAY_USER_THRESHOLD),
                     "One source enumerating many usernames is password "
                     "spraying or account enumeration rather than a forgotten "
                     "password.",
                     spray[:30], source="/var/log/btmp, auth.log, journal",
                     mitre="T1110.003 Password Spraying", times=spray_ts,
                     count=sum(len(v) for ip, v in by_ip.items()
                               if len({u for _t, u, _k, _s, _o in v if u})
                               >= self.SPRAY_USER_THRESHOLD))

        # the finding that matters: an address that failed, then got in
        succeeded = {}
        for ts, ident, msg, _hn, _tty, _src in self.journal_scan()["events"]:
            m = ACCEPTED_LOGIN_RE.search(msg)
            if m:
                succeeded.setdefault(m.group("ip"), []).append(
                    "%s %s as %s" % (ts, m.group("method"), m.group("user")))
        for pat in ("/var/log/auth.log*", "/var/log/secure*"):
            for rel in self.col.rootfs_glob(pat):
                raw = decompress_bytes(rel, self.col.read_bytes(rel))
                if raw is None:
                    continue
                for ln in raw.decode("utf-8", "replace").splitlines():
                    m = ACCEPTED_LOGIN_RE.search(ln)
                    if m:
                        succeeded.setdefault(m.group("ip"), []).append(
                            trunc(ln.strip(), 160))
        both = [ip for ip in by_ip if ip in succeeded]
        if both:
            ev = []
            for ip in sorted(both, key=lambda i: -len(by_ip[i])):
                ev.append("%s: %d failure(s) then SUCCESS - %s"
                          % (ip, len(by_ip[ip]),
                             trunc(succeeded[ip][0], 120)))
            self.add("CRITICAL", "Authentication",
                     "%d address(es) authenticated successfully after failing"
                     % len(both),
                     "An address that guessed wrong and then got it right is "
                     "the signature of a successful credential attack. Every "
                     "account named here needs its session activity reviewed "
                     "and its credentials rotated.",
                     ev[:25], source="/var/log/btmp, auth.log, journal",
                     mitre="T1110 Brute Force / T1078 Valid Accounts",
                     times=[t for ip in both for t, *_ in by_ip[ip]],
                     count=len(both))

        top_users = sorted(by_user.items(), key=lambda kv: -len(kv[1]))[:15]
        self.add("INFO", "Authentication",
                 "%d failed authentication record(s) across %d source address(es)"
                 % (len(rows), len(by_ip)),
                 "Counted from btmp, auth.log and the journal. The FAILED_LOGINS "
                 "table has one row per attempt with the source of each.",
                 ["%-24s %d failure(s)" % (u, len(v)) for u, v in top_users],
                 source="/var/log/btmp, auth.log, journal",
                 times=[t for t, *_ in rows], count=len(rows))

    # -- 10. shell history & anti-forensics ---------------------------------
    # A history file is undated by default, but two shells do record time and
    # both are worth reading: bash with HISTTIMEFORMAT set writes a '#<epoch>'
    # comment before each command, and zsh's extended history writes
    # ': <epoch>:<elapsed>;<command>'. The stamp applies to the commands that
    # follow it, so it is carried forward until the next one.
    ZSH_HIST_RE = re.compile(r"^:\s*(\d{9,10}):\d+;(.*)$")

    HISTORY_GLOBS = ["**/.bash_history", "**/.sh_history", "**/.zsh_history", "**/.ksh_history",
                     "**/.history", "**/.python_history", "**/.mysql_history", "**/.psql_history",
                     "**/.node_repl_history", "**/.rediscli_history", "**/.lesshst", "**/.viminfo"]

    def analyze_history(self):
        found = []
        for pat in self.HISTORY_GLOBS:
            found.extend(self.col.glob(pat))
        found = sorted(set(found))
        hits = []
        for rel in found:
            host = self.col.host_path(rel)
            lines = self.col.lines(rel)
            if not lines:
                continue
            stamp = ""
            for ln in lines:
                s = ln.strip()
                if not s:
                    continue
                if s.startswith("#"):
                    if s[1:].strip().isdigit():
                        stamp = _ts_text(int(s[1:].strip())) or stamp
                    continue
                m = self.ZSH_HIST_RE.match(s)
                if m:
                    stamp = _ts_text(int(m.group(1))) or stamp
                    s = m.group(2).strip()
                    if not s:
                        continue
                for rx, desc, sev in COMPILED_CMD_PATTERNS:
                    if rx.search(s):
                        hits.append((sev, "%s: %s   [%s]" % (host, trunc(s, 140), desc),
                                     stamp))
                        break
        if hits:
            worst = min(hits, key=lambda h: SEV_RANK[h[0]])[0]
            self.add(worst, "Execution", "Suspicious commands in shell history",
                     "Commands recovered from user history files that match attacker "
                     "tradecraft. History is attacker-controlled - absence proves nothing, "
                     "presence is strong evidence.",
                     [h[1] for h in sorted(hits, key=lambda h: SEV_RANK[h[0]])][:60],
                     source=found[0], mitre="T1059 Command and Scripting Interpreter",
                     times=[h[2] for h in hits], count=len(hits))

        # history that should exist but does not - classic clean-up
        interactive = []
        for name, u in self.users.items():
            if re.search(r"(bash|zsh|sh|ksh)$", u.get("shell", "")) and u.get("home", "").startswith(("/home", "/root")):
                interactive.append((name, u["home"]))
        missing = []
        for name, home in interactive:
            hp = home.rstrip("/") + "/.bash_history"
            rel = self.col.rootfs(hp)
            if rel is None:
                missing.append("%s (%s) - no .bash_history collected" % (name, hp))
            elif self.col.size(rel) == 0:
                missing.append("%s (%s) - .bash_history is 0 bytes" % (name, hp))
        if missing:
            self.add("MEDIUM", "Anti-forensics", "Shell history missing or empty for interactive user(s)",
                     "An interactive account that logged in but left no history is "
                     "consistent with `history -c`, HISTFILE=/dev/null, or the file being "
                     "deleted. It can also simply mean the shell has not exited yet - "
                     "correlate with the login records.",
                     missing, source="[root]/home", mitre="T1070.003 Clear Command History")

    # -- 11. persistence ----------------------------------------------------
    def _scan_content(self, rel, label=None):
        """Scan one collected file for attacker command patterns.

        Returns (severity, evidence_line) pairs so the caller can decide how to
        group and rank them.
        """
        lines = self.col.lines(rel)
        if not lines:
            return []
        host = label or self.col.host_path(rel)
        out = []
        for ln in lines:
            s = ln.strip()
            if not s or s.startswith("#"):
                continue
            for rx, desc, sev in COMPILED_CMD_PATTERNS:
                if rx.search(s):
                    out.append((sev, "%s: %s   [%s]" % (host, trunc(s, 150), desc)))
                    break
        return out

    def analyze_persistence(self):
        # --- cron -----------------------------------------------------------
        cron_targets = []
        for pat in ("/etc/crontab", "/etc/anacrontab", "/etc/cron.d/*", "/etc/cron.hourly/*",
                    "/etc/cron.daily/*", "/etc/cron.weekly/*", "/etc/cron.monthly/*",
                    "/var/spool/cron/crontabs/*", "/var/spool/cron/*", "/etc/at.allow",
                    "/var/spool/at/*"):
            cron_targets.extend(self.col.rootfs_glob(pat))
        hits, listing = [], []
        for rel in sorted(set(cron_targets)):
            if rel.endswith((".placeholder", "/README")):
                continue
            listing.append(self.col.host_path(rel))
            hits.extend(self._scan_content(rel))
        if hits:
            worst = min(hits, key=lambda h: SEV_RANK[h[0]])[0]
            self.add(worst, "Persistence", "Suspicious content in scheduled task definitions",
                     evidence=[h[1] for h in sorted(hits, key=lambda h: SEV_RANK[h[0]])][:40],
                     source="[root]/etc/cron*", mitre="T1053.003 Scheduled Task: Cron",
                     count=len(hits))
        if listing:
            self.add("INFO", "Persistence", "%d cron/at definition file(s) collected" % len(listing),
                     evidence=listing[:60], source="[root]/etc/cron*", count=len(listing))

        # user crontabs are the ones attackers actually use
        for rel in self.col.rootfs_glob("/var/spool/cron/crontabs/*"):
            body = [l for l in self.col.lines(rel) if l.strip() and not l.strip().startswith("#")]
            if body:
                self.add("MEDIUM", "Persistence", "User crontab: %s" % os.path.basename(rel),
                         evidence=[trunc(b, 160) for b in body[:25]], source=rel,
                         mitre="T1053.003 Scheduled Task: Cron", count=len(body))

        # --- systemd --------------------------------------------------------
        unit_hits, custom_units, enabled_links = [], [], []
        unit_files = []
        for pat in ("/etc/systemd/system/*.service", "/etc/systemd/system/*.timer",
                    "/etc/systemd/system/*/*.service", "/etc/systemd/system/*/*.timer",
                    "/etc/systemd/user/*.service", "/usr/local/lib/systemd/system/*",
                    "/run/systemd/system/*.service", "/run/systemd/transient/*",
                    # units under /etc are usually enable-symlinks collected as empty
                    # files; the definitions that actually run live here
                    "/usr/lib/systemd/system/*.service", "/usr/lib/systemd/system/*.timer",
                    "/lib/systemd/system/*.service", "/lib/systemd/system/*.timer"):
            unit_files.extend(self.col.rootfs_glob(pat))
        for pat in ("**/.config/systemd/user/*.service", "**/.config/systemd/user/*.timer"):
            unit_files.extend(self.col.glob(pat))
        for rel in sorted(set(unit_files)):
            host = self.col.host_path(rel)
            body = self.col.lines(rel)
            execs = [l.strip() for l in body if re.match(r"\s*Exec(Start|StartPre|StopPost|Reload)\s*=", l)]
            for e in execs:
                cmd = e.split("=", 1)[1].strip().lstrip("-@+!")
                path = cmd.split()[0] if cmd.split() else ""
                if path.startswith(TMPFS_DIRS) or path.startswith(("/home/", "/srv/", "/var/www/")):
                    unit_hits.append(("CRITICAL", "%s: %s" % (host, trunc(e, 150))))
                    self.ioc(path, "systemd unit %s" % host)
                for rx, desc, sev in COMPILED_CMD_PATTERNS:
                    if rx.search(e):
                        unit_hits.append((sev, "%s: %s   [%s]" % (host, trunc(e, 150), desc)))
                        break
            if host.startswith("/etc/systemd/system/"):
                if execs:
                    custom_units.append("%s -> %s" % (host, trunc(execs[0], 110)))
                elif not body:
                    enabled_links.append(host)
        if unit_hits:
            worst = min(unit_hits, key=lambda h: SEV_RANK[h[0]])[0]
            self.add(worst, "Persistence", "Suspicious systemd unit definition(s)",
                     evidence=[h[1] for h in sorted(unit_hits, key=lambda h: SEV_RANK[h[0]])][:40],
                     source="[root]/etc/systemd/system", mitre="T1543.002 Systemd Service",
                     count=len(unit_hits))
        if custom_units:
            self.add("MEDIUM", "Persistence", "%d locally-defined systemd unit(s) in /etc/systemd/system" % len(custom_units),
                     "Units under /etc (as opposed to /usr/lib) were installed locally - "
                     "by an administrator, a third-party package, or an intruder. Each "
                     "one deserves an explanation.",
                     custom_units[:40], source="[root]/etc/systemd/system",
                     mitre="T1543.002 Create or Modify System Process: Systemd Service",
                     count=len(custom_units))
        if enabled_links:
            self.add("INFO", "Persistence",
                     "%d unit(s) enabled via symlink in /etc/systemd/system" % len(enabled_links),
                     "Collected as empty files because they are enable-symlinks; the unit "
                     "bodies were read from /usr/lib/systemd/system instead. The list shows "
                     "what is set to start on this host.",
                     enabled_links[:50], source="[root]/etc/systemd/system",
                     count=len(enabled_links))

        # timers as they were actually scheduled
        src = "live_response/system/systemctl_list-timers_--all.txt"
        rows = [l for l in self.col.lines(src) if l.strip()]
        if len(rows) > 1:
            self.add("INFO", "Persistence", "systemd timers", evidence=rows[:30], source=src,
                     count=len(rows) - 1)          # the first row is the header

        # --- init / profile / autostart / udev ------------------------------
        other = []
        for pat, mitre, sev in (
                ("/etc/rc.local", "T1037.004 RC Scripts", "MEDIUM"),
                ("/etc/init.d/*", "T1037 Boot or Logon Initialization Scripts", "MEDIUM"),
                ("/etc/profile", "T1546.004 Unix Shell Configuration Modification", "HIGH"),
                ("/etc/profile.d/*", "T1546.004", "HIGH"),
                ("/etc/bash.bashrc", "T1546.004", "HIGH"),
                ("/etc/bashrc", "T1546.004", "HIGH"),
                ("/etc/xdg/autostart/*", "T1547 Boot or Logon Autostart", "MEDIUM"),
                ("/etc/update-motd.d/*", "T1037", "MEDIUM"),
                ("/etc/udev/rules.d/*", "T1547 Boot or Logon Autostart", "HIGH"),
                ("/etc/apt/apt.conf.d/*", "T1546 Event Triggered Execution", "HIGH"),
                ("/etc/NetworkManager/dispatcher.d/*", "T1546", "MEDIUM"),
                ("/etc/dhcp/dhclient-exit-hooks.d/*", "T1546", "MEDIUM")):
            for rel in self.col.rootfs_glob(pat):
                if rel.endswith((".placeholder", "/README")):
                    continue
                for sev2, line in self._scan_content(rel):
                    other.append((sev2, line, mitre))
                if pat == "/etc/udev/rules.d/*":
                    for ln in self.col.lines(rel):
                        if "RUN+=" in ln or "RUN=" in ln:
                            other.append(("HIGH", "%s: %s   [udev RUN action]" %
                                          (self.col.host_path(rel), trunc(ln, 140)), mitre))
        for pat in ("**/.bashrc", "**/.bash_profile", "**/.profile", "**/.zshrc", "**/.bash_login",
                    "**/.config/autostart/*", "**/.xinitrc", "**/.xsession"):
            for rel in self.col.glob(pat):
                for sev2, line in self._scan_content(rel):
                    other.append((sev2, line, "T1546.004 Unix Shell Configuration Modification"))
        if other:
            worst = min(other, key=lambda h: SEV_RANK[h[0]])[0]
            self.add(worst, "Persistence", "Suspicious content in startup / shell / hook scripts",
                     "Attackers hide re-execution in the files that every login or boot "
                     "already runs.",
                     [h[1] for h in sorted(other, key=lambda h: SEV_RANK[h[0]])][:50],
                     source="[root]/etc", mitre=other[0][2], count=len(other))

        # PAM modules pointing outside the standard directories
        pam_hits = []
        for rel in self.col.rootfs_glob("/etc/pam.d/*"):
            for ln in self.col.lines(rel):
                s = ln.strip()
                if s.startswith("#") or ".so" not in s:
                    continue
                m = re.search(r"(\S*pam_\S+\.so|\S+\.so)", s)
                if m and ("/" in m.group(1)) and not m.group(1).startswith(
                        ("/lib/", "/usr/lib/", "/lib64/", "/usr/lib64/")):
                    pam_hits.append("%s: %s" % (self.col.host_path(rel), trunc(s, 140)))
                if "pam_exec.so" in s:
                    pam_hits.append("%s: %s   [pam_exec runs an external program on auth]"
                                    % (self.col.host_path(rel), trunc(s, 140)))
        if pam_hits:
            self.add("HIGH", "Persistence", "PAM stack references a non-standard module or external program",
                     "A malicious PAM module is a credential-stealing backdoor that also "
                     "grants authentication bypass.",
                     pam_hits, source="[root]/etc/pam.d", mitre="T1556.003 Pluggable Authentication Modules")

    # -- 12. ssh configuration ---------------------------------------------
    def analyze_ssh(self):
        rel = self.col.rootfs("/etc/ssh/sshd_config")
        extra = self.col.rootfs_glob("/etc/ssh/sshd_config.d/*")
        files = [f for f in [rel] + extra if f]
        weak, notes = [], []
        for f in files:
            host = self.col.host_path(f)
            for ln in self.col.lines(f):
                s = ln.strip()
                if not s or s.startswith("#"):
                    continue
                low = s.lower()
                if low.startswith("permitrootlogin") and "no" not in low:
                    weak.append(("HIGH", "%s: %s" % (host, s)))
                elif low.startswith("permitemptypasswords") and "yes" in low:
                    weak.append(("CRITICAL", "%s: %s" % (host, s)))
                elif low.startswith("passwordauthentication") and "yes" in low:
                    weak.append(("LOW", "%s: %s" % (host, s)))
                elif low.startswith(("authorizedkeysfile", "authorizedkeyscommand",
                                     "forcecommand", "permittunnel", "gatewayports",
                                     "allowtcpforwarding", "listenaddress", "port",
                                     "match ")):
                    notes.append("%s: %s" % (host, s))
        if weak:
            worst = min(weak, key=lambda h: SEV_RANK[h[0]])[0]
            self.add(worst, "Remote Access", "Permissive sshd configuration",
                     evidence=[w[1] for w in weak], source=files[0] if files else "",
                     mitre="T1021.004 Remote Services: SSH")
        if notes:
            self.add("INFO", "Remote Access", "sshd configuration of interest",
                     evidence=notes[:25], source=files[0] if files else "",
                     count=len(notes))
        elif files and not weak:
            active = [l.strip() for f in files for l in self.col.lines(f)
                      if l.strip() and not l.strip().startswith("#")]
            self.add("INFO", "Remote Access", "sshd configuration reviewed, nothing permissive found",
                     "Only the non-default (uncommented) directives are listed.",
                     active[:25], source=files[0], count=len(active))

        for rel in self.col.glob("**/.ssh/known_hosts"):
            entries = [l.split()[0] for l in self.col.lines(rel) if l.strip() and not l.startswith("#")]
            if entries:
                self.add("INFO", "Remote Access", "known_hosts entries in %s" % self.col.host_path(rel),
                         "Hosts this account has connected out to - useful for scoping "
                         "lateral movement.",
                         entries[:30], source=rel, mitre="T1021.004", count=len(entries))

    # -- 13. kernel modules -------------------------------------------------
    def analyze_modules(self):
        src = "live_response/system/lsmod.txt"
        lsmod = []
        for ln in self.col.lines(src)[1:]:
            f = ln.split()
            if f:
                lsmod.append(f[0])
        sys_modules = set()
        for ln in self.col.lines("live_response/system/ls_-la_sys_module.txt"):
            f = ln.split()
            if len(f) >= 9 and f[0].startswith("d") and f[-1] not in (".", ".."):
                sys_modules.add(f[-1])
        if lsmod and sys_modules:
            ghost = [m for m in lsmod if m not in sys_modules and m.replace("-", "_") not in sys_modules]
            if ghost:
                self.add("HIGH", "Rootkit", "Module(s) in lsmod with no /sys/module entry",
                         "A loaded module that does not appear under /sys/module has "
                         "unlinked itself from kernel bookkeeping - standard LKM rootkit "
                         "behaviour.",
                         ghost, source=src, mitre="T1014 Rootkit")

        named = [m for m in lsmod if any(r in m.lower() for r in ROOTKIT_NAMES)]
        named += [d for d in sys_modules if any(r in d.lower() for r in ROOTKIT_NAMES)]
        if named:
            self.add("CRITICAL", "Rootkit", "Module name matching a known Linux rootkit",
                     evidence=sorted(set(named)), source=src, mitre="T1014 Rootkit")

        # modules loaded without a modinfo record collected
        modinfo = {os.path.basename(p)[len("modinfo_"):-4]
                   for p in self.col.glob("live_response/system/modinfo/modinfo_*.txt")}
        if modinfo and lsmod:
            nomod = [m for m in lsmod if m not in modinfo and m.replace("-", "_") not in modinfo]
            if nomod:
                self.add("MEDIUM", "Rootkit", "Loaded module(s) with no modinfo output",
                         "modinfo failed for these modules - typically because the .ko is "
                         "not present on disk (loaded then deleted) or the module is "
                         "hiding from modinfo.",
                         nomod, source=src, mitre="T1547.006 Kernel Modules and Extensions")

        for pat in ("/etc/modprobe.d/*", "/etc/modules-load.d/*", "/etc/modules"):
            for rel in self.col.rootfs_glob(pat):
                body = [l.strip() for l in self.col.lines(rel)
                        if l.strip() and not l.strip().startswith("#")]
                sus = [b for b in body if re.search(r"install\s+\S+\s+/", b) or
                       any(r in b.lower() for r in ROOTKIT_NAMES)]
                if sus:
                    self.add("HIGH", "Persistence", "Module configuration executes a command",
                             evidence=["%s: %s" % (self.col.host_path(rel), s) for s in sus],
                             source=rel, mitre="T1547.006 Kernel Modules and Extensions")

        # eBPF
        src = "live_response/system/ls_-la_sys_fs_bpf.txt"
        rows = [l for l in self.col.lines(src) if l.split() and l.split()[-1] not in (".", "..")
                and not l.startswith("total")]
        if rows:
            self.add("HIGH", "Rootkit", "Pinned eBPF objects present in /sys/fs/bpf",
                     "Pinned eBPF programs survive the loading process exiting and are "
                     "used by modern stealth backdoors (BPFDoor, ebpfkit, boopkit) for "
                     "traffic hooking and process hiding.",
                     rows, source=src, mitre="T1014 Rootkit")

    # -- 14. dmesg ----------------------------------------------------------
    DMESG_PATTERNS = [
        (r"segfault at", "userland crash (possible exploitation attempt)", "MEDIUM"),
        (r"general protection fault|BUG: unable to handle|kernel NULL pointer", "kernel fault", "MEDIUM"),
        (r"module verification failed|loading out-of-tree module|Loading of unsigned module",
         "unsigned / out-of-tree module load", "HIGH"),
        (r"taints kernel|tainting kernel", "module tainted the kernel", "HIGH"),
        (r"promiscuous mode", "interface entered promiscuous mode", "HIGH"),
        (r"Out of memory: Kill|oom-kill", "OOM kill", "LOW"),
        (r"audit:.*(avc|denied)", "MAC denial", "LOW"),
        (r"\bbpf\b.*(prog|jit)", "eBPF program load", "MEDIUM"),
        (r"insmod|rmmod", "module load/unload", "MEDIUM"),
        (r"usb .*: new .* device", "USB device attached", "LOW"),
    ]

    DMESG_MONOTONIC_RE = re.compile(r"^\[\s*(\d+\.\d+)\]")
    DMESG_DATED_RE = re.compile(r"^\[([A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d+\s+[\d:]+\s+\d{4})\]")

    def dmesg_clock(self):
        """The boot instant, as UTC, so dmesg's '[ 1234.56]' becomes a real time.

        dmesg prints seconds since boot, not a date; `uptime -s` prints the boot
        wall clock in host-local time, and the two together give each line a
        timestamp. The monotonic clock stops while a machine is suspended and
        the wall clock does not, so a host that slept will read early here -
        which is why these times date a finding's span and are never written
        into the timeline as though they had been logged that way.
        """
        if self._dmesg_base is None:
            booted = (self.meta.get("Booted at") or "").strip()
            s = norm_log_ts(booted, self.tz_offset) if booted else ""
            try:
                self._dmesg_base = (datetime.strptime(s, "%Y-%m-%d %H:%M:%S")
                                    .replace(tzinfo=timezone.utc)) if s else False
            except ValueError:
                self._dmesg_base = False
        return self._dmesg_base or None

    def dmesg_time(self, line):
        """One dmesg line -> 'YYYY-MM-DD HH:MM:SS' UTC, or '' if undatable."""
        m = self.DMESG_DATED_RE.match(line)          # dmesg -T already dated it
        if m:
            return norm_log_ts("Xxx " + m.group(1), self.tz_offset)
        base = self.dmesg_clock()
        m = self.DMESG_MONOTONIC_RE.match(line)
        if not base or not m:
            return ""
        return (base + timedelta(seconds=float(m.group(1)))).strftime("%Y-%m-%d %H:%M:%S")

    def analyze_dmesg(self):
        src = "live_response/hardware/dmesg.txt"
        lines = self.col.lines(src)
        if not lines:
            return
        # systemd loads its own LSM BPF programs on every boot - not a finding
        benign = re.compile(r"bpf-restrict-fs|restrict_fs|LSM BPF program attached|"
                            r"systemd\[1\]: bpf-", re.I)
        buckets = defaultdict(list)
        for ln in lines:
            for pat, desc, sev in self.DMESG_PATTERNS:
                if re.search(pat, ln, re.I):
                    if benign.search(ln):
                        sev = "INFO"
                    buckets[(sev, desc)].append((trunc(ln, 190), self.dmesg_time(ln)))
                    break
        for (sev, desc), rows in sorted(buckets.items(), key=lambda kv: SEV_RANK[kv[0][0]]):
            self.add(sev, "Kernel", "dmesg: %s (%d line(s))" % (desc, len(rows)),
                     evidence=[r[0] for r in rows[:20]], source=src,
                     times=[r[1] for r in rows], count=len(rows))

    # -- 15. file system anomalies -----------------------------------------
    def analyze_filesystem_lists(self):
        # hidden files / directories
        for src, kind in (("system/hidden_files.txt", "file"),
                          ("system/hidden_directories.txt", "directory")):
            rows = [l.strip() for l in self.col.lines(src) if l.strip().startswith("/")]
            if not rows:
                continue
            interesting, high = [], []
            for p in rows:
                if BENIGN_HIDDEN.search(p):
                    continue
                if p.startswith(TMPFS_DIRS) or p.startswith(("/usr/", "/bin/", "/sbin/", "/lib",
                                                             "/boot/", "/opt/", "/srv/", "/var/www/")):
                    high.append(p)
                    self.ioc(p, "hidden %s" % kind)
                else:
                    interesting.append(p)
            if high:
                self.add("HIGH", "Hiding", "Hidden %s(s) in a system or world-writable location" % kind,
                         "Dot-prefixed names in directories that should not contain them "
                         "are a basic but effective hiding technique.",
                         high, source=src, mitre="T1564.001 Hidden Files and Directories")
            if interesting:
                self.add("LOW", "Hiding", "%d other hidden %s(s) outside the common baseline" % (len(interesting), kind),
                         evidence=interesting[:40], source=src, mitre="T1564.001",
                         count=len(interesting))

        # unowned files
        for src, what in (("system/user_name_unknown_files.txt", "user"),
                          ("system/group_name_unknown_files.txt", "group"),
                          ("system/user_name_unknown_directories.txt", "user"),
                          ("system/group_name_unknown_directories.txt", "group")):
            rows = [l.strip() for l in self.col.lines(src) if l.strip().startswith("/")]
            if rows:
                self.add("MEDIUM", "Filesystem", "Object(s) with an unresolvable %s id (%s)" % (what, os.path.basename(src)),
                         "No matching entry in /etc/passwd or /etc/group - left behind by "
                         "a deleted account, an extracted archive, or a rootkit filtering "
                         "those files.",
                         rows[:40], source=src, mitre="T1564 Hide Artifacts",
                         count=len(rows))

        # World-writable objects in locations that should never be.
        # UAC's world_writable_* lists come straight from `find -perm`, and some
        # builds emit far too much, so every hit is re-checked against the mode
        # recorded in the bodyfile before it is reported as a finding.
        sensitive = ("/etc/", "/boot/", "/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/",
                     "/usr/lib/", "/lib/", "/usr/local/", "/root/", "/var/spool/cron/")
        for src, what in (("system/world_writable_files.txt", "file"),
                          ("system/world_writable_directories.txt", "directory")):
            listed, confirmed, unverified = 0, [], 0
            for ln in self.col.iter_lines(src):
                p = ln.strip()
                if not p.startswith("/"):
                    continue
                listed += 1
                if not p.startswith(sensitive):
                    continue
                if self.bodyfile_seen:
                    if p in self.ww_paths:
                        confirmed.append(p)
                else:
                    unverified += 1
            if confirmed:
                self.add("HIGH", "Filesystem", "World-writable %s(s) in a system location" % what,
                         "Any local user can modify these - a direct privilege escalation "
                         "and persistence surface. Permissions were confirmed against the "
                         "mode recorded in the bodyfile.",
                         confirmed[:40], source=src, count=len(confirmed),
                         mitre="T1222 File and Directory Permissions Modification")
            elif unverified:
                self.add("LOW", "Filesystem",
                         "%d %s(s) in system paths listed as world-writable (unverified)" % (unverified, what),
                         "No bodyfile was available to confirm the mode bits, and this "
                         "list is unreliable in some UAC builds - verify before acting.",
                         source=src, count=unverified)
            elif listed and self.bodyfile_seen:
                self.add("INFO", "Filesystem",
                         "%d entr(ies) in %s; none in a system path confirmed world-writable"
                         % (listed, os.path.basename(src)), source=src, count=listed)

        # bodyfile-derived world-writable objects the UAC list may have missed
        extra = sorted(p for p in self.ww_paths if p.startswith(sensitive))
        if extra:
            self.add("HIGH", "Filesystem",
                     "%d system path(s) carry world-write permission (from the bodyfile)" % len(extra),
                     "Derived directly from the recorded mode bits, independent of UAC's "
                     "own world-writable list.",
                     extra[:40], source="bodyfile/bodyfile.txt", count=len(extra),
                     mitre="T1222 File and Directory Permissions Modification")

    # -- 16. bodyfile / timeline -------------------------------------------
    def analyze_bodyfile(self):
        src = None
        for cand in ("bodyfile/bodyfile.txt", "bodyfile/bodyfile.csv"):
            if self.col.exists(cand):
                src = cand
                break
        if not src:
            return

        ws = self.window_start()
        ct = self.collection_time
        tmpfs_exec, sysrecent, stomped, future, authkeys = [], [], [], [], []
        tmpfs_other, suid_bodies = [], []
        # the recorded time behind each bucket above: a bodyfile finding is
        # dated by the files it names, which is the whole point of a bodyfile
        when = defaultdict(list)
        oldest = latest = None        # span of the timeline as a whole
        total = 0
        recent_all = []

        for ln in self.col.iter_lines(src):
            if not ln or "|" not in ln:
                continue
            parts = ln.split("|")
            if len(parts) < 11:
                continue
            total += 1
            tail = parts[-9:]
            name = "|".join(parts[1:-9])
            inode, mode, uid, gid, size = tail[0], tail[1], tail[2], tail[3], tail[4]
            atime, mtime, ctime, crtime = (epoch(tail[5]), epoch(tail[6]),
                                           epoch(tail[7]), epoch(tail[8]))
            path = name.split(" -> ")[0]
            is_reg = mode.startswith("-")
            is_dir = mode.startswith("d")
            is_exec = is_reg and "x" in mode[1:]
            newest = max([t for t in (mtime, ctime, crtime) if t], default=None)
            if newest:
                oldest = newest if oldest is None or newest < oldest else oldest
                latest = newest if latest is None or newest > latest else latest

            # World-writable, but only for objects where it means anything:
            # symlinks are always lrwxrwxrwx, and sticky directories (/tmp) are
            # world-writable by design. Both dominate a naive `find -perm -0002`.
            if len(mode) >= 10 and mode[8] == "w" and (is_reg or is_dir) \
                    and not (is_dir and mode[9] in ("t", "T")):
                self.ww_paths.add(path)

            if path.startswith(TMPFS_DIRS) and (is_reg or is_dir) \
                    and "/systemd-private-" not in path:
                row = "%-10s %s  uid=%s size=%-9s mtime=%s" % (
                    mode, path, uid, size,
                    mtime.strftime("%Y-%m-%d %H:%M:%S") if mtime else "-")
                if is_exec:
                    tmpfs_exec.append(row)
                    when["tmpfs_exec"].append(mtime)
                    self.ioc(path, "bodyfile (executable in tmpfs)")
                    self.event(mtime, "File", "executable in tmpfs: %s" % path, "HIGH", src)
                elif is_reg and size != "0":
                    tmpfs_other.append(row)
                    when["tmpfs_other"].append(mtime)

            if is_reg and ("s" in mode[1:4] or "s" in mode[4:7]):
                suid_bodies.append("%-10s %s (uid=%s gid=%s)" % (mode, path, uid, gid))
                when["suid"].append(newest)

            if path.endswith((".ssh/authorized_keys", ".ssh/authorized_keys2")):
                authkeys.append("%s  mtime=%s ctime=%s" % (
                    path, mtime.strftime("%Y-%m-%d %H:%M:%S") if mtime else "-",
                    ctime.strftime("%Y-%m-%d %H:%M:%S") if ctime else "-"))
                when["authkeys"].extend((mtime, ctime))
                self.event(mtime, "Persistence", "authorized_keys modified: %s" % path, "HIGH", src)

            if ct and newest and newest > ct + timedelta(hours=1):
                future.append("%s  mtime=%s (after collection)" % (
                    path, newest.strftime("%Y-%m-%d %H:%M:%S")))
                when["future"].append(newest)

            # Timestomping: content timestamp far older than the metadata change,
            # and the metadata change lands inside the incident window. A package
            # install rewrites ctime for thousands of files at once, so the volume
            # of hits is what separates "os install" from "someone forged mtime".
            if is_reg and mtime and ctime and ws and ctime >= ws and \
                    path.startswith(SYSTEM_BIN_DIRS + SYSTEM_CFG_DIRS) and \
                    (ctime - mtime).days > 180:
                stomped.append("%s  mtime=%s  ctime=%s  (%d days apart)" % (
                    path, mtime.strftime("%Y-%m-%d"), ctime.strftime("%Y-%m-%d"),
                    (ctime - mtime).days))
                when["stomped"].append(ctime)

            if ws and newest and newest >= ws:
                recent_all.append((newest, mode, path, uid, size))
                if path.startswith(SYSTEM_BIN_DIRS + SYSTEM_CFG_DIRS) and is_reg:
                    sysrecent.append((newest, "%s  %-10s uid=%s size=%-8s %s" % (
                        newest.strftime("%Y-%m-%d %H:%M:%S"), mode, uid, size, path)))

        if tmpfs_exec:
            self.add("CRITICAL", "Filesystem",
                     "%d executable file(s) in world-writable temp directories" % len(tmpfs_exec),
                     "/tmp, /var/tmp and /dev/shm are the default drop locations for "
                     "payloads. /dev/shm is memory-backed, so files there disappear on "
                     "reboot - an attacker choice, not an accident.",
                     tmpfs_exec[:50], source=src, mitre="T1036 Masquerading / T1059",
                     times=when["tmpfs_exec"], count=len(tmpfs_exec))
        if authkeys:
            self.add("HIGH", "Persistence", "authorized_keys file timestamps",
                     "Compare these against the incident window - a key file written "
                     "during the intrusion is attacker persistence.",
                     authkeys[:30], source=src, mitre="T1098.004 SSH Authorized Keys",
                     times=when["authkeys"], count=len(authkeys))
        if future:
            self.add("HIGH", "Anti-forensics", "File(s) timestamped after the collection ran",
                     "Timestamps in the future usually mean deliberate timestomping (or a "
                     "badly skewed clock).",
                     future[:30], source=src, mitre="T1070.006 Timestomp",
                     times=when["future"], count=len(future))
        if stomped:
            bulk = len(stomped) > 200
            self.add("INFO" if bulk else "MEDIUM", "Anti-forensics",
                     "%d system file(s) with an mtime far older than a ctime inside the window"
                     % len(stomped),
                     ("This many at once is a package install or upgrade rewriting metadata "
                      "in bulk, not timestomping - use the package logs to confirm the "
                      "session that caused it." if bulk else
                      "A content timestamp much older than the metadata timestamp is what "
                      "remains when mtime is forged: ctime cannot be set from userspace."),
                     stomped[:25], source=src, mitre="T1070.006 Timestomp",
                     times=when["stomped"], count=len(stomped))
        if suid_bodies:
            self.add("INFO", "Privilege", "%d setuid/setgid file(s) in the filesystem timeline" % len(suid_bodies),
                     evidence=suid_bodies[:40], source=src,
                     times=when["suid"], count=len(suid_bodies))
        if sysrecent:
            sysrecent.sort()
            bulk = len(sysrecent) > 2000
            self.add("LOW" if bulk else "MEDIUM", "Filesystem",
                     "%d system file(s) created or modified within %dh of collection"
                     % (len(sysrecent), self.opts.window),
                     ("At this volume the host itself was built or upgraded inside the "
                      "window, so the list is not a signal on its own. Re-run with a "
                      "smaller --window to isolate changes after that point; the most "
                      "recent entries are shown." if bulk else
                      "Changes to /etc, /usr, /bin, /lib and /boot inside the incident "
                      "window are the shortest path to what the intruder touched."),
                     [r[1] for r in sysrecent[-60:]], source=src,
                     times=[r[0] for r in sysrecent], count=len(sysrecent))

        if tmpfs_other:
            self.add("LOW", "Filesystem",
                     "%d non-executable file(s) in temp / shared-memory directories" % len(tmpfs_other),
                     "Staged data, dropped configs and exfil archives live here too - "
                     "worth eyeballing even when nothing is marked executable.",
                     tmpfs_other[:40], source=src,
                     times=when["tmpfs_other"], count=len(tmpfs_other))

        # feed the timeline
        recent_all.sort()
        # systemd gives many services a private /tmp; those directories are not
        # what "something appeared in /tmp" is supposed to mean.
        private_tmp = re.compile(r"/systemd-private-[0-9a-f]+-")
        # shared-memory scratch files every desktop Linux box has
        tmpfs_benign = re.compile(r"lttng-ust-wait|pulse-shm|/sem\.|\.X11-unix|\.ICE-unix")
        # runtime state that churns constantly, including while UAC itself runs
        noise = re.compile(r"^/(run/(systemd|udev|user|lock|blkid|mount|NetworkManager)|"
                           r"proc/|sys/|var/lib/systemd/|var/cache/|var/lib/NetworkManager/)")
        recent_all = [r for r in recent_all if not noise.match(r[2])]
        for ts, mode, path, uid, size in recent_all[-self.opts.timeline_limit:]:
            notable = (path.startswith(TMPFS_DIRS) and not private_tmp.search(path)
                       and not tmpfs_benign.search(path)
                       and (mode.startswith("-") and "x" in mode[1:]
                            or path.startswith(("/dev/shm/", "/run/shm/"))))
            self.event(ts, "File", "%s %s (uid=%s size=%s)" % (mode, path, uid, size),
                       "HIGH" if notable else "INFO", src)

        self.bodyfile_seen = total > 0
        self.add("INFO", "Filesystem", "%d filesystem entries in the bodyfile" % total,
                 "Full MACB timeline. Convert with mactime for a classic timeline: "
                 "`mactime -b bodyfile.txt -d`.", source=src,
                 times=[oldest, latest], count=total)

    @staticmethod
    def lsof_pid(line):
        """The PID column of an lsof row - 'COMMAND PID USER FD ...'."""
        f = line.split()
        return f[1] if len(f) > 1 and f[1].isdigit() else None

    # -- 17. open files -----------------------------------------------------
    def analyze_open_files(self):
        src = "live_response/process/lsof_-nPl.txt"
        if not self.col.exists(src):
            return
        deleted_exec, tmp_open, memfd, rawsock = [], [], [], []
        # an open descriptor has no time of its own; the process holding it does
        pids = defaultdict(list)
        for ln in self.col.iter_lines(src):
            pid = self.lsof_pid(ln)
            if "(deleted)" in ln:
                f = ln.split()
                if len(f) > 4 and ("txt" in f[3:6] or " txt " in ln):
                    if "/memfd:" not in ln:
                        deleted_exec.append(trunc(ln, 190))
                        pids["deleted_exec"].append(pid)
                if "/memfd:" in ln:
                    memfd.append(trunc(ln, 160))
                    pids["memfd"].append(pid)
            if any(d in ln for d in ("/dev/shm/", "/var/tmp/", "/tmp/")) and " REG " in ln:
                if not re.search(r"/tmp/\.(X11|ICE|font|XIM)", ln):
                    tmp_open.append(trunc(ln, 190))
                    pids["tmp_open"].append(pid)
            if re.search(r"\bpack\b|\braw\b|\bRAW\b", ln) and "IPv" in ln:
                rawsock.append(trunc(ln, 160))
                pids["rawsock"].append(pid)
        if deleted_exec:
            self.add("HIGH", "Process", "Process(es) with a deleted executable image open",
                     evidence=deleted_exec[:25], source=src,
                     mitre="T1070.004 Indicator Removal: File Deletion",
                     times=self.proc_times(pids["deleted_exec"]), count=len(deleted_exec))
        if memfd:
            # pipewire/wireplumber/systemd/browsers use memfd constantly; only the
            # unexpected owners are worth a MEDIUM.
            known = re.compile(r"^(pipewire|wireplumb|systemd|gnome-she|chrome|firefox|"
                               r"Web Content|dbus-|snapd|mutter|Xwayland)", re.I)
            unexpected = [m for m in memfd if not known.match(m.strip())]
            self.add("MEDIUM" if unexpected else "LOW", "Process",
                     "memfd-backed (fileless) mappings open",
                     "memfd_create() is used constantly by pipewire, systemd and browsers, "
                     "and also by fileless loaders that never touch disk. Only unexpected "
                     "owners matter.",
                     (unexpected or memfd)[:20], source=src,
                     mitre="T1620 Reflective Code Loading",
                     times=self.proc_times(pids["memfd"]),
                     count=len(unexpected or memfd))
        if tmp_open:
            # tracing/session scratch files that every desktop Linux box has open
            benign = re.compile(r"lttng-ust-wait|cups-dbus-notifier-lockfile|"
                                r"/tmp/\.(X11|ICE|font|XIM)|pulse-shm|/dev/shm/sem\.")
            unexpected = [t for t in tmp_open if not benign.search(t)]
            self.add("MEDIUM" if unexpected else "LOW", "Process",
                     "Open regular files in temp / shared-memory directories",
                     "A daemon holding a file open under /tmp or /dev/shm is worth a look; "
                     "audio and tracing libraries do it routinely.",
                     (unexpected or tmp_open)[:30], source=src,
                     times=self.proc_times(pids["tmp_open"]),
                     count=len(unexpected or tmp_open))
        if rawsock:
            self.add("MEDIUM", "Network", "Raw / packet socket(s) open",
                     "Raw sockets are used by sniffers and by backdoors that read traffic "
                     "off the wire instead of listening on a port.",
                     rawsock[:20], source=src, mitre="T1040 Network Sniffing",
                     times=self.proc_times(pids["rawsock"]), count=len(rawsock))

        # unix sockets in unusual places
        src = "live_response/network/lsof_-U.txt"
        odd, odd_pids = [], []
        for ln in self.col.iter_lines(src):
            m = re.search(r"(/(?:tmp|var/tmp|dev/shm)/\S+)", ln)
            if m and not re.search(r"/tmp/\.(X11|ICE|font|XIM)", ln):
                odd.append(trunc(ln, 180))
                odd_pids.append(self.lsof_pid(ln))
        if odd:
            self.add("MEDIUM", "Network", "Unix domain socket(s) in a temp directory",
                     evidence=odd[:25], source=src,
                     times=self.proc_times(odd_pids), count=len(odd))

        src = "live_response/system/socket_files.txt"
        rows = [l.strip() for l in self.col.lines(src) if l.strip().startswith(TMPFS_DIRS)]
        if rows:
            self.add("MEDIUM", "Network", "Socket file(s) in a world-writable directory",
                     evidence=rows[:25], source=src, count=len(rows))

    # -- 18. packages -------------------------------------------------------
    SUSPECT_PKGS = {"nmap", "netcat", "netcat-openbsd", "netcat-traditional", "ncat", "socat",
                    "tcpdump", "hydra", "john", "hashcat", "masscan", "proxychains",
                    "proxychains4", "tor", "sshpass", "telnet", "nikto", "sqlmap",
                    "metasploit-framework", "responder", "aircrack-ng", "ettercap-text-only",
                    "chisel", "ngrok", "openvpn", "wireguard", "cryptsetup", "upx-ucl"}

    # a build environment appearing mid-incident means something was compiled here
    TOOLCHAIN_PKGS = {"build-essential", "gcc", "g++", "clang", "make", "cmake", "nasm",
                      "yasm", "git", "golang-go", "rustc", "linux-headers-generic",
                      "libpam0g-dev", "libssl-dev", "libgcrypt-dev", "libcap-dev",
                      "libelf-dev", "libbpf-dev", "bpftool", "dkms", "kmod",
                      "python3-dev", "autoconf", "automake", "libtool", "patch"}

    def analyze_packages(self):
        src = "live_response/packages/dpkg_-l.txt"
        rows = self.col.lines(src)
        if rows:
            broken, suspect = [], []
            for ln in rows:
                m = re.match(r"^([a-z][a-zA-Z])\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)$", ln)
                if not m:
                    continue
                state, name, ver = m.group(1), m.group(2).split(":")[0], m.group(3)
                if state not in ("ii", "rc"):
                    broken.append("%s %s %s" % (state, name, ver))
                if name in self.SUSPECT_PKGS:
                    suspect.append("%s %s" % (name, ver))
            if suspect:
                self.add("MEDIUM", "Software", "Dual-use / offensive tooling installed",
                         "These packages are legitimate administration tools and also "
                         "standard attacker equipment - confirm they belong on this host.",
                         sorted(suspect), source=src, mitre="T1588.002 Obtain Capabilities: Tool")
            if broken:
                self.add("LOW", "Software", "Package(s) not in a fully installed state",
                         evidence=broken[:25], source=src, count=len(broken))

        # recent installs from apt / dpkg logs
        ws = self.window_start()
        rel = self.col.rootfs("/var/log/dpkg.log")
        if rel and ws:
            recent, pending, notable_pkgs, notable_ts = [], [], [], []
            for ln in self.col.iter_lines(rel):
                m = re.match(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)\s+(install|upgrade|remove|purge)\s+(\S+)\s+(\S+)\s*(\S*)", ln)
                if not m:
                    continue
                try:
                    ts = self.local_to_utc(datetime.strptime(
                        m.group(1), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc))
                except ValueError:
                    continue
                if ts >= ws:
                    recent.append("%s %s %s %s" % (m.group(1), m.group(2), m.group(3), m.group(5) or m.group(4)))
                    pending.append((ts, "%s %s" % (m.group(2), m.group(3))))
                    pkg = m.group(3).split(":")[0]
                    if m.group(2) == "install" and (
                            pkg in self.TOOLCHAIN_PKGS or pkg in self.SUSPECT_PKGS):
                        notable_pkgs.append("%s  install %s %s" % (
                            m.group(1), pkg, m.group(5) or m.group(4)))
                        notable_ts.append(ts)
                        self.event(ts, "Software", "install %s" % pkg, "HIGH", rel)
            if recent:
                bulk = len(recent) > 100
                # an OS build writes thousands of dpkg lines; one event each would
                # bury everything else in the timeline
                if not bulk:
                    for ts, desc in pending:
                        self.event(ts, "Software", desc, "MEDIUM", rel)
                self.add("LOW" if bulk else "MEDIUM", "Software",
                         "%d package operation(s) within %dh of collection" % (len(recent), self.opts.window),
                         ("A run this large is an OS install or a distribution upgrade, not "
                          "targeted tooling - narrow the window with --window to see what "
                          "happened after it." if bulk else
                          "Software installed or removed during the incident window - "
                          "attackers install their toolchain, and remove evidence."),
                         recent[-40:], source=rel, mitre="T1072 Software Deployment Tools",
                         times=[t for t, _d in pending], count=len(recent))
            if notable_pkgs:
                self.add("MEDIUM", "Software",
                         "Compiler / dual-use package(s) installed inside the incident window",
                         "A build toolchain or offensive utility arriving during the window "
                         "is how an intruder compiles a rootkit or module on the victim "
                         "host, which is also why the resulting binary matches no package "
                         "and no public hash. Development headers name what was being built "
                         "against.",
                         notable_pkgs[:30], source=rel, times=notable_ts,
                         count=len(notable_pkgs),
                         mitre="T1588.002 Obtain Capabilities: Tool / T1587.001 Develop Capabilities")

        rel = self.col.rootfs("/var/log/apt/history.log")
        if rel and ws:
            blocks, cur = [], {}
            for ln in self.col.iter_lines(rel):
                if not ln.strip():
                    if cur:
                        blocks.append(cur)
                        cur = {}
                    continue
                if ":" in ln:
                    k, v = ln.split(":", 1)
                    cur[k.strip()] = v.strip()
            if cur:
                blocks.append(cur)
            recent, recent_ts = [], []
            for b in blocks:
                st = b.get("Start-Date", "")
                try:
                    ts = self.local_to_utc(datetime.strptime(
                        st, "%Y-%m-%d  %H:%M:%S").replace(tzinfo=timezone.utc))
                except ValueError:
                    continue
                if ts >= ws:
                    recent.append("%s  %s  (by %s)" % (st, trunc(b.get("Commandline", "?"), 110),
                                                       b.get("Requested-By", "root")))
                    recent_ts.append(ts)
                    self.event(ts, "Software", trunc(b.get("Commandline", "apt run"), 110), "MEDIUM", rel)
            if recent:
                self.add("MEDIUM", "Software", "apt session(s) within the incident window",
                         evidence=recent[:25], source=rel,
                         times=recent_ts, count=len(recent))

    # -- 19. hashes ---------------------------------------------------------
    def analyze_hashes(self):
        def load(rel):
            out = {}
            for ln in self.col.iter_lines(rel):
                m = re.match(r"^([0-9a-fA-F]{32,64})\s+(.*)$", ln.strip())
                if m:
                    out.setdefault(m.group(1).lower(), []).append(m.group(2).strip())
            return out

        disk = load("hash_executables/hash_executables.md5")
        running = load("live_response/process/hash_running_processes.md5")
        if not running:
            return
        # hash_running_processes hashes /proc/<pid>/exe, so resolve each pid back
        # to the real executable path before comparing with the on-disk inventory.
        path_hash = {}
        for h, paths in disk.items():
            for p in paths:
                path_hash[p] = h

        mismatched, unknown = [], []
        hash_pids = defaultdict(list)
        for h, paths in running.items():
            for p in paths:
                m = re.match(r"^/proc/(\d+)/exe$", p.strip())
                pid = m.group(1) if m else None
                exe = (self.processes.get(pid, {}).get("exe") or "") if pid else p
                clean = exe.split(" (deleted)")[0]
                label = "%s  pid %-7s %s" % (h, pid or "-", exe or p)
                if clean and clean in path_hash:
                    if path_hash[clean] != h:
                        mismatched.append("%s   [on-disk md5 %s]" % (label, path_hash[clean]))
                        hash_pids["mismatched"].append(pid)
                        self.ioc(clean, "hash mismatch")
                elif exe.endswith("(deleted)") or clean.startswith(TMPFS_DIRS):
                    unknown.append(label)
                    hash_pids["unknown"].append(pid)
                    self.ioc(h, "running-process hash")
        if mismatched:
            self.add("CRITICAL", "Integrity",
                     "%d running process(es) whose image differs from the file on disk" % len(mismatched),
                     "The executable backing the running process does not hash to the same "
                     "value as the file at that path. Either the on-disk binary was "
                     "replaced after the process started, or the running image was tampered "
                     "with - both mean the file you would examine is not what is running.",
                     mismatched[:30], source="live_response/process/hash_running_processes.md5",
                     mitre="T1036 Masquerading / T1554 Compromise Host Software Binary",
                     times=self.proc_times(hash_pids["mismatched"]), count=len(mismatched))
        if unknown:
            self.add("HIGH", "Integrity",
                     "%d running executable(s) with no corresponding file on disk" % len(unknown),
                     "The process image was deleted or lives in a temp filesystem, so no "
                     "on-disk copy was hashed during the sweep. These hashes are the ones "
                     "to submit for reputation lookup and to carve out of the memory image.",
                     unknown[:30], source="live_response/process/hash_running_processes.md5",
                     mitre="T1070.004 Indicator Removal: File Deletion",
                     times=self.proc_times(hash_pids["unknown"]), count=len(unknown))

        dupes = []
        for h, paths in disk.items():
            uniq = sorted(set(paths))
            if len(uniq) > 1:
                names = {os.path.basename(p) for p in uniq}
                if len(names) > 1:
                    dupes.append("%s -> %s" % (h, ", ".join(uniq[:6])))
        if dupes:
            self.add("LOW", "Integrity", "Identical binaries present under different names",
                     "Usually distro alternatives/hardlinks; occasionally a copied shell "
                     "hidden under a benign name.",
                     dupes[:25], source="hash_executables/hash_executables.md5",
                     count=len(dupes))

    # -- 20. logging / anti-forensics ---------------------------------------
    def analyze_logging(self):
        # journald configured not to persist
        for rel in [r for r in [self.col.rootfs("/etc/systemd/journald.conf")] if r] + \
                   self.col.rootfs_glob("/etc/systemd/journald.conf.d/*"):
            for ln in self.col.lines(rel):
                s = ln.strip()
                if re.match(r"^Storage\s*=\s*(none|volatile)", s, re.I):
                    self.add("MEDIUM", "Anti-forensics", "journald not persisting logs (%s)" % s,
                             evidence=["%s: %s" % (self.col.host_path(rel), s)], source=rel,
                             mitre="T1562.001 Impair Defenses")
                if re.match(r"^(MaxRetentionSec|SystemMaxUse)\s*=\s*[0-9]+[smh]?$", s, re.I):
                    self.add("LOW", "Anti-forensics", "journald retention limited (%s)" % s,
                             evidence=["%s: %s" % (self.col.host_path(rel), s)], source=rel)

        # log files that exist but are empty
        zeroed = []
        # the error log belongs beside the access log here: it is where a
        # refused exploit attempt is recorded, so it is the half of the pair
        # an attacker has the most reason to truncate
        for name in ("auth.log", "secure", "syslog", "messages", "wtmp", "audit/audit.log",
                     "cron", "kern.log", "apache2/access.log", "nginx/access.log",
                     "apache2/error.log", "nginx/error.log", "httpd/access_log",
                     "httpd/error_log"):
            rel = self.col.rootfs("/var/log/" + name)
            if rel and self.col.size(rel) == 0:
                zeroed.append("/var/log/%s is 0 bytes" % name)
        if zeroed:
            self.add("HIGH", "Anti-forensics", "Log file(s) present but empty",
                     "A zero-length log that the system actively writes to is the "
                     "signature of `> /var/log/...` truncation.",
                     zeroed, source="[root]/var/log", mitre="T1070.002 Clear Linux Logs")

        # logs that should exist and do not
        missing = []
        for name in ("auth.log", "secure"):
            if self.col.rootfs("/var/log/" + name) is None:
                missing.append(name)
        if len(missing) == 2:
            self.add("LOW", "Collection", "No auth.log/secure collected",
                     "Authentication history may live only in the systemd journal on this "
                     "host - parse [root]/var/log/journal/*.journal with journalctl "
                     "--file, or with a journal parser.", source="[root]/var/log")

        journals = self.col.rootfs_glob("/var/log/journal/*/*.journal*")
        if journals:
            self.add("INFO", "Logging", "%d systemd journal file(s) collected" % len(journals),
                     "Read them offline: `journalctl --file <path> -o short-iso`. "
                     "Rotated files ending in ~ are previous boots.",
                     [self.col.host_path(j) for j in journals[:20]], source=journals[0],
                     count=len(journals))

        src = "live_response/system/journalctl_--list-boots.txt"
        rows = [l for l in self.col.lines(src) if l.strip()]
        if rows:
            self.add("INFO", "System", "Boot history", evidence=rows[:20], source=src,
                     count=len(rows))

    # -- 21. misc host configuration ---------------------------------------
    def analyze_misc(self):
        rel = self.col.rootfs("/etc/hosts")
        if rel:
            odd = []
            for ln in self.col.lines(rel):
                s = ln.strip()
                if not s or s.startswith("#"):
                    continue
                f = s.split()
                # the stock IPv6 boilerplate every Debian/Ubuntu host ships with
                if len(f) >= 2 and f[0] not in ("127.0.0.1", "::1", "127.0.1.1",
                                                "ff02::1", "ff02::2", "ff02::3",
                                                "fe00::0", "ff00::0"):
                    odd.append(s)
                if re.search(r"\b(0\.0\.0\.0|127\.0\.0\.1)\s+.*(update|security|antivirus|"
                             r"clamav|defender|sophos|crowdstrike)", s, re.I):
                    odd.append(s + "   [security domain redirected to localhost]")
            if odd:
                self.add("MEDIUM", "Configuration", "Non-default /etc/hosts entries",
                         "Static host entries can redirect update/security traffic or "
                         "pin a C2 name to an address.",
                         odd, source=rel, mitre="T1565.001 Data Manipulation")

        rel = self.col.rootfs("/etc/resolv.conf")
        if rel:
            ns = [l.strip() for l in self.col.lines(rel) if l.strip().startswith("nameserver")]
            ext = [n for n in ns if not is_private_ip(n.split()[-1])]
            if ext:
                self.add("LOW", "Configuration", "External DNS resolver configured",
                         evidence=ns, source=rel)

        # firewall state
        for rel in ([r for r in [self.col.rootfs("/etc/ufw/ufw.conf")] if r] +
                    self.col.glob("live_response/network/iptables*") +
                    self.col.glob("live_response/network/nft*")):
            txt = self.col.text(rel)
            if txt and re.search(r"ENABLED\s*=\s*no", txt, re.I):
                self.add("MEDIUM", "Configuration", "Host firewall disabled",
                         evidence=[self.col.host_path(rel)], source=rel,
                         mitre="T1562.004 Impair Defenses: Disable or Modify System Firewall")

        # NAT / redirect rules: the mechanism behind a port that answers from
        # somewhere other than the process listening on it
        nat_ev = []
        for rel in (self.col.glob("live_response/network/nft*") +
                    self.col.glob("live_response/network/iptables_-t_nat*") +
                    self.col.glob("live_response/network/ip6tables_-t_nat*")):
            for ln in self.col.lines(rel):
                s = ln.strip()
                if re.search(r"\b(dnat to|DNAT|REDIRECT|--to-destination|"
                             r"redirect to)\b", s):
                    nat_ev.append("%s: %s" % (os.path.basename(rel), trunc(s, 150)))
        if nat_ev:
            self.add("LOW" if len(nat_ev) < 12 else "MEDIUM", "Network",
                     "%d NAT / port-redirect rule(s) in the firewall" % len(nat_ev),
                     "A DNAT or REDIRECT rule sends traffic somewhere other than "
                     "the process bound to the port. Container publishing looks "
                     "exactly like a redirect an intruder installed, so each rule "
                     "needs an owner in CONTAINERS or an explanation.",
                     nat_ev[:25], source="live_response/network", count=len(nat_ev),
                     mitre="T1572 Protocol Tunneling")

        # containers
        cjson = (self.col.rootfs_glob("/run/docker/runtime-runc/*/*/state.json") +
                 self.col.rootfs_glob("/var/run/docker/runtime-runc/*/*/state.json") +
                 self.col.rootfs_glob("/run/containerd/*/*/*/config.json") +
                 self.col.rootfs_glob("/var/run/containerd/*/*/*/config.json") +
                 self.col.rootfs_glob("/var/lib/docker/containers/*/config.v2.json"))
        if cjson or self.col.rootfs("/var/lib/docker") \
                or self.col.glob("live_response/containers/**"):
            per_container = {}
            for rel in cjson:
                try:
                    d = json.loads(self.col.text(rel) or "")
                except Exception:
                    continue
                if not isinstance(d, dict):
                    continue
                cid = (d.get("id") or "")[:12]
                if not cid:
                    # containerd's config.json carries the id only in its path
                    m = re.search(r"/([0-9a-f]{12,64})/", self.col.host_path(rel))
                    cid = m.group(1)[:12] if m else os.path.basename(
                        os.path.dirname(rel))
                cfg = d.get("config") if isinstance(d.get("config"), dict) else {}
                lin = d.get("linux") if isinstance(d.get("linux"), dict) else {}
                proc = d.get("process") if isinstance(d.get("process"), dict) else {}
                risky = []
                for mnt in (d.get("mounts") or cfg.get("mounts") or []):
                    if not isinstance(mnt, dict):
                        continue
                    src_p = mnt.get("source") or mnt.get("Source") or ""
                    dst_p = mnt.get("destination") or mnt.get("Destination") or ""
                    # a container that can write these owns the host
                    if src_p in ("/", "/etc", "/root", "/var/run/docker.sock",
                                 "/run/docker.sock", "/proc", "/sys", "/boot") \
                            or src_p.startswith(("/etc/", "/root/", "/home/")):
                        risky.append("mounts host %s at %s" % (src_p, dst_p))
                if not lin.get("namespaces") and lin:
                    risky.append("no namespace isolation")
                for e in (proc.get("env") or []):
                    if re.match(r"^[A-Z_]*(PASSWORD|PASSWD|SECRET|TOKEN|KEY)=", str(e)):
                        risky.append("credential in environment: %s"
                                     % str(e).split("=", 1)[0])
                if cid:
                    per_container.setdefault(cid, [])
                    for r in risky:
                        if r not in per_container[cid]:
                            per_container[cid].append(r)
            ev = ["%s: %s" % (cid, "; ".join(risky) if risky
                              else "no host mounts or secrets flagged")
                  for cid, risky in sorted(per_container.items())]
            sev = "MEDIUM" if any("mounts host" in e or "credential" in e
                                  for e in ev) else "INFO"
            self.add(sev, "Containers",
                     ("%d container(s) reconstructed from runtime state"
                      % len(per_container)) if per_container
                     else "Container artifacts present",
                     "Container runtime data was collected - the CONTAINERS table "
                     "has the image, entrypoint, environment and bind mounts for "
                     "each one. Host bind mounts and credentials in the "
                     "environment are the two that change the blast radius.",
                     ev[:25] or self.col.glob("live_response/containers/**")[:20],
                     source=cjson[0] if cjson else "live_response/containers",
                     count=len(per_container) or None)

        # mounted filesystems worth noting
        src = "live_response/storage/mount.txt"
        rows = [l for l in self.col.lines(src) if l.strip()]
        odd = [r for r in rows if re.search(r"\b(exec)\b", r) and re.search(r"\son\s/(tmp|dev/shm|var/tmp)\s", r)]
        if odd:
            self.add("MEDIUM", "Configuration", "Temp filesystem mounted with exec permitted",
                     "noexec on /tmp and /dev/shm blocks the simplest payload execution "
                     "path; these mounts allow it.",
                     odd, source=src)

        # FOR577 "Altered files": /dev should hold devices and links only
        plen = len(self.col.prefix)
        devroot, devtmp = [], []
        for low, real in sorted(self.col._names.items(), key=lambda kv: kv[1]):
            if not low.startswith(self.col.prefix):
                continue
            rel = real[plen:]
            if not rel.lstrip("/").lower().startswith(
                    tuple(rd.lower() + "/dev/" for rd in self.col.rootfs_dirs)):
                continue
            host = self.col.host_path(rel)
            if host.startswith("/dev/pts/"):
                continue
            entry = "%-52s %s" % (host, human_size(self.col.size(rel)))
            if host.startswith(("/dev/shm/", "/dev/mqueue/")):
                devtmp.append(entry)
            else:
                devroot.append(entry)
            self.ioc(host, "regular file under /dev")
        if devroot:
            self.add("HIGH", "Filesystem",
                     "%d regular file(s) directly under /dev" % len(devroot),
                     "/dev is a device filesystem: it should contain device "
                     "nodes and symlinks, not files. A regular file here is "
                     "hidden from anyone listing the usual directories.",
                     devroot[:25], source="[root]/dev", count=len(devroot),
                     mitre="T1564 Hide Artifacts")
        if devtmp:
            self.add("MEDIUM", "Filesystem",
                     "%d file(s) staged in /dev/shm or /dev/mqueue" % len(devtmp),
                     "These are tmpfs and can hold files legitimately, but they "
                     "are memory-backed, world-writable and vanish on reboot, "
                     "which is why they are the standard payload drop.",
                     devtmp[:25], source="[root]/dev/shm", count=len(devtmp),
                     mitre="T1074 Data Staged")

        # chkrootkit / other scanner output
        for rel in self.col.glob("chkrootkit/**"):
            if rel.endswith("etc_ld_so_preload.txt"):
                continue
            body = [l.strip() for l in self.col.lines(rel) if l.strip()]
            if body:
                self.add("MEDIUM", "Rootkit", "chkrootkit artifact: %s" % os.path.basename(rel),
                         evidence=body[:25], source=rel, count=len(body))

    # -- 22. deep scan of memory strings -----------------------------------
    DEEP_PATTERNS = [
        (r"/dev/shm/[A-Za-z0-9_./-]+", "path in /dev/shm"),
        (r"ld\.so\.preload", "ld.so.preload reference"),
        (r"(?:\d{1,3}\.){3}\d{1,3}:(?:4444|3333|1337|6666|31337|8888|9001)", "implant port"),
        (r"stratum\+tcp://\S+", "mining pool"),
        # A greedy [A-Za-z0-9_-]{16,} in front of a literal backtracks across every
        # long base64 run in the dump, which makes a multi-GB scan crawl. Onion
        # addresses are base32 (a-z, 2-7) and fixed length: 16 (v2) or 56 (v3).
        (r"[a-z2-7]{16}(?:[a-z2-7]{40})?\.onion\b", "onion address"),
        (r"(?:curl|wget)\s+-[a-zA-Z]*\s*https?://\S+", "download command"),
        (r"bash\s+-i\s+>&\s*/dev/tcp/\S+", "reverse shell"),
        (r"BEGIN (?:RSA|OPENSSH|EC) PRIVATE KEY", "private key material"),
    ]

    def analyze_memory_strings(self):
        if not self.opts.deep:
            return
        src = None
        for cand in self.col.glob("memory_dump/*strings*"):
            src = cand
            break
        if not src:
            return
        total = self.col.size(src)
        status("[*] deep scan of %s (%.1f GB)..." % (src, total / (1024.0 ** 3)))

        # One combined pattern over raw byte chunks. Scanning line by line with a
        # regex per pattern is roughly an order of magnitude slower on a file
        # this size, and the dump is mostly lines we do not care about.
        labels = {}
        alts = []
        for i, (pat, desc) in enumerate(self.DEEP_PATTERNS):
            name = "p%d" % i
            labels[name] = desc
            alts.append(b"(?P<" + name.encode() + b">" + pat.encode() + b")")
        combined = re.compile(b"|".join(alts))

        hits = defaultdict(set)
        real = self.col.resolve(src)
        chunk = 8 * 1024 * 1024
        overlap = b""
        done = 0
        try:
            fh = self.col._open(real)
        except Exception:
            return
        try:
            while True:
                data = fh.read(chunk)
                if not data:
                    break
                done += len(data)
                buf = overlap + data
                for m in combined.finditer(buf):
                    desc = labels.get(m.lastgroup)
                    if desc:
                        hits[desc].add(trunc(m.group(0).decode("utf-8", "replace"), 160))
                overlap = buf[-1024:]        # keep matches that straddle a boundary
                if total and done % (512 * 1024 * 1024) < chunk:
                    print("    ... %d%%" % (100 * done // total), file=sys.stderr)
        finally:
            try:
                fh.close()
            except Exception:
                pass

        for desc, values in hits.items():
            self.add("MEDIUM", "Memory", "Memory strings: %s (%d unique)" % (desc, len(values)),
                     "Recovered from the memory image string dump. Strings carry no "
                     "context - confirm each against process and file artifacts before "
                     "acting on them.",
                     sorted(values)[:40], source=src, count=len(values))

    # -- 23. cross-artifact pivot ------------------------------------------
    # Artifacts a text search should never open: images, archives that are not
    # log rotations, and the memory dump, which --deep covers separately.
    PIVOT_SKIP_EXT = (".png", ".jpg", ".jpeg", ".gif", ".pdf", ".ico", ".so",
                      ".ko", ".pyc", ".db", ".sqlite", ".sqlite3", ".journal",
                      ".zip", ".tar", ".rpm", ".deb", ".img", ".iso", ".lime",
                      ".raw", ".mem", ".vmem", ".core", ".woff", ".woff2",
                      ".ttf", ".jar", ".class")
    PIVOT_MAX_FILE = 256 * 1024 * 1024

    def _pivot_terms(self):
        """--pivot values, expanding '@file' into one term per line."""
        terms = []
        for raw in self.opts.pivot or []:
            if raw.startswith("@"):
                try:
                    with open(raw[1:], encoding="utf-8", errors="replace") as fh:
                        for line in fh:
                            t = line.strip()
                            if t and not t.startswith("#"):
                                terms.append(t)
                except OSError as e:
                    self.add("MEDIUM", "Pivot", "IOC list could not be read",
                             str(e), source=raw[1:])
            else:
                terms.append(raw)
        # auto-pivot on the strongest indicators found so far: anything
        # executing from a temp filesystem, plus every preloaded library
        for t in sorted(self.auto_pivot) + [
                t for t in self.iocs
                if t.startswith("/") and t.startswith(TMPFS_DIRS)]:
            if t not in terms:
                terms.append(t)
        seen, out = set(), []
        for t in terms:
            if t.lower() not in seen:
                seen.add(t.lower())
                out.append(t)
        return out

    def analyze_pivot(self):
        """Search every collected artifact for the given indicators.

        This used to read a hardcoded list of thirteen files, which meant an
        IP address that appeared only in auth.log, an access log or a shell
        history was reported as 'not found' - the one answer a pivot must
        never give wrongly. It now streams every text artifact in the
        collection, compressed log rotations included.

        All terms are matched in a single compiled alternation, so searching
        for four hundred indicators costs one pass over the collection rather
        than four hundred; that is what makes a bulk '@ioc-list.txt' practical.
        Matching is case-insensitive because indicator lists and artifacts
        disagree constantly about the case of hashes and hostnames.
        """
        terms = self._pivot_terms()[: self.opts.pivot_limit]
        if not terms:
            return
        try:
            rx = re.compile("|".join("(%s)" % re.escape(t) for t in terms), re.I)
        except re.error as e:
            self.add("MEDIUM", "Pivot", "Indicator list could not be compiled",
                     str(e))
            return
        hits = defaultdict(list)                  # term index -> evidence
        counts = defaultdict(lambda: defaultdict(int))   # term -> artifact -> n
        spans = defaultdict(lambda: ["", ""])     # term index -> [first, last]
        plen = len(self.col.prefix)
        for low, real in sorted(self.col._names.items(), key=lambda kv: kv[1]):
            if not low.startswith(self.col.prefix):
                continue
            rel = real[plen:]
            rl = rel.lstrip("/").lower()
            if rl.endswith(self.PIVOT_SKIP_EXT) or rl.startswith("memory_dump/"):
                continue
            if self.col._sizes.get(low, 0) > self.PIVOT_MAX_FILE:
                continue
            host = self.col.host_path(rel)
            raw = decompress_bytes(rel, self.col.read_bytes(rel))
            if raw is None:
                continue
            if b"\x00" in raw[:4096]:             # binary, not worth grepping
                continue
            for n, line in enumerate(raw.decode("utf-8", "replace").splitlines(), 1):
                m = rx.search(line)
                if not m:
                    continue
                idx = m.lastindex - 1 if m.lastindex else 0
                counts[idx][host] += 1
                # dated from every hit, not from the sixty kept for evidence:
                # a span taken over a truncated sample is a narrower window
                # than the indicator actually spans, which is the one direction
                # a pivot must not be wrong in
                span_add(spans[idx], self.log_ts(split_log_line(line)[0]))
                if len(hits[idx]) < 60 and counts[idx][host] <= 6:
                    hits[idx].append((host, n, trunc(line.strip(), 200)))
        self.pivot_hits = []
        for idx, term in enumerate(terms):
            ev = hits.get(idx)
            if not ev:
                continue
            total = sum(counts[idx].values())
            self.pivot_stats[term] = (total, spans[idx][0], spans[idx][1])
            for host, n, line in ev:
                self.pivot_hits.append((term, host, n, line))
            self.add("HIGH", "Pivot", "Cross-artifact hits for '%s'" % term,
                     "%d mention(s) in %d artifact(s) - the same indicator "
                     "followed through process, network, log, hash and "
                     "filesystem evidence."
                     % (total, len(counts[idx])),
                     ["%-52s :%-6d %s" % (h, n, l) for h, n, l in ev[:60]],
                     source="(%d artifacts)" % len(counts[idx]), count=total,
                     times=spans[idx])
            self.ioc(term, "pivot")

    # -- run ----------------------------------------------------------------
    def run(self):
        steps = [
            self.analyze_collection,
            self.analyze_accounts,          # populates users/uids/gids first
            self.analyze_kernel_taint,
            self.analyze_ld_preload,
            self.analyze_processes,
            self.analyze_hidden_pids,       # needs the process table
            self.analyze_network,
            self.analyze_suid_sgid,
            self.analyze_logins,
            self.analyze_history,
            self.analyze_persistence,
            self.analyze_ssh,
            self.analyze_modules,
            self.analyze_dmesg,
            self.analyze_bodyfile,          # supplies mode bits for the next check
            self.analyze_filesystem_lists,
            self.analyze_open_files,
            self.analyze_packages,
            self.analyze_hashes,
            self.analyze_logging,
            self.analyze_misc,
            self.analyze_memory_strings,
            self.analyze_pivot,
        ]
        prog = Progress(len(steps), "analyzing", not self.opts.quiet)
        for step in steps:
            prog.step(step.__name__.replace("analyze_", ""))
            try:
                step()
            except Exception as exc:            # never let one artifact kill the run
                if self.opts.debug:
                    raise
                self.add("LOW", "Triage", "Analyzer %s failed: %s" % (step.__name__, exc),
                         "This check was skipped; the rest of the report is unaffected.")
        prog.done()
        self.findings.sort(key=lambda f: (SEV_RANK[f.severity], f.category, f.title))
        self.events.sort(key=lambda e: e.ts)
        return self.findings


# ---------------------------------------------------------------------------
# log decoders: compressed text, utmp/lastlog, and the systemd journal
# ---------------------------------------------------------------------------

_PROGRESS = []                  # the bars currently drawing, outermost first


def status(msg, stream=None):
    """A [*]/[!] line that does not land on top of the progress bar.

    print() straight to stderr while a bar is drawn appends to it, which is how
    '[ 92%] building tables sigma[*] sigma: 407 rule(s) loaded' happens. Erase
    the bar first; the next step() redraws it.
    """
    for p in _PROGRESS:
        p.erase()
    print(msg, file=stream or sys.stderr)


class Progress:
    """A one-line percentage on stderr, rewritten in place.

    Only when stderr is a terminal: redirected to a file, a carriage-return
    progress bar turns one line into thousands and buries the [*] and [!] lines
    that matter. Everything here is cosmetic, so it never raises - a broken
    console must not end a parse that has run for four minutes.

    A nested bar - Sigma runs inside the table build - renders its parent's
    percentage alongside its own, because a bar that reads 92% and then 62% a
    moment later looks like the run went backwards.
    """

    def __init__(self, total, label, enabled=True, stream=None, parent=None):
        self.total = max(1, int(total or 1))
        self.label = label
        self.parent = parent
        self.n = 0
        self.width = 0
        self.stream = stream or sys.stderr
        try:
            self.on = bool(enabled) and self.stream.isatty()
        except Exception:
            self.on = False

    def pct(self):
        return min(100, int(100.0 * self.n / self.total))

    def step(self, name="", n=None):
        self.n = self.n + 1 if n is None else n
        if not self.on:
            return
        if self not in _PROGRESS:
            _PROGRESS.append(self)
        if self.parent is not None and self.parent.on:
            line = "  [%3d%%] %s %s %d%% %s" % (
                self.parent.pct(), self.parent.label, self.label,
                self.pct(), trunc(str(name), 34))
        else:
            line = "  [%3d%%] %s %s" % (self.pct(), self.label,
                                        trunc(str(name), 46))
        try:
            pad = max(0, self.width - len(line))
            self.stream.write("\r" + line + " " * pad)
            self.stream.flush()
            self.width = len(line)
        except Exception:
            self.on = False

    def erase(self):
        """Blank the line but stay live, so status() can print over it."""
        if not self.on or not self.width:
            return
        try:
            self.stream.write("\r" + " " * self.width + "\r")
            self.stream.flush()
            self.width = 0
        except Exception:
            self.on = False

    def done(self):
        if self in _PROGRESS:
            _PROGRESS.remove(self)
        if not self.on:
            return
        self.erase()
        self.on = False


COMPRESSED_EXT = (".gz", ".bz2", ".xz", ".lzma", ".zst", ".zstd", ".lz4")


def zstd_decompress(raw):
    """zstd via the 3.14 stdlib module, else the third-party package, else None."""
    try:
        from compression import zstd          # Python 3.14+
        return zstd.decompress(raw)
    except ImportError:
        pass
    except Exception:
        return None
    try:
        import zstandard
        return zstandard.ZstdDecompressor().decompressobj().decompress(raw)
    except Exception:
        return None


def lz4_block_decompress(src):
    """LZ4 block format - systemd's default journal compression on many distros.

    Pure Python so the script keeps working with no third-party module; journal
    payloads are small enough that speed does not matter here.
    """
    out = bytearray()
    i, n = 0, len(src)
    while i < n:
        token = src[i]; i += 1
        lit = token >> 4
        if lit == 15:
            while i < n:
                c = src[i]; i += 1; lit += c
                if c != 255:
                    break
        out += src[i:i + lit]; i += lit
        if i >= n - 1:
            break
        offset = src[i] | (src[i + 1] << 8); i += 2
        if offset == 0:
            return None
        match = token & 15
        if match == 15:
            while i < n:
                c = src[i]; i += 1; match += c
                if c != 255:
                    break
        match += 4
        start = len(out) - offset
        if start < 0:
            return None
        for k in range(match):
            out.append(out[start + k])
    return bytes(out)


def decompress_bytes(name, raw):
    """Transparently expand a rotated log. Returns None if we cannot."""
    if raw is None:
        return None
    low = name.lower()
    try:
        if low.endswith(".gz") or raw[:2] == b"\x1f\x8b":
            return gzip.decompress(raw)
        if low.endswith(".bz2") or raw[:3] == b"BZh":
            return bz2.decompress(raw)
        if low.endswith((".xz", ".lzma")) or raw[:6] == b"\xfd7zXZ\x00":
            return lzma.decompress(raw)
        if low.endswith((".zst", ".zstd")) or raw[:4] == b"\x28\xb5\x2f\xfd":
            return zstd_decompress(raw)
    except Exception:
        return None
    return raw


# -- utmp / wtmp / btmp ------------------------------------------------------

UTMP_FMT = "<ii32s4s32s256shhiii4i20s"      # Linux x86_64, 384 bytes per record
UTMP_SIZE = struct.calcsize(UTMP_FMT)
UTMP_TYPES = {0: "EMPTY", 1: "RUN_LVL", 2: "BOOT_TIME", 3: "NEW_TIME",
              4: "OLD_TIME", 5: "INIT_PROCESS", 6: "LOGIN_PROCESS",
              7: "USER_PROCESS", 8: "DEAD_PROCESS", 9: "ACCOUNTING"}


def _cstr(b):
    return b.split(b"\x00", 1)[0].decode("utf-8", "replace")


def parse_utmp(raw):
    """Yield dicts from a wtmp/btmp/utmp file."""
    if not raw or len(raw) < UTMP_SIZE:
        return
    for off in range(0, len(raw) - UTMP_SIZE + 1, UTMP_SIZE):
        f = struct.unpack_from(UTMP_FMT, raw, off)
        ut_type, pid, line, uid_str, user, host = f[0], f[1], f[2], f[3], f[4], f[5]
        sec, usec = f[9], f[10]
        addr = f[11:15]
        if ut_type == 0 and not sec:
            continue
        ip = ""
        if addr[0]:
            try:
                ip = str(ipaddress.ip_address(struct.pack("<I", addr[0] & 0xFFFFFFFF)))
            except Exception:
                ip = ""
        yield {
            "type": UTMP_TYPES.get(ut_type, str(ut_type)),
            "pid": pid,
            "line": _cstr(line),
            "id": _cstr(uid_str),
            "user": _cstr(user),
            "host": _cstr(host),
            "ip": ip,
            "time": (datetime.fromtimestamp(sec, timezone.utc) if sec else None),
        }


LASTLOG_FMT = "<i32s256s"                    # ll_time, ll_line, ll_host
LASTLOG_SIZE = struct.calcsize(LASTLOG_FMT)

# struct faillog: short fail_cnt, short fail_max, char fail_line[12],
# time_t fail_time, long fail_locktime. fail_line ends at offset 16, which is
# already 8-aligned, so there is no padding: 32 bytes on 64-bit builds and 24
# on 32-bit ones. The file size decides which layout applies.
FAILLOG_FMT_64 = "<hh12sqq"
FAILLOG_FMT_32 = "<hh12sll"
FAILLOG_SIZE_64 = struct.calcsize(FAILLOG_FMT_64)
FAILLOG_SIZE_32 = struct.calcsize(FAILLOG_FMT_32)


def parse_faillog(raw):
    """faillog is a flat array indexed by uid, like lastlog.

    FOR577 rates it unreliable - it is only written by tools that bother to,
    and it is trivially reset - but a non-zero counter is still a record of
    failed authentication for that account, so it is decoded and labelled.
    """
    if not raw:
        return
    for size, fmt in ((FAILLOG_SIZE_64, FAILLOG_FMT_64),
                      (FAILLOG_SIZE_32, FAILLOG_FMT_32)):
        if len(raw) % size:
            continue
        for uid in range(len(raw) // size):
            cnt, mx, line, when, lock = struct.unpack_from(fmt, raw, uid * size)
            if not cnt and not when:
                continue
            yield {"uid": uid, "count": cnt, "max": mx, "line": _cstr(line),
                   "time": (datetime.fromtimestamp(when, timezone.utc)
                            if 0 < when < (1 << 62) else None),
                   "locktime": lock}
        return


def parse_lastlog(raw):
    """lastlog is a flat array indexed by uid; yields only populated slots."""
    if not raw:
        return
    for uid in range(len(raw) // LASTLOG_SIZE):
        t, line, host = struct.unpack_from(LASTLOG_FMT, raw, uid * LASTLOG_SIZE)
        if not t:
            continue
        yield {"uid": uid, "time": datetime.fromtimestamp(t, timezone.utc),
               "line": _cstr(line), "host": _cstr(host)}


# -- systemd journal ---------------------------------------------------------

JOURNAL_MAGIC = b"LPKSHHRH"
_J_OBJ_DATA, _J_OBJ_ENTRY = 1, 3
_J_INC_COMPACT = 16
_J_OF_XZ, _J_OF_LZ4, _J_OF_ZSTD = 1, 2, 4

SYSLOG_PRIORITY = {0: "emerg", 1: "alert", 2: "crit", 3: "err", 4: "warning",
                   5: "notice", 6: "info", 7: "debug"}


def parse_journal(raw):
    """Decode a binary systemd journal file into entry dicts.

    Walks the object arena directly rather than following the entry-array
    chain: a truncated or actively-written journal (the '.journal~' rotations
    UAC copies) still yields every entry object that made it to disk.
    Returns (entries, stats).
    """
    stats = {"entries": 0, "undecodable_fields": 0, "compression": set()}
    if not raw or raw[:8] != JOURNAL_MAGIC or len(raw) < 272:
        return [], stats
    incompatible = struct.unpack_from("<I", raw, 12)[0]
    header_size = struct.unpack_from("<Q", raw, 88)[0]
    compact = bool(incompatible & _J_INC_COMPACT)
    n = len(raw)
    # DATA object: header(16) + hash,next_hash,next_field,entry,entry_array,
    # n_entries (6 x le64), plus 2 x le32 tail-entry-array fields when COMPACT
    data_skip = 16 + 8 * 6 + (8 if compact else 0)

    def payload(off):
        if off <= 0 or off + 16 > n:
            return None
        if raw[off] != _J_OBJ_DATA:
            return None
        flags = raw[off + 1]
        size = struct.unpack_from("<Q", raw, off + 8)[0]
        if size < data_skip or off + size > n:
            return None
        blob = raw[off + data_skip: off + size]
        if flags & _J_OF_ZSTD:
            stats["compression"].add("zstd")
            return zstd_decompress(blob)
        if flags & _J_OF_XZ:
            stats["compression"].add("xz")
            try:
                return lzma.decompress(blob)
            except Exception:
                return None
        if flags & _J_OF_LZ4:
            stats["compression"].add("lz4")
            return lz4_block_decompress(blob[8:]) if len(blob) >= 8 else None
        return blob

    entries = []
    off = header_size
    while off + 16 <= n:
        otype = raw[off]
        size = struct.unpack_from("<Q", raw, off + 8)[0]
        if size < 16 or off + size > n:
            break
        if otype == _J_OBJ_ENTRY:
            realtime = struct.unpack_from("<Q", raw, off + 24)[0]
            # seqnum(8) realtime(8) monotonic(8) boot_id(16) xor_hash(8)
            items_at = off + 16 + 48
            item_size = 4 if compact else 16
            fields = {}
            for k in range((off + size - items_at) // item_size):
                at = items_at + k * item_size
                doff = (struct.unpack_from("<I", raw, at)[0] if compact
                        else struct.unpack_from("<Q", raw, at)[0])
                p = payload(doff)
                if p is None:
                    stats["undecodable_fields"] += 1
                    continue
                key, sep, val = p.partition(b"=")
                if sep:
                    fields[key.decode("utf-8", "replace")] = \
                        val.decode("utf-8", "replace")
            if fields:
                fields["__REALTIME"] = realtime
                entries.append(fields)
                stats["entries"] += 1
        off += (size + 7) & ~7          # objects are 8-byte aligned
    return entries, stats


# 'Mar 24 15:47:28 host proc[123]: message' or an ISO variant
SYSLOG_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}[T ]\S+)\s+"
    r"(?P<host>\S+)\s+(?P<proc>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$")

# the installer and busybox syslogd omit the hostname: 'Mar 24 15:47:28 proc: msg'
SYSLOG_NOHOST_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}[T ]\S+)\s+"
    r"(?P<proc>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$")

# dpkg.log and friends: 'YYYY-MM-DD HH:MM:SS rest of line'
ISO_TS_RE = re.compile(r"^(?P<ts>\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d)\s+(?P<msg>.*)$")

# 'update-alternatives 2026-03-24 15:48:15: run with ...'
TOOL_TS_RE = re.compile(
    r"^(?P<proc>\S+)\s+(?P<ts>\d{4}-\d\d-\d\d\s+\d\d:\d\d:\d\d):\s*(?P<msg>.*)$")

# boot.log banner: '------------ Tue Mar 24 11:53:47 EDT 2026 ------------'
BANNER_TS_RE = re.compile(
    r"^-{3,}\s*(?P<ts>\w{3}\s+\w{3}\s+\d{1,2}\s+\d\d:\d\d:\d\d\s+\S*\s*\d{4})\s*-{3,}$")

# 'Log started: 2026-03-24  15:48:35' in apt/term.log
LOGSTART_RE = re.compile(r"^(?P<msg>Log (?:started|ended)):\s*(?P<ts>.+)$")

# cups: 'E [24/Mar/2026:19:16:30 -0400] message'
CUPS_RE = re.compile(
    r"^(?P<level>[EWIDN])\s+\[(?P<ts>\d{2}/\w{3}/\d{4}:\d\d:\d\d:\d\d\s*[+-]?\d*)\]"
    r"\s*(?P<msg>.*)$")
CUPS_LEVELS = {"E": "error", "W": "warning", "I": "info", "D": "debug",
               "N": "notice"}

# common / combined access log
ACCESS_RE = re.compile(
    r'^(?P<host>\S+)\s+(?P<ident>\S+)\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<req>[^"]*)"\s+(?P<status>\d{3})\s+(?P<size>\S+)')


def split_log_line(ln):
    """Best-effort (timestamp, host, process, pid, message) for one log line.

    Tried most-specific first. Falls back to the raw line with an empty
    timestamp rather than guessing, so an unmatched row is visibly unmatched.
    """
    m = SYSLOG_RE.match(ln)
    if m:
        return (m.group("ts"), m.group("host"), m.group("proc"),
                m.group("pid") or "", m.group("msg"))
    a = ACCESS_RE.match(ln)
    if a:
        return (a.group("ts"), a.group("host"), "http", "",
                "%s -> %s (%s bytes) user=%s" % (a.group("req"), a.group("status"),
                                                 a.group("size"), a.group("user")))
    m = CUPS_RE.match(ln)
    if m:
        return (m.group("ts"), "", CUPS_LEVELS.get(m.group("level"), m.group("level")),
                "", m.group("msg"))
    m = TOOL_TS_RE.match(ln)
    if m:
        return m.group("ts"), "", m.group("proc"), "", m.group("msg")
    m = SYSLOG_NOHOST_RE.match(ln)
    if m:
        return (m.group("ts"), "", m.group("proc"), m.group("pid") or "",
                m.group("msg"))
    m = BANNER_TS_RE.match(ln)
    if m:
        return m.group("ts"), "", "", "", ln.strip()
    m = LOGSTART_RE.match(ln)
    if m:
        return m.group("ts"), "", "", "", m.group("msg")
    m = ISO_TS_RE.match(ln)
    if m:
        return m.group("ts"), "", "", "", m.group("msg")
    return "", "", "", "", ln.rstrip()


# ---------------------------------------------------------------------------
# artifact tables - normalise every interesting artifact into a browsable grid
# ---------------------------------------------------------------------------

_XML_BAD = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


_SPILL_DIR = []                 # one temp dir per process, made on first spill


def _spill_dir():
    if not _SPILL_DIR:
        d = tempfile.mkdtemp(prefix="linsight_rows_")
        _SPILL_DIR.append(d)
        # registered rather than cleaned up by the caller: the run can end at a
        # SystemExit from any of the output checks, and a few hundred MB of
        # row spill left in the temp directory is a bug an examiner finds
        # weeks later on a full disk
        atexit.register(shutil.rmtree, d, True)
    return _SPILL_DIR[0]


class Table:
    """One normalised artifact grid: a CSV file, a JSON key, an Excel sheet.

    Rows spill to disk once a table gets large. A web server's collection puts
    3.3 million rows in these tables - a million of them in VAR_LOG alone - and
    holding every one in memory while the rules, then four writers, each take
    their turn is what drove the process past 2 GB. Small tables never spill,
    because the file would cost more than the list.

    Consumers must iterate `iter_rows()` rather than touch `.rows`, which is
    only ever the unflushed tail once a table has spilled.
    """

    # Off by default, enabled by --low-memory. Measured on the Apache
    # collection: spilling holds the run to 802 MB instead of 1,805 MB, and
    # costs 45s of the 220s run because every writer then re-reads and
    # re-parses each row from disk. On a workstation 1.8 GB is unremarkable
    # and the time matters more; on a constrained box the reverse is true, so
    # it is a switch rather than a default.
    #
    # Overridable from the environment so the equivalence test can force every
    # table through the spill path: a code path that only runs on collections
    # too big to test with is a code path nobody has tested.
    SPILL_NEVER = 10 ** 12
    SPILL_AFTER = int(os.environ.get("LINSIGHT_SPILL_AFTER", SPILL_NEVER))
    SPILL_CHUNK = int(os.environ.get("LINSIGHT_SPILL_CHUNK", 4000))

    def __init__(self, name, title, columns, category="", description="", sources=None):
        self.name = name                  # sheet / file name, <=31 chars, unique
        self.title = title
        self.columns = list(columns)
        self.category = category
        self.description = description
        self.sources = list(sources or [])
        self.rows = []
        self._count = 0
        self._spill_path = None

    def add(self, *values):
        """Append a row, padded / truncated to the column count."""
        row = list(values)
        if len(row) < len(self.columns):
            row += [""] * (len(self.columns) - len(row))
        self.rows.append([("" if v is None else v) for v in row[: len(self.columns)]])
        self._count += 1
        if len(self.rows) >= self.SPILL_CHUNK and self._count > self.SPILL_AFTER:
            self._flush()

    def add_dict(self, mapping):
        self.add(*[mapping.get(c, "") for c in self.columns])

    def drop_empty_columns(self, keep=()):
        """Drop the columns no row in this collection filled.

        A column list is what the tool can parse, not what the host collected.
        A UAC profile that never ran modinfo leaves twelve of KERNEL_MODULES'
        eighteen columns blank in every row, and a heading with nothing under
        it reads as an artifact that was collected and came back empty - which
        is a different and much more interesting statement than "this host
        never collected that". Call it once, after the last row is added.
        """
        rows = list(self.iter_rows())
        used = set(keep)
        for r in rows:
            for i, v in enumerate(r[: len(self.columns)]):
                if _s(v).strip():
                    used.add(self.columns[i])
        if len(used) >= len(self.columns):
            return
        idx = [i for i, c in enumerate(self.columns) if c in used]
        self.columns = [self.columns[i] for i in idx]
        # rebuilt through add() so a spilled table stays spilled rather than
        # being pulled back into memory by the tidying
        if self._spill_path:
            try:
                os.remove(self._spill_path)
            except OSError:
                pass
            self._spill_path = None
        self.rows, self._count = [], 0
        for r in rows:
            self.add(*[r[i] for i in idx])

    def _flush(self):
        """Append the buffered rows to this table's spill file.

        Rows are stored as JSON arrays of display strings: `_s` is what every
        writer applies anyway, and JSON survives the embedded newlines, tabs
        and quotes that log lines are full of without a quoting scheme of our
        own.
        """
        if not self.rows:
            return
        if self._spill_path is None:
            self._spill_path = os.path.join(
                _spill_dir(), "%s_%d.jsonl" % (re.sub(r"\W+", "_", self.name),
                                               id(self)))
        with open(self._spill_path, "a", encoding="utf-8") as fh:
            for row in self.rows:
                fh.write(json.dumps([_s(v) for v in row],
                                    ensure_ascii=False) + "\n")
        self.rows = []

    def iter_rows(self):
        """Every row, from disk then memory - the only supported way to read."""
        if self._spill_path is None:
            for row in self.rows:
                yield row
            return
        self._flush()                 # so the tail is on disk and order holds
        with open(self._spill_path, encoding="utf-8") as fh:
            for ln in fh:
                if ln.strip():
                    yield json.loads(ln)

    def __len__(self):
        return self._count

    def as_dict(self, limit=None):
        rows = (list(self.iter_rows()) if limit is None
                else list(itertools.islice(self.iter_rows(), limit)))
        return {
            "name": self.name,
            "title": self.title,
            "category": self.category,
            "description": self.description,
            "sources": self.sources,
            "columns": self.columns,
            # self._count, not len(self.rows): once a table has spilled, the
            # list is only the unflushed tail, and iterating above emptied it -
            # so this reported every large table as having no rows at all while
            # still shipping them
            "row_count": self._count,
            "rows_included": len(rows),
            "rows": [[_s(v) for v in r] for r in rows],
        }


def _s(v):
    """Cell -> display string."""
    if v is None:
        return ""
    if isinstance(v, datetime):
        return v.strftime("%Y-%m-%d %H:%M:%S")
    return v if isinstance(v, str) else str(v)


def _mode_from_bodyfile(mode):
    """'drwxr-xr-x' style string straight from the bodyfile."""
    return mode or ""


class TableBuilder:
    """Turns a Collection into ~45 normalised tables.

    Every extractor is independent and failure-tolerant, exactly like the
    analyzers: a malformed artifact costs that one table, never the export.
    Files consumed by an extractor are recorded so FILE_INVENTORY can flag
    whatever nothing understood - that is the list worth eyeballing by hand.
    """

    def __init__(self, col, tri):
        self.col = col
        self.tri = tri
        self.tables = []
        self.consumed = {}            # lowercase rel name -> table name
        self.scope = "full"           # set by build(); see LIVE_EXTRACTORS
        self.rule_errors = []         # (engine, rule, reason) for RULE_ERRORS
        self.timings = []             # (label, seconds, rows) when --timing
        self.progress = Progress(1, "", False)
        self._gid_names = None        # lazily built gid -> group name
        self._exe_hash_map = None     # lazily built path -> {md5, sha1, sha256}
        self._proc_merged = None      # t_process_master's join, reused by the tree

    # -- plumbing -----------------------------------------------------------
    def table(self, name, title, columns, category="", description="", sources=None):
        t = Table(name, title, columns, category, description, sources)
        self.tables.append(t)
        return t

    def use(self, rel, table_name):
        if rel:
            key = rel.lstrip("/").lower()
            prev = self.consumed.get(key)
            self.consumed[key] = table_name if not prev else "%s; %s" % (prev, table_name)

    def lines(self, rel, table_name, skip=0):
        """Read a file, mark it consumed, return its lines."""
        self.use(rel, table_name)
        ln = self.col.lines(rel)
        return ln[skip:] if skip else ln

    def ts_utc(self, text):
        """Log timestamp -> UTC string. The rule lives on Triage.log_ts, which
        the analyzers need too - both layers must date a line identically."""
        return self.tri.log_ts(text)

    @staticmethod
    def row_time_index(cols):
        """Index of a built table's own event-time column, or -1.

        Wider than NDJSON_TIME_COLUMNS, and read at call time because that
        tuple is defined further down beside the writer that owns it: a file's
        mtime is exactly the time wanted when dating one row of BODYFILE or
        SUID_SGID, while it is not the event time an export should key a whole
        table on.
        """
        for name in NDJSON_TIME_COLUMNS + ("mtime_utc", "ctime_utc"):
            if name in cols:
                return cols.index(name)
        return -1

    def text(self, rel, table_name):
        self.use(rel, table_name)
        return self.col.text(rel) or ""

    # -- cross-source enrichment -------------------------------------------
    # Half the artifacts identify a thing by a bare number - a pid, a uid, a
    # gid - which is unreadable on its own and unjoinable without opening
    # another table. These resolve the number once so every table can carry the
    # name beside it.
    def _procs(self):
        if not self.tri.processes:
            self.tri._parse_process_tables()
        return self.tri.processes

    def proc_of(self, pid):
        """pid -> {name, exe, user, container, args} as far as anything knows."""
        p = self._procs().get(str(pid) if pid is not None else "", {})
        if not p:
            return {}
        exe = (p.get("exe") or "").split(" (deleted)")[0]
        name = os.path.basename(exe)
        if not name:
            args = (p.get("args") or "").split()
            name = os.path.basename(args[0]).strip("[]():") if args else ""
        return {"name": name, "exe": p.get("exe", ""),
                "user": p.get("user") or p.get("owner", ""),
                "container": p.get("container", ""),
                "args": p.get("args", "")}

    def uid_name(self, uid):
        """uid -> username, or '' when it resolves to no account."""
        u = str(uid).strip()
        if not u.isdigit():
            return ""
        return (self.tri.uids or {}).get(int(u), "")

    def gid_name(self, gid):
        g = str(gid).strip()
        if not g.isdigit():
            return ""
        if self._gid_names is None:
            names = {}
            grel = self.col.rootfs("/etc/group")
            for ln in self.col.lines(grel) if grel else []:
                f = ln.split(":")
                if len(f) >= 3 and f[2].isdigit():
                    names[int(f[2])] = f[0]
            self._gid_names = names
        return self._gid_names.get(int(g), "")

    def running_pids_for(self, command):
        """Which live processes, if any, are running this command line.

        Turns a persistence entry from "something that would run" into
        "something that is running right now", which is the difference between
        a lead and a live compromise.
        """
        cmd = (command or "").strip()
        if not cmd:
            return ""
        first = cmd.split()[0].lstrip("-@+!:")
        base = os.path.basename(first)
        if not base or base in ("sh", "bash", "true", "false", "test", "["):
            return ""
        hits = []
        for pid, p in self._procs().items():
            args = p.get("args") or ""
            exe = (p.get("exe") or "").split(" (deleted)")[0]
            if args.startswith("["):
                continue
            if first == exe or first in args.split() or \
                    (base and os.path.basename(exe) == base):
                hits.append(pid)
        return ",".join(sorted(hits, key=lambda p: int(p) if p.isdigit() else 0))

    # -- generic shapes -----------------------------------------------------
    def kv_table(self, name, title, specs, category="", description="", sep="="):
        """`key <sep> value` files -> (source, key, value).

        sep may be a tuple: the separator that appears first in the line wins,
        so one table can hold both 'key: value' command output and 'key=value'
        config files without mangling either.
        """
        seps = (sep,) if isinstance(sep, str) else tuple(sep)
        t = self.table(name, title, ["source", "key", "value"], category, description,
                       [r for r, _ in specs])
        for rel, label in specs:
            for ln in self.lines(rel, name):
                if not ln.strip() or ln.lstrip().startswith(("#", ";")):
                    continue
                at = [(ln.index(s), s) for s in seps if s in ln]
                if at:
                    _, s = min(at)
                    k, v = ln.split(s, 1)
                    t.add(label, k.strip(), v.strip())
                else:
                    t.add(label, ln.strip(), "")
        return t

    def raw_table(self, name, title, rels, category="", description=""):
        """Anything with no better structure -> (source, line_no, text)."""
        t = self.table(name, title, ["source", "line_no", "text"], category,
                       description, list(rels))
        for rel in rels:
            for i, ln in enumerate(self.lines(rel, name), 1):
                if ln.strip():
                    t.add(os.path.basename(rel), i, ln.rstrip())
        return t

    # -- 1. collection / inventory -----------------------------------------
    def t_metadata(self):
        t = self.table("METADATA", "Collection and host metadata", ["key", "value"],
                       "Collection",
                       "Header facts about the collection and the host it came "
                       "from - uac.log and live_response under UAC, "
                       "collection_context.json plus what the artifacts and the "
                       "filesystem copy state under Velociraptor.",
                       ["uac.log", "collection_context.json"])
        for k, v in self.tri.meta.items():
            if v:
                t.add(k, v)
        # UAC stamps the clock immediately before each snapshot command; that is
        # the reference every relative age in the export is measured against
        for rel in sorted(self.col.glob("live_response/*/date_before_*.txt")) + \
                sorted(self.col.glob("live_response/*/date_after_*.txt")):
            val = (self.text(rel, "METADATA") or "").strip().splitlines()
            if val:
                t.add("Host clock at %s" % os.path.basename(rel)
                      .replace(".txt", ""), val[0])
        # claimed here, not in t_velo_results: the analyzers read these in every
        # scope, and claiming them from a live-tagged extractor left them
        # looking unparsed under --scope offline
        for rel in self.VELO_BOOKKEEPING:
            if self.col.exists(rel):
                self.use(rel, "METADATA")
        t.add("Collection path", self.col.path)
        t.add("Collection kind", self.col.kind)
        t.add("Collection layout", self.col.layout)
        t.add("Files in collection", len(self.col._names))
        t.add("Rootfs dirs", ", ".join(self.col.rootfs_dirs))
        # an export that holds half the collection has to say so on its face -
        # otherwise a missing PROCESSES table reads as a host with no processes
        t.add("Table scope", self.scope + ("" if self.scope == "full" else
                                           " (partial export)"))
        t.add("Triage tool version", VERSION)

    def t_collection_log(self):
        t = self.table("COLLECTION_LOG", "uac.log entries",
                       ["timestamp_utc", "timestamp_host", "utc_offset", "level",
                        "message"],
                       "Collection", "Every line UAC logged while collecting, "
                       "with the host's local stamp normalised to UTC so the "
                       "collection itself sits on the same timeline as the "
                       "evidence.", ["uac.log"])
        ts_re = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) ([+-]\d{4}) (\w{3}) (.*)$")
        for ln in self.lines("uac.log", "COLLECTION_LOG"):
            m = ts_re.match(ln)
            if m:
                t.add(norm_log_ts(m.group(1), _tz_delta(m.group(2))),
                      m.group(1), m.group(2), m.group(3), m.group(4))
            elif ln.strip():
                t.add("", "", "", "", ln.rstrip())

    def t_findings(self):
        t = self.table("FINDINGS", "Triage findings",
                       ["severity", "category", "title", "mitre", "artifact",
                        "count", "first_utc", "last_utc",
                        "detail", "evidence_count", "evidence"],
                       "Analysis", "The findings produced by the analyzers.")
        for f in self.tri.findings:
            ev = f.evidence or []
            t.add(f.severity, f.category, f.title, f.mitre, f.source,
                  f.count, f.first_seen, f.last_seen,
                  f.detail.replace("\n", " | "), len(ev), "\n".join(_s(e) for e in ev))

    def t_timeline(self):
        t = self.table("TIMELINE", "Normalised event timeline",
                       ["timestamp_utc", "severity", "category", "description", "source"],
                       "Analysis", "All dated events, every clock normalised to UTC.")
        for e in self.tri.events:
            t.add(e.ts, e.severity, e.category, e.description, e.source)

    def t_iocs(self):
        t = self.table("IOCS", "Extracted indicators",
                       ["indicator", "seen_in_count", "seen_in"], "Analysis",
                       "Indicators the analyzers pulled out, with where they appeared.")
        for val, where in sorted(self.tri.iocs.items()):
            t.add(val, len(where), "; ".join(sorted(where)))

    def t_file_inventory(self):
        """Every file in the collection - the 'did anything get missed' table."""
        t = self.table("FILE_INVENTORY", "Every file in the collection",
                       ["path", "host_path", "top_level", "category", "size_bytes",
                        "size_human", "parsed_into"],
                       "Collection",
                       "One row per collected file, with the table that parsed "
                       "it. Under a narrowed --scope, parsed_into says so for "
                       "the half that was not read - an empty cell always means "
                       "'offered to every extractor and taken by none'.")
        plen = len(self.col.prefix)
        rootfs = tuple(rd + "/" for rd in self.col.rootfs_dirs)
        for low, real in sorted(self.col._names.items(), key=lambda kv: kv[1]):
            if not low.startswith(self.col.prefix):
                continue
            rel = real[plen:]
            rel_low = rel.lstrip("/").lower()
            size = self.col._sizes.get(low, 0)
            top = rel.split("/", 1)[0] if "/" in rel else rel
            if rel_low.startswith(rootfs):
                cat, host = "host filesystem copy", self.col.host_path(rel)
            else:
                cat, host = "command output", ""
            into = self.consumed.get(rel_low, "")
            if not into and self.scope != "full":
                ps = self.path_scope(rel, host or rel)
                if ps and ps != self.scope:
                    into = "not read under --scope %s" % self.scope
            t.add(rel, host, top, cat, size, human_size(size), into)

    # -- 2. processes -------------------------------------------------------
    def t_processes(self):
        t = self.table("PROCESSES", "Process table (merged)",
                       ["pid", "ppid", "user", "owner", "group", "start_utc",
                        "exe", "exe_source", "cwd", "cwd_source", "container",
                        "cgroup", "args"],
                       "Process",
                       "Merged from every ps_* output. exe is resolved from the "
                       "best source the collection has - the /proc/<pid>/exe "
                       "link, an lsof txt descriptor, the first executable "
                       "mapping in maps, the journal's _EXE for this boot, or "
                       "argv[0] as a last resort - and exe_source names which, "
                       "because argv[0] is attacker-controlled and a symlink "
                       "target is not. An empty exe on a [bracketed] process is "
                       "correct: kernel threads have no binary.",
                       ["live_response/process/ps_*.txt",
                        "live_response/process/running_processes_full_paths.txt"])
        for rel in self.col.glob("live_response/process/ps*.txt"):
            self.use(rel, "PROCESSES")
        # the 2021 profiles spell it 'ls -la', later ones 'ls -l' - glob rather
        # than name it, or the directory listing goes unclaimed on one of them
        for rel in (["live_response/process/running_processes_full_paths.txt"]
                    + self.col.glob("live_response/process/ls_-l*_proc*.txt")):
            self.use(rel, "PROCESSES")
        if not self.tri.processes:
            self.tri._parse_process_tables()
        # claimed here rather than where the rows are read: the analyzers parse
        # the process table in every scope, and claiming there would report a
        # PROCESSES table that --scope offline never built
        if self.col.velo and self.tri.processes:
            self._velo_claim(self.col.velo, Triage.VELO_PROCESS_ARTIFACTS, t)
        for pid, p in sorted(self.tri.processes.items(),
                             key=lambda kv: int(kv[0]) if kv[0].isdigit() else 0):
            t.add(pid, p.get("ppid", ""), p.get("user", ""), p.get("owner", ""),
                  p.get("group", ""), p.get("start"), p.get("exe", ""),
                  p.get("exe_source", ""), p.get("cwd", ""),
                  p.get("cwd_source", ""), p.get("container", ""),
                  p.get("cgroup", ""), p.get("args", ""))

    def t_ps_raw(self):
        """Each ps variant kept verbatim - column layouts differ and that matters."""
        t = self.table("PS_RAW", "ps output, every variant",
                       ["source", "line_no", "text"], "Process",
                       "Verbatim ps output so nothing is lost to the merge.")
        for rel in self.col.glob("live_response/process/ps*.txt") + \
                   self.col.glob("live_response/process/top*.txt"):
            for i, ln in enumerate(self.lines(rel, "PS_RAW"), 1):
                if ln.strip():
                    t.add(os.path.basename(rel), i, ln.rstrip())

    def t_proc_pid(self):
        """One row per /proc/<pid> directory UAC captured."""
        t = self.table("PROC_PID", "/proc/<pid> per-process detail",
                       ["pid", "name", "state", "ppid", "uid_real", "user",
                        "gid_real", "group", "threads", "vm_rss_kb", "cmdline",
                        "comm", "exe", "cwd", "container", "fd_count",
                        "has_environ", "has_maps", "captured_files", "note"],
                       "Process",
                       "Parsed from live_response/process/proc/<pid>/*. A row "
                       "with no status/cmdline is not a parse gap - it is a PID "
                       "whose /proc entry resisted collection.")
        pids = {}
        for rel in self.col.glob("live_response/process/proc/**"):
            parts = rel.split("/")
            try:
                pid = parts[parts.index("proc") + 1]
            except (ValueError, IndexError):
                continue
            pids.setdefault(pid, []).append(rel)
        for pid in sorted(pids, key=lambda p: int(p) if p.isdigit() else 0):
            files = pids[pid]
            base = "live_response/process/proc/%s" % pid
            for rel in files:
                self.use(rel, "PROC_PID")
            st = {}
            for ln in self.col.lines("%s/status.txt" % base):
                if ":" in ln:
                    k, v = ln.split(":", 1)
                    st[k.strip()] = v.strip()
            cmdline = (self.col.text("%s/cmdline.txt" % base) or "").replace("\x00", " ").strip()
            comm = (self.col.text("%s/comm.txt" % base) or "").strip()
            exe = cwd = ""
            for ln in self.col.lines("%s/fd.txt" % base):
                pass
            fd_lines = [l for l in self.col.lines("%s/fd.txt" % base)
                        if " -> " in l]
            p = self.tri.processes.get(pid, {})
            exe = p.get("exe", "")
            cwd = p.get("cwd", "")
            uid = (st.get("Uid", "").split() or [""])[0]
            gid = (st.get("Gid", "").split() or [""])[0]
            notes = []
            if not st:
                notes.append("no status.txt captured")
            if not cmdline and not comm:
                notes.append("no cmdline/comm")
            if pid in self.tri.hidden_pids:
                notes.append("HIDDEN: in /proc but absent from ps")
            i = self.proc_of(pid)
            t.add(pid, st.get("Name", comm), st.get("State", ""), st.get("PPid", ""),
                  uid, self.uid_name(uid) or i.get("user", ""),
                  gid, self.gid_name(gid), st.get("Threads", ""),
                  (st.get("VmRSS", "").split() or [""])[0], cmdline, comm,
                  exe or i.get("exe", ""), cwd, i.get("container", ""),
                  len(fd_lines), "yes" if self.col.exists("%s/environ.txt" % base) else "",
                  "yes" if self.col.exists("%s/maps.txt" % base) else "",
                  len(files), "; ".join(notes))

    def t_proc_maps(self):
        """Mapped files per process - where injected libraries show up."""
        t = self.table("PROC_MAPS", "Process memory maps",
                       ["pid", "process", "user", "container", "address_range",
                        "perms", "offset", "device", "inode", "path", "source"],
                       "Process",
                       "/proc/<pid>/maps for every captured process, with the "
                       "process named - a bare pid cannot be triaged and does "
                       "not survive being sorted by path.")
        rx = re.compile(r"^([0-9a-f]+-[0-9a-f]+)\s+(\S{4})\s+(\S+)\s+(\S+)\s+(\d+)\s*(.*)$")
        for rel in self.col.glob("live_response/process/proc/*/maps.txt"):
            parts = rel.split("/")
            try:
                pid = parts[parts.index("proc") + 1]
            except (ValueError, IndexError):
                continue
            i = self.proc_of(pid)
            for ln in self.lines(rel, "PROC_MAPS"):
                m = rx.match(ln.strip())
                if m:
                    t.add(pid, i.get("name", ""), i.get("user", ""),
                          i.get("container", ""), m.group(1), m.group(2),
                          m.group(3), m.group(4), m.group(5),
                          m.group(6).strip(), rel)

    def t_proc_environ(self):
        t = self.table("PROC_ENVIRON", "Process environment variables",
                       ["pid", "process", "user", "container", "variable",
                        "value", "source"], "Process",
                       "/proc/<pid>/environ - LD_PRELOAD and friends live here.")
        for rel in self.col.glob("live_response/process/proc/*/environ.txt"):
            parts = rel.split("/")
            try:
                pid = parts[parts.index("proc") + 1]
            except (ValueError, IndexError):
                continue
            i = self.proc_of(pid)
            raw = self.text(rel, "PROC_ENVIRON")
            for item in raw.replace("\x00", "\n").splitlines():
                if "=" in item:
                    k, v = item.split("=", 1)
                    t.add(pid, i.get("name", ""), i.get("user", ""),
                          i.get("container", ""), k.strip(), v.strip(), rel)

    def t_proc_fds(self):
        t = self.table("PROC_FD", "Per-process file descriptors",
                       ["pid", "process", "user", "container", "fd", "mode",
                        "fd_owner", "target", "source"], "Process",
                       "ls -l of /proc/<pid>/fd for every captured process.")
        rx = re.compile(r"^(\S+)\s+\d+\s+(\S+)\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+"
                        r"(\S+)\s+->\s+(.*)$")
        for rel in self.col.glob("live_response/process/proc/*/fd.txt"):
            parts = rel.split("/")
            try:
                pid = parts[parts.index("proc") + 1]
            except (ValueError, IndexError):
                continue
            i = self.proc_of(pid)
            for ln in self.lines(rel, "PROC_FD"):
                m = rx.match(ln.strip())
                if m:
                    t.add(pid, i.get("name", ""), i.get("user", ""),
                          i.get("container", ""), m.group(3), m.group(1),
                          m.group(2), m.group(4).strip(), rel)

    def t_process_master(self):
        """One row per PID correlating every process artifact.

        The per-artifact tables each hold one slice of a process; the answer to
        "what is PID 939 and should I care" needs all of them at once. Deliberately
        excludes pstree, whose value is the drawing, not the columns.
        """
        t = self.table("PROCESS_MASTER", "Correlated process view (one row per PID)",
                       ["pid", "ppid", "parent", "user", "uid", "gid", "state",
                        "comm", "exe", "exe_source", "exe_deleted", "cwd",
                        "cmdline",
                        "start_utc", "elapsed", "cpu_pct", "mem_pct", "rss_kb",
                        "vsz_kb", "threads", "tty", "stat", "container", "cgroup",
                        "md5", "sha1", "fd_count", "fd_deleted", "fd_sockets",
                        "fd_tmpfs", "maps_count", "maps_nonsystem", "ld_preload",
                        "env_count", "socket_count", "listening", "peers",
                        "open_files", "hidden", "flags", "sources"],
                       "Process",
                       "Every process artifact joined on PID: ps variants, "
                       "/proc/<pid>/{status,cmdline,environ,fd,maps}, exe hashes, "
                       "lsof and ss. Excludes pstree.")

        if not self.tri.processes:
            self.tri._parse_process_tables()
        procs = {}

        def rec(pid):
            return procs.setdefault(str(pid), {"src": set()})

        for pid, p in self.tri.processes.items():
            r = rec(pid)
            r.update({k: v for k, v in p.items() if v not in (None, "")})
            r["src"].add("ps")

        # ps auxwww: %CPU %MEM VSZ RSS TTY STAT
        for ln in self.col.lines("live_response/process/ps_auxwww.txt")[1:]:
            f = ln.split(None, 10)
            if len(f) >= 11 and f[1].isdigit():
                r = rec(f[1])
                r.update({"cpu": f[2], "mem": f[3], "vsz": f[4], "rss": f[5],
                          "tty": f[6], "stat": f[7]})
                r.setdefault("user", f[0])
                r.setdefault("args", f[10].strip())
                r["src"].add("ps_auxwww")

        # elapsed time since start - `ps -eo` on a pre-2022 profile
        for rel in ("live_response/process/ps_-axo_pid_user_etime_args.txt",
                    "live_response/process/ps_-eo_pid_user_etime_args.txt"):
            for ln in self.col.lines(rel)[1:]:
                f = ln.split(None, 3)
                if len(f) >= 3 and f[0].isdigit():
                    r = rec(f[0])
                    r["etime"] = f[2]
                    r.setdefault("user", f[1])
                    if len(f) > 3:
                        r.setdefault("args", f[3].strip())
                    r["src"].add("ps_etime")

        # cgroup: containerised or unit-owned processes
        for rel in ("live_response/process/ps_-axo_pid_user_cgroup.txt",
                    "live_response/process/ps_-eo_pid_user_cgroup.txt"):
            for ln in self.col.lines(rel)[1:]:
                f = ln.split(None, 2)
                if len(f) >= 3 and f[0].isdigit():
                    r = rec(f[0])
                    r.setdefault("user", f[1])
                    cg = f[2].strip()
                    if cg and cg != "-":
                        r["cgroup"] = cg
                    r["src"].add("ps_cgroup")

        # ps -efl: F S UID PID PPID C PRI NI ADDR SZ WCHAN STIME TTY TIME CMD
        for ln in self.col.lines("live_response/process/ps_-efl.txt")[1:]:
            f = ln.split(None, 14)
            if len(f) >= 5 and f[3].isdigit():
                r = rec(f[3])
                r.setdefault("sstate", f[1])
                r.setdefault("user", f[2])
                r.setdefault("ppid", f[4])
                if len(f) > 14:
                    r.setdefault("args", f[14].strip())
                r["src"].add("ps_efl")

        # top gives a second opinion on cpu/mem
        seen_hdr = False
        for ln in self.col.lines("live_response/process/top_-b_-n1.txt"):
            f = ln.split(None, 11)
            if not seen_hdr:
                seen_hdr = ln.lstrip().startswith("PID ")
                continue
            if len(f) >= 12 and f[0].isdigit():
                r = rec(f[0])
                r.setdefault("cpu", f[8])
                r.setdefault("mem", f[9])
                r.setdefault("user", f[1])
                # top truncates COMMAND to the width it was given and marks the
                # cut with a trailing '+', so 'systemd+' and 'ACVC.GT+' are not
                # names. top is parsed before /proc/<pid>/status, so taking one
                # hid the real name from every table that shows a process name.
                cmd = f[11].strip()
                if cmd and not cmd.endswith("+"):
                    r.setdefault("comm", cmd)
                r["src"].add("top")

        # exe hashes
        for algo in ("md5", "sha1"):
            for ln in self.col.lines(
                    "live_response/process/hash_running_processes.%s" % algo):
                parts = ln.split(None, 1)
                if len(parts) != 2:
                    continue
                m = re.search(r"/proc/(\d+)/", parts[1])
                if m:
                    r = rec(m.group(1))
                    r[algo] = parts[0].strip()
                    r["src"].add("hash_running_processes")

        # /proc/<pid>/* detail
        proc_dirs = {}
        for rel in self.col.glob("live_response/process/proc/**"):
            parts = rel.split("/")
            try:
                pid = parts[parts.index("proc") + 1]
            except (ValueError, IndexError):
                continue
            proc_dirs.setdefault(pid, []).append(rel)

        fd_rx = re.compile(r"\s(\d+)\s+->\s+(.*)$")
        map_rx = re.compile(r"^[0-9a-f]+-[0-9a-f]+\s+\S{4}\s+\S+\s+\S+\s+\d+\s+(.+)$")
        for pid, files in proc_dirs.items():
            r = rec(pid)
            r["src"].add("/proc")
            base = "live_response/process/proc/%s" % pid
            st = {}
            for ln in self.col.lines("%s/status.txt" % base):
                if ":" in ln:
                    k, v = ln.split(":", 1)
                    st[k.strip()] = v.strip()
            if st:
                r.setdefault("comm", st.get("Name", ""))
                r["pstate"] = st.get("State", "")
                r.setdefault("ppid", st.get("PPid", ""))
                r["uid"] = (st.get("Uid", "").split() or [""])[0]
                r["gid"] = (st.get("Gid", "").split() or [""])[0]
                r["threads"] = st.get("Threads", "")
                r.setdefault("rss", (st.get("VmRSS", "").split() or [""])[0])
            cmd = (self.col.text("%s/cmdline.txt" % base) or "").replace("\x00", " ")
            if cmd.strip():
                r.setdefault("args", cmd.strip())
            comm = (self.col.text("%s/comm.txt" % base) or "").strip()
            if comm:
                r.setdefault("comm", comm)

            fds = deleted = socks = tmpfd = 0
            for ln in self.col.lines("%s/fd.txt" % base):
                m = fd_rx.search(ln.strip())
                if not m:
                    continue
                fds += 1
                target = m.group(2)
                if "(deleted)" in target:
                    deleted += 1
                if target.startswith(("socket:", "anon_inode:")):
                    socks += 1
                if target.startswith(TMPFS_DIRS):
                    tmpfd += 1
            if fds:
                r.update({"fds": fds, "fd_del": deleted, "fd_sock": socks,
                          "fd_tmp": tmpfd})

            nmaps = 0
            nonsys = set()
            for ln in self.col.lines("%s/maps.txt" % base):
                m = map_rx.match(ln.strip())
                if not m:
                    continue
                path = m.group(1).strip()
                if not path or path.startswith("["):
                    continue
                nmaps += 1
                # only genuinely odd mappings: a library on tmpfs, a deleted
                # file still mapped, or something out of a user's home. Testing
                # "not in a system dir" instead flags /usr/libexec, /run and
                # /var/log for half the daemons on the box.
                if path.startswith(TMPFS_DIRS) or path.startswith("/home/") or \
                        ("(deleted)" in path and not path.startswith(
                            ("/memfd:", "memfd:", "/anon_hugepage", "/dev/zero"))):
                    nonsys.add(path)
            if nmaps:
                r["maps"] = nmaps
                r["maps_ns"] = sorted(nonsys)

            env = {}
            raw_env = self.col.text("%s/environ.txt" % base) or ""
            for item in raw_env.replace("\x00", "\n").splitlines():
                if "=" in item:
                    k, v = item.split("=", 1)
                    env[k.strip()] = v.strip()
            if env:
                r["env_n"] = len(env)
                if env.get("LD_PRELOAD"):
                    r["ld_preload"] = env["LD_PRELOAD"]

        # sockets by pid
        for rel in ("live_response/network/ss_-anp.txt",
                    "live_response/network/ss_-tanp.txt",
                    "live_response/network/ss_-uanp.txt"):
            lines = self.col.lines(rel)
            if not lines:
                continue
            before_local = lines[0].split("Local")[0]
            has_netid = "Netid" in before_local
            has_state = "State" in before_local
            lead = (1 if has_netid else 0) + (1 if has_state else 0) + 2
            for ln in lines[1:]:
                f = ln.split()
                if len(f) < lead + 2:
                    continue
                state = f[1 if has_netid else 0] if has_state else ""
                local, peer = f[lead], f[lead + 1]
                rest = " ".join(f[lead + 2:])
                for pid in set(re.findall(r"pid=(\d+)", rest)):
                    r = rec(pid)
                    r["nsock"] = r.get("nsock", 0) + 1
                    if state == "LISTEN":
                        r.setdefault("listen", set()).add(local)
                    elif state == "ESTAB" and peer not in ("*", "*:*"):
                        r.setdefault("peers", set()).add(peer)
                    r["src"].add("ss")

        # open file counts from lsof
        for rel in ("live_response/process/lsof_-nPl.txt",
                    "live_response/network/lsof_-nPli.txt"):
            lines = self.col.lines(rel)
            for ln in lines[1:] if lines else []:
                f = ln.split(None, 8)
                if len(f) >= 9 and f[1].isdigit():
                    r = rec(f[1])
                    r["lsof"] = r.get("lsof", 0) + 1
                    r["src"].add("lsof")

        for pid in self.tri.hidden_pids:
            rec(pid)["src"].add("hidden_pids")

        # PROCESS_TREE is built next and wants exactly this join - every
        # artifact that named a PPID, /proc/<pid>/status included, not just
        # the ps output - so it is kept rather than merged a second time.
        self._proc_merged = procs

        known_uids = set(str(u) for u in self.tri.uids) if self.tri.uids else set()
        for pid in sorted(procs, key=lambda p: int(p) if p.isdigit() else 0):
            r = procs[pid]
            exe = r.get("exe", "")
            exe_path = exe.split(" (deleted)")[0]
            args = r.get("args", "")
            comm = r.get("comm", "")
            ppid = str(r.get("ppid", "") or "")
            parent = procs.get(ppid, {})
            parent_name = parent.get("comm") or \
                os.path.basename((parent.get("exe") or "").split(" (deleted)")[0]) or \
                trunc(parent.get("args", ""), 40)
            hidden = "yes" if pid in self.tri.hidden_pids else ""

            flags = []
            if hidden:
                flags.append("HIDDEN")
            if "(deleted)" in exe:
                flags.append("DELETED-BINARY")
            if exe_path.startswith(TMPFS_DIRS):
                flags.append("RUNS-FROM-TMPFS")
            if r.get("ld_preload"):
                flags.append("LD_PRELOAD")
            if r.get("maps_ns"):
                flags.append("NONSYSTEM-LIB")
            if r.get("fd_del"):
                flags.append("DELETED-FD")
            if r.get("fd_tmp"):
                flags.append("TMPFS-FD")
            uid = str(r.get("uid", ""))
            if uid and known_uids and uid not in known_uids:
                flags.append("UNKNOWN-UID")
            if args.startswith("[") and exe_path and not exe_path.startswith("/proc"):
                # a real kernel thread has no exe target
                flags.append("FAKE-KTHREAD")
            # a process visible in only one artifact is either very short-lived
            # (the collector's own commands) or actively hiding from the others
            evidence = r.get("src", set()) - {"hidden_pids"}
            if len(evidence) <= 1 and not re.match(r"^(/usr/bin/|/bin/)?ps\b", args):
                flags.append("SINGLE-SOURCE")

            start = r.get("start")
            t.add(pid, ppid, trunc(parent_name, 40), r.get("user", r.get("owner", "")),
                  uid, r.get("gid", ""),
                  r.get("pstate") or r.get("sstate", ""), comm, exe,
                  r.get("exe_source", ""),
                  "yes" if "(deleted)" in exe else "", r.get("cwd", ""), args,
                  start.strftime("%Y-%m-%d %H:%M:%S") if start else "",
                  r.get("etime", ""), r.get("cpu", ""), r.get("mem", ""),
                  r.get("rss", ""), r.get("vsz", ""), r.get("threads", ""),
                  r.get("tty", ""), r.get("stat", ""), r.get("container", ""),
                  r.get("cgroup", ""),
                  r.get("md5", ""), r.get("sha1", ""),
                  r.get("fds", ""), r.get("fd_del", ""), r.get("fd_sock", ""),
                  r.get("fd_tmp", ""), r.get("maps", ""),
                  "; ".join(r.get("maps_ns", [])[:8]),
                  r.get("ld_preload", ""), r.get("env_n", ""),
                  r.get("nsock", ""), " ".join(sorted(r.get("listen", []))),
                  " ".join(sorted(r.get("peers", []))), r.get("lsof", ""),
                  hidden, " ".join(flags), ", ".join(sorted(r["src"])))

    # Interpreters, which are what argv[0] says when comm says something far
    # more useful. python2/python3.11 and the rest are matched by prefix.
    INTERPRETERS = frozenset((
        "sh", "bash", "dash", "ksh", "zsh", "csh", "tcsh", "ash", "busybox",
        "perl", "ruby", "node", "php", "awk", "gawk", "expect", "lua"))

    @classmethod
    def _script_name(cls, p):
        """A script's own name, or ''.

        '/bin/sh ./uac -p full' is 'uac' to the kernel and to pstree, and 'sh'
        only to whoever reads argv[0]: the shebang means the script is what
        was execve()d, so the script is what comm holds. Without this the same
        command line is 'uac' where /proc/<pid>/status was collected and 'sh'
        where it was not, which is one process under two names in one tree.
        """
        f = (p.get("args") or "").split()
        if len(f) < 2 or f[1].startswith("-"):
            return ""
        base = os.path.basename(f[0])
        if base not in cls.INTERPRETERS and not base.startswith("python"):
            return ""
        return os.path.basename(f[1].rstrip(":"))

    @staticmethod
    def _tree_name(p):
        """The short name to hang a process on in the tree column."""
        cut = (p.get("comm") or "").strip()
        n = "" if cut.endswith("+") else cut     # a name top cut to fit, not a name
        if not n:
            n = (TableBuilder._script_name(p)
                 or os.path.basename((p.get("exe") or "").split(" (deleted)")[0]))
            if not n:
                a = (p.get("args") or "").strip()
                if a.startswith("["):    # a kernel thread, brackets and all
                    n = a.split()[0]
                elif a:
                    # 'avahi-daemon: chroot helper' names itself in argv[0] the
                    # way a daemon setproctitle()s, colon and all
                    n = os.path.basename(a.split()[0]).rstrip(":")
            # pstree prints comm, which is the name the process answers to:
            # 1495 is 'python3' only in the sense that every Python service is,
            # and 1689 and 1695 are both 'smbd' until the drawing calls them
            # smbd-notifyd and smbd-cleanupd. Kept only where what we already
            # have is not the same name spelled out in full, so a resolved
            # 'gnome-session-binary' is not shortened back to comm's 15.
            ps = (p.get("pstree_name") or "").strip()
            if ps and not n.startswith(ps):
                n = ps
        return n or cut or "?"

    _PSTREE_PID = re.compile(r"\((\d+)\)")

    @staticmethod
    def _pstree_entry_start(line, i):
        """Where the pstree entry whose '(pid)' opens at line[i] begins.

        Walking left rather than matching a name pattern, because a process
        name is not a restricted alphabet: '-' is in half of them and in all
        of the branch art, and '(sd-pam)' brings its own parentheses. What
        does end a name, always, is the character the art is made of.
        """
        j = i
        while j > 0:
            c = line[j - 1]
            if c in " |`+":
                break
            if c == ")":
                k = line.rfind("(", 0, j - 1)
                if k < 0 or line[k + 1:j - 1].isdigit():
                    break            # the '(pid)' of the entry to the left
                j = k                # a name carrying parentheses of its own
                continue
            j -= 1
        return j

    def _pstree_nodes(self):
        """PID -> (name, PPID) read out of a `pstree -p` drawing.

        pstree runs after ps in a UAC collection, so a process that started in
        between exists in the drawing and in no ps output at all: the
        collector's own `uac` and `pstree`, a cron job that fired during the
        run, and - the reason this is worth reading rather than shrugging at -
        anything that was hidden from one listing and not the other.

        The parentage is in the columns, not in the text: every child of a
        node begins at the same column, whether it is the one written on the
        parent's own line after '-+-' or the ones written below it after '|-'
        and '`-'. So the column a node starts in names its parent, which is
        one pass and no recursion - as long as a column stops meaning what it
        meant for a subtree that has already ended, which is what the purge
        below is for. Without it a process inherits whichever unrelated
        parent last had children at that indent.
        """
        nodes = {}
        for rel in sorted(self.col.glob("live_response/process/pstree*.txt")):
            text = self.col.text(rel) or ""
            if "(" not in text:          # pstree without -p, no PID to read
                continue
            self.use(rel, "PROCESS_TREE")
            col_parent = {}
            for line in text.splitlines():
                for m in self._PSTREE_PID.finditer(line):
                    start = self._pstree_entry_start(line, m.start())
                    pid = m.group(1)
                    name = line[start:m.start()].lstrip("-")
                    parent = col_parent.get(start, "")
                    for col in [c for c in col_parent if c > start]:
                        del col_parent[col]      # subtrees that ended above
                    # Where this process's children begin, read from the art
                    # that follows it rather than from the next entry on the
                    # line: pstree cuts every line at the width it was given
                    # and marks the cut with a '+', so the first child is
                    # routinely the half of the line that was thrown away.
                    end = m.end()
                    if line[end:end + 2] == "-+":
                        col_parent[end + 2] = pid
                    elif line[end:end + 1] == "-":
                        col_parent[end] = pid
                    # '{name}(pid)' is a thread of the process before it, and
                    # 484 of the 655 entries in one of these files are threads
                    if not name.startswith("{"):
                        nodes.setdefault(pid, (name, parent))
        return nodes

    _PSTREE_RUN = re.compile(r"^(\d+)\*\[(.*)\]$")

    def _pstree_a_lines(self):
        """`pstree -a` -> [(depth, comm, args)], threads dropped, runs expanded.

        The -a capture carries no PIDs, so it can name a process and never
        identify one. It is here because it is the capture that survives:
        pstree cuts every line at the width it was given, and -a spends that
        width going down the page where -p spends it going across, so the
        deep end of a tree - the tail of whatever the analyst is chasing -
        is routinely present in one and cut out of the other.
        """
        for rel in sorted(self.col.glob("live_response/process/pstree_-a*.txt")):
            out = []
            for line in (self.col.text(rel) or "").splitlines():
                if not line.strip():
                    continue
                body = line.lstrip(" |`")
                pad = len(line) - len(body)
                if body.startswith("-"):
                    body, depth = body[1:].strip(), (pad + 1) // 4
                else:
                    body, depth = body.strip(), 0
                n = 1
                run = self._PSTREE_RUN.match(body)
                if run:                  # '5*[apache2]' - five of them, drawn once
                    n, body = int(run.group(1)), run.group(2).strip()
                if not body or body.startswith("{"):
                    continue             # a thread of the process above it
                f = body.split(None, 1)
                for _ in range(n):
                    out.append((depth, f[0], f[1] if len(f) > 1 else ""))
            if out:
                self.use(rel, "PROCESS_TREE")
                return out
        return []

    _PSTREE_ART = re.compile(r"\|-|`-|-\+-|---")

    def _pstree_flat_lines(self):
        """A plain `pstree` drawing -> [(depth, comm, "")], document order.

        The oldest UAC profiles capture only this one - no -a, no -p - so it
        is the last place a 2021 collection names the process that ran last.
        It is the compact form, which is also the awkward one: several
        processes to a line, and runs of identical children folded up as
        '14*[{auomscollect}]'. A folded run and everything under it is
        skipped rather than guessed at: it is by definition a set of siblings
        ps already listed one by one, so nothing is lost by leaving it to ps.
        """
        for rel in sorted(self.col.glob("live_response/process/pstree*.txt")):
            text = self.col.text(rel) or ""
            if not text.strip() or self._PSTREE_PID.search(text):
                continue                 # the -p capture, read for its PIDs
            out, col_at = [], {}         # column -> (depth, skip this subtree)
            for line in text.splitlines():
                if not line.strip():
                    continue
                marks = list(self._PSTREE_ART.finditer(line))
                entries = []
                head = line[:marks[0].start()] if marks else line
                if head.strip(" |`"):    # the root, written at column 0
                    entries.append((0, head.strip()))
                for i, mk in enumerate(marks):
                    end = marks[i + 1].start() if i + 1 < len(marks) else len(line)
                    name = line[mk.end():end].strip()
                    tok = mk.group(0)
                    if name:
                        entries.append((mk.start() + (1 if tok in ("|-", "`-")
                                                      else 2 if tok == "-+-"
                                                      else 0), name))
                for i, (at, name) in enumerate(entries):
                    depth, skip = col_at.get(at, (0, False))
                    for c in [c for c in col_at if c > at]:
                        del col_at[c]    # subtrees that ended above
                    skip = skip or "*[" in name
                    if i + 1 < len(entries):
                        col_at[entries[i + 1][0]] = (depth + 1, skip)
                    if not skip and not name.startswith("{"):
                        out.append((depth, name, ""))
            if out:
                self.use(rel, "PROCESS_TREE")
                return out
        return []

    def _pstree_unlisted(self, procs, kids, roots):
        """What `pstree -a` draws that no PID-bearing artifact holds.

        -> {parent PID or key: [(key, comm, args)]}, walking the drawing and
        the rebuilt tree together and matching child against child. The last
        process in a collection is a case with no other answer: pstree is the
        last process listing UAC runs, so pstree's own PID is in no ps output,
        and the -p capture that would have given it one cut the line before
        reaching it.

        Matching is on comm at the 15 characters the kernel stores, with the
        arguments breaking ties between siblings of the same name - where the
        drawing carries any, which the compact form does not. A drawing whose
        names do not line up with the tree is reported and dropped rather
        than turned into a page of processes that do not exist.
        """
        lines = self._pstree_a_lines() or self._pstree_flat_lines()
        if not lines:
            return {}
        extra, used, stack, seq = defaultdict(list), set(), [], []
        for depth, comm, args in lines:
            while stack and stack[-1][0] >= depth:
                stack.pop()
            parent = stack[-1][1] if stack else ""
            want = comm[:15]
            pool = []
            for pid in (kids.get(parent, ()) if parent else roots):
                if pid in used:
                    continue
                p = procs[pid]
                base = os.path.basename((p.get("args") or "").split(" ")[0])
                if want in (self._tree_name(p)[:15], base[:15],
                            self._script_name(p)[:15]):
                    pool.append(pid)
            hit = ""
            for pid in pool:             # same arguments, same process
                rest = " ".join((procs[pid].get("args") or "").split()[1:])
                if args and rest and (rest.startswith(args[:40])
                                      or args.startswith(rest[:40])):
                    hit = pid
                    break
            hit = hit or (pool[0] if pool else "")
            if hit:
                used.add(hit)
                stack.append((depth, hit))
            else:
                key = "pstree-a:%d" % len(seq)
                seq.append(key)
                extra[parent].append((key, comm, args))
                stack.append((depth, key))
        # A handful of processes the drawing alone holds is the normal state
        # of a collection - ps and pstree ran minutes apart on a live host.
        # A quarter of them is not: that is a drawing whose names do not line
        # up with the tables, and grafting it would invent a page of
        # processes rather than recover the few that are real.
        if len(seq) > max(8, len(lines) // 4):
            status("[!] the pstree drawing does not line up with the process "
                   "tables (%d of %d entries unmatched) - not grafting it"
                   % (len(seq), len(lines)))
            return {}
        return extra

    def t_process_tree(self):
        """The tree rebuilt from PID/PPID, one row per process.

        pstree draws a picture: '-+-' where a process has several children,
        '`-' for the last of them, '6*[{ACVC.GTK.Servic}]' for a run of
        identical threads. That is readable in a terminal 100 columns wide and
        nowhere else - it does not survive a CSV, it cannot be filtered to a
        PID, sorting the table destroys it, and the collapsed 'N*[...]' runs
        hide the one PID among six that is not like the others.

        So the shape is rebuilt from the PPIDs instead, and rendered the way
        Volatility's pstree renders it: depth as leading '*' markers on the
        name, everything else a real column. What '-+-' was announcing becomes
        the `children` count, and the identical children pstree collapsed get
        a row each, with their own PID, start time and command line - which is
        the whole point of looking at them.
        """
        t = self.table("PROCESS_TREE", "Process tree (one row per PID)",
                       ["depth", "tree", "pid", "ppid", "user", "start_utc",
                        "elapsed", "container", "children", "hidden", "cmdline",
                        "note"],
                       "Process",
                       "Parent/child shape rebuilt from PID/PPID rather than "
                       "copied out of pstree's drawing: one row per process, "
                       "depth as leading '*' markers the way Volatility's "
                       "pstree writes them, children ordered by PID under "
                       "their parent. `children` is the direct child count - "
                       "what pstree's '-+-' was announcing - and `cmdline` is "
                       "truncated, with the full row for any PID here in "
                       "PROCESS_MASTER. Read top to bottom: sorting the table "
                       "by any other column breaks the tree order, and `depth` "
                       "is there to sort it back. PIDs that only the pstree "
                       "capture holds are grafted in and say so in `note` - "
                       "pstree ran after ps, so the processes that started "
                       "between them are in no ps output; where even the "
                       "pstree capture that carries PIDs was cut short, the "
                       "`pstree -a` drawing is matched against the tree and "
                       "what it alone shows is grafted in with an empty pid. "
                       "`start_utc` is the "
                       "true start where ps captured lstart; `elapsed` is what "
                       "ps itself measured. pstree's own output is kept "
                       "verbatim in PROCESS_TREE_RAW.")
        procs = self._proc_merged
        if procs is None:                # PROCESS_TREE built without its master
            if not self.tri.processes:
                self.tri._parse_process_tables()
            procs = self.tri.processes
        # Everything pstree saw and ps did not. Grafted rather than merged
        # into PROCESS_MASTER: a name and a parent are all the drawing knows,
        # and a master row carrying only those two would look like a process
        # every other artifact had lost sight of.
        pstree_only, drawn = set(), self._pstree_nodes()
        if drawn:
            procs = dict((pid, dict(p)) for pid, p in procs.items())
        for pid, (name, ppid) in drawn.items():
            if pid in procs:
                procs[pid]["pstree_name"] = name
            else:
                procs[pid] = {"comm": name, "ppid": ppid, "src": {"pstree"}}
                pstree_only.add(pid)
        pids = set(p for p in procs if str(p).isdigit())
        if not pids:
            return

        # A PPID is only a parent when the collection also holds that PID:
        # PPID 0 is the kernel, and a PPID belonging to a process that had
        # already exited when ps ran is an orphan, which is worth saying out
        # loud rather than quietly rooting the subtree as if it were normal.
        kids, roots, orphan = defaultdict(list), [], {}
        have_ppid = False
        for pid in pids:
            ppid = str(procs[pid].get("ppid", "") or "").strip()
            if ppid:
                have_ppid = True
            if ppid and ppid != pid and ppid in pids:
                kids[ppid].append(pid)
                continue
            roots.append(pid)
            if ppid and ppid != "0":
                orphan[pid] = ppid

        # Processes only the PID-less drawing knows about hang off whichever
        # PID it drew them under, and off each other by key: they are rows in
        # a table keyed by PID that have no PID, which is the whole of what
        # the collection can say about them.
        if not have_ppid:
            unlisted = {}
        else:
            unlisted = self._pstree_unlisted(procs, kids, roots)
        for parent, items in unlisted.items():
            for key, comm, args in items:
                procs[key] = {"comm": comm, "args": args, "src": {"pstree -a"}}
                if parent:
                    kids.setdefault(parent, []).append(key)
                else:
                    roots.append(key)

        # Iterative, and each PID emitted once: a collection is a snapshot of
        # a moving system, and PPIDs read from artifacts captured seconds
        # apart can close a loop that a live kernel never had.
        num = lambda p: (0, int(p), "") if p.isdigit() else (1, 0, p)
        # A PID that only a hash list or a /proc capture ever named is a
        # process that had already gone when ps ran - the collector's own
        # children, mostly. They are real and they stay, but they carry no
        # name and no parent, so they sink below the tree instead of being
        # scattered through its roots by PID order.
        frag = lambda pid: not (procs[pid].get("args") or procs[pid].get("comm")
                                or procs[pid].get("exe"))
        rows, seen = [], set()
        stack = [(pid, 0) for pid in sorted(roots, key=lambda p: (frag(p), num(p)),
                                            reverse=True)]
        while stack:
            pid, depth = stack.pop()
            if pid in seen:
                continue
            seen.add(pid)
            note = ("orphan - parent %s is not in this collection" % orphan[pid]
                    if pid in orphan else "")
            rows.append((pid, depth, note))
            for ch in sorted(kids.get(pid, ()), key=num, reverse=True):
                stack.append((ch, depth + 1))
        for pid in sorted(pids - seen, key=num):
            rows.append((pid, 0, "unreachable - PPID %s closes a loop"
                         % (procs[pid].get("ppid", "") or "?")))

        for pid, depth, note in rows:
            p = procs[pid]
            name = self._tree_name(p)
            if not pid.isdigit():
                note = "in the pstree drawing only - no artifact gave it a PID"
            elif not have_ppid:
                note = "no PPID in this collection - see PROCESS_TREE_RAW"
            elif pid in pstree_only:
                only = "in pstree only - started after ps ran, or ps did not list it"
                note = "%s; %s" % (note, only) if note else only
            elif name == "?" and not note:
                note = ("listed in %s, named by nothing"
                        % (", ".join(sorted(p.get("src", ()))) or "one artifact"))
            start = p.get("start")
            t.add(depth,
                  ("*" * depth + " " if depth else "") + name,
                  pid if pid.isdigit() else "",
                  str(p.get("ppid", "") or "") if pid.isdigit() else "",
                  p.get("user", p.get("owner", "")),
                  start.strftime("%Y-%m-%d %H:%M:%S") if start else "",
                  p.get("etime", ""),
                  p.get("container", ""), len(kids.get(pid, ())) or "",
                  "yes" if pid in self.tri.hidden_pids else "",
                  # /proc/<pid>/cmdline separates argv with NULs, and a capture
                  # that stored them as newlines puts a five-line command in
                  # one cell of a table meant to be read a row at a time
                  trunc(" ".join(str(p.get("args", "")).split()), 160), note)

    def t_process_tree_raw(self):
        t = self.table("PROCESS_TREE_RAW", "pstree output, verbatim",
                       ["source", "line_no", "text"], "Process",
                       "Every pstree artifact exactly as the host drew it, "
                       "'-+-' branches and 'N*[...]' collapsed children "
                       "included. PROCESS_TREE is the same shape rebuilt from "
                       "PID/PPID a row at a time; this is what to read when a "
                       "collection carried no ps output with a PPID in it, and "
                       "what to check the rebuild against.")
        for rel in self.col.glob("live_response/process/pstree*.txt"):
            for i, ln in enumerate(self.lines(rel, "PROCESS_TREE_RAW"), 1):
                if ln.strip():
                    t.add(os.path.basename(rel), i, ln.rstrip())

    def t_process_hashes(self):
        """Hashes of the running binaries.

        UAC hashes the /proc/<pid>/exe symlink, so the path column in its output
        is literally '/proc/1234/exe' - which identifies nothing once the host
        is gone. The resolved binary is looked up by PID so the hash can be
        matched against a package database or a threat feed.
        """
        t = self.table("PROCESS_HASHES", "Running process binary hashes",
                       ["pid", "exe", "exe_source", "hashed_path", "md5",
                        "sha1", "sha256", "process"], "Process",
                       "hash_running_processes.* keyed by /proc/<pid>/exe, with "
                       "the exe link resolved to the real binary path.")
        by_path = {}
        for algo in ("md5", "sha1", "sha256"):
            rel = "live_response/process/hash_running_processes.%s" % algo
            for ln in self.lines(rel, "PROCESS_HASHES"):
                parts = ln.split(None, 1)
                if len(parts) == 2:
                    by_path.setdefault(parts[1].strip(), {})[algo] = parts[0].strip()
        if not self.tri.processes:
            self.tri._parse_process_tables()
        for path in sorted(by_path, key=lambda p: (
                int(re.search(r"/proc/(\d+)/", p).group(1))
                if re.search(r"/proc/(\d+)/", p) else 0, p)):
            m = re.search(r"/proc/(\d+)/", path)
            pid = m.group(1) if m else ""
            p = self.tri.processes.get(pid, {})
            # if UAC already hashed a real path rather than the symlink, that
            # path is the better answer than anything we would resolve
            exe = p.get("exe", "") if path.endswith("/exe") else path
            t.add(pid, exe, p.get("exe_source", "") if path.endswith("/exe") else
                  "hashed path", path,
                  by_path[path].get("md5", ""), by_path[path].get("sha1", ""),
                  by_path[path].get("sha256", ""), trunc(p.get("args", ""), 120))

    def t_hidden_pids(self):
        t = self.table("HIDDEN_PIDS", "PIDs present in /proc but missing from ps",
                       ["pid", "note"], "Process",
                       "UAC's own hidden-process check.")
        for ln in self.lines("live_response/process/hidden_pids_for_ps_command.txt",
                             "HIDDEN_PIDS"):
            s = ln.strip()
            if s:
                t.add(s if s.isdigit() else "", s if not s.isdigit() else "")

    def t_open_files(self):
        t = self.table("OPEN_FILES", "Open files (lsof)",
                       ["command", "pid", "user", "fd", "type", "device", "size",
                        "node", "name", "source"], "Process",
                       "lsof output, one row per descriptor.")
        for rel in ("live_response/process/lsof_-nPl.txt",
                    "live_response/process/lsof.txt",
                    "live_response/network/lsof_-nPli.txt",
                    "live_response/network/lsof_-U.txt"):
            lines = self.lines(rel, "OPEN_FILES")
            if not lines:
                continue
            for ln in lines[1:]:
                f = ln.split(None, 8)
                if len(f) >= 9 and f[1].isdigit():
                    t.add(f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7],
                          f[8].strip(), os.path.basename(rel))

    # -- 3. network ---------------------------------------------------------
    IP_FAMILIES = ("tcp", "udp", "raw", "icmp", "icmp6", "mptcp", "sctp", "dccp",
                   "udplite", "tcp6", "udp6")

    def t_sockets(self):
        t = self.table("SOCKETS", "Sockets (ss, merged)",
                       ["proto", "state", "recv_q", "send_q", "local_addr",
                        "local_port", "peer_addr", "peer_port", "pid", "process",
                        "exe", "user", "container", "source"], "Network",
                       "Every ss_* variant merged; source keeps the originating "
                       "file. exe/user/container are joined from the process "
                       "table, because 'which binary holds this port' is the "
                       "question and ss only gives a truncated name.")
        for rel in sorted(self.col.glob("live_response/network/ss_*.txt")):
            lines = self.lines(rel, "SOCKETS")
            if not lines:
                continue
            # ss drops columns depending on the flags it was given:
            #   -anp  -> Netid State Recv-Q Send-Q Local Peer Process
            #   -tlnp -> State Recv-Q Send-Q Local Peer Process   (no Netid)
            #   -0bp  -> Netid Recv-Q Send-Q Local Peer Process   (no State)
            # so the layout has to come from the header, not from fixed offsets.
            header = lines[0]
            before_local = header.split("Local")[0]
            has_netid = "Netid" in before_local
            has_state = "State" in before_local
            lead = (1 if has_netid else 0) + (1 if has_state else 0) + 2
            base = os.path.basename(rel)
            # with no Netid column the family comes from the flags in the name
            implied = ("tcp" if re.search(r"ss_-[a-z0-9]*t", base) else
                       "udp" if re.search(r"ss_-[a-z0-9]*u", base) else
                       "raw" if re.search(r"ss_-[a-z0-9]*w", base) else "")
            for ln in lines[1:]:
                f = ln.split()
                if len(f) < lead + 1:
                    continue
                proto = f[0] if has_netid else implied
                state = f[1 if has_netid else 0] if has_state else ""
                rq, sq = f[lead - 2], f[lead - 1]
                if proto.startswith("u_"):
                    # unix sockets print '<path-or-*> <inode>' for each side, so
                    # the address and its 'port' are two whitespace-separated
                    # fields - reading them as host:port puts the local inode in
                    # the peer column and invents a 0.0.0.0 peer that never existed
                    la = f[lead]
                    lp = f[lead + 1] if len(f) > lead + 1 else ""
                    pa = f[lead + 2] if len(f) > lead + 2 else ""
                    pp = f[lead + 3] if len(f) > lead + 3 else ""
                    rest = " ".join(f[lead + 4:]) if len(f) > lead + 4 else ""
                elif proto in self.IP_FAMILIES or (not has_netid and implied):
                    local = f[lead]
                    peer = f[lead + 1] if len(f) > lead + 1 else ""
                    rest = " ".join(f[lead + 2:]) if len(f) > lead + 2 else ""
                    la, lp = split_hostport(local)
                    pa, pp = split_hostport(peer)
                else:
                    # netlink / packet / vsock - the columns are not IP endpoints,
                    # so they are kept verbatim rather than coerced into one
                    la, lp = f[lead], ""
                    pa = f[lead + 1] if len(f) > lead + 1 else ""
                    pp = ""
                    rest = " ".join(f[lead + 2:]) if len(f) > lead + 2 else ""
                pidset = sorted(set(re.findall(r"pid=(\d+)", rest)),
                                key=lambda p: int(p))
                pids = ",".join(pidset)
                names = ",".join(sorted(set(re.findall(r'users:\(\("([^"]+)"', rest)))) \
                    or rest.strip()
                info = [self.proc_of(p) for p in pidset]
                join = lambda k: ",".join(
                    sorted({i.get(k, "") for i in info if i.get(k)}))
                t.add(proto, state, rq, sq, la, lp, pa, pp, pids, names,
                      join("exe"), join("user"), join("container"), base)
        self._velo_sockets(t)

    def _socket_owner_maps(self):
        """(inode -> (pid, command), endpoint -> (pid, process)) for attribution.

        /proc/net names no process - it gives a socket inode and a uid. The
        inode is the join key the kernel itself uses, so lsof's network rows
        (whose DEVICE column is that inode) and /proc/<pid>/fd's 'socket:[N]'
        targets both resolve it. Where neither was collected, matching the
        endpoint tuple against ss/netstat is the fallback.
        """
        by_inode, by_endpoint = {}, {}
        for rel in ("live_response/network/lsof_-nPli.txt",
                    "live_response/process/lsof_-nPl.txt",
                    "live_response/process/lsof.txt",
                    "live_response/network/lsof_-i.txt"):
            if not self.col.exists(rel):
                continue
            for ln in self.col.iter_lines(rel):
                f = ln.split(None, 8)
                if len(f) < 9 or not f[1].isdigit():
                    continue
                if f[4] not in ("IPv4", "IPv6", "unix", "sock"):
                    continue
                if f[5].isdigit():          # DEVICE is the socket inode here
                    by_inode.setdefault(f[5], (f[1], f[0]))
        for rel in self.col.glob("live_response/process/proc/*/fd.txt"):
            pid = rel.split("/")[-2]
            for ln in self.col.lines(rel):
                m = re.search(r"socket:\[(\d+)\]", ln)
                if m:
                    by_inode.setdefault(m.group(1), (pid, ""))
        # ss/netstat already resolved endpoint -> process; reuse that
        for rel in sorted(self.col.glob("live_response/network/ss_-*p*.txt")):
            lines = self.col.lines(rel)
            if not lines:
                continue
            for ln in lines[1:]:
                pids = re.findall(r"pid=(\d+)", ln)
                names = re.findall(r'users:\(\("([^"]+)"', ln)
                if not pids:
                    continue
                f = ln.split()
                for tok in f:
                    la, lp = split_hostport(tok)
                    if lp:
                        by_endpoint.setdefault((la, lp), (pids[0],
                                                          names[0] if names else ""))
        return by_inode, by_endpoint

    def t_proc_net(self):
        t = self.table("PROC_NET", "/proc/net/{tcp,udp} decoded",
                       ["proto", "local_addr", "local_port", "remote_addr",
                        "remote_port", "state", "uid", "user", "inode", "pid",
                        "process", "attributed_by", "source"], "Network",
                       "Hex-decoded kernel socket tables - ground truth versus "
                       "ss. /proc/net names no process, so the owner is resolved "
                       "from the socket inode via lsof or /proc/<pid>/fd, and "
                       "from the endpoint via ss as a fallback; attributed_by "
                       "says which, and a blank owner on a live socket is "
                       "itself the finding.")
        states = {"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV",
                  "04": "FIN_WAIT1", "05": "FIN_WAIT2", "06": "TIME_WAIT",
                  "07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK",
                  "0A": "LISTEN", "0B": "CLOSING"}
        by_inode, by_endpoint = self._socket_owner_maps()
        uids = self.tri.uids or {}
        procs = self.tri.processes or {}
        for rel in sorted(self.col.glob("live_response/network/proc_net_*.txt")) + \
                   sorted(self.col.glob("live_response/process/proc/*/net/*.txt")):
            proto = os.path.basename(rel).replace("proc_net_", "").replace(".txt", "")
            lines = self.lines(rel, "PROC_NET")
            for ln in lines[1:]:
                f = ln.split()
                if len(f) < 10 or ":" not in f[1]:
                    continue
                lh, lpx = f[1].rsplit(":", 1)
                rh, rpx = f[2].rsplit(":", 1)
                try:
                    lp, rp = int(lpx, 16), int(rpx, 16)
                except ValueError:
                    continue
                uid, inode = f[7], f[9]
                la = hexip_to_str(lh)
                pid = name = how = ""
                if inode in by_inode:
                    pid, name = by_inode[inode]
                    how = "socket inode"
                elif (norm_ip(la), lp) in by_endpoint:
                    pid, name = by_endpoint[(norm_ip(la), lp)]
                    how = "endpoint match against ss"
                # lsof truncates COMMAND to 9 characters, so 'docker-pr' and
                # 'inetsim_p' come back ambiguous - prefer the process table's
                # full name and keep lsof's only when there is nothing better
                if pid:
                    p = procs.get(pid, {})
                    full = os.path.basename(
                        (p.get("exe") or "").split(" (deleted)")[0])
                    if not full:
                        args = (p.get("args") or "").split()
                        full = os.path.basename(args[0]).strip("[]():") \
                            if args else ""
                    if full and (not name or full.startswith(name)
                                 or len(full) > len(name)):
                        name = full
                t.add(proto, la, lp, hexip_to_str(rh), rp,
                      states.get(f[3].upper(), f[3]), uid,
                      uids.get(int(uid)) if uid.isdigit() else "",
                      inode, pid, name, how, rel)

    def t_netstat(self):
        """netstat is the other half of the socket picture.

        UAC runs both ss and netstat.  Leaving netstat unparsed threw away the
        cross-check that catches an implant hiding from one tool but not the
        other, and on hosts without iproute2 it is the only socket list there is.
        """
        t = self.table("NETSTAT", "Sockets (netstat)",
                       ["proto", "state", "recv_q", "send_q", "local_addr",
                        "local_port", "peer_addr", "peer_port", "pid", "process",
                        "exe", "container", "inode", "user", "source"], "Network",
                       "netstat output, merged across every variant UAC ran; "
                       "compare with SOCKETS (ss) and PROC_NET. For unix rows "
                       "local_addr is the socket path and recv_q is RefCnt.")
        for rel in sorted(self.col.glob("live_response/network/netstat_*.txt")):
            base = os.path.basename(rel)
            lines = self.lines(rel, "NETSTAT")
            if not lines:
                continue
            if "_-i" in base or "_-r" in base:
                continue                # interface / route listings, not sockets
            # netstat -e inserts User and Inode before PID/Program, and the unix
            # section's Flags column is bracketed and may be empty, so both are
            # driven off the section header rather than fixed offsets
            has_user = False
            unix_section = False
            unix_rx = re.compile(r"^(unix)\s+(\d+)\s+\[([^\]]*)\]\s+(\S+)"
                                 r"(?:\s+(\S+))?\s+(\d+)\s*(.*)$")
            for ln in lines:
                s = ln.rstrip()
                if not s.strip():
                    continue
                low = s.lower()
                if low.startswith("active internet"):
                    unix_section = False
                    continue
                if low.startswith("active unix"):
                    unix_section = True
                    continue
                if s.split()[0] == "Proto":
                    has_user = "User" in s.split()
                    continue
                if unix_section:
                    m = unix_rx.match(s.strip())
                    if not m:
                        continue
                    tail = m.group(7).split()
                    pid = name = ""
                    if tail and (re.match(r"^\d+/", tail[0]) or tail[0] == "-"):
                        pid, _, name = tail.pop(0).partition("/")
                        if pid == "-":
                            pid = ""
                    i = self.proc_of(pid)
                    t.add(m.group(1), m.group(5) or "", m.group(2), "",
                          " ".join(tail), "", "", "", pid, name,
                          i.get("exe", ""), i.get("container", ""),
                          m.group(6), i.get("user", ""), base)
                    continue
                f = s.split()
                if len(f) < 5 or not f[1].isdigit() or not f[2].isdigit():
                    continue
                proto, rq, sq, local, peer = f[0], f[1], f[2], f[3], f[4]
                rest = f[5:]
                state = ""
                # udp rows have no State column unless the socket is connected
                if rest and not re.match(r"^(\d+|-)/", rest[0]) \
                        and not rest[0].isdigit():
                    state = rest.pop(0)
                pid = name = inode = user = ""
                if has_user and len(rest) >= 2 and rest[0].isdigit() \
                        and rest[1].isdigit():
                    user, inode = rest.pop(0), rest.pop(0)
                for tok in rest:
                    if re.match(r"^(\d+|-)/", tok):
                        pid, _, name = tok.partition("/")
                        if pid == "-":
                            pid = ""
                    elif tok.isdigit() and not inode:
                        inode = tok
                la, lp = split_hostport(local)
                pa, pp = split_hostport(peer)
                i = self.proc_of(pid)
                # netstat -e prints the owner as a numeric uid; show the name
                # when /etc/passwd resolves it, and fall back to the process's
                # own user when the row carried no uid at all
                owner = self.uid_name(user) or user or i.get("user", "")
                t.add(proto, state, rq, sq, la, lp, pa, pp, pid, name,
                      i.get("exe", ""), i.get("container", ""), inode,
                      owner, base)

    def t_interfaces(self):
        t = self.table("INTERFACES", "Network interfaces",
                       ["index", "name", "flags", "mtu", "state", "mac",
                        "addresses", "source"],
                       "Network",
                       "Parsed from ip addr show / ip link show / ifconfig. Each "
                       "command contributes its own row, so source says which "
                       "tool the row came from and promiscuous-mode disagreements "
                       "between them stay visible.")
        cur = None
        rx = re.compile(r"^(\d+):\s+([^:@]+)[:@]\S*\s+<([^>]*)>\s+mtu\s+(\d+)(.*)$")
        for rel in ("live_response/network/ip_addr_show.txt",
                    "live_response/network/ip_link_show.txt",
                    "live_response/network/ip_-d_addr.txt",
                    "live_response/network/ip_a.txt"):
            base = os.path.basename(rel)
            for ln in self.lines(rel, "INTERFACES"):
                m = rx.match(ln.strip())
                if m:
                    if cur:
                        t.add_dict(cur)
                    st = re.search(r"state\s+(\S+)", m.group(5) or "")
                    cur = {"index": m.group(1), "name": m.group(2).strip(),
                           "flags": m.group(3), "mtu": m.group(4),
                           "state": st.group(1) if st else "", "mac": "",
                           "addresses": "", "source": base}
                elif cur is not None:
                    s = ln.strip()
                    mm = re.match(r"link/\w+\s+(\S+)", s)
                    if mm:
                        cur["mac"] = mm.group(1)
                    ma = re.match(r"inet6?\s+(\S+)", s)
                    if ma:
                        cur["addresses"] = (cur["addresses"] + " " + ma.group(1)).strip()
            if cur:
                t.add_dict(cur)
                cur = None
        # ifconfig is the only interface list on hosts without iproute2, and it
        # carries the RX/TX counters ip does not
        for rel in ("live_response/network/ifconfig_-a.txt",
                    "live_response/network/ifconfig.txt"):
            cur = None
            base = os.path.basename(rel)
            for ln in self.lines(rel, "INTERFACES"):
                m = re.match(r"^(\S+):\s+flags=\d+<([^>]*)>\s+mtu\s+(\d+)", ln)
                if not m:
                    m = re.match(r"^(\S+)\s+Link encap:\S+", ln)
                    if m:
                        if cur:
                            t.add_dict(cur)
                        cur = {"index": "", "name": m.group(1), "flags": "",
                               "mtu": "", "state": "", "mac": "", "addresses": "",
                               "source": base}
                        continue
                else:
                    if cur:
                        t.add_dict(cur)
                    cur = {"index": "", "name": m.group(1), "flags": m.group(2),
                           "mtu": m.group(3),
                           "state": "UP" if "UP" in m.group(2).split(",") else "",
                           "mac": "", "addresses": "", "source": base}
                    continue
                if cur is None:
                    continue
                s = ln.strip()
                em = re.search(r"\bether\s+(\S+)|HWaddr\s+(\S+)", s)
                if em:
                    cur["mac"] = em.group(1) or em.group(2)
                am = re.search(r"\binet6?\s+(?:addr:)?(\S+)", s)
                if am:
                    cur["addresses"] = (cur["addresses"] + " " + am.group(1)).strip()
            if cur:
                t.add_dict(cur)

    def t_routes(self):
        t = self.table("ROUTES", "Routing table",
                       ["destination", "via", "device", "proto", "scope", "src",
                        "metric", "raw", "source"], "Network",
                       "ip route show / netstat -rn / route -n, with the "
                       "originating command kept - a route present in one and "
                       "not another is worth a second look.")
        for rel in ("live_response/network/ip_route_show.txt",
                    "live_response/network/ip_route.txt",
                    "live_response/network/ip_-6_route_show.txt"):
            for ln in self.lines(rel, "ROUTES"):
                s = ln.strip()
                if not s:
                    continue
                f = s.split()
                g = lambda k: (f[f.index(k) + 1]
                               if k in f and f.index(k) + 1 < len(f) else "")
                t.add(f[0], g("via"), g("dev"), g("proto"), g("scope"), g("src"),
                      g("metric"), s, os.path.basename(rel))
        # route / netstat -r on hosts without iproute2
        for rel in ("live_response/network/netstat_-rn.txt",
                    "live_response/network/netstat_-r.txt",
                    "live_response/network/route_-n.txt"):
            for ln in self.lines(rel, "ROUTES"):
                f = ln.split()
                if len(f) < 8 or f[0] in ("Kernel", "Destination"):
                    continue
                t.add(f[0], f[1], f[-1], "", "", "", f[4], ln.strip(),
                      os.path.basename(rel))

    def t_arp(self):
        t = self.table("ARP_NEIGHBORS", "ARP / neighbour cache",
                       ["address", "device", "mac", "state", "raw", "source"],
                       "Network",
                       "ip neighbor / arp -a / /proc/net/arp - who this host was "
                       "talking to on the LAN.")
        for rel in ("live_response/network/ip_neighbor_show.txt",
                    "live_response/network/ip_neigh_show.txt",
                    "live_response/network/ip_-6_neighbor_show.txt"):
            for ln in self.lines(rel, "ARP_NEIGHBORS"):
                s = ln.strip()
                if not s:
                    continue
                f = s.split()
                g = lambda k: (f[f.index(k) + 1]
                               if k in f and f.index(k) + 1 < len(f) else "")
                t.add(f[0], g("dev"), g("lladdr"), f[-1], s, os.path.basename(rel))
        # 'arp -a' resolves names, so it can name a host ip neigh only numbers
        for rel in ("live_response/network/arp_-a.txt",
                    "live_response/network/arp_-an.txt",
                    "live_response/network/arp.txt"):
            for ln in self.lines(rel, "ARP_NEIGHBORS"):
                s = ln.strip()
                if not s:
                    continue
                m = re.match(r"^(\S+)\s+\(([^)]+)\)\s+at\s+(\S+)"
                             r"(?:\s+\[\w+\])?\s*(?:on\s+(\S+))?", s)
                if m:
                    name = m.group(1)
                    t.add(m.group(2), m.group(4) or "", m.group(3),
                          "" if name == "?" else "name=%s" % name, s,
                          os.path.basename(rel))
                else:
                    f = s.split()
                    if len(f) >= 3 and f[0] not in ("Address",):
                        t.add(f[0], f[-1], f[2], "", s, os.path.basename(rel))
        for rel in ("live_response/network/proc_net_arp.txt",):
            for ln in self.lines(rel, "ARP_NEIGHBORS")[1:]:
                f = ln.split()
                if len(f) >= 6:
                    t.add(f[0], f[5], f[3], "flags=%s" % f[2], ln.strip(),
                          os.path.basename(rel))

    def t_network_config(self):
        specs = []
        for rel in sorted(self.col.glob("live_response/network/nmcli*.txt")) + \
                  ["live_response/network/hostname.txt",
                   "live_response/network/hostname_-f.txt",
                   "live_response/network/hostnamectl.txt",
                   "live_response/network/uname_-n.txt",
                   "live_response/network/resolvectl_status.txt",
                   "live_response/network/systemd-resolve_--status.txt"]:
            specs.append((rel, os.path.basename(rel)))
        # the saved connection profiles: DNS overrides and static routes an
        # intruder can plant here survive a reboot and show up nowhere else
        for pat in ("/etc/NetworkManager/system-connections/*",
                    "/run/NetworkManager/system-connections/*",
                    "/var/run/NetworkManager/system-connections/*",
                    "/etc/netplan/*", "/etc/network/interfaces",
                    "/etc/network/interfaces.d/*", "/etc/sysconfig/network",
                    "/etc/sysconfig/network-scripts/ifcfg-*",
                    "/etc/dhcp/dhclient.conf", "/etc/wpa_supplicant/*.conf"):
            for rel in self.col.rootfs_glob(pat):
                specs.append((rel, self.col.host_path(rel)))
        self.kv_table("NETWORK_CONFIG", "Network configuration", specs, "Network",
                      "nmcli / hostname output plus the saved NetworkManager, "
                      "netplan and ifcfg connection profiles, as key-value pairs.",
                      sep=(":", "="))

    def t_unix_sockets(self):
        t = self.table("UNIX_SOCKETS", "Unix domain sockets",
                       ["command", "pid", "user", "fd", "type", "inode", "path",
                        "state", "source"], "Network",
                       "Unix socket inventory - IPC paths used by implants.")
        for rel in ("live_response/network/lsof_-U.txt",
                    "live_response/process/lsof_-U.txt"):
            lines = self.lines(rel, "UNIX_SOCKETS")
            if not lines:
                continue
            base = os.path.basename(rel)
            for ln in lines[1:]:
                f = ln.split(None, 8)
                if len(f) < 9 or not f[1].isdigit():
                    continue
                name = f[8].strip()
                st = ""
                sm = re.search(r"\(([A-Z]+)\)\s*$", name)
                if sm:
                    st = sm.group(1)
                path = re.sub(r"\s+type=\S+.*$", "", name).strip()
                t.add(f[0], f[1], f[2], f[3], f[4], f[7], path, st, base)
        # socket_files.txt is a plain find(1) listing, not lsof - keep it whole
        for rel in ("live_response/system/socket_files.txt",
                    "live_response/filesystem/socket_files.txt"):
            for ln in self.lines(rel, "UNIX_SOCKETS"):
                if ln.strip():
                    t.add("", "", "", "", "socket", "", ln.strip(), "",
                          os.path.basename(rel))

    FIREWALL_FILES = {
        "iptables_-L_-v_-n.txt": ("iptables", "filter"),
        "iptables_-t_nat_-L_-v_-n.txt": ("iptables", "nat"),
        "iptables_-t_mangle_-L_-v_-n.txt": ("iptables", "mangle"),
        "iptables_-t_raw_-L_-v_-n.txt": ("iptables", "raw"),
        "iptables_-S.txt": ("iptables", "rule-spec"),
        "ip6tables_-L_-v_-n.txt": ("ip6tables", "filter"),
        "ip6tables_-t_nat_-L_-v_-n.txt": ("ip6tables", "nat"),
        "ip6tables_-S.txt": ("ip6tables", "rule-spec"),
        "iptables_save.txt": ("iptables-save", ""),
        "nft_list_ruleset.txt": ("nftables", ""),
        "ufw_status_verbose.txt": ("ufw", ""),
        "ufw_status_numbered.txt": ("ufw", ""),
        "firewall-cmd_--list-all.txt": ("firewalld", ""),
        "firewall-cmd_--list-all-zones.txt": ("firewalld", ""),
    }

    def t_firewall(self):
        """Packet-filter state.

        A host firewall is where an intruder opens a port, blocks a security
        agent's egress or redirects traffic, and none of it shows up anywhere
        else in the export - so every ruleset dump gets parsed down to the
        chain/rule level rather than being left as an unread text file.
        """
        t = self.table("FIREWALL", "Firewall rules",
                       ["tool", "table", "chain", "policy", "packets", "bytes",
                        "target", "proto", "in_iface", "out_iface", "source",
                        "destination", "detail", "rule", "artifact"],
                       "Network",
                       "iptables / nftables / ufw / firewalld rules, one row per "
                       "rule, with NAT and redirect rules kept intact.")
        chain_rx = re.compile(r"^Chain\s+(\S+)\s+\((?:policy\s+(\S+)"
                              r"(?:\s+(\d+)\s+packets,\s+(\d+)\s+bytes)?|"
                              r"(\d+)\s+references)\)")
        found = defaultdict(list)
        plen = len(self.col.prefix)
        for low, real in self.col._names.items():
            if not low.startswith(self.col.prefix):
                continue
            rel = real[plen:]
            if rel.lstrip("/").lower().startswith("live_response/"):
                found[os.path.basename(rel).lower()].append(rel)
        for base, (tool, tbl) in sorted(self.FIREWALL_FILES.items()):
            for rel in sorted(found.get(base.lower(), []), key=str.lower):
                lines = self.lines(rel, "FIREWALL")
                art = os.path.basename(rel)
                if tool == "nftables":
                    self._nft_rules(t, lines, art)
                    continue
                if tool in ("ufw", "firewalld"):
                    for ln in lines:
                        if ln.strip():
                            t.add(tool, "", "", "", "", "", "", "", "", "", "",
                                  "", "", ln.strip(), art)
                    continue
                chain = policy = ""
                for ln in lines:
                    s = ln.rstrip()
                    if not s.strip():
                        continue
                    m = chain_rx.match(s.strip())
                    if m:
                        chain = m.group(1)
                        policy = m.group(2) or ""
                        t.add(tool, tbl, chain, policy, m.group(3) or "",
                              m.group(4) or "", "", "", "", "", "", "",
                              "%s references" % m.group(5) if m.group(5) else "",
                              s.strip(), art)
                        continue
                    if s.lstrip().startswith("pkts"):        # column header
                        continue
                    if s.lstrip().startswith("-"):           # iptables -S form
                        t.add(tool, tbl, "", "", "", "", "", "", "", "", "", "",
                              "", s.strip(), art)
                        continue
                    f = s.split(None, 9)
                    # pkts bytes target prot opt in out source destination [extra]
                    if len(f) >= 9 and f[0].rstrip("KMG").isdigit():
                        t.add(tool, tbl, chain, policy, f[0], f[1], f[2], f[3],
                              f[5], f[6], f[7], f[8],
                              f[9].strip() if len(f) > 9 else "", s.strip(), art)
                    else:
                        t.add(tool, tbl, chain, policy, "", "", "", "", "", "",
                              "", "", "", s.strip(), art)
        # the persisted rulesets: what comes back after a reboot, which is not
        # necessarily what is loaded right now
        for pat, tool in (("/etc/ufw/*.rules", "ufw (on disk)"),
                          ("/etc/ufw/ufw.conf", "ufw (on disk)"),
                          ("/etc/default/ufw", "ufw (on disk)"),
                          ("/etc/nftables.conf", "nftables (on disk)"),
                          ("/etc/nftables.d/*", "nftables (on disk)"),
                          ("/etc/iptables/rules.v4", "iptables (on disk)"),
                          ("/etc/iptables/rules.v6", "ip6tables (on disk)"),
                          ("/etc/sysconfig/iptables", "iptables (on disk)"),
                          ("/etc/sysconfig/ip6tables", "ip6tables (on disk)"),
                          ("/etc/firewalld/zones/*", "firewalld (on disk)")):
            for rel in self.col.rootfs_glob(pat):
                host = self.col.host_path(rel)
                chain = ""
                for i, ln in enumerate(self.lines(rel, "FIREWALL"), 1):
                    s = ln.strip()
                    if not s or s.startswith("#"):
                        continue
                    cm = re.match(r"^[:*]?(\S+)\s+(ACCEPT|DROP|REJECT)\s", s)
                    if s.startswith(":") and cm:
                        chain, policy = cm.group(1), cm.group(2)
                        t.add(tool, "", chain, policy, "", "", "", "", "", "",
                              "", "", "", s, host)
                        continue
                    tgt = re.search(r"-j\s+(\S+)", s)
                    t.add(tool, "", chain, "", "", "",
                          tgt.group(1) if tgt else "", "", "", "", "", "",
                          "line %d" % i, s, host)

    def _nft_rules(self, t, lines, art):
        """nft list ruleset is a nested block; flatten it to table/chain/rule."""
        tbl = chain = policy = ""
        for ln in lines:
            s = ln.strip()
            if not s or s == "}":
                continue
            m = re.match(r"^table\s+(\S+)\s+(\S+)\s*\{", s)
            if m:
                tbl, chain, policy = "%s %s" % (m.group(1), m.group(2)), "", ""
                continue
            m = re.match(r"^chain\s+(\S+)\s*\{", s)
            if m:
                chain, policy = m.group(1), ""
                continue
            m = re.match(r"^type\s+\S+\s+hook\s+\S+.*policy\s+(\w+)", s)
            if m:
                policy = m.group(1)
                t.add("nftables", tbl, chain, policy, "", "", "", "", "", "",
                      "", "", "", s, art)
                continue
            pk = re.search(r"counter packets (\d+) bytes (\d+)", s)
            tgt = re.search(r"\b(accept|drop|reject|masquerade|dnat|snat|redirect|"
                            r"jump|goto|return|log)\b", s)
            t.add("nftables", tbl, chain, policy,
                  pk.group(1) if pk else "", pk.group(2) if pk else "",
                  tgt.group(1) if tgt else "", "", "", "", "", "", "", s, art)

    # -- 4. kernel / system -------------------------------------------------
    def t_modules(self):
        t = self.table("KERNEL_MODULES", "Loaded kernel modules",
                       ["module", "size", "used_by_count", "used_by", "filename",
                        "license", "description", "author", "version", "vermagic",
                        "srcversion", "intree", "retpoline", "signer", "sig_id",
                        "depends", "parameters", "source"], "Kernel",
                       "lsmod and /proc/modules joined with every modinfo/* "
                       "capture. source names which listing the module came "
                       "from: one that appears in /proc/modules but not lsmod "
                       "(or the reverse) is hiding from one of them. The "
                       "modinfo columns - license, signer, vermagic and the "
                       "rest - are dropped when this collection's profile "
                       "captured no modinfo, so the columns present are the "
                       "ones the host actually answered.")
        info = {}
        for rel in sorted(self.col.glob("live_response/system/modinfo/**")):
            name = os.path.basename(rel)
            name = re.sub(r"^modinfo_", "", name)
            name = re.sub(r"\.txt$", "", name)
            d = {}
            for ln in self.lines(rel, "KERNEL_MODULES"):
                if ":" in ln:
                    k, v = ln.split(":", 1)
                    k = k.strip()
                    v = v.strip()
                    d[k] = (d[k] + "; " + v) if k in d and v else (v or d.get(k, ""))
            if d:
                info[d.get("name", name)] = d
                info.setdefault(name, d)
        params = {}
        for rel in sorted(self.col.glob("live_response/system/module/*/parameters.txt")):
            mod = rel.split("/")[-2]
            vals = [l.strip() for l in self.lines(rel, "KERNEL_MODULES") if l.strip()]
            if vals:
                params[mod] = ", ".join(vals)
        seen = set()
        # FOR577: lsmod draws from /proc/modules, so take whichever the
        # collection has - a rootkit that hides from one may not hide from both
        mod_lines = [(ln, "lsmod.txt") for ln in
                     self.lines("live_response/system/lsmod.txt",
                                "KERNEL_MODULES")[1:]]
        for alt in ("live_response/system/proc_modules.txt",
                    "live_response/system/modules.txt",
                    "live_response/kernel/proc_modules.txt"):
            mod_lines += [(ln, os.path.basename(alt))
                          for ln in self.lines(alt, "KERNEL_MODULES")]
        prel = self.col.rootfs("/proc/modules")
        if prel:
            mod_lines += [(ln, "/proc/modules")
                          for ln in self.lines(prel, "KERNEL_MODULES")]
        # a module listed by more than one source keeps both names, so the
        # absence of one is visible in the same cell
        origins = defaultdict(list)
        for ln, origin in mod_lines:
            f = ln.split(None, 3)
            if len(f) >= 3 and f[1].isdigit() and origin not in origins[f[0]]:
                origins[f[0]].append(origin)
        for ln, _origin in mod_lines:
            f = ln.split(None, 3)
            if len(f) < 3 or not f[1].isdigit():
                continue
            mod, size, used = f[0], f[1], f[2]
            if mod in seen:
                continue
            # /proc/modules spells the dependants '[a,b]' or '-'
            by = f[3].strip() if len(f) > 3 else ""
            by = "" if by in ("-", "[permanent]") else by.strip("[]").rstrip(",")
            d = info.get(mod, {})
            seen.add(mod)
            t.add(mod, size, used, by, d.get("filename", ""), d.get("license", ""),
                  d.get("description", ""), d.get("author", ""), d.get("version", ""),
                  d.get("vermagic", ""), d.get("srcversion", ""), d.get("intree", ""),
                  d.get("retpoline", ""), d.get("signer", ""), d.get("sig_id", ""),
                  d.get("depends", ""), params.get(mod, ""),
                  ", ".join(origins.get(mod, [])))
        for mod, d in sorted(info.items()):
            if mod in seen:
                continue
            seen.add(mod)
            t.add(mod, "", "", "(not in any module listing)", d.get("filename", ""),
                  d.get("license", ""), d.get("description", ""), d.get("author", ""),
                  d.get("version", ""), d.get("vermagic", ""), d.get("srcversion", ""),
                  d.get("intree", ""), d.get("retpoline", ""), d.get("signer", ""),
                  d.get("sig_id", ""), d.get("depends", ""), params.get(mod, ""),
                  "modinfo only")
        self._velo_modules(t)
        # Only the columns this collection has something to say in: lsmod and
        # /proc/modules answer six of these, the other twelve come from
        # modinfo/ and module/*/parameters, and most UAC profiles collect
        # neither. Eighteen headings for six answers reads as missing data.
        t.drop_empty_columns(keep=("module",))

    def t_sysctl(self):
        self.kv_table("SYSCTL", "Kernel parameters (sysctl -a)",
                      [("live_response/system/sysctl_-a.txt", "sysctl -a"),
                       ("live_response/system/cat_proc_sys_kernel_tainted.txt",
                        "kernel.tainted"),
                       ("live_response/system/core_pattern.txt", "core_pattern")],
                      "Kernel", "Every runtime kernel tunable.")

    def t_services(self):
        t = self.table("SERVICES", "Services and systemd units",
                       ["unit", "load", "active", "sub", "state", "description",
                        "source"], "System",
                       "systemctl list-units / list-unit-files / service --status-all.")
        for rel in ("live_response/system/systemctl_list-units.txt",
                    "live_response/system/systemctl_list-unit-files.txt",
                    "live_response/system/systemctl_list-units_--all.txt"):
            lines = self.lines(rel, "SERVICES")
            for ln in lines:
                s = ln.strip().lstrip("Ã¢â€”Â").strip()
                if not s or s.startswith(("UNIT", "LOAD ", "ACTIVE", "SUB ", "To show",
                                          "Legend", "unit files listed", "loaded units")):
                    continue
                if "loaded units listed" in s or "unit files listed" in s:
                    continue
                f = s.split(None, 4)
                if not f or "." not in f[0]:
                    continue
                if "list-unit-files" in rel and len(f) >= 2:
                    t.add(f[0], "", "", "", f[1], " ".join(f[2:]), os.path.basename(rel))
                elif len(f) >= 4:
                    t.add(f[0], f[1], f[2], f[3], "", f[4] if len(f) > 4 else "",
                          os.path.basename(rel))
        for ln in self.lines("live_response/system/service_--status-all.txt", "SERVICES"):
            s = ln.strip()
            m = re.match(r"^\[\s*([-+?])\s*\]\s+(\S+)", s)
            if m:
                state = {"+": "running", "-": "stopped", "?": "unknown"}[m.group(1)]
                t.add(m.group(2), "", state, "", state, "", "service --status-all")
        self._velo_services(t)

    def t_timers(self):
        t = self.table("SYSTEMD_TIMERS", "systemd timers",
                       ["source", "line_no", "text"], "Persistence",
                       "Timers are cron for systemd - a common persistence spot.")
        for rel in ("live_response/system/systemctl_list-timers_--all.txt",
                    "live_response/system/systemctl_status_timer.txt"):
            for i, ln in enumerate(self.lines(rel, "SYSTEMD_TIMERS"), 1):
                if ln.strip():
                    t.add(os.path.basename(rel), i, ln.rstrip())

    def t_dmesg(self):
        t = self.table("DMESG", "Kernel ring buffer",
                       ["seq", "timestamp_offset", "timestamp_utc", "facility",
                        "message", "source"], "Kernel",
                       "dmesg and kern.log - module loads, taint events and "
                       "iptables LOG output all land here. Rotations are "
                       "expanded; kern.log lines carry a real clock, dmesg "
                       "lines only an offset from boot.")
        rx = re.compile(r"^\[\s*([\d.]+)\]\s*(.*)$")
        rels = ["live_response/hardware/dmesg.txt",
                "live_response/system/dmesg.txt",
                "live_response/process/dmesg.txt"]
        # FOR577: on Ubuntu 22.04 and older the same records are in kern.log
        rels += self.col.rootfs_glob("/var/log/dmesg*")
        rels += self.col.rootfs_glob("/var/log/kern.log*")
        rels += self.col.rootfs_glob("/var/log/kernel*")
        seen = set()
        for rel in rels:
            if rel.lower() in seen:
                continue
            seen.add(rel.lower())
            lines = self.dlines(rel, "DMESG")
            if lines is None:
                continue
            base = os.path.basename(rel)
            for i, ln in enumerate(lines, 1):
                if not ln.strip():
                    continue
                m = rx.match(ln)
                if m:
                    t.add(i, m.group(1), "", "kernel", m.group(2), base)
                    continue
                # kern.log is syslog-shaped, so it has a usable wall clock
                ts, _h, proc, _pid, msg = split_log_line(ln)
                if ts:
                    t.add(i, "", self.ts_utc(ts), proc or "kernel", msg, base)
                else:
                    t.add(i, "", "", "", ln.rstrip(), base)

    # Globs, not plain names: binfmt_misc is a directory of one file per
    # registered interpreter, and a name spelled out in full only ever matches
    # the one profile it was copied from. Each entry is still explicit, because
    # a bare live_response/system/*.txt here would swallow the last/lastb/
    # sysctl/systemctl artifacts that their own extractors run on later.
    SYSTEM_INFO_GLOBS = (
        "live_response/system/uname_-a.txt", "live_response/system/date.txt",
        "live_response/system/uptime.txt", "live_response/system/uptime_-s.txt",
        "live_response/system/free.txt", "live_response/system/vmstat.txt",
        "live_response/system/hwclock.txt", "live_response/system/runlevel.txt",
        "live_response/system/timedatectl_status.txt",
        "live_response/system/ulimit_-a.txt",
        "live_response/system/journalctl_--list-boots.txt",
        # binfmt_misc registers an interpreter for a magic byte sequence:
        # execution of an arbitrary binary through a file nothing marks as
        # executable, and a persistence spot the module list does not show
        "live_response/system/binfmt_misc/*",
        # eBPF programs load into the kernel without appearing in lsmod, and
        # are the modern way to hide a process or a connection
        "live_response/system/bpftool_*.txt",
        "live_response/system/ls_-la_sys_fs_bpf.txt",
        "live_response/system/ls_-la_sys_module.txt",
        # core_pattern pipes a crashing process to a program of the attacker's
        # choosing, running as root
        "live_response/system/core_pattern.txt",
        "live_response/system/cat_proc_sys_kernel_tainted.txt",
        "live_response/system/sudo_lectured_timestamps.txt",
    )

    def t_system_info(self):
        t = self.table("SYSTEM_INFO", "System state snapshots",
                       ["source", "line_no", "text"], "System",
                       "Uptime, clock, memory, boots, kernel taint, core_pattern, "
                       "eBPF and binfmt_misc state.")
        for pat in self.SYSTEM_INFO_GLOBS:
            for rel in self.col.glob(pat):
                for i, ln in enumerate(self.lines(rel, "SYSTEM_INFO"), 1):
                    if ln.strip():
                        t.add(os.path.basename(rel), i, ln.rstrip())
        self._velo_system_info(t)

    def t_env(self):
        self.kv_table("ENV_VARS", "Collector environment",
                      [("live_response/system/env.txt", "env")], "System",
                      "Environment of the collecting shell.")

    def t_hardware(self):
        t = self.table("HARDWARE", "Hardware inventory",
                       ["source", "line_no", "text"], "System",
                       "lscpu / lspci / lsusb / dmidecode.")
        for rel in sorted(self.col.glob("live_response/hardware/*.txt")):
            if rel.endswith("dmesg.txt"):
                continue
            for i, ln in enumerate(self.lines(rel, "HARDWARE"), 1):
                if ln.strip():
                    t.add(os.path.basename(rel), i, ln.rstrip())

    @staticmethod
    def _json_entries(text):
        """A JSON document -> one record per entity, or None if it is not JSON.

        UAC's `-J` artifacts are a single pretty-printed document: `lsblk -J`
        is one object spread over fifty lines. Read a line at a time, one disk
        became forty rows of '"name": "sda",' fragments and the table could not
        be sorted, filtered or read. The entity is the row, not the line.

        `children` is flattened rather than nested, because a partition and a
        submount are things in their own right; each keeps a _parent naming the
        entity it hung under, so the tree survives the flattening.
        """
        s = (text or "").lstrip()
        if not s.startswith(("{", "[")):
            return None
        try:
            doc = json.loads(s)
        except ValueError:
            return None                    # malformed: fall back to raw lines
        # lsblk and findmnt wrap their list in one key: blockdevices, filesystems
        if isinstance(doc, dict) and len(doc) == 1:
            only = next(iter(doc.values()))
            if isinstance(only, list):
                doc = only
        out = []

        def walk(node, parent):
            if not isinstance(node, dict):
                out.append({"value": node} if parent == "" else
                           {"value": node, "_parent": parent})
                return
            row = {k: v for k, v in node.items() if k != "children"}
            if parent:
                row["_parent"] = parent
            out.append(row)
            ident = str(node.get("name") or node.get("target")
                        or node.get("source") or "")
            kids = node.get("children")
            for kid in kids if isinstance(kids, list) else []:
                walk(kid, ident)

        for item in (doc if isinstance(doc, list) else [doc]):
            walk(item, "")
        return out

    # -- storage ------------------------------------------------------------
    @staticmethod
    def _fixed_width_rows(lines):
        """A fixed-width command table with a header row -> list of dicts.

        `lsblk -f` cannot be split on whitespace: FSVER holds 'LVM2 001' and
        LABEL is routinely empty, so a field *count* is not a field position.
        `df` puts a space in the header itself ('Mounted on'). What all of
        these tools do guarantee is a column of spaces between fields in every
        row, so the boundaries are read off the block instead of assumed - a
        cut is any run of offsets blank in all lines, header included. That
        also settles alignment without having to know it: a right-aligned
        '1024M' under a four-character 'SIZE' header lands in its own column
        either way.
        """
        rows = [ln.rstrip() for ln in lines if ln.strip()]
        if len(rows) < 2:
            return []
        width = max(len(ln) for ln in rows)
        pad = [ln.ljust(width) for ln in rows]
        blank = [all(ln[i] == " " for ln in pad) for i in range(width)]
        cuts, i = [], 0
        while i < width:
            if blank[i]:
                j = i
                while j < width and blank[j]:
                    j += 1
                if i > 0:                    # a gap between fields, not the margin
                    cuts.append((i, j))
                i = j
            else:
                i += 1
        bounds, prev = [], 0
        for a, b in cuts:
            bounds.append((prev, a))
            prev = b
        bounds.append((prev, width))
        head = [pad[0][a:b].strip() for a, b in bounds]
        return [dict((h, ln[a:b].strip()) for h, (a, b) in zip(head, bounds))
                for ln in pad[1:]]

    # df and findmnt list these beside the real disks. A tmpfs is a mount, not
    # a device, and giving it a row in a table of block devices is the same
    # mistake as filing a MySQL log under HTTP: MOUNTS is where it belongs.
    PSEUDO_FS = frozenset((
        "tmpfs", "devtmpfs", "sysfs", "proc", "udev", "efivarfs", "cgroup",
        "cgroup2", "devpts", "securityfs", "pstore", "bpf", "debugfs",
        "tracefs", "fusectl", "configfs", "mqueue", "hugetlbfs", "autofs",
        "binfmt_misc", "nsfs", "overlay", "squashfs", "ramfs", "none",
        "systemd-1", "rpc_pipefs", "sunrpc", "fuse.gvfsd-fuse", "fuse.portal",
        "swap", "shm", "run", "cgmfs", "snapfuse"))

    # lsblk draws its tree in the NAME column and findmnt in TARGET
    TREE_CHARS = "|`- │├└─"

    @classmethod
    def _devkey(cls, name):
        """/dev/mapper/vg-lv, /dev/sda1, ../../sda1 and 'sda1' -> one key.

        Every artifact spells the same device differently, and a join on the
        spelling is a join that silently does not happen: df says
        /dev/mapper/ubuntu--vg-ubuntu--lv where lsblk says
        ubuntu--vg-ubuntu--lv, so without this the logical volume is two rows,
        one holding its size and the other its usage, and neither says it is
        the root filesystem.
        """
        n = (name or "").strip().strip(cls.TREE_CHARS)
        if not n:
            return ""
        n = n.split("[", 1)[0]               # findmnt's 'tmpfs[/subvol]'
        if n.startswith(("/dev/", "../")):
            n = n.rsplit("/", 1)[-1]
        return n

    def t_storage(self):
        """One row per block device, joined across every artifact naming it.

        A UAC collection describes storage six times over - lsblk with its -f,
        -l and -J variants, blkid, fdisk, df, findmnt, mount, the
        /dev/disk/by-* symlinks - and each spelling knows a different part of
        the answer: lsblk has the size and the tree, lsblk -f the filesystem,
        blkid the UUID, fdisk the sector offsets and disk model, df the usage.
        Read one artifact at a time and the table is 250 rows that answer
        nothing; joined on the device, six rows answer "what is this disk,
        what is on it, where is it mounted and how full is it".

        The join is on `_devkey`, and the devices themselves are joined on
        maj:min afterwards, because /dev/dm-0 and ubuntu--vg-ubuntu--lv are
        the same device under the two names different tools print.

        STORAGE_RAW keeps every storage artifact verbatim. A join is a
        summary, and the LVM and mdadm output that has no device row of its
        own has to stay somewhere.
        """
        t = self.table("STORAGE", "Block devices, joined",
                       ["device", "kind", "size", "size_bytes", "parent",
                        "maj_min", "removable", "read_only", "model", "fstype",
                        "fs_version", "label", "uuid", "partuuid", "part_type",
                        "mountpoint", "mount_options", "fs_size", "fs_used",
                        "fs_avail", "fs_use_pct", "start_sector", "end_sector",
                        "sectors", "by_id", "aliases", "sources"], "System",
                       "One row per disk, partition, LVM volume or loop device, "
                       "merged from lsblk (-f/-l/-J), blkid, blkid.tab, fdisk, "
                       "df, findmnt, mount, /proc/partitions, /etc/fstab and the "
                       "/dev/disk/by-* symlinks; `sources` names which of them "
                       "spoke for the row. A disk's `uuid` is the partition "
                       "table's identifier. Pseudo-filesystems (tmpfs, sysfs) "
                       "are mounts rather than devices and stay in MOUNTS; LVM "
                       "and mdadm detail stays in STORAGE_RAW.")

        devs = {}
        multi = ("mountpoint",)              # a device can be mounted twice
        # /dev/disk/by-id/dm-name-<lv> -> ../../dm-0 is the kernel telling us
        # those two names are one device. Without it the LV's UUID lands on a
        # phantom dm-0 row and the row that says '/' has no UUID.
        alias = {}

        def key_of(name):
            k = self._devkey(name)
            return alias.get(k, k)

        def rec(name, source, strict=False, **vals):
            raw = (name or "").strip()
            k = key_of(raw)
            if not k or k.lower() in self.PSEUDO_FS:
                return None
            # df, findmnt and mount list filesystems, not devices. A source
            # that is not a /dev/ path and that no device artifact has ever
            # named is a pseudo-filesystem - lxcfs, gvfsd, a snap's squashfs
            # loop by name - and giving it a row is how 'lxcfs' ended up
            # listed as a disk. Shape, not a blocklist of names to maintain.
            if strict and k not in devs and not raw.startswith("/dev/"):
                return None
            d = devs.get(k)
            if d is None:
                d = devs[k] = {"device": k, "_sources": []}
            if source and source not in d["_sources"]:
                d["_sources"].append(source)
            for f, v in vals.items():
                v = "" if v is None else str(v).strip()
                if not v:
                    continue
                if f in multi:
                    cur = [x for x in d.get(f, "").split("; ") if x]
                    if v not in cur:
                        d[f] = "; ".join(cur + [v])
                elif not d.get(f):
                    d[f] = v
            return d

        # artifacts are keyed by basename so a profile that spells the
        # directory differently still resolves; missing ones are simply absent
        arts = {}
        for rel in sorted(self.col.glob("live_response/storage/**")):
            arts.setdefault(os.path.basename(rel).lower(), rel)

        def art(name):
            rel = arts.get(name)
            return self.text(rel, "STORAGE") if rel else None

        def yn(v):
            return "yes" if str(v).strip() in ("1", "True", "true") else ""

        def lsblk_json(name, label):
            txt = art(name)
            for ent in self._json_entries(txt or "") or []:
                mp = ent.get("mountpoints")
                mp = [x for x in mp if x] if isinstance(mp, list) else [mp]
                d = rec(ent.get("name"), label,
                        kind=ent.get("type"), size=ent.get("size"),
                        maj_min=ent.get("maj:min"), parent=ent.get("_parent"),
                        removable=yn(ent.get("rm")), read_only=yn(ent.get("ro")),
                        fstype=ent.get("fstype"), fs_version=ent.get("fsver"),
                        label=ent.get("label"), uuid=ent.get("uuid"),
                        fs_avail=ent.get("fsavail"), fs_use_pct=ent.get("fsuse%"),
                        partuuid=ent.get("partuuid"))
                for one in mp:
                    if d is not None and one:
                        rec(ent.get("name"), label, mountpoint=one)

        def lsblk_text(name, label):
            txt = art(name)
            if txt is None:
                return
            parent_at = {}                   # indent depth -> device
            for r in self._fixed_width_rows(txt.splitlines()):
                raw = r.get("NAME", "")
                depth = len(raw) - len(raw.lstrip(self.TREE_CHARS))
                dev = self._devkey(raw)
                if not dev:
                    continue
                parent = ""
                for d0 in sorted(parent_at):
                    if d0 < depth:
                        parent = parent_at[d0]
                parent_at[depth] = dev
                for d0 in [x for x in parent_at if x > depth]:
                    del parent_at[d0]
                rec(dev, label, kind=r.get("TYPE"), size=r.get("SIZE"),
                    maj_min=r.get("MAJ:MIN"), parent=parent,
                    removable=yn(r.get("RM")), read_only=yn(r.get("RO")),
                    fstype=r.get("FSTYPE"), fs_version=r.get("FSVER"),
                    label=r.get("LABEL"), uuid=r.get("UUID"),
                    fs_avail=r.get("FSAVAIL"), fs_use_pct=r.get("FSUSE%"),
                    mountpoint=r.get("MOUNTPOINTS") or r.get("MOUNTPOINT"))

        # the by-id symlinks are read for their aliases before anything can
        # create a row under the name they resolve away
        disk_ls = art("ls_-l_dev_disk.txt") or ""
        for m in re.finditer(r"\sdm-name-(\S+)\s+->\s+(\S+)\s*$", disk_ls, re.M):
            alias[self._devkey(m.group(2))] = m.group(1)

        # df before lsblk: the four usage figures are df's answer, and lsblk
        # -f's FSAVAIL is the same number rounded differently - first-wins
        # would otherwise report a 3.5G free beside a 9.0G used of 14G.
        live_mounts = False              # did anything report a live mount table
        for name, label in (("df_-h.txt", "df -h"), ("df.txt", "df")):
            for r in self._fixed_width_rows((art(name) or "").splitlines()):
                live_mounts = True
                rec(r.get("Filesystem"), label, strict=True,
                    fs_size=r.get("Size") or r.get("1K-blocks")
                    or r.get("1024-blocks"),
                    fs_used=r.get("Used"),
                    fs_avail=r.get("Avail") or r.get("Available"),
                    fs_use_pct=r.get("Use%"), mountpoint=r.get("Mounted on"))

        # JSON first: it is the same command with the shape already parsed, so
        # anything the text parse gets wrong is corrected before it is read
        lsblk_json("lsblk_-j.txt", "lsblk -J")
        lsblk_json("lsblk_-f_-j.txt", "lsblk -f -J")
        lsblk_json("lsblk_-l_-j.txt", "lsblk -l -J")
        lsblk_text("lsblk.txt", "lsblk")
        lsblk_text("lsblk_-f.txt", "lsblk -f")
        lsblk_text("lsblk_-l.txt", "lsblk -l")

        # blkid: '/dev/sda2: UUID="..." TYPE="ext4" PARTUUID="..."'
        for ln in (art("blkid.txt") or "").splitlines():
            dev, _, rest = ln.partition(":")
            if not dev.startswith("/dev/") or not rest.strip():
                continue
            a = dict(re.findall(r'(\w+)="([^"]*)"', rest))
            rec(dev, "blkid", uuid=a.get("UUID") or a.get("PTUUID"),
                fstype=a.get("TYPE"), label=a.get("LABEL") or a.get("PARTLABEL"),
                partuuid=a.get("PARTUUID"))

        # fdisk -l: a narrative per disk, then that disk's partition table
        cur = ""
        fl = (art("fdisk_-l.txt") or "").splitlines()
        i = 0
        while i < len(fl):
            ln = fl[i]
            m = re.match(r"^Disk (/dev/\S+):\s*(.+?),\s*(\d+) bytes,\s*(\d+) sectors",
                         ln)
            if m:
                cur = self._devkey(m.group(1))
                rec(m.group(1), "fdisk", kind="disk", size=m.group(2),
                    size_bytes=m.group(3), sectors=m.group(4))
                i += 1
                continue
            m = re.match(r"^Disk model:\s*(.+)$", ln)
            if m and cur:
                rec(cur, "fdisk", model=m.group(1))
                i += 1
                continue
            # for a disk this is the partition table's own id, which is what
            # identifies the disk across a re-image
            m = re.match(r"^Disk identifier:\s*(\S+)", ln)
            if m and cur:
                rec(cur, "fdisk", uuid=m.group(1))
                i += 1
                continue
            if re.match(r"^Device\s+\S", ln):
                blk, j = [ln], i + 1
                while j < len(fl) and fl[j].strip():
                    blk.append(fl[j])
                    j += 1
                for r in self._fixed_width_rows(blk):
                    if not (r.get("Device") or "").startswith("/dev/"):
                        continue
                    rec(r["Device"], "fdisk", kind="part", parent=cur,
                        start_sector=r.get("Start"), end_sector=r.get("End"),
                        sectors=r.get("Sectors"), size=r.get("Size"),
                        part_type=r.get("Type"))
                i = j
                continue
            i += 1

        # findmnt / mount: the options are the reason to read them - a noexec
        # or ro that is not in fstab is a live change someone made
        for ent in self._json_entries(art("findmnt_-j.txt") or "") or []:
            live_mounts = True
            rec(ent.get("source"), "findmnt -J", strict=True,
                mountpoint=ent.get("target"), fstype=ent.get("fstype"),
                mount_options=ent.get("options"))
        for r in self._fixed_width_rows((art("findmnt.txt") or "").splitlines()):
            live_mounts = True
            rec(r.get("SOURCE"), "findmnt", strict=True,
                mountpoint=(r.get("TARGET") or "").lstrip(self.TREE_CHARS),
                fstype=r.get("FSTYPE"), mount_options=r.get("OPTIONS"))
        for ln in (art("mount.txt") or "").splitlines():
            m = re.match(r"^(\S+)\s+on\s+(\S+)\s+type\s+(\S+)\s+\((.*)\)$", ln.strip())
            if m:
                live_mounts = True
                rec(m.group(1), "mount", strict=True, mountpoint=m.group(2),
                    fstype=m.group(3), mount_options=m.group(4))

        # /dev/disk/by-*: on a host with no blkid output these symlinks are the
        # only record of a partition's UUID, and by-id carries the model and
        # serial the disk reported to the kernel
        section = ""
        for ln in disk_ls.splitlines():
            s = ln.strip()
            if s.endswith(":") and "/dev/disk/" in s:
                section = s.rstrip(":").rsplit("/", 1)[-1]
                continue
            m = re.search(r"\s(\S+)\s+->\s+(\S+)$", s)
            if not m or not section:
                continue
            link, target = m.group(1), m.group(2)
            if section == "by-uuid":
                rec(target, "by-uuid", uuid=link)
            elif section == "by-partuuid":
                rec(target, "by-partuuid", partuuid=link)
            elif section == "by-label":
                rec(target, "by-label", label=link.replace("\\x20", " "))
            elif section == "by-id":
                rec(target, "by-id", by_id=link)

        # /proc/partitions, when the collection copied it: major/minor and the
        # size in 1K blocks for every device the kernel knew about, including
        # ones no other artifact mentions
        for rel in [self.col.rootfs("/proc/partitions"),
                    arts.get("proc_partitions.txt")] + \
                [self.col.glob_one("live_response/system/proc_partitions.txt")
                 if hasattr(self.col, "glob_one") else None]:
            if not rel:
                continue
            for ln in self.lines(rel, "STORAGE"):
                f = ln.split()
                if len(f) == 4 and f[0].isdigit() and f[2].isdigit():
                    rec(f[3], "/proc/partitions", maj_min="%s:%s" % (f[0], f[1]),
                        size_bytes=int(f[2]) * 1024)

        # blkid.tab is blkid's own cache, and on a collection that ran no
        # storage commands at all it is the only device inventory there is
        for path in ("/var/run/blkid/blkid.tab", "/run/blkid/blkid.tab",
                     "/etc/blkid.tab"):
            rel = self.col.rootfs(path)
            if not rel:
                continue
            for ln in self.lines(rel, "STORAGE"):
                m = re.search(r"<device\s+([^>]*)>([^<]+)</device>", ln)
                if not m:
                    continue
                a = dict(re.findall(r'(\w+)="([^"]*)"', m.group(1)))
                rec(m.group(2), "blkid.tab", uuid=a.get("UUID"),
                    fstype=a.get("TYPE"), label=a.get("LABEL"),
                    partuuid=a.get("PARTUUID"))

        # fstab last: it names devices by UUID, so it needs every UUID source
        # already read to know which device a line is talking about
        by_uuid = {}
        by_partuuid = {}
        by_label = {}
        by_id = {}
        for k, d in devs.items():
            for idx, f in ((by_uuid, "uuid"), (by_partuuid, "partuuid"),
                           (by_label, "label"), (by_id, "by_id")):
                if d.get(f):
                    idx.setdefault(d[f].lower(), k)

        def fstab_dev(spec):
            s = spec.strip()
            for pre, idx in (("uuid=", by_uuid), ("partuuid=", by_partuuid),
                             ("label=", by_label), ("id=", by_id)):
                if s.lower().startswith(pre):
                    return idx.get(s[len(pre):].strip('"').lower(), "")
            # an unresolved /dev/disk/by-*/ path names a device by a property,
            # not by a device: taking its basename invents a disk called
            # 'dm-uuid-LVM-ETR52u...' that no other artifact has ever heard of
            if s.startswith("/dev/disk/"):
                which, _, val = s[len("/dev/disk/"):].partition("/")
                return {"by-uuid": by_uuid, "by-partuuid": by_partuuid,
                        "by-label": by_label, "by-id": by_id
                        }.get(which, {}).get(val.lower(), "")
            return s if s.startswith("/dev/") else ""

        # and only where nothing live was collected. fstab says where a device
        # *would* mount; where df/findmnt/mount ran, a device they did not
        # name is a device that is not mounted, and vbox's fstab entry for the
        # CD drive would otherwise report an empty sr0 as mounted on
        # /media/cdrom0. With no live mount table at all - shaher collected
        # none - fstab is the only answer there is, so it is used.
        rel = self.col.rootfs("/etc/fstab") if not live_mounts else None
        if rel:
            for ln in self.lines(rel, "STORAGE"):
                s = ln.strip()
                if not s or s.startswith("#"):
                    continue
                f = s.split()
                if len(f) < 3:
                    continue
                dev = fstab_dev(f[0])
                if dev and f[1].startswith("/"):
                    rec(dev, "fstab", strict=True, mountpoint=f[1],
                        fstype=f[2],
                        mount_options=f[3] if len(f) > 3 else "")

        # /dev/dm-0 and ubuntu--vg-ubuntu--lv are one device under the two
        # names different tools print: the by-id symlinks point at the dm
        # spelling while lsblk reports the LV name. maj:min is the kernel's own
        # identity, so a collision there is one device, not two.
        groups = {}
        for k, d in devs.items():
            if d.get("maj_min"):
                groups.setdefault(d["maj_min"], []).append(k)
        generic = re.compile(r"^(dm-\d+|loop\d+)$")
        for mm, keys in groups.items():
            if len(keys) < 2:
                continue
            keys.sort(key=lambda k: (bool(generic.match(k)), k))
            keep = devs[keys[0]]
            for other in keys[1:]:
                d = devs.pop(other)
                for f, v in d.items():
                    if f in ("device", "_sources"):
                        continue
                    if f in multi:
                        for one in v.split("; "):
                            cur = [x for x in keep.get(f, "").split("; ") if x]
                            if one and one not in cur:
                                keep[f] = "; ".join(cur + [one])
                    elif v and not keep.get(f):
                        keep[f] = v
                for s in d["_sources"]:
                    if s not in keep["_sources"]:
                        keep["_sources"].append(s)
                keep["aliases"] = "; ".join(
                    [x for x in (keep.get("aliases", ""), other) if x])

        # a partition under its disk, a volume under the partition it sits on
        def order(d):
            return (d.get("parent") or d["device"], 1 if d.get("parent") else 0,
                    d["device"])

        for d in sorted(devs.values(), key=order):
            d["sources"] = ", ".join(d.pop("_sources"))
            t.add_dict(d)

    def t_storage_raw(self):
        t = self.table("STORAGE_RAW", "Storage artifacts, verbatim",
                       ["source", "line_no", "text"], "System",
                       "Every live_response/storage artifact as collected - the "
                       "LVM (pvs/vgs/lvs/*display), mdadm and lxc output that "
                       "has no device row of its own, and what the tools "
                       "actually printed behind the STORAGE join. The -J "
                       "artifacts are JSON documents, so each device or "
                       "filesystem is one row rather than one row per line of "
                       "pretty-printed JSON; nested children are flattened and "
                       "carry _parent.")
        for rel in sorted(self.col.glob("live_response/storage/**")):
            txt = self.text(rel, "STORAGE_RAW")
            entries = self._json_entries(txt)
            if entries is not None:
                for i, ent in enumerate(entries, 1):
                    t.add(os.path.basename(rel), i,
                          "; ".join("%s=%s" % (k, _velo_cell(v))
                                    for k, v in ent.items()
                                    if v not in (None, "", [], {})))
                continue
            for i, ln in enumerate(txt.splitlines(), 1):
                if ln.strip():
                    t.add(os.path.basename(rel), i, ln.rstrip())

    def t_mounts(self):
        t = self.table("MOUNTS", "Mounted filesystems",
                       ["device", "mountpoint", "fstype", "options", "source"],
                       "System", "Parsed mount table plus /etc/fstab.")
        for ln in self.col.lines("live_response/storage/mount.txt"):
            m = re.match(r"^(\S+)\s+on\s+(\S+)\s+type\s+(\S+)\s+\((.*)\)$", ln.strip())
            if m:
                t.add(m.group(1), m.group(2), m.group(3), m.group(4), "mount")
        # /etc/mtab is what the host itself believed was mounted, in the same
        # field order as fstab. It can disagree with the live mount output -
        # a bind mount hiding a directory shows in one and not the other.
        for path in ("/etc/fstab", "/etc/mtab", "/proc/mounts"):
            rel = self.col.rootfs(path)
            if not rel:
                continue
            for ln in self.lines(rel, "MOUNTS"):
                s = ln.strip()
                if not s or s.startswith("#"):
                    continue
                f = s.split()
                if len(f) >= 4:
                    t.add(f[0], f[1], f[2], f[3], path)

    # -- 5. accounts and authentication -------------------------------------
    def t_users(self):
        """Accounts, joined with everything else that says something about them.

        Reviewing accounts means asking the same four questions of each one -
        can it log in, is it privileged, does it have a key, has anyone used it -
        and those answers live in four different files. They are joined here so
        the review is one pass over one table.
        """
        t = self.table("USERS", "Local accounts",
                       ["username", "uid", "gid", "primary_group", "gecos",
                        "home", "shell", "login_capable", "password_status",
                        "privileged_groups", "all_groups", "authorized_keys",
                        "has_private_key", "last_login_utc", "last_login_from",
                        "failed_logins", "shell_history_lines", "sudo_rules",
                        "running_processes", "last_change", "min", "max",
                        "warn", "inactive", "expire"], "Account",
                       "/etc/passwd joined with /etc/shadow, /etc/group, the "
                       "SSH key files, lastlog/wtmp/btmp and the process table - "
                       "so 'is this account a problem' is answerable from one "
                       "row instead of six tables.")
        shadow = {}
        srel = self.col.rootfs("/etc/shadow")
        if srel:
            for ln in self.lines(srel, "USERS"):
                f = ln.split(":")
                if len(f) >= 9:
                    shadow[f[0]] = f
        # group membership, including the primary gid each account points at
        member_of = defaultdict(list)
        gid_of = {}
        grel = self.col.rootfs("/etc/group")
        for ln in self.lines(grel, "USERS") if grel else []:
            f = ln.split(":")
            if len(f) < 4:
                continue
            gid_of[f[2]] = f[0]
            for mem in f[3].split(","):
                if mem.strip():
                    member_of[mem.strip()].append(f[0])
        # ssh material and per-user shell history, keyed by home directory owner
        akeys, privkeys, hist = defaultdict(int), defaultdict(list), defaultdict(int)
        for pat in ("/root/.ssh/authorized_keys*", "/home/*/.ssh/authorized_keys*"):
            for rel in self.col.rootfs_glob(pat):
                owner = self._home_owner(self.col.host_path(rel))
                akeys[owner] += sum(
                    1 for l in self.col.lines(rel)
                    if l.strip() and not l.strip().startswith("#"))
        for pat in ("/root/.ssh/id_*", "/home/*/.ssh/id_*"):
            for rel in self.col.rootfs_glob(pat):
                host = self.col.host_path(rel)
                if not host.endswith(".pub"):
                    privkeys[self._home_owner(host)].append(os.path.basename(host))
        for pat in ("/root/.*history*", "/home/*/.*history*"):
            for rel in self.col.rootfs_glob(pat):
                hist[self._home_owner(self.col.host_path(rel))] += sum(
                    1 for l in self.col.lines(rel) if l.strip())
        # sudo rules naming the account directly
        sudo_for = defaultdict(list)
        sfiles = [r for r in [self.col.rootfs("/etc/sudoers")] if r] + \
            self.col.rootfs_glob("/etc/sudoers.d/*")
        for rel in sfiles:
            for ln in self.col.lines(rel):
                s = ln.strip()
                if not s or s.startswith("#") or s.startswith("Defaults"):
                    continue
                who = s.split()[0] if s.split() else ""
                if who and not who.startswith(("%", "@")):
                    sudo_for[who].append(trunc(s, 80))
        last_login, failed = self._login_summaries()
        procs_by_user = defaultdict(list)
        for pid, p in self._procs().items():
            u = p.get("user") or p.get("owner") or ""
            if u:
                procs_by_user[u].append(pid)

        prel = self.col.rootfs("/etc/passwd")
        for ln in self.lines(prel, "USERS") if prel else []:
            f = ln.split(":")
            if len(f) < 7:
                continue
            name = f[0]
            sh = shadow.get(name, [])
            pw = sh[1] if len(sh) > 1 else ""
            status = ("locked" if pw.startswith(("!", "*")) else
                      "no password" if pw == "" else
                      "hash set")
            lastchg = ""
            if len(sh) > 2 and sh[2].isdigit():
                lastchg = (datetime(1970, 1, 1, tzinfo=timezone.utc) +
                           timedelta(days=int(sh[2]))).strftime("%Y-%m-%d")
            groups = member_of.get(name, [])
            priv = [g for g in groups if g in PRIVILEGED_GROUPS]
            ll = last_login.get(name, ("", ""))
            t.add(name, f[2], f[3], gid_of.get(f[3], ""), f[4], f[5], f[6],
                  "no" if re.search(r"(nologin|/false|/sync)$", f[6]) else "yes",
                  status,
                  ", ".join(sorted(priv)), ", ".join(sorted(groups)),
                  akeys.get(name, "") or "",
                  ", ".join(sorted(privkeys.get(name, []))),
                  ll[0], ll[1], failed.get(name, "") or "",
                  hist.get(name, "") or "",
                  " | ".join(sudo_for.get(name, [])),
                  # a count, not the pid list: root owns every kernel thread and
                  # the list is unreadable. Filter PROCESSES by user for the pids.
                  len(procs_by_user.get(name, [])) or "",
                  lastchg,
                  sh[3] if len(sh) > 3 else "", sh[4] if len(sh) > 4 else "",
                  sh[5] if len(sh) > 5 else "", sh[6] if len(sh) > 6 else "",
                  sh[7] if len(sh) > 7 else "")

    @staticmethod
    def _home_owner(host_path):
        m = re.match(r"/home/([^/]+)/", host_path)
        return m.group(1) if m else ("root" if host_path.startswith("/root/") else "")

    def _login_summaries(self):
        """username -> (last login utc, from where), and -> failed-login count."""
        last, failed = {}, defaultdict(int)
        uid_to_name = {}
        prel = self.col.rootfs("/etc/passwd")
        for ln in self.col.lines(prel) if prel else []:
            f = ln.split(":")
            if len(f) >= 3 and f[2].isdigit():
                uid_to_name[int(f[2])] = f[0]
        for rel in self._log_files():
            base = os.path.basename(rel).lower()
            raw = decompress_bytes(rel, self.col.read_bytes(rel))
            if not raw:
                continue
            if base.startswith("lastlog"):
                for r in parse_lastlog(raw):
                    nm = uid_to_name.get(r["uid"])
                    if nm:
                        last[nm] = (r["time"].strftime("%Y-%m-%d %H:%M:%S"),
                                    r["host"] or r["line"])
            elif base.startswith("wtmp"):
                for r in parse_utmp(raw):
                    if r["type"] != "USER_PROCESS" or not r["user"] or not r["time"]:
                        continue
                    cur = last.get(r["user"])
                    stamp = r["time"].strftime("%Y-%m-%d %H:%M:%S")
                    if not cur or stamp > cur[0]:
                        last[r["user"]] = (stamp, r["ip"] or r["host"] or "local")
            elif base.startswith("btmp"):
                for r in parse_utmp(raw):
                    if r["user"]:
                        failed[r["user"]] += 1
        return last, failed

    def t_groups(self):
        t = self.table("GROUPS", "Local groups",
                       ["group", "gid", "members", "member_count"], "Account",
                       "/etc/group - check the privileged ones for surprises.")
        grel = self.col.rootfs("/etc/group")
        for ln in self.lines(grel, "GROUPS") if grel else []:
            f = ln.split(":")
            if len(f) >= 4:
                mem = [m for m in f[3].split(",") if m]
                t.add(f[0], f[2], ", ".join(mem), len(mem))

    def t_sudoers(self):
        t = self.table("SUDOERS", "sudo configuration",
                       ["file", "line_no", "rule", "nopasswd"], "Privilege",
                       "/etc/sudoers and /etc/sudoers.d/* - passwordless rules stand out.")
        files = []
        main = self.col.rootfs("/etc/sudoers")
        if main:
            files.append(main)
        files += self.col.rootfs_glob("/etc/sudoers.d/*")
        for rel in files:
            for i, ln in enumerate(self.lines(rel, "SUDOERS"), 1):
                s = ln.strip()
                if s and not s.startswith("#"):
                    t.add(self.col.host_path(rel), i, s,
                          "yes" if "NOPASSWD" in s.upper() else "")

    def t_logins(self):
        t = self.table("LOGINS", "Login history",
                       ["user", "terminal", "source_host", "start", "end", "duration",
                        "source"], "Authentication",
                       "last / lastb / who, every variant UAC captured.")
        rx = re.compile(r"^(\S+)\s+(\S+)\s+(\S*)\s{2,}(\w{3}\s+\w{3}\s+\d+\s+[\d:]+)"
                        r"\s*-?\s*(\S+)?\s*(\(.*\))?\s*$")
        for rel in sorted(self.col.glob("live_response/system/last*.txt")) + \
                   sorted(self.col.glob("live_response/system/who*.txt")):
            for ln in self.lines(rel, "LOGINS"):
                s = ln.rstrip()
                if not s.strip() or s.startswith("wtmp begins") or s.startswith("btmp begins"):
                    continue
                m = rx.match(s)
                if m:
                    t.add(m.group(1), m.group(2), m.group(3), m.group(4),
                          m.group(5) or "", (m.group(6) or "").strip("()"),
                          os.path.basename(rel))
                else:
                    f = s.split()
                    if f:
                        t.add(f[0], f[1] if len(f) > 1 else "", "",
                              " ".join(f[2:]), "", "", os.path.basename(rel))

    # message shape -> (event label, regex whose named groups fill user/ip/port)
    # (event label, regex, class) - class 'priv' feeds PRIVILEGE_ACTIVITY.
    # FOR577: the authorization log is where "account creation, user logins from
    # external services and privilege use such as using sudo" are recorded, so
    # each of those three gets its own recognisable event rather than a blob.
    AUTH_EVENT_RULES = [
        # -- privilege use ---------------------------------------------------
        ("sudo command", re.compile(
            r"^\s*(?P<user>\S+)\s*:\s*(?:TTY=(?P<tty>\S*)\s*;\s*)?"
            r"(?:PWD=(?P<pwd>\S*)\s*;\s*)?(?:USER=(?P<target>\S*)\s*;\s*)?"
            r"(?:GROUP=\S*\s*;\s*)?(?:TSID=\S*\s*;\s*)?"
            r"(?:ENV=.*?\s*;\s*)?COMMAND=(?P<cmd>.*)$"), "priv"),
        ("sudo denied", re.compile(
            r"^\s*(?P<user>\S+)\s*:\s*(?P<detail>\d+ incorrect password attempts?"
            r"|user NOT in sudoers|command not allowed|"
            r"sorry, you must have a tty to run sudo|"
            r"a password is required)"), "priv"),
        ("su", re.compile(
            r"(?:\(to (?P<target>\S+)\)\s*(?P<user>\S+)|"
            r"Successful su for (?P<target2>\S+) by (?P<user2>\S+))"), "priv"),
        ("su failed", re.compile(
            r"FAILED su(?: \(to (?P<target>\S+)\))?(?: for (?P<target2>\S+))?"
            r"(?: by (?P<user>\S+))?"), "priv"),
        ("polkit authorization", re.compile(
            r"(?:Operator of unix-(?:session|process):\S+ successfully "
            r"authenticated as unix-user:(?P<user>\S+)|"
            r"Registered Authentication Agent)"), "priv"),
        ("pkexec", re.compile(
            r"(?P<user>\S+):\s*Executing command\s*\[USER=(?P<target>[^\]\s]+)"
            r".*?\[?COMMAND=(?P<cmd>[^\]]*)\]?"), "priv"),
        ("run0/systemd-run elevation", re.compile(
            r"(?:run0|systemd-run).*?(?:as|to) (?:unix-)?user (?P<target>\S+)"), "priv"),
        # -- account and group modification ----------------------------------
        # target_user holds the account or group that changed; user holds who
        # made the change on the lines that name them (gpasswd does, useradd
        # does not - the caller is in the surrounding sudo record instead)
        ("account created", re.compile(
            r"new user: name=(?P<target>[^,]+)"), "priv"),
        ("account deleted", re.compile(
            r"delete user '(?P<target>[^']+)'"), "priv"),
        ("account modified", re.compile(
            r"(?:change user '(?P<target>[^']+)'|"
            r"changed (?:shell|home directory|password expiry) for (?P<target2>\S+))"),
         "priv"),
        ("group created", re.compile(
            r"new group: name=(?P<target>[^,]+)"), "priv"),
        ("group deleted", re.compile(
            r"(?:group '(?P<target>[^']+)' removed|"
            r"removed group '(?P<target2>[^']+)')"), "priv"),
        ("group membership change", re.compile(
            r"(?:add '(?P<target>[^']+)' to (?:group|shadow group) '(?P<grp>[^']+)'"
            r"|delete '(?P<target2>[^']+)' from (?:group|shadow group) '(?P<grp2>[^']+)'"
            r"|user (?P<target3>\S+) (?:added|removed) by (?P<user>\S+) "
            r"(?:to|from) group (?P<grp3>\S+))"), "priv"),
        # anchored on 'changed for' so 'Failed password for invalid user ...'
        # is not read as a password change
        ("password changed", re.compile(
            r"password changed for (?P<target>[^\s,]+)"), "priv"),
        # -- remote / interactive authentication -----------------------------
        ("failed password", re.compile(
            r"Failed (?P<method>password|publickey|none|keyboard-interactive\S*) for "
            r"(?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)"
            r"(?: port (?P<port>\d+))?"), "auth"),
        ("invalid user", re.compile(
            r"Invalid user (?P<user>\S*)\s*from (?P<ip>\S+)"
            r"(?: port (?P<port>\d+))?"), "auth"),
        ("accepted login", re.compile(
            r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+)"
            r"(?: port (?P<port>\d+))?"), "auth"),
        ("public key accepted", re.compile(
            r"Found matching (?P<method>\S+) key: (?P<detail>\S+)"), "auth"),
        ("root login refused", re.compile(
            r"ROOT LOGIN REFUSED|Root login rejected|"
            r"User root from (?P<ip>\S+) not allowed"), "auth"),
        ("max auth attempts", re.compile(
            r"(?:error: maximum authentication attempts exceeded|"
            r"Too many authentication failures)(?: for (?P<user>\S+))?"
            r"(?: from (?P<ip>\S+))?"), "auth"),
        ("connection closed", re.compile(
            r"(?:Connection closed|Connection reset|Disconnected from|"
            r"Received disconnect from)"
            r"(?: by)?(?: (?:authenticating |invalid )?user (?P<user>\S+))?"
            r" (?P<ip>\S+)(?: port (?P<port>\d+))?"), "auth"),
        ("session opened", re.compile(
            r"session opened for user (?P<user>[^\s(]+)"), "session"),
        ("session closed", re.compile(
            r"session closed for user (?P<user>\S+)"), "session"),
        ("new session", re.compile(
            r"New session (?P<detail>\S+) of user (?P<user>\S+)"), "session"),
        ("session removed", re.compile(
            r"(?:Removed session|Session (?P<detail>\S+) logged out)"), "session"),
        ("authentication failure", re.compile(
            r"authentication failure;"), "auth"),
        ("pam module failure", re.compile(
            r"PAM \d+ more authentication failures?|"
            r"pam_\w+\(.*\): (?:auth could not identify password|"
            r"check pass; user unknown)"), "auth"),
        ("cron session", re.compile(
            r"pam_unix\(cron:session\)"), "session"),
    ]

    # tags a message as privileged even when no rule above claimed it
    PRIV_HINT_RE = PRIV_HINT_RE

    AUTH_LOG_PATTERNS = ["/var/log/auth.log*", "/var/log/secure*",
                         "/var/log/sulog*", "/var/log/authlog*",
                         "/var/log/user.log*"]

    def _auth_classify(self, proc, msg):
        """One auth line -> parsed fields, or empties when no rule claims it.

        Returns (event, class, user, target_user, target_group, ip, port, cmd,
        tty, pwd).
        """
        for label, erx, klass in self.AUTH_EVENT_RULES:
            em = erx.search(msg)
            if not em:
                continue
            g = em.groupdict()
            # 'sudo command' and friends key off the sudo message shape, which
            # other daemons can imitate; require the daemon to match
            if label.startswith("sudo") and "sudo" not in proc.lower():
                continue
            if label in ("su", "su failed") and \
                    proc.lower().split("[")[0] not in ("su", "su-l", "runuser"):
                continue
            pick = lambda *k: next((g[x].strip() for x in k
                                    if g.get(x) and g[x].strip()), "")
            return (label, klass, pick("user", "user2", "user3"),
                    pick("target", "target2", "target3"),
                    pick("grp", "grp2", "grp3"), pick("ip"),
                    pick("port"), pick("cmd"), pick("tty"), pick("pwd"))
        return ("", "", "", "", "", "", "", "", "", "")

    def t_auth_events(self):
        """auth.log / secure, rotations included, with the semantics broken out.

        FOR577 lists three things this log answers: who logged in from outside,
        what accounts and groups changed, and what was run with elevated
        privilege.  Each gets its own column here so none of them needs a regex
        over the message blob to find.
        """
        t = self.table("AUTH_LOG", "Authentication log entries",
                       ["timestamp_utc", "timestamp_raw", "host", "process", "pid",
                        "event", "event_class", "user", "target_user",
                        "target_group", "source_ip", "port", "tty", "pwd",
                        "command", "result", "message", "source"],
                       "Authentication",
                       "auth.log / secure - remote logins, account and group "
                       "changes, and privilege use (sudo/su/pkexec). Compressed "
                       "rotations are expanded; event_class is one of "
                       "auth/session/priv.")
        rx = re.compile(r"^(\w{3}\s+\d+\s+[\d:]+|\S+T\S+|\d{4}-\d\d-\d\d \S+)\s+"
                        r"(\S+)\s+([^\s:]+?)(?:\[(\d+)\])?:\s*(.*)$")
        for pat in self.AUTH_LOG_PATTERNS:
            for rel in self.col.rootfs_glob(pat):
                lines = self.dlines(rel, "AUTH_LOG")
                if lines is None:
                    self.use(rel, "AUTH_LOG (undecodable)")
                    continue
                host_path = self.col.host_path(rel)
                for ln in lines:
                    m = rx.match(ln)
                    if not m:
                        continue
                    raw_ts, lhost, proc, pid, msg = m.groups()
                    (event, klass, user, target, grp, ip, port,
                     cmd, tty, pwd) = self._auth_classify(proc, msg)
                    # PAM spells the same facts as key=value regardless of the
                    # service, so fill anything the shape rules did not supply
                    if not user:
                        um = re.search(r"\b(?:user|acct|ruser|logname)=[\"']?"
                                       r"([^\s\"']+)", msg)
                        user = um.group(1) if um else ""
                    if not ip:
                        rm = re.search(r"\brhost=([^\s]+)", msg)
                        ip = rm.group(1) if rm and rm.group(1) not in ("", "-") else ""
                    if not tty:
                        tm = re.search(r"\btty=(\S+)", msg)
                        tty = tm.group(1) if tm else ""
                    if not klass and self.PRIV_HINT_RE.search(proc):
                        klass = "priv"
                    result = ("failure" if re.search(
                        r"\b(fail|failed|failure|denied|refused|invalid|"
                        r"incorrect|NOT in sudoers|error)\b", msg, re.I)
                        else "success" if event else "")
                    if ip:
                        self.tri.ioc(ip, host_path)
                    t.add(self.ts_utc(raw_ts), raw_ts, lhost, proc, pid or "",
                          event, klass, user, target, grp, ip, port, tty, pwd,
                          cmd, result, msg, host_path)

    def t_privilege_activity(self):
        """Every elevation and account change, wherever it was logged.

        On a journal-only host there is no auth.log at all, and on a host with
        auditd the same sudo call is recorded a third way.  Answering "what did
        they do as root" from one table means reading all three, so this view
        merges them and keeps the origin in a column.
        """
        t = self.table("PRIVILEGE_ACTIVITY", "Privilege use and account changes",
                       ["timestamp_utc", "event", "actor", "target_user",
                        "target_group", "command", "tty", "working_dir",
                        "source_ip", "result", "logged_by", "detail", "source"],
                       "Privilege",
                       "sudo/su/pkexec, useradd/usermod/groupadd and password "
                       "changes, merged from auth.log, the journal and auditd - "
                       "so the answer is the same whichever of the three the "
                       "host happens to keep. actor is who elevated where the "
                       "line names them; target_user/target_group are what "
                       "changed. The same act can appear once per source, which "
                       "logged_by makes explicit rather than hiding.")

        def name_for(actor):
            """auditd and the journal identify the actor by loginuid, not name."""
            a = (actor or "").strip()
            if a.isdigit():
                nm = self.tri.uids.get(int(a))
                return "%s (uid %s)" % (nm, a) if nm else "uid %s" % a
            return a

        def emit(ts, event, actor, target, grp, cmd, tty, pwd, ip, result,
                 origin, detail, src):
            t.add(ts, event, name_for(actor), target, grp, cmd, tty, pwd, ip,
                  result, origin, trunc(detail, 400), src)

        # -- 1. auth.log / secure
        rx = re.compile(r"^(\w{3}\s+\d+\s+[\d:]+|\S+T\S+|\d{4}-\d\d-\d\d \S+)\s+"
                        r"(\S+)\s+([^\s:]+?)(?:\[(\d+)\])?:\s*(.*)$")
        for pat in self.AUTH_LOG_PATTERNS:
            for rel in self.col.rootfs_glob(pat):
                lines = self.dlines(rel, "PRIVILEGE_ACTIVITY")
                if lines is None:
                    continue
                host_path = self.col.host_path(rel)
                for ln in lines:
                    m = rx.match(ln)
                    if not m:
                        continue
                    raw_ts, _lhost, proc, _pid, msg = m.groups()
                    (event, klass, user, target, grp, ip, _port,
                     cmd, tty, pwd) = self._auth_classify(proc, msg)
                    if klass != "priv":
                        continue
                    result = "failure" if re.search(
                        r"\b(fail|failed|denied|NOT in sudoers|incorrect)\b",
                        msg, re.I) else "success"
                    emit(self.ts_utc(raw_ts), event, user, target, grp, cmd,
                         tty, pwd, ip, result, "auth.log", msg, host_path)

        # -- 2. the journal (the only store on a modern journal-only host)
        for ts, ident, msg, _hostname, tty0, host_path in \
                self.tri.journal_scan()["events"]:
            (event, klass, user, target, grp, ip, _port,
             cmd, tty, pwd) = self._auth_classify(ident, msg)
            if klass != "priv":
                continue
            result = "failure" if re.search(
                r"\b(fail|failed|denied|NOT in sudoers|incorrect)\b",
                msg, re.I) else "success"
            emit(ts, event, user, target, grp, cmd, tty or tty0, pwd, ip,
                 result, "journal", msg, host_path)

        # -- 3. auditd, which records the syscall rather than the message
        for rel in self._audit_files():
            lines = self.dlines(rel, "PRIVILEGE_ACTIVITY")
            if lines is None:
                continue
            host_path = self.col.host_path(rel)
            for ln in lines:
                m = self.AUDIT_HDR_RE.search(ln)
                if not m:
                    continue
                rtype, ts_s, _eid, body = m.groups()
                if rtype not in ("USER_CMD", "USER_AUTH", "USER_ACCT",
                                 "USER_START", "USER_ROLE_CHANGE",
                                 "ADD_USER", "DEL_USER", "ADD_GROUP",
                                 "DEL_GROUP", "USER_MGMT", "CHUSER_ID",
                                 "USER_CHAUTHTOK", "CRED_ACQ", "CRED_REFR",
                                 "GRP_MGMT", "ACCT_LOCK", "ACCT_UNLOCK"):
                    continue
                kv = self._audit_kv(body)
                dt = epoch(ts_s)
                res = kv.get("res", "")
                emit(dt.strftime("%Y-%m-%d %H:%M:%S") if dt else "",
                     rtype.lower().replace("_", " "),
                     kv.get("auid", kv.get("uid", "")),
                     kv.get("acct", kv.get("id", "")), kv.get("grp", ""),
                     kv.get("cmd", kv.get("exe", "")),
                     kv.get("terminal", kv.get("tty", "")), kv.get("cwd", ""),
                     kv.get("addr", ""),
                     "success" if res in ("success", "yes", "1") else
                     "failure" if res else "",
                     "auditd", body, host_path)

    FAILED_LOGIN_RULES = FAILED_LOGIN_RULES

    @staticmethod
    def _failed_login_match(proc, msg):
        return match_failed_login(proc, msg)


    def t_failed_logins(self):
        """Every failed authentication, from all five places Linux records them.

        FOR577 lists "check for large numbers of failed logins" as the first
        sign of account attack, but the evidence is scattered: btmp holds the
        binary records, auth.log the sshd/sudo/PAM messages, the journal the
        same messages on hosts with no auth.log, auditd the syscall-level view
        and faillog a per-account counter. One table, with where each row came
        from, so a brute-force burst is countable instead of correlated by hand.
        """
        t = self.table("FAILED_LOGINS", "Failed authentication attempts",
                       ["timestamp_utc", "kind", "user", "source_host",
                        "source_ip", "port", "terminal", "service", "method",
                        "detail", "logged_by", "source"],
                       "Authentication",
                       "btmp, auth.log/secure, the journal, auditd and faillog "
                       "merged. The same attempt can be recorded by more than "
                       "one of them; logged_by says which, so a count can be "
                       "taken from a single source rather than the union.")

        # -- 1. btmp: the binary record of failed logins
        for rel in self._log_files():
            base = os.path.basename(rel).lower()
            if not base.startswith("btmp"):
                continue
            raw = decompress_bytes(rel, self.col.read_bytes(rel))
            host_path = self.col.host_path(rel)
            if not raw:
                self.use(rel, "FAILED_LOGINS (empty - no failed logins recorded)")
                continue
            self.use(rel, "FAILED_LOGINS")
            for r in parse_utmp(raw):
                if r["ip"]:
                    self.tri.ioc(r["ip"], host_path)
                t.add(r["time"].strftime("%Y-%m-%d %H:%M:%S") if r["time"] else "",
                      "failed login", r["user"], r["host"], r["ip"], "",
                      r["line"], "", "", r["type"], "btmp", host_path)

        # -- 2. auth.log / secure
        rx = re.compile(r"^(\w{3}\s+\d+\s+[\d:]+|\S+T\S+|\d{4}-\d\d-\d\d \S+)\s+"
                        r"(\S+)\s+([^\s:]+?)(?:\[(\d+)\])?:\s*(.*)$")
        for pat in self.AUTH_LOG_PATTERNS:
            for rel in self.col.rootfs_glob(pat):
                lines = self.dlines(rel, "FAILED_LOGINS")
                if lines is None:
                    continue
                host_path = self.col.host_path(rel)
                for ln in lines:
                    m = rx.match(ln)
                    if not m:
                        continue
                    raw_ts, _lhost, proc, _pid, msg = m.groups()
                    hit = self._failed_login_match(proc, msg)
                    if not hit:
                        continue
                    label, user, ip, port, method, detail = hit
                    if not user:
                        um = re.search(r"\b(?:user|acct|ruser|logname)=[\"']?"
                                       r"([^\s\"']+)", msg)
                        user = um.group(1) if um else ""
                    if not ip:
                        rm = re.search(r"\brhost=([^\s]+)", msg)
                        ip = rm.group(1) if rm and rm.group(1) not in ("", "-") else ""
                    tm = re.search(r"\btty=(\S+)", msg)
                    if ip:
                        self.tri.ioc(ip, host_path)
                    t.add(self.ts_utc(raw_ts), label, user, "", ip, port,
                          tm.group(1) if tm else "", proc, method,
                          detail or trunc(msg, 200), "auth.log", host_path)

        # -- 3. the journal, which is the only store on a journal-only host
        for ts, ident, msg, hostname, tty, host_path in \
                self.tri.journal_scan()["events"]:
            hit = self._failed_login_match(ident, msg)
            if not hit:
                continue
            label, user, ip, port, method, detail = hit
            if not user:
                um = re.search(r"\b(?:user|acct|ruser|logname)=[\"']?"
                               r"([^\s\"']+)", msg)
                user = um.group(1) if um else ""
            if not ip:
                rm = re.search(r"\brhost=([^\s]+)", msg)
                ip = rm.group(1) if rm and rm.group(1) not in ("", "-") else ""
            if ip:
                self.tri.ioc(ip, host_path)
            t.add(ts, label, user, hostname, ip, port, tty, ident, method,
                  detail or trunc(msg, 200), "journal", host_path)

        # -- 4. auditd
        for rel in self._audit_files():
            lines = self.dlines(rel, "FAILED_LOGINS")
            if lines is None:
                continue
            host_path = self.col.host_path(rel)
            for ln in lines:
                m = self.AUDIT_HDR_RE.search(ln)
                if not m:
                    continue
                rtype, ts_s, _eid, body = m.groups()
                if rtype not in ("USER_AUTH", "USER_LOGIN", "USER_ACCT",
                                 "USER_ERR", "ANOM_LOGIN_FAILURES",
                                 "USER_CHAUTHTOK", "CRED_ACQ"):
                    continue
                kv = self._audit_kv(body)
                if kv.get("res") in ("success", "yes", "1"):
                    continue
                dt = epoch(ts_s)
                addr = kv.get("addr", "")
                if addr in ("?", "-"):
                    addr = ""
                if addr:
                    self.tri.ioc(addr, host_path)
                t.add(dt.strftime("%Y-%m-%d %H:%M:%S") if dt else "",
                      rtype.lower().replace("_", " "),
                      kv.get("acct", kv.get("auid", "")),
                      kv.get("hostname", ""), addr, "",
                      kv.get("terminal", kv.get("tty", "")),
                      os.path.basename(kv.get("exe", "")), kv.get("op", ""),
                      trunc(body, 200), "auditd", host_path)

        # -- 5. faillog: a per-account counter rather than per-attempt records
        uid_to_name = {}
        prel = self.col.rootfs("/etc/passwd")
        for ln in self.col.lines(prel) if prel else []:
            f = ln.split(":")
            if len(f) >= 3 and f[2].isdigit():
                uid_to_name[int(f[2])] = f[0]
        # _log_files() already covers /var/log, so the explicit glob is only a
        # fallback for profiles that store it elsewhere - dedupe the overlap
        seen_fail = set()
        for rel in self._log_files() + self.col.rootfs_glob("/var/log/faillog") \
                + self.col.rootfs_glob("/etc/security/faillog"):
            if os.path.basename(rel).lower() != "faillog" \
                    or rel.lower() in seen_fail:
                continue
            seen_fail.add(rel.lower())
            raw = decompress_bytes(rel, self.col.read_bytes(rel))
            host_path = self.col.host_path(rel)
            if not raw:
                self.use(rel, "FAILED_LOGINS (faillog empty)")
                continue
            self.use(rel, "FAILED_LOGINS")
            for r in parse_faillog(raw):
                t.add(r["time"].strftime("%Y-%m-%d %H:%M:%S") if r["time"] else "",
                      "faillog counter",
                      uid_to_name.get(r["uid"], "uid %d" % r["uid"]), "", "", "",
                      r["line"], "", "",
                      "%d failure(s), max %d" % (r["count"], r["max"]),
                      "faillog", host_path)

    def t_ssh(self):
        t = self.table("SSH", "SSH configuration and keys",
                       ["type", "path", "owner_hint", "detail"], "Remote Access",
                       "authorized_keys, known_hosts, host keys and sshd_config.")
        for pat, kind in (("/root/.ssh/authorized_keys*", "authorized_keys"),
                          ("/home/*/.ssh/authorized_keys*", "authorized_keys"),
                          ("/etc/ssh/authorized_keys*", "authorized_keys"),
                          ("/etc/ssh/sshd_config.d/*", "sshd_config"),
                          ("/root/.ssh/known_hosts*", "known_hosts"),
                          ("/home/*/.ssh/known_hosts*", "known_hosts"),
                          ("/etc/ssh/ssh_host_*_key.pub", "host_key"),
                          ("/root/.ssh/*.pub", "user_public_key"),
                          ("/home/*/.ssh/*.pub", "user_public_key"),
                          ("/root/.ssh/config", "ssh_client_config"),
                          ("/home/*/.ssh/config", "ssh_client_config")):
            for rel in self.col.rootfs_glob(pat):
                host = self.col.host_path(rel)
                if kind == "user_public_key" and (
                        host.endswith(("known_hosts.pub", "authorized_keys.pub"))):
                    continue
                m = re.match(r"/home/([^/]+)/", host)
                owner = m.group(1) if m else ("root" if host.startswith("/root/") else "")
                emitted = False
                for ln in self.lines(rel, "SSH"):
                    if ln.strip() and not ln.strip().startswith("#"):
                        t.add(kind, host, owner, ln.strip())
                        emitted = True
                if not emitted:
                    # an empty authorized_keys still answers "was one present?"
                    t.add(kind, host, owner, "(file present but empty)")
        # private keys: never print the material, but record that it exists -
        # a key pair the account should not have is the lead, not its bytes
        for pat in ("/root/.ssh/id_*", "/home/*/.ssh/id_*",
                    "/root/.ssh/*.pem", "/home/*/.ssh/*.pem",
                    "/etc/ssh/ssh_host_*_key"):
            for rel in self.col.rootfs_glob(pat):
                host = self.col.host_path(rel)
                if host.endswith(".pub"):
                    continue
                m = re.match(r"/home/([^/]+)/", host)
                owner = m.group(1) if m else ("root" if host.startswith("/root/") else "")
                head = (self.text(rel, "SSH") or "").strip().splitlines()
                first = head[0] if head else ""
                enc = "encrypted" if any("ENCRYPTED" in h or "Proc-Type" in h
                                         for h in head[:4]) else "unencrypted"
                kind = ("host_private_key" if host.startswith("/etc/ssh/")
                        else "user_private_key")
                t.add(kind, host, owner, "%s bytes, %s, %s"
                      % (self.col.size(rel), enc, trunc(first, 60)))
        cfg = self.col.rootfs("/etc/ssh/sshd_config")
        if cfg:
            for ln in self.lines(cfg, "SSH"):
                s = ln.strip()
                if s and not s.startswith("#"):
                    t.add("sshd_config", "/etc/ssh/sshd_config", "", s)
        for rel in self.col.rootfs_glob("/etc/ssh/sshd_config.d/*"):
            for ln in self.lines(rel, "SSH"):
                s = ln.strip()
                if s and not s.startswith("#"):
                    t.add("sshd_config", self.col.host_path(rel), "", s)
        # The system-wide client config is a persistence spot in its own right:
        # a ProxyCommand or LocalCommand here runs for every outbound ssh any
        # account on the box makes. ssh_import_id names the remote source
        # authorized_keys is pulled from, which is an inbound trust decision.
        for pat in ("/etc/ssh/ssh_config", "/etc/ssh/ssh_config.d/*",
                    # vendor drop-ins are included by the same Include line as
                    # /etc/ssh/ssh_config.d and carry the same weight
                    "/usr/lib/ssh/ssh_config.d/*",
                    "/usr/lib/systemd/ssh_config.d/*",
                    "/usr/local/etc/ssh/ssh_config*",
                    "/etc/ssh/ssh_import_id"):
            for rel in self.col.rootfs_glob(pat):
                for ln in self.lines(rel, "SSH"):
                    s = ln.strip()
                    if s and not s.startswith("#"):
                        t.add("ssh_client_config", self.col.host_path(rel), "", s)
        # moduli is a large table of DH primes with no per-host meaning; record
        # that it was collected rather than emitting 4000 rows of numbers
        for rel in self.col.rootfs_glob("/etc/ssh/moduli"):
            self.use(rel, "SSH (moduli, not expanded)")
            t.add("moduli", self.col.host_path(rel), "",
                  "%s bytes of DH parameters, not expanded" % self.col.size(rel))

    # -- 6. persistence -----------------------------------------------------
    # /etc/cron.<period>/ holds executables, not crontab lines - the period is
    # implied by the directory and the file itself is a script
    CRON_DROPIN_PERIOD = {"cron.hourly": "@hourly", "cron.daily": "@daily",
                          "cron.weekly": "@weekly", "cron.monthly": "@monthly",
                          "cron.yearly": "@yearly", "cron.annually": "@yearly"}

    def t_cron(self):
        t = self.table("CRON", "Scheduled jobs (cron/at)",
                       ["file", "owner", "kind", "schedule", "run_as", "command",
                        "running_pids", "line_no"],
                       "Persistence",
                       "Crontabs split into schedule/command; cron.<period> "
                       "drop-in scripts listed as scripts with the period the "
                       "directory implies. running_pids joins the command "
                       "against the live process table - a scheduled job that "
                       "is also running right now is a different problem from "
                       "one that merely would.")
        pats = ["/etc/crontab", "/etc/cron.d/*", "/etc/cron.hourly/*",
                "/etc/cron.daily/*", "/etc/cron.weekly/*", "/etc/cron.monthly/*",
                "/etc/cron.yearly/*", "/etc/cron.annually/*",
                "/var/spool/cron/*", "/var/spool/cron/crontabs/*", "/var/spool/at/*",
                "/var/spool/cron/atjobs/*", "/var/spool/cron/atspool/*",
                "/var/spool/atjobs/*", "/etc/at.allow", "/etc/at.deny",
                "/etc/cron.allow", "/etc/cron.deny", "/etc/anacrontab"]
        seen = set()
        for pat in pats:
            for rel in self.col.rootfs_glob(pat):
                if rel.lower() in seen:
                    continue
                seen.add(rel.lower())
                host = self.col.host_path(rel)
                owner = os.path.basename(host) if "/spool/cron" in host else ""
                period = ""
                for d, p in self.CRON_DROPIN_PERIOD.items():
                    if "/%s/" % d in host:
                        period = p
                        break
                lines = self.lines(rel, "CRON")
                if period:
                    # one row for the job itself, then its body for review
                    t.add(host, owner, "script", period, "root",
                          os.path.basename(host),
                          self.running_pids_for(host), "")
                    for i, ln in enumerate(lines, 1):
                        s = ln.strip()
                        if s and not s.startswith("#"):
                            t.add(host, owner, "script_line", period, "", s,
                                  self.running_pids_for(s), i)
                    continue
                for i, ln in enumerate(lines, 1):
                    s = ln.strip()
                    if not s or s.startswith("#"):
                        continue
                    # SHELL=, PATH=, MAILTO= change how every later job runs
                    if re.match(r"^[A-Z_]+\s*=", s):
                        t.add(host, owner, "env", "", "", s, "", i)
                        continue
                    m = re.match(r"^(@\w+|(?:\S+\s+){4}\S+)\s+(.*)$", s)
                    if not m:
                        # anacrontab: 'period delay job-id command'
                        a = re.match(r"^(\d+|@\w+)\s+(\d+)\s+(\S+)\s+(.*)$", s)
                        if a:
                            t.add(host, owner, "anacron",
                                  "period=%s delay=%s" % (a.group(1), a.group(2)),
                                  "", a.group(4),
                                  self.running_pids_for(a.group(4)), i)
                        else:
                            t.add(host, owner, "unparsed", "", "", s, "", i)
                        continue
                    # the raw field separator may be tabs; collapse it so the
                    # schedule is groupable instead of '17 *\t* * *'
                    sched, rest = " ".join(m.group(1).split()), m.group(2)
                    runas = ""
                    if "/etc/cron" in host and rest.split():
                        first = rest.split()[0]
                        if re.match(r"^[a-z_][a-z0-9_-]*$", first) and "/" not in first:
                            runas, rest = first, rest[len(first):].strip()
                    t.add(host, owner, "crontab", sched, runas, rest,
                          self.running_pids_for(rest), i)
        self._velo_cron(t)

    UNIT_EXTS = (".service", ".timer", ".socket", ".path", ".target", ".mount",
                 ".automount", ".slice", ".scope", ".swap", ".device")

    def t_systemd_units(self):
        """Every unit file at any depth, not just .service.

        .socket and .path units start programs on a trigger and are a standard
        persistence spot, so restricting this to .service would hide them.
        """
        t = self.table("SYSTEMD_UNITS", "systemd unit files on disk",
                       ["unit", "unit_type", "path", "scope", "description",
                        "exec_start", "running_pids", "exec_start_pre",
                        "exec_stop", "user", "environment", "environment_file",
                        "wanted_by", "required_by", "listen", "watch_path",
                        "restart", "enabled_link"],
                       "Persistence",
                       "Every unit file copied from the host, all unit types, "
                       "with the lines that make something run. running_pids "
                       "joins ExecStart against the live process table.")
        plen = len(self.col.prefix)
        rootfs = tuple(rd.lower() + "/" for rd in self.col.rootfs_dirs)
        units = []
        for low, real in self.col._names.items():
            if not low.startswith(self.col.prefix):
                continue
            rel = real[plen:]
            rl = rel.lstrip("/").lower()
            if not rl.startswith(rootfs) or "/systemd/" not in rl:
                continue
            # A drop-in is a .conf inside <unit>.d/ and overrides the unit it
            # sits beside - including ExecStart. Editing a vendor unit shows up
            # in a package-integrity check; adding a drop-in beside it does not,
            # which is exactly why it is used. Matching only UNIT_EXTS meant
            # every one of them was invisible here.
            if rl.endswith(self.UNIT_EXTS) or (
                    rl.endswith(".conf")
                    and re.search(r"/[^/]+\.(?:%s)\.d/[^/]+\.conf$"
                                  % "|".join(e.lstrip(".") for e in self.UNIT_EXTS),
                                  rl)):
                units.append(rel)
        for rel in sorted(units, key=str.lower):
            host = self.col.host_path(rel)
            # /var/run is the same tmpfs as /run - classifying it as 'vendor'
            # made transient and generator units look shipped-by-a-package
            scope = ("user" if ("/systemd/user" in host
                                or re.search(r"/user/\d+/systemd/", host)) else
                     "runtime" if host.startswith(("/run/", "/var/run/")) else
                     "host-local" if host.startswith("/etc/") else "vendor")
            # a unit under a *.wants/ or *.requires/ dir is an enablement link
            link = ""
            m = re.search(r"/([^/]+\.(?:wants|requires))/", host)
            if m:
                link = m.group(1)
            d = defaultdict(list)
            for ln in self.lines(rel, "SYSTEMD_UNITS"):
                s = ln.strip()
                if "=" in s and not s.startswith(("#", ";", "[")):
                    k, v = s.split("=", 1)
                    d[k.strip().lower()].append(v.strip())
            j = lambda *keys: " | ".join(
                v for k in keys for v in d.get(k, []))
            base = os.path.basename(host)
            # a drop-in is named after the override, not the unit; report it
            # under the unit it modifies so the two sort together
            dm = re.search(r"/([^/]+)\.d/[^/]+\.conf$", host)
            if dm:
                base = dm.group(1)
                scope += " drop-in"
            t.add(base, os.path.splitext(base)[1].lstrip("."), host, scope,
                  j("description"), j("execstart"),
                  self.running_pids_for(j("execstart").split(" | ")[0]),
                  j("execstartpre"),
                  j("execstop"), j("user"), j("environment"), j("environmentfile"),
                  j("wantedby"), j("requiredby"),
                  j("listenstream", "listendatagram", "listensequentialpacket",
                    "listenfifo", "listenunix"),
                  j("pathexists", "pathchanged", "pathmodified",
                    "directorynotempty"),
                  j("restart"), link)

    def t_init_scripts(self):
        t = self.table("INIT_AND_PROFILE", "init scripts and shell profiles",
                       ["path", "line_no", "text"], "Persistence",
                       "rc.local, init.d, profile.d and per-user rc files.")
        pats = ["/etc/rc.local", "/etc/rc.local.shutdown", "/etc/rc*.d/*",
                "/etc/init.d/*", "/etc/init/*", "/etc/profile",
                # vendor packages drop login scripts outside /etc too, and the
                # same /etc/profile loop sources them
                "/etc/profile.d/*", "/usr/lib/*/profile.d/*",
                "/usr/share/*/profile.d/*",
                "/etc/bash.bashrc", "/etc/bashrc",
                "/etc/zsh/*", "/etc/csh.cshrc", "/etc/csh.login",
                "/root/.bashrc", "/root/.bash_profile", "/root/.profile",
                "/root/.bash_logout", "/root/.bash_login", "/root/.bash_aliases",
                "/root/.zshrc", "/root/.zshenv",
                "/root/.zprofile", "/root/.zlogin", "/root/.xinitrc",
                "/root/.xsession", "/root/.xprofile",
                "/home/*/.bashrc", "/home/*/.bash_profile", "/home/*/.profile",
                "/home/*/.bash_logout", "/home/*/.bash_login",
                "/home/*/.bash_aliases", "/home/*/.zshrc", "/home/*/.zshenv",
                "/home/*/.zprofile", "/home/*/.zlogin", "/home/*/.xinitrc",
                "/home/*/.xsession", "/home/*/.xprofile",
                "/home/*/.config/fish/config.fish",
                "/etc/ld.so.preload", "/etc/ld.so.conf",
                "/etc/ld.so.conf.d/*", "/etc/modules", "/etc/modules-load.d/*",
                "/etc/modprobe.d/*",
                "/etc/xdg/autostart/*", "/home/*/.config/autostart/*",
                "/root/.config/autostart/*",
                # hook directories that run as root on a routine system event -
                # a standard persistence spot that nothing else in the export
                # would have surfaced
                "/etc/update-motd.d/*", "/etc/logrotate.d/*",
                "/etc/apt/apt.conf.d/*", "/etc/dhcp/dhclient-exit-hooks.d/*",
                "/etc/dhcp/dhclient-enter-hooks.d/*",
                "/etc/NetworkManager/dispatcher.d/*",
                "/etc/networkd-dispatcher/*/*",
                "/etc/network/if-up.d/*", "/etc/network/if-pre-up.d/*",
                "/etc/network/if-down.d/*", "/etc/network/if-post-down.d/*",
                "/etc/kernel/postinst.d/*", "/etc/skel/.*", "/etc/pm/sleep.d/*", "/usr/lib/pm-utils/sleep.d/*",
                "/etc/systemd/system-generators/*",
                "/usr/lib/systemd/system-generators/*",
                # systemd runs every executable in these directories as root
                # around suspend and shutdown - the same idea as rc.local, in a
                # directory nothing else in the export was looking at
                "/etc/systemd/system-sleep/*", "/lib/systemd/system-sleep/*",
                "/usr/lib/systemd/system-sleep/*",
                "/etc/systemd/system-shutdown/*",
                "/lib/systemd/system-shutdown/*",
                "/usr/lib/systemd/system-shutdown/*"]
        seen = set()
        for pat in pats:
            for rel in self.col.rootfs_glob(pat):
                if rel.lower() in seen:
                    continue
                seen.add(rel.lower())
                host = self.col.host_path(rel)
                for i, ln in enumerate(self.lines(rel, "INIT_AND_PROFILE"), 1):
                    s = ln.strip()
                    if s and not s.startswith("#"):
                        t.add(host, i, ln.rstrip())

    def t_history(self):
        """Shell history, with the timestamp forms the shells actually write.

        bash under HISTTIMEFORMAT writes a '#<epoch>' line before each command
        and zsh writes ': <epoch>:<elapsed>;<command>'.  Emitting those as
        commands loses the only clock the history file has, so they are folded
        into a timestamp column instead.
        """
        t = self.table("SHELL_HISTORY", "Shell history",
                       ["user", "timestamp_utc", "shell", "file", "line_no",
                        "command"], "Execution",
                       "Every history file, in file order. bash/zsh timestamp "
                       "markers are decoded rather than listed as commands.")
        pats = ["/root/.*history*", "/home/*/.*history*", "/root/.*_history",
                "/home/*/.*_history", "/root/.mysql_history",
                "/home/*/.mysql_history", "/root/.histfile", "/home/*/.histfile",
                "/root/.local/share/fish/fish_history",
                "/home/*/.local/share/fish/fish_history",
                "/root/.config/fish/fish_history",
                "/home/*/.config/fish/fish_history"]
        zsh_rx = re.compile(r"^:\s*(\d+):\d+;(.*)$")
        seen = set()
        for pat in pats:
            for rel in self.col.rootfs_glob(pat):
                if rel.lower() in seen:
                    continue
                seen.add(rel.lower())
                host = self.col.host_path(rel)
                base = os.path.basename(host).lower()
                shell = ("zsh" if "zsh" in base else "fish" if "fish" in base else
                         "bash" if "bash" in base else "sh" if base in
                         (".sh_history", ".histfile") else
                         base.lstrip(".").replace("_history", ""))
                m = re.match(r"/home/([^/]+)/", host)
                user = m.group(1) if m else ("root" if host.startswith("/root/") else "")
                pending = ""
                for i, ln in enumerate(self.lines(rel, "SHELL_HISTORY"), 1):
                    s = ln.rstrip()
                    if not s.strip():
                        continue
                    if shell == "fish":
                        # fish writes '- cmd: <command>' / '  when: <epoch>'
                        fm = re.match(r"^\s*-\s*cmd:\s*(.*)$", s)
                        if fm:
                            pending = fm.group(1)
                            continue
                        fw = re.match(r"^\s*when:\s*(\d+)", s)
                        if fw and pending:
                            dt = epoch(fw.group(1))
                            t.add(user, dt.strftime("%Y-%m-%d %H:%M:%S") if dt else "",
                                  shell, host, i, pending)
                            pending = ""
                            continue
                        continue
                    zm = zsh_rx.match(s)
                    if zm:
                        dt = epoch(zm.group(1))
                        t.add(user, dt.strftime("%Y-%m-%d %H:%M:%S") if dt else "",
                              "zsh", host, i, zm.group(2))
                        continue
                    hm = re.match(r"^#(\d{9,})$", s.strip())
                    if hm:                      # bash HISTTIMEFORMAT marker
                        dt = epoch(hm.group(1))
                        pending = dt.strftime("%Y-%m-%d %H:%M:%S") if dt else ""
                        continue
                    t.add(user, pending, shell, host, i, s)
                    pending = ""
                if pending and shell == "fish":
                    t.add(user, "", shell, host, "", pending)

    def t_ld_preload(self):
        t = self.table("LD_PRELOAD", "LD_PRELOAD configuration",
                       ["path", "entry", "note"], "Rootkit",
                       "/etc/ld.so.preload - populated on a stock host means trouble.")
        for rel in ["chkrootkit/etc_ld_so_preload.txt",
                    "chkrootkit/stat_etc_ld_so_preload.txt"]:
            for ln in self.lines(rel, "LD_PRELOAD"):
                if ln.strip():
                    t.add(rel, ln.strip(), "")
        pre = self.col.rootfs("/etc/ld.so.preload")
        if pre:
            for ln in self.lines(pre, "LD_PRELOAD"):
                if ln.strip():
                    t.add("/etc/ld.so.preload", ln.strip(), "preloaded into every process")

    # -- 7. filesystem ------------------------------------------------------
    # UAC moved the filesystem-survey artifacts between profile generations:
    # the 2021 profiles wrote suid/sgid/getcap and the writable/hidden lists
    # under live_response/system/, later ones under a top-level system/.
    # Reading only one of the two locations does not raise - it produces an
    # empty table, which an analyst reads as "this host has no SUID binaries"
    # rather than "the parser looked in the wrong directory".
    SYS_DIRS = ("system", "live_response/system")

    def sysfiles(self, *names):
        """Collection-relative paths for a system-survey artifact, any profile."""
        out = []
        for d in self.SYS_DIRS:
            for name in names:
                out.extend(self.col.glob("%s/%s" % (d, name)))
        return sorted(set(out), key=str.lower)

    def _path_list(self, name, title, rels, category, description):
        t = self.table(name, title, ["path", "directory", "basename", "source"],
                       category, description, list(rels))
        for rel in rels:
            for ln in self.lines(rel, name):
                s = ln.strip()
                if s:
                    t.add(s, os.path.dirname(s), os.path.basename(s),
                          os.path.basename(rel))
        return t

    def t_suid(self):
        t = self.table("SUID_SGID", "SUID and SGID binaries",
                       ["path", "kind", "basename", "in_distro_baseline", "mode",
                        "uid", "owner", "gid", "group", "size", "mtime_utc",
                        "md5", "source"], "Privilege",
                       "system/suid.txt and sgid.txt, cross-checked against the "
                       "bodyfile for owner and timestamps and against "
                       "hash_executables for the hash.")
        meta = self._bodyfile_meta()
        hashes = self._exe_hashes()
        pairs = ([(r, "suid") for r in self.sysfiles("suid.txt")] +
                 [(r, "sgid") for r in self.sysfiles("sgid.txt")])
        for rel, kind in pairs:
            for ln in self.lines(rel, "SUID_SGID"):
                p = ln.strip()
                if not p:
                    continue
                bf = meta.get(p, {})
                t.add(p, kind, os.path.basename(p),
                      "yes" if p in BASELINE_SUID else "no",
                      bf.get("mode", ""), bf.get("uid", ""),
                      self.uid_name(bf.get("uid", "")), bf.get("gid", ""),
                      self.gid_name(bf.get("gid", "")), bf.get("size", ""),
                      bf.get("mtime", ""), hashes.get(p, {}).get("md5", ""), rel)

    def _exe_hashes(self):
        """path -> {md5, sha1, sha256} from hash_executables, built once."""
        if self._exe_hash_map is None:
            out = {}
            for algo in ("md5", "sha1", "sha256"):
                for rel in self.col.glob("hash_executables/*.%s" % algo):
                    for ln in self.col.lines(rel):
                        parts = ln.split(None, 1)
                        if len(parts) == 2:
                            out.setdefault(parts[1].strip(), {})[algo] = \
                                parts[0].strip()
            self._exe_hash_map = out
        return self._exe_hash_map

    def t_getcap(self):
        t = self.table("CAPABILITIES", "File capabilities (getcap)",
                       ["path", "basename", "capabilities", "mode", "owner",
                        "group", "mtime_utc", "md5", "source"], "Privilege",
                       "Capabilities grant slices of root without the SUID bit.")
        meta = self._bodyfile_meta()
        hashes = self._exe_hashes()
        for src in self.sysfiles("getcap.txt", "getcap_*.txt"):
            for ln in self.lines(src, "CAPABILITIES"):
                s = ln.strip()
                if not s:
                    continue
                m = re.match(r"^(\S+)\s+(.*)$", s)
                path, caps = (m.group(1), m.group(2)) if m else (s, "")
                bf = meta.get(path, {})
                t.add(path, os.path.basename(path), caps, bf.get("mode", ""),
                      self.uid_name(bf.get("uid", "")) or bf.get("uid", ""),
                      self.gid_name(bf.get("gid", "")) or bf.get("gid", ""),
                      bf.get("mtime", ""), hashes.get(path, {}).get("md5", ""), src)

    def t_writable(self):
        # 'not sticky' is the one that matters: /tmp is world-writable by
        # design and harmless because the sticky bit stops one user deleting
        # another's files. A world-writable directory *without* it is the
        # drop spot, so the list UAC keeps separately gets its own source.
        self._path_list("WORLD_WRITABLE", "World-writable paths (as UAC listed them)",
                        self.sysfiles("world_writable_files.txt",
                                      "world_writable_directories.txt",
                                      "world_writable_not_sticky_directories.txt"),
                        "Filesystem",
                        "UAC's raw list. Mostly symlinks - confirm modes in BODYFILE. "
                        "source names the list: *_not_sticky_directories are the "
                        "ones any user can delete out of.")
        self._path_list("GROUP_WRITABLE", "Group-writable paths",
                        self.sysfiles("group_writable_files.txt",
                                      "group_writable_directories.txt"), "Filesystem",
                        "UAC's raw group-writable list.")

    def t_hidden_files(self):
        self._path_list("HIDDEN_PATHS", "Hidden files and directories",
                        self.sysfiles("hidden_files.txt",
                                      "hidden_directories.txt"),
                        "Filesystem", "Dot-files outside the usual config set.")

    def t_socket_files(self):
        """Unix socket files as they sit on disk.

        UNIX_SOCKETS answers which sockets are bound right now; this answers
        which socket paths exist, including the ones nothing is listening on -
        a stale socket in a world-writable directory is a lead the live view
        cannot show.
        """
        self._path_list("SOCKET_FILES", "Socket files on disk",
                        self.sysfiles("socket_files.txt"), "Filesystem",
                        "Socket inodes found on the filesystem. Cross-check "
                        "against UNIX_SOCKETS: a path here with no bound "
                        "socket there is orphaned.")

    def t_unknown_owner(self):
        self._path_list("ORPHANED_PATHS", "Paths with no matching user or group",
                        self.sysfiles("user_name_unknown_files.txt",
                                      "user_name_unknown_directories.txt",
                                      "group_name_unknown_files.txt",
                                      "group_name_unknown_directories.txt"),
                        "Filesystem",
                        "Owners that no longer resolve - deleted attacker accounts.")

    def _bodyfile_meta(self):
        """path -> mode/uid/gid/size/mtime, built once and cached."""
        if getattr(self, "_bf_meta", None) is not None:
            return self._bf_meta
        meta = {}
        for ln in self.col.iter_lines("bodyfile/bodyfile.txt"):
            f = ln.split("|")
            if len(f) < 11:
                continue
            path = f[1].split(" -> ")[0]
            mt = ""
            try:
                n = int(f[8])
                if n > 0:
                    mt = datetime.fromtimestamp(n, timezone.utc).strftime(
                        "%Y-%m-%d %H:%M:%S")
            except (TypeError, ValueError, OverflowError, OSError):
                pass
            meta[path] = {"mode": f[3], "uid": f[4], "gid": f[5], "size": f[6],
                          "mtime": mt}
        self._bf_meta = meta
        return meta

    def t_bodyfile(self):
        t = self.table("BODYFILE", "Filesystem timeline (bodyfile)",
                       ["inode", "path", "directory", "basename", "link_target",
                        "mode", "uid", "owner", "gid", "group", "size",
                        "atime_utc", "mtime_utc", "ctime_utc", "crtime_utc"],
                       "Filesystem",
                       "Full mactime bodyfile, epochs rendered as UTC, with "
                       "uid/gid resolved against /etc/passwd and /etc/group - a "
                       "numeric owner that resolves to nothing is itself a lead.",
                       ["bodyfile/bodyfile.txt"])
        self.use("bodyfile/bodyfile.txt", "BODYFILE")

        def ts(v):
            try:
                n = int(v)
            except (TypeError, ValueError):
                return ""
            if n <= 0:
                return ""
            try:
                return datetime.fromtimestamp(n, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            except (OverflowError, OSError, ValueError):
                return ""

        for ln in self.col.iter_lines("bodyfile/bodyfile.txt"):
            f = ln.split("|")
            if len(f) < 11:
                continue
            name = f[1]
            path, _, target = name.partition(" -> ")
            t.add(f[2], path, os.path.dirname(path), os.path.basename(path),
                  target, f[3], f[4], self.uid_name(f[4]), f[5],
                  self.gid_name(f[5]), f[6],
                  ts(f[7]), ts(f[8]), ts(f[9]), ts(f[10]))

    def t_file_hashes(self):
        t = self.table("FILE_HASHES", "Executable hashes",
                       ["path", "directory", "basename", "md5", "sha1", "sha256",
                        "size", "owner", "mtime_utc", "running_pids"], "Integrity",
                       "hash_executables.* merged by path - feed straight to VT. "
                       "sha256 is kept when the profile produced it, and "
                       "running_pids says whether the file is executing now.")
        for rel in self.col.glob("hash_executables/**"):
            self.use(rel, "FILE_HASHES")
        by_path = self._exe_hashes()
        meta = self._bodyfile_meta()
        running = defaultdict(list)
        for pid, p in self._procs().items():
            exe = (p.get("exe") or "").split(" (deleted)")[0]
            if exe:
                running[exe].append(pid)
        for path in sorted(by_path):
            bf = meta.get(path, {})
            t.add(path, os.path.dirname(path), os.path.basename(path),
                  by_path[path].get("md5", ""), by_path[path].get("sha1", ""),
                  by_path[path].get("sha256", ""), bf.get("size", ""),
                  self.uid_name(bf.get("uid", "")) or bf.get("uid", ""),
                  bf.get("mtime", ""),
                  ",".join(sorted(running.get(path, []),
                                  key=lambda p: int(p) if p.isdigit() else 0)))

    # -- 8. software / logs -------------------------------------------------
    def t_packages(self):
        t = self.table("PACKAGES", "Installed packages",
                       ["status", "name", "version", "architecture", "description",
                        "source"], "Software", "dpkg -l / rpm -qa as captured.")
        for rel in sorted(self.col.glob("live_response/packages/**")):
            lines = self.lines(rel, "PACKAGES")
            started = False
            for ln in lines:
                if ln.startswith("+++"):
                    started = True
                    continue
                if not started:
                    if re.match(r"^[a-z0-9][a-z0-9+._-]*\s+\S+\s+\S+", ln) and \
                            "dpkg" not in rel:
                        f = ln.split(None, 3)
                        t.add("", f[0], f[1] if len(f) > 1 else "",
                              f[2] if len(f) > 2 else "",
                              f[3] if len(f) > 3 else "", os.path.basename(rel))
                    continue
                f = ln.split(None, 4)
                if len(f) >= 4:
                    t.add(f[0], f[1], f[2], f[3], f[4] if len(f) > 4 else "",
                          os.path.basename(rel))
        # dpkg's own database, for the profiles that copy /var/lib rather than
        # run dpkg -l. It also survives when the binary was tampered with, and
        # carries the Status field verbatim - 'deinstall ok config-files' is a
        # package someone removed, which the -l summary shows as rc and nothing
        # else in the export explains.
        for rel in (self.col.rootfs_glob("/var/lib/dpkg/status")
                    + self.col.rootfs_glob("/var/lib/dpkg/status-old")):
            src = self.col.host_path(rel)
            pkg = {}
            for ln in self.lines(rel, "PACKAGES") + [""]:
                if ln.startswith(" "):
                    continue
                if not ln.strip():
                    if pkg.get("package"):
                        t.add(pkg.get("status", ""), pkg["package"],
                              pkg.get("version", ""), pkg.get("architecture", ""),
                              pkg.get("description", ""), src)
                    pkg = {}
                    continue
                if ":" in ln:
                    k, v = ln.split(":", 1)
                    pkg[k.strip().lower()] = v.strip()
        self._velo_packages(t)

    def t_package_logs(self):
        """dpkg.log is line-oriented; apt/history.log is block-oriented.

        Parsing the apt blocks line-by-line loses the link between a command
        line and the packages it touched, which is exactly what you want when
        asking "how did this get installed".
        """
        t = self.table("PACKAGE_HISTORY", "Package install/removal history",
                       ["timestamp_utc", "timestamp", "action", "package",
                        "version", "detail", "commandline", "requested_by",
                        "source"], "Software",
                       "dpkg.log lines plus apt transactions reassembled from "
                       "their Start-Date/End-Date blocks. timestamp_utc "
                       "normalises the host clock so package events sort "
                       "against the rest of the timeline.")

        def row(ts, *rest):
            t.add(self.ts_utc(ts), ts, *rest)

        # -- dpkg.log style: '2026-03-24 15:48:35 install pkg:amd64 <none> 1.0'
        for pat in ("/var/log/dpkg.log*", "/var/log/yum.log*",
                    "/var/log/dnf.rpm.log*", "/var/log/alternatives.log*"):
            for rel in self.col.rootfs_glob(pat):
                host = self.col.host_path(rel)
                lines = self.dlines(rel, "PACKAGE_HISTORY")
                if lines is None:
                    self.use(rel, "PACKAGE_HISTORY (undecodable)")
                    continue
                for ln in lines:
                    s = ln.strip()
                    if not s:
                        continue
                    # alternatives.log puts the tool name before the timestamp:
                    # 'update-alternatives 2026-03-24 15:48:15: run with --install ...'
                    a = re.match(r"^(\S+)\s+(\d{4}-\d\d-\d\d\s+[\d:]+):\s*(.*)$", s)
                    if a:
                        rest = a.group(3)
                        act = rest.split()[0] if rest.split() else ""
                        row(a.group(2), act, "", "", rest, "", "", host)
                        continue
                    m = re.match(r"^(\d{4}-\d\d-\d\d\s+[\d:]+)\s+(\S+)\s*(.*)$", s)
                    if not m:
                        row("", "", "", "", s, "", "", host)
                        continue
                    ts, action, rest = m.groups()
                    f = rest.split()
                    pkg = f[0] if f else ""
                    ver = f[-1] if len(f) > 1 else ""
                    row(ts, action, pkg, ver, rest, "", "", host)

        # -- apt/history.log style: RFC822-ish blocks separated by blank lines
        for pat in ("/var/log/apt/history.log*",):
            for rel in self.col.rootfs_glob(pat):
                host = self.col.host_path(rel)
                lines = self.dlines(rel, "PACKAGE_HISTORY")
                if lines is None:
                    self.use(rel, "PACKAGE_HISTORY (undecodable)")
                    continue
                block = {}
                blocks = []
                for ln in lines + [""]:
                    s = ln.strip()
                    if not s:
                        if block:
                            blocks.append(block)
                            block = {}
                        continue
                    if ":" in s:
                        k, v = s.split(":", 1)
                        block[k.strip().lower()] = v.strip()
                for b in blocks:
                    ts = b.get("start-date", "")
                    cmd = b.get("commandline", "")
                    who = b.get("requested-by", "")
                    hit = False
                    for action in ("install", "upgrade", "remove", "purge",
                                   "downgrade", "reinstall"):
                        if action not in b:
                            continue
                        hit = True
                        # 'pkg:arch (ver, automatic), pkg2:arch (old, new)'
                        for m in re.finditer(r"([^\s,(]+)\s*\(([^)]*)\)",
                                             b[action]):
                            row(ts, action, m.group(1), m.group(2),
                                b.get("end-date", ""), cmd, who, host)
                    if not hit:
                        row(ts, b.get("error") and "error" or "transaction", "",
                            "", "; ".join("%s=%s" % kv for kv in b.items()),
                            cmd, who, host)

        # -- apt/term.log: the raw dpkg terminal transcript
        for rel in self.col.rootfs_glob("/var/log/apt/term.log*"):
            host = self.col.host_path(rel)
            lines = self.dlines(rel, "PACKAGE_HISTORY")
            if lines is None:
                self.use(rel, "PACKAGE_HISTORY (undecodable)")
                continue
            for ln in lines:
                s = ln.strip()
                if s.startswith(("Log started:", "Log ended:")):
                    row(s.split(":", 1)[1].strip(), "term_log", "", "", s,
                        "", "", host)

    def t_chkrootkit(self):
        t = self.table("CHKROOTKIT", "chkrootkit artifacts",
                       ["source", "line_no", "text"], "Rootkit",
                       "Whatever UAC's chkrootkit module collected.")
        for rel in sorted(self.col.glob("chkrootkit/**")):
            for i, ln in enumerate(self.lines(rel, "CHKROOTKIT"), 1):
                if ln.strip():
                    t.add(os.path.basename(rel), i, ln.rstrip())

    # -- 8b. /var/log -------------------------------------------------------
    def dlines(self, rel, table_name):
        """Read a log file, transparently expanding .gz/.bz2/.xz/.zst."""
        self.use(rel, table_name)
        return self.dread(rel)

    def dread(self, rel):
        """The same read without claiming the file.

        For a candidate an extractor may still reject: claiming it first and
        walking away leaves FILE_INVENTORY naming a table the rows are not in.
        """
        raw = decompress_bytes(rel, self.col.read_bytes(rel))
        if raw is None:
            return None
        return raw.decode("utf-8", "replace").splitlines()

    def _log_files(self):
        """Every regular file under /var/log, at any depth."""
        out = []
        plen = len(self.col.prefix)
        roots = tuple(rd.lower() + "/var/log/" for rd in self.col.rootfs_dirs)
        for low, real in self.col._names.items():
            if not low.startswith(self.col.prefix):
                continue
            rel = real[plen:]
            if rel.lstrip("/").lower().startswith(roots):
                out.append(rel)
        return sorted(out, key=str.lower)

    def t_journal(self):
        """systemd-journald is the only log store on a modern distro."""
        t = self.table("JOURNAL", "systemd journal entries",
                       ["timestamp_utc", "priority", "priority_name", "hostname",
                        "unit", "identifier", "comm", "pid", "uid", "gid", "exe",
                        "cmdline", "transport", "message", "source_file"],
                       "Logging",
                       "Binary .journal files decoded directly - this host has no "
                       "syslog/auth.log, so the journal IS the log.",
                       ["/var/log/journal/*/*.journal*"])
        tot = {"files": 0, "entries": 0, "bad": 0, "comp": set()}
        for rel in self._log_files():
            if ".journal" not in os.path.basename(rel).lower():
                continue
            raw = self.col.read_bytes(rel)
            if not raw or raw[:8] != JOURNAL_MAGIC:
                continue
            self.use(rel, "JOURNAL")
            entries, stats = parse_journal(raw)
            tot["files"] += 1
            tot["entries"] += stats["entries"]
            tot["bad"] += stats["undecodable_fields"]
            tot["comp"] |= stats["compression"]
            host = self.col.host_path(rel)
            for e in entries:
                try:
                    ts = datetime.fromtimestamp((e.get("__REALTIME") or 0) / 1e6,
                                                timezone.utc)
                except (OverflowError, OSError, ValueError):
                    ts = None
                pri = e.get("PRIORITY", "")
                pname = SYSLOG_PRIORITY.get(int(pri), "") if pri.isdigit() else ""
                t.add(ts.strftime("%Y-%m-%d %H:%M:%S") if ts else "", pri, pname,
                      e.get("_HOSTNAME", ""),
                      e.get("_SYSTEMD_UNIT", e.get("UNIT", "")),
                      e.get("SYSLOG_IDENTIFIER", ""), e.get("_COMM", ""),
                      e.get("_PID", ""), e.get("_UID", ""), e.get("_GID", ""),
                      e.get("_EXE", ""), e.get("_CMDLINE", ""),
                      e.get("_TRANSPORT", ""), e.get("MESSAGE", ""), host)
        if tot["files"]:
            note = "%d file(s), %d entries, compression: %s" % (
                tot["files"], tot["entries"], ", ".join(sorted(tot["comp"])) or "none")
            if tot["bad"]:
                note += "; %d field(s) undecodable" % tot["bad"]
            t.description += "  [%s]" % note

    def t_login_records(self):
        t = self.table("LOGIN_RECORDS", "Binary login records (wtmp/btmp/utmp)",
                       ["timestamp_utc", "record_type", "user", "terminal", "pid",
                        "remote_host", "remote_ip", "outcome", "source"],
                       "Authentication",
                       "utmp-format records decoded from the binaries themselves; "
                       "btmp rows are failed logins.")
        # /run/utmp is the live session list; UAC may store it under /var/run
        cands = (self._log_files() + self.col.rootfs_glob("/run/utmp")
                 + self.col.rootfs_glob("/var/run/utmp")
                 + self.col.rootfs_glob("/var/run/utmpx"))
        for rel in cands:
            base = os.path.basename(rel).lower()
            if not base.startswith(("wtmp", "btmp", "utmp")) or base.endswith(".db"):
                continue
            raw = decompress_bytes(rel, self.col.read_bytes(rel))
            host = self.col.host_path(rel)
            if not raw:
                # a zero-length btmp means no failed logins - worth recording
                self.use(rel, "LOGIN_RECORDS (empty)")
                continue
            self.use(rel, "LOGIN_RECORDS")
            outcome = "FAILED LOGIN" if base.startswith("btmp") else ""
            for r in parse_utmp(raw):
                t.add(r["time"].strftime("%Y-%m-%d %H:%M:%S") if r["time"] else "",
                      r["type"], r["user"], r["line"], r["pid"], r["host"],
                      r["ip"], outcome, host)
                if r["time"] and r["user"] and r["type"] == "USER_PROCESS":
                    self.tri.event(r["time"], "Authentication",
                                   "login %s on %s from %s"
                                   % (r["user"], r["line"], r["host"] or "local"),
                                   "INFO", host)
        # Some profiles run utmpdump on the host instead of copying the binary.
        # Its output is the same records already decoded above when both are
        # present, but it is the only copy when the wtmp file itself was not
        # collected - and it is what the host's own libc read, so a disagreement
        # between the two is itself the finding.
        for rel in self.col.glob("live_response/system/utmpdump_*.txt"):
            base = os.path.basename(rel)
            src = "/" + base[len("utmpdump_"):-len(".txt")].replace("_", "/")
            failed = "btmp" in base
            for ln in self.lines(rel, "LOGIN_RECORDS"):
                # '[7] [01234] [ts/0] [root ] [pts/0] [10.0.0.5] [10.0.0.5] [2026-06-11T09:10:19,123456+00:00]'
                f = re.findall(r"\[([^\]]*)\]", ln)
                if len(f) < 8:
                    continue
                f = [x.strip() for x in f]
                try:
                    kind = UTMP_TYPES.get(int(f[0]), f[0])
                except ValueError:
                    kind = f[0]
                # utmpdump writes ISO-8601 with a comma before the fraction
                ts = re.sub(r",\d+", "", f[7])
                # 0.0.0.0 is utmpdump's rendering of "no address recorded"
                ip = "" if f[6] in ("0.0.0.0", "::") else f[6]
                t.add(self.ts_utc(ts) or ts, kind, f[3], f[4], f[1], f[5], ip,
                      "FAILED LOGIN" if failed else "", src)

    def t_wtmpdb(self):
        """Debian 13+ replaced wtmp with wtmpdb, a SQLite database."""
        t = self.table("WTMPDB", "Login database (wtmpdb)",
                       ["login_utc", "logout_utc", "duration", "type", "user",
                        "tty", "remote_host", "service", "source"],
                       "Authentication",
                       "SQLite login database - the modern replacement for wtmp.")
        types = {1: "boot", 2: "runlevel", 3: "user", 4: "dead"}

        def us(v):
            if not v:
                return None
            try:
                return datetime.fromtimestamp(v / 1e6, timezone.utc)
            except (OverflowError, OSError, ValueError):
                return None

        for rel in self._log_files():
            if not os.path.basename(rel).lower().endswith(".db"):
                continue
            raw = self.col.read_bytes(rel)
            if not raw or raw[:15] != b"SQLite format 3":
                continue
            self.use(rel, "WTMPDB")
            host = self.col.host_path(rel)
            tmp = None
            try:
                # sqlite needs a real file and the collection may be an archive
                fd, tmp = tempfile.mkstemp(suffix=".wtmpdb")
                with os.fdopen(fd, "wb") as fh:
                    fh.write(raw)
                con = sqlite3.connect(tmp)
                try:
                    tabs = [r[0] for r in con.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'")]
                    if "wtmp" not in tabs:
                        continue
                    for row in con.execute(
                            "SELECT Type,User,Login,Logout,TTY,RemoteHost,Service"
                            " FROM wtmp ORDER BY Login"):
                        ty, user, login, logout, tty, rhost, svc = row
                        li, lo = us(login), us(logout)
                        t.add(li.strftime("%Y-%m-%d %H:%M:%S") if li else "",
                              lo.strftime("%Y-%m-%d %H:%M:%S") if lo else "",
                              str(lo - li) if li and lo else "",
                              types.get(ty, ty), user or "", tty or "",
                              rhost or "", svc or "", host)
                        if li and user:
                            self.tri.event(li, "Authentication",
                                           "login %s on %s via %s from %s"
                                           % (user, tty or "?", svc or "?",
                                              rhost or "local"), "INFO", host)
                finally:
                    con.close()
            finally:
                if tmp and os.path.exists(tmp):
                    try:
                        os.unlink(tmp)
                    except OSError:
                        pass

    def t_lastlog(self):
        t = self.table("LASTLOG", "Last login per account",
                       ["uid", "username", "last_login_utc", "terminal",
                        "remote_host", "source"], "Authentication",
                       "lastlog is a flat array indexed by uid; only populated "
                       "slots are listed. FOR577 rates lastlog and faillog as "
                       "unreliable - corroborate anything here against "
                       "LOGIN_RECORDS (wtmp/btmp) before relying on it.")
        uid_to_name = {}
        prel = self.col.rootfs("/etc/passwd")
        for ln in self.col.lines(prel) if prel else []:
            f = ln.split(":")
            if len(f) >= 3 and f[2].isdigit():
                uid_to_name[int(f[2])] = f[0]
        for rel in self._log_files():
            if os.path.basename(rel).lower() != "lastlog":
                continue
            raw = decompress_bytes(rel, self.col.read_bytes(rel))
            if not raw:
                continue
            self.use(rel, "LASTLOG")
            host = self.col.host_path(rel)
            for r in parse_lastlog(raw):
                t.add(r["uid"], uid_to_name.get(r["uid"], ""),
                      r["time"].strftime("%Y-%m-%d %H:%M:%S"), r["line"],
                      r["host"], host)

    def t_var_log(self):
        """Every text log under /var/log, syslog-aware, rotations expanded."""
        t = self.table("VAR_LOG", "/var/log text entries",
                       ["timestamp_utc", "timestamp", "host", "process", "pid",
                        "message", "log", "line_no"], "Logging",
                       "All plain-text logs including .gz/.xz/.bz2 rotations. "
                       "Syslog-format lines are split into columns; anything else "
                       "is kept verbatim in message. timestamp_utc normalises "
                       "every clock so logs from different daemons sort together.")
        for rel in self._log_files():
            low = os.path.basename(rel).lower()
            if ".journal" in low or low.endswith((".db", ".dat")):
                continue
            if low.startswith(("wtmp", "btmp", "utmp", "lastlog")):
                continue
            if self.col.size(rel) > 64 * 1024 * 1024:
                self.use(rel, "VAR_LOG (too large, skipped)")
                continue
            lines = self.dlines(rel, "VAR_LOG")
            if lines is None:
                self.use(rel, "VAR_LOG (undecodable)")
                continue
            host_path = self.col.host_path(rel)
            for i, ln in enumerate(lines, 1):
                if not ln.strip():
                    continue
                if "\x00" in ln:                 # binary payload, not a text log
                    self.use(rel, "VAR_LOG (binary, skipped)")
                    break
                ts, lhost, proc, pid, msg = split_log_line(ln)
                t.add(self.ts_utc(ts), ts, lhost, proc, pid, msg, host_path, i)

    def t_log_inventory(self):
        t = self.table("LOG_INVENTORY", "/var/log inventory",
                       ["path", "size_bytes", "size_human", "compressed", "rotated",
                        "empty", "parsed_into"],
                       "Logging", "Every log file collected - zero-length ones matter.")
        for rel in self._log_files():
            host = self.col.host_path(rel)
            size = self.col.size(rel)
            low = host.lower()
            # '.1' is a rotation, not a compression - conflating the two made
            # every uncompressed rotation read as unreadable-without-gunzip
            t.add(host, size, human_size(size),
                  "yes" if low.endswith((".gz", ".xz", ".bz2", ".zst", ".lz4",
                                         ".z")) else "",
                  "yes" if (re.search(r"\.\d+(\.(gz|xz|bz2|zst|lz4|z))?$", low)
                            or low.endswith("~")) else "",
                  "yes" if size == 0 else "",
                  self.consumed.get(rel.lstrip("/").lower(), ""))

    def t_etc_configs(self):
        """Security-relevant /etc files, verbatim."""
        t = self.table("ETC_CONFIGS", "Key /etc configuration files",
                       ["path", "line_no", "text"], "Configuration",
                       "Resolver, hosts, PAM, auditd, firewall and login policy, "
                       "plus the account-file backups (passwd-/shadow-/gshadow), "
                       "the boot chain, udev/tmpfiles/cloud-init hooks, D-Bus and "
                       "polkit authorisation, MAC policy and endpoint-agent "
                       "configuration.")
        pats = ["/etc/hosts", "/etc/hosts.allow", "/etc/hosts.deny", "/etc/resolv.conf",
                "/etc/nsswitch.conf", "/etc/pam.d/*", "/etc/security/*.conf",
                "/etc/login.defs", "/etc/audit/*.rules", "/etc/audit/auditd.conf",
                "/etc/rsyslog.conf", "/etc/rsyslog.d/*", "/etc/logrotate.conf",
                "/etc/sysctl.conf", "/etc/sysctl.d/*", "/etc/os-release",
                "/etc/machine-id", "/etc/hostname", "/etc/timezone",
                # every package manager's repository list: FOR577 flags
                # "unusual repository use" as a hunting signal, and each family
                # keeps the list somewhere different
                "/etc/apt/sources.list", "/etc/apt/sources.list.d/*",
                "/etc/apt/auth.conf", "/etc/apt/auth.conf.d/*",
                "/etc/yum.repos.d/*", "/etc/yum.conf", "/etc/dnf/dnf.conf",
                "/etc/zypp/repos.d/*", "/etc/zypp/zypp.conf",
                "/etc/apk/repositories", "/etc/pacman.conf",
                "/etc/pacman.d/mirrorlist",
                # the resolver actually in force is the runtime copy, not /etc
                "/run/systemd/resolve/resolv.conf",
                "/run/systemd/resolve/stub-resolv.conf",
                "/var/run/systemd/resolve/resolv.conf",
                "/var/run/systemd/resolve/stub-resolv.conf",
                "/run/NetworkManager/resolv.conf",
                "/var/run/NetworkManager/resolv.conf",
                "/etc/systemd/resolved.conf", "/etc/systemd/resolved.conf.d/*",
                "/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/*",
                "/etc/security/limits.d/*", "/etc/sudo.conf",
                "/etc/audit/rules.d/*", "/etc/selinux/config",
                "/etc/environment", "/etc/environment.d/*",
                "/etc/default/grub", "/etc/fstab", "/etc/crypttab",
                # The '-' copies are the previous generation of each account
                # file, written by useradd/passwd before they edit. Diffing
                # passwd against passwd- dates an account creation to the
                # minute without a single log line, and gshadow carries the
                # group passwords and administrator lists that /etc/group does
                # not - neither was being read at all.
                "/etc/passwd-", "/etc/shadow-", "/etc/group-",
                "/etc/gshadow", "/etc/gshadow-",
                # subordinate uid/gid ranges: what a rootless container can map
                # itself onto, and a namespace-escape precondition
                "/etc/subuid", "/etc/subgid", "/etc/subuid-", "/etc/subgid-",
                # account creation policy - a default shell or skel change
                # affects every account made after it
                "/etc/adduser.conf", "/etc/deluser.conf", "/etc/default/useradd",
                "/etc/shells", "/etc/securetty",
                # what greets a login, and the scripts that generate it
                "/etc/issue", "/etc/issue.net", "/etc/motd", "/etc/legal",
                # udev runs RUN+= as root on device events, at boot and on hot
                # plug: persistence that survives a unit-file audit
                "/etc/udev/rules.d/*", "/etc/udev/udev.conf",
                "/run/udev/rules.d/*", "/lib/udev/rules.d/*",
                "/usr/lib/udev/rules.d/*",
                # tmpfiles.d can create, chown or symlink a path on every boot
                "/etc/tmpfiles.d/*", "/usr/lib/tmpfiles.d/*", "/run/tmpfiles.d/*",
                # cloud-init runs runcmd/bootcmd as root from instance metadata
                "/etc/cloud/cloud.cfg", "/etc/cloud/cloud.cfg.d/*",
                "/etc/cloud/ds-identify.cfg",
                # the boot chain: a kernel argument or an initramfs hook runs
                # before anything that could log it
                "/etc/grub.d/*", "/boot/grub/grub.cfg",
                "/boot/efi/EFI/*/grub.cfg", "/etc/initramfs-tools/*",
                "/etc/initramfs-tools/conf.d/*", "/etc/dracut.conf",
                "/etc/dracut.conf.d/*", "/etc/kernel/postrm.d/*",
                "/etc/kernel/preinst.d/*", "/etc/kernel/cmdline",
                # D-Bus and polkit decide which unprivileged caller may ask a
                # root daemon to do something - a local privilege-escalation
                # surface that no other table covers
                "/etc/dbus-1/system.d/*", "/etc/dbus-1/system-local.conf",
                "/etc/dbus-1/session.d/*", "/usr/share/dbus-1/system.d/*",
                "/usr/share/dbus-1/session.d/*",
                # a .service file here names an Exec= and a User= that D-Bus
                # will launch on the first method call - activation on demand,
                # with no unit file and no entry in systemctl's list
                "/usr/share/dbus-1/system-services/*",
                "/usr/share/dbus-1/services/*",
                "/etc/systemd/system-preset/*", "/usr/lib/systemd/system-preset/*",
                "/usr/lib/systemd/user-preset/*", "/usr/lib/systemd/*.conf.d/*",
                "/usr/lib/systemd/ntp-units.d/*",
                "/etc/systemd/network/*", "/usr/lib/systemd/network/*",
                "/etc/polkit-1/**", "/var/lib/polkit-1/**",
                "/usr/share/polkit-1/rules.d/*",
                # a .policy declares which action an unprivileged caller may
                # invoke and whether it needs a password - allow_active=yes on
                # something that runs code is a local escalation
                "/usr/share/polkit-1/actions/*",
                # apt pinning can hold a package at a vulnerable version or
                # pull it from somewhere other than the distribution
                "/etc/apt/preferences", "/etc/apt/preferences.d/*",
                "/etc/apt/preferences.d.save/*", "/etc/apt/apt.conf",
                "/etc/depmod.d/*",
                # mandatory access control: a profile in complain mode, or a
                # permissive SELinux, is why an exploit that should have been
                # confined was not
                "/etc/selinux/*.conf", "/etc/selinux/semanage.conf",
                "/etc/apparmor/*.conf", "/etc/apparmor.d/local/*",
                "/etc/apparmor.d/disable/*", "/etc/apparmor.d/force-complain/*",
                # ufw's before/after hooks are shell scripts run as root
                "/etc/ufw/*.init", "/etc/ufw/*.rules", "/etc/ufw/ufw.conf",
                "/etc/ufw/sysctl.conf", "/etc/ufw/applications.d/*",
                # completion and readline files are sourced by every
                # interactive shell, the same way .bashrc is
                "/etc/bash_completion", "/etc/bash_completion.d/*",
                "/etc/inputrc", "/etc/vim/vimrc", "/etc/vim/vimrc.local",
                "/etc/zsh_command_not_found",
                # X session scripts run on graphical login
                "/etc/X11/Xsession", "/etc/X11/Xsession.d/*",
                "/etc/xdg/systemd/user",
                # systemd's own daemons, including what logind does on idle and
                # where pstore/coredumps are written
                "/etc/systemd/*.conf", "/etc/systemd/*.conf.d/*",
                # per-service defaults: several of these are shell fragments
                # sourced by an init script, with the daemon's argv in them
                "/etc/default/*",
                # sudo's logging and audit's library config say whether the
                # privilege trail this collection relies on was even being kept
                "/etc/sudo_logsrvd.conf", "/etc/sudo_logsrv.conf",
                "/etc/libaudit.conf",
                # hook directories that run on power and network events
                "/etc/apm/event.d/*", "/etc/acpi/events/*", "/etc/acpi/*.sh",
                # endpoint agent configuration - FOR577 device profiling asks
                # what was watching the host, and an exclusion list is the
                # first thing an intruder edits
                "/etc/opt/microsoft/**", "/etc/opt/omi/conf/**",
                "/opt/microsoft/*/conf/**", "/etc/falcon*/*",
                "/etc/crowdstrike/**", "/etc/vmware-tools/tools.conf",
                "/etc/vmware-tools/*.conf",
                # name resolution and service-name mapping the resolver uses
                "/etc/host.conf", "/etc/gai.conf", "/etc/ldap/ldap.conf",
                "/etc/ethertypes", "/etc/networks", "/etc/protocols",
                "/etc/idmapd.conf", "/etc/exports", "/etc/exports.d/*",
                "/etc/samba/smb.conf", "/etc/samba/*.conf",
                "/etc/at.allow", "/etc/at.deny", "/etc/cron.allow",
                "/etc/cron.deny", "/etc/anacrontab",
                "/etc/wgetrc", "/etc/curlrc", "/etc/dhcpcd.conf",
                "/etc/iscsi/initiatorname.iscsi",
                "/etc/fuse.conf", "/etc/xattr.conf", "/etc/e2scrub.conf",
                # PAM's flat-file form and the password-history file: opasswd
                # holds previous password hashes, which is credential material
                # /etc/shadow alone does not show
                "/etc/pam.conf", "/etc/security/opasswd",
                "/etc/security/namespace.init", "/etc/security/namespace.conf",
                # auditd's dispatcher: a plugin here receives every audit event,
                # and disabling one is how the audit trail goes quiet
                "/etc/audit/plugins.d/*", "/etc/audisp/plugins.d/*",
                "/etc/audisp/audispd.conf",
                # log shippers - where a copy of this host's logs went, and
                # whether it is still going there
                "/etc/filebeat/*.yml", "/etc/auditbeat/*.yml",
                "/etc/metricbeat/*.yml", "/etc/winlogbeat/*.yml",
                "/etc/td-agent/**", "/etc/fluent*/**", "/etc/promtail/**",
                "/etc/splunk*/**", "/etc/syslog-ng/*.conf",
                "/etc/syslog-ng/conf.d/*",
                # a local resolver's config decides what every name on this box
                # resolves to
                "/etc/dnsmasq.conf", "/etc/dnsmasq.d/*",
                "/etc/dnsmasq.d-available/*", "/etc/systemd/dnssd/*",
                "/etc/unbound/**", "/etc/bind/named.conf*",
                # interpreter and tool rc files: sitecustomize.py is imported by
                # every python process on the host, and gdbinit/init.lua/nanorc
                # are the same trick for their own interpreter
                "/etc/python*/sitecustomize.py", "/etc/python*/debian_config",
                "/etc/gdb/gdbinit", "/etc/gdb/gdbinit.d/*",
                "/etc/wireshark/init.lua", "/etc/nanorc", "/etc/screenrc",
                "/etc/tmux.conf", "/etc/emacs/site-start.d/*",
                "/etc/perl/**", "/etc/R/*", "/etc/ltrace.conf",
                # request-key hands a kernel key request to a userspace program
                # running as root
                "/etc/request-key.conf", "/etc/request-key.d/*",
                # boot and root-filesystem shape: overlayroot means changes to
                # / are discarded on reboot, which changes what 'persistence'
                # even means on this host
                "/etc/overlayroot*.conf", "/etc/default/grub.d/*",
                "/etc/kernel-img.conf", "/etc/cryptsetup-initramfs/*",
                "/etc/mdadm/mdadm.conf", "/etc/mke2fs.conf",
                # which cloud this instance is, which the hostname does not say
                "/etc/ec2_version", "/etc/cloud/build.info", "/etc/waagent.conf",
                "/etc/google_system.cfg", "/etc/oracle-cloud-agent/**",
                # the guest agent runs these as root on host power events
                "/etc/vmware-tools/*-vm-default", "/etc/vmware-tools/*.subr",
                "/etc/vmware-tools/scripts/**", "/etc/vmware-tools/vm-support",
                # an openssl engine or provider directive loads a shared object
                # into every process that uses libssl
                "/etc/ssl/openssl.cnf", "/etc/ssl/openssl.cnf.d/*",
                "/etc/crypto-policies/config", "/etc/pki/tls/openssl.cnf",
                # database configuration, and the maintenance credentials that
                # ship beside it - debian.cnf is a plaintext root password for
                # the local MySQL instance
                "/etc/mysql/**", "/etc/my.cnf", "/etc/my.cnf.d/*",
                "/etc/postgresql/**", "/etc/redis/*.conf", "/etc/mongod.conf",
                "/etc/mongodb.conf", "/etc/elasticsearch/*.yml",
                "/etc/opensearch/*.yml", "/etc/cassandra/*.yaml",
                # the previous resolver, saved before something rewrote it -
                # the DNS server in force before the change is evidence the
                # current resolv.conf has already lost
                "/etc/.resolv.conf*", "/etc/resolv.conf.*",
                "/etc/resolvconf/**", "/usr/lib/systemd/resolv.conf",
                # the bus-wide policy every D-Bus service inherits
                "/usr/share/dbus-1/system.conf",
                "/usr/share/dbus-1/session.conf",
                # cloud-init's disable switch and its clean hooks
                "/etc/cloud/clean.d/*", "/etc/cloud/cloud-init.disabled",
                # what was mounted according to the mount table on disk
                "/etc/mtab", "/etc/netconfig", "/etc/multipath.conf",
                "/etc/multipath/*", "/etc/udev/*.conf",
                "/etc/vconsole.conf", "/etc/vim/vimrc.*",
                "/etc/iscsi/*.conf",
                # the init systems that are not systemd: a runit or s6 service
                # directory is a run script plus a symlink, and neither appears
                # in systemctl's view of the world
                "/etc/sv/**", "/etc/runit/**", "/etc/s6/**",
                "/etc/service/**", "/etc/dinit.d/**",
                # a native-messaging host lets a browser extension execute a
                # local binary - browser-resident persistence with a foothold
                # outside the browser
                "/etc/chromium/native-messaging-hosts/*",
                "/etc/opt/chrome/native-messaging-hosts/*",
                "/etc/opt/edge/native-messaging-hosts/*",
                "/usr/lib/mozilla/native-messaging-hosts/*",
                # X session entry points, the same class as Xsession.d
                "/etc/X11/xinit/**", "/etc/X11/Xreset", "/etc/X11/Xreset.d/*",
                "/etc/X11/Xresources", "/etc/X11/Xresources/*",
                "/etc/xdg/Xwayland-session.d/*",
                "/etc/NetworkManager/NetworkManager.conf",
                "/etc/NetworkManager/conf.d/*",
                # NetworkManager's saved state: which networks this host has
                # actually been on, and when it last held each lease
                "/var/lib/NetworkManager/*.conf",
                "/var/lib/NetworkManager/*.state",
                "/var/lib/NetworkManager/timestamps",
                "/var/lib/NetworkManager/*.lease",
                "/var/lib/dhcp/*.leases", "/var/lib/dhclient/*.leases",
                # the display manager runs these around every graphical login,
                # as root before the session starts and as the user after
                "/etc/gdm*/Init/*", "/etc/gdm*/PreSession/*",
                "/etc/gdm*/PostSession/*", "/etc/gdm*/PostLogin/*",
                "/etc/gdm*/Xsession", "/etc/gdm*/*.conf",
                "/etc/lightdm/**", "/etc/sddm.conf", "/etc/sddm.conf.d/*",
                "/etc/xdg/plasma-workspace/env/*",
                "/etc/xdg/plasma-workspace/shutdown/*",
                "/etc/dconf/profile/*", "/etc/dconf/db/*.d/*",
                "/etc/X11/Xsession.options", "/etc/X11/Xwrapper.config",
                "/etc/X11/default-display-manager",
                # scripts run when an interface comes up, and the dialer chat
                # scripts that carry the credentials for it
                "/etc/wpa_supplicant/*.sh", "/etc/wpa_supplicant/*.conf",
                "/etc/chatscripts/*",
                # network-facing daemons whose configuration decides what they
                # answer and to whom
                "/etc/cups/*.conf", "/etc/cups/printers.conf*",
                "/etc/snmp/*.conf", "/etc/avahi/*.conf", "/etc/avahi/hosts",
                "/etc/geoclue/geoclue.conf", "/etc/ipp-usb/*.conf",
                "/etc/bluetooth/*.conf",
                # adjtime records the RTC drift and, on its third line, whether
                # the hardware clock is UTC or LOCAL. Every timestamp in this
                # export is normalised against the host's offset, so that line
                # is the one that says whether the normalisation is right.
                "/etc/adjtime",
                "/var/spool/anacron/*"]
        seen = set()
        for pat in pats:
            for rel in self.col.rootfs_glob(pat):
                if rel.lower() in seen or self.col.size(rel) > 512 * 1024:
                    continue
                seen.add(rel.lower())
                host = self.col.host_path(rel)
                for i, ln in enumerate(self.lines(rel, "ETC_CONFIGS"), 1):
                    if ln.strip():
                        t.add(host, i, ln.rstrip())

    # -- 8c. containers, auditd and live sessions ---------------------------
    # FOR577 "Application Logs - Web Server Logs": Nginx /var/log/nginx,
    # Apache /var/log/apache2, RHEL /var/log/httpd, plus the three SSL logs.
    WEB_LOG_DIRS = ("/var/log/nginx", "/var/log/apache2", "/var/log/httpd",
                    "/var/log/lighttpd", "/var/log/caddy", "/var/log/tomcat*",
                    "/var/log/httpd24", "/opt/*/logs")

    # combined log format, which is the Nginx and Apache default; the common
    # format is the same line without the referer and user-agent pair
    COMBINED_RE = re.compile(
        r'^(?P<ip>\S+)\s+(?P<ident>\S+)\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+'
        r'"(?P<req>[^"]*)"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
        r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?')
    # 'GET /path HTTP/1.1'
    REQ_RE = re.compile(r"^(?P<method>[A-Z]+)\s+(?P<res>\S+)(?:\s+(?P<proto>\S+))?$")
    # apache error log: '[Tue Mar 24 15:47:28.123456 2026] [core:error] [pid 1] [client 1.2.3.4:5] msg'
    APACHE_ERR_RE = re.compile(
        r"^\[(?P<ts>[^\]]+)\]\s+\[(?P<mod>[^\]]+)\]\s+(?:\[pid (?P<pid>\d+)[^\]]*\]\s+)?"
        r"(?:\[client (?P<ip>[^\]]+)\]\s+)?(?P<msg>.*)$")
    # nginx error log: '2026/03/24 15:47:28 [error] 1#1: *1 msg, client: 1.2.3.4'
    # the worker#tid block is absent from the lines nginx writes before it
    # forks - a failed config test, 'bind() to 0.0.0.0:80 failed' - which are
    # exactly the lines that say why a server was not listening when it should
    # have been, so it is optional here rather than required.
    NGINX_ERR_RE = re.compile(
        r"^(?P<ts>\d{4}/\d\d/\d\d \d\d:\d\d:\d\d)\s+\[(?P<level>\w+)\]\s+"
        r"(?:(?P<pid>\d+)#\S*:\s*)?(?P<msg>.*)$")

    # -- error-log detail ---------------------------------------------------
    # '[client 1.2.3.4:5]' only follows the pid block when nothing else does.
    # With a module source reference ('mod_dumpio.c(140):') or an APR error
    # prefix ('(20023)The given path was above the root path:') in front of it
    # the bracket sits inside the message instead, and on the Apache
    # collection that is 339,317 of 489,851 error lines - every one of them an
    # attacker address the row silently dropped.
    CLIENT_RE = re.compile(r"\[client (?P<ip>[^\]\s]+)")
    # Apache's message identifier. AH00127 is the path traversal
    # CVE-2021-41773 exploits, AH01215 a CGI exec that failed, AH01630 a
    # client denied by configuration - the id earns a column because it groups
    # thousands of differently-worded lines into one filter.
    AH_CODE_RE = re.compile(r"\b(AH\d{5})\b")
    # a request quoted inside an error message, either nginx's
    # 'request: "GET /x HTTP/1.1"' or Apache's 'AH00127: Cannot map GET /x
    # HTTP/1.1 to file'. A request the server refused this early is often not
    # in the access log in the form the server actually saw.
    ERR_REQ_RE = re.compile(
        r"\b(?P<method>[A-Z]{3,10})\s+(?P<res>\S+)\s+(?P<proto>HTTP/[\d.]+)")
    NGINX_REFERRER_RE = re.compile(r'referrer:\s*"([^"]*)"')
    # cups writes 'E [date] [component] message'; the component names the
    # subsystem (cups-driverd, Notifier, 'Job 42') and belongs beside the level
    CUPS_COMP_RE = re.compile(r"^\[(?P<comp>[^\]]+)\]\s*")

    def _is_web_log(self, lines, probe=200):
        """Does this file hold web server log lines, or only have the name?

        The catch-all globs below match on the filename, and '*error*log*' is
        a name plenty of non-HTTP daemons use - /var/log/mysql/error.log is
        the standing example: 181 rows of MySQL startup filed under "HTTP
        server logs" with not one field parsed out of them. Deciding by shape
        instead of by path keeps a vhost log in an unusual directory and drops
        the database, with no blocklist of daemon names to keep current.
        """
        n = 0
        for ln in lines:
            s = ln.strip()
            if not s:
                continue
            if (self.COMBINED_RE.match(s) or self.APACHE_ERR_RE.match(s) or
                    self.NGINX_ERR_RE.match(s) or CUPS_RE.match(s)):
                return True
            n += 1
            if n >= probe:
                return False
        return False

    def t_web_logs(self):
        """Web server access and error logs, split into request fields.

        FOR577 names the fields worth having: client address, time, method,
        resource, status and response size.  A web log left as one text column
        cannot answer "what did this IP request and did it get a 200", which is
        the whole reason to collect it.

        The error log is the other half of that question and gets the same
        treatment.  It holds the attempts that never reached a handler - a
        traversal the server refused, a CGI exec that failed, a client denied
        by configuration - and it names the client, the module, the message id
        and often the request itself, so each of those gets a column instead of
        one blob of text.
        """
        t = self.table("WEB_LOG", "HTTP server logs",
                       ["timestamp_utc", "timestamp_raw", "server", "kind",
                        "client_ip", "user", "method", "resource", "protocol",
                        "status", "size", "referer", "user_agent", "level",
                        "module", "code", "pid", "message", "log", "line_no"],
                       "Web",
                       "Nginx/Apache/httpd access, error and ssl_* logs. Access "
                       "lines are split into Common/Combined Log Format fields, "
                       "error lines into level, module, message id, pid, client "
                       "and the request the message names. CUPS also serves HTTP "
                       "and writes both formats, so it lands here too - the "
                       "server column says which daemon wrote the line.")
        seen = set()
        cands = []
        indir = set()
        for d in self.WEB_LOG_DIRS:
            for rel in self.col.rootfs_glob(d + "/**"):
                cands.append(rel)
                indir.add(rel.lower())
        # a web log can be configured anywhere; catch the usual names too
        for pat in ("/var/log/*access*log*", "/var/log/*error*log*",
                    "/var/log/*/access*log*", "/var/log/*/error*log*",
                    "/var/log/*/ssl_*log*"):
            cands += self.col.rootfs_glob(pat)
        for rel in sorted(set(cands), key=str.lower):
            if rel.lower() in seen:
                continue
            seen.add(rel.lower())
            base = os.path.basename(rel).lower()
            kind = ("ssl_request" if "ssl_request" in base else
                    "ssl_access" if "ssl_access" in base else
                    "ssl_error" if "ssl_error" in base else
                    "error" if "error" in base else
                    "access" if "access" in base else "other")
            in_web_dir = rel.lower() in indir
            lines = self.dread(rel)
            if lines is None:
                if in_web_dir:
                    self.use(rel, "WEB_LOG (undecodable)")
                continue
            # a file under /var/log/nginx is a web log whatever it holds, and
            # an empty one still records that the server was configured; a
            # match on the name alone has to earn its place
            if not in_web_dir and not self._is_web_log(lines):
                continue
            self.use(rel, "WEB_LOG")
            host = self.col.host_path(rel)
            server = next((s for s in ("nginx", "apache2", "httpd", "cups",
                                       "lighttpd", "caddy", "tomcat")
                           if "/%s" % s in host.lower()), "")
            for i, ln in enumerate(lines, 1):
                s = ln.rstrip()
                if not s.strip():
                    continue
                m = self.COMBINED_RE.match(s)
                if m:
                    g = m.groupdict()
                    rq = self.REQ_RE.match(g["req"] or "") if g.get("req") else None
                    dash = lambda v: "" if v in ("-", None) else v
                    self.tri.ioc(g["ip"], host)
                    t.add(self.ts_utc(g["ts"]), g["ts"], server,
                          kind if kind != "other" else "access",
                          g["ip"], dash(g["user"]),
                          rq.group("method") if rq else "",
                          rq.group("res") if rq else g["req"],
                          rq.group("proto") if rq and rq.group("proto") else "",
                          g["status"], dash(g["size"]),
                          dash(g.get("referer")), dash(g.get("agent")),
                          "", "", "", "", "", host, i)
                    continue
                m = self.NGINX_ERR_RE.match(s)
                if m:
                    g = m.groupdict()
                    msg = g["msg"]
                    cm = re.search(r"client:\s*([^\s,]+)", msg)
                    rm = re.search(r'request:\s*"([^"]*)"', msg)
                    rq = self.REQ_RE.match(rm.group(1)) if rm else None
                    ref = (self.NGINX_REFERRER_RE.search(msg)
                           if "referrer:" in msg else None)
                    if cm:
                        self.tri.ioc(cm.group(1), host)
                    t.add(self.ts_utc(g["ts"].replace("/", "-")), g["ts"],
                          server, "error", cm.group(1) if cm else "", "",
                          rq.group("method") if rq else "",
                          rq.group("res") if rq else "",
                          rq.group("proto") if rq and rq.group("proto") else "",
                          "", "", ref.group(1) if ref else "", "",
                          g["level"], "", "", g["pid"] or "", msg, host, i)
                    continue
                m = self.APACHE_ERR_RE.match(s)
                if m:
                    g = m.groupdict()
                    mod, _, lvl = (g["mod"] or "").rpartition(":")
                    msg = g["msg"] or ""
                    ip = g.get("ip") or ""
                    if not ip and "[client " in msg:
                        cm = self.CLIENT_RE.search(msg)
                        ip = cm.group("ip") if cm else ""
                    ip = ip.rsplit(":", 1)[0]
                    code = ""
                    if "AH" in msg:
                        km = self.AH_CODE_RE.search(msg)
                        code = km.group(1) if km else ""
                    rq = self.ERR_REQ_RE.search(msg) if "HTTP/" in msg else None
                    if ip:
                        self.tri.ioc(ip, host)
                    t.add(self.ts_utc(re.sub(r"\.\d+", "", g["ts"])), g["ts"],
                          server, "error", ip, "",
                          rq.group("method") if rq else "",
                          rq.group("res") if rq else "",
                          rq.group("proto") if rq else "",
                          "", "", "", "", lvl or mod, mod if lvl else "",
                          code, g["pid"] or "", msg, host, i)
                    continue
                m = CUPS_RE.match(s)
                if m:
                    g = m.groupdict()
                    msg = g["msg"]
                    comp = self.CUPS_COMP_RE.match(msg)
                    if comp:
                        msg = msg[comp.end():]
                    t.add(self.ts_utc(g["ts"]), g["ts"], server or "cups",
                          kind if kind != "other" else "error",
                          "", "", "", "", "", "", "", "", "",
                          CUPS_LEVELS.get(g["level"], g["level"]),
                          comp.group("comp") if comp else "", "", "",
                          msg, host, i)
                    continue
                # anything else: a CGI's own stderr, or a startup message
                # written before the server had a log format - 'AH00558: Could
                # not reliably determine the server's fully qualified domain
                # name'. Keep the message id even without a timestamp.
                ts, _h, lvl, pid, msg = split_log_line(s)
                code = ""
                if "AH" in msg:
                    km = self.AH_CODE_RE.search(msg)
                    code = km.group(1) if km else ""
                t.add(self.ts_utc(ts), ts, server, kind, "", "", "", "", "", "",
                      "", "", "", lvl if kind != "access" else "", "", code,
                      pid, msg, host, i)

    def t_samba_logs(self):
        """Samba logs, which are two-line records rather than syslog lines.

        Every record is a '[date, level] source:line(function)' header followed
        by indented body lines.  Parsed line-by-line the header carries no
        message and the body carries no timestamp, so neither half is usable;
        they are joined back together here.
        """
        t = self.table("SAMBA_LOG", "Samba (SMB) log records",
                       ["timestamp_utc", "timestamp_raw", "level", "source_ref",
                        "function", "client", "user", "message", "log",
                        "line_no"], "File Sharing",
                       "/var/log/samba/log.* - per-client logs are named after "
                       "the client host or IP, so an empty one still records "
                       "that the client connected at some point.")
        hdr = re.compile(r"^\[(?P<ts>\d{4}/\d\d/\d\d \d\d:\d\d:\d\d)(?:\.\d+)?,"
                         r"\s*(?P<lvl>\d+)(?:,[^\]]*)?\]\s*(?P<ref>\S+?)"
                         r"(?:\((?P<fn>[^)]*)\))?\s*$")
        for rel in sorted(self.col.rootfs_glob("/var/log/samba/**")):
            base = os.path.basename(rel)
            if not base.lower().startswith("log"):
                continue
            lines = self.dlines(rel, "SAMBA_LOG")
            if lines is None:
                continue
            host = self.col.host_path(rel)
            # log.<client> - the filename itself names who talked to this host
            client = ""
            if base.lower().startswith("log.") and \
                    base.lower() not in ("log.smbd", "log.nmbd", "log.winbindd"):
                client = base[4:]
                self.tri.ioc(client, host)
            cur = None
            body = []

            def flush():
                if cur is None:
                    return
                msg = " ".join(b.strip() for b in body if b.strip())
                um = re.search(r"user\s*\[?([^\]\s]+)\]?", msg, re.I)
                t.add(self.ts_utc(cur["ts"].replace("/", "-")), cur["ts"],
                      cur["lvl"], cur["ref"], cur["fn"] or "", client,
                      um.group(1) if um else "", msg, host, cur["i"])

            for i, ln in enumerate(lines, 1):
                m = hdr.match(ln.rstrip())
                if m:
                    flush()
                    g = m.groupdict()
                    cur = {"ts": g["ts"], "lvl": g["lvl"], "ref": g["ref"],
                           "fn": g["fn"], "i": i}
                    body = []
                elif cur is not None:
                    body.append(ln)
                elif ln.strip():
                    t.add("", "", "", "", "", client, "", ln.strip(), host, i)
            flush()

    def t_firewall_log(self):
        """Packets the firewall actually logged.

        FOR577 puts iptables' own log output in the kernel message log and UFW's
        in /var/log/ufw.log; both write the same NETFILTER key=value line.  The
        FIREWALL table says what the rules are - this one says what they caught.
        """
        t = self.table("FIREWALL_LOG", "Firewall log entries",
                       ["timestamp_utc", "timestamp_raw", "action", "in_iface",
                        "out_iface", "src", "dst", "proto", "spt", "dpt", "len",
                        "ttl", "mac", "prefix", "message", "log", "line_no"],
                       "Network",
                       "UFW/iptables NETFILTER log lines and firewalld messages, "
                       "wherever they landed - /var/log/ufw.log, kern.log, "
                       "syslog or the journal.")
        kv = re.compile(r"\b([A-Z]+)=(\S*)")
        act = re.compile(r"\[(?P<pfx>[^\]]*(?:BLOCK|ALLOW|AUDIT|DENY|LIMIT|"
                         r"LOG)[^\]]*)\]")

        def emit(ts_raw, msg, host, i):
            d = dict(kv.findall(msg))
            am = act.search(msg)
            prefix = am.group("pfx").strip() if am else ""
            action = ""
            for word in ("BLOCK", "DENY", "REJECT", "DROP", "ALLOW", "ACCEPT",
                         "AUDIT", "LIMIT"):
                if word in prefix.upper() or word in msg.upper()[:120]:
                    action = word
                    break
            if d.get("SRC"):
                self.tri.ioc(d["SRC"], host)
            t.add(self.ts_utc(ts_raw), ts_raw, action, d.get("IN", ""),
                  d.get("OUT", ""), d.get("SRC", ""), d.get("DST", ""),
                  d.get("PROTO", ""), d.get("SPT", ""), d.get("DPT", ""),
                  d.get("LEN", ""), d.get("TTL", ""), d.get("MAC", "")[:60],
                  prefix, trunc(msg, 400), host, i)

        # a firewall log record is a NETFILTER key=value line or an explicit
        # ufw/firewalld tag - matching 'nf_conntrack' anywhere would drag in
        # every 'Modules linked in:' oops the kernel ever printed
        want = re.compile(r"\bSRC=\S+.*\bDST=\S+|\[\s*UFW [A-Z]+\s*\]|"
                          r"\bfirewalld\b", re.I)
        for pat in ("/var/log/ufw.log*", "/var/log/kern.log*",
                    "/var/log/firewalld*", "/var/log/messages*",
                    "/var/log/syslog*"):
            for rel in self.col.rootfs_glob(pat):
                lines = self.dlines(rel, "FIREWALL_LOG")
                if lines is None:
                    continue
                host = self.col.host_path(rel)
                for i, ln in enumerate(lines, 1):
                    if not want.search(ln):
                        continue
                    ts, _h, _p, _pid, msg = split_log_line(ln)
                    emit(ts, msg or ln.strip(), host, i)
        # the journal carries the same records on hosts with no text logs
        for n, (ts, _ident, msg, _hostname, _tty, host) in enumerate(
                self.tri.journal_scan()["events"], 1):
            if "SRC=" not in msg or "DST=" not in msg:
                continue
            d = dict(kv.findall(msg))
            am = act.search(msg)
            if d.get("SRC"):
                self.tri.ioc(d["SRC"], host)
            t.add(ts, ts, next((w for w in ("BLOCK", "DROP", "REJECT",
                                            "ALLOW", "ACCEPT")
                                if w in msg.upper()), ""),
                  d.get("IN", ""), d.get("OUT", ""), d.get("SRC", ""),
                  d.get("DST", ""), d.get("PROTO", ""), d.get("SPT", ""),
                  d.get("DPT", ""), d.get("LEN", ""), d.get("TTL", ""),
                  d.get("MAC", "")[:60],
                  am.group("pfx").strip() if am else "",
                  trunc(msg, 400), host, n)

    # FOR577 repeats one instruction for every application log: "check the
    # configuration file to locate logs and determine current configuration".
    LOG_CONFIG_FILES = [
        ("/etc/rsyslog.conf", "rsyslog"), ("/etc/rsyslog.d/*", "rsyslog"),
        ("/etc/syslog.conf", "syslog"), ("/etc/syslog-ng/syslog-ng.conf", "syslog-ng"),
        ("/etc/systemd/journald.conf", "journald"),
        ("/etc/systemd/journald.conf.d/*", "journald"),
        ("/etc/logrotate.conf", "logrotate"), ("/etc/logrotate.d/*", "logrotate"),
        ("/etc/audit/auditd.conf", "auditd"), ("/etc/audit/audit.rules", "auditd"),
        ("/etc/audit/rules.d/*", "auditd"),
        ("/etc/mysql/my.cnf", "mysql"), ("/etc/mysql/conf.d/*", "mysql"),
        ("/etc/mysql/mysql.conf.d/*", "mysql"), ("/etc/my.cnf", "mysql"),
        ("/etc/my.cnf.d/*", "mysql"),
        ("/var/lib/pgsql/data/postgresql.conf", "postgresql"),
        ("/etc/postgresql/*/*/postgresql.conf", "postgresql"),
        ("/etc/vsftpd.conf", "vsftpd"), ("/etc/vsftpd/vsftpd.conf", "vsftpd"),
        ("/etc/proftpd/proftpd.conf", "proftpd"),
        ("/etc/samba/smb.conf", "samba"),
        ("/etc/nginx/nginx.conf", "nginx"), ("/etc/nginx/conf.d/*", "nginx"),
        ("/etc/nginx/sites-enabled/*", "nginx"),
        ("/etc/apache2/apache2.conf", "apache"),
        ("/etc/apache2/conf-enabled/*", "apache"),
        ("/etc/apache2/sites-enabled/*", "apache"),
        ("/etc/httpd/conf/httpd.conf", "apache"),
        ("/etc/httpd/conf.d/*", "apache"),
        ("/etc/ssh/sshd_config", "sshd"), ("/etc/ssh/sshd_config.d/*", "sshd"),
        ("/etc/sysconfig/firewalld", "firewalld"),
        ("/etc/ufw/ufw.conf", "ufw"), ("/etc/default/ufw", "ufw"),
    ]

    def t_log_config(self):
        """Where each service was told to write its logs, and when it last rotated.

        Two questions this answers that nothing else can: whether a log that is
        missing was ever enabled, and whether one that is short was rotated or
        truncated.  logrotate's state file carries the last rotation time per
        log, which is the difference between "rotated on schedule" and "someone
        wiped it".
        """
        t = self.table("LOG_CONFIG", "Logging configuration and rotation state",
                       ["service", "path", "line_no", "directive", "value",
                        "text"], "Logging",
                       "rsyslog/journald/logrotate/auditd plus the per-service "
                       "config files that decide where application logs go, and "
                       "logrotate's recorded last-rotation time for each log.")
        seen = set()
        for pat, svc in self.LOG_CONFIG_FILES:
            for rel in self.col.rootfs_glob(pat):
                if rel.lower() in seen or self.col.size(rel) > 512 * 1024:
                    continue
                seen.add(rel.lower())
                host = self.col.host_path(rel)
                for i, ln in enumerate(self.lines(rel, "LOG_CONFIG"), 1):
                    s = ln.strip()
                    if not s or s.startswith(("#", ";")):
                        continue
                    d = v = ""
                    m = re.match(r"^([A-Za-z_][\w.-]*)\s*[=: \t]\s*(.*)$", s)
                    if m:
                        d, v = m.group(1), m.group(2).strip()
                    t.add(svc, host, i, d, v, s)
        # logrotate state: 'logfile "/var/log/syslog" 2026-8-16-6:0:0'
        st_rx = re.compile(r'^"?(?P<path>[^"]+)"?\s+(?P<y>\d{4})-(?P<mo>\d{1,2})'
                           r'-(?P<d>\d{1,2})-(?P<h>\d{1,2}):(?P<mi>\d{1,2})'
                           r':(?P<s>\d{1,2})\s*$')
        for pat in ("/var/lib/logrotate/status", "/var/lib/logrotate.status",
                    "/var/lib/logrotate/logrotate.status"):
            for rel in self.col.rootfs_glob(pat):
                host = self.col.host_path(rel)
                for i, ln in enumerate(self.lines(rel, "LOG_CONFIG"), 1):
                    m = st_rx.match(ln.strip())
                    if not m:
                        continue
                    g = m.groupdict()
                    stamp = "%s-%02d-%02d %02d:%02d:%02d" % (
                        g["y"], int(g["mo"]), int(g["d"]), int(g["h"]),
                        int(g["mi"]), int(g["s"]))
                    t.add("logrotate-state", host, i, g["path"],
                          self.ts_utc(stamp) or stamp, ln.strip())

    def t_device_profile(self):
        """FOR577 "Device Profiling": the facts that identify the host itself.

        The distro release file differs on every family, so all of them are read
        rather than assuming os-release exists - on older RHEL it does not.
        """
        t = self.table("DEVICE_PROFILE", "Device profile",
                       ["category", "source", "key", "value"], "System",
                       "Hostname, hosts file, timezone, distro release, "
                       "partitions and mount points - the identity of the "
                       "machine the collection came from.")
        simple = [
            ("hostname", "/etc/hostname"), ("hostname", "/etc/HOSTNAME"),
            ("machine-id", "/etc/machine-id"), ("machine-id", "/var/lib/dbus/machine-id"),
            ("timezone", "/etc/timezone"),
        ]
        # lookups are case-insensitive, so /etc/hostname and /etc/HOSTNAME
        # resolve to the same member on most collections
        emitted = set()
        for cat, path in simple:
            rel = self.col.rootfs(path)
            if not rel or rel.lower() in emitted:
                continue
            emitted.add(rel.lower())
            for ln in self.lines(rel, "DEVICE_PROFILE"):
                if ln.strip():
                    t.add(cat, self.col.host_path(rel), cat, ln.strip())
        # /etc/localtime is a symlink; a collection stores the target's bytes,
        # so record only that it exists and how big it is
        rel = self.col.rootfs("/etc/localtime")
        if rel:
            self.use(rel, "DEVICE_PROFILE")
            t.add("timezone", "/etc/localtime", "localtime",
                  "%d bytes of tzdata (symlink target)" % self.col.size(rel))
        for path in ("/etc/os-release", "/etc/lsb-release", "/etc/redhat-release",
                     "/etc/fedora-release", "/etc/centos-release",
                     "/etc/rocky-release", "/etc/system-release",
                     "/etc/oracle-release", "/etc/SuSE-release",
                     "/etc/SUSE-brand", "/etc/debian_version",
                     "/etc/alpine-release", "/usr/lib/os-release"):
            rel = self.col.rootfs(path)
            if not rel:
                continue
            for ln in self.lines(rel, "DEVICE_PROFILE"):
                s = ln.strip()
                if not s or s.startswith("#"):
                    continue
                if "=" in s:
                    k, v = s.split("=", 1)
                    t.add("distro", path, k.strip(), v.strip().strip('"'))
                else:
                    t.add("distro", path, "release", s)
        # these live under /proc on the host, so a collection can hold them
        # either as command output or as a copied rootfs file
        for cat, rels in (
                ("partitions", ("live_response/system/proc_partitions.txt",
                                "live_response/storage/proc_partitions.txt")),
                ("mounts", ("live_response/system/proc_mounts.txt",
                            "live_response/storage/proc_mounts.txt",
                            "live_response/storage/mount.txt")),
                ("kernel", ("live_response/system/proc_version.txt",
                            "live_response/system/uname_-a.txt"))):
            for rel in rels:
                for i, ln in enumerate(self.lines(rel, "DEVICE_PROFILE"), 1):
                    if ln.strip():
                        t.add(cat, rel, str(i), ln.strip())
        for cat, path in (("partitions", "/proc/partitions"),
                          ("mounts", "/proc/mounts"),
                          ("mounts", "/proc/self/mountinfo"),
                          ("kernel", "/proc/version"),
                          ("kernel", "/proc/cmdline"),
                          ("uptime", "/proc/uptime")):
            rel = self.col.rootfs(path)
            if not rel:
                continue
            for i, ln in enumerate(self.lines(rel, "DEVICE_PROFILE"), 1):
                if ln.strip():
                    t.add(cat, path, str(i), ln.strip())
        rel = self.col.rootfs("/etc/hosts")
        if rel:
            for i, ln in enumerate(self.lines(rel, "DEVICE_PROFILE"), 1):
                s = ln.strip()
                if s and not s.startswith("#"):
                    f = s.split()
                    t.add("hosts", "/etc/hosts", f[0], " ".join(f[1:]))

    def t_dev_files(self):
        """Regular files under /dev.

        FOR577 puts this under "Altered files": /dev should hold device nodes
        and symlinks, so a regular file there is either a payload staged where
        nobody looks or data staged for exfiltration. /dev/shm is tmpfs and
        legitimately holds files, but it is the single most common drop
        location, so it is listed rather than excluded.
        """
        t = self.table("DEV_FILES", "Regular files under /dev",
                       ["path", "area", "size_bytes", "size_human", "preview"],
                       "Filesystem",
                       "/dev should contain only device nodes and links. Every "
                       "regular file a collection captured there is listed - "
                       "shm and mqueue are tmpfs and can legitimately hold "
                       "files, but they are also the usual staging ground.")
        plen = len(self.col.prefix)
        rootfs = tuple(rd.lower() + "/dev/" for rd in self.col.rootfs_dirs)
        for low, real in sorted(self.col._names.items(), key=lambda kv: kv[1]):
            if not low.startswith(self.col.prefix):
                continue
            rel = real[plen:]
            if not rel.lstrip("/").lower().startswith(rootfs):
                continue
            host = self.col.host_path(rel)
            area = ("shm" if host.startswith("/dev/shm/") else
                    "mqueue" if host.startswith("/dev/mqueue/") else
                    "pts" if host.startswith("/dev/pts/") else "dev root")
            size = self.col.size(rel)
            raw = self.col.read_bytes(rel, 512) or b""
            preview = ("(binary)" if b"\x00" in raw else
                       trunc(" / ".join(raw.decode("utf-8", "replace")
                                        .splitlines()[:3]), 200))
            t.add(host, area, size, human_size(size), preview)
            self.use(rel, "DEV_FILES")
            if area != "pts":
                self.tri.ioc(host, "regular file under /dev")

    def t_editor_history(self):
        """Text editor and pager history.

        FOR577 lists these beside shell history as their own hunting category:
        .viminfo records which files were opened and what was searched for,
        .lesshst what was paged and searched.  They survive when an attacker
        truncates .bash_history, because they rarely think to clear them.
        """
        t = self.table("EDITOR_HISTORY", "Editor and pager history",
                       ["user", "tool", "kind", "timestamp_utc", "value",
                        "file", "line_no"], "Execution",
                       ".viminfo, .lesshst, nano search history and .gdb_history "
                       "- the files an attacker opened and the terms they "
                       "searched for.")
        specs = [("/root/.viminfo", "vim"), ("/home/*/.viminfo", "vim"),
                 ("/root/.lesshst", "less"), ("/home/*/.lesshst", "less"),
                 ("/root/.local/share/nano/search_history", "nano"),
                 ("/home/*/.local/share/nano/search_history", "nano"),
                 ("/root/.gdb_history", "gdb"), ("/home/*/.gdb_history", "gdb"),
                 ("/root/.local/share/recently-used.xbel", "gtk-recent"),
                 ("/home/*/.local/share/recently-used.xbel", "gtk-recent")]
        for pat, tool in specs:
            for rel in self.col.rootfs_glob(pat):
                host = self.col.host_path(rel)
                m = re.match(r"/home/([^/]+)/", host)
                user = m.group(1) if m else ("root" if host.startswith("/root/")
                                             else "")
                lines = self.lines(rel, "EDITOR_HISTORY")
                section = ""
                for i, ln in enumerate(lines, 1):
                    s = ln.rstrip()
                    if not s.strip():
                        continue
                    if tool == "vim":
                        # '# Command Line History (newest to oldest):' headings,
                        # then ':cmd' / '?search' / '> /path/to/file' entries,
                        # each '>' entry followed by indented mark data
                        if s.startswith("#"):
                            section = s.strip("# :").split("(")[0].strip()
                            continue
                        if s.startswith("|") or ln[:1] in (" ", "\t"):
                            continue     # machine-readable duplicate / mark data
                        kind = ("command" if s.startswith(":") else
                                "search" if s.startswith(("?", "/")) else
                                "file" if s.startswith(">") else
                                section.lower() or "entry")
                        # strip only the one-character marker, so a path keeps
                        # the leading slash that makes it a path
                        val = s[1:].strip() if s[:1] in ":?/>" else s
                        t.add(user, tool, kind, "", val, host, i)
                    elif tool == "gtk-recent":
                        rm = re.search(r'href="([^"]+)".*?modified="([^"]*)"', s)
                        if rm:
                            t.add(user, tool, "recent file",
                                  self.ts_utc(rm.group(2)), rm.group(1), host, i)
                    else:
                        if s.startswith(".") and len(s) < 20:
                            section = s.lstrip(".")   # .search / .shell in lesshst
                            continue
                        if s.startswith('"'):
                            s = s[1:]
                        t.add(user, tool, section or "entry", "", s, host, i)

    def t_containers(self):
        """Container runtime state.

        A container is a process tree, a filesystem and a network endpoint that
        none of the host-level tables explains: ps shows the runc child without
        saying which image it came from, and the port it answers on is a DNAT
        rule.  The runtime's own JSON has the mapping, so it gets parsed.
        """
        t = self.table("CONTAINERS", "Containers",
                       ["runtime", "container_id", "name", "image", "state",
                        "init_pid", "created", "hostname", "command", "rootfs",
                        "environment", "mounts", "capabilities", "source"],
                       "Containers",
                       "runc/containerd/docker on-disk state - image, entrypoint, "
                       "environment (credentials live here) and bind mounts.")
        pats = ["/run/docker/runtime-runc/*/*/state.json",
                "/var/run/docker/runtime-runc/*/*/state.json",
                "/run/containerd/*/*/*/config.json",
                "/var/run/containerd/*/*/*/config.json",
                "/var/lib/docker/containers/*/config.v2.json",
                "/var/lib/containerd/*/*/*/config.json"]
        seen = set()
        merged = {}                     # container id -> row dict
        order = []
        for pat in pats:
            for rel in self.col.rootfs_glob(pat):
                if rel.lower() in seen:
                    continue
                seen.add(rel.lower())
                host = self.col.host_path(rel)
                txt = self.text(rel, "CONTAINERS")
                try:
                    d = json.loads(txt)
                except Exception:
                    continue
                if not isinstance(d, dict):
                    continue
                cid = d.get("id") or d.get("ID") or ""
                if not cid:
                    m = re.search(r"/([0-9a-f]{12,64})/", host)
                    cid = m.group(1) if m else ""
                cfg = d.get("config") if isinstance(d.get("config"), dict) else {}
                proc = d.get("process") if isinstance(d.get("process"), dict) else {}
                runtime = ("docker" if "/docker/" in host else
                           "containerd" if "containerd" in host else "runc")
                mounts = d.get("mounts") or cfg.get("mounts") or []
                bind = []
                for mnt in mounts if isinstance(mounts, list) else []:
                    if not isinstance(mnt, dict):
                        continue
                    src = mnt.get("source") or mnt.get("Source") or ""
                    dst = mnt.get("destination") or mnt.get("Destination") or ""
                    # only host-path binds matter; proc/sysfs/tmpfs are boilerplate
                    if src.startswith("/") and dst:
                        bind.append("%s -> %s" % (src, dst))
                env = proc.get("env") or cfg.get("Env") or []
                caps = proc.get("capabilities") or {}
                capl = caps.get("effective") if isinstance(caps, dict) else None
                args = proc.get("args") or d.get("Path") or ""
                if isinstance(args, list):
                    args = " ".join(str(a) for a in args)
                row = {
                    "runtime": runtime, "container_id": cid,
                    "name": (d.get("Name") or "").lstrip("/"),
                    "image": (d.get("Image") or
                              ((d.get("Config") or {}).get("Image", "")
                               if isinstance(d.get("Config"), dict) else "")),
                    "state": (d.get("State", {}).get("Status", "")
                              if isinstance(d.get("State"), dict) else ""),
                    "init_pid": d.get("init_process_pid") or d.get("Pid") or "",
                    "created": d.get("created") or d.get("Created") or "",
                    "hostname": d.get("hostname") or cfg.get("hostname") or "",
                    "command": args,
                    "rootfs": ((d.get("root") or {}).get("path", "")
                               if isinstance(d.get("root"), dict)
                               else cfg.get("rootfs", "")),
                    "environment": (" | ".join(str(e) for e in env)
                                    if isinstance(env, list) else ""),
                    "mounts": " | ".join(bind),
                    "capabilities": ",".join(capl) if isinstance(capl, list) else "",
                    "source": host,
                }
                # runc's state.json and containerd's config.json each hold half
                # the picture for the same container - one row per container
                if cid and cid in merged:
                    prev = merged[cid]
                    for k, v in row.items():
                        if not prev.get(k) and v:
                            prev[k] = v
                        elif k == "source" and v and v not in prev[k]:
                            prev[k] += " | " + v
                    continue
                key = cid or host
                merged[key] = row
                order.append(key)
        for key in order:
            t.add_dict(merged[key])
        # whatever docker/podman/crictl reported live
        for rel in sorted(self.col.glob("live_response/containers/*.txt")) + \
                sorted(self.col.glob("live_response/*/docker_*.txt")) + \
                sorted(self.col.glob("live_response/*/podman_*.txt")):
            for ln in self.lines(rel, "CONTAINERS"):
                if ln.strip():
                    t.add(os.path.basename(rel).split("_")[0], "", "", "", "",
                          "", "", "", ln.strip(), "", "", "", "",
                          os.path.basename(rel))

    AUDIT_HDR_RE = re.compile(
        r"type=(\S+)\s+msg=audit\(([\d.]+):(\d+)\):\s*(.*)$")
    # auditd values are bare, "double quoted" or 'single quoted'; the trailing
    # quote of msg='...' otherwise sticks to the last value and res=success'
    # never compares equal to "success"
    AUDIT_KV_RE = re.compile(r"""(\w+)=("[^"]*"|'[^']*'|\S+)""")

    def _audit_files(self):
        """Every auditd log exactly once - the usual globs overlap."""
        out, seen = [], set()
        for pat in ("/var/log/audit/audit.log*", "/var/log/audit/*.log*",
                    "/var/log/audit.log*", "/var/log/audit/audit_log*"):
            for rel in self.col.rootfs_glob(pat):
                if rel.lower() in seen:
                    continue
                seen.add(rel.lower())
                out.append(rel)
        return out

    @classmethod
    def _audit_kv(cls, body, _depth=0):
        """auditd 'k=v k="v" k='v'' body -> dict, hex fields decoded.

        USER_* records nest their real fields inside msg='...', so that value is
        re-parsed rather than kept as one opaque string - otherwise acct, cmd
        and res are invisible on exactly the records that matter most.
        """
        kv = {}
        for k, v in cls.AUDIT_KV_RE.findall(body):
            v = v.strip("\"'")
            if k == "msg" and "=" in v and _depth < 2:
                kv.update(cls._audit_kv(v, _depth + 1))
                continue
            if k in ("cmd", "proctitle", "name", "cwd", "exe") and \
                    re.fullmatch(r"(?:[0-9A-Fa-f]{2})+", v or ""):
                try:                    # auditd hex-encodes anything with spaces
                    v = bytes.fromhex(v).decode(
                        "utf-8", "replace").replace("\x00", " ").strip()
                except ValueError:
                    pass
            kv[k] = v
        return kv

    def t_audit_log(self):
        """auditd records the syscalls no other log keeps.

        Every record is 'key=value key=value', so it is parsed into columns and
        the hex-encoded proctitle/name fields are decoded - an audit line whose
        command is still hex is an unread audit line.
        """
        t = self.table("AUDIT_LOG", "Linux audit records",
                       ["timestamp_utc", "event_id", "type", "pid", "ppid", "auid",
                        "uid", "gid", "euid", "comm", "exe", "cwd", "name", "key",
                        "success", "syscall", "terminal", "addr", "acct", "res",
                        "message", "source"],
                       "Audit",
                       "/var/log/audit/audit.log - execve, file and auth records "
                       "with the msg=audit(epoch:id) header decoded to UTC.")
        for rel in self._audit_files():
            lines = self.dlines(rel, "AUDIT_LOG")
            if lines is None:
                continue
            host = self.col.host_path(rel)
            for ln in lines:
                m = self.AUDIT_HDR_RE.search(ln)
                if not m:
                    continue
                rtype, ts, eid, body = m.groups()
                dt = epoch(ts)
                kv = self._audit_kv(body)
                if kv.get("addr") and kv["addr"] not in ("?", "-"):
                    self.tri.ioc(kv["addr"], host)
                t.add(dt.strftime("%Y-%m-%d %H:%M:%S") if dt else "", eid,
                      rtype, kv.get("pid", ""), kv.get("ppid", ""),
                      kv.get("auid", ""), kv.get("uid", ""), kv.get("gid", ""),
                      kv.get("euid", ""), kv.get("comm", ""), kv.get("exe", ""),
                      kv.get("cwd", ""), kv.get("name", ""), kv.get("key", ""),
                      kv.get("success", kv.get("res", "")),
                      kv.get("syscall", ""), kv.get("terminal", kv.get("tty", "")),
                      kv.get("addr", ""), kv.get("acct", ""), kv.get("res", ""),
                      kv.get("proctitle", kv.get("cmd", body.strip())), host)

    def t_live_sessions(self):
        """logind's runtime state: who was logged in at the moment of capture.

        wtmp says who logged in historically; /run/systemd/sessions says who was
        still there, from which address, on which seat - the answer to 'was the
        intruder on the box while we collected'.
        """
        t = self.table("LIVE_SESSIONS", "Logged-in sessions at collection time",
                       ["kind", "id", "key", "value", "source"], "Authentication",
                       "systemd-logind session/user/seat state plus who/w output.")
        for kind, pats in (
                ("session", ("/run/systemd/sessions/*", "/var/run/systemd/sessions/*")),
                ("user", ("/run/systemd/users/*", "/var/run/systemd/users/*")),
                ("seat", ("/run/systemd/seats/*", "/var/run/systemd/seats/*"))):
            for pat in pats:
                for rel in self.col.rootfs_glob(pat):
                    host = self.col.host_path(rel)
                    ident = os.path.basename(host)
                    if ident.endswith(".ref"):
                        continue
                    for ln in self.lines(rel, "LIVE_SESSIONS"):
                        s = ln.strip()
                        if not s or s.startswith("#") or "=" not in s:
                            continue
                        k, v = s.split("=", 1)
                        t.add(kind, ident, k.strip(), v.strip(), host)
        for rel in sorted(self.col.glob("live_response/system/w*.txt")) + \
                sorted(self.col.glob("live_response/system/who*.txt")) + \
                sorted(self.col.glob("live_response/system/loginctl*.txt")):
            base = os.path.basename(rel)
            for i, ln in enumerate(self.lines(rel, "LIVE_SESSIONS"), 1):
                if ln.strip():
                    t.add("command", base, str(i), ln.rstrip(), base)

    # Where each web stack keeps the files that decide what gets served and by
    # which interpreter. mods-enabled/conf-enabled/sites-enabled are symlink
    # farms - what is *linked* is the running configuration, so the enabled
    # column is the one to read first.
    WEB_CONFIG_PATS = (
        "/etc/apache2/**", "/etc/httpd/**", "/etc/apache2-*/**",
        "/etc/nginx/**", "/etc/lighttpd/**", "/etc/caddy/**",
        "/etc/php/**", "/etc/php.ini", "/etc/php.d/**", "/etc/php-fpm.d/**",
        "/etc/tomcat*/**", "/usr/local/apache2/conf/**",
        "/usr/local/nginx/conf/**",
        # per-directory overrides live with the content, not with the server,
        # and are writable by whoever can write the docroot
        "/var/www/**/.htaccess", "/srv/www/**/.htaccess",
        "/usr/share/nginx/**/.htaccess",
    )

    def t_web_config(self):
        """The web server's own configuration, not just its logs.

        WEB_LOG answers what was requested. This answers what the server was
        willing to serve and what it would execute: which interpreter modules
        are loaded, which vhosts and aliases exist, where each docroot points
        and which directories allow CGI. A webshell is usually invisible in the
        access log alone - the enabling line is here.
        """
        t = self.table("WEB_CONFIG", "Web server configuration",
                       ["server", "path", "enabled", "line_no", "directive",
                        "value", "text"], "Web",
                       "Apache/nginx/lighttpd/PHP configuration. enabled marks "
                       "files under a *-enabled/ or conf.d/ directory - the ones "
                       "actually in force. directive/value split the line so "
                       "DocumentRoot, Alias, LoadModule and ScriptAlias can be "
                       "read as a column.")
        seen = set()
        for pat in self.WEB_CONFIG_PATS:
            for rel in self.col.rootfs_glob(pat):
                if rel.lower() in seen:
                    continue
                seen.add(rel.lower())
                host = self.col.host_path(rel)
                low = host.lower()
                server = ("apache" if "/apache" in low or "/httpd" in low else
                          "nginx" if "/nginx" in low else
                          "lighttpd" if "/lighttpd" in low else
                          "caddy" if "/caddy" in low else
                          "tomcat" if "/tomcat" in low else
                          "php" if "/php" in low else "web")
                if low.endswith("/.htaccess"):
                    server = "htaccess"
                enabled = "yes" if re.search(
                    r"/(?:[a-z]+-enabled|conf\.d|sites-enabled|mods-enabled|"
                    r"conf-enabled)/", low) else ""
                # magic/mime.types are lookup tables, not policy: thousands of
                # rows that say nothing about how this host was configured
                if os.path.basename(low) in ("magic", "mime.types") or \
                        self.col.size(rel) > 512 * 1024:
                    self.use(rel, "WEB_CONFIG (reference data, not expanded)")
                    t.add(server, host, enabled, "", "", "",
                          "%s bytes, not expanded" % self.col.size(rel))
                    continue
                for i, ln in enumerate(self.lines(rel, "WEB_CONFIG"), 1):
                    s = ln.strip()
                    if not s or s.startswith(("#", ";")):
                        continue
                    m = re.match(r"^([A-Za-z_][\w.-]*)\s+(.*)$", s)
                    t.add(server, host, enabled, i,
                          m.group(1) if m else "", m.group(2).strip() if m else "",
                          ln.rstrip())

    # Application logs live wherever the application was installed. /var/log is
    # only the convention - a tool run out of a home directory writes beside
    # itself, and that is precisely the tool worth reading.
    APP_LOG_PATS = ("/root/**/*.log", "/home/*/**/*.log", "/opt/**/*.log",
                    "/srv/**/*.log", "/usr/local/**/*.log",
                    "/var/opt/**/*.log", "/var/snap/**/*.log",
                    "/var/lib/*/**/*.log", "/var/www/**/*.log",
                    "/root/**/*.log.[0-9]", "/home/*/**/*.log.[0-9]",
                    # boot-time components write to /run before /var/log is
                    # mounted, and that is the only copy of what they did
                    "/run/**/*.log", "/var/run/**/*.log")

    # Directory names that say where a log was filed, not what wrote it, plus
    # the instance ids some agents insert between the two.
    _GENERIC_DIR = {"log", "logs", "var", "opt", "srv", "usr", "local", "share",
                    "state", "lib", "run", "home", "root", "data", "cache",
                    "common", "current", "sessions", "session", "tmp", "snap",
                    "www", "config", ".config", ".local", ".cache"}
    _OPAQUE_DIR = re.compile(r"^(?:[0-9a-f-]{8,}|\d+)$", re.I)

    def _app_name(self, host):
        """Name the application from the directory a log sits under.

        'Responder/logs/Analyzer-Session.log' is written by Responder; taking
        the parent directory blindly names it 'logs', and taking it from the
        filename names it 'Analyzer-Session'. Walk up past the directories
        that only describe filing, and past the instance GUIDs agents insert.
        """
        parts = [p for p in host.split("/")[:-1] if p]
        for p in reversed(parts):
            if p.lower() in self._GENERIC_DIR or self._OPAQUE_DIR.match(p):
                continue
            return p
        return os.path.splitext(os.path.basename(host))[0]

    def t_app_logs(self):
        """Logs outside /var/log.

        VAR_LOG covers the system log directory; nothing covered the logs an
        application writes next to itself. On the collections this was built
        against that gap held a credential-relay tool's session logs and a
        password cracker's run log in /root - the highest-value text in the
        image, sitting in UNPARSED_FILES.
        """
        t = self.table("APP_LOGS", "Application logs outside /var/log",
                       ["timestamp_utc", "timestamp", "application", "path",
                        "line_no", "message"], "Logging",
                       "Logs an application wrote beside itself rather than into "
                       "/var/log - tooling dropped into a home directory shows up "
                       "here and nowhere else.")
        varlog = set(r.lower() for r in self._log_files())
        seen = set()
        for pat in self.APP_LOG_PATS:
            for rel in self.col.rootfs_glob(pat):
                low = rel.lower()
                if low in seen or low in varlog:
                    continue
                seen.add(low)
                host = self.col.host_path(rel)
                if self.col.size(rel) > 32 * 1024 * 1024:
                    self.use(rel, "APP_LOGS (too large, skipped)")
                    continue
                lines = self.dlines(rel, "APP_LOGS")
                if lines is None:
                    self.use(rel, "APP_LOGS (undecodable)")
                    continue
                app = self._app_name(host)
                for i, ln in enumerate(lines, 1):
                    if not ln.strip():
                        continue
                    if "\x00" in ln:
                        self.use(rel, "APP_LOGS (binary, skipped)")
                        break
                    ts, _lh, _pr, _pid, msg = split_log_line(ln)
                    t.add(self.ts_utc(ts), ts, app, host, i, msg or ln.rstrip())

    # Per-account files that record what the account reached out to or what it
    # holds credentials for. None of them are shell history, so nothing else
    # in the export was looking at them.
    USER_ARTIFACT_PATS = (
        ("/root/.wget-hsts", "wget", "hosts contacted over HTTPS"),
        ("/home/*/.wget-hsts", "wget", "hosts contacted over HTTPS"),
        ("/root/.netrc", "netrc", "stored login credentials"),
        ("/home/*/.netrc", "netrc", "stored login credentials"),
        ("/root/.git-credentials", "git", "stored credentials"),
        ("/home/*/.git-credentials", "git", "stored credentials"),
        ("/root/.gitconfig", "git", "git identity and hooks"),
        ("/home/*/.gitconfig", "git", "git identity and hooks"),
        ("/root/.docker/config.json", "docker", "registry credentials"),
        ("/home/*/.docker/config.json", "docker", "registry credentials"),
        ("/root/.aws/credentials", "aws", "cloud credentials"),
        ("/home/*/.aws/credentials", "aws", "cloud credentials"),
        ("/root/.aws/config", "aws", "cloud profile"),
        ("/home/*/.aws/config", "aws", "cloud profile"),
        ("/root/.kube/config", "kubernetes", "cluster credentials"),
        ("/home/*/.kube/config", "kubernetes", "cluster credentials"),
        ("/root/.npmrc", "npm", "registry token"),
        ("/home/*/.npmrc", "npm", "registry token"),
        ("/root/.pypirc", "pypi", "registry token"),
        ("/home/*/.pypirc", "pypi", "registry token"),
        ("/root/.config/rclone/rclone.conf", "rclone", "remote storage targets"),
        ("/home/*/.config/rclone/rclone.conf", "rclone", "remote storage targets"),
        ("/root/.curlrc", "curl", "default curl options"),
        ("/home/*/.curlrc", "curl", "default curl options"),
        ("/root/.wgetrc", "wget", "default wget options"),
        ("/home/*/.wgetrc", "wget", "default wget options"),
    )
    # anything that looks like key material is recorded as present, never printed
    SECRET_HINT = re.compile(
        r"(?i)(password|passwd|secret|token|auth|api[_-]?key|private[_-]?key)")

    def t_user_artifacts(self):
        """Per-account credential and remote-target files.

        The HSTS cache is the interesting one: wget and curl append a host to
        it on the first HTTPS request, so it is a durable record of where an
        account fetched from, surviving the shell history being cleared.
        """
        t = self.table("USER_ARTIFACTS", "Per-account tool and credential files",
                       ["user", "tool", "artifact", "path", "line_no", "value"],
                       "Account",
                       "HSTS caches, .netrc and per-tool credential files. Lines "
                       "that look like key material are reported as present "
                       "without their value - the finding is that the account "
                       "holds one, not what it is.")
        for pat, tool, what in self.USER_ARTIFACT_PATS:
            for rel in self.col.rootfs_glob(pat):
                host = self.col.host_path(rel)
                m = re.match(r"/home/([^/]+)/", host)
                user = m.group(1) if m else ("root" if host.startswith("/root/")
                                             else "")
                emitted = False
                for i, ln in enumerate(self.lines(rel, "USER_ARTIFACTS"), 1):
                    s = ln.strip()
                    if not s or s.startswith("#"):
                        continue
                    if self.SECRET_HINT.search(s):
                        key = s.split("=")[0].split(":")[0].strip()
                        s = "%s = (value withheld, %d chars)" % (key, len(s))
                    t.add(user, tool, what, host, i, s)
                    emitted = True
                if not emitted:
                    t.add(user, tool, what, host, "", "(file present but empty)")

    # Two spellings of a profile header, both still in use:
    #   profile <name> [/attach/path] [flags=(complain)] {
    #   /attach/path [flags=(complain)] {
    # The flags= prefix is optional in the older syntax, which is why it is not
    # required here - and the flag is the whole point of the row.
    # The bare form is only accepted at column 0: indented, an attachment path
    # followed by a brace is a rule with a brace expansion in it
    # (/var/lib/dhcp{,6}) or a variable (@{multiarch}), not a profile header.
    # A space before the brace is likewise required, which is what separates
    # 'profile foo /bin/foo {' from 'owner /run/user/@{uid}/ rw,'.
    APPARMOR_PROFILE_RE = re.compile(
        # the attachment may itself contain brace expansion -
        # '/{,usr/}{,s}bin/unix_chkpwd' - so it runs to whitespace, not to '{'
        r"(?m)^(?:\s*profile\s+(?P<name>[^\s{]+)(?:\s+(?P<attach>/\S+))?"
        r"|(?P<attach2>/\S+))"
        r"(?:\s+(?:flags\s*=\s*)?\((?P<flags>[^)]*)\))?\s+\{")

    # Every VPN and tunnel client keeps its peer, its route pushes and its key
    # material somewhere different. FOR577 groups them under remote access for
    # the same reason SSH is there: they are how something reached this host,
    # or how this host reached a network it is not on.
    VPN_PATS = (
        ("/etc/openvpn/**", "openvpn"), ("/etc/wireguard/*", "wireguard"),
        ("/etc/ipsec.conf", "ipsec"), ("/etc/ipsec.d/**", "ipsec"),
        ("/etc/ipsec.secrets", "ipsec"), ("/etc/strongswan.conf", "ipsec"),
        ("/etc/swanctl/**", "ipsec"), ("/etc/ppp/**", "ppp"),
        ("/etc/tinc/**", "tinc"), ("/etc/zerotier-one/*.conf", "zerotier"),
        ("/etc/tailscale/**", "tailscale"),
        ("/var/lib/tailscale/*.conf", "tailscale"),
        ("/root/**/*.ovpn", "openvpn"), ("/home/*/**/*.ovpn", "openvpn"),
        ("/root/.config/AWSVPNClient/**", "aws-vpn-client"),
        ("/home/*/.config/AWSVPNClient/**", "aws-vpn-client"),
        ("/etc/NetworkManager/system-connections/*", "networkmanager"),
    )
    # extensions whose contents are key material or a certificate: recorded as
    # present with a fingerprint-sized summary, never emitted line by line
    KEY_EXTS = (".key", ".pem", ".crt", ".csr", ".req", ".p12", ".pfx", ".der",
                ".cer", ".jks", ".keystore")

    def t_memory_output(self):
        """Volatility output UAC saved beside the memory image.

        The image itself is out of scope here - but the plugin output next to
        it is text, and it is the one view of the host that did not come from
        the host's own userland. A socket that appears in linux.sockstat and
        not in SOCKETS is the definition of a hidden connection.
        """
        t = self.table("MEMORY_OUTPUT", "Memory-analysis output",
                       ["plugin", "line_no", "text", "source"], "Memory",
                       "Volatility (or equivalent) output collected alongside "
                       "the memory image. Compare against the live tables: what "
                       "memory shows and userland does not is the finding. The "
                       "image itself is only scanned with --deep.")
        for rel in sorted(self.col.glob("memory_dump/*")):
            base = os.path.basename(rel)
            low = base.lower()
            if "strings" in low or low.endswith((".lime", ".raw", ".mem",
                                                 ".dmp", ".core", ".vmem",
                                                 ".img", ".bin")):
                continue          # the image and its strings, not an analysis
            if self.col.size(rel) > 32 * 1024 * 1024:
                self.use(rel, "MEMORY_OUTPUT (too large, skipped)")
                continue
            plugin = re.sub(r"^output[-_]", "", base)
            for i, ln in enumerate(self.lines(rel, "MEMORY_OUTPUT"), 1):
                if ln.strip():
                    t.add(plugin, i, ln.rstrip(), rel)

    def t_remote_access(self):
        """VPN and tunnel configuration, and the key material beside it.

        SSH is one way in and it already has a table. This is the rest: which
        peer this host dials, which routes that pushes, and which certificates
        and pre-shared keys it holds. An .ovpn in a home directory is a route
        into a network the host list does not describe.
        """
        t = self.table("REMOTE_ACCESS", "VPN and tunnel configuration",
                       ["technology", "kind", "path", "owner_hint", "detail"],
                       "Remote Access",
                       "OpenVPN/WireGuard/IPsec/PPP configuration, NetworkManager "
                       "connection profiles and VPN client profiles, plus the "
                       "certificates and keys they reference. Key material is "
                       "recorded as present, never printed.")
        seen = set()
        for pat, tech in self.VPN_PATS:
            for rel in self.col.rootfs_glob(pat):
                if rel.lower() in seen:
                    continue
                seen.add(rel.lower())
                host = self.col.host_path(rel)
                m = re.match(r"/home/([^/]+)/", host)
                owner = m.group(1) if m else ("root" if host.startswith("/root/")
                                              else "")
                low = host.lower()
                if low.endswith(self.KEY_EXTS):
                    head = (self.text(rel, "REMOTE_ACCESS") or "").strip().splitlines()
                    t.add(tech, "key material", host, owner,
                          "%s bytes, %s" % (self.col.size(rel),
                                            trunc(head[0] if head else "binary", 60)))
                    continue
                if self.col.size(rel) > 256 * 1024:
                    self.use(rel, "REMOTE_ACCESS (too large, not expanded)")
                    t.add(tech, "config", host, owner,
                          "%s bytes, not expanded" % self.col.size(rel))
                    continue
                emitted = False
                for ln in self.lines(rel, "REMOTE_ACCESS"):
                    s = ln.strip()
                    if not s or s.startswith(("#", ";")):
                        continue
                    if self.SECRET_HINT.search(s):
                        # keep the directive, drop everything after it - a line
                        # that is only a value has no directive to keep
                        head = s.split("=")[0].split()
                        s = "%s (value withheld)" % (head[0] if head else "line")
                    t.add(tech, "config", host, owner, s)
                    emitted = True
                if not emitted:
                    t.add(tech, "config", host, owner, "(file present but empty)")

    def t_mac_policy(self):
        """AppArmor and SELinux policy, one row per profile rather than per line.

        The question a profile answers is not what it permits in detail - it is
        whether it is enforcing. A profile in complain mode logs a violation
        and allows it, so an exploit that the policy would have stopped runs
        anyway; a profile in /etc/apparmor.d/disable is not loaded at all.
        Expanding the rule bodies would have added thousands of rows of shipped
        distribution policy to say that.
        """
        t = self.table("MAC_POLICY", "Mandatory access control profiles",
                       ["system", "profile", "attachment", "mode", "flags",
                        "rules", "path"], "Privilege",
                       "AppArmor profiles and SELinux policy config. mode is the "
                       "one to read: 'complain' logs violations instead of "
                       "blocking them, and a profile under disable/ is not "
                       "loaded. Rule bodies are counted, not expanded.")
        disabled = set()
        for rel in self.col.rootfs_glob("/etc/apparmor.d/disable/*"):
            disabled.add(os.path.basename(self.col.host_path(rel)))
        # abstractions/tunables/abi are fragments profiles include, local and
        # disable are handled elsewhere, and cache is compiled output - the
        # rest of the tree is profiles, at whatever depth the distribution
        # filed them (lxc/ and containers/ nest one level down)
        fragments = ("/abstractions/", "/tunables/", "/abi/", "/cache/",
                     "/local/", "/disable/", "/force-complain/")
        for rel in self.col.rootfs_glob("/etc/apparmor.d/**"):
            host = self.col.host_path(rel)
            base = os.path.basename(host)
            if any(f in host for f in fragments):
                continue
            if base.startswith(".") or self.col.size(rel) > 512 * 1024:
                continue
            text = self.text(rel, "MAC_POLICY")
            if "profile " not in text and "{" not in text:
                continue
            rules = sum(1 for ln in text.splitlines()
                        if ln.strip() and not ln.strip().startswith("#"))
            found = False
            for m in self.APPARMOR_PROFILE_RE.finditer(text):
                name = m.group("name")
                attach = m.group("attach") or m.group("attach2")
                if not name and not attach:
                    continue
                flags = (m.group("flags") or "").strip()
                mode = ("disabled" if base in disabled else
                        "complain" if "complain" in flags else
                        "unconfined" if "unconfined" in flags else "enforce")
                t.add("apparmor", name or attach, attach or "", mode, flags,
                      rules, host)
                found = True
            if not found:
                t.add("apparmor", base, "", "disabled" if base in disabled
                      else "enforce", "", rules, host)
        for pat in ("/etc/selinux/config", "/etc/selinux/semanage.conf",
                    "/etc/selinux/*/setrans.conf"):
            for rel in self.col.rootfs_glob(pat):
                host = self.col.host_path(rel)
                for ln in self.lines(rel, "MAC_POLICY"):
                    s = ln.strip()
                    if s and not s.startswith("#"):
                        t.add("selinux", "", "", "", s, "", host)

    # -- 9. detection rules -------------------------------------------------
    # What YARA is pointed at. The rootfs copy is the obvious target; the
    # per-process memory strings are the one that finds things a file scan
    # cannot, because an implant that unlinked itself still has its strings in
    # the address space UAC dumped. The multi-GB memory image stays behind
    # --deep, like the existing strings scan.
    YARA_MAX_FILE = 16 * 1024 * 1024

    def _rule_files(self, paths, exts):
        """Every rule file under the given files/directories, sorted."""
        out = []
        for p in paths or []:
            if os.path.isdir(p):
                for root, _dirs, files in os.walk(p):
                    for f in sorted(files):
                        if f.lower().endswith(exts):
                            out.append(os.path.join(root, f))
            elif os.path.exists(p):
                out.append(p)
            else:
                self.rule_errors.append(("(path)", p, "no such file or directory"))
        return sorted(set(out))

    def _read_rule(self, path):
        try:
            # _win_long: a rule cached from SigmaHQ can sit five directories
            # deep with a CVE-length name, which is past what Windows opens
            # under a plain path - and it would be reported as a missing file
            with open(_win_long(path), "r", encoding="utf-8",
                      errors="replace") as fh:
                return fh.read()
        except OSError as e:
            self.rule_errors.append(("(file)", path, str(e)))
            return None

    def _yara_targets(self):
        """(rel, kind, data) for everything YARA should look at."""
        plen = len(self.col.prefix)
        rootfs = tuple(rd.lower() + "/" for rd in self.col.rootfs_dirs)
        for low, real in sorted(self.col._names.items(), key=lambda kv: kv[1]):
            if not low.startswith(self.col.prefix):
                continue
            rel = real[plen:]
            rl = rel.lstrip("/").lower()
            size = self.col._sizes.get(low, 0)
            if not size:
                continue
            if "/strings.txt" in rl and "/process/proc/" in rl:
                raw = decompress_bytes(rel, self.col.read_bytes(rel))
                if raw:
                    yield rel, "process strings", raw
                continue
            if rl.startswith("memory_dump/"):
                if self.tri.opts.deep and "strings" in rl:
                    raw = self.col.read_bytes(rel)
                    if raw:
                        yield rel, "memory image strings", raw
                continue
            if not rl.startswith(rootfs) or size > self.YARA_MAX_FILE:
                continue
            raw = self.col.read_bytes(rel)
            if raw:
                yield rel, "collected file", raw

    def t_yara(self):
        """Scan the collection with YARA rules supplied on the command line."""
        paths = getattr(self.tri.opts, "yara", None)
        if not paths:
            return
        rules = []
        for path in self._rule_files(paths, (".yar", ".yara", ".rule", ".rules")):
            text = self._read_rule(path)
            if text is None:
                continue
            got, errs = parse_yara(text, path)
            rules.extend(got)
            self.rule_errors.extend(("yara", "%s: %s" % (path, n), e)
                                    for n, e in errs)
        t = self.table("YARA_MATCHES", "YARA rule matches",
                       ["rule", "severity", "tags", "description", "path",
                        "target", "strings_hit", "first_offset", "match_preview",
                        "rule_file"], "Detection",
                       "Files and process memory strings matched by the YARA "
                       "rules given with --yara. Offsets are into the collected "
                       "artifact, not the live host.")
        if not rules:
            return
        status("[*] yara: %d rule(s) loaded" % len(rules))
        scanned = 0
        for rel, kind, data in self._yara_targets():
            scanned += 1
            host = self.col.host_path(rel)
            for r in rules:
                hits = r.match(data)
                if not hits:
                    continue
                self.use(rel, "YARA_MATCHES")
                idents = sorted(hits)
                first = min(off for h in hits.values() for off, _ in h)
                sample = next(iter(hits.values()))[0][1]
                t.add(r.name, self._rule_severity(r.meta), " ".join(r.tags),
                      r.meta.get("description", ""), host, kind,
                      ", ".join("$" + i for i in idents), first,
                      trunc(_printable(sample), 120), r.source)
                self.tri.add(self._rule_severity(r.meta), "Detection",
                             "YARA rule %s matched %s" % (r.name, host),
                             r.meta.get("description", "") or
                             "matched %s in %s" % (", ".join("$" + i for i in idents),
                                                   kind),
                             ["%s at offset %d: %s"
                              % ("$" + i, hits[i][0][0],
                                 trunc(_printable(hits[i][0][1]), 100))
                              for i in idents[:10]],
                             host, r.meta.get("mitre", ""), count=len(idents))
                self.tri.ioc(host, "yara:%s" % r.name)
        status("[*] yara: scanned %d artifact(s), %d match row(s)"
              % (scanned, len(t)))

    @staticmethod
    def _rule_severity(meta):
        """A rule's own opinion of how bad a hit is, if it states one."""
        for key in ("severity", "level", "confidence"):
            v = str(meta.get(key, "")).upper()
            if v in SEVERITIES:
                return v
        try:                                    # signature-base style score
            score = int(meta.get("score", ""))
            return ("CRITICAL" if score >= 80 else "HIGH" if score >= 60
                    else "MEDIUM" if score >= 40 else "LOW")
        except (TypeError, ValueError):
            return "HIGH"

    # Which built tables a Sigma rule runs against, keyed by the logsource it
    # declares. A rule with no service or category runs against all of them -
    # that is what a bare 'product: linux' rule means.
    SIGMA_STREAMS = (
        ("PROCESSES", ("process_creation", "process", "ps"), "start_utc"),
        ("PROCESS_MASTER", ("process_creation", "process"), "start_utc"),
        ("AUDIT_LOG", ("auditd", "audit"), "timestamp_utc"),
        ("AUTH_LOG", ("auth", "authentication", "sshd", "sudo", "secure",
                      "syslog"), "timestamp_utc"),
        ("FAILED_LOGINS", ("auth", "authentication", "sshd"), "timestamp_utc"),
        ("PRIVILEGE_ACTIVITY", ("auth", "sudo", "sudoers"), "timestamp_utc"),
        ("JOURNAL", ("journald", "journal", "syslog", "systemd"), "timestamp_utc"),
        ("VAR_LOG", ("syslog", "messages", "cron", "log"), "timestamp_utc"),
        ("CRON", ("cron", "crontab"), ""),
        ("WEB_LOG", ("webserver", "apache", "nginx", "httpd"), "timestamp_utc"),
        ("SHELL_HISTORY", ("bash", "shell", "history"), "timestamp_utc"),
        ("SYSTEMD_UNITS", ("systemd", "service"), ""),
        ("KERNEL_MODULES", ("kernel", "modules"), ""),
        ("SOCKETS", ("network_connection", "network"), ""),
    )

    # VAR_LOG and JOURNAL are every log on the host in one table, so routing a
    # rule to them by logsource is not enough: 'service: cron' means the cron
    # log, and SigmaHQ's crontab rule is the single keyword REPLACE, which
    # matched cloud-init and dmesg lines until the rows were narrowed to the
    # service the rule actually named.
    SIGMA_MIXED_STREAMS = frozenset(("VAR_LOG", "JOURNAL"))

    # Fields a match summary must carry for a given table, whatever their
    # column position. matched_row takes the first few fields of the row, and
    # WEB_LOG puts status at column 10 - past the cut - so every web hit was
    # reported without the one field that says whether it mattered. A rule
    # firing on a request that returned 200 is a breach; the same request
    # returning 404 is a scanner being ignored, and the row read identically.
    SIGMA_SUMMARY_KEYS = {
        "WEB_LOG": ("status", "method", "resource", "client_ip", "user_agent"),
    }

    @classmethod
    def _sigma_summary(cls, tname, d, limit=8):
        """One matched row as 'key=value; ...' for SIGMA_MATCHES.matched_row.

        Fields named for this table lead and are never lost to the cap; the
        rest follow in the row's own order. A table with no entry keeps
        exactly the previous behaviour.
        """
        lead = [k for k in cls.SIGMA_SUMMARY_KEYS.get(tname, ())
                if d.get(k) not in (None, "")]
        rest = [k for k in d if k not in lead]
        keys = (lead + rest)[:max(limit, len(lead))]
        return "; ".join("%s=%s" % (k, trunc(str(d[k]), 80)) for k in keys)
    SIGMA_SERVICE_HINTS = {
        "cron": ("cron", "anacron", "crond"),
        "sshd": ("sshd", "ssh"),
        "auth": ("auth", "secure", "sshd", "sudo", "su", "login", "pam",
                 "polkit", "systemd-logind"),
        "authentication": ("auth", "secure", "sshd", "sudo", "su", "login"),
        "sudo": ("sudo", "auth", "secure"),
        "sudoers": ("sudo", "auth", "secure"),
        "auditd": ("audit",),
        "clamav": ("clamav", "clamd", "freshclam"),
        "vsftpd": ("vsftpd", "ftp"),
        "guacamole": ("guacamole", "guacd"),
        "modsecurity": ("modsec", "apache", "nginx", "error"),
    }

    @classmethod
    def _service_filter(cls, service):
        """Row predicate narrowing a mixed log table to one service, or None."""
        hints = cls.SIGMA_SERVICE_HINTS.get((service or "").lower())
        if not hints:
            return None

        def keep(d):
            where = (d.where() if isinstance(d, Row) else
                     ("%s %s %s" % (d.get("log", ""), d.get("process", ""),
                                    d.get("unit", ""))).lower())
            return any(h in where for h in hints)
        return keep

    # Where to hunt for tool names, and what kind of text each column holds.
    # 'command' and 'path' columns name something executable, so the ambiguous
    # tier is matched there too; 'text' columns are free prose from a log and
    # get the unambiguous tier only.
    HACKTOOL_SCAN = (
        ("SHELL_HISTORY", ("command",), "command"),
        ("EDITOR_HISTORY", ("value",), "command"),
        ("PROCESS_MASTER", ("exe", "args", "comm"), "command"),
        ("PROCESSES", ("exe", "args"), "command"),
        ("PROC_ENVIRON", ("value",), "command"),
        ("CRON", ("command",), "command"),
        ("SYSTEMD_UNITS", ("exec_start", "exec_start_pre"), "command"),
        ("INIT_AND_PROFILE", ("text",), "command"),
        ("PACKAGES", ("name", "description"), "path"),
        ("SUID_SGID", ("path",), "path"),
        ("CAPABILITIES", ("path",), "path"),
        ("FILE_HASHES", ("path",), "path"),
        ("BODYFILE", ("path",), "path"),
        ("OPEN_FILES", ("name",), "path"),
        ("HIDDEN_PATHS", ("path",), "path"),
        # a scanner's User-Agent names the tool that ran; a requested path is
        # attacker *input* - a wordlist contains every tool name there is, so
        # /wordpress/john says nothing about john being present
        ("WEB_LOG", ("user_agent",), "command"),
        ("WEB_LOG", ("resource",), "text"),
        ("WEB_CONFIG", ("value", "text"), "text"),
        ("APP_LOGS", ("message",), "text"),
        ("VAR_LOG", ("message",), "text"),
        ("JOURNAL", ("message",), "text"),
        ("AUTH_LOG", ("message",), "text"),
        ("AUDIT_LOG", ("exe", "proctitle", "name"), "command"),
        ("KERNEL_MODULES", ("name", "path"), "path"),
    )

    # Paths a package manager owns. A tool name here is almost always the
    # distribution's own word rather than an operator's file, so the ambiguous
    # tier is not matched at all and the unambiguous tier is reported a step
    # lower - /usr/share/nmap belongs to the nmap package, which is a different
    # fact from /root/nmap.
    DISTRO_PATHS = ("/usr/share/", "/usr/src/", "/usr/lib/", "/usr/include/",
                    "/lib/", "/lib64/", "/usr/share/man/", "/usr/share/doc/",
                    "/var/lib/dpkg/", "/var/lib/rpm/", "/snap/", "/etc/alternatives/")

    def t_hacktools(self):
        """Named offensive tooling, hunted across every artifact that names one.

        SUSPICIOUS_CMD_PATTERNS already covers technique shapes - a reverse
        shell, a piped download, history tampering. This covers the other half
        of the question an analyst asks: is any of the well-known toolkit here
        at all, whether it was run, downloaded, installed, left on disk or only
        mentioned in a log. Answering that from the built tables means a hit in
        a filename, a package list, a web request and a shell history all land
        in one place, with where_seen saying which - because a tool in bash
        history is a different fact from a tool named in an access log.
        """
        t = self.table("HACKTOOL_HITS", "Known offensive tooling referenced",
                       ["severity", "category", "tool", "count", "first_utc",
                        "last_utc", "timestamp_utc", "where_seen", "table",
                        "context", "detail"], "Detection",
                       "Well-known attacker tooling matched by name across the "
                       "artifacts. Ambiguous names ('john', 'empire', 'beacon') "
                       "are only matched in command lines and paths, never in "
                       "free log text, because there they are just words. "
                       "timestamp_utc is the source row's own time, where the "
                       "table it came from carries one; count, first_utc and "
                       "last_utc describe the tool across every table and "
                       "repeat on each of its rows, matching the one finding "
                       "raised per tool. They count every reference, not the "
                       "twelve per table kept as samples.")
        by_name = {tb.name: tb for tb in self.tables}
        extra = self._extra_keywords()
        # --no-hunt turns off the built-in list but never the terms the user
        # explicitly asked for: passing both should hunt exactly those
        builtin = not getattr(self.tri.opts, "no_hunt", False)
        if not builtin and not extra:
            return
        seen = defaultdict(list)                  # (tool, cat, table) -> details
        tally = defaultdict(int)                  # same key -> every match
        spans = defaultdict(lambda: ["", ""])     # same key -> [first, last]
        variants = defaultdict(dict)              # same key -> {text: [n, span, cols]}
        for tname, want_cols, kind in self.HACKTOOL_SCAN:
            tb = by_name.get(tname)
            if tb is None or not len(tb):
                continue
            cols = [str(c) for c in tb.columns]
            idxs = [(c, cols.index(c)) for c in want_cols if c in cols]
            if not idxs:
                continue
            ts_i = self.row_time_index(cols)
            tiers = [(HACKTOOL_RE, HACKTOOL_CAT, False)] if builtin else []
            if builtin and kind in ("command", "path"):
                tiers.append((HACKTOOL_CTX_RE, HACKTOOL_CTX_CAT, True))
            for row in tb.iter_rows():
                # resolved on the first match in this row, not for every row:
                # BODYFILE and VAR_LOG are hundreds of thousands of rows each
                # and almost none of them name a tool
                rowts = None
                for cname, i in idxs:
                    if i >= len(row):
                        continue
                    val = row[i]
                    if not val:
                        continue
                    val = str(val)
                    distro = val.startswith(self.DISTRO_PATHS)
                    # lowered once per cell, not per tier, and matched against
                    # case-sensitive patterns built from lowercased names. The
                    # evidence below still quotes `val`, so what an analyst
                    # reads is the artifact's own text, not this copy.
                    low = val.lower()
                    for rx, catmap, ambiguous in tiers:
                        # an ordinary word inside distribution content is the
                        # distribution's word: hydra.h is a PowerPC kernel
                        # header, terminfo/b/beacon is a terminal definition
                        if ambiguous and distro:
                            continue
                        # search first: it is a single C call that returns None
                        # for the overwhelming majority of log lines, where
                        # finditer would allocate an iterator per cell - three
                        # million allocations to find nothing
                        if rx.search(low) is None:
                            continue
                        # one hit per category per cell, exactly as the
                        # per-category searches produced: scanning left to
                        # right, the first match for a category is that
                        # category's earliest occurrence in the string
                        done = set()
                        for mt in rx.finditer(low):
                            tool = mt.group(1)
                            cat = catmap.get(tool)
                            if cat is None or cat in done:
                                continue
                            done.add(cat)
                            if rowts is None:
                                rowts = (_ts_text(row[ts_i])
                                         if 0 <= ts_i < len(row) else "")
                            key = (tool, cat, tname, kind, distro)
                            tally[key] += 1
                            span_add(spans[key], rowts)
                            variant_add(variants[key], val, cname, rowts)
                            if len(seen[key]) < 12:
                                seen[key].append((cname, trunc(val, 200), rowts))
                    for term, rx in extra:
                        if rx.search(val):
                            if rowts is None:
                                rowts = (_ts_text(row[ts_i])
                                         if 0 <= ts_i < len(row) else "")
                            key = (term, "user keyword", tname, kind, distro)
                            tally[key] += 1
                            span_add(spans[key], rowts)
                            variant_add(variants[key], val, cname, rowts)
                            if len(seen[key]) < 12:
                                seen[key].append((cname, trunc(val, 200), rowts))
        # One finding per tool, not per table. The same toolkit shows up in the
        # bodyfile, the hashes and the shell history, and three findings saying
        # 'certipy' is three times the reading for one fact - the tables it was
        # seen in belong in the evidence, which is also where the strongest
        # context is visible.
        per_tool = defaultdict(lambda: {"sev": "INFO", "where": [], "ev": [],
                                        "n": 0, "span": ["", ""]})
        graded = []
        for key, rows in sorted(seen.items()):
            tool, cat, tname, kind, distro = key
            # A name in a log message is weaker evidence than the same name as
            # something that ran, and a name inside a distribution-owned path
            # is weaker still, so each knocks the severity down one step.
            step = (1 if kind == "text" else 0) + (1 if distro else 0)
            base = HACKTOOL_SEVERITY.get(cat, "HIGH")
            sev = SEVERITIES[min(len(SEVERITIES) - 1,
                                 SEVERITIES.index(base) + step)]
            where = "%s (distribution-owned path)" % kind if distro else kind
            graded.append((key, rows, sev, where))
            agg = per_tool[(tool, cat)]
            if SEVERITIES.index(sev) < SEVERITIES.index(agg["sev"]):
                agg["sev"] = sev
            agg["where"].append("%s (%s) x%d" % (tname, where, tally[key]))
            agg["n"] += tally[key]
            span_add(agg["span"], spans[key][0])
            span_add(agg["span"], spans[key][1])
            agg["ev"].extend("%s %s: %s" % (tname, c, d) for c, d, _w in rows[:4])
            self.tri.ioc(tool, "hacktool:%s" % tname)
        # rows only once every table has been graded: each carries its tool's
        # totals, which are not known until the last table has been read
        for (tool, cat, tname, _kind, _distro), rows, sev, where in graded:
            agg = per_tool[(tool, cat)]
            for cname, detail, rowts in rows:
                t.add(sev, cat, tool, agg["n"], agg["span"][0], agg["span"][1],
                      rowts, cname, tname, where, detail)
        for (tool, cat), agg in sorted(per_tool.items()):
            self.tri.add(agg["sev"], "Detection",
                         "Offensive tool referenced: %s" % tool,
                         "%s - seen in %s" % (cat, "; ".join(agg["where"])),
                         agg["ev"][:12], ", ".join(sorted(
                             w.split(" ")[0] for w in agg["where"])),
                         count=agg["n"], times=agg["span"])
        # The same references rolled up: one row per distinct string per tool,
        # counted over every hit rather than the twelve sampled per table.
        # HACKTOOL_HITS answers "when did each one happen" and keeps the
        # cadence that a rollup destroys; this answers "what exactly was seen
        # and how often", where thirteen masscan rows are two scanner builds.
        roll = {}
        for key, _rows, sev, where in graded:
            tool, cat, tname, _kind, _distro = key
            for text, (n, span, cols) in variants.get(key, {}).items():
                r = roll.get((tool, cat, text))
                if r is None:
                    r = roll[(tool, cat, text)] = {
                        "sev": SEVERITIES[-1], "n": 0, "span": ["", ""],
                        "tables": defaultdict(int), "cols": set(), "ctx": set()}
                if SEVERITIES.index(sev) < SEVERITIES.index(r["sev"]):
                    r["sev"] = sev
                r["n"] += n
                span_add(r["span"], span[0])
                span_add(r["span"], span[1])
                r["tables"][tname] += n
                r["cols"] |= cols
                r["ctx"].add(where)
        if roll:
            v = self.table("HACKTOOL_VARIANTS",
                           "Offensive tooling per distinct reference",
                           ["severity", "category", "tool", "detail", "count",
                            "first_utc", "last_utc", "tables", "where_seen",
                            "context", "tool_total"], "Detection",
                           "HACKTOOL_HITS rolled up to one row per exact "
                           "string a tool was named by, so two builds of one "
                           "scanner read as two lines rather than thirteen "
                           "near-identical ones. Every column but the last is "
                           "scoped to that one string: count is how often it "
                           "appeared across every table, first_utc and "
                           "last_utc are its own window, tables carries the "
                           "per-table split. tool_total is the only "
                           "whole-tool figure, kept so a variant can be read "
                           "against the tool it belongs to. Past %d distinct "
                           "strings for one tool in one table the tail folds "
                           "into a single '%s' row - the count there is "
                           "exact, the strings are not listed."
                           % (HACKTOOL_VARIANT_CAP, HACKTOOL_VARIANT_OTHER))
            # Grouped by tool, worst and busiest first, and the overflow
            # row last within its tool: it is a footnote about what was not
            # listed, and ranking it on its own count alone puts it at the
            # head of the whole table.
            for (tool, cat, text), r in sorted(
                    roll.items(),
                    key=lambda kv: (SEVERITIES.index(kv[1]["sev"]),
                                    -per_tool[(kv[0][0], kv[0][1])]["n"],
                                    kv[0][0], kv[0][1],
                                    kv[0][2] == HACKTOOL_VARIANT_OTHER,
                                    -kv[1]["n"], kv[0][2])):
                v.add(r["sev"], cat, tool, text, r["n"], r["span"][0],
                      r["span"][1],
                      "; ".join("%s x%d" % (nm, c) for nm, c in
                                sorted(r["tables"].items(),
                                       key=lambda i: (-i[1], i[0]))),
                      ", ".join(sorted(r["cols"])),
                      ", ".join(sorted(r["ctx"])),
                      per_tool[(tool, cat)]["n"])
        if len(t):
            status("[*] hacktools: %d reference(s) to %d distinct tool(s), "
                   "%d distinct reference string(s)"
                  % (len(t), len({k[0] for k in seen}), len(roll)))

    def _extra_keywords(self):
        """User-supplied terms from --keywords, compiled like the built-ins."""
        out = []
        for path in getattr(self.tri.opts, "keywords", None) or []:
            text = self._read_rule(path)
            if text is None:
                continue
            for line in text.splitlines():
                term = line.strip()
                if not term or term.startswith("#"):
                    continue
                try:
                    out.append((term, re.compile(r"(?<![\w.])%s(?![\w-])"
                                                 % re.escape(term), re.I)))
                except re.error as e:
                    self.rule_errors.append(("keywords", term, str(e)))
        return out

    def t_sigma(self):
        """Run Sigma rules over the normalised tables built above."""
        paths = getattr(self.tri.opts, "sigma", None)
        if not paths:
            return
        rules = []
        for path in self._rule_files(paths, (".yml", ".yaml")):
            text = self._read_rule(path)
            if text is None:
                continue
            got, errs = parse_sigma(text, lambda f: f.lower(), path)
            rules.extend(got)
            self.rule_errors.extend(("sigma", "%s: %s" % (path, n), e)
                                    for n, e in errs)
        t = self.table("SIGMA_MATCHES", "Sigma rule matches",
                       ["rule", "severity", "level", "table", "count",
                        "first_utc", "last_utc", "timestamp_utc",
                        "mitre", "matched_row", "description", "rule_id",
                        "rule_file"], "Detection",
                       "Rows of the normalised tables that satisfied a Sigma "
                       "rule given with --sigma. table names which artifact the "
                       "row came from, so the hit can be traced back to it. "
                       "timestamp_utc is the matched row's own time; count, "
                       "first_utc and last_utc describe the rule against that "
                       "table and repeat on each of its rows, matching the "
                       "finding raised for the pair. A rule that hits the "
                       "per-rule cap stops being evaluated, so its count and "
                       "span are a floor - the '(further matches suppressed)' "
                       "row is where that is said.")
        if not rules:
            return
        status("[*] sigma: %d rule(s) loaded" % len(rules))
        cov = self.table("SIGMA_COVERAGE", "Sigma rule coverage against this collection",
                         ["rule", "level", "product", "service_or_category",
                          "applicable", "why_not", "tables_checked",
                          "rows_matched", "rule_id", "rule_file"], "Detection",
                         "Every rule that loaded, and whether this collection "
                         "could have triggered it. A rule marked not applicable "
                         "produced no hits because there is nothing here for it "
                         "to read - that is not the same as a clean result, and "
                         "matters most when pointing this at a Windows Event Log "
                         "ruleset such as Hayabusa's or Chainsaw's.")
        by_name = {tb.name: tb for tb in self.tables}
        matched = 0

        # Route every rule to its tables first, then walk each table once with
        # the rules that target it. The obvious loop - rules outside, rows
        # inside - rebuilt a dict for every row for every rule, which on a real
        # SigmaHQ checkout is 400 rules x a million log rows of pure overhead.
        plan, cov_rows = {}, []
        for rule in rules:
            want = (rule.service or rule.category or "").lower()
            # A rule declaring a platform this export does not represent cannot
            # fire, and running it anyway invites a Windows process_creation
            # rule to match a Linux ps row through the field synonyms.
            product_ok = rule.product.lower() in ("", "linux", "unix")
            streams = [(tn, ts) for tn, svc, ts in self.SIGMA_STREAMS
                       if (not want or want in svc)
                       and by_name.get(tn) is not None and len(by_name[tn])]
            usable = []
            for tn, ts in streams if product_ok else []:
                if self._rule_can_hit(rule, set(str(c) for c in by_name[tn].columns)):
                    usable.append((tn, ts))
            why = ("" if usable else
                   "logsource product '%s' is not this collection" % rule.product
                   if not product_ok else
                   "no table here carries '%s' data" % (want or "that logsource")
                   if not streams else
                   "no table here has the fields this rule reads")
            for tn, ts in usable:
                plan.setdefault(tn, []).append((rule, ts))
            cov_rows.append([rule, bool(usable), why,
                             ", ".join(tn for tn, _ in usable), 0])
        idx = {id(c[0]): c for c in cov_rows}

        # rows, not tables: one table can be a million rows and the next forty,
        # so a per-table percentage sits at 3% for four minutes and then jumps
        total_rows = sum(len(by_name[tn]) for tn in plan) or 1
        sig_prog = Progress(total_rows, "sigma", self.progress.on,
                            parent=self.progress)
        seen_rows = 0
        for tname, entries in plan.items():
            tb = by_name[tname]
            cols = [str(c) for c in tb.columns]
            ncol = len(cols)
            sig_prog.step("%s (%d rule%s)" % (tname, len(entries),
                                              "" if len(entries) == 1 else "s"),
                          n=seen_rows)
            # Row-outer, rule-inner. Each row's dict is still built exactly
            # once and shared by every rule on the table - which was the point
            # of building them up front - but only one is alive at a time.
            # Materialising the whole table's dicts first meant 1.19M of them
            # for VAR_LOG, held on top of the rows they were built from, for as
            # long as the slowest rule took.
            #   [rule, ts index, service filter, kept samples, hits, stopped,
            #    span]
            #
            # A table-wide keyword prefilter was tried here and removed: one
            # alternation over the 49 keyword patterns of a table's gated rules
            # measured 153us per row against 101us for running those 49
            # searches separately, for identical results. Python's engine
            # optimises a small pattern with a literal prefix and cannot do
            # that for a 10KB alternation full of .* branches, so combining
            # them past a handful inverts the win. Alternation helps for many
            # short literals (the hacktool sweep); it hurts here.
            prepared = [[rule, cols.index(ts_col) if ts_col in cols else -1,
                         (self._service_filter(rule.service or rule.category)
                          if tname in self.SIGMA_MIXED_STREAMS else None),
                         [], 0, False, ["", ""]]
                        for rule, ts_col in entries]
            for rn, row in enumerate(tb.iter_rows()):
                if not rn & 0x3FFF:            # every 16k rows, not every row
                    sig_prog.step("%s (%d rule%s)"
                                  % (tname, len(entries),
                                     "" if len(entries) == 1 else "s"),
                                  n=seen_rows + rn)
                d = Row((cols[i], row[i]) for i in range(min(ncol, len(row)))
                        if row[i] not in (None, ""))
                live = False
                for e in prepared:
                    if e[5]:
                        continue
                    live = True
                    rule, ts_i, keep = e[0], e[1], e[2]
                    if keep is not None and not keep(d):
                        continue
                    if not rule.test(d):
                        continue
                    e[4] += 1
                    when = row[ts_i] if 0 <= ts_i < len(row) else ""
                    # spanned before the cap rather than from the kept samples,
                    # so the match that trips suppression is still inside the
                    # window. Past that the rule stops being evaluated at all -
                    # that is what the cap is for - so its count and span are a
                    # floor, and the '+' on the finding says so.
                    span_add(e[6], _ts_text(when))
                    if e[4] > 200:          # one noisy rule cannot flood
                        e[5] = True
                        continue
                    summary = self._sigma_summary(tname, d)
                    e[3].append((when, summary))
                if not live:                # every rule here has had its fill
                    break
            seen_rows += len(tb)
            for rule, _ts_i, _keep, kept, hits, stopped, span in prepared:
                for when, summary in kept:
                    t.add(rule.title, rule.severity, rule.level, tname,
                          hits, span[0], span[1], when,
                          rule.mitre, summary, rule.description, rule.id,
                          rule.source)
                if stopped:
                    t.add(rule.title, rule.severity, rule.level, tname,
                          hits, span[0], span[1], "",
                          rule.mitre, "(further matches suppressed)",
                          rule.description, rule.id, rule.source)
                if hits:
                    matched += hits
                    idx[id(rule)][4] += hits
                    self.tri.add(rule.severity, "Detection",
                                 "Sigma rule matched: %s" % rule.title,
                                 "%d%s row(s) in %s%s"
                                 % (hits, "+" if stopped else "", tname,
                                  " - " + rule.description if rule.description
                                  else ""),
                                 [s for _w, s in kept[-10:]],
                                 tname, rule.mitre,
                                 times=span, count=hits)
        sig_prog.done()
        applicable_n = sum(1 for c in cov_rows if c[1])
        for rule, ok, why, tables, hits in cov_rows:
            cov.add(rule.title, rule.level, rule.product or "",
                    rule.service or rule.category or "", "yes" if ok else "no",
                    why, tables, hits, rule.id, rule.source)
        status("[*] sigma: %d of %d rule(s) applicable to this collection, "
              "%d match row(s)" % (applicable_n, len(rules), matched))
        if applicable_n < len(rules):
            status("[*] sigma: %d rule(s) had no data here to read - see "
                  "SIGMA_COVERAGE" % (len(rules) - applicable_n))

    @staticmethod
    def _rule_can_hit(rule, cols):
        """Could this rule ever fire against a table with these columns?

        Skipping a table a rule cannot read is the difference between a run
        that finishes and one that does not, but a wrong skip is a missed
        detection - so this is exact rather than a heuristic. Each selection is
        satisfiable here only if some AND-group has every one of its matchers
        readable: a field the table carries, a keyword block, which reads the
        whole row, or a null test, which is satisfied by the field being
        absent.

        A satisfiable selection is then a free variable, not a true one.
        'sel and not filt' fires on the rows where filt happens not to match,
        so pinning a readable filt to true would prune a rule that does fire.
        The real question is satisfiability - is there any combination of
        outcomes for the readable selections that makes the condition true,
        with the unreadable ones pinned false - so the assignments are
        enumerated. That also protects 'not selection' rules, which fire
        precisely when nothing matches.
        """
        class _Stub:
            def __init__(self, v):
                self.v = v

            def test(self, _row):
                return self.v

        free = []
        pinned = {}
        for name, sel in rule.selections.items():
            can = False
            for grp in sel.groups:
                ok = True
                for mt in grp:
                    if isinstance(mt, Keywords):
                        continue                      # reads the whole row
                    if any(c in cols for c in mt.candidates):
                        continue
                    if any(x is None for x in getattr(mt, "tests", [])):
                        continue                      # 'field: null' wants absence
                    ok = False
                    break
                if ok:
                    can = True
                    break
            (free.append(name) if can else pinned.__setitem__(name, False))
        if len(free) > 12:                            # 4096 assignments is plenty
            return True
        try:
            for bits in range(1 << len(free)):
                env = dict(pinned)
                for i, name in enumerate(free):
                    env[name] = bool(bits & (1 << i))
                if eval_sigma(rule.cond,
                              {n: _Stub(v) for n, v in env.items()}, {}):
                    return True
            return False
        except Exception:
            return True                               # unsure means run it


    def t_pivot(self):
        """Where each --pivot indicator was seen, one row per hit."""
        t = self.table("IOC_HITS", "Indicator hits across the collection",
                       ["indicator", "ioc_type", "mitre", "count", "first_utc",
                        "last_utc", "artifact", "line_no", "line"],
                       "Detection",
                       "Every artifact mentioning a term given with --pivot "
                       "(or '@file' of them). Sort by indicator to follow one "
                       "IOC across process, network, log and filesystem "
                       "evidence; the same rows are the evidence on the "
                       "matching Pivot finding. count, first_utc and last_utc "
                       "describe the indicator as a whole and repeat on each "
                       "of its rows, so the table sorts by how often and how "
                       "recently a term was seen; they cover every hit, not "
                       "the sample kept as evidence. A row's own time is not "
                       "a separate column because the line it quotes already "
                       "carries its stamp where the artifact recorded one. "
                       "mitre is the technique implied by where the indicator "
                       "was picked up, and is empty for a term supplied on "
                       "the command line, which arrives with no such history.")
        stats = getattr(self.tri, "pivot_stats", {})
        iocs = getattr(self.tri, "iocs", {})
        for term, host, n, line in getattr(self.tri, "pivot_hits", []):
            cnt, first, last = stats.get(term, ("", "", ""))
            t.add(term, ioc_type(term), ioc_mitre(iocs.get(term)),
                  cnt, first, last, host, n, line)

    def t_rule_errors(self):
        """Rules that would not load, and why - the coverage you did not get."""
        t = self.table("RULE_ERRORS", "Detection rules that failed to load",
                       ["engine", "rule", "reason"], "Detection",
                       "A rule listed here was NOT applied. These engines are "
                       "subsets: anything they cannot represent faithfully is "
                       "rejected rather than half-matched, because a rule that "
                       "silently matches nothing looks like a clean result.")
        for engine, name, reason in self.rule_errors:
            t.add(engine, name, reason)

    def t_collection_errors(self):
        """UAC's per-command .stderr output.

        A missing artifact is ambiguous on its own: the tool was not installed,
        the command was denied, or the profile never ran it.  UAC writes the
        command's stderr beside the output file, which settles it - so "no
        firewall rules were collected" stops being read as "the firewall was
        empty".  Without this the .stderr files were the largest single block
        in UNPARSED_FILES, where they looked like a parser gap instead of the
        collection's own error log.
        """
        t = self.table("COLLECTION_ERRORS", "Commands that failed during collection",
                       ["artifact", "category", "message", "occurrences",
                        "first_line", "source"], "Collection",
                       "Why an artifact is absent or empty: the stderr UAC saved "
                       "for each command it ran. Identical messages are collapsed "
                       "with a count - one walk of a filesystem it could not read "
                       "produces thousands of the same line, and the count is the "
                       "useful part. Read beside UNPARSED_FILES and LOG_INVENTORY.")
        plen = len(self.col.prefix)
        for low, real in sorted(self.col._names.items(), key=lambda kv: kv[1]):
            if not low.startswith(self.col.prefix) or not low.endswith(".stderr"):
                continue
            rel = real[plen:]
            artifact = rel[:-len(".stderr")]
            parts = artifact.lstrip("/").split("/")
            cat = "/".join(parts[:-1]) or "collection"
            counts, first = defaultdict(int), {}
            for i, ln in enumerate(self.lines(rel, "COLLECTION_ERRORS"), 1):
                s = ln.rstrip()
                if not s.strip():
                    continue
                counts[s] += 1
                first.setdefault(s, i)
            for msg, n in sorted(counts.items(), key=lambda kv: first[kv[0]]):
                t.add(artifact, cat, msg, n, first[msg], rel)

    # Files a distribution ships as reference data: character maps, certificate
    # stores, AppArmor abstraction fragments, font and locale definitions.
    # They are collected because UAC copies /etc wholesale, not because anyone
    # is going to read them, and left undifferentiated they buried the handful
    # of rows in this table that are an actual parser gap. They are still
    # listed - just labelled, so the list can be sorted by reason and the top
    # of it is the part worth eyeballing.
    REFERENCE_DATA = (
        "/etc/apparmor.d/abstractions/", "/etc/apparmor.d/tunables/",
        "/etc/apparmor.d/abi/", "/etc/apparmor.d/cache/",
        "/etc/ssl/certs/", "/usr/share/ca-certificates/",
        "/etc/ca-certificates/", "/etc/pki/",
        "/etc/console-setup/", "/etc/fonts/", "/etc/locale.alias",
        "/etc/libibverbs.d/", "/etc/iproute2/", "/etc/logcheck/",
        "/etc/xml/", "/etc/sgml/", "/etc/terminfo/", "/etc/alternatives/",
        "/etc/cloud/templates/", "/etc/dpkg/origins/", "/etc/dpkg/shlibs",
        "/usr/share/dbus-1/interfaces/", "/usr/share/doc/",
        "/usr/share/man/", "/usr/share/i18n/",
        "/etc/vmware-tools/vgauth/schemas/", "/etc/apport/",
        "/etc/needrestart/", "/etc/sensors", "/etc/thermald/",
        "/etc/fwupd/", "/etc/OpenCL/", "/etc/UPower/", "/etc/PackageKit/",
        "/etc/update-manager/", "/etc/usb_modeswitch",
        "/boot/System.map", "/boot/config-", "/boot/initrd.img",
        # journald's message catalog, systemd's repart definitions, LVM's
        # metadata archive and dracut's module library: shipped data, not
        # anything this host's administrator or intruder chose
        "/usr/lib/systemd/catalog/", "/usr/lib/systemd/repart/",
        "/etc/lvm/", "/usr/lib/dracut/", "/lib/dracut/",
        "/etc/libblockdev/", "/etc/libnl-3/", "/etc/groff/", "/etc/byobu/",
        "/etc/sysstat/", "/etc/gnutls/", "/etc/smi.conf", "/etc/gprofng.rc",
        "/etc/bindresvport.blacklist", "/etc/udisks2/", "/etc/ucf.conf",
        "/etc/debconf.conf", "/etc/supercat/", "/etc/thermald/",
        "/etc/xdg/user-dirs", "/etc/locale.gen", "/etc/locale.conf",
        "/etc/ubuntu-advantage/", "/etc/sos/", "/etc/hdparm.conf",
        "/etc/magic", "/etc/mime.types", "/etc/mailcap", "/etc/manpath.config",
        "/etc/rpc", "/etc/services", "/etc/rmt", "/etc/newt/",
        "/etc/ca-certificates.conf", "/etc/popularity-contest.conf",
        "/etc/updatedb.conf", "/etc/calendar/", "/etc/emacs/site-lisp/",
        "/etc/samba/gdbcommands", "/etc/pollinate/", "/etc/opt/omi/ssl/",
        "/etc/vmware-tools/tools.conf.example", "/etc/dpkg/dpkg.cfg",
        # braille tables, X resource defaults, desktop entries, speech
        # synthesiser voices, font and Java trust config, GRUB's module
        # library and udev's per-device property cache
        "/etc/brltty/", "/etc/X11/app-defaults/", "/etc/X11/cursors/",
        "/etc/X11/fonts/", "/usr/share/applications/",
        "/etc/speech-dispatcher/", "/etc/ghostscript/", "/etc/java-",
        "/boot/grub/i386-pc/", "/boot/grub/x86_64-efi/",
        "/var/run/udev/data/", "/run/udev/data/",
        "/etc/openvpn/easy-rsa/pki/", "/etc/enchant/",
        # scanner backends, printer descriptions, image-library delegates,
        # font and paper tables: driver data shipped by a package
        "/etc/sane.d/", "/etc/cups/ppd/", "/etc/cupshelpers/",
        "/etc/imagemagick", "/etc/ImageMagick", "/etc/paperspecs",
        "/etc/timidity/", "/etc/openal/", "/etc/openni2/", "/etc/libao.conf",
        "/etc/vdpau_wrapper.cfg", "/etc/gtk-", "/etc/gnome/",
        "/etc/libreoffice/", "/etc/lynx/", "/etc/cracklib/",
        "/etc/X11/rgb.txt", "/etc/X11/XvMCConfig", "/etc/X11/xsm",
        "/etc/xdg/menus/", "/etc/xdg/kickoffrc", "/etc/xdg/kcm-",
        "/etc/reportbug.conf", "/etc/apt/listchanges.conf",
        "/etc/plymouth/", "/etc/rygel.conf", "/etc/firefox",
        "/etc/insserv.conf.d/", "/etc/pulse/",
        # the distribution's own archive signing keys; a key added by hand
        # would be an mtime outlier in BODYFILE, not a line in this table
        "/etc/apt/trusted.gpg", "/etc/apt/keyrings/",
        "/usr/share/keyrings/", "/etc/bogofilter",
    )
    # matched anywhere in the path, not as a prefix, because these sit under a
    # home directory whose name varies: editor and browser application state -
    # caches, leveldb journals, crash-reporter ids - rather than anything the
    # account holder or an intruder configured
    APP_STATE = ("/.config/code/", "/.config/vscode", "/.config/chromium/",
                 "/.config/google-chrome/", "/.config/microsoft-edge/",
                 "/.cache/", "/.local/share/trash/",
                 "/.config/enchant/", "/.config/go/telemetry/",
                 "/.mozilla/firefox/crashes/", "/.config/pulse/")
    # a checked-out repository is the tool's own source, not host evidence -
    # except the git metadata that dates the checkout, which BODYFILE has
    VENDORED = ("/.git/hooks/", "/.git/info/", "/site-packages/",
                "/node_modules/", "/impacket-env/", "/venv/", "/.venv/")

    def _unparsed_reason(self, host):
        low = host.lower()
        if any(s in low for s in self.VENDORED):
            return "vendored source tree, not host configuration"
        # compare lowercased on both sides: /etc/PackageKit and /etc/OpenCL are
        # mixed case on disk and matched nothing until this was symmetrical
        if any(low.startswith(p.lower()) for p in self.REFERENCE_DATA):
            return "distribution reference data"
        if any(s in low for s in self.APP_STATE):
            return "application state, not configuration"
        # /run is a tmpfs the kernel and daemons use as scratch: pid files,
        # lock files, sockets, udev's tag markers. It is collected because the
        # session and resolver state in it does matter - and those parts are
        # claimed by LIVE_SESSIONS and ETC_CONFIGS - but the rest is bookkeeping
        # that exists only until the next boot.
        if low.startswith(("/run/", "/var/run/")):
            return "runtime state (/run tmpfs)"
        # Under a narrowed scope this is the residue of the half that *was*
        # read, and it is not the same claim as a gap in the parser: the
        # `last`/`lastlog` command output sits in the live tree but is parsed
        # by the login extractors, which are offline. Saying 'no extractor'
        # here would report a scope decision as a missing feature.
        if self.scope != "full":
            return "no extractor in --scope %s (claimed under --scope full)" \
                % self.scope
        return "no extractor for this artifact"

    # -- Velociraptor results ----------------------------------------------
    # Tier 1 - the filesystem copy under uploads/ - needs nothing here: those
    # extractors ask Collection for host absolute paths and the layout is
    # already resolved beneath them. What follows is tier 2, the artifact
    # results, which have no UAC counterpart to reuse.
    #
    # Mapped artifacts append to the table the same evidence lands in under
    # UAC, so an analyst reads one SOCKETS table and not two. add_dict is used
    # throughout: these tables carry up to eighteen columns and a positional
    # row is one inserted column away from silently shifting every value.
    #
    # Names are listed with their known spellings rather than one canonical
    # form. The Exchange fork of an artifact is a different artifact name for
    # the same data, and matching only the upstream name would drop it.

    def _velo(self):
        return self.col.velo

    def _velo_claim(self, velo, artifacts, t):
        """Record a mapped artifact as read: coverage, provenance and inventory.

        All three, together. velo.claimed drives VELO_ARTIFACTS, t.sources names
        the evidence on the table, and self.consumed is what keeps the file out
        of UNPARSED_FILES - and only the last of those was being set by the
        passthrough, so under --scope offline an artifact that had genuinely
        fed PACKAGES was still reported as a file nothing read.
        """
        velo.claim(artifacts, t.name)
        for rel in velo.sources(*artifacts):
            self.use(rel, t.name)
            if rel not in t.sources:
                t.sources.append(rel)


    @staticmethod
    def _velo_addr(row, prefix):
        """('1.2.3.4', '443') from Laddr/Raddr, nested or flattened."""
        val = velo_get(row, prefix)
        if isinstance(val, dict):
            ip = velo_get(val, "IP", "Ip", "Address", "Addr")
            port = velo_get(val, "Port")
        else:
            ip = velo_get(row, prefix + ".IP", prefix + "IP", prefix + "_ip")
            port = velo_get(row, prefix + ".Port", prefix + "Port", prefix + "_port")
            if not ip and isinstance(val, str) and val:
                # 'ip:port', and IPv6 brings its own colons - rsplit, not split
                ip, _, port = val.rpartition(":")
                ip = ip.strip("[]") or val
        ip = str(ip) if ip not in (None, "") else ""
        port = str(port) if port not in (None, "") else ""
        return ip, "" if port == "0" else port

    # How netstat() spells 'no peer' - a listening socket has none, and a
    # 0.0.0.0:0 printed in the peer columns is an endpoint that never existed
    NO_PEER = ("", "0.0.0.0", "::", "[::]")

    VELO_SOCKET_ARTIFACTS = ("Linux.Network.Netstat", "Exchange.Linux.Network.Netstat",
                             "Generic.Network.Netstat", "Linux.Network.NetstatEnriched")

    def _velo_sockets(self, t):
        velo = self._velo()
        if not velo or not velo.has(*self.VELO_SOCKET_ARTIFACTS):
            return
        n = 0
        for rel, row in velo.rows(*self.VELO_SOCKET_ARTIFACTS):
            fam = str(velo_get(row, "Family", "FamilyString"))
            typ = str(velo_get(row, "Type", "TypeString", "Protocol")).lower()
            proto = typ or ("tcp" if "STREAM" in fam.upper() else "")
            if "6" in fam or "INET6" in fam.upper():
                proto += "6"
            la, lp = self._velo_addr(row, "Laddr")
            pa, pp = self._velo_addr(row, "Raddr")
            if pa in self.NO_PEER and not pp:
                pa = ""
            pid = str(velo_get(row, "Pid", "pid")).strip()
            proc = self.proc_of(pid) if pid.isdigit() else {}
            t.add_dict({
                "proto": proto,
                "state": velo_get(row, "Status", "State"),
                "local_addr": la, "local_port": lp,
                "peer_addr": pa, "peer_port": pp,
                "pid": pid,
                "process": velo_get(row, "Name", "Comm") or proc.get("name", ""),
                "exe": proc.get("exe", ""),
                "user": velo_get(row, "Username", "User") or proc.get("user", ""),
                "container": proc.get("container", ""),
                "source": os.path.basename(rel),
            })
            n += 1
        if n:
            self._velo_claim(velo, self.VELO_SOCKET_ARTIFACTS, t)

    VELO_SERVICE_ARTIFACTS = ("Linux.Sys.Services", "Linux.Systemd.Units",
                              "Exchange.Linux.Sys.Services")

    def _velo_services(self, t):
        velo = self._velo()
        if not velo or not velo.has(*self.VELO_SERVICE_ARTIFACTS):
            return
        n = 0
        for rel, row in velo.rows(*self.VELO_SERVICE_ARTIFACTS):
            unit = velo_get(row, "Unit", "Name", "Id", "Service")
            if not unit:
                continue
            t.add_dict({
                "unit": unit,
                "load": velo_get(row, "Load", "LoadState"),
                "active": velo_get(row, "Active", "ActiveState"),
                "sub": velo_get(row, "Sub", "SubState"),
                "state": velo_get(row, "State", "UnitFileState", "Enabled"),
                "description": velo_get(row, "Description", "Desc"),
                "source": os.path.basename(rel),
            })
            n += 1
        if n:
            self._velo_claim(velo, self.VELO_SERVICE_ARTIFACTS, t)

    VELO_CRON_ARTIFACTS = ("Linux.Sys.Crontab", "Linux.Persistence.Crontab",
                           "Exchange.Linux.Sys.Crontab")
    _VELO_CRON_FIELDS = ("Minute", "Hour", "DayOfMonth", "Month", "DayOfWeek")

    def _velo_cron(self, t):
        velo = self._velo()
        if not velo or not velo.has(*self.VELO_CRON_ARTIFACTS):
            return
        n = 0
        for rel, row in velo.rows(*self.VELO_CRON_ARTIFACTS):
            cmd = str(velo_get(row, "Command", "Cmd", "Line") or "").strip()
            if not cmd:
                continue
            sched = str(velo_get(row, "Schedule", "Spec", "Timespec") or "").strip()
            if not sched:
                parts = [str(velo_get(row, f)) for f in self._VELO_CRON_FIELDS]
                sched = " ".join(p for p in parts if p).strip()
            path = str(velo_get(row, "Path", "File", "Filename",
                                "OSPath", "_Source") or "").strip()
            t.add_dict({
                "file": path or os.path.basename(rel),
                "owner": velo_get(row, "Owner", "FileOwner"),
                "kind": "crontab",
                "schedule": sched,
                "run_as": velo_get(row, "User", "RunAs", "Username"),
                "command": cmd,
                # the join that turns 'would run' into 'is running'; it works
                # here for the same reason it works under UAC, because the
                # process table above it was populated either way
                "running_pids": self.running_pids_for(cmd),
                "line_no": velo_get(row, "Line", "LineNumber"),
            })
            n += 1
        if n:
            self._velo_claim(velo, self.VELO_CRON_ARTIFACTS, t)

    VELO_PACKAGE_ARTIFACTS = ("Linux.Debian.Packages", "Linux.LSB.Packages",
                              "Linux.RPM.Packages", "Linux.Sys.Packages",
                              "Exchange.Linux.Debian.Packages")

    def _velo_packages(self, t):
        velo = self._velo()
        if not velo or not velo.has(*self.VELO_PACKAGE_ARTIFACTS):
            return
        n = 0
        for rel, row in velo.rows(*self.VELO_PACKAGE_ARTIFACTS):
            name = velo_get(row, "Name", "Package")
            if not name:
                continue
            ver = str(velo_get(row, "Version", "Ver") or "")
            rev = str(velo_get(row, "Release", "Revision") or "")
            t.add_dict({
                "status": velo_get(row, "Status", "State"),
                "name": name,
                "version": "%s-%s" % (ver, rev) if ver and rev else (ver or rev),
                "architecture": velo_get(row, "Architecture", "Arch"),
                "description": velo_get(row, "Description", "Summary"),
                "source": os.path.basename(rel),
            })
            n += 1
        if n:
            self._velo_claim(velo, self.VELO_PACKAGE_ARTIFACTS, t)

    VELO_MODULE_ARTIFACTS = ("Linux.Proc.Modules", "Linux.Sys.Modules",
                             "Exchange.Linux.Proc.Modules")

    def _velo_modules(self, t):
        velo = self._velo()
        if not velo or not velo.has(*self.VELO_MODULE_ARTIFACTS):
            return
        n = 0
        for rel, row in velo.rows(*self.VELO_MODULE_ARTIFACTS):
            mod = velo_get(row, "Name", "Module")
            if not mod:
                continue
            used = velo_get(row, "UsedBy", "Used_by", "Dependencies")
            if isinstance(used, list):
                used = ",".join(str(u) for u in used)
            t.add_dict({
                "module": mod,
                "size": velo_get(row, "Size", "ModuleSize"),
                "used_by_count": velo_get(row, "UseCount", "RefCount", "Instances"),
                "used_by": used,
                "filename": velo_get(row, "Path", "FileName", "OSPath"),
                "source": os.path.basename(rel),
            })
            n += 1
        if n:
            self._velo_claim(velo, self.VELO_MODULE_ARTIFACTS, t)

    VELO_SYSINFO_ARTIFACTS = ("Generic.Client.Info", "Generic.Client.Info/BasicInformation",
                              "Linux.Sys.Uname", "Linux.Sys.Uptime", "Linux.Sys.Hostname")

    def _velo_system_info(self, t):
        """Flatten the host-state artifacts into SYSTEM_INFO's line shape."""
        velo = self._velo()
        if not velo or not velo.has(*self.VELO_SYSINFO_ARTIFACTS):
            return
        n = 0
        seen = {}
        for rel, row in velo.rows(*self.VELO_SYSINFO_ARTIFACTS):
            label = os.path.basename(rel)
            for k, v in row.items():
                if v in (None, "", [], {}):
                    continue
                # numbered across the file, not restarted per row: two rows of
                # the same artifact would otherwise both claim line 1
                seen[label] = seen.get(label, 0) + 1
                t.add_dict({"source": label, "line_no": seen[label],
                            "text": "%s: %s" % (k, _velo_cell(v))})
                n += 1
        if n:
            self._velo_claim(velo, self.VELO_SYSINFO_ARTIFACTS, t)

    def t_velo_uploads(self):
        """uploads.json - what Velociraptor copied, with the hashes it took."""
        velo = self._velo()
        if not velo or not self.col.exists("uploads.json"):
            return
        t = self.table("VELO_UPLOADS", "Files Velociraptor uploaded",
                       ["host_path", "stored_at", "accessor", "size_bytes",
                        "size_human", "stored_size", "md5", "sha256", "type"],
                       "Collection",
                       "Velociraptor's own manifest of the filesystem copy. The "
                       "hashes are taken by the collector on the live host, so "
                       "they are the pre-transfer value: a mismatch against the "
                       "stored file is evidence about the collection, not about "
                       "the host.", ["uploads.json"])
        self.use("uploads.json", "VELO_UPLOADS")
        for ln in self.col.iter_lines("uploads.json"):
            if not ln.strip():
                continue
            try:
                row = json.loads(ln)
            except ValueError:
                continue
            if not isinstance(row, dict):
                continue
            stored = str(velo_get(row, "vfs_path", "VFSPath", "StoredName") or "")
            size = velo_get(row, "file_size", "Size", "expected_size", default="")
            t.add_dict({
                "host_path": velo_get(row, "OSPath", "Path", "file_name", "Name"),
                "stored_at": stored,
                "accessor": velo_get(row, "Accessor", "accessor")
                            or (stored.split("/")[1] if stored.count("/") >= 1 else ""),
                "size_bytes": size,
                "size_human": human_size(size),
                "stored_size": velo_get(row, "uploaded_size", "StoredSize", default=""),
                "md5": velo_get(row, "Md5", "md5", "MD5"),
                "sha256": velo_get(row, "Sha256", "sha256", "SHA256"),
                "type": velo_get(row, "Type", "type"),
            })

    # Bookkeeping files that are about the collection rather than the host.
    # Named so UNPARSED_FILES classifies them instead of counting them as
    # artifacts nothing understood.
    VELO_BOOKKEEPING = ("collection_context.json", "log.json", "logs.json",
                        "uploads.json", "requests.json", "metadata.json")

    # Which mapped artifact set is fed by which extractor. Kept as one list so
    # --scope and the coverage table read the same mapping the appenders use;
    # two copies of this would drift and the drift would show up as a table
    # quietly reappearing under a scope that excluded it.
    @property
    def VELO_MAPPED(self):
        return (
            (Triage.VELO_PROCESS_ARTIFACTS, "t_processes"),
            (self.VELO_SOCKET_ARTIFACTS, "t_sockets"),
            (self.VELO_SERVICE_ARTIFACTS, "t_services"),
            (self.VELO_CRON_ARTIFACTS, "t_cron"),
            (self.VELO_PACKAGE_ARTIFACTS, "t_packages"),
            (self.VELO_MODULE_ARTIFACTS, "t_modules"),
            (self.VELO_SYSINFO_ARTIFACTS, "t_system_info"),
        )

    def t_velo_results(self):
        """Every artifact result no mapped extractor took, as its own table.

        This is the half of Velociraptor support that cannot be enumerated in
        advance: the artifact set belongs to whoever built the collector, and a
        parser that only understood a fixed list would drop a custom detection
        artifact - exactly the row an analyst added the artifact to see. The
        passthrough is deliberately dumb: one column per JSON key, in the order
        the rows use them, nested values rendered as compact JSON.
        """
        velo = self._velo()
        if not velo:
            return
        for rel in self.col.glob("results/**"):
            if rel.lower().endswith(VelociraptorResults.SIDECAR_EXTS):
                self.use(rel, "VELO_ARTIFACTS")     # seek index, no evidence
        # An artifact whose mapped extractor was skipped by --scope has not
        # been read, and passing it through here would put a table back that
        # the scope was asked to leave out.
        skipped = set()
        for artifacts, fname in self.VELO_MAPPED:
            if not self.in_scope(fname, self.scope):
                skipped.update(velo.sources(*artifacts))
        used = set()
        for rel in velo.files:
            if rel in velo.claimed:
                self.use(rel, velo.claimed[rel])
                continue
            if rel in skipped:
                velo.claimed[rel] = "not read under --scope %s" % self.scope
                self.consumed[rel.lstrip("/").lower()] = velo.claimed[rel]
                continue
            name = velo.names.get(rel, rel)
            # two streaming passes, not one materialised list: the columns have
            # to be known before the table exists, and a file-finder result over
            # a whole disk is large enough that holding the rows and the table
            # at once is the difference between running and not. Re-reading a
            # zip member costs a second decompress, which is the cheaper half.
            cols = []
            for _r, row in velo.rows_of(rel):
                for k in row:
                    k = str(k)
                    if k not in cols:
                        cols.append(k)
            if not cols:
                self.consumed[rel.lstrip("/").lower()] = "VELO_ARTIFACTS (no rows)"
                continue
            tname = _velo_table_name(name, used)
            used.add(tname)
            t = self.table(tname, "Velociraptor: %s" % name, cols, "Velociraptor",
                           "Rows from the %s artifact, passed through unmapped - "
                           "this parser has no normalisation for it, so the "
                           "artifact's own columns are kept verbatim." % name,
                           [rel])
            for _r, row in velo.rows_of(rel):
                t.add_dict({str(k): _velo_cell(v) for k, v in row.items()})
            self.consumed[rel.lstrip("/").lower()] = tname
            velo.claimed[rel] = tname

    def t_velo_artifacts(self):
        """One row per artifact in the collection and where its rows went.

        The point of this table is the 'no mapping for this artifact' case. A
        collection can only be read as complete if the artifacts it does not
        cover are visible, and an absent table is not visible.
        """
        velo = self._velo()
        if not velo:
            return
        t = self.table("VELO_ARTIFACTS", "Velociraptor artifacts in this collection",
                       ["artifact", "result_file", "rows", "unreadable_rows",
                        "parsed_into", "coverage"], "Collection",
                       "Every artifact result file, its row count and the table "
                       "it fed. coverage reads 'normalised' when the rows were "
                       "merged into this parser's own table, 'passed through' "
                       "when the artifact has no mapping and kept its own "
                       "columns, 'empty' when the artifact ran and returned "
                       "nothing - which is a fact about the host, not a gap - "
                       "and 'not read' when this run never opened the file, "
                       "which is neither. An empty rows cell means not counted; "
                       "a 0 means counted and there were none.")
        # which mapped extractors --scope left out, and whether the passthrough
        # itself ran, so an artifact nobody opened can say so by name
        skipped = {}
        for artifacts, fname in self.VELO_MAPPED:
            if not self.in_scope(fname, self.scope):
                for rel in velo.sources(*artifacts):
                    skipped[rel] = fname
        passthrough = self.in_scope("t_velo_results", self.scope)
        for rel in velo.files:
            into = velo.claimed.get(rel, "")
            # None, not 0: an artifact this run never opened has no row count,
            # and reporting it as zero rows says the host had none of that -
            # which is the one answer a coverage table must never invent
            rows = velo.counts.get(rel)
            if into.startswith("not read under"):
                cov = into
            elif rows is None:
                if rel in skipped:
                    cov = "not read - %s not run under --scope %s" % (
                        skipped[rel], self.scope)
                elif not passthrough:
                    cov = "not read - passthrough not run under --scope %s" % self.scope
                else:
                    cov = "not read"
                into = into or cov
            elif not rows:
                cov = "empty - artifact ran and returned no rows"
            elif into.startswith("VELO_"):
                cov = "passed through - no mapping for this artifact"
            elif into:
                cov = "normalised into this parser's table"
            else:
                # findings, the timeline and the IOC list run over the whole
                # collection whatever --scope says, so rows can be read and
                # used without any table claiming them
                cov = "read by the analyzers - no table claimed the rows"
            t.add_dict({"artifact": velo.names.get(rel, rel), "result_file": rel,
                        "rows": "" if rows is None else rows,
                        "unreadable_rows": velo.bad_rows.get(rel, 0),
                        "parsed_into": into, "coverage": cov})

    def t_unparsed(self):
        """Anything no extractor claimed - so 'every file' really means every file."""
        t = self.table("UNPARSED_FILES", "Files no extractor claimed",
                       ["path", "size_bytes", "size_human", "reason", "preview"],
                       "Collection",
                       "Review these by hand; nothing here was silently dropped. "
                       "Sort by reason: 'no extractor for this artifact' is the "
                       "genuine residue, the other reasons are files that were "
                       "classified rather than parsed. Under --scope live or "
                       "--scope offline the other half of the collection is "
                       "listed as out of scope, not as a parser gap.")
        plen = len(self.col.prefix)
        binary_ext = (".gz", ".xz", ".bz2", ".zst", ".zip", ".tar", ".lz4", ".db",
                      ".journal", ".so", ".ko", ".png", ".jpg", ".gif", ".pdf",
                      ".bin", ".img", ".raw", ".core", ".lz")
        for low, real in sorted(self.col._names.items(), key=lambda kv: kv[1]):
            if not low.startswith(self.col.prefix):
                continue
            rel = real[plen:]
            if rel.lstrip("/").lower() in self.consumed:
                continue
            size = self.col._sizes.get(low, 0)
            host = self.col.host_path(rel)
            lower = rel.lower()
            # a narrowed run did not look at the other half of the collection;
            # say that, rather than blaming an extractor that was never called
            if self.scope != "full":
                ps = self.path_scope(rel, host)
                if ps and ps != self.scope:
                    t.add(host or rel, size, human_size(size),
                          "not read under --scope %s" % self.scope, "")
                    continue
            # a zero-length file has no content to parse, and the fact that it
            # is empty is the whole of what it says - most of them are marker
            # or lock files whose existence is the signal
            if size == 0:
                t.add(host or rel, size, human_size(size), "zero length", "")
                continue
            if lower.endswith(binary_ext):
                t.add(host or rel, size, human_size(size), "compressed or binary", "")
                continue
            if size > 2 * 1024 * 1024:
                t.add(host or rel, size, human_size(size), "too large to preview", "")
                continue
            raw = self.col.read_bytes(rel, 4096) or b""
            if b"\x00" in raw:
                t.add(host or rel, size, human_size(size), "binary content", "")
                continue
            preview = raw.decode("utf-8", "replace").strip()
            preview = " / ".join(preview.splitlines()[:3])
            t.add(host or rel, size, human_size(size),
                  self._unparsed_reason(host or rel), trunc(preview, 400))

    # -- driver -------------------------------------------------------------
    EXTRACTORS = [
        "t_metadata", "t_collection_log",
        "t_processes", "t_ps_raw", "t_proc_pid", "t_proc_maps", "t_proc_environ",
        "t_proc_fds", "t_process_master", "t_process_tree",
        "t_process_tree_raw", "t_process_hashes",
        "t_hidden_pids",
        "t_open_files",
        "t_sockets", "t_netstat", "t_proc_net", "t_interfaces", "t_routes",
        "t_arp", "t_network_config", "t_unix_sockets", "t_firewall",
        "t_modules", "t_sysctl", "t_services", "t_timers", "t_dmesg",
        "t_system_info", "t_env", "t_hardware", "t_storage", "t_storage_raw",
        "t_mounts",
        "t_device_profile",
        "t_users", "t_groups", "t_sudoers", "t_logins", "t_auth_events",
        "t_failed_logins", "t_privilege_activity", "t_ssh",
        "t_remote_access", "t_memory_output",
        "t_cron", "t_systemd_units", "t_init_scripts", "t_history",
        "t_editor_history", "t_ld_preload",
        "t_suid", "t_getcap", "t_mac_policy",
        "t_writable", "t_hidden_files", "t_unknown_owner",
        "t_socket_files",
        "t_dev_files", "t_bodyfile", "t_file_hashes",
        "t_user_artifacts",
        "t_packages", "t_package_logs", "t_chkrootkit",
        # /var/log: the binary stores first, then the text logs
        "t_journal", "t_audit_log", "t_login_records", "t_wtmpdb", "t_lastlog",
        "t_live_sessions",
        # the application logs FOR577 calls out, before the catch-all
        "t_web_logs", "t_web_config", "t_samba_logs", "t_firewall_log",
        "t_var_log", "t_app_logs",
        "t_containers",
        "t_log_config", "t_log_inventory", "t_etc_configs",
        # Velociraptor: the manifest of the filesystem copy, then every artifact
        # result no mapped extractor above took. Both must precede the rule
        # engines, because a passed-through artifact is a table and Sigma runs
        # over tables - ordering them after would hide a custom detection
        # artifact from the rules the analyst added it for.
        "t_velo_uploads", "t_velo_results", "t_velo_artifacts",
        # Detection rules run over the artifacts and the tables above, and add
        # to the finding list - so they must come before the three derived
        # views, which are snapshots of that list rather than artifacts in
        # their own right. Ordering them the other way silently dropped every
        # rule hit out of FINDINGS and the console report.
        "t_hacktools", "t_yara", "t_sigma", "t_pivot", "t_rule_errors",
        "t_findings", "t_timeline", "t_iocs",
        # why an artifact above is absent, before the list of what is left
        "t_collection_errors",
        "t_unparsed",          # must stay last: it reports on everything above
    ]

    # --scope splits the extractors by where their evidence came from, not by
    # what it is about.
    #
    #   live    - state that existed only while the host was running: the
    #             process table, open sockets and files, loaded modules, the
    #             live session list. UAC captured it by running commands, and
    #             no disk image contains it.
    #   offline - what a dead-box examination recovers: the filesystem copy,
    #             its configuration, its logs, its timeline.
    #
    # The filesystem surveys - suid/sgid, getcap, the writable and hidden
    # lists, the bodyfile, the executable hashes - are produced by UAC running
    # find on the live host, so by capture method they are 'live'. They are
    # classified offline anyway, because what they describe is disk state and
    # an examiner reaching for them is doing disk work. Capture method is a
    # fact about UAC; the scope is a statement about the investigation.
    #
    # chkrootkit is the reverse case: its output is about the filesystem, but
    # it is a scanner's verdict at one moment on a running host, so it is live.
    #
    # Anything not named below runs in every scope. That covers two kinds:
    # collection accounting (METADATA, COLLECTION_LOG, COLLECTION_ERRORS,
    # UNPARSED_FILES) and derived views (FINDINGS, TIMELINE, IOCS), plus the
    # handful of tables that genuinely merge both sides - FIREWALL holds the
    # running ruleset and the saved rules file, PACKAGES the dpkg output and
    # the dpkg database, MOUNTS the mount command and fstab. Those keep both
    # halves in a narrow scope: --scope chooses tables, never lines within one.
    # Defaulting an untagged extractor to 'runs everywhere' is deliberate - a
    # new extractor someone forgets to tag shows up in too many scopes, which
    # is visible, rather than silently vanishing from all of them.
    LIVE_EXTRACTORS = frozenset((
        "t_processes", "t_ps_raw", "t_proc_pid", "t_proc_maps", "t_proc_environ",
        "t_proc_fds", "t_process_master", "t_process_tree",
        "t_process_tree_raw", "t_process_hashes",
        "t_hidden_pids", "t_open_files",
        "t_sockets", "t_netstat", "t_proc_net", "t_unix_sockets",
        "t_interfaces", "t_routes", "t_arp",
        "t_modules", "t_sysctl", "t_services", "t_timers",
        "t_system_info", "t_env", "t_hardware", "t_storage_raw",
        "t_live_sessions", "t_memory_output", "t_chkrootkit",
        # Velociraptor artifact results are the volatile snapshot in the same
        # sense live_response is: a command run against the running host.
        "t_velo_results",
    ))
    OFFLINE_EXTRACTORS = frozenset((
        "t_users", "t_groups", "t_sudoers", "t_logins", "t_auth_events",
        "t_failed_logins", "t_privilege_activity", "t_ssh", "t_remote_access",
        "t_cron", "t_systemd_units", "t_init_scripts", "t_history",
        "t_editor_history", "t_ld_preload",
        "t_suid", "t_getcap", "t_mac_policy", "t_writable", "t_hidden_files",
        "t_unknown_owner", "t_socket_files", "t_dev_files", "t_bodyfile",
        "t_file_hashes", "t_user_artifacts", "t_package_logs",
        "t_journal", "t_audit_log", "t_login_records", "t_wtmpdb", "t_lastlog",
        "t_web_logs", "t_web_config", "t_samba_logs", "t_firewall_log",
        "t_var_log", "t_app_logs",
        "t_log_config", "t_log_inventory", "t_etc_configs",
        # uploads.json describes the filesystem copy, so it belongs to the half
        # of the collection a dead-box examination would have
        "t_velo_uploads",
    ))
    SCOPES = ("full", "live", "offline")

    def in_scope(self, fname, scope):
        if scope == "live":
            return fname not in self.OFFLINE_EXTRACTORS
        if scope == "offline":
            return fname not in self.LIVE_EXTRACTORS
        return True

    # The same split expressed as collection paths, for UNPARSED_FILES. Under a
    # narrowed scope the files an unrun extractor would have taken are still
    # unclaimed, and reporting them as 'no extractor for this artifact' would
    # be a lie about the parser rather than a fact about the run.
    LIVE_TREES = ("live_response/", "memory_dump/", "chkrootkit/", "results/")
    LIVE_ROOTFS = ("/proc/", "/run/", "/var/run/")
    ALWAYS_READ = ("uac.log", "collection_context.json", "log.json", "logs.json",
                   "uploads.json", "requests.json", "metadata.json")

    def path_scope(self, rel, host):
        """'live', 'offline' or '' for a collected path."""
        low = rel.lstrip("/").lower()
        if low.startswith(self.ALWAYS_READ) or low.endswith(".stderr"):
            return ""                      # collection accounting, always read
        if low.startswith(self.LIVE_TREES):
            return "live"
        if host.startswith(self.LIVE_ROOTFS):
            return "live"
        return "offline"

    def build(self, keep_empty=False, verbose=True, only=None, scope="full"):
        self.scope = scope
        names = [f for f in (only or self.EXTRACTORS)
                 if only or self.in_scope(f, scope)]
        self.progress = Progress(len(names), "building tables", verbose)
        for fname in names:
            self.progress.step(fname.replace("t_", ""))
            before = len(self.tables)
            t0 = time.perf_counter()
            try:
                getattr(self, fname)()
                self.timings.append((fname, time.perf_counter() - t0,
                                     sum(len(t) for t in self.tables[before:])))
            except Exception as exc:
                if self.tri.opts.debug:
                    raise
                # always reported, even under --quiet: a silently missing table
                # reads as "this host had none of that", which is a wrong answer
                status("[!] table extractor %s failed: %s" % (fname, exc))
                del self.tables[before:]
        if only:
            self.progress.done()
            if not keep_empty:
                self.tables = [t for t in self.tables if len(t)]
            return self.tables
        # FILE_INVENTORY is built from self.consumed, so it runs after everything
        try:
            self.t_file_inventory()
        except Exception as exc:
            if self.tri.opts.debug:
                raise
            status("[!] table extractor t_file_inventory failed: %s" % exc)
        self.progress.done()
        if not keep_empty:
            self.tables = [t for t in self.tables if len(t)]
        return self.tables


def human_size(n):
    try:
        n = float(n)
    except (TypeError, ValueError):
        return ""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return "%.0f %s" % (n, unit) if unit == "B" else "%.1f %s" % (n, unit)
        n /= 1024.0
    return ""


# ---------------------------------------------------------------------------
# table writers: CSV, JSON, HTML browser
# ---------------------------------------------------------------------------

def write_tables_csv(tables, dirpath):
    os.makedirs(dirpath, exist_ok=True)
    index = os.path.join(dirpath, "00_INDEX.csv")
    with open(index, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh)
        w.writerow(["table", "title", "category", "rows", "columns", "csv_file",
                    "description"])
        for t in tables:
            w.writerow([t.name, t.title, t.category, len(t), len(t.columns),
                        t.name + ".csv", t.description])
    for t in tables:
        path = os.path.join(dirpath, t.name + ".csv")
        with open(path, "w", newline="", encoding="utf-8-sig") as fh:
            w = csv.writer(fh)
            w.writerow(t.columns)
            for row in t.iter_rows():
                w.writerow([_s(v) for v in row])
    return len(tables) + 1


def _table_json_body(t, fh):
    """One table as a JSON object, streamed row by row.

    Never json.dumps the whole table: BODYFILE and the log tables run to
    hundreds of thousands of rows, and building the string first doubles the
    peak for no benefit when the rows are written once and never re-read.
    """
    fh.write('{\n "name": %s,\n "title": %s,\n "category": %s,\n'
             % (json.dumps(t.name), json.dumps(t.title), json.dumps(t.category)))
    fh.write(' "description": %s,\n' % json.dumps(t.description))
    fh.write(' "sources": %s,\n' % json.dumps(t.sources))
    fh.write(' "columns": %s,\n' % json.dumps(t.columns))
    fh.write(' "row_count": %d,\n "rows": [' % len(t))
    for j, row in enumerate(t.iter_rows()):
        fh.write("%s%s" % ("," if j else "", json.dumps([_s(v) for v in row])))
    fh.write("]\n}\n")


# Columns a table may carry its event time in, best first.
NDJSON_TIME_COLUMNS = ("timestamp_utc", "timestamp", "start_utc",
                       "last_utc", "first_utc")

# Context added to every event. Prefixed because the row's own fields win and
# must: SIGMA_MATCHES and HACKTOOL_HITS both have a column literally called
# 'table', and an unprefixed context field would overwrite the evidence with
# the name of the file it came from.
NDJSON_PREFIX = "triage_"


def _epoch_utc(text):
    """'2026-08-17 09:41:02' or ISO8601 -> epoch seconds, or None.

    Splunk takes _time as epoch. Emitting it beats leaving Splunk to guess from
    the raw line, which on a row whose first field is a pid picks up a number
    that is not a time at all.
    """
    s = str(text or "").strip()
    if not s:
        return None
    s = s.replace("T", " ").replace("Z", "").split("+")[0].split(".")[0].strip()
    try:
        dt = datetime.strptime(s[:19], "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None
    return dt.replace(tzinfo=timezone.utc).timestamp()


def write_tables_ndjson(tables, dirpath, meta=None):
    """One JSON object per row - newline-delimited, one file per table.

    A self-describing JSON document per table cannot be ingested by Splunk (or
    anything else that reads a line at a time): the whole table is one event,
    the rows array runs to 43 MB on a single line for BODYFILE against a
    default TRUNCATE of 10,000 bytes, and positional row arrays leave every
    field unnamed. One object per line fixes all three, and the per-table
    metadata that the document used to carry moves to 00_INDEX.json.

    Empty values are omitted rather than written as "": an absent field costs
    nothing to search and keeps the events small, which is the convention every
    log platform expects.
    """
    os.makedirs(dirpath, exist_ok=True)
    meta = meta or {}
    ctx = {}
    for key, val in ((NDJSON_PREFIX + "host", meta.get("hostname")),
                     (NDJSON_PREFIX + "collected", meta.get("collected")),
                     (NDJSON_PREFIX + "collection",
                      os.path.basename(str(meta.get("collection") or ""))),
                     (NDJSON_PREFIX + "layout", meta.get("layout"))):
        if val:
            ctx[key] = val

    index = [{"name": t.name, "title": t.title, "category": t.category,
              "rows": len(t), "columns": t.columns, "description": t.description,
              "sources": t.sources, "ndjson_file": t.name + ".ndjson"}
             for t in tables]
    with open(os.path.join(dirpath, "00_INDEX.json"), "w", encoding="utf-8") as fh:
        json.dump({"tool": "linsight.py", "version": VERSION,
                   "generated_from": meta, "tables": index}, fh, indent=1)

    for t in tables:
        cols = [str(c) for c in t.columns]
        ncol = len(cols)
        ti = next((cols.index(c) for c in NDJSON_TIME_COLUMNS if c in cols), -1)
        path = os.path.join(dirpath, t.name + ".ndjson")
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            for row in t.iter_rows():
                ev = {NDJSON_PREFIX + "table": t.name}
                ev.update(ctx)
                for i in range(min(ncol, len(row))):
                    v = row[i]
                    if v not in (None, ""):
                        ev[cols[i]] = _s(v)
                if 0 <= ti < len(row):
                    epoch = _epoch_utc(row[ti])
                    if epoch is not None:
                        ev["_time"] = epoch
                fh.write(json.dumps(ev, ensure_ascii=False,
                                    separators=(",", ":"), default=str) + "\n")
    return len(tables) + 1


def write_tables_json(tables, path, meta=None):
    """Streamed - the bodyfile table alone can be a couple of hundred thousand rows."""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write('{\n"tool": "linsight.py",\n"version": %s,\n' % json.dumps(VERSION))
        fh.write('"generated_from": %s,\n' % json.dumps(meta or {}))
        fh.write('"index": %s,\n' % json.dumps(
            [{"name": t.name, "title": t.title, "category": t.category,
              "rows": len(t), "columns": t.columns, "description": t.description}
             for t in tables], indent=1))
        fh.write('"tables": {\n')
        for i, t in enumerate(tables):
            fh.write("%s%s: {\n" % (",\n" if i else "", json.dumps(t.name)))
            fh.write('  "title": %s,\n  "category": %s,\n  "description": %s,\n'
                     % (json.dumps(t.title), json.dumps(t.category),
                        json.dumps(t.description)))
            fh.write('  "sources": %s,\n' % json.dumps(t.sources))
            fh.write('  "columns": %s,\n' % json.dumps(t.columns))
            fh.write('  "row_count": %d,\n  "rows": [' % len(t))
            for j, row in enumerate(t.iter_rows()):
                fh.write("%s%s" % ("," if j else "",
                                   json.dumps([_s(v) for v in row])))
            fh.write("]\n }")
        fh.write("\n}\n}\n")


# -- HTML browser ------------------------------------------------------------


def _script_json(obj):
    """JSON safe to embed inside a <script> element.

    json.dumps leaves '<' alone, so a cell containing '</script>' closes the
    script early and the rest of the payload is parsed as HTML: the page ends
    up with dozens of script elements, __TABLES__ never gets assigned and the
    browser renders an empty shell. A forensic export is exactly the input that
    hits this - the collection had a saved GitHub page sitting in /etc/php, and
    the artifact tables carry web content, log lines and shell history verbatim
    by design.

    Escaping every '<' as \\u003c is still valid JSON (the parser decodes it
    back to '<') and removes the whole class of hazard at once: </script>,
    <!-- and <script all stop being HTML tokens. '<' only ever appears inside
    string values here, so nothing structural is touched.
    """
    return json.dumps(obj).replace("<", "\\u003c")


def write_tables_html(tables, path, html_cap=2000, meta=None, tri=None,
                      opts=None):
    """The console: triage views and every artifact table in one page.

    Self-contained by design - no server, no CDN, no fetch. The box that reads
    a triage collection is routinely the box that is not allowed to fetch
    anything, so the payload is embedded and the CSS and JS are inline.

    `tri` is optional: without it the page is the artifact browser alone, which
    is what a single-table export (--process-map p.html) should still produce.
    """
    esc = htmllib.escape
    index, tbls = [], {}
    for t in tables:
        index.append({"name": t.name, "title": t.title,
                      "category": t.category or "Other", "rows": len(t)})
        d = t.as_dict(limit=html_cap)
        d["cap"] = 500          # rows rendered at once in the DOM
        tbls[t.name] = d

    payload = {"meta": [], "counts": {s: 0 for s in SEVERITIES}, "findings": [],
               "events": [], "iocs": [], "names": {}, "tactics": {},
               "order": ATTACK_ORDER, "version": VERSION,
               "index": index, "tables": tbls}
    if tri is not None:
        payload.update(_triage_payload(tri, opts))
    elif meta:
        payload["meta"] = [[k, str(v)] for k, v in meta.items() if v]

    host = (tri.meta.get("Hostname") if tri is not None else None) or            (meta or {}).get("Hostname") or "collection"
    src = tri.col.path if tri is not None else (meta or {}).get("Collection", "")

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("<!doctype html><html><head><meta charset='utf-8'>"
                 "<meta name='viewport' content='width=device-width,initial-scale=1'>"
                 "<title>linsight - %s</title><style>%s</style></head><body>"
                 % (esc(str(host)), APP_CSS))
        fh.write("<header><div class='brand'><b>linsight</b>"
                 "<span>PARSE LINUX DEEP. HUNT THE MALICIOUS.</span></div>"
                 "<div class='host'><b>%s</b> &nbsp;<code>%s</code></div>"
                 "<div class='chips' id='chips'></div></header>"
                 % (esc(str(host)), esc(str(src))))
        fh.write("<div class='layout'><nav id='nav'></nav>"
                 "<main id='main'></main></div>")
        fh.write("<script>window.__LINSIGHT__=%s;</script>" % _script_json(payload))
        fh.write("<script>%s</script></body></html>" % APP_JS)


def write_single_table(table, path, html_cap=100000):
    """Write one table to one file; the format follows the extension."""
    ext = os.path.splitext(path)[1].lower()
    if ext == ".json":
        write_tables_json([table], path)
    elif ext in (".html", ".htm"):
        write_tables_html([table], path, html_cap)
    else:
        with open(path, "w", newline="", encoding="utf-8-sig") as fh:
            w = csv.writer(fh)
            w.writerow(table.columns)
            for row in table.iter_rows():
                w.writerow([_s(v) for v in row])
    return ext or ".csv"


def _check_output_paths(col, opts):
    """Never write output into the evidence.

    It contaminates the collection, and the next run would then parse the
    previous run's own tables back in as artifacts.
    """
    if col.kind != "dir":
        return
    base = os.path.abspath(col.path)
    for path in (opts.export, opts.csv_dir, opts.tables_json, opts.tables_html,
                 opts.json, opts.html, opts.timeline, opts.process_map):
        if not path:
            continue
        full = os.path.abspath(path)
        if full == base or full.startswith(base + os.sep):
            raise SystemExit(
                "[!] refusing to write inside the collection:\n"
                "      %s\n"
                "    output would become part of the evidence - choose a path "
                "outside\n      %s" % (full, base))


def export_tables(tri, col, opts, tb=None):
    """Build every table once, then write whichever formats were requested."""
    _check_output_paths(col, opts)          # fail before a minute of parsing
    prebuilt = tb is not None
    tb = tb or TableBuilder(col, tri)

    # --process-map on its own only needs the one extractor, not all 60
    only_map = opts.process_map and not any(
        (opts.export, opts.csv_dir, opts.tables_json, opts.tables_html))
    if only_map:
        # a prebuilt builder already has it; rebuilding would append a second
        # PROCESS_MASTER to the same builder and re-do the correlation
        if not prebuilt:
            tb.build(only=["t_process_master"], verbose=not opts.quiet)
        master = next((t for t in tb.tables if t.name == "PROCESS_MASTER"), None)
        if master is None:
            raise SystemExit("[!] no process artifacts found in this collection")
        ext = write_single_table(master, opts.process_map, opts.html_rows)
        print("[+] process map written to %s (%d processes, %d columns, %s)"
              % (opts.process_map, len(master), len(master.columns), ext),
              file=sys.stderr)
        return [master]

    scope = getattr(opts, "scope", "full")
    # rules were run before the console report, so the tables already exist -
    # rebuilding would re-scan every artifact and double every rule finding
    tables = tb.tables if prebuilt else tb.build(verbose=not opts.quiet,
                                                 scope=scope)
    meta = {
        "collection": col.path,
        "hostname": tri.meta.get("Hostname", tri.meta.get("hostname", "")),
        "collected": tri.meta.get("Collection finished", ""),
        "scope": scope,
        "layout": col.layout,
        "tables": len(tables),
        "rows_total": sum(len(t) for t in tables),
    }
    status("[*] built %d tables, %s rows total%s"
          % (len(tables), "{:,}".format(meta["rows_total"]),
             "" if scope == "full" else
             " (--scope %s: %s artifacts only)"
             % (scope, "live response" if scope == "live" else "on-disk")))

    outdir = opts.export
    csv_dir = opts.csv_dir or (os.path.join(outdir, "csv") if outdir else None)
    # --export writes one .json per table, mirroring the CSV directory.
    # --tables-json FILE still writes the single combined document, for a
    # consumer that wants one file to load.
    json_dir = os.path.join(outdir, "json") if outdir else None
    json_path = opts.tables_json
    html_path = opts.tables_html or (os.path.join(outdir, "browser.html") if outdir else None)

    if outdir:
        os.makedirs(outdir, exist_ok=True)
    writer_times = []
    if csv_dir:
        t0 = time.perf_counter()
        n = write_tables_csv(tables, csv_dir)
        writer_times.append(("write CSV", time.perf_counter() - t0))
        print("[+] %d CSV files written to %s" % (n, csv_dir), file=sys.stderr)
    if json_dir:
        t0 = time.perf_counter()
        n = write_tables_ndjson(tables, json_dir, meta)
        writer_times.append(("write NDJSON (per table)", time.perf_counter() - t0))
        status("[+] %d NDJSON files written to %s (one JSON object per row)"
               % (n, json_dir))
    if json_path:
        t0 = time.perf_counter()
        write_tables_json(tables, json_path, meta)
        writer_times.append(("write JSON (combined)", time.perf_counter() - t0))
        print("[+] combined table JSON written to %s" % json_path, file=sys.stderr)
    if html_path:
        t0 = time.perf_counter()
        write_tables_html(tables, html_path, opts.html_rows, meta, tri, opts)
        writer_times.append(("write HTML browser", time.perf_counter() - t0))
        print("[+] console written to %s (%d findings, %d tables)"
              % (html_path, len(tri.findings), len(tables)), file=sys.stderr)
    if opts.process_map:
        master = next((t for t in tables if t.name == "PROCESS_MASTER"), None)
        if master is None:
            status("[!] no PROCESS_MASTER table to write")
        else:
            ext = write_single_table(master, opts.process_map, opts.html_rows)
            print("[+] process map written to %s (%d processes, %d columns, %s)"
                  % (opts.process_map, len(master), len(master.columns), ext),
                  file=sys.stderr)
    if getattr(opts, "timing", False):
        print_timing(tb, writer_times)
    return tables


def print_timing(tb, writer_times, top=15):
    """Where the run actually went, per extractor and per writer.

    A collection that takes minutes is usually one artifact, not the tool being
    slow overall, and the answer changes per collection - a web server's
    access_log, a host with a year of journal. Guessing which costs a rerun;
    this prints it.
    """
    rows = ([(lab, sec, n) for lab, sec, n in tb.timings]
            + [(lab, sec, None) for lab, sec in writer_times])
    total = sum(r[1] for r in rows)
    rows.sort(key=lambda r: -r[1])
    print("\n[*] timing: %.1fs accounted for, slowest %d:"
          % (total, min(top, len(rows))), file=sys.stderr)
    for lab, sec, n in rows[:top]:
        if sec < 0.05:
            break
        share = "%5.1f%%" % (100 * sec / total) if total else "     "
        print("      %-24s %7.2fs %s%s"
              % (lab, sec, share,
                 "" if n is None else "  %s rows" % format(n, ",")),
              file=sys.stderr)


# ---------------------------------------------------------------------------
# reporting
# ---------------------------------------------------------------------------

def c(text, style, enabled):
    return "%s%s%s" % (COLORS[style], text, COLORS["reset"]) if enabled else text


def can_encode(stream, text):
    """Whether `stream` can actually render `text` in its own encoding.

    Asked before writing rather than caught after: a UnicodeEncodeError part
    way through leaves half a masthead on the terminal, and a console on cp437
    or cp1252 cannot draw block characters at all.
    """
    enc = getattr(stream, "encoding", None)
    if not enc:
        return False
    try:
        text.encode(enc)
        return True
    except (UnicodeEncodeError, LookupError, TypeError):
        return False


def print_banner(color, stream=None):
    """The mark, once, before any work - and never on stdout.

    stdout carries the report; a caller redirecting it to a file wants the
    findings in that file, not a masthead, and one piping it into another tool
    wants it even less. stderr is where the [*] status lines already go.
    """
    out = stream or sys.stderr
    # opts.color is decided by stdout, and this writes to stderr: one can be a
    # terminal while the other is a pipe, and colouring a pipe puts raw escape
    # sequences in whatever reads it.
    try:
        color = color and out.isatty()
    except Exception:
        color = False

    block = can_encode(out, BANNER_BLOCK)
    art = BANNER_BLOCK if block else BANNER_ASCII
    cell = SCALE_BLOCK if block else SCALE_ASCII
    scale = "".join(c(cell, sev, color) for sev in SEVERITIES)
    try:
        # normalised: one constant carries a leading newline and one does not,
        # and the masthead must not jump a line depending on the code page
        out.write("\n" + c(art.strip("\n"), "head", color) + "\n")
        out.write(" %s  %s\n" % (scale, c("parse linux deep. hunt the malicious.", "bold", color)))
        out.write(c(" v%s   developed by %s\n\n" % (VERSION, AUTHOR), "dim", color))
        out.flush()
    except Exception:
        pass          # a closed or undecodable stderr must not end the run


def print_console(tri, opts):
    color = opts.color
    out = sys.stdout
    findings = [f for f in tri.findings if SEV_RANK[f.severity] <= SEV_RANK[opts.min_severity]]
    counts = defaultdict(int)
    for f in tri.findings:
        counts[f.severity] += 1

    out.write("\n" + c("=" * 100, "head", color) + "\n")
    out.write(c("  LINUX TRIAGE REPORT", "bold", color) + "   v%s\n" % VERSION)
    out.write("  %-14s : %s\n" % ("collection", tri.col.path))
    out.write("  %-14s : %s\n" % ("layout", {"uac": "UAC",
                                             "velociraptor": "Velociraptor offline collector"}
                                  .get(tri.col.layout, tri.col.layout)))
    for k, label in (("Hostname", "hostname"),
                     ("Hostname (from archive name)", "hostname"),
                     ("uname", "kernel"),
                     ("Operating system", "os"), ("System architecture", "arch"),
                     ("Collection finished", "collected"), ("Host UTC offset", "host offset"),
                     ("Time zone", "time zone"), ("Command line", "collector command")):
        if tri.meta.get(k):
            out.write("  %-14s : %s\n" % (label, trunc(str(tri.meta[k]), 110)))
    out.write(c("=" * 100, "head", color) + "\n\n")

    out.write(c("  FINDING SUMMARY", "bold", color) + "\n")
    for sev in SEVERITIES:
        if counts[sev]:
            out.write("    %s  %d\n" % (c("%-9s" % sev, sev, color), counts[sev]))
    out.write("    %-9s  %d\n" % ("TOTAL", len(tri.findings)))

    top = [f for f in tri.findings if f.severity in ("CRITICAL", "HIGH")]
    if top:
        out.write("\n" + c("  HEADLINES", "bold", color) + "\n")
        for f in top[:12]:
            out.write("    %s %s\n" % (c("[%s]" % f.severity, f.severity, color), f.title))
    out.write("\n")

    for sev in SEVERITIES:
        block = [f for f in findings if f.severity == sev]
        if not block:
            continue
        out.write(c("-" * 100, "head", color) + "\n")
        out.write(c(" %s FINDINGS (%d)" % (sev, len(block)), sev, color) + "\n")
        out.write(c("-" * 100, "head", color) + "\n")
        for i, f in enumerate(block, 1):
            out.write("\n%s %s\n" % (c("[%s/%s]" % (sev[:4], i), sev, color),
                                     c(f.title, "bold", color)))
            out.write("    category : %s\n" % f.category)
            if f.mitre:
                out.write("    att&ck   : %s\n" % f.mitre)
            if f.source:
                out.write("    artifact : %s\n" % f.source)
            seen = f.seen_text()
            if seen:
                out.write("    seen     : %s\n" % seen)
            if f.detail:
                for line in wrap(f.detail, 92):
                    out.write("    %s\n" % c(line, "dim", color))
            shown = f.evidence[: opts.max_evidence]
            for e in shown:
                out.write("      | %s\n" % e)
            if len(f.evidence) > len(shown):
                out.write("      | ... %d more (use --max-evidence or --json)\n"
                          % (len(f.evidence) - len(shown)))
        out.write("\n")

    if opts.show_timeline and tri.events:
        # a console timeline is only useful if it fits on a screen: prefer the
        # events that were scored above INFO, and fall back when there are none
        notable = [e for e in tri.events if e.severity != "INFO"]
        shown_events = notable if len(notable) >= 10 else tri.events
        label = "notable events" if shown_events is notable else "events"
        out.write(c("-" * 100, "head", color) + "\n")
        out.write(c(" EVENT TIMELINE (last %d of %d %s; full list via --timeline)"
                    % (min(len(shown_events), opts.timeline_show), len(shown_events), label),
                    "head", color) + "\n")
        out.write(c("-" * 100, "head", color) + "\n")
        for e in shown_events[-opts.timeline_show:]:
            out.write("  %s  %-9s %-10s %s\n" % (
                e.ts.strftime("%Y-%m-%d %H:%M:%S"),
                c("%-9s" % e.severity, e.severity, color) if e.severity != "INFO" else "%-9s" % "",
                e.category, trunc(e.description, 110)))
        out.write("\n")


def wrap(text, width):
    out = []
    for para in text.split("\n"):
        line = ""
        for word in para.split():
            if len(line) + len(word) + 1 > width:
                out.append(line)
                line = word
            else:
                line = (line + " " + word).strip()
        out.append(line)
    return out


def write_json(tri, path):
    data = {
        "tool": "linsight.py", "version": VERSION,
        "collection": tri.col.path,
        "metadata": tri.meta,
        "summary": {s: sum(1 for f in tri.findings if f.severity == s) for s in SEVERITIES},
        "findings": [f.as_dict() for f in tri.findings],
        "events": [e.as_dict() for e in tri.events],
        "iocs": {k: sorted(v) for k, v in sorted(tri.iocs.items())},
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    print("[+] JSON written to %s" % path, file=sys.stderr)


def write_timeline(tri, path):
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["timestamp_utc", "severity", "category", "description", "source"])
        for e in tri.events:
            w.writerow([e.ts.strftime("%Y-%m-%d %H:%M:%S"), e.severity, e.category,
                        e.description, e.source])
    print("[+] timeline (%d events) written to %s" % (len(tri.events), path), file=sys.stderr)


HTML_CSS = """
:root{--bg:#f7f8fa;--fg:#1b1f24;--card:#fff;--line:#e3e6ea;--muted:#5b6570}
@media (prefers-color-scheme:dark){:root{--bg:#14171b;--fg:#e6e9ed;--card:#1c2026;--line:#2b3138;--muted:#98a2ad}}
*{box-sizing:border-box}
body{margin:0;padding:24px;background:var(--bg);color:var(--fg);
 font:14px/1.55 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
h1{font-size:22px;margin:0 0 4px} h2{font-size:16px;margin:28px 0 10px}
.meta{color:var(--muted);font-size:13px;margin-bottom:18px}
.meta code{font-size:12px}
.cards{display:flex;flex-wrap:wrap;gap:10px;margin:16px 0 26px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;
 padding:10px 16px;min-width:104px}
.card b{display:block;font-size:22px;line-height:1.1}
.card span{font-size:11px;letter-spacing:.06em;color:var(--muted)}
.f{background:var(--card);border:1px solid var(--line);border-left-width:5px;
 border-radius:8px;margin:0 0 10px;padding:12px 16px}
.f>summary{cursor:pointer;font-weight:600;list-style:none;display:flex;gap:10px;align-items:baseline}
.f>summary::-webkit-details-marker{display:none}
.tag{font-size:10px;font-weight:700;letter-spacing:.06em;padding:2px 7px;border-radius:4px;
 color:#fff;white-space:nowrap}
.CRITICAL{border-left-color:#b3132a}.CRITICAL .tag{background:#b3132a}
.HIGH{border-left-color:#d9531e}.HIGH .tag{background:#d9531e}
.MEDIUM{border-left-color:#c99700}.MEDIUM .tag{background:#c99700}
.LOW{border-left-color:#2b7fb8}.LOW .tag{background:#2b7fb8}
.INFO{border-left-color:#6b7684}.INFO .tag{background:#6b7684}
.detail{color:var(--muted);margin:8px 0}
.kv{font-size:12px;color:var(--muted);margin:2px 0}
pre{background:rgba(127,127,127,.09);border-radius:6px;padding:10px;overflow-x:auto;
 font:12px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace;margin:8px 0 0}
table{border-collapse:collapse;width:100%;font-size:12.5px;display:block;overflow-x:auto}
th,td{text-align:left;padding:5px 10px;border-bottom:1px solid var(--line);white-space:nowrap}
th{color:var(--muted);font-weight:600}
td.d{white-space:normal}
"""


def write_html(tri, path, opts):
    esc = htmllib.escape
    counts = {s: sum(1 for f in tri.findings if f.severity == s) for s in SEVERITIES}
    parts = ["<!doctype html><html><head><meta charset='utf-8'>",
             "<meta name='viewport' content='width=device-width,initial-scale=1'>",
             "<title>UAC triage - %s</title><style>%s</style></head><body>"
             % (esc(tri.meta.get("Hostname", "collection")), HTML_CSS)]
    parts.append("<h1>UAC triage report</h1><div class='meta'>")
    parts.append("<div><code>%s</code></div>" % esc(tri.col.path))
    for k, v in tri.meta.items():
        if v:
            parts.append("<div>%s: <code>%s</code></div>" % (esc(k), esc(str(v))))
    parts.append("</div><div class='cards'>")
    for s in SEVERITIES:
        parts.append("<div class='card %s'><b>%d</b><span>%s</span></div>" % (s, counts[s], s))
    parts.append("</div>")

    for sev in SEVERITIES:
        block = [f for f in tri.findings if f.severity == sev]
        if not block:
            continue
        parts.append("<h2>%s findings (%d)</h2>" % (sev.title(), len(block)))
        for f in block:
            openattr = " open" if sev in ("CRITICAL", "HIGH") else ""
            parts.append("<details class='f %s'%s><summary><span class='tag'>%s</span>%s</summary>"
                         % (sev, openattr, sev, esc(f.title)))
            if f.detail:
                parts.append("<div class='detail'>%s</div>" % esc(f.detail))
            parts.append("<div class='kv'>category: %s" % esc(f.category))
            if f.mitre:
                parts.append(" &nbsp;|&nbsp; ATT&amp;CK: %s" % esc(f.mitre))
            if f.source:
                parts.append(" &nbsp;|&nbsp; artifact: <code>%s</code>" % esc(f.source))
            parts.append("</div>")
            seen = f.seen_text()
            if seen:
                parts.append("<div class='kv'>seen: %s</div>" % esc(seen))
            if f.evidence:
                shown = f.evidence[:400]
                parts.append("<pre>%s</pre>" % esc("\n".join(shown)))
                if len(f.evidence) > len(shown):
                    parts.append("<div class='kv'>... %d more lines</div>"
                                 % (len(f.evidence) - len(shown)))
            parts.append("</details>")

    if tri.events:
        parts.append("<h2>Event timeline (%d)</h2><table><tr><th>time (UTC)</th><th>sev</th>"
                     "<th>category</th><th>event</th></tr>" % len(tri.events))
        for e in tri.events[-opts.timeline_limit:]:
            parts.append("<tr><td>%s</td><td>%s</td><td>%s</td><td class='d'>%s</td></tr>"
                         % (e.ts.strftime("%Y-%m-%d %H:%M:%S"), e.severity,
                            esc(e.category), esc(trunc(e.description, 300))))
        parts.append("</table>")

    if tri.iocs:
        parts.append("<h2>Indicators observed (%d)</h2><table><tr><th>indicator</th>"
                     "<th>seen in</th></tr>" % len(tri.iocs))
        for k, v in sorted(tri.iocs.items()):
            parts.append("<tr><td><code>%s</code></td><td class='d'>%s</td></tr>"
                         % (esc(k), esc(", ".join(sorted(v)))))
        parts.append("</table>")

    parts.append("<p class='kv'>generated by linsight.py v%s</p></body></html>" % VERSION)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("".join(parts))
    print("[+] HTML report written to %s" % path, file=sys.stderr)


# ---------------------------------------------------------------------------
# The GUI: one self-contained page that carries the triage picture.
#
# --html writes a document - a flat page you read top to bottom and hand to
# someone. This is the other thing an analyst wants from the same data: a
# console to work the findings in, filter by severity, pivot on a technique,
# read the evidence beside the list rather than by scrolling to it.
#
# It stays one file with no dependency on the network, because the box that
# reads a triage collection is routinely the box that is not allowed to fetch
# anything. Tables are deliberately not bundled: --export already writes
# browser.html for those, and folding 3.3 million rows into this page would
# cost the instant first paint that makes it usable.

# Technique -> tactic, parent IDs only; a sub-technique inherits its parent's
# column. Only the tactic is stored: the technique's *name* already arrives in
# the finding's mitre string ("T1053.003 Scheduled Task: Cron"), so keeping a
# second copy here would be one more thing to hold consistent with ATT&CK.
# An ID that is not listed lands in "Other" rather than being dropped - a Sigma
# rule can carry any technique at all, and a hit that vanishes from the matrix
# because the map is short is worse than a hit in the wrong column.
ATTACK_TACTICS = {
    "T1592": "Reconnaissance", "T1595": "Reconnaissance",
    "T1587": "Resource Development", "T1588": "Resource Development",
    "T1608": "Resource Development",
    "T1133": "Initial Access", "T1190": "Initial Access",
    "T1195": "Initial Access", "T1566": "Initial Access",
    "T1059": "Execution", "T1203": "Execution", "T1204": "Execution",
    "T1569": "Execution", "T1610": "Execution",
    "T1053": "Persistence", "T1078": "Persistence", "T1098": "Persistence",
    "T1136": "Persistence", "T1176": "Persistence", "T1505": "Persistence",
    "T1525": "Persistence", "T1543": "Persistence", "T1546": "Persistence",
    "T1547": "Persistence", "T1554": "Persistence", "T1574": "Persistence",
    "T1068": "Privilege Escalation", "T1134": "Privilege Escalation",
    "T1548": "Privilege Escalation", "T1611": "Privilege Escalation",
    "T1014": "Defense Evasion", "T1027": "Defense Evasion",
    "T1036": "Defense Evasion", "T1055": "Defense Evasion",
    "T1070": "Defense Evasion", "T1140": "Defense Evasion",
    "T1205": "Defense Evasion", "T1218": "Defense Evasion",
    "T1222": "Defense Evasion", "T1480": "Defense Evasion",
    "T1497": "Defense Evasion", "T1553": "Defense Evasion",
    "T1562": "Defense Evasion", "T1564": "Defense Evasion",
    "T1620": "Defense Evasion",
    "T1003": "Credential Access", "T1040": "Credential Access",
    "T1110": "Credential Access", "T1528": "Credential Access",
    "T1539": "Credential Access", "T1552": "Credential Access",
    "T1555": "Credential Access", "T1556": "Credential Access",
    "T1557": "Credential Access",
    "T1018": "Discovery", "T1033": "Discovery", "T1046": "Discovery",
    "T1049": "Discovery", "T1057": "Discovery", "T1069": "Discovery",
    "T1082": "Discovery", "T1083": "Discovery", "T1087": "Discovery",
    "T1518": "Discovery", "T1526": "Discovery", "T1613": "Discovery",
    "T1021": "Lateral Movement", "T1072": "Lateral Movement",
    "T1210": "Lateral Movement", "T1563": "Lateral Movement",
    "T1570": "Lateral Movement",
    "T1005": "Collection", "T1074": "Collection", "T1560": "Collection",
    "T1071": "Command and Control", "T1090": "Command and Control",
    "T1095": "Command and Control", "T1104": "Command and Control",
    "T1105": "Command and Control", "T1132": "Command and Control",
    "T1219": "Command and Control", "T1571": "Command and Control",
    "T1572": "Command and Control", "T1573": "Command and Control",
    "T1041": "Exfiltration", "T1048": "Exfiltration", "T1567": "Exfiltration",
    "T1485": "Impact", "T1486": "Impact", "T1489": "Impact",
    "T1490": "Impact", "T1495": "Impact", "T1496": "Impact",
    "T1499": "Impact", "T1531": "Impact", "T1561": "Impact",
    "T1565": "Impact",
}

# Left to right as ATT&CK draws it, so the matrix reads as an attack sequence.
ATTACK_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion",
    "Credential Access", "Discovery", "Lateral Movement", "Collection",
    "Command and Control", "Exfiltration", "Impact", "Other",
]

_TECH_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def _gui_techniques(mitre):
    """Every technique ID in one finding's mitre string.

    The field is prose, not a list: "T1078 Valid Accounts / T1021.004 SSH" is
    two techniques and "T1036 Masquerading" is one, and Sigma contributes its
    own comma-joined form. Pulling the IDs out with a pattern handles all of
    them without asking every analyzer to change what it writes.
    """
    return _TECH_RE.findall(mitre or "")


def _gui_label(mitre, tech):
    """The human name beside a technique ID, taken from the finding itself.

    "T1053.003 Scheduled Task: Cron" -> "Scheduled Task: Cron". Nothing is
    invented when the string is a bare ID - the matrix then shows the ID alone,
    which is still the thing an analyst looks up.
    """
    if not mitre:
        return ""
    i = mitre.find(tech)
    if i < 0:
        return ""
    rest = mitre[i + len(tech):].lstrip(" -:")
    for sep in ("/", ","):
        if sep in rest:
            rest = rest.split(sep)[0]
    rest = rest.strip()
    # A trailing fragment that is just another ID is not a name.
    return "" if _TECH_RE.match(rest) else rest[:60]


APP_CSS = """
:root{--bg:#0f1419;--panel:#161b22;--panel2:#1c2330;--line:#2b3440;--fg:#d7dee7;
--dim:#8b98a8;--accent:#58a6ff;--gold:#f5d067;
--CRITICAL:#ff5f56;--HIGH:#ff9f43;--MEDIUM:#ffd93d;--LOW:#5ad1e6;--INFO:#8b98a8}
*{box-sizing:border-box}
body{margin:0;font:13px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
background:var(--bg);color:var(--fg);overflow:hidden}
code,pre{font-family:ui-monospace,SFMono-Regular,Consolas,Menlo,monospace}
a{color:var(--accent);text-decoration:none}

/* ---- chrome ---- */
header{display:flex;align-items:center;gap:16px;padding:10px 16px;
border-bottom:1px solid var(--line);background:var(--panel);height:56px}
.brand{display:flex;align-items:baseline;gap:9px;flex:0 0 auto}
.brand b{font-size:17px;font-weight:600;letter-spacing:-.3px}
.brand span{font-size:9.5px;letter-spacing:2px;color:var(--dim)}
.host{color:var(--dim);font-size:12px;overflow:hidden;text-overflow:ellipsis;
white-space:nowrap;flex:1 1 auto}
.host b{color:var(--fg);font-weight:600}
.chips{display:flex;gap:6px;flex:0 0 auto}
.chip{border:1px solid var(--line);border-radius:14px;padding:2px 10px;cursor:pointer;
font-size:11px;letter-spacing:.5px;background:transparent;color:var(--dim);
font-variant-numeric:tabular-nums;user-select:none}
.chip b{color:var(--fg);margin-right:5px}
.chip.on{background:var(--panel2)}
.chip.on.CRITICAL{color:var(--CRITICAL);border-color:var(--CRITICAL)}
.chip.on.HIGH{color:var(--HIGH);border-color:var(--HIGH)}
.chip.on.MEDIUM{color:var(--MEDIUM);border-color:var(--MEDIUM)}
.chip.on.LOW{color:var(--LOW);border-color:var(--LOW)}
.chip.on.INFO{color:var(--INFO);border-color:var(--INFO)}
.chip.off{opacity:.42;text-decoration:line-through}

.layout{display:flex;height:calc(100vh - 56px)}
nav{width:248px;flex:0 0 248px;background:var(--panel);border-right:1px solid var(--line);
padding:10px 0;display:flex;flex-direction:column;overflow-y:auto}
nav a{display:flex;justify-content:space-between;align-items:center;gap:8px;
padding:7px 14px;color:var(--fg);border-left:3px solid transparent;cursor:pointer}
nav a:hover{background:var(--panel2)}
nav a.active{background:var(--panel2);border-left-color:var(--gold);color:var(--gold)}
nav a .n{color:var(--dim);font-size:11px;font-variant-numeric:tabular-nums}
nav .foot{margin-top:auto;padding:10px 14px;color:var(--dim);font-size:10.5px;
border-top:1px solid var(--line)}
main{flex:1;overflow:auto;padding:16px 18px;min-width:0}
h2{margin:0 0 12px;font-size:14px;font-weight:600;letter-spacing:.3px}
h3{margin:22px 0 9px;font-size:12px;font-weight:600;color:var(--dim);
text-transform:uppercase;letter-spacing:1px}

/* ---- overview ---- */
.cards{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:6px}
.card{flex:1 1 128px;background:var(--panel);border:1px solid var(--line);
border-top-width:3px;border-radius:6px;padding:11px 13px;cursor:pointer}
.card:hover{background:var(--panel2)}
.card b{display:block;font-size:25px;line-height:1.15;font-variant-numeric:tabular-nums}
.card span{color:var(--dim);font-size:10.5px;letter-spacing:1.1px}
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(330px,1fr));gap:18px}
.bars{display:flex;flex-direction:column;gap:5px}
.bar{display:grid;grid-template-columns:1fr 46px;gap:9px;align-items:center;cursor:pointer}
.bar:hover .lbl{color:var(--gold)}
.bar .lbl{position:relative;padding:3px 7px;overflow:hidden;text-overflow:ellipsis;
white-space:nowrap;border-radius:3px;background:var(--panel)}
.bar .fill{position:absolute;left:0;top:0;bottom:0;background:var(--panel2);z-index:0}
.bar .tx{position:relative;z-index:1}
.bar .n{text-align:right;color:var(--dim);font-variant-numeric:tabular-nums}
.histo{display:flex;align-items:flex-end;gap:2px;background:var(--panel);
border:1px solid var(--line);border-radius:6px;padding:8px}
.histo .col{flex:1;min-width:2px;height:100%;display:flex;flex-direction:column-reverse}
.histo .col:hover{outline:1px solid var(--gold);outline-offset:1px}
.histo.click .col{cursor:pointer}
/* A bucket holding one event still has to be visible next to a bucket holding
   a thousand, or a quiet week reads as no data at all. */
.histo .seg{width:100%;opacity:.85;min-height:2px}
.histo .col:hover .seg{opacity:1}
.histo .col.on{outline:1px solid var(--gold)}
.axis{display:flex;justify-content:space-between;color:var(--dim);font-size:10.5px;
padding:4px 2px 0}
table.meta{border-collapse:collapse;font-size:12px}
table.meta td{padding:3px 14px 3px 0;vertical-align:top;border:0}
table.meta td:first-child{color:var(--dim);white-space:nowrap}

/* ---- findings ---- */
.split{display:flex;gap:14px;height:calc(100vh - 56px - 32px - 42px)}
.list{flex:0 0 45%;overflow:auto;border:1px solid var(--line);border-radius:6px;
background:var(--panel)}
.row{padding:8px 11px;border-bottom:1px solid var(--line);cursor:pointer;
border-left:3px solid transparent}
.row:hover{background:var(--panel2)}
.row.sel{background:var(--panel2);border-left-color:var(--gold)}
.row .t{display:flex;gap:8px;align-items:baseline}
.row .tag{font-size:9.5px;letter-spacing:.7px;padding:1px 5px;border-radius:3px;
flex:0 0 auto;color:#0f1419;font-weight:700}
.row .ti{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.row .sub{color:var(--dim);font-size:11px;margin-top:2px;overflow:hidden;
text-overflow:ellipsis;white-space:nowrap}
.detail{flex:1;overflow:auto;border:1px solid var(--line);border-radius:6px;
background:var(--panel);padding:14px 16px}
.detail h4{margin:0 0 6px;font-size:14px;font-weight:600}
.detail .d{color:var(--dim);margin-bottom:12px}
.detail pre{background:var(--bg);border:1px solid var(--line);border-radius:5px;
padding:10px;overflow:auto;max-height:52vh;font-size:11.5px;white-space:pre-wrap;
word-break:break-all;margin:0}
.kv{display:grid;grid-template-columns:92px 1fr;gap:4px 12px;margin-bottom:13px;
font-size:12px}
.kv span{color:var(--dim)}
.pill{display:inline-block;border:1px solid var(--line);border-radius:11px;
padding:0 8px;margin:0 4px 4px 0;font-size:11px;cursor:pointer;color:var(--accent)}
.pill:hover{background:var(--panel2)}
.empty{color:var(--dim);padding:26px 4px;text-align:center}
.bartop{display:flex;gap:8px;align-items:center;margin-bottom:10px}
input[type=search],select{background:var(--panel);color:var(--fg);
border:1px solid var(--line);border-radius:5px;padding:5px 9px;font:inherit;outline:none}
input[type=search]{flex:1}
input[type=search]:focus,select:focus{border-color:var(--accent)}
.count{color:var(--dim);font-size:11.5px;white-space:nowrap}

/* ---- attack matrix ---- */
.matrix{display:flex;gap:8px;overflow-x:auto;padding-bottom:8px;align-items:flex-start}
.tac{flex:0 0 152px;background:var(--panel);border:1px solid var(--line);border-radius:6px}
.tac .h{padding:7px 9px;border-bottom:1px solid var(--line);font-size:10.5px;
color:var(--dim);text-transform:uppercase;letter-spacing:.8px;line-height:1.3}
.tac .h b{display:block;color:var(--fg);font-size:11.5px;letter-spacing:0;
text-transform:none}
.cell{margin:6px;padding:5px 7px;border-radius:4px;cursor:pointer;
border-left:3px solid var(--line);background:var(--panel2)}
.cell:hover{outline:1px solid var(--gold)}
.cell .id{font-size:11px;font-variant-numeric:tabular-nums}
.cell .nm{color:var(--dim);font-size:10.5px;overflow:hidden;text-overflow:ellipsis;
white-space:nowrap}
.cell .n{float:right;color:var(--dim);font-size:10.5px}

/* ---- tables (timeline, iocs) ---- */
table.grid{width:100%;border-collapse:collapse;font-size:12px}
table.grid th{position:sticky;top:0;background:var(--panel2);text-align:left;
padding:6px 9px;border-bottom:1px solid var(--line);font-weight:600;z-index:1}
table.grid td{padding:4px 9px;border-bottom:1px solid var(--line);vertical-align:top}
table.grid tr:hover td{background:var(--panel)}
td.mono{font-family:ui-monospace,Consolas,monospace;white-space:nowrap}
td.wrap{word-break:break-word}
.more{margin:12px 0;padding:7px;text-align:center;border:1px dashed var(--line);
border-radius:5px;color:var(--dim);cursor:pointer}
.more:hover{color:var(--fg);border-color:var(--accent)}
/* nav: the five views, then every table under its category */
nav .cat{padding:12px 14px 4px;color:var(--dim);font-size:10px;text-transform:uppercase;
letter-spacing:1px}
nav .sec{margin-top:6px;border-top:1px solid var(--line);padding-top:4px}
nav a.tbl{padding:5px 14px;font-size:12px}
nav a.tbl span:first-child{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}

/* ---- tables ----
   Scoped to .tbl: the console has tables of its own (the timeline, the
   indicator list, the collection metadata) and fixed layout with measured
   column widths is right for an artifact grid and wrong for those. */
.desc{color:var(--dim);margin:0 0 12px;font-size:12px}
.controls{display:flex;gap:8px;align-items:center;margin-bottom:10px;flex-wrap:wrap}
.badge{background:#0d1117;border:1px solid var(--line);border-radius:11px;padding:2px 9px;
color:var(--dim);font-size:11px;white-space:nowrap}
.warn{color:var(--HIGH)}
/* fixed layout so the <colgroup> widths computed from the data are what the
   browser actually uses - with auto layout one long cell drags its column
   wide and squeezes every other column into a ragged strip */
/* min-width so a narrow table still fills the pane - fixed layout then shares
   the spare width across the columns instead of leaving a ragged right edge */
table.tbl{border-collapse:collapse;font-size:12px;table-layout:fixed;min-width:100%}
.tbl th,.tbl td{border:1px solid var(--line);padding:4px 8px;text-align:left;vertical-align:top;
overflow-wrap:anywhere}
/* a cell taller than this scrolls inside itself, so one 4000-character
   evidence blob cannot push the next row off the screen */
.tbl td .c{white-space:pre-wrap;max-height:8.5em;overflow-y:auto}
.tbl td.nw .c{white-space:nowrap;overflow-x:hidden;text-overflow:ellipsis}
.tbl td.nw:hover .c{overflow-x:auto;text-overflow:clip}
.tbl th{background:#1c2330;position:sticky;top:0;z-index:4;cursor:pointer;user-select:none;
white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.tbl th:hover{color:var(--accent)}
/* the per-column filter row sits directly under the labels; its offset is set
   from the measured label height in wire(), because the two rows have to stay
   glued together when the body scrolls under them */
.tbl tr.f th{background:var(--panel);padding:3px 4px;cursor:auto;z-index:3}
.tbl tr.f th:hover{color:inherit}
.tbl tr.f input{width:100%;background:#0d1117;border:1px solid var(--line);color:var(--fg);
border-radius:3px;padding:2px 5px;font:11px/1.5 inherit}
.tbl tr.f input:focus{outline:none;border-color:var(--accent)}
.tbl tr.f input.on{border-color:var(--accent);background:#10243d;color:#fff}
button.clr{background:#0d1117;border:1px solid var(--line);color:var(--dim);
border-radius:11px;padding:2px 9px;font-size:11px;cursor:pointer}
button.clr:hover{color:var(--accent);border-color:var(--accent)}
.tbl tbody tr:nth-child(even){background:#12171e}
.tbl tbody tr:hover{background:#1a212b}
.tbl td.num{text-align:right;font-variant-numeric:tabular-nums}
.sev-CRITICAL{color:var(--CRITICAL);font-weight:600}
.sev-HIGH{color:var(--HIGH);font-weight:600}
.sev-MEDIUM{color:var(--MEDIUM)}
.sev-LOW{color:var(--LOW)}
.sev-INFO{color:var(--INFO)}
"""

APP_JS = """
var D=window.__LINSIGHT__,SEV=['CRITICAL','HIGH','MEDIUM','LOW','INFO'];
var st={view:'overview',sev:{},q:'',cat:'',tech:'',sel:null,page:400,bucket:null,
        table:null,tq:''};
var TB=D.tables||{},IDX=D.index||[];
var VIEWS=[['overview','Overview',null],['findings','Findings',0],
 ['attack','ATT&CK',null],['timeline','Timeline',(D.events||[]).length],
 ['iocs','Indicators',(D.iocs||[]).length]];
var TLB=[];   /* the timeline chart's bucket bounds, from the last render */
SEV.forEach(function(s){st.sev[s]=true;});

function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,function(c){
 return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
function el(id){return document.getElementById(id);}
function sevRank(s){var i=SEV.indexOf(s);return i<0?99:i;}

/* One predicate for every view, so a severity chip means the same thing in the
   matrix as it does in the finding list. */
function match(f){
 if(!st.sev[f.sev])return false;
 if(st.cat&&f.cat!==st.cat)return false;
 if(st.tech&&f.techs.indexOf(st.tech)<0)return false;
 if(st.q){
  var q=st.q.toLowerCase();
  if((f.hay||'').indexOf(q)<0)return false;
 }
 return true;
}
function findings(){return D.findings.filter(match);}

function setView(v,name){
 st.view=v;st.page=400;
 if(v==='table'&&name!==st.table){st.table=name;sortCol=-1;colFilters=[];st.tq='';}
 location.hash=(v==='table')?'t/'+st.table:v;
 render();
}
/* The nav is built once; only the highlight moves, because rebuilding 89
   anchors on every keystroke is work nobody asked for. */
function markNav(){
 [].forEach.call(document.querySelectorAll('nav a'),function(a){
  a.classList.toggle('active',st.view==='table'
   ?a.getAttribute('data-t')===st.table
   :a.getAttribute('data-v')===st.view);});
}
function chips(){
 /* A page written without the triage half has nothing for them to filter, so
    five zeroes in the header would be furniture rather than a control. */
 if(!D.findings.length&&!D.events.length){el('chips').innerHTML='';return;}
 var h='';
 SEV.forEach(function(s){
  h+='<button class="chip '+s+' '+(st.sev[s]?'on':'off')+'" data-s="'+s+'">'+
     '<b>'+(D.counts[s]||0)+'</b>'+s+'</button>';});
 el('chips').innerHTML=h;
 [].forEach.call(document.querySelectorAll('#chips .chip'),function(b){
  b.onclick=function(ev){
   ev=ev||window.event;
   var s=b.getAttribute('data-s');
   /* Alt-click isolates one severity: the common move is "show me only the
      criticals", which is otherwise four clicks. */
   if(ev&&ev.altKey){
    SEV.forEach(function(x){st.sev[x]=(x===s);});
   }else{st.sev[s]=!st.sev[s];}
   st.bucket=null;chips();render();};});
}

/* ---------- overview ---------- */
/* act is what a click on a bar filters by (''  = not clickable); lab turns the
   key into what the row reads as, so a technique bar can show its name while
   still filtering on the bare ID. */
function barList(pairs,act,lab){
 if(!pairs.length)return '<div class="empty">nothing</div>';
 var max=pairs[0][1]||1,h='<div class="bars">';
 pairs.forEach(function(p){
  h+='<div class="bar" data-k="'+esc(p[0])+'" data-act="'+(act||'')+'">'+
     '<div class="lbl"><div class="fill" style="width:'+
     Math.max(2,Math.round(p[1]*100/max))+'%"></div>'+
     '<div class="tx">'+esc((lab?lab(p[0]):p[0])||'(none)')+'</div></div>'+
     '<div class="n">'+p[1]+'</div></div>';});
 return h+'</div>';
}
function techLabel(t){return D.names[t]?t+'  '+D.names[t]:t;}
function tally(list,fn){
 var m={},out=[];
 list.forEach(function(x){var ks=fn(x);if(!ks)return;
  if(!(ks instanceof Array))ks=[ks];
  ks.forEach(function(k){m[k]=(m[k]||0)+1;});});
 for(var k in m)out.push([k,m[k]]);
 out.sort(function(a,b){return b[1]-a[1];});
 return out;
}
function viewOverview(){
 var fs=findings(),h='<h2>Overview</h2><div class="cards">';
 SEV.forEach(function(s){
  var n=fs.filter(function(f){return f.sev===s;}).length;
  h+='<div class="card" data-sev="'+s+'" style="border-top-color:var(--'+s+')">'+
     '<b style="color:var(--'+s+')">'+n+'</b><span>'+s+'</span></div>';});
 h+='<div class="card" style="border-top-color:var(--gold)"><b>'+D.events.length+
    '</b><span>TIMELINE EVENTS</span></div>';
 h+='<div class="card" style="border-top-color:var(--accent)"><b>'+D.iocs.length+
    '</b><span>INDICATORS</span></div></div>';

 h+='<div class="grid2"><div><h3>Activity</h3>'+spark()+'</div>';
 h+='<div><h3>Collection</h3><table class="meta">';
 D.meta.forEach(function(kv){
  h+='<tr><td>'+esc(kv[0])+'</td><td>'+esc(kv[1])+'</td></tr>';});
 h+='</table></div></div>';

 h+='<div class="grid2"><div><h3>Categories</h3>'+
    barList(tally(fs,function(f){return f.cat;}).slice(0,14),'cat')+'</div>';
 h+='<div><h3>Techniques</h3>'+
    barList(tally(fs,function(f){return f.techs;}).slice(0,14),'tech',techLabel)+
    '</div></div>';

 h+='<div><h3>Loudest artifacts</h3>'+
    barList(tally(fs,function(f){return f.src;}).slice(0,10),'')+'</div>';
 return h;
}
/* Events bucketed into n columns between the first and last, each column a
   stack of severity segments. Buckets rather than one bar per event: a
   collection covering a year and one covering an hour have to produce the same
   shaped chart, and the stack is what makes a burst of CRITICAL visible inside
   an hour that also carries a thousand INFO lines.
   Returns the markup and, on the object, the bucket bounds - the timeline view
   needs them to turn a click back into a time range. */
function histo(ev,n,h_px,clickable){
 if(!ev.length)return {html:'<div class="empty">no dated events</div>',b:[]};
 /* Span from the extremes rather than from the ends of the list: the payload
    is sorted, but a filtered view is only as ordered as what it kept, and one
    event before ev[0] would otherwise land in a negative bucket. */
 var t0=ev[0].e,t1=t0,i;
 ev.forEach(function(e){if(e.e<t0)t0=e.e;if(e.e>t1)t1=e.e;});
 var span=Math.max(1,t1-t0),b=[];
 for(i=0;i<n;i++)b.push({n:0,s:{},t0:t0+span*i/n,t1:t0+span*(i+1)/n});
 ev.forEach(function(e){
  var k=Math.max(0,Math.min(n-1,Math.floor((e.e-t0)*n/span)));
  b[k].n++;b[k].s[e.s]=(b[k].s[e.s]||0)+1;});
 var max=0;b.forEach(function(x){if(x.n>max)max=x.n;});
 max=max||1;
 var h='<div class="histo'+(clickable?' click':'')+'" style="height:'+h_px+'px">';
 for(i=0;i<n;i++){
  var tip=[];
  SEV.forEach(function(sv){if(b[i].s[sv])tip.push(b[i].s[sv]+' '+sv);});
  h+='<div class="col'+(st.bucket===i&&clickable?' on':'')+'" data-b="'+i+
     '" title="'+esc(fmtT(b[i].t0)+'  -  '+(tip.join(', ')||'0'))+'">';
  /* column-reverse stacks the first child at the bottom, so walking INFO to
     CRITICAL puts the loud severities on top where they are read first. */
  for(var j=SEV.length-1;j>=0;j--){
   var c=b[i].s[SEV[j]];
   if(c)h+='<div class="seg" style="height:'+(c*100/max)+'%;background:var(--'+
     SEV[j]+')"></div>';}
  h+='</div>';}
 h+='</div><div class="axis"><span>'+esc(fmtT(t0))+'</span><span>'+
    esc(fmtT(t0+span/2))+'</span><span>'+esc(fmtT(t1))+'</span></div>';
 return {html:h,b:b};
}
/* Epoch seconds back to the same string shape the rows carry. Built from the
   UTC parts, never the locale: the whole report is UTC and a chart axis that
   quietly shifts to the examiner's timezone is a wrong answer. */
function fmtT(sec){
 var d=new Date(sec*1000),p=function(x){return (x<10?'0':'')+x;};
 return d.getUTCFullYear()+'-'+p(d.getUTCMonth()+1)+'-'+p(d.getUTCDate())+' '+
        p(d.getUTCHours())+':'+p(d.getUTCMinutes());
}
function spark(){return histo(D.events,60,88,false).html;}

/* ---------- findings ---------- */
function viewFindings(){
 var fs=findings();
 fs.sort(function(a,b){
  var d=sevRank(a.sev)-sevRank(b.sev);if(d)return d;
  return (b.last||'').localeCompare(a.last||'');});
 var cats=tally(D.findings,function(f){return f.cat;}).map(function(p){return p[0];}).sort();
 var h='<div class="bartop"><input type="search" id="q" placeholder="filter findings, evidence, artifact..." value="'+
   esc(st.q)+'"><select id="cat"><option value="">all categories</option>';
 cats.forEach(function(c){h+='<option'+(st.cat===c?' selected':'')+'>'+esc(c)+'</option>';});
 h+='</select>';
 if(st.tech)h+='<span class="pill" data-clear="tech">'+esc(st.tech)+' &times;</span>';
 h+='<span class="count">'+fs.length+' of '+D.findings.length+'</span></div>';

 h+='<div class="split"><div class="list" id="list">';
 if(!fs.length)h+='<div class="empty">nothing matches</div>';
 fs.slice(0,st.page).forEach(function(f){
  h+='<div class="row'+(st.sel===f.id?' sel':'')+'" data-id="'+f.id+'">'+
     '<div class="t"><span class="tag" style="background:var(--'+f.sev+')">'+
     f.sev+'</span><span class="ti">'+esc(f.title)+'</span></div>'+
     '<div class="sub">'+esc(f.cat)+(f.last?' &middot; '+esc(f.last):'')+
     (f.src?' &middot; '+esc(f.src):'')+'</div></div>';});
 if(fs.length>st.page)h+='<div class="more" id="more">show '+
   Math.min(400,fs.length-st.page)+' more of '+(fs.length-st.page)+'</div>';
 h+='</div><div class="detail" id="det">'+detail(fs)+'</div></div>';
 return h;
}
function detail(fs){
 var f=null;
 D.findings.forEach(function(x){if(x.id===st.sel)f=x;});
 if(!f)f=fs[0];
 if(!f)return '<div class="empty">select a finding</div>';
 st.sel=f.id;
 var h='<h4><span class="tag" style="background:var(--'+f.sev+');color:#0f1419;'+
   'padding:1px 6px;border-radius:3px;font-size:10px;margin-right:7px">'+f.sev+
   '</span>'+esc(f.title)+'</h4>';
 if(f.detail)h+='<div class="d">'+esc(f.detail)+'</div>';
 h+='<div class="kv"><span>category</span><div>'+esc(f.cat)+'</div>';
 if(f.src)h+='<span>artifact</span><div><code>'+esc(f.src)+'</code></div>';
 if(f.seen)h+='<span>seen</span><div>'+esc(f.seen)+'</div>';
 h+='<span>occurrences</span><div>'+f.count+'</div>';
 if(f.techs.length){
  h+='<span>ATT&amp;CK</span><div>';
  f.techs.forEach(function(t){h+='<span class="pill" data-tech="'+esc(t)+'">'+
    esc(t)+(D.names[t]?' '+esc(D.names[t]):'')+'</span>';});
  h+='</div>';}
 h+='</div>';
 if(f.ev.length){
  h+='<pre>'+esc(f.ev.join('\\n'))+'</pre>';
  if(f.more)h+='<div class="count" style="margin-top:6px">... '+f.more+
    ' more line(s) not shown</div>';}
 return h;
}

/* ---------- attack matrix ---------- */
function viewAttack(){
 var fs=findings(),by={};
 fs.forEach(function(f){
  f.techs.forEach(function(t){
   var tac=D.tactics[t]||'Other';
   if(!by[tac])by[tac]={};
   if(!by[tac][t])by[tac][t]={n:0,sev:'INFO'};
   by[tac][t].n++;
   if(sevRank(f.sev)<sevRank(by[tac][t].sev))by[tac][t].sev=f.sev;});});
 var order=D.order.filter(function(t){return by[t];});
 if(!order.length)return '<h2>ATT&amp;CK</h2><div class="empty">'+
   'no findings carry a technique at this filter</div>';
 var h='<h2>ATT&amp;CK <span class="count">&mdash; click a technique to filter the findings</span></h2>'+
   '<div class="matrix">';
 order.forEach(function(tac){
  var ts=[];for(var t in by[tac])ts.push(t);
  ts.sort(function(a,b){
   var d=sevRank(by[tac][a].sev)-sevRank(by[tac][b].sev);
   return d?d:by[tac][b].n-by[tac][a].n;});
  h+='<div class="tac"><div class="h"><b>'+esc(tac)+'</b>'+ts.length+' technique(s)</div>';
  ts.forEach(function(t){
   var c=by[tac][t];
   h+='<div class="cell" data-tech="'+esc(t)+'" style="border-left-color:var(--'+
      c.sev+')"><div class="id">'+esc(t)+'<span class="n">'+c.n+'</span></div>'+
      (D.names[t]?'<div class="nm">'+esc(D.names[t])+'</div>':'')+'</div>';});
  h+='</div>';});
 return h+'</div>';
}

/* ---------- timeline ---------- */
function viewTimeline(){
 var q=st.q.toLowerCase();
 var ev=D.events.filter(function(e){
  if(!st.sev[e.s])return false;
  if(q&&(e.t+' '+e.c+' '+e.d).toLowerCase().indexOf(q)<0)return false;
  return true;});
 /* The chart is drawn from everything the severity chips and the search box
    left, and the selected bucket then narrows only the table below it - so
    picking a spike never hides the shape the spike sits in. */
 var g=histo(ev,80,132,true);
 TLB=g.b;
 var rows=ev;
 if(st.bucket!=null&&TLB[st.bucket]){
  var b=TLB[st.bucket];
  rows=ev.filter(function(e){return e.e>=b.t0&&(e.e<b.t1||st.bucket===TLB.length-1);});}
 var h='<div class="bartop"><input type="search" id="q" placeholder="filter events..." value="'+
   esc(st.q)+'">';
 if(st.bucket!=null&&TLB[st.bucket])
  h+='<span class="pill" data-clear="bucket">'+esc(fmtT(TLB[st.bucket].t0)+
     ' - '+fmtT(TLB[st.bucket].t1))+' &times;</span>';
 h+='<span class="count">'+rows.length+' of '+D.events.length+'</span></div>';
 h+=g.html;
 h+='<table class="grid" style="margin-top:14px"><tr><th>time (UTC)</th><th>sev</th>'+
    '<th>category</th><th>event</th></tr>';
 rows.slice(0,st.page).forEach(function(e){
  h+='<tr><td class="mono">'+esc(e.t)+'</td><td style="color:var(--'+e.s+')">'+
     e.s+'</td><td>'+esc(e.c)+'</td><td class="wrap">'+esc(e.d)+'</td></tr>';});
 h+='</table>';
 if(rows.length>st.page)h+='<div class="more" id="more">show more ('+
   (rows.length-st.page)+' left)</div>';
 return h;
}

/* ---------- indicators ---------- */
function viewIocs(){
 var q=st.q.toLowerCase();
 var rows=D.iocs.filter(function(r){
  return !q||(r.i+' '+r.w).toLowerCase().indexOf(q)>=0;});
 var h='<div class="bartop"><input type="search" id="q" placeholder="filter indicators..." value="'+
   esc(st.q)+'"><span class="count">'+rows.length+' of '+D.iocs.length+'</span></div>';
 if(!rows.length)return h+'<div class="empty">no indicators recorded</div>';
 h+='<table class="grid"><tr><th>indicator</th><th>seen in</th></tr>';
 rows.slice(0,st.page).forEach(function(r){
  h+='<tr><td class="mono">'+esc(r.i)+'</td><td class="wrap">'+esc(r.w)+'</td></tr>';});
 h+='</table>';
 if(rows.length>st.page)h+='<div class="more" id="more">show more ('+
   (rows.length-st.page)+' left)</div>';
 return h;
}

/* ---------- render + wiring ---------- */
function render(){
 /* A table renders itself - it owns its sort, its column filters and its
    caret, none of which survive being rebuilt from a string. */
 if(st.view==='table'){tRender();markNav();return;}
 var m=el('main');
 m.innerHTML=st.view==='findings'?viewFindings():
             st.view==='attack'?viewAttack():
             st.view==='timeline'?viewTimeline():
             st.view==='iocs'?viewIocs():viewOverview();
 wire();
 markNav();
 el('nFind').textContent=findings().length;
}
function wire(){
 var q=el('q');
 if(q){
  /* The bucket index only means something against the chart it was clicked on;
     a new query rebuilds the buckets, so the selection has to go with it. */
  q.oninput=function(){st.q=q.value;st.page=400;st.bucket=null;render();
   var n=el('q');if(n){n.focus();n.setSelectionRange(n.value.length,n.value.length);}};
 }
 var c=el('cat');
 if(c)c.onchange=function(){st.cat=c.value;st.page=400;render();};
 var more=el('more');
 if(more)more.onclick=function(){st.page+=400;render();};

 [].forEach.call(document.querySelectorAll('[data-tech]'),function(x){
  x.onclick=function(){st.tech=x.getAttribute('data-tech');setView('findings');};});
 [].forEach.call(document.querySelectorAll('[data-clear]'),function(x){
  var k=x.getAttribute('data-clear');
  x.onclick=function(){st[k]=(k==='bucket')?null:'';render();};});
 [].forEach.call(document.querySelectorAll('.histo.click .col'),function(c){
  c.onclick=function(){
   var i=+c.getAttribute('data-b');
   st.bucket=(st.bucket===i)?null:i;st.page=400;render();};});
 [].forEach.call(document.querySelectorAll('.row'),function(r){
  r.onclick=function(){st.sel=+r.getAttribute('data-id');render();};});
 [].forEach.call(document.querySelectorAll('.card[data-sev]'),function(cd){
  cd.onclick=function(){
   var s=cd.getAttribute('data-sev');
   SEV.forEach(function(x){st.sev[x]=(x===s);});
   chips();setView('findings');};});
 [].forEach.call(document.querySelectorAll('.bar[data-act]'),function(b){
  b.onclick=function(){
   var a=b.getAttribute('data-act'),k=b.getAttribute('data-k');
   if(a==='cat'){st.cat=k;setView('findings');}
   else if(a==='tech'){st.tech=k;setView('findings');}};});
}
/* Views first, then every table under its category. A page written without
   the triage half (one table exported on its own) shows only the tables, and
   one written without tables is the console alone - the same nav covers both
   rather than each half carrying its own. */
function buildNav(){
 var h='';
 if(D.findings.length||D.events.length){
  VIEWS.forEach(function(v){
   var n=v[2]==null?'':'<span class="n"'+(v[0]==='findings'?' id="nFind"':'')+'>'+
     (v[0]==='findings'?'':v[2])+'</span>';
   h+='<a data-v="'+v[0]+'">'+v[1]+n+'</a>';});}
 if(IDX.length){
  var byCat={},order=[];
  IDX.forEach(function(t){
   if(!byCat[t.category]){byCat[t.category]=[];order.push(t.category);}
   byCat[t.category].push(t);});
  h+='<div class="sec"></div>';
  order.forEach(function(c){
   h+='<div class="cat">'+esc(c||'Other')+'</div>';
   byCat[c].forEach(function(t){
    h+='<a class="tbl" data-t="'+esc(t.name)+'" title="'+esc(t.title)+'"><span>'+
       esc(t.name)+'</span><span class="n">'+t.rows.toLocaleString()+'</span></a>';});});}
 el('nav').innerHTML=h;
 [].forEach.call(document.querySelectorAll('nav a'),function(a){
  a.onclick=function(){
   var t=a.getAttribute('data-t');
   setView(t?'table':a.getAttribute('data-v'),t);};});
}
function start(){
 chips();
 buildNav();
 if(el('nFind'))el('nFind').textContent=D.findings.length;
 var v=(location.hash||'').replace('#','');
 if(v.indexOf('t/')===0&&TB[v.slice(2)])setView('table',v.slice(2));
 else if(['overview','findings','attack','timeline','iocs'].indexOf(v)>=0&&
         (D.findings.length||D.events.length))setView(v);
 else if(D.findings.length||D.events.length)setView('overview');
 else if(IDX.length)setView('table',IDX[0].name);
 document.onkeydown=function(e){
  if(e.target.tagName==='INPUT'||e.target.tagName==='SELECT')return;
  var k=e.key;
  if(k==='/'){var q=el('q');if(q){q.focus();e.preventDefault();}}
  if(k>='1'&&k<='5'&&D.findings.length)setView(['overview','findings','attack',
   'timeline','iocs'][+k-1]);
  /* j/k walk the finding list without leaving the keyboard, the way the
     console report is read. */
  if(st.view==='findings'&&(k==='j'||k==='k')){
   var fs=findings();fs.sort(function(a,b){
    var d=sevRank(a.sev)-sevRank(b.sev);if(d)return d;
    return (b.last||'').localeCompare(a.last||'');});
   var i=-1;fs.forEach(function(f,n){if(f.id===st.sel)i=n;});
   i=Math.max(0,Math.min(fs.length-1,i+(k==='j'?1:-1)));
   if(fs[i]){st.sel=fs[i].id;render();
    var sel=document.querySelector('.row.sel');
    if(sel&&sel.scrollIntoView)sel.scrollIntoView({block:'nearest'});}}};
}


/* ---------- tables ---------- */
var sortCol=-1,sortAsc=true;
var colFilters=[],lay=null;   /* per-column filter text; measured column tLayout */



/* Per-column width from the rows on screen, not from the widest value in the
   table: sizing to the maximum lets a single long cell decide the tLayout, and
   every other column ends up too narrow to read. The 90th percentile fits the
   rows being scanned and leaves the outliers to wrap or scroll in place.
   Recomputed per tRender so it follows the filter - narrowing to one noisy
   process should retighten the columns around what is left. */
function tLayout(t,rows,cap){
 var n=t.columns.length,out=[],step=Math.max(1,Math.floor(cap/200));
 for(var j=0;j<n;j++){
  var lens=[],num=(rows.length>0),seen=0;
  for(var i=0;i<cap;i+=step){
   var v=rows[i][j];if(v===undefined||v===null||v==='')continue;
   v=String(v);seen++;
   if(num&&!/^-?[\\d.]+$/.test(v))num=false;
   var parts=v.split('\\n'),m=0;
   for(var k=0;k<parts.length;k++)if(parts[k].length>m)m=parts[k].length;
   lens.push(m);
  }
  lens.sort(function(a,b){return a-b;});
  var p90=lens.length?lens[Math.min(lens.length-1,Math.floor(lens.length*0.9))]:0;
  var chars=Math.max(t.columns[j].length+2,p90);
  /* Short columns keep their content on one line; long ones wrap. The
     threshold sits above a UTC timestamp (19 chars) on purpose - wrapping
     '2026-06-11 12:24:57' onto two lines doubles the height of every row in
     the table for no gain. */
  var nw=(p90<=28&&!num)||(num&&seen);
  var px=Math.round(chars*7.2)+18;
  out.push({w:Math.max(64,Math.min(nw?300:460,px)),num:(num&&seen>0),nw:nw});
 }
 return out;
}
function tSortRows(rows){
 return rows.slice().sort(function(a,b){
  var x=a[sortCol]||'',y=b[sortCol]||'';
  var nx=parseFloat(x),ny=parseFloat(y);
  var c=(!isNaN(nx)&&!isNaN(ny)&&/^-?[\\d.]+$/.test(x)&&/^-?[\\d.]+$/.test(y))
       ?nx-ny:String(x).localeCompare(String(y));
  return sortAsc?c:-c;});
}
/* The global box searches the whole row; a per-column box searches only its
   own column. They combine with AND, which is what makes them worth having
   separately - 'sshd' anywhere plus user=root is a different question from
   either on its own. */
function tMatching(t){
 var q=(st.tq||'').toLowerCase();
 var rows=t.rows;
 if(q){rows=rows.filter(function(r){return r.join(' ').toLowerCase().indexOf(q)>=0;});}
 var act=[];
 for(var i=0;i<colFilters.length;i++){
  if(colFilters[i]){act.push([i,colFilters[i].toLowerCase()]);}}
 if(act.length){rows=rows.filter(function(r){
  for(var k=0;k<act.length;k++){
   var v=r[act[k][0]];v=(v===undefined||v===null)?'':String(v);
   if(v.toLowerCase().indexOf(act[k][1])<0){return false;}}
  return true;});}
 if(sortCol>=0){rows=tSortRows(rows);}
 return rows;
}
/* Excel offers a tick-list of a column's distinct values; the same idea here
   is a <datalist>, so a low-cardinality column (level, user, process, status)
   suggests what is actually in it instead of making you guess. Columns whose
   values are long or nearly unique get no list - a dropdown of 60 different
   log messages is noise. */
function tOptions(t,j){
 var seen={},n=0,step=Math.max(1,Math.floor(t.rows.length/4000));
 for(var i=0;i<t.rows.length;i+=step){
  var v=t.rows[i][j];v=(v===undefined||v===null)?'':String(v);
  if(!v){continue;}
  if(v.length>48){return null;}
  if(!seen[v]){seen[v]=1;n++;if(n>60){return null;}}}
 return n>1?Object.keys(seen).sort():null;
}
function tBodyHtml(t,rows,cap){
 var sevIdx=t.columns.indexOf('severity'),h='';
 for(var i=0;i<cap;i++){
  var r=rows[i];h+='<tr>';
  for(var j=0;j<t.columns.length;j++){
   var v=r[j]===undefined?'':r[j];
   var cls=(sevIdx===j)?'sev-'+esc(v):(lay[j].num?'num':'');
   if(lay[j].nw){cls+=(cls?' ':'')+'nw';}
   h+='<td'+(cls?' class="'+cls+'"':'')+'><div class="c">'+esc(v)+'</div></td>';}
  h+='</tr>';}
 return h;
}
/* Only the tbody and the counters are rebuilt, never the filter inputs:
   replacing an input while it has focus loses the caret, which makes it
   impossible to type more than one character into a filter. */
function tRefresh(){
 var t=TB[st.table];if(!t){return;}
 var rows=tMatching(t);
 var cap=rows.length>t.cap?t.cap:rows.length;
 var tb=document.getElementById('tb');
 if(tb){tb.innerHTML=tBodyHtml(t,rows,cap);}
 var mn=document.getElementById('matchn');
 if(mn){mn.textContent=rows.length.toLocaleString()+' matching';}
 var note=document.getElementById('note');
 if(note){note.innerHTML=rows.length>cap?'Showing first '+cap.toLocaleString()+
  ' of '+rows.length.toLocaleString()+' matching rows. Narrow the filter, or use'+
  ' the CSV / JSON export for everything.':'';}
 var none=document.getElementById('none');
 if(none){none.style.display=rows.length?'none':'block';}
 [].forEach.call(document.querySelectorAll('tr.f input'),function(inp){
  inp.classList.toggle('on',!!inp.value);});
}
function tRender(){
 var t=TB[st.table];if(!t){return;}
 var rows=tMatching(t);
 var cap=rows.length>t.cap?t.cap:rows.length;
 var h='<h2>'+esc(t.title)+' <span class="badge">'+t.name+'</span></h2>';
 h+='<p class="desc">'+esc(t.description||'');
 if(t.sources&&t.sources.length){h+='<br>sources: '+esc(t.sources.join(', '));}
 h+='</p>';
 h+='<div class="controls"><input type="search" id="q" placeholder="filter rows '+
    'in this table..." value="'+esc(st.tq||'')+'"><span class="badge">'+t.row_count.toLocaleString()+
    ' rows total</span><span class="badge" id="matchn">'+rows.length.toLocaleString()+
    ' matching</span><button class="clr" id="clr">clear filters</button>';
 if(t.row_count>t.rows.length){h+='<span class="badge warn">HTML capped at '+
   t.rows.length.toLocaleString()+' \\u2014 full data in the CSV / JSON export</span>';}
 h+='</div>';
 /* the layout is measured once per table, not per keystroke - columns that
    resize while you are typing into them are worse than columns that do not */
 lay=tLayout(t,rows.length?rows:t.rows,Math.max(cap,1));
 /* table-layout:fixed only honours the <colgroup> if the table itself has a
    width. Left to 'auto' the browser falls back to shrink-to-fit and sizes
    column 1 from its content - which is how IOCS ended up with a 3567px
    'indicator' beside a 58px 'seen_in'. Sum the columns and say so. */
 var total=0,elastic=-1,widest=0;
 lay.forEach(function(L,i){total+=L.w;
  /* only a wrapping column is a candidate: extra width buys it another line
     of visible text, whereas a one-line column just gains blank space */
  if(!L.num&&!L.nw&&L.w>widest){widest=L.w;elastic=i;}});
 var avail=Math.max(320,(document.getElementById('main').clientWidth||0)-38);
 var stretch=total<avail;
 /* Hand the slack to the widest wrapping column rather than letting fixed
    layout spread it proportionally - a 297px 'seen_in_count' is padding, the
    same pixels on 'seen_in' are another line of the value worth reading. With
    no wrapping column to give it to (a table of short fields), fall back to
    proportional so the table still fills the pane instead of stretching one
    column to 1000px of whitespace. */
 h+='<table class="tbl" style="width:'+(stretch?avail:total)+'px"><colgroup>';
 lay.forEach(function(L,i){
  h+=(stretch&&i===elastic)?'<col>':'<col style="width:'+L.w+'px">';});
 h+='</colgroup><thead><tr id="hdr">';
 t.columns.forEach(function(c,i){
  var mark=sortCol===i?(sortAsc?' \\u25b2':' \\u25bc'):'';
  h+='<th data-i="'+i+'" title="'+esc(c)+' \\u2014 click to sort">'+
     '<span class="lbl">'+esc(c)+mark+'</span></th>';});
 h+='</tr><tr class="f" id="frow">';
 var lists='';
 t.columns.forEach(function(c,i){
  var opts=tOptions(t,i),lid='';
  if(opts){lid='dl_'+i;
   lists+='<datalist id="'+lid+'">';
   opts.forEach(function(o){lists+='<option value="'+esc(o).replace(/"/g,'&quot;')+'">';});
   lists+='</datalist>';}
  h+='<th><input data-i="'+i+'" placeholder="filter '+esc(c)+'"'+
     (lid?' list="'+lid+'"':'')+' value="'+esc(colFilters[i]||'').replace(/"/g,'&quot;')+
     '"></th>';});
 h+='</tr></thead><tbody id="tb">'+tBodyHtml(t,rows,cap)+'</tbody></table>'+lists;
 h+='<div class="empty" id="none"'+(rows.length?' style="display:none"':'')+
    '>No rows match.</div>';
 h+='<p class="desc" id="note">'+(rows.length>cap?'Showing first '+cap.toLocaleString()+
  ' of '+rows.length.toLocaleString()+' matching rows. Narrow the filter, or use'+
  ' the CSV / JSON export for everything.':'')+'</p>';
 document.getElementById('main').innerHTML=h;
 tWire();
}
function tWire(){
 [].forEach.call(document.querySelectorAll('#hdr th'),function(th){
  th.onclick=function(){var i=+th.getAttribute('data-i');
   if(sortCol===i){sortAsc=!sortAsc;}else{sortCol=i;sortAsc=true;}
   /* repaint the sort arrows in place rather than re-rendering the head,
      which would take the filter inputs and their values with it */
   [].forEach.call(document.querySelectorAll('#hdr th'),function(o){
    var j=+o.getAttribute('data-i');
    o.querySelector('.lbl').textContent=TB[st.table].columns[j]+
     (sortCol===j?(sortAsc?' \\u25b2':' \\u25bc'):'');});
   tRefresh();};});
 [].forEach.call(document.querySelectorAll('tr.f input'),function(inp){
  var i=+inp.getAttribute('data-i');
  inp.oninput=function(){colFilters[i]=inp.value;tRefresh();};
  /* the input lives inside a th whose click handler sorts - without this,
     clicking into a filter box would reorder the table under the cursor */
  inp.onclick=function(e){e.stopPropagation();};});
 var q=el('q');
 if(q)q.oninput=function(){st.tq=q.value;tRefresh();};
 var clr=document.getElementById('clr');
 if(clr){clr.onclick=function(){
  colFilters=[];st.tq='';var qq=el('q');if(qq)qq.value='';
  [].forEach.call(document.querySelectorAll('tr.f input'),function(i){i.value='';});
  tRefresh();};}
 /* glue the filter row to the bottom of the label row, measured rather than
    assumed - the label height moves with the font and the zoom level */
 var hdr=document.getElementById('hdr'),frow=document.getElementById('frow');
 if(hdr&&frow){
  var top=hdr.getBoundingClientRect().height;
  [].forEach.call(frow.querySelectorAll('th'),function(th){th.style.top=top+'px';});}
}

start();
"""


def _triage_payload(tri, opts):
    """The triage half of the page's data: findings, events, indicators.

    Split out from the writer because the page it feeds is the same page that
    carries the artifact tables - one file, one nav, one set of severity chips
    over both halves. A run that only exported one table passes no triage at
    all and gets the tables alone.
    """
    counts = {s: sum(1 for f in tri.findings if f.severity == s) for s in SEVERITIES}

    findings, names, tactics = [], {}, {}
    for i, f in enumerate(tri.findings):
        techs = []
        for t in _gui_techniques(f.mitre):
            if t not in techs:
                techs.append(t)
            if t not in names:
                lbl = _gui_label(f.mitre, t)
                if lbl:
                    names[t] = lbl
            # A sub-technique inherits its parent's column.
            tactics[t] = ATTACK_TACTICS.get(t.split(".")[0], "Other")
        ev = f.evidence[:400]
        # One lowercased haystack per finding, built once here rather than on
        # every keystroke in the browser: the search box filters the whole set
        # on each character, and re-joining evidence there is what makes a
        # 20,000-finding page feel slow.
        hay = " ".join([f.title, f.detail, f.category, f.source, f.mitre] + ev).lower()
        findings.append({
            "id": i, "sev": f.severity, "cat": f.category, "title": f.title,
            "detail": f.detail, "src": f.source, "techs": techs,
            "seen": f.seen_text(), "last": f.last_seen or f.first_seen,
            "count": f.count, "ev": ev,
            "more": max(0, len(f.evidence) - len(ev)), "hay": hay,
        })

    events = []
    # Sorted before it is capped: analyzers append as they run, and the rule
    # hunts append after everything else, so the tail of the list is the last
    # thing parsed rather than the last thing that happened. Uncapped that is
    # only untidy; capped it silently drops the wrong events, and the chart
    # downstream reads the first event as the start of time.
    for e in sorted(tri.events, key=lambda x: x.ts)[-opts.timeline_limit:]:
        events.append({
            "t": e.ts.strftime("%Y-%m-%d %H:%M:%S"),
            # Epoch seconds alongside the string: the activity chart buckets on
            # it, and re-parsing 3000 timestamps in the browser is wasted work.
            # An analyzer that built a naive datetime still meant UTC, so it is
            # stamped as such rather than drifting by the examiner's offset.
            "e": int((e.ts if e.ts.tzinfo else
                      e.ts.replace(tzinfo=timezone.utc)).timestamp()),
            "s": e.severity, "c": e.category,
            "d": trunc(e.description, 300),
        })

    iocs = [{"i": k, "w": ", ".join(sorted(v))} for k, v in sorted(tri.iocs.items())]

    return {
        "meta": [[k, str(v)] for k, v in tri.meta.items() if v],
        "counts": counts, "findings": findings, "events": events,
        "iocs": iocs, "names": names, "tactics": tactics,
    }


# ---------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Parse a UAC or Velociraptor Linux collection and highlight "
                    "critical / interesting events.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n"
               "  python linsight.py ./uac-host-linux-20260324\n"
               "  python linsight.py collection.tar.gz --html report.html --json out.json\n"
               "  python linsight.py ./coll --min-severity HIGH --timeline timeline.csv\n"
               "  python linsight.py ./coll --pivot /dev/shm/kit --pivot libymv.so.3\n"
               "  python linsight.py ./coll --export ./triage_out\n"
               "  python linsight.py ./coll --csv-dir ./tables --quiet\n"
               "  python linsight.py ./coll --export ./live --scope live\n"
               "  python linsight.py ./coll --export ./disk --scope offline\n"
               "  python linsight.py ./coll --update-sigma   # fetch SigmaHQ, then hunt\n"
               "  python linsight.py ./coll --sigma-cached   # hunt offline with the cache\n"
               "  python linsight.py --update-sigma          # refresh the cache only\n")
    ap.add_argument("collection", nargs="?",
                    help="collection directory, .tar, .tar.gz or .zip - UAC "
                         "output or a Velociraptor offline collector zip; the "
                         "layout is detected, not declared. Optional only when "
                         "--update-sigma is refreshing rules on its own")
    ap.add_argument("--min-severity", default="INFO", choices=SEVERITIES,
                    help="lowest severity to print on the console (default INFO)")
    ap.add_argument("--window", type=int, default=72, metavar="H",
                    help="incident window in hours before collection time (default 72)")
    ap.add_argument("--max-evidence", type=int, default=25,
                    help="evidence lines printed per finding on the console (default 25)")
    ap.add_argument("--json", metavar="PATH", help="write full findings as JSON")
    ap.add_argument("--html", metavar="PATH", help="write a self-contained HTML report")
    ap.add_argument("--timeline", metavar="PATH", help="write the event timeline as CSV")
    ap.add_argument("--show-timeline", action="store_true",
                    help="also print the timeline on the console")
    ap.add_argument("--timeline-show", type=int, default=60,
                    help="timeline rows to print with --show-timeline (default 60)")
    ap.add_argument("--timeline-limit", type=int, default=3000,
                    help="max file events kept in the timeline (default 3000)")
    ap.add_argument("--pivot", action="append", metavar="TERM",
                    help="search every collected artifact for TERM, case-"
                         "insensitively (repeatable). Use '@file' to read a "
                         "list of indicators, one per line, '#' for comments - "
                         "all terms are matched in one pass, so a long list "
                         "costs no more than a short one.")
    ap.add_argument("--pivot-limit", type=int, default=500,
                    help="max indicators to search for (default 500)")
    ap.add_argument("--deep", action="store_true",
                    help="also scan memory_dump/*strings* (slow, multi-GB)")
    rg = ap.add_argument_group(
        "detection rules",
        "Hunt with your own rules. Both engines are built in - nothing to "
        "install - and cover the constructs Linux IR rules use; PyYAML is used "
        "for Sigma if it happens to be importable. A rule the engine cannot "
        "represent faithfully is rejected and listed in RULE_ERRORS rather "
        "than half-applied, because a rule that silently matches nothing looks "
        "exactly like a clean result. Sigma rules go stale the same way: "
        "--update-sigma keeps a local copy of the public ruleset current, and "
        "is the only thing here that uses the network.")
    rg.add_argument("--yara", action="append", metavar="PATH",
                    help="YARA rule file or directory (repeatable). Scans the "
                         "collected filesystem and the per-process memory "
                         "strings; add --deep for the memory image strings.")
    rg.add_argument("--no-hunt", action="store_true",
                    help="skip the built-in offensive-tool keyword sweep. The "
                         "sweep reads the normalised tables, so it costs the "
                         "table build even when no export was asked for - on a "
                         "mid-size collection that is roughly 12s to 65s. Use "
                         "this when you want the analyzer findings only.")
    rg.add_argument("--keywords", action="append", metavar="PATH",
                    help="file of extra terms to hunt for, one per line "
                         "(repeatable). Matched the same way as the built-in "
                         "tool names, across every artifact - use it for "
                         "case-specific names, hostnames or filenames.")
    rg.add_argument("--sigma", action="append", metavar="PATH",
                    help="Sigma rule file or directory (repeatable). Runs "
                         "against the normalised tables - auth, journal, "
                         "auditd, processes, cron, web logs - routed by each "
                         "rule's logsource.")
    rg.add_argument("--update-sigma", action="store_true",
                    help="fetch the current SigmaHQ ruleset into a local cache "
                         "and hunt with it. Keeps the rules that can reach a "
                         "table this tool builds - the Linux and web-log ones - "
                         "and skips the ~3000 Windows event log rules, which "
                         "would only slow the load and fill RULE_ERRORS. The "
                         "fetch is conditional: an unchanged ruleset is a 304 "
                         "and no download. Works with no collection argument "
                         "when you just want the cache refreshed.")
    rg.add_argument("--sigma-cached", action="store_true",
                    help="hunt with the cached ruleset as last fetched, without "
                         "touching the network - the offline half of "
                         "--update-sigma.")
    rg.add_argument("--sigma-dir", metavar="DIR",
                    help="where the cached ruleset lives (default "
                         "~/.linsight/sigma, or $LINSIGHT_SIGMA_DIR). It is a "
                         "plain directory of .yml files, so --sigma takes it "
                         "too.")
    rg.add_argument("--sigma-source", metavar="URL|ZIP|DIR",
                    help="what --update-sigma reads instead of SigmaHQ's "
                         "master zip: another ruleset's URL, a zip already "
                         "downloaded, or a directory - for the evidence "
                         "workstation with no route out, and for your own "
                         "rule repository.")
    rg.add_argument("--sigma-all", action="store_true",
                    help="cache every rule --update-sigma finds, including the "
                         "ones for platforms this tool builds no table for. "
                         "SIGMA_COVERAGE then says, rule by rule, why each one "
                         "could not fire here.")
    tg = ap.add_argument_group(
        "artifact tables",
        "Normalise every interesting artifact into browsable grids - one table "
        "per artifact type, with a source column keeping the originating file.")
    tg.add_argument("--scope", choices=TableBuilder.SCOPES, default="full",
                    help="which half of the collection to build tables from: "
                         "'live' = the volatile snapshot (processes, sockets, "
                         "open files, modules, live sessions); 'offline' = what "
                         "a dead-box exam recovers (filesystem, config, logs, "
                         "persistence, bodyfile); 'full' = both (default). "
                         "Findings and the timeline always use the whole "
                         "collection - they are cross-artifact by nature.")
    tg.add_argument("--export", metavar="DIR",
                    help="write every table format into DIR "
                         "(csv/ and json/, one file per table, plus "
                         "browser.html - the console)")
    tg.add_argument("--csv-dir", metavar="DIR",
                    help="write one CSV per table into DIR")
    tg.add_argument("--tables-json", metavar="PATH",
                    help="write every table as a single JSON document")
    tg.add_argument("--tables-html", metavar="PATH",
                    help="write the self-contained console: findings, ATT&CK, "
                         "timeline, indicators and every artifact table")
    tg.add_argument("--process-map", metavar="PATH",
                    help="write ONLY the correlated one-row-per-PID process table "
                         "to a single file (.csv/.html/.json by extension)")
    tg.add_argument("--html-rows", type=int, default=2000, metavar="N",
                    help="rows per table embedded in the HTML browser (default 2000; "
                         "the CSV and JSON exports always get everything)")

    ap.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    ap.add_argument("--quiet", action="store_true", help="suppress the console report")
    ap.add_argument("--debug", action="store_true", help="re-raise analyzer exceptions")
    ap.add_argument("--low-memory", action="store_true",
                    help="spill large tables to a temp file instead of holding "
                         "every row in memory - roughly halves peak memory on a "
                         "large collection and costs about 20%% of the run time")
    ap.add_argument("--timing", action="store_true",
                    help="report wall time per table extractor and per output "
                         "writer - use it to find which artifact a slow "
                         "collection is spending its minutes on")
    opts = ap.parse_args(argv)

    # set before any table is built, because a table that has already buffered
    # its rows cannot be made to have spilled them
    if opts.low_memory and "LINSIGHT_SPILL_AFTER" not in os.environ:
        Table.SPILL_AFTER = 20000

    opts.color = (not opts.no_color) and sys.stdout.isatty()
    if opts.color and os.name == "nt":
        try:                                    # enable VT sequences on Windows
            import ctypes
            k = ctypes.windll.kernel32
            k.SetConsoleMode(k.GetStdHandle(-11), 7)
        except Exception:
            opts.color = False

    if not opts.quiet:
        print_banner(opts.color)

    # Rules first: refreshing the cache is the one thing worth doing without a
    # collection at all, and a fetch that fails should say so before a tar is
    # opened rather than after four minutes of parsing.
    # Flags that only mean something next to another flag: silently ignoring
    # one of these ends with a hunt that ran the wrong rules, or none
    if opts.sigma_source and not opts.update_sigma:
        ap.error("--sigma-source is where --update-sigma fetches from; to hunt "
                 "with rules already on disk use --sigma")
    if opts.sigma_all and not opts.update_sigma:
        ap.error("--sigma-all is what --update-sigma keeps; --sigma reads every "
                 "rule it is given already")
    if opts.sigma_dir and not (opts.update_sigma or opts.sigma_cached):
        ap.error("--sigma-dir is the cache --update-sigma writes and "
                 "--sigma-cached reads; to hunt with any other directory of "
                 "rules use --sigma")
    opts.sigma_note = ""
    if opts.update_sigma or opts.sigma_cached:
        cache = sigma_cache_dir(opts.sigma_dir)
        # The same rule the output paths follow: a ruleset written under the
        # collection contaminates it, and the next run would read it back as a
        # collected artifact.
        if opts.collection and os.path.isdir(opts.collection):
            base = os.path.abspath(opts.collection)
            if cache == base or cache.startswith(base + os.sep):
                ap.error("refusing to keep the rule cache inside the "
                         "collection:\n      %s\n    choose a --sigma-dir "
                         "outside\n      %s" % (cache, base))
        if opts.update_sigma:
            update_sigma_rules(cache, opts.sigma_source, opts.sigma_all,
                               quiet=opts.quiet)
        elif not sigma_cache_count(cache):
            ap.error("no cached Sigma rules in %s - run --update-sigma once to "
                     "fetch them" % cache)
        m = sigma_cache_manifest(cache)
        # Kept in the report metadata as well as on stderr: which ruleset, of
        # which date, produced a hit is part of the hit.
        opts.sigma_note = ("%d rule(s) from %s%s"
                           % (sigma_cache_count(cache),
                              m.get("source") or cache,
                              ", fetched %s UTC" % m["fetched_utc"]
                              if m.get("fetched_utc") else ""))
        if not opts.update_sigma:
            status("[*] sigma: cached %s" % opts.sigma_note)
        opts.sigma = (opts.sigma or []) + [cache]

    if not opts.collection:
        if opts.update_sigma:
            return 0                    # a rule refresh on its own
        ap.error("a collection is required (or --update-sigma on its own to "
                 "refresh the rule cache)")

    if not os.path.exists(opts.collection):
        ap.error("collection not found: %s" % opts.collection)

    col = Collection(opts.collection)
    status("[*] loaded %s collection: %d files, root prefix '%s', rootfs dirs %s"
          % (col.kind, len(col._names), col.prefix or "(none)", ", ".join(col.rootfs_dirs)))

    _check_output_paths(col, opts)      # before any work, for every output flag

    tri = Triage(col, opts)
    tri.run()
    if opts.sigma_note:
        tri.meta["Sigma ruleset"] = opts.sigma_note

    # Rule hits are findings, and the console report, --json and --html are all
    # written from the finding list - so when rules are in play the tables have
    # to be built first. The build is reused by the export below rather than
    # repeated.
    tb = None
    asked_for_rules = bool(opts.yara or opts.sigma or opts.keywords)
    # --process-map on its own is a targeted extraction of one table, not a
    # triage run: building all 70 tables to hunt would turn a seconds-long
    # command into a minute. Explicit rule flags still win over that.
    map_only = bool(opts.process_map) and not any(
        (opts.export, opts.csv_dir, opts.tables_json, opts.tables_html))
    if (asked_for_rules or not opts.no_hunt) and not (map_only and
                                                      not asked_for_rules):
        _check_output_paths(col, opts)
        tb = TableBuilder(col, tri)
        tb.build(verbose=not opts.quiet, scope=getattr(opts, "scope", "full"))

    if not opts.quiet:
        print_console(tri, opts)
    if opts.json:
        write_json(tri, opts.json)
    if opts.html:
        write_html(tri, opts.html, opts)
    if opts.timeline:
        write_timeline(tri, opts.timeline)

    if any((opts.export, opts.csv_dir, opts.tables_json,
            opts.tables_html, opts.process_map)):
        export_tables(tri, col, opts, tb)

    crit = sum(1 for f in tri.findings if f.severity == "CRITICAL")
    high = sum(1 for f in tri.findings if f.severity == "HIGH")
    return 2 if crit else (1 if high else 0)


if __name__ == "__main__":
    sys.exit(main())
