# -*- coding: utf-8 -*-
from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from datetime import timedelta
from datetime import timezone
import atexit
import itertools
import json
import os
import re
import shutil
import sqlite3
import tempfile
import time

from .constants import VERSION
from .model import SEVERITIES
from .term import Progress, status, trunc
from .common import (
    BASELINE_SUID, FAILED_LOGIN_RULES, HACKTOOL_CAT, HACKTOOL_CTX_CAT,
    HACKTOOL_CTX_RE, HACKTOOL_PATH_CAT, HACKTOOL_PATH_RE, HACKTOOL_RE,
    HACKTOOL_SEVERITY, HACKTOOL_VARIANT_CAP,
    SENSITIVE_FILE_BENIGN, SENSITIVE_FILE_EXPECTED,
    SENSITIVE_FILE_RE, PRIVATE_KEY_DIR, PUBLIC_CERT_DIR,
    HACKTOOL_VARIANT_OTHER, NDJSON_TIME_COLUMNS, PRIVILEGED_GROUPS,
    PRIV_HINT_RE, TMPFS_DIRS, _printable, _ts_text, _tz_delta, clean_addr,
    _trie_alt,
    epoch,
    hexip_to_str, human_size, ioc_mitre, ioc_type, match_failed_login,
    norm_ip, norm_log_ts, span_add, split_hostport, variant_add)
from .decode import (
    CUPS_LEVELS, CUPS_RE, JOURNAL_MAGIC, SYSLOG_PRIORITY, UTMP_TYPES,
    decompress_bytes, parse_faillog, parse_journal, parse_lastlog, parse_utmp,
    split_log_line)
from .collect import (
    VelociraptorResults, _velo_cell, _velo_table_name, velo_get)
from .rules import (
    Keywords, Row, _win_long, eval_sigma, parse_sigma, parse_yara)
from .triage import Triage



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


def _human_duration(seconds):
    """Seconds -> '3d 04h', '2h 14m', '4m 55s', '41s'.

    Every unit is labelled. `last` writes a four-minute session as '(00:04)'
    and this followed it, which was fine while wtmp was the only source:
    wtmp sessions are minutes at least. PAM sessions are often seconds, so
    the column now holds '41s' and '00:04' side by side, and there is no
    reading of '00:04' that is obviously four minutes rather than four
    seconds. duration_seconds is the one to sort on either way.
    """
    if seconds in ("", None):
        return ""
    try:
        n = int(seconds)
    except (TypeError, ValueError):
        return ""
    if n < 0:
        return ""
    if n < 60:
        return "%ds" % n
    days, rest = divmod(n, 86400)
    hours, rest = divmod(rest, 3600)
    mins, secs = divmod(rest, 60)
    if days:
        return "%dd %02dh" % (days, hours)
    if hours:
        return "%dh %02dm" % (hours, mins)
    return "%dm %02ds" % (mins, secs)


#: 'pam_unix(sshd:session): session opened ...' -> the service that opened it.
PAM_SERVICE_RE = re.compile(r"pam_\w+\(([^:)]+):session\)")

#: How long before a session opens an addressed line may be and still be
#: taken as belonging to it. sshd writes 'Accepted password' and 'session
#: opened' in the same second; the slack is for a slow keyboard-interactive
#: or two-factor prompt. A pid is reused eventually, and the point of the
#: window is that a session does not inherit the address of whatever last
#: held its pid - days earlier, or on the boot before.
ADDRESS_WINDOW = 300


def _address_for(rows, start, ip, tty):
    """Fill a session's address in from the newest addressed line before it.

    Nothing is filled from a line after the session opened, or from one so
    far before it that the pid has plainly been reused since.
    """
    for when, was_ip, was_tty in reversed(rows or ()):
        gap = _span_seconds(when, start)
        if gap == "" or gap > ADDRESS_WINDOW:
            continue
        return ip or was_ip, tty or was_tty
    return ip, tty


def _span_seconds(start, end):
    """Seconds between two 'YYYY-MM-DD HH:MM:SS' strings, or ''."""
    if not start or not end:
        return ""
    try:
        a = datetime.strptime(str(start)[:19], "%Y-%m-%d %H:%M:%S")
        b = datetime.strptime(str(end)[:19], "%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return ""
    secs = int((b - a).total_seconds())
    # a syslog year rollover, or a clock that moved: a negative span is not a
    # duration, and printing one would be worse than printing none
    return secs if secs >= 0 else ""


def _end_after(start, seconds):
    """A 'YYYY-MM-DD HH:MM:SS' start plus a duration -> when it ended, or ''.

    `last` prints the logout as a bare 'HH:MM' - 'Sun Jan  4 13:40 - 08:56'
    is a session that ran 154 days, and the 08:56 is the clock on the day it
    ended, not the day it began. So the printed end cannot be read as a time
    on its own, and the duration printed beside it can: start plus duration is
    the same instant, said a way that survives being sorted.
    """
    if not start or seconds in ("", None):
        return ""
    try:
        dt = datetime.strptime(str(start)[:19], "%Y-%m-%d %H:%M:%S")
        return (dt + timedelta(seconds=int(seconds))).strftime(
            "%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError, OverflowError):
        return ""


def _duration_seconds(text):
    """`last`'s own '(01:23)' or '(2+03:04)' -> seconds.

    'still logged in' and 'gone - no logout' start with a letter and come back
    empty rather than zero: a session of unknown length is not a session of no
    length, and a zero here would sort with the forty-second ones.
    """
    s = str(text or "").strip().strip("()")
    if not s or not s[0].isdigit():
        return ""
    days = 0
    if "+" in s:
        head, _, s = s.partition("+")
        try:
            days = int(head)
        except ValueError:
            return ""
    try:
        nums = [int(p) for p in s.split(":")]
    except ValueError:
        return ""
    if len(nums) == 2:
        return days * 86400 + nums[0] * 3600 + nums[1] * 60
    if len(nums) == 3:
        return days * 86400 + nums[0] * 3600 + nums[1] * 60 + nums[2]
    return ""


def _fs_ts(when):
    """A filesystem timestamp as the string every other table prints, or ''."""
    if not when:
        return ""
    try:
        return when.strftime("%Y-%m-%d %H:%M:%S")
    except (AttributeError, ValueError):
        return ""


def _netstat_hostport(addr):
    """Split the way netstat prints, which is not the way ss does.

    netstat never brackets an IPv6 address: it writes ":::80" for
    every address on port 80, and "::1:631" for loopback on 631. The
    last colon is the separator whatever the address looks like.
    Read as a bare IPv6 address instead - which is what a general
    splitter has to assume, because "::ffff:1.2.3.4" really is one -
    the port is dropped, and this host's own IPv6 listeners on 80
    and 22 were recorded as listening on nothing at all.
    """
    a = (addr or "").strip()
    if not a:
        return "", ""
    if a.startswith("["):                 # [::]:80, if it ever appears
        h, sep, p = a.rpartition("]:")
        if sep:
            return norm_ip(h.lstrip("[")), p
        return norm_ip(a), ""
    h, sep, p = a.rpartition(":")
    if not sep:                           # a path, or a bare host
        return norm_ip(a), ""
    return (norm_ip(h) if h else "::"), p


def _port_text(addr):
    """The port field exactly as printed, a service name included.

    split_hostport answers with a number or None, which is what
    anything comparing ports wants. This is for recording what the
    tool actually said.
    """
    a = (addr or "").strip()
    if a.startswith("["):
        _h, sep, p = a.rpartition("]:")
        return p if sep else ""
    h, sep, p = a.rpartition(":")
    if not sep or h.count(":") >= 2:      # bare IPv6, no port
        return ""
    return p


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
        self._home_map = None         # lazily built home dir -> username
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
        """The live process map, parsed once.

        The guard is "has this been attempted", not "is the result empty".
        A disk image has no live processes, so the parse yields {} - which is
        falsy, so an emptiness check re-ran the whole parse on every call. It
        is called once per row by t_cron, t_users, t_systemd_units and
        t_file_hashes, and on a disk image that turned the cron table alone
        into 104 seconds of re-parsing nothing for 604 rows: 40% of the run.
        """
        if not self.tri.processes and not getattr(self.tri, "_procs_parsed", False):
            self.tri._procs_parsed = True
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
        t.add("Collection layout",
              getattr(self.col, "display_layout", "") or self.col.layout)
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
                       "Analysis",
                       "All dated events, every clock normalised to UTC. Every "
                       "dated finding is here too, at its first_utc and under "
                       "its own severity, so the timeline and the findings "
                       "list answer a severity filter with the same set - a "
                       "finding-derived row carries the artifact it came from "
                       "in source, or '(finding)' where it had none.")
        for e in self.tri.events:
            t.add(e.ts, e.severity, e.category, e.description, e.source)

    def t_file_inventory(self):
        """Every file in the collection - the 'did anything get missed' table."""
        t = self.table("FILE_INVENTORY", "Every file in the collection",
                       ["path", "host_path", "top_level", "category", "size_bytes",
                        "size_human", "mtime_utc", "atime_utc", "ctime_utc",
                        "crtime_utc", "time_source", "parsed_into"],
                       "Collection",
                       "One row per collected file, with its times and the "
                       "table that parsed it. Under a narrowed --scope, "
                       "parsed_into says so for the half that was not read - "
                       "an empty cell always means 'offered to every extractor "
                       "and taken by none'. time_source says where the times "
                       "came from, because that decides what they mean: "
                       "'bodyfile' and 'filesystem' are the host's own, read "
                       "from the inode; 'archive' is the mtime the collector "
                       "preserved into the tar or zip, which is the host's "
                       "when it was collected with the flags to keep it; "
                       "'collected file' is the extracted copy's own mtime and "
                       "is the weakest of the three.")
        plen = len(self.col.prefix)
        rootfs = tuple(rd + "/" for rd in self.col.rootfs_dirs)
        # The bodyfile is the authoritative record of the host's own times
        # where the collection has one - it was read off the inodes. Anything
        # else is what the container happened to preserve, so it is the
        # fallback and is labelled as such rather than presented as equal.
        meta = self._bodyfile_meta()
        fallback = getattr(self.col, "time_source", "archive")
        if self.col.kind == "dir":
            fallback = "collected file"
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
            times = self.col.member_time(rel)
            bf = meta.get(host) if host else None
            if times[1] or times[2] or times[3]:
                # the backend read the inode itself, so it has all four and
                # the bodyfile - which on these backends is built from the
                # same inodes - can only be a subset of it
                mtime, atime, ctime, crtime = times
                origin = self.col.time_source
            elif bf and bf.get("mtime"):
                mtime, atime, ctime, crtime = bf["mtime"], "", "", ""
                origin = "bodyfile"
            else:
                mtime, atime, ctime, crtime = times
                origin = fallback if mtime else ""
            t.add(rel, host, top, cat, size, human_size(size),
                  mtime, atime, ctime, crtime, origin, into)

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
        """One row per process, and one per variable beside it.

        PROC_ENVIRON is what an examiner opens, so it holds what an
        examiner wants to read: a process and its whole environment, on
        one line. Forty rows that have to be gathered back together by
        eye before they mean anything is a table asking its reader to do
        the work it exists to do.
        The per-variable form is still built, because a search for a
        tool name wants the value on its own rather than buried in a
        line of them - that is what the hacktool sweep reads, and it is
        pointed at PROC_ENVIRON_VARIABLES rather than here.
        """
        t = self.table("PROC_ENVIRON",
                       "Process environments, one row per process",
                       ["pid", "process", "user", "container", "variables",
                        "ld_preload", "ld_library_path", "path", "pwd", "home",
                        "shell", "environment", "source"], "Process",
                       "/proc/<pid>/environ - LD_PRELOAD and friends "
                       "live here. variables counts them; environment "
                       "is every one of them in the order the file "
                       "recorded, which is the order the kernel holds "
                       "them, so a variable appended after the process "
                       "started sits at the end. The variables worth reading "
                       "on their own get their own column - LD_PRELOAD and "
                       "LD_LIBRARY_PATH because they are how a library is "
                       "forced into a process, PATH because a writable "
                       "directory early in it is how a command is hijacked - "
                       "and environment still holds all of them, in order, so "
                       "nothing is only in a column. PROC_ENVIRON_VARIABLES "
                       "carries the same data one row per variable, which is "
                       "the shape to filter and sort on.")
        v = self.table("PROC_ENVIRON_VARIABLES",
                       "Process environment variables, one row each",
                       ["pid", "process", "user", "container", "variable",
                        "value", "source"], "Process",
                       "The same /proc/<pid>/environ files as "
                       "PROC_ENVIRON, split so one variable is one row. "
                       "Filter variable for LD_PRELOAD, sort by it, or "
                       "search value for a path - none of which the "
                       "rolled-up form can answer.")
        for rel in self.col.glob("live_response/process/proc/*/environ.txt"):
            parts = rel.split("/")
            try:
                pid = parts[parts.index("proc") + 1]
            except (ValueError, IndexError):
                continue
            i = self.proc_of(pid)
            raw = self.text(rel, "PROC_ENVIRON")
            pairs = []
            for item in raw.replace("\x00", "\n").splitlines():
                if "=" in item:
                    k, val = item.split("=", 1)
                    k, val = k.strip(), val.strip()
                    pairs.append((k, val))
                    v.add(pid, i.get("name", ""), i.get("user", ""),
                          i.get("container", ""), k, val, rel)
            if pairs:
                # Read the named ones out rather than leaving an examiner to
                # find LD_PRELOAD inside a hundred characters of one line.
                # Last wins: a variable set twice in an environment is the
                # later one, which is what the process actually sees.
                seen = {}
                for k, val in pairs:
                    seen[k.upper()] = val
                t.add(pid, i.get("name", ""), i.get("user", ""),
                      i.get("container", ""), len(pairs),
                      seen.get("LD_PRELOAD", ""),
                      seen.get("LD_LIBRARY_PATH", ""),
                      seen.get("PATH", ""), seen.get("PWD", ""),
                      seen.get("HOME", ""), seen.get("SHELL", ""),
                      " ".join("%s=%s" % kv for kv in pairs), rel)

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
            # State is optional - a DGRAM row has none - and is only ever a
            # word. Left unconstrained it matched the I-Node instead, and the
            # I-Node group then took the digits off the front of the next
            # token: "unix 2 [ ] DGRAM 733323 602/systemd /run/..." recorded
            # its inode as a state, the pid as an inode, and "/systemd
            # /run/..." as the path. 38 rows of netstat_-anp.txt here.
            # Letters for the state, and a whole token for the I-Node.
            unix_rx = re.compile(r"^(unix)\s+(\d+)\s+\[([^\]]*)\]\s+(\S+)"
                                 r"(?:\s+([A-Z][A-Z_]*))?\s+(\d+)(?=\s|$)"
                                 r"\s*(.*)$")
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
                # Split netstat's own way, and keep the port as printed: a
                # service name where -n was not given, '*' for a wildcard.
                # Both used to come back empty - '0.0.0.0:ssh' and ':::80'
                # were recorded as listeners on no port at all, which is the
                # sshd and the web server missing from the port column.
                la, lp = _netstat_hostport(local)
                pa, pp = _netstat_hostport(peer)
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
        # The home globs overlap by construction - /home/* and the /home/alice
        # that /etc/passwd declares match the same file - so every one of
        # these counts each file once. Without that, an account whose home is
        # under /home has its history and its keys counted twice, which is a
        # wrong number in a column an analyst reads as a fact.
        for rel in self._home_files(".ssh/authorized_keys*"):
            owner = self.home_owner(self.col.host_path(rel))
            akeys[owner] += sum(
                1 for l in self.col.lines(rel)
                if l.strip() and not l.strip().startswith("#"))
        for rel in self._home_files(".ssh/id_*"):
            host = self.col.host_path(rel)
            if not host.endswith(".pub"):
                privkeys[self.home_owner(host)].append(os.path.basename(host))
        for rel in self._home_files(".*history*"):
            hist[self.home_owner(self.col.host_path(rel))] += sum(
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

    #: Homes that name nowhere. Distributions point service accounts at these
    #: precisely so that nothing is stored for them, and globbing under them
    #: searches the whole filesystem or nothing at all.
    NON_HOMES = ("", "/", "/nonexistent", "/dev/null", "/bin/false",
                 "/usr/sbin/nologin", "/none", "/no/home")

    def homes(self):
        """{home directory -> username}, as /etc/passwd declares them.

        A home is wherever passwd says it is, and on a server that is
        routinely not /home. www-data lives in /var/www, postgres in
        /var/lib/postgresql, an application account in /opt/<app> or
        /srv/<service> - and a compromised service account is exactly the one
        whose shell history matters, because it is the account a web shell
        runs as. Globbing /home/*/ finds none of them.

        /root and /home/* stay in the search regardless of what passwd says.
        A home directory with no account behind it is not an absence of
        evidence: it is what an account deleted after the fact leaves, and the
        history in it is the reason to care.
        """
        if getattr(self, "_home_map", None) is not None:
            return self._home_map
        out = {}
        rel = self.col.rootfs("/etc/passwd")
        for ln in (self.col.lines(rel) if rel else []):
            f = ln.split(":")
            if len(f) < 6 or ln.startswith("#"):
                continue
            name, home = f[0].strip(), f[5].strip().rstrip("/")
            if not name or home in self.NON_HOMES or not home.startswith("/"):
                continue
            out.setdefault(home, name)
        self._home_map = out
        return out

    def home_owner(self, host_path):
        """Which account's home a path sits in, by the longest home that fits.

        Longest wins because homes nest: /var and /var/www can both be homes,
        and a file under /var/www belongs to the account that lives there
        rather than to the one above it.
        """
        best, who = "", ""
        for home, name in self.homes().items():
            if (host_path == home or host_path.startswith(home + "/"))                     and len(home) > len(best):
                best, who = home, name
        if who:
            return who
        return self._home_owner(host_path)

    def _home_files(self, *suffixes):
        """Every distinct file matching these names under any home."""
        out, seen = [], set()
        for pat in self.home_globs(*suffixes):
            for rel in self.col.rootfs_glob(pat):
                key = rel.lower()
                if key not in seen:
                    seen.add(key)
                    out.append(rel)
        return out

    def home_globs(self, *suffixes):
        """Every place to look for a per-user artifact, given its name(s).

        The classic two are always searched, so a home directory left behind
        by a deleted account is still read; everything /etc/passwd declares is
        searched as well.
        """
        roots = ["/root", "/home/*"]
        for home in sorted(self.homes()):
            if home not in roots:
                roots.append(home)
        return [r + "/" + s.lstrip("/") for r in roots for s in suffixes]

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

    #: The utmp record types the session pairing below turns on.
    UT_BOOT = "BOOT_TIME"
    UT_RUNLVL = "RUN_LVL"
    UT_USER = "USER_PROCESS"
    UT_DEAD = "DEAD_PROCESS"

    def _wtmp_sessions(self):
        """Login sessions rebuilt from wtmp, with how long each one lasted.

        How long someone was logged in is usually the question the login
        records are being read for. A root session held open for three days
        across the window is a different fact from a root login that lasted
        forty seconds, and wtmp does not store the difference: it stores a
        login record and, later, a logout record on the same terminal, and the
        duration is the gap between them. `last` does that pairing on a live
        host. Nothing does it for a disk image, where there is no `last`
        output and the wtmp file is the only thing there is.

        Pairing is by terminal in file order, the way last does it. A boot or
        shutdown record closes everything still open before it: those sessions
        never had a logout written, and the moment the machine went down is
        the honest end for them rather than a blank or a guess.
        """
        cached = getattr(self, "_wtmp_session_cache", None)
        if cached is not None:
            return cached
        out = []
        seen_files = set()
        for rel in self._log_files() + self.col.rootfs_glob("/var/log/wtmp*"):
            base = os.path.basename(rel).lower()
            if not base.startswith("wtmp") or base.endswith(".db"):
                continue
            if rel.lower() in seen_files:
                continue
            seen_files.add(rel.lower())
            raw = decompress_bytes(rel, self.col.read_bytes(rel))
            if not raw:
                continue
            host = self.col.host_path(rel)
            open_on = {}                    # terminal -> the session open on it
            for r in parse_utmp(raw):
                when, kind, line = r["time"], r["type"], r["line"]
                if kind == self.UT_BOOT or (kind == self.UT_RUNLVL
                                            and r["user"] in ("shutdown",
                                                              "runlevel")):
                    ended = ("ended at reboot" if kind == self.UT_BOOT
                             else "ended at shutdown")
                    for sess in open_on.values():
                        sess["end"] = when
                        sess["state"] = ended
                    open_on = {}
                    continue
                if kind == self.UT_USER and r["user"] and line:
                    prev = open_on.get(line)
                    if prev is not None:
                        # a second login on the same terminal with no logout
                        # between them: the first one ended here, and saying
                        # so beats leaving it open until the next reboot
                        prev["end"] = when
                        prev["state"] = "no logout record"
                    sess = {"user": r["user"], "line": line, "host": r["host"],
                            "ip": r["ip"], "pid": r["pid"], "start": when,
                            "end": None, "state": "", "source": host}
                    open_on[line] = sess
                    out.append(sess)
                elif kind == self.UT_DEAD and line and line in open_on:
                    sess = open_on.pop(line)
                    sess["end"] = when
                    sess["state"] = "closed"
            for sess in open_on.values():
                sess["state"] = "still open at the end of this wtmp"
        self._wtmp_session_cache = out
        return out

    def _auth_sessions(self):
        """Sessions paired out of auth.log / secure, from PAM's own records.

        PAM writes 'session opened for user X' and later 'session closed for
        user X' around every session it sets up, and that is a wider net than
        wtmp casts. wtmp records logins that took a terminal; PAM records
        every session there was - sudo, su, cron, systemd's user manager -
        and most of those never touch wtmp at all. A sudo session that ran for
        forty minutes at three in the morning is exactly the kind of thing
        this table should be able to show, and wtmp has no idea it happened.

        It is also the copy that survives differently. wtmp is a binary an
        intruder can truncate in one command; auth.log is text that is
        usually shipped somewhere else as well, so the two disagreeing is
        itself worth seeing - which is why both are kept rather than merged,
        each carrying the file it came from.

        Pairing is on the service, its pid and the user. The pid is what
        ties an open to its close when several sessions overlap, but not
        every service logs one - sudo and su write no pid at all - so the
        user carries the pairing when it is missing. Opens on one key are
        held as a stack and a close takes the most recent, which is what
        nested sudo actually does.

        The rows are sorted before pairing. auth.log is read together with
        its rotated auth.log.1 and auth.log.*.gz, and those arrive in
        filename order, not time order; pairing them as they come produces
        sessions that end before they start.
        """
        auth = next((x for x in self.tables if x.name == "AUTH_LOG"), None)
        if auth is None or not len(auth):
            return []
        cols = [str(c) for c in auth.columns]
        try:
            i_ts, i_proc, i_pid = (cols.index("timestamp_utc"),
                                   cols.index("process"), cols.index("pid"))
            i_ev, i_user, i_src = (cols.index("event"), cols.index("user"),
                                   cols.index("source"))
        except ValueError:
            return []
        i_ip = cols.index("source_ip") if "source_ip" in cols else -1
        i_tty = cols.index("tty") if "tty" in cols else -1
        i_msg = cols.index("message") if "message" in cols else -1
        recs, ctx = [], []
        for row in auth.iter_rows():
            event = str(row[i_ev]) if i_ev < len(row) else ""
            proc = str(row[i_proc]) if i_proc < len(row) else ""
            if event not in ("session opened", "session closed"):
                # PAM's 'session opened' line carries no address. sshd logs
                # where the connection came from on the line before it -
                # 'Accepted password for mail from 192.168.210.131 port
                # 57686' - and both lines carry the sshd child pid, which is
                # what ties them together. Keep the addressed lines to fill
                # the session in from. Only ones with a pid: without one the
                # address would come from whatever else that service did.
                pid = str(row[i_pid]) if i_pid < len(row) else ""
                ip = str(row[i_ip]) if 0 <= i_ip < len(row) else ""
                tty = str(row[i_tty]) if 0 <= i_tty < len(row) else ""
                if pid and (ip or tty):
                    ctx.append((str(row[i_ts]) if i_ts < len(row) else "",
                                proc, pid, ip, tty))
                continue
            # PAM names the service in its own message, and that is the clean
            # answer. The syslog ident is not: GDM really does log as
            # 'gdm-password]' and systemd's user manager as '(systemd)', which
            # are faithful to the log and useless as a column to group on.
            msg = str(row[i_msg]) if 0 <= i_msg < len(row) else ""
            ms = PAM_SERVICE_RE.search(msg)
            if ms:
                proc = ms.group(1)
            recs.append((str(row[i_ts]) if i_ts < len(row) else "", event, proc,
                         str(row[i_pid]) if i_pid < len(row) else "",
                         str(row[i_user]) if i_user < len(row) else "",
                         str(row[i_ip]) if 0 <= i_ip < len(row) else "",
                         str(row[i_tty]) if 0 <= i_tty < len(row) else "",
                         str(row[i_src]) if i_src < len(row) else ""))
        # undated rows keep their order and go last; they cannot be placed.
        recs.sort(key=lambda r: (r[0] == "", r[0]))
        ctx.sort(key=lambda r: (r[0] == "", r[0]))
        addressed = {}
        for when, proc, pid, ip, tty in ctx:
            addressed.setdefault((proc, pid), []).append((when, ip, tty))
        out, open_on = [], {}
        for when, event, proc, pid, user, ip, tty, src in recs:
            key = (proc, pid, user)
            if event == "session opened":
                if pid and not (ip and tty):
                    ip, tty = _address_for(addressed.get((proc, pid)), when,
                                           ip, tty)
                sess = {"user": user, "service": proc, "pid": pid,
                        "start": when, "end": "", "state": "",
                        "host": ip, "line": tty, "source": src}
                open_on.setdefault(key, []).append(sess)
                out.append(sess)
                continue
            stack = open_on.get(key)
            if stack:
                sess = stack.pop()
                sess["end"] = when
                sess["state"] = "closed"
        for stack in open_on.values():
            for sess in stack:
                sess["state"] = "still open at the end of this log"
        return out

    # `last` prints a session three ways and the collector runs all three.
    # The plain and -i forms put the origin third and date the row
    # 'Thu Jun 11 11:15' - no year, no seconds; -F dates it in full and moves
    # the origin to the end of the line. `who` is a fourth shape again. One
    # regex fitted to the plain form is not enough for any of that. On a real
    # collection it read 5,584 rows into an undated 'Thu Jun 11 11:15' and
    # dropped the other 5,663 - every -F row, every 'still logged in' row,
    # every 'gone - no logout' row, every `who` row - into a split() fallback
    # that put the rest of the line in the start column. 508 of the 11,756
    # starts in that table were timestamps, every one of them from wtmp or
    # PAM, and the newest start of all - the row that answers "when did
    # anyone last sign in" - was the string 'tty1 Jun 8 08:56'.
    _TS_FULL = r"\w{3}\s+\w{3}\s+\d{1,2}\s+\d\d:\d\d:\d\d(?:\s+\S+)?\s+\d{4}"
    _TS_SHORT = r"\w{3}\s+\w{3}\s+\d{1,2}\s+\d\d:\d\d"
    # 'reboot   system boot  ...' is the one terminal with a space in it
    _TTY = r"(?:system boot|\S+)"
    # Both the terminal and the origin are optional: `lastb` writes neither
    # for an attempt that never reached one, and the row is still a record of
    # someone trying.
    LAST_F_RE = re.compile(r"^(\S+)\s+(?:(%s)\s+)?(%s)\s*(.*)$"
                           % (_TTY, _TS_FULL))
    LAST_RE = re.compile(r"^(\S+)\s+(?:(%s)\s+)?(\S*?)\s+(%s)\s*(.*)$"
                         % (_TTY, _TS_SHORT))
    LAST_FULL_RE = re.compile(_TS_FULL)
    LAST_DUR_RE = re.compile(r"\(([^)]*)\)")
    WHO_RE = re.compile(r"^(\S+)\s+(?:[-+?]\s+)?(\S+)\s+"
                        r"(\d{4}-\d\d-\d\d\s+\d\d:\d\d(?::\d\d)?"
                        r"|\w{3}\s+\d{1,2}\s+\d\d:\d\d(?::\d\d)?)"
                        r"\s*(?:\((.*)\))?\s*$")
    LAST_NOTE_RE = re.compile(r"\b(down|crash)\b", re.I)
    _NO_SECONDS_RE = re.compile(r"\d\d:\d\d$")
    WEEKDAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")

    def _last_ts(self, text):
        """A `last`/`who` stamp -> UTC, whichever of its shapes this is.

        -F prints 'Thu Jun 11 11:15:38 2026', which dates itself. The others
        print 'Thu Jun 11 11:15' and 'Jun  8 08:56' - no year, and no seconds.
        Dropping the weekday and adding ':00' makes them the syslog shape, and
        syslog is what every other undated line in the case is read as: the
        collection year is the anchor, and a month later than the collection
        month is read as the year before. The minute is what was printed; the
        second is not, and a stamp that claims one it was never given would
        be a worse answer than the one it replaces.
        """
        s = " ".join((text or "").split())
        if not s:
            return ""
        out = self.ts_utc(s)
        if out:
            return out
        if s.split(" ")[0][:3].lower() in self.WEEKDAYS:
            s = s.partition(" ")[2]
        if self._NO_SECONDS_RE.search(s):
            s += ":00"
        return self.ts_utc(s)

    @classmethod
    def _last_host(cls, text):
        """The origin off the end of a -F row, which is where -a puts it."""
        t = cls.LAST_DUR_RE.sub(" ", text or "").strip()
        if t.startswith("-"):
            t = t[1:]
        for note in ("still logged in", "gone - no logout", "still running"):
            t = t.replace(note, " ")
        f = t.split()
        return f[-1] if f else ""

    @classmethod
    def _last_state(cls, tail, end):
        """How the session ended, in the vocabulary wtmp and PAM already use.

        The same fact reaches this table from three readers, and a session
        `last` calls 'gone - no logout' is the one the wtmp reader calls 'no
        logout record'. Two spellings of one state is a column that cannot be
        grouped on.
        """
        low = (tail or "").lower()
        if "still logged in" in low or "still running" in low:
            return "still open at the end of this log"
        if "no logout" in low:
            return "no logout record"
        m = cls.LAST_NOTE_RE.search(low)
        if m:
            return ("ended at shutdown" if m.group(1).lower() == "down"
                    else "ended at reboot")
        return "closed" if end else ""

    def _last_row(self, s):
        """One `last`/`lastb` line -> user, tty, host, start, end, secs, state."""
        m = self.LAST_F_RE.match(s)
        if m:
            user, tty, start_raw, tail = m.groups()
            start = self._last_ts(start_raw)
            tty = tty or ""
            em = self.LAST_FULL_RE.search(tail)
            end = self._last_ts(em.group(0)) if em else ""
            dur = self.LAST_DUR_RE.search(tail)
            secs = (_duration_seconds(dur.group(1)) if dur
                    else _span_seconds(start, end))
            host = self._last_host(tail[em.end():] if em else tail)
            return (user, tty, host, start, end, secs,
                    self._last_state(tail, end))
        m = self.LAST_RE.match(s)
        if m:
            user, tty, host, start_raw, tail = m.groups()
            start = self._last_ts(start_raw)
            tty, host = tty or "", host or ""
            dur = self.LAST_DUR_RE.search(tail)
            secs = _duration_seconds(dur.group(1)) if dur else ""
            end = _end_after(start, secs)
            return (user, tty, host, start, end, secs,
                    self._last_state(tail, end))
        return None

    def _who_row(self, s):
        """One `who` line. Everything it lists is signed in right now."""
        m = self.WHO_RE.match(s)
        if not m:
            return None
        user, tty, when, host = m.groups()
        return (user, tty, host or "", self._last_ts(when), "", "",
                "open when the collector ran")

    def t_logins(self):
        t = self.table("LOGINS", "Login history",
                       ["user", "service", "terminal", "source_host", "start",
                        "end", "duration", "duration_seconds", "result",
                        "state", "pid", "source"], "Authentication",
                       "Every login session, from all three records of one: "
                       "last/lastb/who where the collector ran them, wtmp "
                       "paired login-to-logout by terminal, and PAM's own "
                       "'session opened'/'session closed' in auth.log or "
                       "secure paired by service, pid and user. The last of "
                       "those "
                       "is the widest net - wtmp only knows about sessions "
                       "that took a terminal, while PAM records sudo, su, "
                       "cron and systemd's user manager too - and it is the "
                       "copy that survives a truncated wtmp. One session can "
                       "therefore appear more than once, from different "
                       "sources; the source column says which, and two "
                       "records of one session disagreeing is itself worth "
                       "seeing. Every start is UTC: `last` prints its rows "
                       "three ways and only -F carries a year, so the "
                       "year-less forms are dated against the collection year "
                       "the way every other year-less line in the case is, to "
                       "the minute that was printed. `who` lists what was "
                       "open when the collector ran and says so in state. "
                       "result is whether the login was granted, and "
                       "it is a column because one of those sources is not a "
                       "session at all: lastb prints the attempts that were "
                       "refused in the same shape last prints the ones that "
                       "were accepted, so without it the newest row here is "
                       "the last attempt rather than the last sign-in. wtmp, "
                       "who, last and PAM's 'session opened' are logins that "
                       "were granted and are 'success'; lastb is 'failure'. "
                       "Duration is measured from the pair rather than "
                       "reported, state says how the session ended because "
                       "'no logout record' and 'still open' otherwise both "
                       "look like a blank end time - it is not an outcome, a "
                       "session that closed and a login that was refused are "
                       "not the same fact - and duration_seconds is the same "
                       "number unformatted so the table sorts on it.")
        for rel in sorted(self.col.glob("live_response/system/last*.txt")) + \
                   sorted(self.col.glob("live_response/system/who*.txt")):
            base = os.path.basename(rel)
            low = base.lower()
            # last*.txt is lastb.txt and lastlog.txt as well, and neither of
            # them is what the glob was written for. lastb prints the logins
            # that were refused, in the same columns last prints the ones that
            # were granted - which is why this table needs an outcome, and why
            # without one the newest row in a login history is a failed
            # attempt. lastlog is not a list of sessions at all: it is one line
            # per account, most of them '**Never logged in**', and the binary
            # it reads is already parsed into LASTLOG.
            if low.startswith("lastlog"):
                continue
            outcome = "failure" if low.startswith("lastb") else "success"
            read = self._who_row if low.startswith("who") else self._last_row
            for ln in self.lines(rel, "LOGINS"):
                s = ln.rstrip()
                if not s.strip() or s.startswith("wtmp begins") or s.startswith("btmp begins"):
                    continue
                row = read(s)
                if not row:
                    # A line that fits none of the shapes is not a session,
                    # and the old fallback - first token is the user, the
                    # rest is the start - is what put a terminal name in the
                    # start column. Better to leave it out than to record it
                    # as a login that happened at 'tty1 Jun 8 08:56'. Across
                    # the nine last/lastb/who files a real collection writes,
                    # nothing reaches here but the banner lines already
                    # skipped above.
                    continue
                user, tty, host, start, end, secs, state = row
                t.add(user, "", tty, host, start, end,
                      _human_duration(secs), secs, outcome, state, "", base)

        # And the sessions wtmp itself describes. On a disk image this is the
        # whole table; anywhere else it is the cross-check, measured from the
        # records rather than taken from what `last` printed.
        for sess in self._wtmp_sessions():
            start, end = sess["start"], sess["end"]
            secs = ""
            if start and end:
                secs = int((end - start).total_seconds())
                if secs < 0:
                    secs = ""          # clock moved; a negative span is not one
            t.add(sess["user"], "login", sess["line"],
                  sess["host"] or sess["ip"],
                  start.strftime("%Y-%m-%d %H:%M:%S") if start else "",
                  end.strftime("%Y-%m-%d %H:%M:%S") if end else "",
                  _human_duration(secs), secs, "success", sess["state"],
                  sess["pid"], sess["source"])

        # and what PAM recorded, which covers the sessions wtmp never sees
        for sess in self._auth_sessions():
            secs = _span_seconds(sess["start"], sess["end"])
            t.add(sess["user"], sess["service"], sess["line"], sess["host"],
                  sess["start"], sess["end"], _human_duration(secs), secs,
                  "success", sess["state"], sess["pid"], sess["source"])

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
                    pick("grp", "grp2", "grp3"), clean_addr(pick("ip")),
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
                        ip = clean_addr(rm.group(1)) if rm else ""
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
                        self.tri.ioc(ip, "failed authentication source"
                                     if result == "failure"
                                     else "authentication source",
                                     host_path, self.ts_utc(raw_ts))
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
                r["ip"] = clean_addr(r["ip"])
                if r["ip"]:
                    self.tri.ioc(r["ip"], "failed authentication source",
                                 host_path,
                                 r["time"].strftime("%Y-%m-%d %H:%M:%S")
                                 if r["time"] else "")
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
                        ip = clean_addr(rm.group(1)) if rm else ""
                    tm = re.search(r"\btty=(\S+)", msg)
                    if ip:
                        self.tri.ioc(ip, "failed authentication source",
                                     host_path, self.ts_utc(raw_ts))
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
                ip = clean_addr(rm.group(1)) if rm else ""
            if ip:
                self.tri.ioc(ip, "failed authentication source", host_path,
                             ts)
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
                addr = clean_addr(kv.get("addr", ""))
                if addr:
                    self.tri.ioc(addr, "failed authentication source",
                                 host_path, dt.strftime("%Y-%m-%d %H:%M:%S") if dt else "")
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
        # Every home /etc/passwd declares, not just /home/* - see homes().
        pats = self.home_globs(
            ".*history*", ".*_history", ".mysql_history", ".histfile",
            ".local/share/fish/fish_history", ".config/fish/fish_history",
            ".bash_history", ".sh_history", ".zsh_history", ".ash_history",
            ".local/share/nu/history.txt")
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
                user = self.home_owner(host)
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
        """path -> {md5, sha1, sha256}, from whatever recorded them.

        UAC runs a hashing pass and writes the result under hash_executables.
        An AD1 has them already: FTK records an MD5 and a SHA-1 for every file
        as it acquires it, and they are the acquisition's own record of what
        the file was - better provenance than a hash computed afterwards, and
        available for every file rather than only the executables.
        """
        if self._exe_hash_map is None:
            out = {}
            for algo in ("md5", "sha1", "sha256"):
                for rel in self.col.glob("hash_executables/*.%s" % algo):
                    for ln in self.col.lines(rel):
                        parts = ln.split(None, 1)
                        if len(parts) == 2:
                            out.setdefault(parts[1].strip(), {})[algo] = \
                                parts[0].strip()
            for path, stored in (getattr(self.col, "stored_hashes", None)
                                 or {}).items():
                entry = out.setdefault(path, {})
                for algo in ("md5", "sha1", "sha256"):
                    if stored.get(algo) and not entry.get(algo):
                        entry[algo] = stored[algo]
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

    def t_timestomp(self):
        """Every entry that failed a timestamp rule, with all four clocks.

        A derived table, like FINDINGS and TIMELINE: the rules ran on the
        bodyfile pass the analyzer already makes, and re-reading a few hundred
        thousand inode records to render them again would be a second pass for
        nothing.

        The finding says how many and names thirty. This is the rest of them,
        sortable by rule and filterable by path, which is the difference
        between "eleven files are backdated" and knowing which eleven.
        """
        rows = self.tri.timestomp["rows"]
        if not any(rows.get(r) for r in self.tri.TIMESTOMP_ORDER):
            return
        t = self.table("TIMESTOMP", "Timestamp anomalies",
                       ["rule", "severity", "path", "directory", "basename",
                        "mode", "uid", "owner", "size", "inode",
                        "timestamp_utc", "atime_utc", "mtime_utc", "ctime_utc",
                        "crtime_utc", "finding"],
                       "Filesystem",
                       "One row per file whose own four timestamps disagree "
                       "with each other, and the rule that says how. "
                       "timestamp_utc repeats ctime deliberately - it is the "
                       "only one of the four the kernel will not let userspace "
                       "write, so it is the clock this row is placed on: the "
                       "console's time window and the activity chart then "
                       "answer for the moment the metadata actually changed "
                       "rather than the moment the file claims. Rows are "
                       "capped at %d per rule; the count on the finding is "
                       "exact either way."
                       % Triage.TIMESTOMP_ROW_CAP)
        for rule in self.tri.TIMESTOMP_ORDER:
            sev, title = self.tri.TIMESTOMP_RULES[rule][0:2]
            for (path, mode, uid, size, inode,
                 atime, mtime, ctime, crtime, note) in rows.get(rule) or []:
                t.add(rule, sev, path, os.path.dirname(path),
                      os.path.basename(path), mode, uid,
                      self.uid_name(uid) or "", size, inode,
                      _ts_text(ctime), _ts_text(atime), _ts_text(mtime),
                      _ts_text(ctime), _ts_text(crtime),
                      "%s - %s" % (title, note))

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
                    g["ip"] = clean_addr(g["ip"])
                    self.tri.ioc(g["ip"], "web request source", host,
                                 self.ts_utc(g["ts"]))
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
                    cip = clean_addr(cm.group(1)) if cm else ""
                    if cip:
                        self.tri.ioc(cip, "web error source", host,
                                     self.ts_utc(g["ts"].replace("/", "-")))
                    t.add(self.ts_utc(g["ts"].replace("/", "-")), g["ts"],
                          server, "error", cip, "",
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
                    ip = clean_addr(ip)
                    code = ""
                    if "AH" in msg:
                        km = self.AH_CODE_RE.search(msg)
                        code = km.group(1) if km else ""
                    rq = self.ERR_REQ_RE.search(msg) if "HTTP/" in msg else None
                    if ip:
                        self.tri.ioc(ip, "web error source", host,
                                     self.ts_utc(re.sub(r"\.\d+", "", g["ts"])))
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
                # smb.conf ships 'log file = /var/log/samba/log.%m', and samba
                # writes that name literally when it has no client name to put
                # in it. The file is real; '%m' is not a host.
                if "%" in client:
                    client = ""
            cur = None
            body = []
            recs = 0

            def flush():
                nonlocal recs
                if cur is None:
                    return
                ts = self.ts_utc(cur["ts"].replace("/", "-"))
                # registered per record rather than once from the filename:
                # the name says which client, and only the records say how
                # much it did and between when and when
                if client:
                    recs += 1
                    self.tri.ioc(client, "smb client", host, ts)
                msg = " ".join(b.strip() for b in body if b.strip())
                um = re.search(r"user\s*\[?([^\]\s]+)\]?", msg, re.I)
                t.add(ts, cur["ts"],
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
            # a log with no parseable record still names its client, and that
            # the host has a log for it at all is the evidence it connected
            if client and not recs:
                self.tri.ioc(client, "smb client", host)

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
                d["SRC"] = clean_addr(d["SRC"])
                self.tri.ioc(d["SRC"], "firewall-logged source", host,
                             self.ts_utc(ts_raw))
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
                d["SRC"] = clean_addr(d["SRC"])
                self.tri.ioc(d["SRC"], "firewall-logged source", host, ts)
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
            # /dev is full of device nodes and symlinks, and the finding
            # this feeds is about regular files. An archive backend answers
            # 'f' for everything because a directory listing has nothing else
            # in it, so this only ever excludes anything on a backend that
            # reads the filesystem itself - which is the one that sees device
            # nodes at all. Without it every disk image raised a HIGH on its
            # own /dev: 90 of them on Webserver.E01, /dev/console and
            # /dev/dsp among them, and 90 indicators that buried the four
            # real ones.
            kind = self.col.member_kind(rel)
            if kind and kind != "f":
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
                kv["addr"] = clean_addr(kv.get("addr", ""))
                if kv["addr"]:
                    self.tri.ioc(kv["addr"], "audit event source", host,
                                 dt.strftime("%Y-%m-%d %H:%M:%S") if dt else "")
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
        # Opt-in below this line - see SIGMA_OPT_IN_STREAMS. These are the
        # state-of-the-host tables rather than the what-happened tables: what
        # is on the filesystem, in the account files, in the configuration.
        # A disk image is mostly these, and until they were routable no rule
        # could be written for the majority of what a disk investigation
        # actually finds.
        ("BODYFILE", ("file_event", "file", "filesystem"), ""),
        ("FILE_INVENTORY", ("file_event", "file", "filesystem"), ""),
        ("DELETED_FILES", ("file_event", "file", "file_delete"), ""),
        ("SUID_SGID", ("file_event", "file", "filesystem"), ""),
        ("HIDDEN_PATHS", ("file_event", "file", "filesystem"), ""),
        ("SENSITIVE_FILES", ("file_event", "file", "filesystem"), ""),
        ("OPEN_FILES", ("file_event", "file"), ""),
        ("SSH", ("ssh_config", "authorized_keys"), ""),
        ("SUDOERS", ("sudoers_file", "sudoers"), ""),
        ("USERS", ("user_account", "account", "passwd"), ""),
        ("GROUPS", ("user_account", "group", "account"), ""),
        ("ETC_CONFIGS", ("etc_config", "config"), ""),
        ("WEB_CONFIG", ("web_config",), ""),
        ("INIT_AND_PROFILE", ("init", "profile", "startup_script"), ""),
        ("EDITOR_HISTORY", ("editor_history",), ""),
        ("PACKAGES", ("package", "software"), ""),
        ("PACKAGE_HISTORY", ("package", "software"), "timestamp_utc"),
    )

    # Streams a rule reaches only by naming them. A bare 'product: linux' rule
    # with no service or category runs against every stream, which is what it
    # means - but BODYFILE and FILE_INVENTORY are a quarter of a million rows
    # of path names on a disk image, and a keyword rule pointed at them both
    # costs minutes and reports a filename as though it were an event. The
    # what-happened tables stay open to a bare rule; these need asking for.
    SIGMA_OPT_IN_STREAMS = frozenset((
        "BODYFILE", "FILE_INVENTORY", "DELETED_FILES", "SUID_SGID",
        "HIDDEN_PATHS", "SENSITIVE_FILES", "OPEN_FILES", "SSH", "SUDOERS",
        "USERS", "GROUPS", "ETC_CONFIGS", "WEB_CONFIG", "INIT_AND_PROFILE",
        "EDITOR_HISTORY", "PACKAGES", "PACKAGE_HISTORY",
    ))

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
        # message last of the leaders but present: on an error row it is
        # the whole of the evidence - the request body mod_dumpio wrote,
        # or a CGI process's stderr - and it is the 18th column, so
        # without naming it here the field cap dropped it every time.
        "WEB_LOG": ("status", "method", "resource", "client_ip",
                    "user_agent", "message"),
    }

    @staticmethod
    def _evidence(text, cap, anchors):
        """`cap` characters of `text`, centred on what the rule fired on.

        A long log line carries its boilerplate at the front. Apache's
        mod_dumpio writes seventy characters of client address and hook name
        before the request body starts, so the head of the line is the same
        for every row and the interesting part - the command someone posted -
        is past the cut. Measured on this collection: of the 303 error rows
        naming a downloader, 94% have it beyond an 80-character head, the
        median sits at 93 and the worst at 824. Those rows all read
        'mod_dumpio.c(103): [client ...] mod_dumpio:  dumpio_in (data-HEAP)'
        and nothing else, which is evidence of nothing.

        The anchors are the rule's own gate literals - the text it insists a
        row contains - so the window lands on the reason this row is in the
        table. When none of them is in this particular field, or the field is
        short enough anyway, the value is returned exactly as before.
        """
        if len(text) <= cap:
            return text
        low = text.lower()
        at = -1
        for a in anchors or ():
            i = low.find(a)
            if i >= 0 and (at < 0 or i < at):
                at = i
        if at < 0:
            return trunc(text, cap)
        start = max(0, at - cap // 4)      # a little context before the match
        end = start + cap
        return ("..." if start else "") + text[start:end] + (
            "..." if end < len(text) else "")

    @classmethod
    def _sigma_summary(cls, tname, d, limit=8, anchors=()):
        """One matched row as 'key=value; ...' for SIGMA_MATCHES.matched_row.

        Fields named for this table lead and are never lost to the cap; the
        rest follow in the row's own order. A table with no entry keeps
        exactly the previous behaviour.
        """
        lead = [k for k in cls.SIGMA_SUMMARY_KEYS.get(tname, ())
                if d.get(k) not in (None, "")]
        rest = [k for k in d if k not in lead]
        keys = (lead + rest)[:max(limit, len(lead))]
        # _s, not str: a datetime rendered with str() carries '+00:00', which
        # is not how the same value appears in the table this row came from -
        # so the summary quoted a timestamp that matched nothing when it was
        # read back to find the row it describes.
        return "; ".join("%s=%s" % (k, cls._evidence(_s(d[k]), 80, anchors))
                         for k in keys)
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
        ("PROC_ENVIRON_VARIABLES", ("value",), "command"),
        ("CRON", ("command",), "command"),
        ("SYSTEMD_UNITS", ("exec_start", "exec_start_pre"), "command"),
        ("INIT_AND_PROFILE", ("text",), "command"),
        ("PACKAGES", ("name", "description"), "path"),
        ("SUID_SGID", ("path",), "path"),
        ("CAPABILITIES", ("path",), "path"),
        ("FILE_HASHES", ("path",), "path"),
        ("BODYFILE", ("path",), "path"),
        # Every collected filename, which is the only one of these that always
        # exists. BODYFILE needs a collector that produced one and SUID_SGID
        # needs a survey that ran, so on a collection with neither - and on
        # loose files - a tool sitting on disk under its own name was named
        # nowhere the sweep looked. FILE_INVENTORY has one row per file on
        # every backend there is.
        ("COLLECTED_FILES", ("path",), "path"),
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

    def _collected_files(self):
        """Every collected filename, as a table the sweeps can read.

        Not a real table and never exported - FILE_INVENTORY is that, and it
        is built last because it reports on what every other extractor took.
        The sweeps run before it, so without this the one artifact that exists
        on every backend - the list of file names - was the one thing they
        never looked at, and a tool sitting on disk under its own name went
        unreported unless a bodyfile or a suid survey happened to name it too.
        """
        cached = getattr(self, "_collected_files_table", None)
        if cached is not None:
            return cached
        t = Table("COLLECTED_FILES", "Collected file names", ["path", "mtime_utc"],
                  "Collection", "", None)
        plen = len(self.col.prefix)
        for low, real in self.col._names.items():
            if not low.startswith(self.col.prefix):
                continue
            rel = real[plen:]
            host = self.col.host_path(rel)
            try:
                mtime = self.col.member_time(rel)[0]
            except Exception:
                mtime = ""
            t.add(host or rel, mtime)
        self._collected_files_table = t
        return t

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
        by_name["COLLECTED_FILES"] = self._collected_files()
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
            # A path or a command line can hold a filename, where a tool name
            # arrives glued to a version or a suffix; free log text cannot, and
            # there the strict boundaries are what keep an ordinary sentence
            # from matching.
            if kind in ("command", "path"):
                tiers = [(HACKTOOL_PATH_RE, HACKTOOL_PATH_CAT, False)] if builtin else []
            else:
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
                       if (want in svc if tn in self.SIGMA_OPT_IN_STREAMS
                           else (not want or want in svc))
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
            # A table-wide prefilter was tried here once and removed, over the
            # rules' keyword *patterns* - a 10KB alternation full of '.*'
            # branches, which measured slower than running the searches
            # separately. What is built below is a different thing and wins:
            # an alternation over the gate *literals*, which are plain text
            # with no wildcards left in them, factored into a trie so a shared
            # prefix is walked once. It answers "could any gated rule match
            # this row" in one C call, where the loop underneath asks the same
            # question once per rule in Python - and on this collection 71% of
            # rows contain no gate literal at all, so that one call replaces
            # 233 of them. Measured 310us -> 105us per row, identical
            # survivors. The rows it does not settle fall through to exactly
            # the loop that was there before, so a match cannot be lost: the
            # scan only ever skips rows where no gated rule had a literal to
            # find.
            prepared = [[rule, cols.index(ts_col) if ts_col in cols else -1,
                         (self._service_filter(rule.service or rule.category)
                          if tname in self.SIGMA_MIXED_STREAMS else None),
                         [], 0, False, ["", ""], getattr(rule, "gate", None)]
                        for rule, ts_col in entries]
            gated = [e for e in prepared if e[7]]
            plain = [e for e in prepared if not e[7]]
            # Only where it pays for itself: building and compiling the pattern
            # costs tens of milliseconds, which a forty-row table would never
            # earn back.
            pre = None
            if len(gated) >= 8 and len(tb) >= 5000:
                pre = re.compile(_trie_alt(sorted({l for e in gated
                                                   for l in e[7]})))
            stopped_n = 0
            for rn, row in enumerate(tb.iter_rows()):
                if not rn & 0x3FFF:            # every 16k rows, not every row
                    sig_prog.step("%s (%d rule%s)"
                                  % (tname, len(entries),
                                     "" if len(entries) == 1 else "s"),
                                  n=seen_rows + rn)
                d = Row((cols[i], row[i]) for i in range(min(ncol, len(row)))
                        if row[i] not in (None, ""))
                # Nothing a gated rule insists on is anywhere in this row,
                # so only the ungated ones are worth walking.
                batch = prepared
                if pre is not None and pre.search(d.hay_lower()) is None:
                    batch = plain
                for e in batch:
                    if e[5]:
                        continue
                    rule, ts_i, keep = e[0], e[1], e[2]
                    if keep is not None and not keep(d):
                        continue
                    # The literal gate: one or two str.__contains__ calls
                    # against the row's own text, answering "could this rule
                    # match at all" before a single regex is compiled into
                    # action. A rule whose required literal is absent cannot
                    # match, so skipping it changes nothing but the clock.
                    gate = e[7]
                    if gate:
                        hay = d.hay_lower()
                        for lit in gate:
                            if lit in hay:
                                break
                        else:
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
                        stopped_n += 1
                        continue
                    summary = self._sigma_summary(tname, d, anchors=gate)
                    e[3].append((when, summary))
                if stopped_n >= len(prepared):   # all of them have had their fill
                    break
            seen_rows += len(tb)
            for rule, _ts_i, _keep, kept, hits, stopped, span, _gate in prepared:
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
                       ["indicator", "ioc_type", "why", "mitre", "count",
                        "first_utc", "last_utc", "artifact", "line_no",
                        "line"],
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
                       "why is how this term came to be an indicator at all - "
                       "an analyzer's provenance label, or 'pivot' for one "
                       "given on the command line - and mitre is the technique "
                       "that label implies. A term supplied by hand arrives "
                       "with no such history, so both are thin for it; a term "
                       "an analyzer raised carries the reason it was raised "
                       "onto every row of evidence for it, which is the "
                       "context that says whether a hit matters.")
        stats = getattr(self.tri, "pivot_stats", {})
        iocs = getattr(self.tri, "iocs", {})
        seen = getattr(self.tri, "ioc_count", {})
        spans = getattr(self.tri, "ioc_span", {})
        for term, host, n, line in getattr(self.tri, "pivot_hits", []):
            cnt, first, last = stats.get(term, ("", "", ""))
            # the sweep is the fuller answer where it ran, but a term the
            # analyzers raised has been counted and dated already, and that
            # is better than three empty columns
            span = spans.get(term) or ["", ""]
            if cnt == "":
                cnt = seen.get(term, "") or ""
            first, last = first or span[0], last or span[1]
            labels = sorted(iocs.get(term, ()))
            t.add(term, ioc_type(term), "; ".join(labels), ioc_mitre(labels),
                  cnt, first, last, host, n, line)

    def t_iocs(self):
        """Every indicator this run extracted, with why it is one.

        IOC_HITS answers "where was this term seen", one row per hit, and only
        for the terms --pivot was given. This answers the question an analyst
        actually starts from: what are the indicators for this host, all of
        them, in one list to hand to a SIEM or a threat feed.

        The why column is the point. An IP address with no provenance is a
        number - the same 10.0.0.5 is a domain controller or an exfiltration
        destination depending on which analyzer picked it up, and that is
        recorded at the moment of extraction ('failed authentication source',
        'outbound admin protocol', 'bodyfile (executable in tmpfs)') rather
        than guessed at afterwards. Two indicators of the same shape and
        different provenance are two different facts.

        count, first_utc and last_utc come from the same single pass over the
        collection that --pivot uses, so they cover every mention of the
        indicator anywhere - not only the artifact that first named it.
        """
        iocs = getattr(self.tri, "iocs", None)
        if not iocs:
            return
        t = self.table("IOCS", "Indicators extracted from this host",
                       ["indicator", "ioc_type", "why", "mitre", "count",
                        "first_utc", "last_utc", "extracted_from",
                        "sweep_count", "sweep_artifacts"],
                       "Detection",
                       "Every indicator any analyzer extracted, with the "
                       "provenance that made it one. 'why' is what kind of "
                       "observation it was, and is what separates two "
                       "indicators of the same shape: an address seen as a "
                       "failed-login source is a different fact from the same "
                       "address seen on an outbound admin connection. "
                       "'extracted_from' is the artifact that observation was "
                       "read out of - where to go and look at it in context - "
                       "and is a separate question from why, which is the "
                       "reason it is in this list. 'artifacts' is a different "
                       "column again: it is where the term was found by the "
                       "sweep, which includes everything that merely mentions "
                       "it. count, first_utc and last_utc are counted as the "
                       "analyzers extract it and are filled on every run: how "
                       "many times something actually observed this indicator, "
                       "and the span of those observations. For an address in "
                       "a web log that is how many requests came from it and "
                       "when they ran, which is usually the question. "
                       "sweep_count and sweep_artifacts are the wider and much "
                       "slower measure - every mention of the string anywhere "
                       "in the collection, including incidental ones - and are "
                       "filled only for the terms the run pivoted on, or for "
                       "everything under --count-iocs. Feed the indicator "
                       "column to a SIEM; read the why column before you do.")
        # Measured here rather than during the analysis: half the indicators
        # in this table are extracted by the table extractors above, so a
        # sweep run any earlier would count the analyzers' own and quietly
        # leave the rest unmeasured.
        if getattr(self.tri.opts, "count_iocs", False):
            status("[*] counting %s indicator(s) across the collection "
                   "(--count-iocs)" % format(len(iocs), ","))
            try:
                self.tri.count_indicators()
            except Exception as exc:
                status("[!] indicator counting failed: %s" % exc)
        stats = getattr(self.tri, "pivot_stats", {})
        arts = getattr(self.tri, "pivot_artifacts", {})
        srcs = getattr(self.tri, "ioc_sources", {})
        seen = getattr(self.tri, "ioc_count", {})
        spans = getattr(self.tri, "ioc_span", {})
        join = lambda xs: ("; ".join(xs[:12]) + (" ..." if len(xs) > 12 else ""))
        for value in sorted(iocs, key=lambda v: (ioc_type(v), v.lower())):
            labels = sorted(iocs[value])
            span = spans.get(value) or ["", ""]
            swept, _first, _last = stats.get(value, ("", "", ""))
            where = arts.get(value, [])
            t.add(value, ioc_type(value), "; ".join(labels), ioc_mitre(labels),
                  seen.get(value, "") or "", span[0], span[1],
                  join(sorted(srcs.get(value, ()))),
                  swept, join(where))

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

    # -- disk images ---------------------------------------------------------
    def t_disk_layout(self):
        """What was on the disk, including what could not be read.

        This table only has rows when the collection is a disk. It exists so
        that a partition holding a filesystem this tool does not parse, or one
        behind LUKS, is a line in the output rather than an absence - the
        difference between "there was nothing there" and "nothing here could
        read it" is the whole answer in some cases.
        """
        rows = getattr(self.col, "report", None)
        if not callable(rows):
            return
        t = self.table("DISK_LAYOUT", "Disk volumes",
                       ["volume", "scheme", "label", "type", "filesystem",
                        "uuid", "offset", "size", "size_human", "mounted_at",
                        "detail"],
                       "Collection",
                       "Every volume the partition, LVM and LUKS scan found on "
                       "the imaged disk, mounted or not. A volume with no "
                       "mount point was seen and not read, and the detail "
                       "column says why.")
        for row in rows():
            t.add(row["volume"], row["scheme"], row["label"], row["type"],
                  row["filesystem"], row["uuid"], row["offset"], row["size"],
                  human_size(row["size"]), row["mounted_at"], row["detail"])

    def t_deleted_files(self):
        """Inodes that were deleted and still carry their metadata.

        The name is gone with the directory entry, so what is left is an inode
        number, a size, an owner and a set of times. That still answers "was
        something removed from this host during the window", which nothing
        else in this tool and no mounted filesystem can answer at all.
        """
        nodes = getattr(self.col, "deleted_nodes", None)
        if not nodes:
            return
        t = self.table("DELETED_FILES", "Deleted inodes",
                       ["inode", "path", "mode", "uid", "owner", "gid",
                        "group", "size", "size_human", "atime_utc",
                        "mtime_utc", "ctime_utc", "crtime_utc", "dtime_utc"],
                       "Filesystem",
                       "Inodes with a deletion time and no remaining links, "
                       "recovered from the inode tables. The filename is not "
                       "recoverable - it lived in the directory entry that was "
                       "overwritten - so these are dated and sized, not named.")
        for node in nodes:
            t.add(node.inode, node.path, node.mode_string(), node.uid,
                  self.uid_name(str(node.uid)), node.gid,
                  self.gid_name(str(node.gid)), node.size,
                  human_size(node.size), _fs_ts(node.atime),
                  _fs_ts(node.mtime), _fs_ts(node.ctime), _fs_ts(node.crtime),
                  _fs_ts(node.dtime))

    def t_sensitive_files(self):
        """Credential material and secrets, found by what the file is called.

        Nothing here is opened. That is the point: the question "what secrets
        were sitting on this host, and where" is one an analyst asks early,
        and on a collection that took names and metadata but not contents it
        cannot be asked any other way. A name is weaker evidence than a
        content match and it is available for every file there is.

        Distribution paths are excluded rather than down-ranked. Python ships
        secrets.py, OpenSSL ships test keys, and every package manager has an
        example credentials file - including them turns the one private key in
        /home into row four hundred of a table nobody reads.
        """
        t = self.table("SENSITIVE_FILES", "Credential material by filename",
                       ["severity", "host_path", "basename", "directory",
                        "what", "why", "size_bytes", "size_human",
                        "mtime_utc", "owner", "mode", "source"],
                       "Detection",
                       "Files whose name says they hold key material, "
                       "passwords or credentials. Matched on the name alone - "
                       "nothing is opened - so this answers 'what secrets were "
                       "on this host' even for a collection that took metadata "
                       "and not contents. Distribution and packaging paths are "
                       "excluded: they carry test keys and example credentials "
                       "by the hundred, and none of them is a finding.")
        meta = self._bodyfile_meta()
        plen = len(self.col.prefix)
        rootfs = tuple(rd + "/" for rd in self.col.rootfs_dirs)
        seen = set()
        groups = {}
        for low, real in sorted(self.col._names.items(), key=lambda kv: kv[1]):
            if not low.startswith(self.col.prefix):
                continue
            rel = real[plen:]
            if not rel.lstrip("/").lower().startswith(rootfs):
                continue                  # command output is not a host file
            host = self.col.host_path(rel)
            if not host or host in seen:
                continue
            if SENSITIVE_FILE_BENIGN.search(host):
                continue
            if SENSITIVE_FILE_EXPECTED.match(host):
                continue
            if PUBLIC_CERT_DIR.search(host) and not PRIVATE_KEY_DIR.search(host):
                continue
            # a directory named for keys holds the files that are the finding;
            # reporting both says the same thing twice
            if self.col.member_kind(rel) == "d":
                continue
            best = None
            for rx, what, sev, why in SENSITIVE_FILE_RE:
                if not rx.search(host):
                    continue
                if best is None or SEVERITIES.index(sev) < SEVERITIES.index(best[1]):
                    best = (what, sev, why)
            if best is None:
                continue
            seen.add(host)
            what, sev, why = best
            bf = meta.get(host, {})
            mtime = bf.get("mtime") or self.col.member_time(rel)[0]
            size = self.col._sizes.get(low, 0)
            t.add(sev, host, os.path.basename(host), os.path.dirname(host),
                  what, why, size, human_size(size), mtime,
                  self.uid_name(bf.get("uid", "")) or bf.get("uid", ""),
                  bf.get("mode", ""), rel)
            self.use(rel, "SENSITIVE_FILES")
            groups.setdefault((sev, what, why), []).append((host, mtime))

        # One finding per kind rather than per file: forty SSH keys under
        # /home is one fact about the host, and forty findings about it push
        # everything else off the page.
        for (sev, what, why), rows in sorted(
                groups.items(), key=lambda kv: SEVERITIES.index(kv[0][0])):
            rows.sort()
            self.tri.add(sev, "Filesystem",
                         "Credential material on disk: %s" % what,
                         "%s. Matched on the filename alone - the contents "
                         "were not read - so treat each as a lead to confirm "
                         "rather than as a confirmed secret."
                         % (why[0].upper() + why[1:]),
                         evidence=["%s%s" % (h, "   %s" % m if m else "")
                                   for h, m in rows[:40]],
                         source="SENSITIVE_FILES", count=len(rows),
                         times=[m for _h, m in rows if m],
                         mitre="T1552 Unsecured Credentials")

    # -- driver -------------------------------------------------------------
    EXTRACTORS = [
        "t_metadata", "t_disk_layout", "t_collection_log",
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
        "t_users", "t_groups", "t_sudoers", "t_auth_events", "t_logins",
        "t_failed_logins", "t_privilege_activity", "t_ssh",
        "t_remote_access", "t_memory_output",
        "t_cron", "t_systemd_units", "t_init_scripts", "t_history",
        "t_editor_history", "t_ld_preload",
        "t_suid", "t_getcap", "t_mac_policy",
        "t_writable", "t_hidden_files", "t_unknown_owner",
        "t_socket_files",
        "t_dev_files", "t_bodyfile", "t_timestomp", "t_deleted_files",
        "t_file_hashes",
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
        "t_sensitive_files",
        "t_hacktools", "t_yara", "t_sigma", "t_pivot", "t_iocs",
        "t_rule_errors",
        "t_findings", "t_timeline",
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
    # UNPARSED_FILES) and derived views (FINDINGS, TIMELINE), plus the
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
        "t_users", "t_groups", "t_sudoers", "t_auth_events", "t_logins",
        "t_failed_logins", "t_privilege_activity", "t_ssh", "t_remote_access",
        "t_cron", "t_systemd_units", "t_init_scripts", "t_history",
        "t_editor_history", "t_ld_preload",
        "t_suid", "t_getcap", "t_mac_policy", "t_writable", "t_hidden_files",
        "t_unknown_owner", "t_socket_files", "t_dev_files", "t_bodyfile",
        "t_timestomp", "t_deleted_files", "t_disk_layout", "t_sensitive_files",
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


