# -*- coding: utf-8 -*-
"""Cross-host correlation: what several collections say about each other.

One run answers "what happened on this host". An intrusion is rarely about one
host, and the questions that decide an investigation are the ones no single
report can answer:

  the same address    a source that brute-forced web01 and then authenticated
                      successfully on db02 is lateral movement. Each host's
                      report holds half of that and neither states it.
  the same binary     one sha256 under /tmp on three machines is a deployed
                      implant. Three reports each say "an executable in a
                      world-writable directory", which is a much weaker claim.
  the same order      an indicator that reaches host B four minutes after host
                      A says which way the intrusion travelled. That fact only
                      exists between the two reports.

So this builds one view over several finished runs. It is deliberately not a
fourth analyzer: it re-reads nothing and re-parses nothing, and every input is
a projection each host's own run already produced - its indicators, its
findings, its events, its file hashes. What it adds is the join.

What it will not do is pretend the clocks agree. Every comparison here is
between two hosts' normalised UTC, which is only as good as the offset each
run resolved; a host whose zone nothing recorded was read as UTC, and an hour
wrong there is an hour wrong in every ordering below. That is stated as a
finding rather than assumed away, because "B, four minutes after A" is the
kind of sentence a report should not be able to make silently.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
import os
import re
import sys

from .model import Finding, SEVERITIES, SEV_RANK
from .term import status, trunc
from .common import TMPFS_DIRS, _ts_text, ioc_type, span_of
from .triage import Triage
from .tables import Table
from .writers import write_tables_csv, write_tables_html, write_tables_json


#: Where a shared hash stops being "both hosts run the same distribution" and
#: starts being a file somebody put there. Two hosts built from one image share
#: every byte of /usr/bin, so an unscoped hash join returns the operating
#: system and buries the four files that matter.
NOTABLE_DIRS = TMPFS_DIRS + ("/home/", "/root/", "/usr/local/", "/opt/",
                             "/var/www/", "/srv/", "/var/spool/")

#: Findings are grouped across hosts by title, and a title carries its own
#: count - "3 executable file(s)" on one host and "7 executable file(s)" on
#: the next are one check reported twice, not two different findings.
_COUNT_RE = re.compile(r"\d[\d,]*")

#: 'T1110 Brute Force / T1078 Valid Accounts' -> T1110, T1078. The same shape
#: the console's matrix reads, so a technique means one thing in both.
_TECH_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def _norm_title(title):
    return _COUNT_RE.sub("#", title or "")


def _label_for(path, taken):
    """A short, stable name for one input, unique within the run.

    The basename of what the analyst typed, because that is what they will
    look for in the output directory - not the hostname, which is not known
    until the collection has been read and cannot name a directory that has
    to exist before the run starts. The hostname is recorded in HOSTS instead,
    where a disagreement between the two is itself worth seeing.
    """
    base = os.path.basename(os.path.abspath(str(path).rstrip("/\\"))) or "host"
    for ext in (".tar.gz", ".tar.bz2", ".tar.xz", ".tar.zst"):
        if base.lower().endswith(ext):
            base = base[: -len(ext)]
            break
    else:
        base = os.path.splitext(base)[0] or base
    base = re.sub(r"[^A-Za-z0-9._-]+", "_", base).strip("._-") or "host"
    name, n = base, 2
    while name.lower() in taken:
        name, n = "%s-%d" % (base, n), n + 1
    taken.add(name.lower())
    return name


#: The column every merged row gains, and the name the console filters on.
#:
#: Not "host", which reads better and cannot be used: AUTH_LOG and JOURNAL
#: already have a column of that name holding the hostname syslog wrote on the
#: line, and merging into it silently replaced the label with that - three
#: collections' auth logs all claiming to be one host, which is data rather
#: than an error and would have been believed. "collection" is free across
#: every one of the 361 column names the extractors declare, and it is the
#: more accurate word anyway: what a row came from is a collection or an
#: image, which is not always one host and is never the host's own idea of
#: its name.
HOST_COLUMN = "collection"


def host_column(per_host):
    """The merged column's name, guaranteed not to collide in this run.

    HOST_COLUMN is free across every declared column, but not every column is
    declared - a Velociraptor artifact result becomes a table whose columns
    are whatever the artifact emitted. So the name is checked against the
    tables actually in hand and stepped aside if something already owns it,
    once for the whole set rather than per table: the console filters on one
    name, and a name that varied per grid would be no filter at all.
    """
    used = set()
    for _label, tables in per_host:
        for t in tables:
            used.update(t.columns)
    name = HOST_COLUMN
    while name in used:
        name = "_" + name
    return name


def merge_tables(per_host):
    """Several runs' table sets -> one set, each row carrying its host.

    The alternative was a directory per collection, and it is the wrong shape
    for the question people actually bring to three disks: not "show me web01"
    but "show me every process on any of them, then let me narrow". Three
    directories answer the first and make the second a manual join across
    three exports. One table with a host column answers both - grep it, filter
    the column in a spreadsheet, add `WHERE host = 'db02'` in SQL, or pick a
    host in the console and watch every grid narrow at once.

    Tables are merged by name and columns by name, not by position. Two hosts
    do not necessarily produce the same columns for one table: drop_empty_
    columns removes what a collection never filled, so a UAC tar and a disk
    image both make FILE_INVENTORY and only one of them has crtime in it.
    Merging on position would silently slide crtime into the time_source
    column for half the rows, which is the kind of corruption that reads as
    data. A column that only one host has is kept, and is simply empty for the
    hosts that never had it.
    """
    column = host_column(per_host)
    order, byname = [], {}
    for label, tables in per_host:
        for t in tables:
            if t.name not in byname:
                order.append(t.name)
                byname[t.name] = []
            byname[t.name].append((label, t))
    out = []
    for name in order:
        parts = byname[name]
        cols = [column]
        for _label, t in parts:
            for c in t.columns:
                if c not in cols:
                    cols.append(c)
        first = parts[0][1]
        merged = Table(
            name, first.title, cols, first.category,
            (first.description or "")
            + ("  Merged from %d collections; `%s` says which one each row "
               "came from, and no filter on it is all of them."
               % (len(parts), column) if len(parts) > 1 else ""),
            sorted(set(s for _l, t in parts for s in (t.sources or []))))
        for label, t in parts:
            at = [cols.index(c) for c in t.columns]
            width = len(cols)
            for row in t.iter_rows():
                new = [""] * width
                for i, value in zip(at, row):
                    new[i] = value
                new[0] = label      # after the row, never before: the label is
                merged.add(*new)    # the one cell the source table cannot own
        out.append(merged)
    return out, column


def merge_triage(cases, opts, tris):
    """One Triage over several, for the outputs that render findings.

    --html, --json and --timeline are documents about a host, and a merged run
    still has to produce one of each rather than three files with no way to
    say which is which. So the findings are pooled with the host written into
    the artifact column - the one place a reader already looks to ask "where
    did this come from" - and the events likewise. Titles are left alone: a
    finding's title is the claim it makes, and prefixing three hundred of them
    with a hostname would make every list in the report unreadable to save
    looking one column across.
    """
    merged = Triage(_CorrelationSource(cases), opts)
    merged.meta["Hostname"] = "%d collections" % len(cases)
    merged.meta["Hosts"] = ", ".join(c.label for c in cases)
    merged.meta["Collections"] = ", ".join(c.path for c in cases)
    for case, tri in zip(cases, tris):
        for f in tri.findings:
            merged.findings.append(Finding(
                f.severity, f.category, f.title, f.detail, f.evidence,
                ("%s: %s" % (case.label, f.source)) if f.source else case.label,
                f.mitre, f.first_seen, f.last_seen, f.count))
        merged.events.extend(tri.events)
    merged.findings.sort(key=lambda f: (SEV_RANK[f.severity], f.category,
                                        f.title))
    merged.events.sort(key=lambda e: e.ts)
    return merged


class HostCase(object):
    """One finished run, reduced to what a cross-host view needs.

    Taken as projections rather than as the run itself: three collections'
    worth of artifact tables held at once is three times the memory of the
    largest of them, for a join that touches five columns. The tables are
    released with the run that built them; what survives is this.
    """

    def __init__(self, label, path, tri, tables=None):
        self.label = label
        self.path = str(path)
        self.meta = dict(tri.meta)
        self.hostname = (tri.meta.get("Hostname")
                         or tri.meta.get("hostname") or "")
        # The collection-time note explains at length where the anchor came
        # from, which belongs in that run's own metadata rather than in a
        # column three hosts wide. The instant is the part that joins.
        self.collected = (tri.meta.get("Collection finished", "")
                          or "").split(" (")[0].strip()
        self.tz_offset = tri.meta.get("Host UTC offset", "")
        self.distro = tri.meta.get("Distribution", "")
        # Off the collection rather than out of meta: the layout is a fact
        # about the container, and the run records it in the METADATA table
        # instead of in tri.meta - which left this column empty for every host.
        col = getattr(tri, "col", None)
        self.layout = (getattr(col, "display_layout", "")
                       or getattr(col, "layout", "")
                       or getattr(col, "kind", "")
                       or tri.meta.get("Collection layout", ""))
        self.findings = [(f.severity, f.category, f.title, f.mitre or "",
                          f.first_seen or "", f.last_seen or "", f.count or 0)
                         for f in tri.findings]
        self.events = [(_ts_text(e.ts), e.severity, e.category,
                        e.description, e.source or "")
                       for e in tri.events]
        self.iocs = {}
        for value, whys in tri.iocs.items():
            span = tri.ioc_span.get(value) or ["", ""]
            self.iocs[value] = {
                "why": ", ".join(sorted(whys)),
                "sources": ", ".join(sorted(tri.ioc_sources.get(value, ()))),
                "count": tri.ioc_count.get(value, 0),
                "first": span[0] or "",
                "last": span[1] or "",
            }
        self.hashes = {}          # sha256 or md5 -> [paths]
        self.addresses = set()    # every address this host answers on
        self.names = set()        # every name this host answers to
        self.sessions = []        # inbound logins, with where they came from
        self.commands = []        # commands that name a host somewhere
        self.accounts = {}        # username -> what /etc/passwd said about it
        self.keys = {}            # authorized key -> [the files holding it]
        self.persist = {}         # (kind, value) -> where it was found
        self.techniques = {}      # ATT&CK id -> worst severity that carried it
        self._take_identity(tables)
        self._take_sessions(tables)
        self._take_commands(tables)
        self._take_hashes(tables)
        self._take_accounts(tables)
        self._take_keys(tables)
        self._take_persistence(tables)
        self._take_techniques()

    def _take_hashes(self, tables):
        """sha256 where the collection hashed anything, md5 where it did not.

        Keyed on one digest per file rather than on both: a host that produced
        only MD5 and a host that produced only SHA-256 have nothing to join on
        anyway, and indexing both would report the same pair of files twice.
        """
        t = next((x for x in (tables or []) if x.name == "FILE_HASHES"), None)
        if t is None:
            return
        cols = {c: i for i, c in enumerate(t.columns)}
        ip, i256, imd5 = cols.get("path"), cols.get("sha256"), cols.get("md5")
        if ip is None:
            return
        for row in t.iter_rows():
            digest = ""
            if i256 is not None and len(row) > i256:
                digest = (row[i256] or "").strip().lower()
            if not digest and imd5 is not None and len(row) > imd5:
                digest = (row[imd5] or "").strip().lower()
            path = (row[ip] or "").strip()
            if digest and path:
                self.hashes.setdefault(digest, []).append(path)

    @staticmethod
    def _cells(tables, name, wanted):
        """Rows of one table as dicts of the columns asked for, or nothing.

        By column name, never by position: an extractor that drops a column no
        row filled shifts every index after it, and a projection built on
        offsets would read the shell out of the home directory on exactly the
        collections where a column happened to be empty.
        """
        t = next((x for x in (tables or []) if x.name == name), None)
        if t is None:
            return []
        at = dict((c, i) for i, c in enumerate(t.columns))
        if not all(c in at for c in wanted):
            return []
        out = []
        for row in t.iter_rows():
            out.append(dict((c, (row[at[c]] if at[c] < len(row) else "") or "")
                            for c in wanted))
        return out

    def _take_identity(self, tables):
        """Every address and name this collection answers to.

        This is what turns two reports into one network. A login on db02 from
        10.0.0.14 is a fact about db02 and nothing more - until you know that
        10.0.0.14 is web01, which is sitting in the same case. The addresses
        come off the interface list rather than out of the logs, because what
        a host calls itself is the only reliable way to recognise it as the
        far end of somebody else's connection.
        """
        if self.hostname:
            self.names.add(self.hostname.lower())
            self.names.add(self.hostname.split(".")[0].lower())
        self.names.add(self.label.lower())
        for r in self._cells(tables, "INTERFACES", ("name", "addresses")):
            if r["name"] in ("lo", "lo0"):
                continue
            for addr in re.split(r"[,\s]+", r["addresses"]):
                addr = addr.split("/")[0].strip()
                if addr and not addr.startswith(("127.", "::1", "fe80:")):
                    self.addresses.add(addr)
        for r in self._cells(tables, "DEVICE_PROFILE", ("category", "value")):
            if r["category"] == "hostname" and r["value"]:
                self.names.add(r["value"].strip().lower())
        self.names.discard("")
        self.names.discard("localhost")

    def _take_sessions(self, tables):
        """Every login this host accepted, and the address it came from.

        Both halves of the authentication record, because they answer
        different halves of the question: AUTH_LOG carries the attempts with
        their result, LOGINS carries the sessions that actually existed. A
        successful login present in one and missing from the other is worth
        seeing, and dropping either would hide it.
        """
        for r in self._cells(tables, "AUTH_LOG",
                             ("timestamp_utc", "event", "user", "source_ip",
                              "result", "process")):
            if r["source_ip"]:
                self.sessions.append({
                    "when": r["timestamp_utc"], "user": r["user"],
                    "from": r["source_ip"].strip(),
                    "result": r["result"] or r["event"],
                    "service": r["process"], "source": "AUTH_LOG"})
        for r in self._cells(tables, "LOGINS",
                             ("user", "service", "source_host", "start",
                              "result")):
            if r["source_host"]:
                self.sessions.append({
                    "when": r["start"], "user": r["user"],
                    "from": r["source_host"].strip(),
                    "result": r["result"] or "session",
                    "service": r["service"], "source": "LOGINS"})

    #: What a command looks like when it reaches another machine. Deliberately
    #: narrow: `ssh`, `scp`, `rsync` and the rest name their target, and the
    #: target is the whole point. A grep for a hostname anywhere in any command
    #: would match a comment, a filename and a log path, and the resulting
    #: table would be noise wearing the word "lateral".
    REMOTE_CMD_RE = re.compile(
        r"\b(ssh|scp|sftp|rsync|ansible|ansible-playbook|salt|pssh|"
        r"clusterssh|mosh|telnet|ftp|curl|wget|nc|ncat|socat)\b", re.I)

    def _take_commands(self, tables):
        """Commands that invoke something capable of reaching another host."""
        for name, cols, cmd_col, who_col in (
                ("SHELL_HISTORY", ("user", "timestamp_utc", "command", "file"),
                 "command", "user"),
                ("CRON", ("run_as", "command", "file"), "command", "run_as"),
                ("PROCESSES", ("user", "start_utc", "args"), "args", "user")):
            for r in self._cells(tables, name, cols):
                cmd = (r.get(cmd_col) or "").strip()
                if not cmd or not self.REMOTE_CMD_RE.search(cmd):
                    continue
                self.commands.append({
                    "who": r.get(who_col) or "", "cmd": cmd,
                    "when": r.get("timestamp_utc") or r.get("start_utc") or "",
                    "source": name, "where": r.get("file") or ""})

    def _take_accounts(self, tables):
        for r in self._cells(tables, "USERS",
                             ("username", "uid", "home", "shell",
                              "password_status", "privileged_groups",
                              "authorized_keys")):
            if r["username"]:
                self.accounts[r["username"]] = r

    def _take_keys(self, tables):
        """The key material itself, not the line it sat on.

        An authorized_keys line is 'ssh-rsa AAAAB3... user@box', and the
        comment at the end is whatever the client that generated it felt like
        writing - so two hosts trusting one key can disagree about its name.
        The base64 body is the key; that is what is joined on.
        """
        for r in self._cells(tables, "SSH", ("type", "path", "detail")):
            if r["type"] != "authorized_keys" or not r["detail"]:
                continue
            parts = r["detail"].split()
            body = next((p for p in parts if len(p) > 40), "")
            if body:
                self.keys.setdefault(body, []).append(r["path"])

    def _take_persistence(self, tables):
        """What runs without anybody asking, across the three usual places."""
        for r in self._cells(tables, "CRON", ("command", "run_as", "file")):
            if r["command"]:
                self.persist[("cron", r["command"].strip())] = \
                    "%s (as %s)" % (r["file"], r["run_as"] or "?")
        for r in self._cells(tables, "SYSTEMD_UNITS", ("unit", "exec_start")):
            if r["exec_start"]:
                self.persist[("systemd", r["exec_start"].strip())] = r["unit"]
        for r in self._cells(tables, "LD_PRELOAD", ("path", "entry")):
            if r["entry"]:
                self.persist[("ld.so.preload", r["entry"].strip())] = r["path"]

    def _take_techniques(self):
        for sev, _cat, _title, mitre, _f, _l, _n in self.findings:
            for tech in _TECH_RE.findall(mitre or ""):
                have = self.techniques.get(tech)
                if have is None or SEV_RANK[sev] < SEV_RANK[have]:
                    self.techniques[tech] = sev

    def counts(self):
        n = defaultdict(int)
        for sev, _c, _t, _m, _f, _l, _n in self.findings:
            n[sev] += 1
        return n


class _CorrelationSource(object):
    """Stands in for the collection a Triage is normally built over.

    The correlation has findings, a timeline and metadata like any run, and
    reusing Triage for those means reusing every renderer that reads one. What
    it does not have is a collection - its evidence is three other runs - so
    the one attribute those renderers ask for is answered here rather than by
    inventing a directory that does not exist.
    """

    kind = "correlation"
    layout = "correlation"

    def __init__(self, cases):
        self.path = " + ".join(c.path for c in cases)


class Correlator(object):
    """Several HostCases, and what is true of more than one of them."""

    #: Evidence lines per finding. The table carries every row; a finding is
    #: an argument, and an argument that runs to four hundred lines is a dump.
    EVIDENCE = 30

    #: Rows kept for hashes that sit where a package put them. Unbounded, this
    #: is the operating system listed twice; the finding still counts them all.
    PACKAGED_ROW_CAP = 2000

    def __init__(self, cases, opts):
        self.cases = list(cases)
        self.opts = opts
        self.tri = Triage(_CorrelationSource(self.cases), opts)
        self.tables = []
        self.tri.meta["Hostname"] = "correlation of %d hosts" % len(self.cases)
        self.tri.meta["Hosts"] = ", ".join(c.label for c in self.cases)
        self.tri.meta["Collections"] = ", ".join(c.path for c in self.cases)

    # -- helpers ----------------------------------------------------------
    def table(self, name, title, columns, category, description):
        t = Table(name, title, columns, category, description)
        self.tables.append(t)
        return t

    def add(self, *a, **kw):
        self.tri.add(*a, **kw)

    #: The cross-host tables, in the order the Correlation tab shows them:
    #: the strongest claim first. A shared indicator or a shared key is
    #: evidence of one intrusion; a shared technique is evidence of one
    #: playbook, which is weaker and much more often innocent.
    CROSS_TABLES = ("CROSS_SESSIONS", "CROSS_COMMANDS", "CROSS_IOCS",
                    "CROSS_HASHES", "CROSS_KEYS", "CROSS_ACCOUNTS",
                    "CROSS_PERSISTENCE", "CROSS_FINDINGS", "CROSS_TECHNIQUES",
                    "HOSTS")

    def run(self):
        self.t_hosts()
        self.check_clocks()
        self.t_cross_sessions()
        self.t_cross_commands()
        self.t_cross_iocs()
        self.t_cross_hashes()
        self.t_cross_keys()
        self.t_cross_accounts()
        self.t_cross_persistence()
        self.t_cross_findings()
        self.t_cross_techniques()
        self.tri.findings.sort(key=lambda f: (SEV_RANK[f.severity], f.category,
                                              f.title))
        self.t_findings()
        self.t_timeline()
        return self.tables

    # -- 1. the hosts themselves -------------------------------------------
    def t_hosts(self):
        t = self.table("HOSTS", "The collections in this correlation",
                       [HOST_COLUMN, "input", "hostname", "distribution", "layout",
                        "collected_utc", "host_utc_offset", "findings",
                        "critical", "high", "medium", "low", "info",
                        "indicators", "events", "hashed_files"],
                       "Correlation",
                       "One row per input. `collection` is the label every "
                       "other table joins on - the same column a merged export "
                       "carries and the console filters by; `hostname` is what "
                       "the collection itself says it was, which is not always "
                       "the same thing and is worth reading when it is not.")
        for c in self.cases:
            n = c.counts()
            t.add(c.label, c.path, c.hostname, c.distro, c.layout,
                  c.collected, c.tz_offset, len(c.findings),
                  n["CRITICAL"], n["HIGH"], n["MEDIUM"], n["LOW"], n["INFO"],
                  len(c.iocs), len(c.events), len(c.hashes))
        self.add("INFO", "Correlation",
                 "%d collection(s) correlated" % len(self.cases),
                 "Every cross-host statement below is a join over these, and "
                 "over nothing else. A host that was not passed to this run "
                 "is not absent from the intrusion - it is absent from the "
                 "question.",
                 evidence=["%-16s %-20s %-24s %s"
                           % (c.label, c.hostname or "(hostname not recorded)",
                              c.distro or "-", c.path) for c in self.cases],
                 source="the inputs", count=len(self.cases))

    # -- 2. can these clocks be compared at all? ---------------------------
    def check_clocks(self):
        """Say what every ordering below rests on, before making one.

        Cross-host ordering is arithmetic on normalised UTC, and the
        normalisation is only as good as the offset each run resolved. A host
        whose zone nothing recorded was read as UTC; if it was not on UTC,
        every "four minutes after" in this report is wrong by that offset and
        wrong in one direction. That is not a caveat to bury in a footnote -
        it decides whether the sequence means anything.
        """
        unknown = [c for c in self.cases if not c.tz_offset
                   or "unknown" in c.tz_offset.lower()]
        rows = ["%-16s %-34s %s" % (c.label, c.tz_offset or "not recorded",
                                    c.collected or "collection time not recorded")
                for c in self.cases]
        if unknown:
            self.add("MEDIUM", "Correlation",
                     "%d host(s) did not record the offset their clock ran at"
                     % len(unknown),
                     "Their local log timestamps were read as UTC. If those "
                     "hosts were not on UTC, every ordering in this "
                     "correlation involving them is wrong by that offset - "
                     "which is exactly the error that makes a sequence of "
                     "events look like a different sequence rather than like "
                     "nonsense.",
                     evidence=rows, source="the inputs", count=len(unknown))
        else:
            self.add("INFO", "Correlation",
                     "Every host recorded the offset its clock ran at",
                     "Cross-host ordering below is arithmetic over these.",
                     evidence=rows, source="the inputs", count=len(self.cases))

    # -- 2b. one of these machines signing in to another -------------------
    def _who_is(self, value):
        """Which collection answers to this address or name, if any."""
        v = (value or "").strip().lower()
        if not v:
            return None
        for c in self.cases:
            if v in c.addresses or v in c.names or v.split(".")[0] in c.names:
                return c.label
        return None

    def t_cross_sessions(self):
        """Logins into one collection from another collection in this case.

        This is the table the whole exercise is for. Every other cross-host
        row says two machines have something in common; this one says one of
        them logged into the other, names the account it used and says whether
        it worked. A shared indicator is a lead. A session from web01 to db02
        at 03:14 as root is the intrusion moving, written down.

        It is only possible because both ends are in the case: the address in
        db02's auth log is just an address until web01's interface list says
        that address is web01.
        """
        t = self.table("CROSS_SESSIONS",
                       "Sign-ins from one of these machines to another",
                       ["timestamp_utc", "from_collection", "to_collection",
                        "user", "result", "service", "source_address",
                        "evidence"],
                       "Correlation",
                       "A login recorded on one collection whose source "
                       "address belongs to another collection in this case - "
                       "resolved against the interface list each host "
                       "reported, not guessed from a name. `result` is the "
                       "difference between an attempt and a foothold.")
        rows, pairs = [], defaultdict(lambda: {"ok": 0, "fail": 0, "users": set(),
                                               "first": "", "last": ""})
        for c in self.cases:
            for sess in c.sessions:
                origin = self._who_is(sess["from"])
                if not origin or origin == c.label:
                    continue
                ok = "fail" not in (sess["result"] or "").lower()
                rows.append((sess["when"], origin, c.label, sess["user"],
                             sess["result"], sess["service"], sess["from"],
                             sess["source"]))
                p = pairs[(origin, c.label)]
                p["ok" if ok else "fail"] += 1
                if sess["user"]:
                    p["users"].add(sess["user"])
                if sess["when"]:
                    if not p["first"] or sess["when"] < p["first"]:
                        p["first"] = sess["when"]
                    if not p["last"] or sess["when"] > p["last"]:
                        p["last"] = sess["when"]
        rows.sort()
        for r in rows:
            t.add(*r)
        if not pairs:
            return
        good = [(a, b, p) for (a, b), p in pairs.items() if p["ok"]]
        if good:
            self.add("CRITICAL", "Correlation",
                     "%d machine-to-machine sign-in path(s) succeeded between "
                     "these collections" % len(good),
                     "One host in this case authenticated to another. That is "
                     "lateral movement stated rather than inferred - the "
                     "source address is an address the destination logged and "
                     "the origin reported as its own. Follow the account: if "
                     "it is a service account or root, the same credential "
                     "probably reaches further than these two.",
                     evidence=["%s -> %-14s %d ok / %d failed as %s   %s .. %s"
                               % (a, b, p["ok"], p["fail"],
                                  ", ".join(sorted(p["users"])) or "(no user)",
                                  p["first"] or "?", p["last"] or "?")
                               for a, b, p in good[: self.EVIDENCE]],
                     source="CROSS_SESSIONS", count=len(good),
                     times=[p["first"] for _a, _b, p in good if p["first"]],
                     mitre="T1021.004 Remote Services: SSH / T1078 Valid Accounts")
        bad = [(a, b, p) for (a, b), p in pairs.items() if p["fail"] and not p["ok"]]
        if bad:
            self.add("HIGH", "Correlation",
                     "%d machine-to-machine sign-in(s) were attempted and "
                     "failed" % len(bad),
                     "One of these hosts tried to authenticate to another and "
                     "did not get in. A host that is scanning or guessing at "
                     "its neighbours is already compromised; the failure says "
                     "where it did not reach, not that nothing happened.",
                     evidence=["%s -> %-14s %d failed as %s"
                               % (a, b, p["fail"],
                                  ", ".join(sorted(p["users"])) or "(no user)")
                               for a, b, p in bad[: self.EVIDENCE]],
                     source="CROSS_SESSIONS", count=len(bad),
                     mitre="T1021 Remote Services / T1110 Brute Force")

    # -- 2c. one of these machines being told to run something on another ---
    def t_cross_commands(self):
        """Commands on one collection that name another collection.

        The other half of movement, and the half that survives when the
        destination's logs do not: `ssh root@10.0.0.14` in web01's shell
        history is evidence about db02 even if db02's auth log was rotated
        away. Scoped to commands that can actually reach a host - ssh, scp,
        rsync, ansible and the rest - because a hostname can appear in any
        string on the box, and a table of every mention would be noise
        wearing the word 'lateral'.
        """
        t = self.table("CROSS_COMMANDS",
                       "Commands on one machine naming another",
                       ["timestamp_utc", "from_collection", "to_collection",
                        "user", "matched", "command", "source", "where"],
                       "Correlation",
                       "A command recorded on one collection that names "
                       "another collection in this case, by address or by "
                       "name, and that invokes something able to reach it. "
                       "Read with CROSS_SESSIONS: the command is the "
                       "intention and the session is what happened.")
        rows, pairs = [], defaultdict(lambda: {"n": 0, "users": set(), "eg": ""})
        for c in self.cases:
            for cmd in c.commands:
                text = cmd["cmd"].lower()
                for other in self.cases:
                    if other.label == c.label:
                        continue
                    hit = next((tok for tok in
                                sorted(other.addresses | other.names, key=len,
                                       reverse=True)
                                if len(tok) > 3 and tok in text), "")
                    if not hit:
                        continue
                    rows.append((cmd["when"], c.label, other.label, cmd["who"],
                                 hit, trunc(cmd["cmd"], 200), cmd["source"],
                                 cmd["where"]))
                    p = pairs[(c.label, other.label)]
                    p["n"] += 1
                    if cmd["who"]:
                        p["users"].add(cmd["who"])
                    if not p["eg"]:
                        p["eg"] = trunc(cmd["cmd"], 90)
                    break
        rows.sort()
        for r in rows:
            t.add(*r)
        if pairs:
            self.add("HIGH", "Correlation",
                     "%d path(s) where one machine was told to reach another"
                     % len(pairs),
                     "A command on one of these hosts names another of them "
                     "and is capable of reaching it. Where CROSS_SESSIONS "
                     "shows the same pair, the two corroborate each other; "
                     "where it does not, either the destination did not log "
                     "the connection or it never happened - and which of "
                     "those it is, is worth ten minutes.",
                     evidence=["%s -> %-14s %d command(s) as %s\n      %s"
                               % (a, b, p["n"],
                                  ", ".join(sorted(p["users"])) or "?", p["eg"])
                               for (a, b), p in list(pairs.items())[: self.EVIDENCE]],
                     source="CROSS_COMMANDS", count=len(pairs),
                     mitre="T1021 Remote Services / T1570 Lateral Tool Transfer")

    # -- 3. the same indicator on more than one host -----------------------
    def t_cross_iocs(self):
        t = self.table("CROSS_IOCS", "Indicators seen on more than one host",
                       ["indicator", "type", "host_count", "hosts", "why",
                        "first_host", "first_utc", "last_host", "last_utc",
                        "spread", "total_mentions", "per_host"],
                       "Correlation",
                       "An indicator each host's own run extracted, joined on "
                       "the value. `first_host` is where it was seen "
                       "earliest and `spread` how long it took to reach the "
                       "last - the direction an intrusion travelled, which no "
                       "single host's report can state.")
        shared = defaultdict(dict)
        for c in self.cases:
            for value, info in c.iocs.items():
                shared[value][c.label] = info
        rows = []
        for value, by_host in shared.items():
            if len(by_host) < 2:
                continue
            seen = sorted(((info["first"], host) for host, info in by_host.items()
                           if info["first"]))
            first_host, first_utc = (seen[0][1], seen[0][0]) if seen else ("", "")
            last = sorted(((info["last"], host) for host, info in by_host.items()
                           if info["last"]))
            last_host, last_utc = (last[-1][1], last[-1][0]) if last else ("", "")
            whys = sorted(set(w for info in by_host.values()
                              for w in info["why"].split(", ") if w))
            rows.append((len(by_host), value, {
                "type": ioc_type(value),
                "hosts": ", ".join(sorted(by_host)),
                "why": ", ".join(whys),
                "first_host": first_host, "first_utc": first_utc,
                "last_host": last_host, "last_utc": last_utc,
                "spread": _gap(first_utc, last_utc),
                "total": sum(info["count"] for info in by_host.values()),
                "per_host": " | ".join(
                    "%s x%d%s" % (host, info["count"],
                                  " @ %s" % info["first"] if info["first"] else "")
                    for host, info in sorted(by_host.items())),
            }))
        rows.sort(key=lambda r: (-r[0], -r[2]["total"], r[1]))
        for n, value, d in rows:
            t.add(value, d["type"], n, d["hosts"], d["why"], d["first_host"],
                  d["first_utc"], d["last_host"], d["last_utc"], d["spread"],
                  d["total"], d["per_host"])
        if not rows:
            return

        every = [r for r in rows if r[0] == len(self.cases)] \
            if len(self.cases) > 2 else []
        ordered = [r for r in rows if r[2]["spread"]]
        self.add("HIGH", "Correlation",
                 "%d indicator(s) appear on more than one host" % len(rows),
                 "An address, hash or path that each host's run extracted "
                 "independently, joined on the value. One indicator on two "
                 "hosts is the shortest evidence there is that the two "
                 "incidents are one incident.",
                 evidence=["%-42s %-12s %d host(s): %s%s"
                           % (trunc(value, 42), d["type"], n, d["hosts"],
                              "  [%s -> %s, %s]"
                              % (d["first_host"], d["last_host"], d["spread"])
                              if d["spread"] else "")
                           for n, value, d in rows[: self.EVIDENCE]],
                 source="CROSS_IOCS", count=len(rows),
                 mitre="T1021 Remote Services",
                 times=[r[2]["first_utc"] for r in rows if r[2]["first_utc"]])
        if every:
            self.add("HIGH", "Correlation",
                     "%d indicator(s) appear on every host in this correlation"
                     % len(every),
                     "Present everywhere that was looked at, which is either "
                     "the intrusion's common infrastructure or something this "
                     "estate has in common for an innocent reason - a "
                     "monitoring agent, a shared jump host, an internal "
                     "resolver. Both are worth knowing and they are told "
                     "apart by what the indicator is, not by how many hosts "
                     "carry it.",
                     evidence=["%-42s %-12s %s" % (trunc(v, 42), d["type"], d["why"])
                               for _n, v, d in every[: self.EVIDENCE]],
                     source="CROSS_IOCS", count=len(every),
                     times=[d["first_utc"] for _n, _v, d in every if d["first_utc"]])
        if ordered:
            ordered.sort(key=lambda r: r[2]["first_utc"])
            self.add("MEDIUM", "Correlation",
                     "%d indicator(s) reached one host before another"
                     % len(ordered),
                     "The order is the direction. Read it against the clock "
                     "finding above: this is arithmetic on each host's "
                     "normalised UTC, so it is exactly as trustworthy as the "
                     "offsets those runs resolved.",
                     evidence=["%-38s %s %s  ->  %s %s  (%s)"
                               % (trunc(v, 38), d["first_host"], d["first_utc"],
                                  d["last_host"], d["last_utc"], d["spread"])
                               for _n, v, d in ordered[: self.EVIDENCE]],
                     source="CROSS_IOCS", count=len(ordered),
                     mitre="T1021 Remote Services",
                     times=[d["first_utc"] for _n, _v, d in ordered])

    # -- 4. the same conclusion on more than one host ----------------------
    def t_cross_findings(self):
        t = self.table("CROSS_FINDINGS", "Findings raised on more than one host",
                       ["severity", "category", "finding", "technique",
                        "host_count", "hosts", "first_utc", "last_utc",
                        "total_occurrences", "per_host"],
                       "Correlation",
                       "The same check firing on several hosts, grouped by "
                       "title with its counts masked - '3 executable file(s)' "
                       "and '7 executable file(s)' are one finding reported "
                       "twice. Severity is the worst any host gave it.")
        groups = defaultdict(dict)
        for c in self.cases:
            for sev, cat, title, mitre, first, last, n in c.findings:
                key = (cat, _norm_title(title))
                cur = groups[key].get(c.label)
                if cur is None or SEV_RANK[sev] < SEV_RANK[cur[0]]:
                    groups[key][c.label] = (sev, mitre, first, last, n, title)
        rows = []
        for (cat, norm), by_host in groups.items():
            if len(by_host) < 2:
                continue
            sev = min((v[0] for v in by_host.values()), key=lambda s: SEV_RANK[s])
            mitre = next((v[1] for v in by_host.values() if v[1]), "")
            first, last = span_of([v[2] for v in by_host.values()]
                                  + [v[3] for v in by_host.values()])
            rows.append((SEV_RANK[sev], -len(by_host), cat, norm, sev, mitre,
                         by_host, first, last))
        rows.sort()
        for _r, _n, cat, norm, sev, mitre, by_host, first, last in rows:
            t.add(sev, cat, norm, mitre, len(by_host),
                  ", ".join(sorted(by_host)), first, last,
                  sum(v[4] for v in by_host.values()),
                  " | ".join("%s: %s" % (h, v[5])
                             for h, v in sorted(by_host.items())))
        if not rows:
            return
        loud = [r for r in rows if r[4] in ("CRITICAL", "HIGH")]
        worst = rows[0][4]
        self.add(worst if loud else "INFO", "Correlation",
                 "%d finding(s) were raised on more than one host" % len(rows),
                 "The same conclusion reached independently on several hosts. "
                 "Where that conclusion is CRITICAL or HIGH it is the shape "
                 "of the intrusion repeating, and the hosts that share it are "
                 "the ones to work first.",
                 evidence=["[%-8s] %-52s %d hosts: %s"
                           % (sev, trunc("%s / %s" % (cat, norm), 52),
                              len(by_host), ", ".join(sorted(by_host)))
                           for _r, _n, cat, norm, sev, _m, by_host, _f, _l
                           in rows[: self.EVIDENCE]],
                 source="CROSS_FINDINGS", count=len(rows),
                 times=[r[7] for r in rows if r[7]])

    # -- 5. the same bytes on more than one host ---------------------------
    def t_cross_hashes(self):
        t = self.table("CROSS_HASHES", "File hashes present on more than one host",
                       ["digest", "host_count", "hosts", "notable",
                        "same_path", "paths", "per_host"],
                       "Correlation",
                       "One file's digest found on several hosts. Two "
                       "machines built from one image share every byte of "
                       "/usr/bin, so `notable` marks the rows where at least "
                       "one copy sits somewhere a package would not put it - "
                       "and `same_path` says whether it was moved, because a "
                       "shared binary at two different paths is a deployment "
                       "rather than a distribution. Every notable row is here; "
                       "the packaged ones are capped, because unbounded they "
                       "are the operating system listed once per file.")
        shared = defaultdict(dict)
        for c in self.cases:
            for digest, paths in c.hashes.items():
                shared[digest][c.label] = sorted(set(paths))
        rows = []
        for digest, by_host in shared.items():
            if len(by_host) < 2:
                continue
            allpaths = sorted(set(p for ps in by_host.values() for p in ps))
            notable = any(p.startswith(NOTABLE_DIRS) for p in allpaths)
            same = len(allpaths) == 1
            rows.append((not notable, not same, -len(by_host), digest,
                         by_host, allpaths, notable, same))
        rows.sort()
        # Every notable row, and a bounded sample of the rest. Two hosts built
        # from one image share tens of thousands of files under /usr, all of
        # them uninteresting and all of them in this table - which made
        # CROSS_HASHES the largest thing in the export and the slowest panel
        # in the console, for rows whose whole content is "these machines run
        # the same distribution". The count on the finding stays exact.
        kept = 0
        for _a, _b, _c2, digest, by_host, allpaths, notable, same in rows:
            if not notable:
                kept += 1
                if kept > self.PACKAGED_ROW_CAP:
                    continue
            t.add(digest, len(by_host), ", ".join(sorted(by_host)),
                  "yes" if notable else "", "yes" if same else "no",
                  " | ".join(allpaths[:8]),
                  " | ".join("%s: %s" % (h, ", ".join(p[:4]))
                             for h, p in sorted(by_host.items())))
        if not rows:
            return
        notables = [r for r in rows if r[6]]
        if notables:
            self.add("HIGH", "Correlation",
                     "%d file(s) with the same contents on more than one host, "
                     "outside the packaged tree" % len(notables),
                     "Identical bytes under /tmp, /home, /opt, /usr/local or "
                     "a web root on several machines is one file that was put "
                     "on all of them. A distribution does not deliver files "
                     "there; a deployment does.",
                     evidence=["%s  %d hosts: %s\n      %s"
                               % (r[3][:32], len(r[4]), ", ".join(sorted(r[4])),
                                  " | ".join(r[5][:4]))
                               for r in notables[: self.EVIDENCE]],
                     source="CROSS_HASHES", count=len(notables),
                     mitre="T1105 Ingress Tool Transfer")
        rest = len(rows) - len(notables)
        if rest:
            self.add("INFO", "Correlation",
                     "%d further file(s) are byte-identical across hosts" % rest,
                     "Every one of them sits where a package puts files, "
                     "which on machines built from one image is what being "
                     "built from one image looks like. Listed in CROSS_HASHES "
                     "rather than here.",
                     source="CROSS_HASHES", count=rest)

    # -- 5b. the same key trusted by more than one host --------------------
    def t_cross_keys(self):
        t = self.table("CROSS_KEYS", "SSH keys trusted by more than one host",
                       ["key_type", "fingerprint_head", "host_count", "hosts",
                        "comment", "paths"],
                       "Correlation",
                       "One public key found in authorized_keys on several "
                       "hosts, joined on the key material rather than on the "
                       "comment after it - the comment is whatever the client "
                       "that generated the key felt like writing, and two "
                       "hosts trusting one key often disagree about its name. "
                       "Shared keys are ordinary in a managed estate and are "
                       "how one stolen private key becomes every host in it.")
        shared = defaultdict(dict)
        for c in self.cases:
            for body, paths in c.keys.items():
                shared[body][c.label] = sorted(set(paths))
        rows = [(len(by), body, by) for body, by in shared.items() if len(by) > 1]
        rows.sort(key=lambda r: -r[0])
        for n, body, by in rows:
            t.add(_key_type(body), body[:24] + "...", n, ", ".join(sorted(by)),
                  "", " | ".join("%s: %s" % (h, ", ".join(p))
                                 for h, p in sorted(by.items())))
        if rows:
            self.add("HIGH" if any(r[0] == len(self.cases) for r in rows)
                     else "MEDIUM", "Correlation",
                     "%d SSH key(s) are trusted by more than one host" % len(rows),
                     "Whoever holds the private half can reach every host "
                     "listed against it, with no password and usually with no "
                     "log entry that looks unusual. Check each against the "
                     "keys your estate is supposed to have - a shared "
                     "management key is expected, and an attacker's key added "
                     "to three hosts looks exactly the same from here.",
                     evidence=["%-12s %s...  %d host(s): %s"
                               % (_key_type(b), b[:28], n, ", ".join(sorted(by)))
                               for n, b, by in rows[: self.EVIDENCE]],
                     source="CROSS_KEYS", count=len(rows),
                     mitre="T1098.004 SSH Authorized Keys")

    # -- 5c. the same account on more than one host ------------------------
    def t_cross_accounts(self):
        t = self.table("CROSS_ACCOUNTS", "Accounts present on more than one host",
                       ["username", "uid", "host_count", "hosts", "consistent",
                        "shells", "homes", "password_status", "privileged_on"],
                       "Correlation",
                       "One username on several hosts. `consistent` is whether "
                       "uid, shell and home agree everywhere - a name that "
                       "means one thing on web01 and something else on db02 is "
                       "either a naming collision or an account somebody added "
                       "by hand to look like the others. System accounts the "
                       "distribution creates are excluded: every Linux host "
                       "has daemon and www-data, and saying so is noise.")
        shared = defaultdict(dict)
        for c in self.cases:
            for name, info in c.accounts.items():
                shared[name][c.label] = info
        rows = []
        for name, by_host in shared.items():
            if len(by_host) < 2 or not _interesting_account(name, by_host):
                continue
            uids = sorted(set(i["uid"] for i in by_host.values()))
            shells = sorted(set(i["shell"] for i in by_host.values() if i["shell"]))
            homes = sorted(set(i["home"] for i in by_host.values() if i["home"]))
            priv = sorted(h for h, i in by_host.items() if i["privileged_groups"])
            rows.append((-len(by_host), name, uids, shells, homes, by_host, priv))
        rows.sort()
        for _n, name, uids, shells, homes, by_host, priv in rows:
            consistent = len(uids) == 1 and len(shells) <= 1 and len(homes) <= 1
            t.add(name, ", ".join(uids), len(by_host),
                  ", ".join(sorted(by_host)), "yes" if consistent else "no",
                  ", ".join(shells), ", ".join(homes),
                  ", ".join(sorted(set(i["password_status"]
                                       for i in by_host.values() if i["password_status"]))),
                  ", ".join(priv))
        odd = [r for r in rows
               if len(r[2]) > 1 or len(r[3]) > 1 or len(r[4]) > 1]
        if odd:
            self.add("MEDIUM", "Correlation",
                     "%d account(s) are defined differently on the hosts that "
                     "share them" % len(odd),
                     "One username, two definitions. A managed estate creates "
                     "an account the same way everywhere; a name that carries "
                     "a different uid, shell or home on one host was added "
                     "there separately, which is what an intruder's account "
                     "made to blend in looks like.",
                     evidence=["%-18s uid %-14s %s"
                               % (r[1], "/".join(r[2]), ", ".join(sorted(r[5])))
                               for r in odd[: self.EVIDENCE]],
                     source="CROSS_ACCOUNTS", count=len(odd),
                     mitre="T1136 Create Account")
        elif rows:
            self.add("INFO", "Correlation",
                     "%d non-system account(s) exist on more than one host"
                     % len(rows),
                     "Consistently defined on every host that has them, which "
                     "is what central account management looks like.",
                     evidence=["%-18s uid %-8s %s"
                               % (r[1], "/".join(r[2]), ", ".join(sorted(r[5])))
                               for r in rows[: self.EVIDENCE]],
                     source="CROSS_ACCOUNTS", count=len(rows))

    # -- 5d. the same thing set to run on more than one host ---------------
    def t_cross_persistence(self):
        t = self.table("CROSS_PERSISTENCE",
                       "Autostart entries on more than one host",
                       ["kind", "value", "host_count", "hosts", "where"],
                       "Correlation",
                       "A cron command, a systemd ExecStart or an "
                       "ld.so.preload entry that appears on several hosts. "
                       "Configuration management puts the same entries "
                       "everywhere and so does an intruder who scripted the "
                       "install; what tells them apart is what the command "
                       "does, which is why the command itself is the column.")
        shared = defaultdict(dict)
        for c in self.cases:
            for (kind, value), where in c.persist.items():
                shared[(kind, value)][c.label] = where
        rows = [(-len(by), kind, value, by)
                for (kind, value), by in shared.items() if len(by) > 1]
        rows.sort()
        for _n, kind, value, by in rows:
            t.add(kind, value, len(by), ", ".join(sorted(by)),
                  " | ".join("%s: %s" % (h, w) for h, w in sorted(by.items())))
        if rows:
            preload = [r for r in rows if r[1] == "ld.so.preload"]
            self.add("HIGH" if preload else "INFO", "Correlation",
                     "%d autostart entry(ies) appear on more than one host"
                     % len(rows),
                     "The same thing set to run on several machines. An "
                     "ld.so.preload entry shared across hosts is a userland "
                     "rootkit deployed to all of them and is why this is HIGH "
                     "when one is present; a shared cron line is as likely to "
                     "be the configuration management that built the estate."
                     if preload else
                     "The same thing set to run on several machines - which "
                     "on a managed estate is what management looks like. Read "
                     "the commands rather than the count.",
                     evidence=["%-14s %-3d host(s)  %s"
                               % (r[1], -r[0], trunc(r[2], 84))
                               for r in rows[: self.EVIDENCE]],
                     source="CROSS_PERSISTENCE", count=len(rows),
                     mitre="T1053 Scheduled Task/Job / T1574.006 LD_PRELOAD")

    # -- 5e. the shape of the intrusion, per host --------------------------
    def t_cross_techniques(self):
        t = self.table("CROSS_TECHNIQUES", "ATT&CK techniques by host",
                       ["technique", "severity", "host_count", "hosts",
                        "missing_from"],
                       "Correlation",
                       "Which hosts raised which technique, and - the column "
                       "worth reading - which did not. A technique on every "
                       "host but one is either a host that escaped that step "
                       "or a host where the evidence for it was not "
                       "collected, and those are very different answers.")
        by_tech = defaultdict(dict)
        for c in self.cases:
            for tech, sev in c.techniques.items():
                by_tech[tech][c.label] = sev
        labels = [c.label for c in self.cases]
        rows = []
        for tech, by_host in by_tech.items():
            sev = min(by_host.values(), key=lambda s: SEV_RANK[s])
            rows.append((SEV_RANK[sev], -len(by_host), tech, sev, by_host))
        rows.sort()
        for _r, _n, tech, sev, by_host in rows:
            t.add(tech, sev, len(by_host), ", ".join(sorted(by_host)),
                  ", ".join(h for h in labels if h not in by_host))
        shared = [r for r in rows if len(r[4]) > 1]
        if shared:
            self.add(shared[0][3] if shared[0][3] in ("CRITICAL", "HIGH")
                     else "INFO", "Correlation",
                     "%d technique(s) were observed on more than one host"
                     % len(shared),
                     "The same step of the same playbook, reached "
                     "independently on several machines. Where a technique is "
                     "on every host but one, look at that host before "
                     "concluding it was spared - an artifact that was never "
                     "collected raises no finding either.",
                     evidence=["%-12s [%-8s] %d host(s): %s"
                               % (r[2], r[3], len(r[4]), ", ".join(sorted(r[4])))
                               for r in shared[: self.EVIDENCE]],
                     source="CROSS_TECHNIQUES", count=len(shared))

    # -- 6. the two views the console is built on --------------------------
    def t_findings(self):
        """The correlation's own findings, in the shape the console reads.

        Named FINDINGS rather than CROSS_ANYTHING on purpose: the console's
        findings view, its severity chips and its ATT&CK matrix are all
        computed from a table of that name, so a correlation written this way
        opens in the same page as a single host and needs no second console.
        """
        t = self.table("FINDINGS", "Correlation findings",
                       ["severity", "category", "title", "mitre", "source",
                        "count", "first_utc", "last_utc", "detail",
                        "evidence_count", "evidence"],
                       "Analysis",
                       "What is true of more than one of these collections. "
                       "Each host's own findings stayed in that host's own "
                       "report; these exist only between them.")
        for f in self.tri.findings:
            ev = f.evidence or []
            t.add(f.severity, f.category, f.title, f.mitre, f.source, f.count,
                  f.first_seen, f.last_seen, (f.detail or "").replace("\n", " | "),
                  len(ev), "\n".join(str(e) for e in ev))

    def t_timeline(self):
        """Every host's timeline, merged, with the host on every row.

        The merge is the point: two hosts' events interleaved in one ordering
        is the sequence an intrusion actually had, and it is a sort rather
        than an analysis because each run already normalised its own clocks to
        UTC. The host column is what makes a spike in the chart answerable -
        one machine being noisy, or three machines at once.
        """
        t = self.table("TIMELINE", "Merged event timeline",
                       ["timestamp_utc", "host", "severity", "category",
                        "description", "source"],
                       "Analysis",
                       "Every dated event from every collection here, in one "
                       "ordering, each row carrying the host it came from. "
                       "The correlation's own findings are on it too, under "
                       "the host '(correlation)'.")
        rows = []
        for c in self.cases:
            for ts, sev, cat, desc, src in c.events:
                if ts:
                    rows.append((ts, c.label, sev, cat, desc, src))
        for f in self.tri.findings:
            if f.first_seen:
                rows.append((f.first_seen, "(correlation)", f.severity,
                             f.category, f.title, f.source or "(finding)"))
        rows.sort()
        for r in rows:
            t.add(*r)


#: uid below this is the distribution's own, not somebody's account. Every
#: Linux host has daemon, bin, sys and www-data; reporting them as "shared
#: across your estate" is true and useless.
SYSTEM_UID_MAX = 999

#: Names that carry a real uid but are still the distribution's.
SYSTEM_NAMES = frozenset(("root", "nobody", "sync", "shutdown", "halt",
                          "operator"))


def _interesting_account(name, by_host):
    """Is this account somebody's, or the distribution's?"""
    if name in SYSTEM_NAMES:
        return False
    for info in by_host.values():
        try:
            uid = int(info.get("uid") or -1)
        except (TypeError, ValueError):
            return True             # unreadable uid is itself worth a look
        if uid > SYSTEM_UID_MAX or uid == 0:
            return True             # a second uid-0 account is the point
    return False


def _key_type(body):
    """'AAAAB3NzaC1yc2E...' -> 'ssh-rsa'. The type is encoded in the key.

    Read from the body rather than from the prefix on the line, because the
    body is what these rows are joined on and a line's prefix can disagree
    with it - an authorized_keys line edited by hand can say ssh-rsa in front
    of an ed25519 key, and the key is the fact.

    Only the head is decoded. The type is a length-prefixed string in the
    first bytes of the blob, and 52 base64 characters cover the longest name
    there is - sk-ecdsa-sha2-nistp256@openssh.com, at 34 - so that is where
    the read stops. Stopping there means a body that is truncated, padded
    wrong or damaged further along still names its type instead of failing
    whole, and it avoids decoding a kilobyte of key to read nine bytes of it.
    """
    head = (body or "")[:52]
    head = head[: len(head) // 4 * 4]      # base64 only decodes whole quads
    if len(head) < 8:
        return ""
    try:
        import base64
        raw = base64.b64decode(head, validate=False)
    except Exception:
        return ""
    if len(raw) < 5:
        return ""
    n = int.from_bytes(raw[:4], "big")
    if 0 < n <= len(raw) - 4:
        return raw[4:4 + n].decode("ascii", "replace")
    return ""


def _gap(first, last):
    """'2026-03-24 03:01:12' and '... 03:14:40' -> '13m'. Empty when equal."""
    if not first or not last or first == last:
        return ""
    try:
        fmt = "%Y-%m-%d %H:%M:%S"
        d = datetime.strptime(last[:19], fmt) - datetime.strptime(first[:19], fmt)
    except (ValueError, TypeError):
        return ""
    secs = int(d.total_seconds())
    if secs <= 0:
        return ""
    if secs >= 172800:
        return "%d days" % (secs // 86400)
    if secs >= 3600:
        h, m = secs // 3600, (secs % 3600) // 60
        return "%dh%dm" % (h, m) if m else "%dh" % h
    if secs >= 120:
        return "%dm" % (secs // 60)
    return "%ds" % secs


def write_correlation(cases, outdir, opts):
    """Correlate the finished runs and write the result beside them.

    Three formats, always, rather than mirroring the per-host output flags:
    the correlation is one small artifact and the question "which of my nine
    flags applied to it" is not worth making an analyst answer. The console is
    the one to open; the CSVs and the JSON are for everything else.
    """
    if len(cases) < 2:
        status("[!] --correlate needs at least two collections; skipped")
        return None
    cor = Correlator(cases, opts)
    tables = cor.run()
    os.makedirs(outdir, exist_ok=True)
    meta = {"collection": "correlation of %d collections" % len(cases),
            "hostname": ", ".join(c.label for c in cases),
            "collected": "", "scope": "correlation", "layout": "correlation",
            "tables": len(tables),
            "rows_total": sum(len(t) for t in tables)}
    csv_dir = os.path.join(outdir, "csv")
    json_path = os.path.join(outdir, "tables.json")
    html_path = os.path.join(outdir, "console.html")
    n = write_tables_csv(tables, csv_dir)
    write_tables_json(tables, json_path, meta)
    write_tables_html(tables, html_path, getattr(opts, "html_rows", 0), meta,
                      cor.tri, opts)
    status("[+] correlation: %d table(s), %s row(s), %d finding(s)"
           % (len(tables), "{:,}".format(meta["rows_total"]),
              len(cor.tri.findings)))
    print("[+] correlation written to %s (console.html, tables.json, %d CSVs)"
          % (outdir, n), file=sys.stderr)
    return cor
