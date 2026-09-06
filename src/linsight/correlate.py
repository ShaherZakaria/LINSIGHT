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

import bisect

from collections import defaultdict
from datetime import datetime
import os
import re
import sys

from .model import Finding, SEVERITIES, SEV_RANK
from .term import status, trunc
from .common import (
    PRIVILEGED_GROUPS, TMPFS_DIRS, _ts_text, ioc_type, span_of)
from .triage import Triage
from .tables import Table
from .writers import write_tables_csv, write_tables_html, write_tables_json


#: Where a shared hash stops being "both hosts run the same distribution" and
#: starts being a file somebody put there. Two hosts built from one image share
#: every byte of /usr/bin, so an unscoped hash join returns the operating
#: system and buries the four files that matter.
NOTABLE_DIRS = TMPFS_DIRS + ("/home/", "/root/", "/usr/local/", "/opt/",
                             "/var/www/", "/srv/", "/var/spool/")

#: How long after a sign-in a second sign-in still reads as the same movement.
#: Long enough to cover an intruder who lands, looks around and moves on;
#: short enough that two unrelated administrative logins a week apart are not
#: drawn as one path.
CHAIN_WINDOW_SECONDS = 24 * 3600


def _bump(store, key, when, ok, code):
    """Fold one web-log row into a per-key aggregate."""
    got = store.get(key)
    if got is None:
        got = store[key] = {"n": 0, "first": "", "last": "", "ok": 0,
                            "codes": set()}
    got["n"] += 1
    got["ok"] += 1 if ok else 0
    if when:
        if not got["first"] or when < got["first"]:
            got["first"] = when
        if not got["last"] or when > got["last"]:
            got["last"] = when
    if code and len(got["codes"]) < 12:
        got["codes"].add(code)
    return got


def _cap_by_count(store, cap):
    """The busiest `cap` keys, or all of them where there are fewer."""
    if len(store) <= cap:
        return store
    keep = sorted(store.items(), key=lambda kv: -kv[1]["n"])[:cap]
    return dict(keep)


#: Findings are grouped across hosts by title, and a title carries its own
#: count - "3 executable file(s)" on one host and "7 executable file(s)" on
#: the next are one check reported twice, not two different findings.
_COUNT_RE = re.compile(r"\d[\d,]*")

#: 'T1110 Brute Force / T1078 Valid Accounts' -> T1110, T1078. The same shape
#: the console's matrix reads, so a technique means one thing in both.
_TECH_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


#: 'address 192.168.2.100', 'addresses: [10.0.0.5/24]', 'address' with the
#: value in the next column - the three shapes a network configuration writes
#: the host's own address in. Anchored, so 'dns-nameservers' and 'gateway'
#: cannot reach it.
_SELF_ADDRESS_RE = re.compile(r"^address(?:es)?\b[\s:=]*(.*)$", re.I)

_ADDRESS_SPLIT_RE = re.compile(r"[,\s\[\]'\"]+")

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_IPV6_RE = re.compile(r"^[0-9a-f:]{3,45}$", re.I)


def _is_address(text):
    """An address this host answers on, or something that only looks like one."""
    if not text or text.startswith(("127.", "::1", "fe80:", "0.0.0.0")):
        return False
    if _IPV4_RE.match(text):
        return all(0 <= int(p) <= 255 for p in text.split("."))
    return ":" in text and bool(_IPV6_RE.match(text))


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


#: What the collection column says on a row that is about all of them.
#:
#: Not a host label, and deliberately not one of the real ones: a cross-host
#: finding is a statement about the case rather than about any collection in
#: it, and lending it a host's name would put it under a filter it does not
#: belong to. The console's collection picker is built from the input labels,
#: so this never becomes an option in it - narrowing to a host hides these
#: rows, which is the same answer the Correlation tab gives for the same
#: reason.
CORRELATION_LABEL = "(correlation)"


def fold_correlation(tables, cross, column):
    """Put the correlation's own findings and timeline into the merged ones.

    The cross-host tables join the merged export, and the correlator's
    FINDINGS and TIMELINE are held back because the export already has one of
    each. Held back was all that happened to them: the console reads its
    findings list, its severity chips and its ATT&CK matrix out of the
    FINDINGS *table*, so every correlation finding - including "a machine in
    this case signed in to another", which is the strongest thing this tool
    can say - was computed, counted, and then shown nowhere. Not in the
    console, not in FINDINGS.csv, not in case.db. Only --html and --json saw
    them, because those render a Triage rather than a table.

    So the rows are folded in instead of dropped, under a label of their own.
    """
    merged = dict((t.name, t) for t in tables)
    for src in cross:
        if src.name not in ("FINDINGS", "TIMELINE"):
            continue
        dst = merged.get(src.name)
        if dst is None:
            continue
        at = [dst.columns.index(c) if c in dst.columns else -1
              for c in src.columns]
        for row in src.iter_rows():
            new = [""] * len(dst.columns)
            for i, value in zip(at, row):
                if i >= 0:
                    new[i] = value
            if dst.columns[0] == column:
                new[0] = CORRELATION_LABEL
            dst.add(*new)
    return tables


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
        self.file_times = {}      # digest -> when this host first held it
        self.sudo_rules = {}      # a sudoers rule -> the file it is in
        self.group_members = {}   # (privileged group, member) -> gid
        self.web_clients = {}     # client address -> what it asked this host
        self.web_requests = {}    # (method, resource) -> how it was answered
        self._take_identity(tables)
        self._take_sessions(tables)
        self._take_commands(tables)
        self._take_hashes(tables)
        self._take_file_times(tables)
        self._take_accounts(tables)
        self._take_keys(tables)
        self._take_persistence(tables)
        self._take_privilege(tables)
        self._take_web(tables)
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

    def _take_file_times(self, tables):
        """When each hashed file was created on this host, where that is known.

        A shared hash says two machines hold the same bytes. It does not say
        which of them had them first, and that is the whole difference between
        "these hosts run the same distribution" and "this file was put on that
        one from this one". crtime is the clock that answers it: mtime rides
        along with a copy - scp -p, cp -a and every archive preserve it, which
        is exactly why an implant carries the same mtime on all three machines
        - while the creation time is written by the filesystem that received
        the file and cannot be carried in from anywhere.

        FILE_HASHES already carries mtime, so only the creation time has to be
        looked up. It is read off FILE_INVENTORY for the hashed paths alone: a
        few hundred lookups against one pass of a table that is otherwise a
        quarter of a million rows about files nobody hashed.
        """
        paths = {}
        for digest, plist in self.hashes.items():
            for path in plist:
                paths.setdefault(path, digest)
        if not paths:
            return
        for r in self._stream(tables, "FILE_INVENTORY",
                             ("host_path", "crtime_utc", "mtime_utc")):
            digest = paths.get(r["host_path"])
            if not digest:
                continue
            crtime, mtime = r["crtime_utc"].strip(), r["mtime_utc"].strip()
            when = crtime or mtime
            if not when:
                continue
            got = self.file_times.get(digest)
            # The earliest copy is the one that answers "when did this host
            # first hold these bytes"; a second copy made later is a local
            # copy, not the arrival.
            if got is None or when < got["when"]:
                self.file_times[digest] = {
                    "path": r["host_path"], "when": when,
                    "basis": "crtime" if crtime else "mtime",
                    "mtime": mtime}

    def _take_privilege(self, tables):
        """Sudo rules and privileged group membership, as configuration.

        Both answer "who is root here", and both are worth comparing across
        machines. One NOPASSWD rule for a service account on three hosts is a
        single decision that made all three reachable from any of them, and a
        name in sudo or wheel on hosts that share nothing else is either a
        management standard or a foothold that was built three times.
        """
        for r in self._cells(tables, "SUDOERS", ("file", "rule", "nopasswd")):
            rule = " ".join((r["rule"] or "").split())
            if rule and not rule.startswith(("Defaults", "#include", "@include")):
                self.sudo_rules[rule] = "%s%s" % (
                    r["file"], " [NOPASSWD]" if r["nopasswd"] else "")
        for r in self._cells(tables, "GROUPS", ("group", "gid", "members")):
            if r["group"].strip().lower() not in PRIVILEGED_GROUPS:
                continue
            for member in (m.strip() for m in r["members"].split(",")):
                if member:
                    self.group_members[(r["group"].strip(), member)] = r["gid"]

    #: How many distinct web values one host may contribute to the join.
    #:
    #: A scanned host answers hundreds of thousands of requests from tens of
    #: thousands of addresses, and a cross-host table is not improved by all
    #: of them: the shape worth seeing is "this one thing reached several of
    #: these machines". Capped by count, so what survives is what that host
    #: saw most of.
    WEB_CAP = 20000

    def _take_web(self, tables):
        """What each host was asked for over HTTP, aggregated before the join.

        Per address and per request, because they answer different questions.
        One client address reaching several of these machines is a single
        actor working the estate. One request path appearing on several is a
        pattern - a scanner's list, or the same exploit tried everywhere - and
        it is a pattern whether or not one address is behind it, which is why
        it is counted separately.

        Aggregated here rather than in the correlator because WEB_LOG is half
        a million rows on a busy host, and three of those held at once row by
        row is the memory this class exists not to spend.
        """
        clients, requests = {}, {}
        for r in self._stream(tables, "WEB_LOG",
                             ("timestamp_utc", "client_ip", "method",
                              "resource", "status")):
            when = r["timestamp_utc"]
            code = r["status"].strip()
            ok = code[:1] in ("2", "3")
            ip = r["client_ip"].strip()
            if ip:
                _bump(clients, ip, when, ok, code)
            res = r["resource"].strip()
            if res:
                _bump(requests, ((r["method"] or "").strip().upper(), res),
                      when, ok, code)
        self.web_clients = _cap_by_count(clients, self.WEB_CAP)
        self.web_requests = _cap_by_count(requests, self.WEB_CAP)

    @staticmethod
    def _stream(tables, name, wanted):
        """_cells, one row at a time.

        The same projection, without building a list first. WEB_LOG is half a
        million rows on a busy host and FILE_INVENTORY a quarter of a million
        on any disk image; a list of dicts over either is hundreds of
        megabytes held to read five columns and throw the rest away.
        """
        t = next((x for x in (tables or []) if x.name == name), None)
        if t is None:
            return
        at = dict((c, i) for i, c in enumerate(t.columns))
        if not all(c in at for c in wanted):
            return
        for row in t.iter_rows():
            yield dict((c, (row[at[c]] if at[c] < len(row) else "") or "")
                       for c in wanted)

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
        # And, only where that answered nothing, off the configuration.
        #
        # INTERFACES is `ip addr` at collection time, so a disk image produced
        # none of it and every host read from an image resolved to no
        # addresses at all. That is not a small gap: it is the one input
        # CROSS_SESSIONS runs on, so the table this whole module exists for
        # silently reported nothing for disk images however much the logs
        # held. On a three-host Hadoop cluster, slave1's auth.log carried 116
        # successful logins from the master and the correlation reported no
        # sign-ins at all.
        #
        # INTERFACES now reads the on-disk configuration itself when no
        # command ran, and it reads it with the file's structure intact -
        # which is the whole difference. NETWORK_CONFIG is a flat list of
        # key-value pairs, so a netplan file's
        #
        #     nameservers:
        #       addresses: [8.8.8.8, 1.1.1.1]
        #
        # arrives here as the key `addresses` with nothing left to say it was
        # nested under nameservers, and this host claimed Google's resolver as
        # one of its own interfaces. An address wrongly attributed to a host
        # is worse than one missing: _who_is answers with a machine in the
        # case, and every table that names the address then labels traffic to
        # a public resolver as one of these machines.
        #
        # So the flat scrape is kept for the collection that produced neither
        # command output nor a configuration file this parser understands, and
        # is skipped entirely the moment the interface list said anything.
        if self.addresses:
            self._identity_names(tables)
            return
        for r in self._cells(tables, "NETWORK_CONFIG", ("key", "value")):
            m = _SELF_ADDRESS_RE.match(r["key"].strip())
            if not m:
                continue
            for tok in _ADDRESS_SPLIT_RE.split("%s %s" % (m.group(1),
                                                          r["value"])):
                addr = tok.split("/")[0].strip()
                if _is_address(addr):
                    self.addresses.add(addr)
        self._identity_names(tables)

    def _identity_names(self, tables):
        """The name half of the identity - reached by both paths above."""
        for r in self._cells(tables, "DEVICE_PROFILE", ("category", "value")):
            if r["category"] == "hostname" and r["value"]:
                self.names.add(r["value"].strip().lower())
        self.names.discard("")
        self.names.discard("localhost")

    #: AUTH_LOG events that are an authentication result rather than a
    #: connection.
    #:
    #: Every row here becomes a claim that one machine in this case signed in
    #: to another, so it has to be an attempt to authenticate and its outcome
    #: - not a TCP connection ending. sshd writes 'Connection closed by
    #: 10.0.0.11' after a successful login, after a refused one, and after a
    #: scanner opens a socket and goes away; taking it as a sign-in put 399 of
    #: them into a three-host cluster's correlation and made 'connection
    #: closed' read as 'signed in successfully'.
    #:
    #: The failures belong here as much as the successes: a host in the case
    #: trying its neighbour and being refused is the finding CROSS_SESSIONS
    #: reports at HIGH.
    SESSION_EVENTS = frozenset((
        "accepted login", "public key accepted", "session opened",
        "failed password", "invalid user", "authentication failure",
        "max auth attempts", "root login refused",
    ))

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
            if r["source_ip"] and r["event"] in self.SESSION_EVENTS:
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

    #: CRON row kinds that are an autostart entry rather than a line of one.
    #:
    #: The table also keeps 'script_line' - a line *inside* a cron script - so
    #: an examiner can read what the script does, and 'env' and 'unparsed'.
    #: None of those is a thing that runs. Joining on them made
    #: CROSS_PERSISTENCE 183 rows of the fragments two stock Debian hosts have
    #: in common: '$iosched_idle \\', ') | do_sendmail', '-- --quiet'.
    CRON_ENTRY_KINDS = ("crontab", "script")

    def _take_persistence(self, tables):
        """What runs without anybody asking, across the three usual places."""
        cron = self._cells(tables, "CRON",
                           ("command", "run_as", "file", "kind"))
        if not cron:
            # A CRON table from before the kind column existed. Everything is
            # taken, as it was, rather than nothing.
            cron = [dict(r, kind="crontab") for r in
                    self._cells(tables, "CRON", ("command", "run_as", "file"))]
        for r in cron:
            if r["kind"] and r["kind"] not in self.CRON_ENTRY_KINDS:
                continue
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
    CROSS_TABLES = ("CROSS_TIMELINE", "CROSS_SESSIONS", "CROSS_PATHS",
                    "CROSS_COMMANDS",
                    "CROSS_TRANSFERS", "CROSS_IOCS", "CROSS_WEB_CLIENTS",
                    "CROSS_WEB_REQUESTS", "CROSS_HASHES", "CROSS_KEYS",
                    "CROSS_PRIVILEGE", "CROSS_ACCOUNTS", "CROSS_PERSISTENCE",
                    "CROSS_FINDINGS", "CROSS_TECHNIQUES", "HOSTS")

    def run(self):
        self.t_hosts()
        self.check_clocks()
        self.t_cross_sessions()
        self.t_cross_paths()
        self.t_cross_commands()
        self.t_cross_transfers()
        self.t_cross_iocs()
        self.t_cross_web()
        self.t_cross_hashes()
        self.t_cross_keys()
        self.t_cross_privilege()
        self.t_cross_accounts()
        self.t_cross_persistence()
        self.t_cross_timeline()      # after the tables it reads
        self.t_cross_findings()
        self.t_cross_techniques()
        self.tri.findings.sort(key=lambda f: (SEV_RANK[f.severity], f.category,
                                              f.title))
        self.t_findings()
        self.t_timeline()
        return self.tables

    def _rows_of(self, name):
        """Rows of a table this run has already built, as dicts."""
        t = next((x for x in self.tables if x.name == name), None)
        if t is None:
            return []
        at = dict((c, i) for i, c in enumerate(t.columns))
        return [dict((c, (row[i] if i < len(row) else "") or "")
                     for c, i in at.items()) for row in t.iter_rows()]

    # -- 1. the hosts themselves -------------------------------------------
    def t_hosts(self):
        t = self.table("HOSTS", "The collections in this correlation",
                       [HOST_COLUMN, "input", "hostname", "addresses",
                        "distribution", "layout",
                        "collected_utc", "host_utc_offset", "findings",
                        "critical", "high", "medium", "low", "info",
                        "indicators", "events", "hashed_files"],
                       "Correlation",
                       "One row per input. `collection` is the label every "
                       "other table joins on - the same column a merged export "
                       "carries and the console filters by; `hostname` is what "
                       "the collection itself says it was, which is not always "
                       "the same thing and is worth reading when it is not. "
                       "`addresses` is what this collection answers on, which "
                       "is the whole mechanism behind CROSS_SESSIONS: a login "
                       "from 10.0.0.11 is an address until one of these rows "
                       "says whose it is. It is also what tells a reader that "
                       "an address in CROSS_IOCS is one of these machines "
                       "rather than something outside the case.")
        for c in self.cases:
            n = c.counts()
            t.add(c.label, c.path, c.hostname,
                  ", ".join(sorted(c.addresses)), c.distro, c.layout,
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
        # Kept for t_cross_paths, which walks these as edges of a graph. Built
        # here rather than read back out of the table because a hop is a fact
        # about two hosts and a time, not about how the row was formatted.
        self.session_edges = [
            {"when": r[0], "from": r[1], "to": r[2], "user": r[3],
             "ok": "fail" not in (r[4] or "").lower(), "service": r[5]}
            for r in rows if r[0]]
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
                                 # The whole command. It is the evidence -
                                 # `scp ../45010 hadoop@10.0.0.12:/home/...`
                                 # cut at 200 characters loses the path it was
                                 # written to, which is the half that says
                                 # what happened. The console wraps it and the
                                 # row opens in full on a click; the summary
                                 # line on the finding is where shortening
                                 # belongs.
                                 hit, cmd["cmd"], cmd["source"],
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
    # -- 2d. one hop after another: A -> B and then B -> C ------------------
    def t_cross_paths(self):
        """Two sign-ins that are one movement through the estate.

        CROSS_SESSIONS answers "did this machine sign in to that one" one hop
        at a time. An intrusion is a path: the shape worth seeing is web01 ->
        db02 and then db02 -> backup03 an hour later, which read as two rows
        is two facts a reader has to notice sit together, and read as a path
        is the route. The route is what an incident report needs.

        A hop only extends a path when it happens after the hop it extends and
        within a day of it. Without a window, every administrative login into
        a jump host in six months of logs chains to every login out of it and
        the table fills with routes nobody travelled.

        One row per route rather than one per pair of hops, and the pairing is
        a merge over each leg's own sorted times rather than a comparison of
        every hop against every other. A busy estate has thousands of sessions
        between the same few machines; pairing them off would be millions of
        comparisons to produce a handful of distinct routes, most of them the
        same three names over and over.
        """
        edges = getattr(self, "session_edges", [])
        if len(edges) < 2:
            return
        legs = defaultdict(list)
        for e in edges:
            legs[(e["from"], e["to"])].append(e)
        for v in legs.values():
            v.sort(key=lambda e: e["when"])

        routes = {}
        for (a, b), first_leg in legs.items():
            for (b2, c), second_leg in legs.items():
                if b2 != b or c == a:
                    continue
                times = [e["when"] for e in second_leg]
                for e1 in first_leg:
                    # the first hop out of b that could be this one continuing
                    j = bisect.bisect_left(times, e1["when"])
                    if j >= len(second_leg):
                        continue
                    e2 = second_leg[j]
                    gap = _seconds_between(e1["when"], e2["when"])
                    if gap is None or gap > CHAIN_WINDOW_SECONDS:
                        continue
                    path = "%s -> %s -> %s" % (a, b, c)
                    r = routes.get(path)
                    if r is None:
                        r = routes[path] = {
                            "chains": 0, "ok": False, "users": set(),
                            "first": e1["when"], "last": e2["when"],
                            "tightest": None, "detail": ""}
                    r["chains"] += 1
                    r["ok"] = r["ok"] or (e1["ok"] and e2["ok"])
                    for u in (e1["user"], e2["user"]):
                        if u and len(r["users"]) < 12:
                            r["users"].add(u)
                    if e1["when"] < r["first"]:
                        r["first"] = e1["when"]
                    if e2["when"] > r["last"]:
                        r["last"] = e2["when"]
                    if r["tightest"] is None or gap < r["tightest"]:
                        r["tightest"] = gap
                        r["detail"] = ("%s as %s, then %s as %s, %s apart"
                                       % (e1["service"] or "session",
                                          e1["user"] or "?",
                                          e2["service"] or "session",
                                          e2["user"] or "?",
                                          _gap(e1["when"], e2["when"]) or "no gap"))
        if not routes:
            return
        t = self.table("CROSS_PATHS", "Sign-ins that chain into one route",
                       ["path", "hops", "chains", "first_utc", "last_utc",
                        "elapsed", "users", "result", "tightest"],
                       "Correlation",
                       "A sign-in from one collection to another followed by "
                       "a sign-in out of that second one, inside a day. Each "
                       "hop is a row in CROSS_SESSIONS; this is the route they "
                       "make, one row however many times it was walked. "
                       "`result` is 'reached' only where some walk of it "
                       "succeeded at every hop - a route whose hops all failed "
                       "is an attempt at a route, which is worth seeing and is "
                       "not the same claim. `tightest` is the closest the two "
                       "hops ever came, which is the walk to look at first.")
        rows = sorted(routes.items(), key=lambda kv: (not kv[1]["ok"],
                                                      kv[1]["first"]))
        for path, r in rows:
            t.add(path, 2, r["chains"], r["first"], r["last"],
                  _gap(r["first"], r["last"]), ", ".join(sorted(r["users"])),
                  "reached" if r["ok"] else "attempted", r["detail"])
        done = [(p, r) for p, r in rows if r["ok"]]
        if done:
            self.add("CRITICAL", "Correlation",
                     "%d route(s) of two hops between these collections were "
                     "travelled end to end" % len(done),
                     "Somebody signed in to one of these machines from "
                     "another and then signed in from there to a third, "
                     "inside a day. Two successful hops in sequence is not a "
                     "shared credential or a common configuration - it is "
                     "movement, and the third host was reached through the "
                     "second.",
                     evidence=["%s   %s .. %s as %s   %s"
                               % (p, r["first"], r["last"],
                                  ", ".join(sorted(r["users"])) or "(no user)",
                                  r["detail"])
                               for p, r in done[: self.EVIDENCE]],
                     source="CROSS_PATHS", count=len(done),
                     times=[r["first"] for _p, r in done],
                     mitre="T1021 Remote Services / T1570 Lateral Tool Transfer")
        tried = [(p, r) for p, r in rows if not r["ok"]]
        if tried:
            self.add("HIGH", "Correlation",
                     "%d two-hop route(s) were attempted and a hop on them "
                     "failed" % len(tried),
                     "The route was walked and something on it refused. Where "
                     "the first hop worked and the second did not, the middle "
                     "host is compromised and the far one held.",
                     evidence=["%s   %s" % (p, r["detail"])
                               for p, r in tried[: self.EVIDENCE]],
                     source="CROSS_PATHS", count=len(tried),
                     mitre="T1021 Remote Services")

    # -- 4b. the same bytes, and which host had them first ------------------
    def t_cross_transfers(self):
        """A file that is on two hosts, in the order they came to hold it.

        CROSS_HASHES says two machines have the same file. This says which one
        had it first and how long the other took to get it - which is the
        difference between a fact about a distribution and a fact about an
        intrusion. Only files outside the packaged tree are here: /usr/bin is
        identical on two machines built from one image, and the order it
        arrived in is the order they were installed.

        The direction rests on the creation time, and the basis is a column
        because it decides how much the row is worth. crtime is written by the
        filesystem that received the file and cannot be forged by the copy;
        mtime travels with the file, so a row resting on mtime alone says the
        two hosts hold a file with the same modification time - which is what
        a copy looks like, and also what two downloads of one release look
        like.
        """
        moves = []
        for digest, holders in _shared_digests(self.cases):
            timed = [(c.file_times[digest], c) for c in holders
                     if digest in c.file_times]
            if len(timed) < 2:
                continue
            paths = [ft["path"] for ft, _c in timed]
            if not any(p.startswith(NOTABLE_DIRS) for p in paths):
                continue
            timed.sort(key=lambda tc: tc[0]["when"])
            (first_ft, first_c), (last_ft, last_c) = timed[0], timed[-1]
            if first_ft["when"] == last_ft["when"]:
                continue        # same instant on both: no direction to state
            moves.append({
                "digest": digest, "from": first_c.label, "to": last_c.label,
                "from_path": first_ft["path"], "to_path": last_ft["path"],
                "first": first_ft["when"], "last": last_ft["when"],
                "basis": "crtime" if first_ft["basis"] == last_ft["basis"] ==
                         "crtime" else "mtime",
                "hosts": len(timed)})
        if not moves:
            return
        t = self.table("CROSS_TRANSFERS",
                       "Files that reached one host and then another",
                       ["digest", "from_collection", "to_collection",
                        "first_utc", "last_utc", "gap", "basis",
                        "from_path", "to_path", "host_count"],
                       "Correlation",
                       "The same bytes on two collections, with the earlier "
                       "one named as the source. Only files outside the "
                       "packaged tree, because a shared /usr/bin is a shared "
                       "distribution. `basis` is which clock the order rests "
                       "on: 'crtime' is the filesystem's own record of when "
                       "it received the file and is the strong form; 'mtime' "
                       "travels with a copy, so it is consistent with a "
                       "transfer and also with both hosts downloading the "
                       "same release.")
        moves.sort(key=lambda m: (m["basis"] != "crtime", m["first"]))
        for m in moves:
            t.add(m["digest"], m["from"], m["to"], m["first"], m["last"],
                  _gap(m["first"], m["last"]), m["basis"],
                  m["from_path"], m["to_path"], m["hosts"])
        strong = [m for m in moves if m["basis"] == "crtime"]
        if strong:
            self.add("HIGH", "Correlation",
                     "%d file(s) appear on one of these hosts and then on "
                     "another" % len(strong),
                     "The receiving filesystem wrote the creation time, so "
                     "the order is the order the hosts came to hold the file "
                     "- not something a copy carried with it. A file that "
                     "exists on one machine and appears on a second an hour "
                     "later, outside the packaged tree, was put there.",
                     evidence=["%s  %s -> %s after %s\n      %s"
                               % (m["digest"][:32], m["from"], m["to"],
                                  _gap(m["first"], m["last"]) or "no gap",
                                  m["to_path"])
                               for m in strong[: self.EVIDENCE]],
                     source="CROSS_TRANSFERS", count=len(strong),
                     times=[m["first"] for m in strong],
                     mitre="T1105 Ingress Tool Transfer / T1570 Lateral Tool Transfer")
        weak = len(moves) - len(strong)
        if weak:
            self.add("MEDIUM", "Correlation",
                     "%d further shared file(s) are ordered by mtime alone"
                     % weak,
                     "No creation time was recorded for at least one copy, so "
                     "the order rests on a timestamp that travels with the "
                     "file. Consistent with a transfer, and equally "
                     "consistent with two hosts fetching one release.",
                     source="CROSS_TRANSFERS", count=weak)

    # -- 6b. who is root here, asked of every host at once -------------------
    def t_cross_privilege(self):
        """Sudo rules and privileged group membership shared between hosts.

        Both answer "who is root here", and both are worth comparing across
        machines. One NOPASSWD rule for a service account on three hosts is a
        single decision that made all three reachable from any of them, and a
        name in sudo or wheel on hosts that share nothing else is either a
        management standard or a foothold that was built three times.

        Which is why `notable` is the column to read, and the same discipline
        CROSS_HASHES applies. Two Ubuntu machines have identical /etc/sudoers
        and syslog in adm, because that is what Ubuntu ships - reported as a
        finding it is four rows of "these hosts run the same distribution"
        sitting on top of the one rule somebody added.
        """
        grants = defaultdict(dict)
        for c in self.cases:
            for rule, where in c.sudo_rules.items():
                grants[("sudoers", rule)][c.label] = where
            for (group, member), gid in c.group_members.items():
                grants[("group", "%s: %s" % (group, member))][c.label] = (
                    "gid %s" % gid if gid else group)
        shared = dict((k, v) for k, v in grants.items() if len(v) > 1)
        if not shared:
            return
        t = self.table("CROSS_PRIVILEGE",
                       "Privilege granted the same way on several hosts",
                       ["kind", "grant", "host_count", "hosts", "notable",
                        "nopasswd", "where"],
                       "Correlation",
                       "A sudoers rule, or a name in a privileged group, "
                       "present on more than one collection. Shared privilege "
                       "is shared reach: an account that can become root on "
                       "three of these machines turns one stolen credential "
                       "into three compromised hosts. `notable` is what "
                       "somebody decided rather than what the distribution "
                       "ships - a passwordless rule, or a grant naming an "
                       "account that is not a system account. The rest is "
                       "here because a shipped default that has been edited "
                       "on one host and not another is worth being able to "
                       "see, and it is not a finding.")
        rows = sorted(shared.items(), key=lambda kv: (-len(kv[1]), kv[0]))
        notable = []
        for (kind, grant), by_host in rows:
            free = any("NOPASSWD" in w for w in by_host.values())
            mine = free or _somebody_decided(kind, grant, self.cases)
            t.add(kind, grant, len(by_host), ", ".join(sorted(by_host)),
                  "yes" if mine else "", "yes" if free else "",
                  " | ".join("%s: %s" % (h, w)
                             for h, w in sorted(by_host.items())))
            if mine:
                notable.append(((kind, grant), by_host, free))
        if notable:
            free_n = [n for n in notable if n[2]]
            self.add("HIGH" if free_n else "MEDIUM", "Correlation",
                     "%d privilege grant(s) somebody added are identical "
                     "across these hosts" % len(notable),
                     "One decision reaching several machines. Where it is "
                     "passwordless the reach needs no credential at all - "
                     "code execution as that account is root on every host "
                     "carrying the rule.",
                     evidence=["%-8s %-58s %s" % (k, trunc(g, 58),
                                                  ", ".join(sorted(by_host)))
                               for (k, g), by_host, _f in
                               notable[: self.EVIDENCE]],
                     source="CROSS_PRIVILEGE", count=len(notable),
                     mitre="T1078 Valid Accounts / T1548.003 Sudo and Sudo Caching")
        rest = len(rows) - len(notable)
        if rest:
            self.add("INFO", "Correlation",
                     "%d further privilege grant(s) are identical across "
                     "these hosts" % rest,
                     "Every one of them is what the distribution ships - the "
                     "stock /etc/sudoers lines and the system accounts in adm "
                     "and friends. Listed in CROSS_PRIVILEGE rather than "
                     "here, because a stock rule edited on one host and not "
                     "another is worth being able to look up.",
                     source="CROSS_PRIVILEGE", count=rest)

    # -- 7b. the web, which reaches every host that answers on port 80 ------
    def t_cross_web(self):
        """One client, and one request, seen by more than one of these hosts.

        WEB_LOG is the one artifact where the other side of the conversation
        is a first-class column, and until now the correlator never read it.
        Two questions it answers that nothing else does: which addresses
        worked more than one of these machines, and which requests were tried
        on more than one - the second being a pattern even where every request
        came from a different address, which is what a distributed scan looks
        like.
        """
        clients = defaultdict(dict)
        requests = defaultdict(dict)
        for c in self.cases:
            for ip, agg in c.web_clients.items():
                clients[ip][c.label] = agg
            for key, agg in c.web_requests.items():
                requests[key][c.label] = agg
        multi_c = {k: v for k, v in clients.items() if len(v) > 1}
        multi_r = {k: v for k, v in requests.items() if len(v) > 1}
        if multi_c:
            t = self.table("CROSS_WEB_CLIENTS",
                           "Web clients that reached more than one host",
                           ["client", "host_count", "hosts", "requests",
                            "answered", "first_utc", "last_utc", "spread",
                            "per_host"],
                           "Correlation",
                           "One address in the access logs of several of "
                           "these collections. `answered` counts the requests "
                           "that got a 2xx or 3xx anywhere - the difference "
                           "between an address that knocked on several doors "
                           "and one that was let through at least one.")
            got = []
            for ip, by_host in sorted(
                    multi_c.items(),
                    key=lambda kv: (-len(kv[1]),
                                    -sum(a["n"] for a in kv[1].values()))):
                n = sum(a["n"] for a in by_host.values())
                ok = sum(a["ok"] for a in by_host.values())
                first = min(a["first"] for a in by_host.values() if a["first"]) \
                    if any(a["first"] for a in by_host.values()) else ""
                last = max(a["last"] for a in by_host.values() if a["last"]) \
                    if any(a["last"] for a in by_host.values()) else ""
                t.add(ip, len(by_host), ", ".join(sorted(by_host)), n, ok,
                      first, last, _gap(first, last),
                      " | ".join("%s: %d req, %d answered"
                                 % (h, a["n"], a["ok"])
                                 for h, a in sorted(by_host.items())))
                got.append((ip, by_host, n, ok, first))
            served = [g for g in got if g[3]]
            self.add("HIGH" if served else "MEDIUM", "Correlation",
                     "%d web client(s) reached more than one of these hosts"
                     % len(got),
                     "One address working several machines in the same case. "
                     "Where it was answered rather than refused, it had a "
                     "conversation with more than one of them, which is the "
                     "shape of a single actor rather than of two unrelated "
                     "scans.",
                     evidence=["%-39s %d hosts, %d req, %d answered   %s"
                               % (g[0], len(g[1]), g[2], g[3], g[4] or "?")
                               for g in got[: self.EVIDENCE]],
                     source="CROSS_WEB_CLIENTS", count=len(got),
                     times=[g[4] for g in got if g[4]],
                     mitre="T1595 Active Scanning / T1190 Exploit Public-Facing Application")
        if multi_r:
            t = self.table("CROSS_WEB_REQUESTS",
                           "Requests made to more than one host",
                           ["method", "resource", "host_count", "hosts",
                            "requests", "answered", "status_codes",
                            "first_utc", "last_utc", "per_host"],
                           "Correlation",
                           "The same resource asked for on several of these "
                           "collections. A pattern even where every request "
                           "came from a different address, which is what a "
                           "distributed scan and a shared exploit list both "
                           "look like. `answered` is how many got a 2xx or "
                           "3xx: a path that exists on one host and 404s on "
                           "the rest is the row worth reading. Two caps, "
                           "because an internet-facing host answers hundreds "
                           "of thousands of requests: each host offers its "
                           "20,000 busiest resources to the join, and the "
                           "2,000 most-shared rows are written. The count on "
                           "the finding is of every row that matched.")
            rows = sorted(multi_r.items(),
                          key=lambda kv: (-len(kv[1]),
                                          -sum(a["ok"] for a in kv[1].values()),
                                          -sum(a["n"] for a in kv[1].values())))
            for (method, res), by_host in rows[: self.PACKAGED_ROW_CAP]:
                n = sum(a["n"] for a in by_host.values())
                ok = sum(a["ok"] for a in by_host.values())
                codes = sorted({c for a in by_host.values() for c in a["codes"]})
                first = min((a["first"] for a in by_host.values() if a["first"]),
                            default="")
                last = max((a["last"] for a in by_host.values() if a["last"]),
                           default="")
                t.add(method, trunc(res, 300), len(by_host),
                      ", ".join(sorted(by_host)), n, ok, ", ".join(codes[:8]),
                      first, last,
                      " | ".join("%s: %d" % (h, a["n"])
                                 for h, a in sorted(by_host.items())))
            answered = [r for r in rows
                        if any(a["ok"] for a in r[1].values())]
            self.add("MEDIUM", "Correlation",
                     "%d request(s) were made to more than one of these hosts"
                     % len(rows),
                     "The same resource asked for on several machines. Most "
                     "of it is the internet knocking on every door it can "
                     "find; the rows to read are the ones a host answered, "
                     "and the ones naming something no scanner guesses.",
                     evidence=["%-6s %-64s %d hosts, %d answered"
                               % (m, trunc(r, 64), len(by_host),
                                  sum(a["ok"] for a in by_host.values()))
                               for (m, r), by_host in answered[: self.EVIDENCE]],
                     source="CROSS_WEB_REQUESTS", count=len(rows),
                     mitre="T1595 Active Scanning")

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
                       ["kind", "value", "host_count", "hosts", "notable",
                        "where"],
                       "Correlation",
                       "A cron command, a systemd ExecStart or an "
                       "ld.so.preload entry that appears on several hosts. "
                       "Configuration management puts the same entries "
                       "everywhere and so does an intruder who scripted the "
                       "install; what tells them apart is what the command "
                       "does, which is why the command itself is the column. "
                       "`notable` is the reading of that: any ld.so.preload "
                       "entry, and any command that runs something from a "
                       "directory a package does not install into or fetches "
                       "one and pipes it to a shell. The rest is two hosts "
                       "running the same distribution's stock cron.")
        shared = defaultdict(dict)
        for c in self.cases:
            for (kind, value), where in c.persist.items():
                shared[(kind, value)][c.label] = where
        rows = [(-len(by), kind, value, by)
                for (kind, value), by in shared.items() if len(by) > 1]
        rows.sort()
        notable = []
        for _n, kind, value, by in rows:
            mine = _persistence_notable(kind, value)
            t.add(kind, value, len(by), ", ".join(sorted(by)),
                  "yes" if mine else "",
                  " | ".join("%s: %s" % (h, w) for h, w in sorted(by.items())))
            if mine:
                notable.append((-len(by), kind, value, by))
        if notable:
            preload = [r for r in notable if r[1] == "ld.so.preload"]
            self.add("HIGH" if preload else "MEDIUM", "Correlation",
                     "%d autostart entry(ies) somebody added appear on more "
                     "than one host" % len(notable),
                     "The same thing set to run on several machines, from "
                     "somewhere a package does not install into. An "
                     "ld.so.preload entry shared across hosts is a userland "
                     "rootkit deployed to all of them and is why this is HIGH "
                     "when one is present."
                     if preload else
                     "The same thing set to run on several machines, from "
                     "somewhere a package does not install into - which on a "
                     "managed estate is what management looks like, and on a "
                     "compromised one is what an install script looks like. "
                     "Read the commands rather than the count.",
                     evidence=["%-14s %-3d host(s)  %s"
                               % (r[1], -r[0], trunc(r[2], 84))
                               for r in notable[: self.EVIDENCE]],
                     source="CROSS_PERSISTENCE", count=len(notable),
                     mitre="T1053 Scheduled Task/Job / T1574.006 LD_PRELOAD")
        rest = len(rows) - len(notable)
        if rest:
            self.add("INFO", "Correlation",
                     "%d further autostart entry(ies) appear on more than one "
                     "host" % rest,
                     "Every one of them runs something from where a package "
                     "puts files, which on machines built from one "
                     "distribution is what being built from one distribution "
                     "looks like. Listed in CROSS_PERSISTENCE rather than "
                     "here.",
                     source="CROSS_PERSISTENCE", count=rest)

    # -- 4d. everything between these hosts, in the order it happened -------
    def t_cross_timeline(self):
        """Every dated cross-host event on one clock, earliest first.

        The other cross tables answer "what is shared" a kind at a time - a
        sign-in here, a command there, a file on both. None of them answers
        "what happened, in what order", and that is the question an incident
        report is written to. Reading it out of five tables means sorting five
        different timestamp columns by eye and hoping the offsets agreed.

        Every row carries the time, both ends and what it was, so the whole
        cross-host story sorts in one column. `basis` says which table the row
        came from, because a sign-in recorded by the destination and a command
        recorded by the source are different kinds of evidence and a reader
        should not have to remember which is which.
        """
        rows = []
        for r in self._rows_of("CROSS_SESSIONS"):
            when = r.get("timestamp_utc")
            if when:
                ok = "fail" not in (r.get("result") or "").lower()
                rows.append((when, r.get("from_collection"),
                             r.get("to_collection"),
                             "sign-in" if ok else "sign-in refused",
                             "%s%s" % (r.get("user") or "(no user)",
                                       " over %s" % r["service"]
                                       if r.get("service") else ""),
                             "CROSS_SESSIONS"))
        for r in self._rows_of("CROSS_COMMANDS"):
            when = r.get("timestamp_utc")
            if when:
                rows.append((when, r.get("from_collection"),
                             r.get("to_collection"), "remote command",
                             r.get("command") or "",
                             "CROSS_COMMANDS"))
        for r in self._rows_of("CROSS_TRANSFERS"):
            if r.get("first_utc"):
                rows.append((r["first_utc"], r.get("from_collection"),
                             r.get("to_collection"), "file first seen",
                             "%s (%s)" % (r.get("from_path") or "",
                                          r.get("basis") or ""),
                             "CROSS_TRANSFERS"))
            if r.get("last_utc"):
                rows.append((r["last_utc"], r.get("from_collection"),
                             r.get("to_collection"), "file reached the second",
                             "%s (%s)" % (r.get("to_path") or "",
                                          r.get("basis") or ""),
                             "CROSS_TRANSFERS"))
        for r in self._rows_of("CROSS_IOCS"):
            if r.get("first_utc") and r.get("first_host"):
                rows.append((r["first_utc"], r.get("first_host"),
                             r.get("last_host") or "", "indicator first seen",
                             "%s - %s" % (r.get("indicator") or "",
                                          trunc(r.get("why") or "", 80)),
                             "CROSS_IOCS"))
        if not rows:
            return
        rows.sort(key=lambda r: (r[0], r[5]))
        rows = _one_per_act(rows)
        t = self.table("CROSS_TIMELINE",
                       "Everything between these collections, in order",
                       ["timestamp_utc", "from_collection", "to_collection",
                        "event", "detail", "basis"],
                       "Correlation",
                       "One clock for the whole case. Every dated row the "
                       "cross-host tables hold, sorted - a sign-in, a command "
                       "that names another machine, a file appearing on a "
                       "second host, an indicator reaching one before the "
                       "other. `basis` names the table it came from, because "
                       "a sign-in the destination logged and a command the "
                       "source ran are different kinds of evidence - and "
                       "where both recorded one act, `basis` names them all "
                       "on the single row rather than repeating it. Every "
                       "time here is UTC normalised by each host's own "
                       "resolved offset: HOSTS says what those were, and a "
                       "host that never resolved one is its own finding.")
        for r in rows:
            t.add(*r)
        first, last = rows[0][0], rows[-1][0]
        self.add("INFO", "Correlation",
                 "%d dated cross-host event(s), %s to %s"
                 % (len(rows), first[:19], last[:19]),
                 "The order things happened in, across every machine in the "
                 "case. Read it before the per-kind tables: they say what is "
                 "shared, this says what happened.",
                 evidence=["%s  %-13s -> %-13s %-22s %s"
                           % (r[0][:19], r[1], r[2], r[3], trunc(r[4], 60))
                           for r in rows[: self.EVIDENCE]],
                 source="CROSS_TIMELINE", count=len(rows),
                 times=[r[0] for r in rows])

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
        # `artifact`, not `source`, though what it holds is the cross table
        # the finding was read out of. The console looks these columns up by
        # name - severity, category, title, mitre, artifact - so a table that
        # calls the same thing something else opens with an empty column and
        # no error, and a merge by name drops it. One name, both tables.
        t = self.table("FINDINGS", "Correlation findings",
                       ["severity", "category", "title", "mitre", "artifact",
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


#: The sudoers lines a distribution ships. Matched after whitespace has been
#: collapsed, so a file that differs only in spacing still reads as stock.
STOCK_SUDO_RULES = frozenset((
    "root ALL=(ALL) ALL", "root ALL=(ALL:ALL) ALL",
    "%admin ALL=(ALL) ALL", "%admin ALL=(ALL:ALL) ALL",
    "%sudo ALL=(ALL) ALL", "%sudo ALL=(ALL:ALL) ALL",
    "%wheel ALL=(ALL) ALL", "%wheel ALL=(ALL:ALL) ALL",
    "%wheel ALL=(ALL) NOPASSWD: ALL",
))


#: A command that fetches something and runs it. The shape is the finding,
#: whichever downloader is used to write it.
_FETCH_RUN_RE = re.compile(
    r"\b(?:curl|wget|fetch)\b[^|;&]*[|]\s*(?:sudo\s+)?"
    r"(?:ba|da|k|z)?sh\b|\bpython\d?\s+-c\b|\bbase64\s+-d\b", re.I)


def _persistence_notable(kind, value):
    """Is this autostart entry somebody's, or the distribution's?

    The same question CROSS_HASHES asks of a shared file and CROSS_PRIVILEGE
    of a shared sudo rule. Two hosts of one distribution share every stock
    cron entry it ships, and reporting those as shared persistence buries the
    one line that runs something out of /tmp.

    An ld.so.preload entry is always notable: nothing a package installs
    writes to it, and a shared one is a userland rootkit on both machines.
    """
    if kind == "ld.so.preload":
        return True
    text = value or ""
    if _FETCH_RUN_RE.search(text):
        return True
    return any(d in text for d in NOTABLE_DIRS)


def _somebody_decided(kind, grant, cases):
    """Is this grant a decision, or is it what the distribution shipped?

    The same question CROSS_HASHES asks of a shared file. Two Ubuntu hosts
    have byte-identical /etc/sudoers and the same system accounts in adm, and
    reporting that as shared privilege buries the one rule somebody wrote.
    """
    if kind == "sudoers":
        return grant not in STOCK_SUDO_RULES
    member = grant.split(":", 1)[-1].strip()
    if not member or member in SYSTEM_NAMES:
        return False
    for c in cases:
        info = c.accounts.get(member)
        if info is None:
            continue
        try:
            uid = int(info.get("uid") or -1)
        except (TypeError, ValueError):
            return True
        if uid == 0 or uid > SYSTEM_UID_MAX:
            return True
    return False


def _one_per_act(rows):
    """Collapse rows that are one act several artifacts recorded.

    A single sign-in reaches CROSS_SESSIONS from AUTH_LOG and again from
    LOGINS, because those are two records of it and the table keeps both on
    purpose - two records disagreeing is itself a finding. A timeline is the
    other question: it is a list of what happened, and one login written three
    times is three answers to "how many times did they sign in". On the Hadoop
    cluster that was 190 rows for 95 acts.

    The act is the time, the two ends, the kind and the subject - the service
    it came over is part of the record, not of the act, so `hadoop over sshd`
    and `hadoop over login` are one sign-in. What every record of it agreed
    on stays; the tables they came from are joined into `basis`, so nothing
    about provenance is lost by not repeating the row.
    """
    seen = {}
    order = []
    for when, a, b, event, detail, basis in rows:
        subject = str(detail).split(" over ")[0]
        key = (when, a, b, event, subject)
        got = seen.get(key)
        if got is None:
            seen[key] = [when, a, b, event, detail, [basis]]
            order.append(key)
        elif basis not in got[5]:
            got[5].append(basis)
    return [(r[0], r[1], r[2], r[3], r[4], ", ".join(r[5]))
            for r in (seen[k] for k in order)]


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


def _seconds_between(first, last):
    """Seconds from one normalised stamp to another, or None if either is not one."""
    try:
        fmt = "%Y-%m-%d %H:%M:%S"
        return int((datetime.strptime(last[:19], fmt)
                    - datetime.strptime(first[:19], fmt)).total_seconds())
    except (ValueError, TypeError):
        return None


def _shared_digests(cases):
    """(digest, [the cases holding it]) for every digest on more than one."""
    holders = defaultdict(list)
    for c in cases:
        for digest in c.hashes:
            holders[digest].append(c)
    return [(d, hs) for d, hs in holders.items() if len(hs) > 1]


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
