#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Test the cross-host join: what several finished runs say about each other.

    python tests/test_correlate.py            # against src/linsight
    python tests/test_correlate.py --built    # against the built linsight.py

No collection and no image. A correlation is a join over projections each run
already produced - indicators, findings, events, hashes - so the honest way to
test it is to hand it those projections directly. Three synthetic hosts are
cheaper than three disk images and can hold the cases that decide whether the
join is any good:

  the negative     an indicator on one host only, a finding on one host only,
                   and a hash under /usr/bin that every host shares because
                   they run the same distribution. None may be reported.
  the ordering     one address seen on web01 before db02, which is the whole
                   claim - and it must come out in that direction, not the
                   reverse and not unordered.
  the caveat       a host that never resolved its clock offset has to make the
                   correlation say so, because every "four minutes after" in
                   it then rests on a guess.
"""

import argparse
import os
import sys
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def load(built):
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
    from linsight import correlate
    return correlate


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


def ts(h, m, s=0):
    return "2026-03-24 %02d:%02d:%02d" % (h, m, s)


class FakeCol(object):
    kind = "dir"
    layout = "uac"

    def __init__(self, path):
        self.path = path


class FakeTri(object):
    """The five things a HostCase reads off a finished run."""

    def __init__(self, host, offset="+00:00 (from /etc/timezone)"):
        self.col = FakeCol("/evidence/%s" % host)
        self.meta = {"Hostname": host, "Distribution": "Ubuntu 22.04",
                     "Collection finished": "2026-03-24 12:00:00 UTC (anchor)",
                     "Host UTC offset": offset}
        self.findings = []
        self.events = []
        self.iocs = {}
        self.ioc_sources = {}
        self.ioc_count = {}
        self.ioc_span = {}

    def finding(self, sev, cat, title, mitre="", first="", last="", count=1):
        self.findings.append(_F(sev, cat, title, mitre, first, last, count))
        return self

    def ioc(self, value, why, count=1, first="", last=""):
        self.iocs[value] = {why}
        self.ioc_sources[value] = {"auth.log"}
        self.ioc_count[value] = count
        self.ioc_span[value] = [first, last or first]
        return self

    def event(self, when, sev, cat, desc):
        self.events.append(_E(when, sev, cat, desc, "auth.log"))
        return self


class _F(object):
    def __init__(self, severity, category, title, mitre, first, last, count):
        self.severity, self.category, self.title = severity, category, title
        self.mitre, self.first_seen, self.last_seen = mitre, first, last
        self.count = count
        self.evidence, self.detail, self.source = [], "", "test"


class _E(object):
    def __init__(self, ts_, severity, category, description, source):
        self.ts, self.severity, self.category = ts_, severity, category
        self.description, self.source = description, source


class FakeHashes(object):
    """Stands in for the FILE_HASHES table one run produced."""
    name = "FILE_HASHES"
    columns = ["path", "md5", "sha256"]

    def __init__(self, pairs):
        self._rows = [[p, "", d] for p, d in pairs]

    def iter_rows(self):
        return iter(self._rows)


class Grid(object):
    """Any other built table, as the HostCase projections read it."""

    def __init__(self, name, columns, rows):
        self.name, self.columns = name, list(columns)
        self._rows = [list(r) for r in rows]

    def iter_rows(self):
        return iter(self._rows)


#: Valid base64, because a key body that is not is a different test - the
#: prefix is a real ssh-rsa header so the type decoder has something true
#: to read, and the length is a multiple of four so the body is decodable.
KEY_A = "AAAAB3NzaC1yc2EAAAADAQABAAABgQC" + "x" * 89     # on every host
KEY_B = "AAAAB3NzaC1yc2EAAAADAQABAAABgQC" + "y" * 89     # on web01 only


#: The addresses each collection reports as its own. This is the whole
#: mechanism: a login on db02 from 10.0.0.11 means nothing until web01's
#: interface list says 10.0.0.11 is web01.
ADDR = {"web01": "10.0.0.11", "db02": "10.0.0.12", "app03": "10.0.0.13"}
OUTSIDE = "203.0.113.9"          # not one of these machines


def side_tables(label):
    """USERS / SSH / CRON / LD_PRELOAD as each host produced them."""
    users = [["root", "0", "/root", "/bin/bash", "hash", "sudo", "1"],
             ["www-data", "33", "/var/www", "/usr/sbin/nologin", "locked", "", "0"]]
    keys = [["authorized_keys", "/root/.ssh/authorized_keys", "root",
             "ssh-rsa " + KEY_A + " ops@jump"]]
    cron = [["/etc/crontab", "root", "crontab", "* * * * *",
             "root", "/usr/local/bin/collect.sh", "", "1"],
            # what every Debian host runs, which is not shared persistence
            ["/etc/cron.daily/apache2", "root", "script", "",
             "root", "apache2", "", "1"],
            # and the lines *inside* a cron script, which the table keeps so
            # an examiner can read it and which are not autostart entries
            ["/etc/cron.daily/man-db", "root", "script_line", "",
             "root", "$iosched_idle \\", "", "7"],
            ["/etc/cron.daily/man-db", "root", "script_line", "",
             "root", ") | do_sendmail", "", "8"]]
    pre = []
    if label == "web01":
        # a second uid-0 account, and a key nobody else trusts
        users.append(["svc", "0", "/home/svc", "/bin/bash", "hash", "sudo", "0"])
        keys.append(["authorized_keys", "/home/svc/.ssh/authorized_keys",
                     "svc", "ssh-rsa " + KEY_B + " attacker@kali"])
        pre = [["/etc/ld.so.preload", "/usr/lib/libhide.so", ""]]
    if label == "db02":
        # the same name, defined differently - which is the finding
        users.append(["svc", "1001", "/srv/svc", "/bin/sh", "hash", "", "0"])
        pre = [["/etc/ld.so.preload", "/usr/lib/libhide.so", ""]]
    if label == "app03":
        users.append(["deploy", "1002", "/home/deploy", "/bin/bash", "", "", "0"])
    # who logged in here, and from where
    auth = [["2026-03-24 03:00:00", "failed password", "root", OUTSIDE,
             "failure", "sshd"],
            # sshd writes this after a login, after a refusal, and after a
            # scanner opens a socket and leaves. It is not a sign-in.
            ["2026-03-24 03:50:00", "connection closed", "", ADDR["web01"],
             "success", "sshd"]]
    logins = []
    hist = [["root", "2026-03-24 02:50:00", "bash", "/root/.bash_history", "1",
             "cat /etc/passwd"]]
    ifaces = [["eth0", ADDR[label] + "/24"], ["lo", "127.0.0.1/8"]]
    if label == "db02":
        # web01 signed in here, successfully - the finding this exists for
        auth.append(["2026-03-24 03:20:00", "accepted login", "root",
                     ADDR["web01"], "success", "sshd"])
        logins.append(["root", "sshd", "pts/1", ADDR["web01"],
                       "2026-03-24 03:20:01", "success"])
    if label == "app03":
        # web01 tried and failed
        auth.append(["2026-03-24 03:40:00", "failed password", "deploy",
                     ADDR["web01"], "failure", "sshd"])
        # and db02 got in - which makes web01 -> db02 -> app03 one route
        auth.append(["2026-03-24 03:35:00", "accepted login", "root",
                     ADDR["db02"], "success", "sshd"])
        logins.append(["root", "sshd", "pts/0", ADDR["db02"],
                       "2026-03-24 03:35:01", "success"])
    if label == "web01":
        # and web01's own history says where it was going
        hist.append(["root", "2026-03-24 03:19:00", "bash",
                     "/root/.bash_history", "2",
                     "ssh root@" + ADDR["db02"] + " uname -a"])
        hist.append(["root", "2026-03-24 03:21:00", "bash",
                     "/root/.bash_history", "3",
                     "scp /tmp/.x root@db02:/tmp/"])
        # a command that reaches nowhere in this case
        hist.append(["root", "2026-03-24 03:22:00", "bash",
                     "/root/.bash_history", "4", "curl https://example.org/x"])
    # when each hashed file was created here, which is what gives a shared
    # hash a direction. /tmp/.x is created on web01 and appears on db02 twenty
    # minutes later; hide.so has no creation time on app03, so that pair can
    # only be ordered by mtime and has to say so.
    inv = [["/usr/bin/curl", "2019-01-01 00:00:00", "2019-01-01 00:00:00"]]
    sudo = [["/etc/sudoers", "%sudo ALL=(ALL:ALL) ALL", ""]]
    groups = [["sudo", "27", "root", "1"]]
    web = []
    if label == "web01":
        inv.append(["/tmp/.x", "2026-03-24 03:05:00", "2026-03-24 03:04:00"])
        inv.append(["/opt/a/hide.so", "2026-03-24 02:00:00",
                    "2026-03-24 02:00:00"])
        sudo.append(["/etc/sudoers.d/svc", "svc ALL=(ALL) NOPASSWD: ALL", "1"])
        groups = [["sudo", "27", "root,svc", "2"]]
        web = [["2026-03-24 03:00:00", OUTSIDE, "GET", "/wp-login.php", "404"],
               ["2026-03-24 03:01:00", OUTSIDE, "GET", "/shell.php", "200"],
               ["2026-03-24 03:02:00", "198.51.100.7", "GET", "/only-here",
                "200"]]
    if label == "db02":
        inv.append(["/tmp/.x", "2026-03-24 03:25:00", "2026-03-24 03:04:00"])
        sudo.append(["/etc/sudoers.d/svc", "svc ALL=(ALL) NOPASSWD: ALL", "1"])
        web = [["2026-03-24 03:30:00", OUTSIDE, "GET", "/wp-login.php", "404"]]
    if label == "app03":
        # mtime only: the copy carried its timestamp and nothing wrote a crtime
        inv.append(["/usr/local/lib/hide.so", "", "2026-03-24 02:30:00"])
    # A disk image produces no INTERFACES - that is `ip addr` at collection
    # time - so the only record of what this host answers on is its own
    # configuration. app03 is read this way on purpose.
    netcfg = [["/etc/network/interfaces", "auto ens33", ""],
              ["/etc/network/interfaces", "iface ens33 inet static", ""],
              ["/etc/network/interfaces", "address " + ADDR[label], ""],
              ["/etc/network/interfaces", "netmask 255.255.255.0", ""],
              ["/etc/network/interfaces", "network 10.0.0.0", ""],
              ["/etc/network/interfaces", "broadcast 10.0.0.255", ""],
              ["/etc/network/interfaces", "gateway 10.0.0.1", ""],
              ["/etc/network/interfaces", "dns-nameservers 10.0.0.53 8.8.8.8",
               ""]]
    grids = [
        Grid("NETWORK_CONFIG", ["source", "key", "value"], netcfg),
        Grid("FILE_INVENTORY", ["host_path", "crtime_utc", "mtime_utc"], inv),
        Grid("SUDOERS", ["file", "rule", "nopasswd"], sudo),
        Grid("GROUPS", ["group", "gid", "members", "member_count"], groups),
        Grid("WEB_LOG", ["timestamp_utc", "client_ip", "method", "resource",
                         "status"], web),
        Grid("INTERFACES", ["name", "addresses"], [] if label == "app03"
             else ifaces),
        Grid("AUTH_LOG", ["timestamp_utc", "event", "user", "source_ip",
                          "result", "process"], auth),
        Grid("LOGINS", ["user", "service", "terminal", "source_host", "start",
                        "result"], logins),
        Grid("SHELL_HISTORY", ["user", "timestamp_utc", "shell", "file",
                               "line_no", "command"], hist),
        Grid("USERS", ["username", "uid", "home", "shell", "password_status",
                       "privileged_groups", "authorized_keys"], users),
        Grid("SSH", ["type", "path", "owner_hint", "detail"], keys),
        Grid("CRON", ["file", "owner", "kind", "schedule", "run_as",
                      "command", "running_pids", "line_no"], cron),
        Grid("LD_PRELOAD", ["path", "entry", "note"], pre),
    ]
    return grids


SHARED_OS = "a" * 64          # /usr/bin/curl - every host has it, and should
IMPLANT = "b" * 64            # /tmp/.x - two hosts, and that is the finding
MOVED = "c" * 64              # same bytes, different path on each host


def cases(L, third_clock_unknown=True):
    web = (FakeTri("web01")
           .finding("CRITICAL", "Filesystem", "2 executable file(s) in tmpfs",
                    "T1036", ts(3, 1), ts(3, 5), 2)
           .finding("HIGH", "Authentication", "1 address(es) brute forced",
                    "T1110", ts(3, 0), ts(3, 2), 40)
           .ioc("203.0.113.9", "failed authentication source", 40,
                ts(3, 0), ts(3, 2))
           .ioc("198.51.100.7", "web01 only", 3, ts(3, 0))
           # the machines see each other constantly - far more often than they
           # see an intruder, which is what makes "is this address one of us"
           # the question the picture has to get right
           .ioc(ADDR["db02"], "cluster peer", 60, ts(3, 0), ts(3, 30))
           .event(ts(3, 0), "HIGH", "Authentication", "failed login"))
    db = (FakeTri("db02")
          .finding("CRITICAL", "Filesystem", "7 executable file(s) in tmpfs",
                   "T1036", ts(3, 20), ts(3, 25), 7)
          .finding("LOW", "Software", "db02 only finding", "", ts(3, 20))
          .ioc("203.0.113.9", "authentication source", 5, ts(3, 14), ts(3, 30))
          .ioc(ADDR["db02"], "cluster peer", 60, ts(3, 0), ts(3, 30))
          .event(ts(3, 14), "MEDIUM", "Authentication", "accepted password"))
    app = FakeTri("app03", offset="" if third_clock_unknown else "+00:00 (set)")
    app.finding("CRITICAL", "Filesystem", "1 executable file(s) in tmpfs",
                "T1036", ts(4, 0), ts(4, 1), 1)
    app.ioc("203.0.113.9", "outbound connection", 2, ts(4, 0))
    app.ioc(ADDR["db02"], "cluster peer", 60, ts(4, 0))
    app.event(ts(4, 0), "INFO", "Process", "start")
    out = []
    for label, tri, hashes in (
            ("web01", web, [("/usr/bin/curl", SHARED_OS),
                            ("/tmp/.x", IMPLANT), ("/opt/a/hide.so", MOVED)]),
            ("db02", db, [("/usr/bin/curl", SHARED_OS),
                          ("/tmp/.x", IMPLANT)]),
            ("app03", app, [("/usr/bin/curl", SHARED_OS),
                            ("/usr/local/lib/hide.so", MOVED)])):
        out.append(L.HostCase(label, "/evidence/%s" % label, tri,
                              [FakeHashes(hashes)] + side_tables(label)))
    return out


def tables_of(cor):
    return {t.name: t for t in cor.tables}


def rows_of(cor, name):
    t = tables_of(cor)[name]
    cols = {c: i for i, c in enumerate(t.columns)}
    return [dict((c, r[i]) for c, i in cols.items()) for r in t.iter_rows()]


def titles(cor):
    return [f.title for f in cor.tri.findings]


def build(L, **kw):
    opts = argparse.Namespace(window=72, html_rows=0, quiet=True, debug=True)
    cor = L.Correlator(cases(L, **kw), opts)
    cor.run()
    return cor


def check_labels(L, res):
    print("\nnaming the outputs - what the analyst typed, made unique")
    taken = set()
    got = [L._label_for(p, taken) for p in
           ("/cases/uac1", "disk2.dd", "/x/coll.tar.gz", "/y/disk2.dd",
            "/z/weird name!.E01")]
    res.check("basenames, extensions dropped",
              got[:3] == ["uac1", "disk2", "coll"], "got %s" % got[:3])
    res.check("a repeat is suffixed, not overwritten", got[3] == "disk2-2",
              "got %s" % got[3])
    res.check("a name that cannot be a directory is made into one",
              got[4] == "weird_name", "got %s" % got[4])


def check_iocs(L, res):
    print("\nindicators - shared, ordered, and the one that is not shared")
    cor = build(L)
    rows = rows_of(cor, "CROSS_IOCS")
    values = [r["indicator"] for r in rows]
    res.check("the shared address is reported", "203.0.113.9" in values)
    res.check("the one-host address is not", "198.51.100.7" not in values,
              "reported %s" % values)
    r = next(r for r in rows if r["indicator"] == "203.0.113.9")
    res.check("all three hosts are named", r["host_count"] == 3,
              "host_count %s" % r["host_count"])
    res.check("earliest host first: web01 -> app03",
              (r["first_host"], r["last_host"]) == ("web01", "app03"),
              "got %s -> %s" % (r["first_host"], r["last_host"]))
    res.check("the spread is stated", r["spread"] == "1h",
              "spread %r" % r["spread"])
    res.check("mentions are summed across hosts", r["total_mentions"] == 47,
              "got %s" % r["total_mentions"])
    res.check("a finding says it appears on more than one host",
              any("indicator(s) appear on more than one host" in t
                  for t in titles(cor)))
    res.check("and one says which direction it travelled",
              any("reached one host before another" in t for t in titles(cor)))


def check_findings(L, res):
    print("\nfindings - the same check on several hosts, counts masked")
    cor = build(L)
    rows = rows_of(cor, "CROSS_FINDINGS")
    names = [r["finding"] for r in rows]
    res.check("differing counts group into one row",
              names.count("# executable file(s) in tmpfs") == 1,
              "got %s" % names)
    r = rows[0]
    res.check("severity is the worst any host gave it",
              r["severity"] == "CRITICAL", "got %s" % r["severity"])
    res.check("all three hosts are named", r["host_count"] == 3)
    res.check("occurrences are summed: 2 + 7 + 1", r["total_occurrences"] == 10,
              "got %s" % r["total_occurrences"])
    res.check("a finding on one host only is not reported",
              "db02 only finding" not in names)
    res.check("the brute-force finding is not either - only web01 raised it",
              not any("brute forced" in n for n in names), "got %s" % names)


def check_hashes(L, res):
    print("\nhashes - the implant, the moved file, and the distribution")
    cor = build(L)
    rows = {r["digest"]: r for r in rows_of(cor, "CROSS_HASHES")}
    res.check("the shared OS binary is in the table", SHARED_OS in rows)
    res.check("but is not marked notable", rows[SHARED_OS]["notable"] == "",
              "notable=%r" % rows[SHARED_OS]["notable"])
    res.check("the /tmp implant is notable", rows[IMPLANT]["notable"] == "yes")
    res.check("and is at the same path on both",
              rows[IMPLANT]["same_path"] == "yes")
    res.check("the moved file is notable", rows[MOVED]["notable"] == "yes")
    res.check("and is marked as being at different paths",
              rows[MOVED]["same_path"] == "no")
    res.check("the finding counts only the notable ones",
              any(t.startswith("2 file(s) with the same contents")
                  for t in titles(cor)), "titles %s" % titles(cor))
    res.check("and the distribution's own files are set aside, not hidden",
              any("byte-identical across hosts" in t for t in titles(cor)))


def check_clocks(L, res):
    print("\nthe clocks - an ordering is only as good as the offsets under it")
    cor = build(L, third_clock_unknown=True)
    res.check("an unresolved offset is raised as MEDIUM",
              any(f.severity == "MEDIUM"
                  and "did not record the offset" in f.title
                  for f in cor.tri.findings), "titles %s" % titles(cor))
    ok = build(L, third_clock_unknown=False)
    res.check("and when every host resolved one, that is said too",
              any("Every host recorded the offset" in t for t in titles(ok)))
    res.check("as INFO, not as a warning",
              all(f.severity == "INFO" for f in ok.tri.findings
                  if "Every host recorded" in f.title))


def check_views(L, res):
    print("\nthe console's two views, merged")
    cor = build(L)
    t = tables_of(cor)
    res.check("FINDINGS and TIMELINE exist under the names the console reads",
              "FINDINGS" in t and "TIMELINE" in t, "got %s" % sorted(t))
    tl = rows_of(cor, "TIMELINE")
    res.check("every host's events are on it",
              set(r["host"] for r in tl) >= {"web01", "db02", "app03"},
              "hosts %s" % sorted(set(r["host"] for r in tl)))
    res.check("the correlation's own findings are too, labelled as such",
              any(r["host"] == "(correlation)" for r in tl))
    stamps = [r["timestamp_utc"] for r in tl]
    res.check("and it is in one ordering", stamps == sorted(stamps))
    res.check("HOSTS names every input", len(rows_of(cor, "HOSTS")) == 3)
    h = rows_of(cor, "HOSTS")[0]
    res.check("keyed on the same column a merged export carries",
              "collection" in tables_of(cor)["HOSTS"].columns,
              "columns %s" % tables_of(cor)["HOSTS"].columns)
    res.check("with the hostname the collection reported",
              h["hostname"] == "web01", "got %s" % h["hostname"])
    res.check("and the collection-time note trimmed to the instant",
              h["collected_utc"] == "2026-03-24 12:00:00 UTC",
              "got %r" % h["collected_utc"])



class FakeTable(object):
    """A built table, as merge_tables receives it."""

    def __init__(self, name, columns, rows, title="t", category="c",
                 description="d"):
        self.name, self.columns, self._rows = name, list(columns), [list(r) for r in rows]
        self.title, self.category, self.description = title, category, description
        self.sources = []

    def iter_rows(self):
        return iter(self._rows)

    def __len__(self):
        return len(self._rows)


def check_merge(L, res):
    """The join that makes one export out of several runs."""
    print("\nmerging - one table set, every row saying where it came from")
    per_host = [
        ("web01", [FakeTable("USERS", ["username", "uid"],
                             [["root", "0"], ["www", "33"]]),
                   # its own 'host' column: the hostname syslog wrote, which
                   # the merge must not overwrite with the label
                   FakeTable("AUTH_LOG", ["timestamp_utc", "host", "user"],
                             [["2026-03-24 03:00:00", "web01", "root"]])]),
        ("db02", [FakeTable("USERS", ["username", "uid", "shell"],
                            [["root", "0", "/bin/bash"]]),
                  FakeTable("AUTH_LOG", ["timestamp_utc", "host", "user"],
                            [["2026-03-24 03:14:00", "db02", "admin"]]),
                  FakeTable("SOCKETS", ["proto", "port"], [["tcp", "22"]])]),
    ]
    tables, column = L.merge_tables(per_host)
    by = {t.name: t for t in tables}
    res.check("the column is not called 'host'", column == "collection",
              "got %r" % column)
    res.check("every table name survives the merge",
              sorted(by) == ["AUTH_LOG", "SOCKETS", "USERS"], "got %s" % sorted(by))

    users = [list(r) for r in by["USERS"].iter_rows()]
    res.check("columns are unioned, not assumed identical",
              by["USERS"].columns == ["collection", "username", "uid", "shell"],
              "got %s" % by["USERS"].columns)
    res.check("a column only one host has is empty for the other",
              users[0] == ["web01", "root", "0", ""], "got %s" % users[0])
    res.check("and filled for the host that has it",
              users[2] == ["db02", "root", "0", "/bin/bash"], "got %s" % users[2])
    res.check("every row is kept", len(users) == 3, "got %d" % len(users))

    auth = [list(r) for r in by["AUTH_LOG"].iter_rows()]
    res.check("a table's own 'host' column is left alone",
              by["AUTH_LOG"].columns == ["collection", "timestamp_utc", "host", "user"],
              "got %s" % by["AUTH_LOG"].columns)
    res.check("and still holds what it held",
              [r[2] for r in auth] == ["web01", "db02"], "got %s" % auth)
    res.check("beside the label, which is a different fact",
              [r[0] for r in auth] == ["web01", "db02"], "got %s" % auth)

    res.check("a table only one host produced is merged too",
              len(list(by["SOCKETS"].iter_rows())) == 1)
    res.check("and still says which host produced it",
              list(by["SOCKETS"].iter_rows())[0][0] == "db02")

    # a collection whose own tables already use the preferred name
    clash = [("a", [FakeTable("X", ["collection", "v"], [["mine", "1"]])])]
    _t, col2 = L.merge_tables(clash)
    res.check("a collision steps aside rather than overwriting",
              col2 == "_collection", "got %r" % col2)


def check_keys(L, res):
    print("\nkeys - one private half reaching several hosts")
    cor = build(L)
    rows = rows_of(cor, "CROSS_KEYS")
    res.check("the key every host trusts is reported", len(rows) == 1,
              "got %d rows" % len(rows))
    res.check("joined on the key body, not the comment after it",
              rows and rows[0]["host_count"] == 3, "got %s" % rows)
    res.check("the type is decoded out of the key itself",
              rows and rows[0]["key_type"] == "ssh-rsa",
              "got %r" % (rows and rows[0]["key_type"]))
    res.check("a key only one host trusts is not reported",
              all("yyyy" not in r["fingerprint_head"] for r in rows))
    res.check("and a shared key is a finding",
              any("SSH key(s) are trusted by more than one host" in t
                  for t in titles(cor)), "titles %s" % titles(cor))


def check_accounts(L, res):
    print("\naccounts - somebody's, not the distribution's")
    cor = build(L)
    rows = dict((r["username"], r) for r in rows_of(cor, "CROSS_ACCOUNTS"))
    res.check("a distribution account on every host is not reported",
              "www-data" not in rows and "root" not in rows,
              "reported %s" % sorted(rows))
    res.check("an account somebody created is", "svc" in rows,
              "reported %s" % sorted(rows))
    res.check("uid 0 counts even though it is below the system threshold",
              "0" in rows["svc"]["uid"], "uid %r" % rows["svc"]["uid"])
    res.check("one defined differently across hosts is marked inconsistent",
              rows["svc"]["consistent"] == "no")
    res.check("with both shells named",
              "/bin/sh" in rows["svc"]["shells"]
              and "/bin/bash" in rows["svc"]["shells"],
              "shells %r" % rows["svc"]["shells"])
    res.check("an account on one host only is not reported", "deploy" not in rows)
    res.check("and the disagreement is a finding",
              any("defined differently on the hosts" in t for t in titles(cor)))


def check_persistence(L, res):
    print("\npersistence - the same thing set to run")
    cor = build(L)
    rows = dict((r["value"], r) for r in rows_of(cor, "CROSS_PERSISTENCE"))
    res.check("the cron line every host runs is reported",
              "/usr/local/bin/collect.sh" in rows, "got %s" % sorted(rows))
    res.check("naming all three hosts",
              rows["/usr/local/bin/collect.sh"]["host_count"] == 3)
    res.check("the shared ld.so.preload entry is reported",
              "/usr/lib/libhide.so" in rows)
    res.check("on the two hosts that carry it",
              rows["/usr/lib/libhide.so"]["host_count"] == 2)
    res.check("and a shared preload makes the finding HIGH",
              any(f.severity == "HIGH" and "autostart entry" in f.title
                  for f in cor.tri.findings),
              "got %s" % [(f.severity, f.title) for f in cor.tri.findings])


def check_persistence_is_entries(L, res):
    """A line inside a cron script is not a thing that runs.

    CRON keeps 'script_line' rows so an examiner can read what a cron script
    does. Joining on them turned CROSS_PERSISTENCE into the fragments two
    stock Debian hosts have in common - '$iosched_idle \\', ') | do_sendmail'
    - 183 of them on the two disk images this was found on.
    """
    print("\npersistence - entries, and whose they are")
    cor = build(L)
    rows = rows_of(cor, "CROSS_PERSISTENCE")
    values = [r["value"] for r in rows]
    res.check("a line inside a cron script is not an autostart entry",
              not any("do_sendmail" in v or "iosched_idle" in v
                      for v in values), "got %s" % values)
    res.check("the entry that runs the script still is",
              "/usr/local/bin/collect.sh" in values, "got %s" % values)
    by = dict((r["value"], r) for r in rows)
    res.check("something run out of /usr/local is notable",
              by["/usr/local/bin/collect.sh"]["notable"] == "yes",
              "got %s" % by.get("/usr/local/bin/collect.sh"))
    res.check("a stock cron.daily script is not",
              by.get("apache2", {}).get("notable") == "",
              "got %s" % by.get("apache2"))
    res.check("an ld.so.preload entry always is",
              by["/usr/lib/libhide.so"]["notable"] == "yes",
              "got %s" % by.get("/usr/lib/libhide.so"))
    res.check("and the stock ones are counted apart, at INFO",
              any(f.severity == "INFO" and "further autostart" in f.title
                  for f in cor.tri.findings),
              "got %s" % [(f.severity, f.title) for f in cor.tri.findings])


def check_techniques(L, res):
    print("\ntechniques - and which host is missing one")
    cor = build(L)
    rows = dict((r["technique"], r) for r in rows_of(cor, "CROSS_TECHNIQUES"))
    res.check("a technique every host raised is on all three",
              rows["T1036"]["host_count"] == 3, "got %s" % rows.get("T1036"))
    res.check("with nothing missing", rows["T1036"]["missing_from"] == "")
    res.check("one only web01 raised names the hosts that did not",
              rows["T1110"]["host_count"] == 1
              and set(rows["T1110"]["missing_from"].split(", ")) == set(["db02", "app03"]),
              "got %s" % rows.get("T1110"))
    res.check("severity is the worst that carried it",
              rows["T1036"]["severity"] == "CRITICAL")


def check_identity_from_config(L, res):
    """A host read from a disk image still has to be recognisable.

    INTERFACES is `ip addr` at collection time and a disk image has none, so
    identity resolved to nothing and CROSS_SESSIONS - the table this module
    exists for - reported no sign-ins however many the logs held. On a real
    three-host Hadoop cluster that was 116 successful logins from the master
    in slave1's auth.log, and a correlation that said nothing happened.
    """
    print("\nidentity, for a host that was read as a disk")
    cor = build(L)
    by_label = dict((c.label, c) for c in cor.cases)
    app = by_label["app03"]
    res.check("app03 is resolved to its own address, from the configuration",
              ADDR["app03"] in app.addresses,
              "got %s" % sorted(app.addresses))
    for wrong in ("10.0.0.0", "10.0.0.255", "10.0.0.1", "255.255.255.0",
                  "10.0.0.53", "8.8.8.8"):
        res.check("  %s is not this host" % wrong, wrong not in app.addresses,
                  "got %s" % sorted(app.addresses))
    res.check("which is what lets a login from it be attributed",
              cor._who_is(ADDR["app03"]) == "app03",
              "got %r" % cor._who_is(ADDR["app03"]))
    res.check("and an address in the case's range but nobody's is still nobody",
              not cor._who_is("10.0.0.99"),
              "got %r" % cor._who_is("10.0.0.99"))
    web = by_label["web01"]
    res.check("a host that did report an interface list still uses it",
              ADDR["web01"] in web.addresses, "got %s" % sorted(web.addresses))


def check_paths(L, res):
    print("\ntwo hops, read as one route")
    cor = build(L)
    rows = rows_of(cor, "CROSS_PATHS")
    res.check("web01 -> db02 -> app03 is drawn as one path",
              any(r["path"] == "web01 -> db02 -> app03" for r in rows),
              "got %s" % [r["path"] for r in rows])
    one = next(r for r in rows if r["path"] == "web01 -> db02 -> app03")
    res.check("both hops succeeded, so the route was reached",
              one["result"] == "reached", "got %s" % one["result"])
    res.check("and it is dated from the first hop to the last",
              one["first_utc"].endswith("03:20:00")
              and one["last_utc"].endswith("03:35:00"),
              "got %s .. %s" % (one["first_utc"], one["last_utc"]))
    res.check("a closed connection is not a sign-in",
              not any(r["result"] == "connection closed"
                      or "connection closed" in (r["evidence"] or "")
                      for r in rows_of(cor, "CROSS_SESSIONS")),
              "got %s" % [r["result"] for r in rows_of(cor, "CROSS_SESSIONS")])
    res.check("a route travelled end to end is CRITICAL",
              any(f.severity == "CRITICAL" and "travelled end to end" in f.title
                  for f in cor.tri.findings),
              "got %s" % [(f.severity, f.title) for f in cor.tri.findings])
    res.check("a path never doubles back on itself",
              not any(r["path"].split(" -> ")[0] == r["path"].split(" -> ")[2]
                      for r in rows))


def check_paths_window(L, res):
    print("\na hop too late to be the same movement")
    cor = build(L)
    edges = [{"when": "2026-03-24 03:00:00", "from": "a", "to": "b",
              "user": "root", "ok": True, "service": "sshd"},
             {"when": "2026-03-30 03:00:00", "from": "b", "to": "c",
              "user": "root", "ok": True, "service": "sshd"}]
    cor.session_edges = edges
    cor.tables = [t for t in cor.tables if t.name != "CROSS_PATHS"]
    cor.t_cross_paths()
    res.check("six days apart is not one route",
              "CROSS_PATHS" not in [t.name for t in cor.tables])
    edges[1]["when"] = "2026-03-24 06:00:00"
    cor.t_cross_paths()
    res.check("three hours apart is", "CROSS_PATHS" in
              [t.name for t in cor.tables])


def check_transfers(L, res):
    print("\nthe same file, and which host had it first")
    cor = build(L)
    rows = dict((r["digest"], r) for r in rows_of(cor, "CROSS_TRANSFERS"))
    res.check("the implant is reported as a transfer", IMPLANT in rows,
              "got %s" % list(rows))
    got = rows[IMPLANT]
    res.check("from the host that created it first",
              got["from_collection"] == "web01"
              and got["to_collection"] == "db02",
              "got %s -> %s" % (got["from_collection"], got["to_collection"]))
    res.check("with the gap between the two creations",
              got["gap"] == "20m", "got %s" % got["gap"])
    res.check("and the basis named as crtime", got["basis"] == "crtime",
              "got %s" % got["basis"])
    res.check("a file the distribution ships is not a transfer",
              SHARED_OS not in rows)
    res.check("a pair that can only be ordered by mtime says so",
              rows.get(MOVED, {}).get("basis") == "mtime",
              "got %s" % rows.get(MOVED))
    res.check("crtime-ordered transfers are HIGH",
              any(f.severity == "HIGH" and "and then on another" in f.title
                  for f in cor.tri.findings),
              "got %s" % [(f.severity, f.title) for f in cor.tri.findings])
    res.check("mtime-ordered ones are reported apart, at MEDIUM",
              any(f.severity == "MEDIUM" and "ordered by mtime" in f.title
                  for f in cor.tri.findings))


def check_privilege(L, res):
    print("\nprivilege granted the same way twice")
    cor = build(L)
    rows = rows_of(cor, "CROSS_PRIVILEGE")
    grants = dict((r["grant"], r) for r in rows)
    res.check("a sudoers rule on two hosts is here",
              "svc ALL=(ALL) NOPASSWD: ALL" in grants, "got %s" % list(grants))
    got = grants["svc ALL=(ALL) NOPASSWD: ALL"]
    res.check("named on both", got["host_count"] == 2
              and set(got["hosts"].split(", ")) == set(["web01", "db02"]),
              "got %s" % got["hosts"])
    res.check("and marked passwordless", got["nopasswd"] == "yes")
    res.check("a privileged group membership on every host is here too",
              grants.get("sudo: root", {}).get("host_count") == 3,
              "got %s" % grants.get("sudo: root"))
    res.check("a member only one host has is not",
              "sudo: svc" not in grants)
    res.check("a passwordless shared rule makes the finding HIGH",
              any(f.severity == "HIGH" and "privilege grant" in f.title
                  for f in cor.tri.findings),
              "got %s" % [(f.severity, f.title) for f in cor.tri.findings])
    res.check("the rule somebody wrote is notable",
              got["notable"] == "yes", "got %s" % got.get("notable"))
    res.check("the line every Ubuntu ships is not",
              grants["%sudo ALL=(ALL:ALL) ALL"]["notable"] == "",
              "got %s" % grants.get("%sudo ALL=(ALL:ALL) ALL"))
    res.check("nor is a system account in a privileged group",
              grants["sudo: root"]["notable"] == "",
              "got %s" % grants.get("sudo: root"))
    res.check("and the stock ones are counted apart, at INFO",
              any(f.severity == "INFO" and "further privilege grant" in f.title
                  for f in cor.tri.findings),
              "got %s" % [(f.severity, f.title) for f in cor.tri.findings])


def check_web(L, res):
    print("\nthe web logs, which nothing cross-host read before")
    cor = build(L)
    clients = dict((r["client"], r) for r in rows_of(cor, "CROSS_WEB_CLIENTS"))
    res.check("an address that reached two hosts is here", OUTSIDE in clients,
              "got %s" % list(clients))
    got = clients[OUTSIDE]
    res.check("with both named", got["host_count"] == 2
              and set(got["hosts"].split(", ")) == set(["web01", "db02"]),
              "got %s" % got["hosts"])
    res.check("and the requests it was answered counted",
              int(got["requests"]) == 3 and int(got["answered"]) == 1,
              "got %s of %s" % (got["answered"], got["requests"]))
    res.check("an address only one host saw is not here",
              "198.51.100.7" not in clients)
    res.check("being answered on more than one host is HIGH",
              any(f.severity == "HIGH" and "web client" in f.title
                  for f in cor.tri.findings),
              "got %s" % [(f.severity, f.title) for f in cor.tri.findings])
    reqs = dict((r["resource"], r) for r in rows_of(cor, "CROSS_WEB_REQUESTS"))
    res.check("a path asked for on two hosts is here", "/wp-login.php" in reqs,
              "got %s" % list(reqs))
    res.check("a path only one host was asked for is not",
              "/shell.php" not in reqs and "/only-here" not in reqs)


def check_findings_reach_the_merge(L, res):
    """A correlation finding has to be in the merged FINDINGS table.

    The console reads its findings list, its severity chips and its ATT&CK
    matrix out of that table rather than out of a Triage. The merged export
    holds the cross-host tables back from a second FINDINGS - and held the
    findings back with them, so "one of these machines signed in to another"
    was computed and then shown in no console, no CSV and no case.db.
    """
    print("\nthe correlation's own findings, in the merged export")
    cor = build(L)
    cross = cor.tables
    # a merged export, as cli.py builds one: per-host tables joined, then the
    # cross tables added and the correlation's findings folded in
    def table(name, cols, rows):
        t = L.Table(name, name.title(), cols, "Analysis", "")
        for r in rows:
            t.add(*r)
        return t

    per_host = [(c.label,
                 [table("FINDINGS", ["severity", "category", "title",
                                     "artifact", "count"],
                        [["HIGH", "Filesystem", "%s only" % c.label,
                          "bodyfile", 1]]),
                  table("TIMELINE", ["timestamp_utc", "severity", "category",
                                     "description"],
                        [[ts(3, 0), "HIGH", "Authentication",
                          "%s event" % c.label]])])
                for c in cor.cases]
    tables, column = L.merge_tables(per_host)
    L.fold_correlation(tables, cross, column)
    merged = dict((t.name, t) for t in tables)

    rows = list(merged["FINDINGS"].iter_rows())
    cols = merged["FINDINGS"].columns
    ti, ci = cols.index("title"), cols.index(column)
    titles = [r[ti] for r in rows]
    res.check("a per-host finding is still there",
              any(t.endswith(" only") for t in titles), "got %s" % titles[:4])
    res.check("and the correlation's own findings are too",
              any("machine-to-machine" in t for t in titles),
              "got %s" % titles[:8])
    corr = [r for r in rows if "machine-to-machine" in r[ti]]
    ai = cols.index("artifact")
    res.check("carrying the cross table it came from, in the column the "
              "console reads",
              all(r[ai] for r in corr), "got %s" % [r[ai] for r in corr])
    res.check("labelled as the correlation, not as one of the hosts",
              all(r[ci] == L.CORRELATION_LABEL for r in corr),
              "got %s" % [r[ci] for r in corr])
    res.check("which is not one of the input labels",
              L.CORRELATION_LABEL not in [c.label for c in cor.cases])
    tl = list(merged["TIMELINE"].iter_rows())
    tcols = merged["TIMELINE"].columns
    res.check("the correlation's timeline rows are folded in as well",
              len(tl) > len(cor.cases),
              "%d row(s) for %d host(s)" % (len(tl), len(cor.cases)))
    res.check("every folded row keeps its own columns",
              all(len(r) == len(tcols) for r in tl))


def check_diagram(L, res):
    """The diagram has to be drawn from the case, not from a case.

    The first version of this picture was a script with one case's hosts,
    counts and captions typed into it. That draws exactly one investigation
    and silently mislabels every other. These checks are the difference: the
    same code, handed this fixture, must produce this fixture's names and
    numbers and nothing from anywhere else.
    """
    print("\nthe correlation, drawn")
    cor = build(L)
    svg = _build_svg(L)(cor.tables, {"hostname": "web01, db02, app03"})
    res.check("something was drawn", bool(svg) and svg.startswith("<svg"),
              "got %r" % (svg[:40] if svg else svg))
    res.check("it is well-formed XML", _parses(svg))
    for host in ("web01", "db02", "app03"):
        res.check("  %s is on it" % host, host in svg)
    res.check("the address that reached two hosts is on it too",
              OUTSIDE in svg, "expected %s" % OUTSIDE)
    # A host's own address belongs on its own card - that is what the arrows
    # are about. What it must never be is a node of its own, so the check is
    # against the titles, not against the whole document.
    titles = _re().findall(r'class="t1"[^>]*>([^<]+)<', svg)
    res.check("a host's address is shown on its card",
              any(ADDR["web01"] in t for t in
                  _re().findall(r'class="t3[^"]*"[^>]*>([^<]+)<', svg)),
              "expected %s under a host name" % ADDR["web01"])
    res.check("but it is not a node of its own",
              ADDR["web01"] not in titles,
              "%s drawn as an outsider" % ADDR["web01"])
    # The cluster's own peers are the most-shared indicators in any real case,
    # so a filter that only knows the collection *names* draws the machines
    # themselves as strangers and pushes the real outsider off the picture.
    res.check("nor is the peer address every host sees most often",
              ADDR["db02"] not in titles,
              "%s drawn as an outsider" % ADDR["db02"])
    res.check("and the outsider survives being outranked by them",
              OUTSIDE in svg, "expected %s to be drawn" % OUTSIDE)
    res.check("HOSTS says what each collection answers on",
              any(r.get("addresses") for r in rows_of(cor, "HOSTS")),
              "no addresses column filled")
    res.check("the sign-in edges are labelled with their count",
              "sign-in" in svg and "refused" in svg)
    res.check("a shared file is named on the line that carries it",
              "file" in svg, "no file relation in any label")
    res.check("and a command that names another host is named too",
              "cmd" in svg, "no command relation in any label")
    res.check("a pair related several ways gets one line saying all of it",
              any(" · " in t for t in
                  __import__("re").findall(r'class="lbl"[^>]*>([^<]+)', svg)),
              "no combined label - every relation drew its own line again")
    res.check("the caption says what it was drawn from", "drawn from:" in svg)
    res.check("both themes are defined, not one flipped",
              "prefers-color-scheme: dark" in svg
              and 'data-theme="dark"' in svg)
    res.check("nothing from another case leaked in",
              "HDFS" not in svg and "hadoop" not in svg and "45010" not in svg)


def check_diagram_one_host(L, res):
    """One collection is not a correlation, and must not be drawn as one."""
    print("\nthe diagram declines when there is nothing to correlate")
    cor = build(L)
    hosts = [t for t in cor.tables if t.name == "HOSTS"][0]
    rows = list(hosts.iter_rows())
    hosts.rows = rows[:1]
    hosts._count = 1
    hosts._spill_path = None
    svg = _build_svg(L)(cor.tables, {})
    res.check("a single collection draws nothing at all", svg == "",
              "got %d bytes" % len(svg))


def _re():
    import re
    return re


def _build_svg(L):
    """The drawing code of whichever build is under test.

    Built, every module is one namespace and `build_svg` is on L itself.
    From src, L is linsight.correlate and the drawing lives next door. Taking
    it off L first is what makes `--built` test the built file rather than
    quietly importing src and reporting a pass for code it never ran.
    """
    got = getattr(L, "build_svg", None)
    if got is not None:
        return got
    from linsight.graph import build_svg
    return build_svg


def _parses(svg):
    import xml.dom.minidom
    try:
        xml.dom.minidom.parseString(svg.encode("utf-8"))
        return True
    except Exception:
        return False


def check_cross_timeline(L, res):
    """One clock for the whole case, and it has to carry every dated kind."""
    print(chr(10) + "everything between the hosts, in order")
    cor = build(L)
    rows = rows_of(cor, "CROSS_TIMELINE")
    res.check("there is a timeline at all", bool(rows), "no rows")
    stamps = [r["timestamp_utc"] for r in rows]
    res.check("it is sorted", stamps == sorted(stamps), "out of order")
    res.check("every row carries a time", all(stamps))
    kinds = set(r["basis"] for r in rows)
    for want in ("CROSS_SESSIONS", "CROSS_COMMANDS", "CROSS_TRANSFERS"):
        res.check("  %s reaches it" % want, want in kinds, "got %s" % kinds)
    res.check("both ends are named",
              all(r["from_collection"] and r["to_collection"] for r in rows
                  if r["basis"] != "CROSS_IOCS"))
    res.check("a refused sign-in is not called a sign-in",
              any(r["event"] == "sign-in refused" for r in rows),
              "got %s" % sorted(set(r["event"] for r in rows)))
    res.check("and it is counted in a finding",
              any("dated cross-host event" in f.title for f in cor.tri.findings),
              "got %s" % [f.title for f in cor.tri.findings][:4])


def check_tab_contract(L, res):
    """The console's Correlation tab reads these by name, so they must exist."""
    print("\nthe Correlation tab table contract")
    cor = build(L)
    names = [t.name for t in cor.tables]
    missing = [n for n in L.Correlator.CROSS_TABLES if n not in names]
    res.check("every table the tab names is built", not missing,
              "missing %s" % missing)


def check_sessions(L, res):
    """The table the whole exercise is for: one machine signing in to another."""
    print("\nsessions - one of these machines signing in to another")
    cor = build(L)
    rows = rows_of(cor, "CROSS_SESSIONS")
    pairs = [(r["from_collection"], r["to_collection"], r["result"]) for r in rows]
    res.check("web01 -> db02 is recorded",
              any(p[0] == "web01" and p[1] == "db02" for p in pairs),
              "got %s" % pairs)
    res.check("from both AUTH_LOG and LOGINS, not one of them",
              len([p for p in pairs if p[0] == "web01" and p[1] == "db02"]) == 2,
              "got %s" % pairs)
    res.check("the failed attempt on app03 is recorded too",
              any(p[0] == "web01" and p[1] == "app03" for p in pairs))
    res.check("a login from outside the case is not a cross-host session",
              all(r["source_address"] != "203.0.113.9" for r in rows),
              "got %s" % [r["source_address"] for r in rows])
    res.check("the successful path is CRITICAL",
              any(f.severity == "CRITICAL" and "sign-in path" in f.title
                  for f in cor.tri.findings),
              "got %s" % [(f.severity, f.title) for f in cor.tri.findings])
    res.check("and the failed-only path is HIGH, separately",
              any(f.severity == "HIGH" and "attempted and" in f.title
                  for f in cor.tri.findings))
    res.check("the account used is named in the finding",
              any("root" in " ".join(f.evidence or []) for f in cor.tri.findings
                  if "sign-in path" in f.title))


def check_commands(L, res):
    print("\ncommands - one machine told to reach another")
    cor = build(L)
    rows = rows_of(cor, "CROSS_COMMANDS")
    res.check("the ssh by address is caught",
              any(r["to_collection"] == "db02" and "ssh" in r["command"]
                  for r in rows), "got %s" % [r["command"] for r in rows])
    res.check("and the scp by hostname",
              any(r["to_collection"] == "db02" and "scp" in r["command"]
                  for r in rows), "got %s" % [r["command"] for r in rows])
    res.check("every row names where it was going",
              all(r["to_collection"] and r["matched"] for r in rows))
    res.check("a command reaching outside the case is not reported",
              not any("example.org" in r["command"] for r in rows))
    res.check("and a command that reaches nothing is not either",
              not any("/etc/passwd" in r["command"] for r in rows))
    res.check("it is a finding",
              any("told to reach another" in t for t in titles(cor)),
              "titles %s" % titles(cor))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--built", action="store_true",
                    help="test the built linsight.py instead of src/linsight")
    opts = ap.parse_args()
    L = load(opts.built)

    res = Result()
    check_labels(L, res)
    check_merge(L, res)
    check_iocs(L, res)
    check_findings(L, res)
    check_hashes(L, res)
    check_clocks(L, res)
    check_views(L, res)
    check_sessions(L, res)
    check_commands(L, res)
    check_keys(L, res)
    check_accounts(L, res)
    check_persistence(L, res)
    check_persistence_is_entries(L, res)
    check_techniques(L, res)
    check_identity_from_config(L, res)
    check_paths(L, res)
    check_paths_window(L, res)
    check_transfers(L, res)
    check_privilege(L, res)
    check_web(L, res)
    check_findings_reach_the_merge(L, res)
    check_diagram(L, res)
    check_diagram_one_host(L, res)
    check_cross_timeline(L, res)
    check_tab_contract(L, res)

    print("\n%d passed, %d failed" % (res.passed, len(res.failed)))
    if res.failed:
        print("\nfailures:")
        for what, why in res.failed:
            print("  %s: %s" % (what, why))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
