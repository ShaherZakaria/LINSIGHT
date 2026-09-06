#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Test the timestamp-forgery rules against a bodyfile written to trip them.

    python tests/test_timestomp.py            # against src/linsight
    python tests/test_timestomp.py --built    # against the built linsight.py

No fixture and no image: the input is eleven bodyfile lines this file writes,
which is the whole evidence these rules ever see. A timestomp check is a
statement about four integers on one inode, so a synthetic inode tests it
exactly as well as a real one - and unlike a disk image it can hold the cases
that matter, including the ones that must *not* fire.

Half of this suite is those. A rule that flags every backdated mtime finds
every timestomp and is still useless, because on a Linux host `dpkg`, `cp -p`
and `tar -p` produce that shape by the thousand. So the fixture carries a
package-installed binary, a file on a relatime mount whose atime equals its
mtime, and a directory - and the test fails if any of them is reported.
"""

import argparse
import calendar
import os
import sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

COLLECTED = datetime(2026, 3, 24, 12, 0, 0, tzinfo=timezone.utc)


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
    from linsight import triage
    return triage


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


def e(y, mo, d, h=0, mi=0, s=0):
    """A UTC wall-clock time as the epoch seconds a bodyfile carries."""
    return calendar.timegm((y, mo, d, h, mi, s, 0, 0, 0))


def row(path, inode, mode, atime, mtime, ctime, crtime):
    """mactime: md5|name|inode|mode|uid|gid|size|atime|mtime|ctime|crtime."""
    return "0|%s|%d|%s|0|0|4096|%d|%d|%d|%d" % (
        path, inode, mode, atime, mtime, ctime, crtime)


#: (path, what it is there to prove). The clean entries come first so that a
#: rule which has become too broad fails on them before anything else.
BODYFILE = [
    # -- must stay silent -------------------------------------------------
    # written once, read later: the ordinary shape of a file nobody edited
    row("/usr/bin/ls", 101, "-rwxr-xr-x",
        e(2026, 3, 20, 8, 14, 37), e(2025, 11, 2, 3, 41, 9),
        e(2026, 1, 5, 17, 22, 51), e(2026, 1, 5, 17, 22, 51)),
    # a packaged binary: dpkg keeps the build date as mtime and creates the
    # file at install time, so mtime is a year older than crtime. This is the
    # single biggest false positive available and it must not be taken
    row("/usr/sbin/nginx", 102, "-rwxr-xr-x",
        e(2026, 2, 1, 6, 0, 0), e(2024, 9, 12, 14, 8, 33),
        e(2026, 2, 1, 6, 0, 0), e(2026, 2, 1, 6, 0, 0)),
    # relatime, never read since it was written: atime == mtime exactly, and
    # the build stamped a round minute. Not the touch -t shape - ctime agrees
    row("/usr/share/doc/pkg/changelog", 103, "-rw-r--r--",
        e(2025, 5, 1, 12, 0, 0), e(2025, 5, 1, 12, 0, 0),
        e(2025, 5, 1, 12, 0, 0), e(2025, 5, 1, 12, 0, 0)),
    # a directory whose mtime runs ahead of its ctime. Only regular files are
    # scored: a directory's mtime moves when an entry is added or removed
    row("/var/spool/cron", 104, "drwxr-xr-x",
        e(2026, 3, 23, 22, 0, 0), e(2026, 3, 24, 4, 0, 0),
        e(2026, 3, 23, 22, 0, 0), e(2026, 1, 1, 0, 0, 0)),
    # one second of disagreement, which is a coarse clock rather than a lie
    row("/etc/resolv.conf", 105, "-rw-r--r--",
        e(2026, 3, 24, 9, 2, 13), e(2026, 3, 24, 9, 2, 14),
        e(2026, 3, 24, 9, 2, 13), e(2026, 1, 5, 17, 22, 51)),

    # -- must fire --------------------------------------------------------
    # mtime_ahead: mtime five hours past its own ctime
    row("/usr/sbin/sshd", 201, "-rwxr-xr-x",
        e(2026, 3, 23, 22, 0, 2), e(2026, 3, 24, 4, 1, 11),
        e(2026, 3, 23, 23, 0, 2), e(2026, 1, 5, 17, 22, 51)),
    # pre_creation: the inode changed before it existed
    row("/usr/lib/libc.so.7", 202, "-rwxr-xr-x",
        e(2025, 6, 1, 0, 0, 0), e(2025, 6, 1, 0, 0, 2),
        e(2025, 6, 1, 0, 0, 3), e(2026, 3, 23, 21, 0, 0)),
    # new_file_old_mtime: created during the window, mtime reads 2019
    row("/usr/local/bin/updater", 203, "-rwxr-xr-x",
        e(2026, 3, 23, 20, 0, 0), e(2019, 4, 2, 11, 30, 0),
        e(2026, 3, 23, 20, 0, 0), e(2026, 3, 23, 20, 0, 0)),
    # minute_aligned: the touch -t shape, and old enough to be backdated too
    row("/tmp/.x/payload", 204, "-rwxr-xr-x",
        e(2024, 1, 1, 0, 0, 0), e(2024, 1, 1, 0, 0, 0),
        e(2026, 3, 23, 21, 14, 39), e(2026, 3, 23, 21, 14, 39)),
    # stamp_missing: mtime zeroed rather than forged
    row("/var/www/html/shell.php", 205, "-rw-r--r--",
        e(2026, 3, 23, 19, 0, 0), 0,
        e(2026, 3, 23, 19, 0, 0), e(2026, 3, 23, 19, 0, 0)),
    # a backdated mtime with no crtime to contradict it - what a collector's
    # own bodyfile looks like. Only the ctime-based rules can speak here
    row("/usr/bin/passwd", 206, "-rwsr-xr-x",
        e(2026, 3, 23, 18, 0, 0), e(2017, 1, 1, 0, 0, 0),
        e(2026, 3, 23, 18, 0, 0), 0),
]

CLEAN = ("/usr/bin/ls", "/usr/sbin/nginx", "/usr/share/doc/pkg/changelog",
         "/var/spool/cron", "/etc/resolv.conf")

#: rule -> the paths that rule, and only that rule, must name
EXPECTED = {
    "mtime_ahead": ["/usr/sbin/sshd"],
    "pre_creation": ["/usr/lib/libc.so.7"],
    "new_file_old_mtime": ["/tmp/.x/payload", "/usr/lib/libc.so.7",
                           "/usr/local/bin/updater"],
    "minute_aligned": ["/tmp/.x/payload"],
    "stamp_missing": ["/var/www/html/shell.php"],
}


class Col(object):
    """The two calls analyze_bodyfile makes of a collection."""
    kind = "dir"
    prefix = ""
    notes = ()

    def exists(self, rel):
        return rel == "bodyfile/bodyfile.txt"

    def iter_lines(self, rel):
        return iter(BODYFILE)


def run(L, window=72, collected=COLLECTED):
    opts = argparse.Namespace(window=window, timeline_limit=3000, debug=True)
    tri = L.Triage(Col(), opts)
    tri.collection_time = collected
    tri.analyze_bodyfile()
    return tri


def fired(tri):
    return {rule: sorted(r[0] for r in tri.timestomp["rows"].get(rule) or [])
            for rule in tri.TIMESTOMP_ORDER}


def check_rules(L, res):
    print("\nthe rules - what each one may and may not name")
    tri = run(L)
    got = fired(tri)
    for rule, want in EXPECTED.items():
        res.check("%-19s %s" % (rule, ", ".join(os.path.basename(p) for p in want)),
                  got[rule] == want, "named %s" % got[rule])
    named = set(p for paths in got.values() for p in paths)
    for path in CLEAN:
        res.check("silent on %s" % path, path not in named,
                  "was reported")
    # /tmp/.x/payload is deliberately in two rules: they are independent
    # statements about one inode, not a classifier that has to pick one
    res.check("one inode may fail two rules",
              "/tmp/.x/payload" in got["minute_aligned"]
              and "/tmp/.x/payload" in got["new_file_old_mtime"])


def check_no_window(L, res):
    print("\nwithout a collection time - four of the five still answer")
    tri = run(L, collected=None)
    got = fired(tri)
    res.check("the provable rules still fire",
              got["mtime_ahead"] and got["pre_creation"]
              and got["minute_aligned"] and got["stamp_missing"])
    res.check("the one that needs the window abstains",
              got["new_file_old_mtime"] == [],
              "named %s" % got["new_file_old_mtime"])


def check_findings(L, res):
    print("\nfindings - one per rule, dated by the clock that was not forged")
    tri = run(L)
    by_title = {}
    for f in tri.findings:
        if f.category == "Anti-forensics":
            by_title[f.title.split(":")[0]] = f
    for rule, want in EXPECTED.items():
        sev, title, _detail, _bulk = tri.TIMESTOMP_RULES[rule]
        f = by_title.get(title)
        res.check("finding for %s" % rule,
                  f is not None and f.severity == sev and f.count == len(want),
                  "got %r" % (f and (f.severity, f.count),))
        res.check("  %s carries T1070.006" % rule,
                  f is not None and "T1070.006" in (f.mitre or ""))
    sshd = by_title[tri.TIMESTOMP_RULES["mtime_ahead"][1]]
    res.check("dated by ctime, not by the mtime it claims",
              sshd.first_seen == "2026-03-23 23:00:02",
              "first_seen %r" % sshd.first_seen)


def check_events(L, res):
    print("\ntimeline - the provable rules only, and on ctime")
    tri = run(L)
    evs = [ev for ev in tri.events if ev.category == "Anti-forensics"]
    res.check("two events, one per provable hit", len(evs) == 2,
              "got %d" % len(evs))
    res.check("placed at ctime",
              sorted(str(ev.ts)[:19] for ev in evs)
              == ["2025-06-01 00:00:03", "2026-03-23 23:00:02"],
              "at %s" % sorted(str(ev.ts)[:19] for ev in evs))
    res.check("corroborating rules stay off the timeline",
              not any("exact minute" in ev.description for ev in evs))


def check_no_double_report(L, res):
    """The older bodyfile check stands aside where TIMESTOMP says it better.

    /usr/local/bin/updater satisfies both: created inside the window with a
    2019 mtime, which is new_file_old_mtime, and an mtime far older than a
    ctime inside the window, which is the check that was there first. Two
    findings, framed differently, naming one file - and nothing in either to
    tell a reader they are the same file.

    /usr/bin/passwd is the reason the older check stays. Its bodyfile row has
    no creation time, so the rule that would replace it cannot fire at all,
    and the older check is the only thing left that sees the backdating.
    """
    print("\none file, one finding")
    tri = run(L)
    old = next((f for f in tri.findings
                if "mtime far older than a ctime" in f.title), None)
    res.check("the older check still fires where there is no crtime",
              old is not None, "no finding at all")
    ev = " ".join(old.evidence) if old else ""
    res.check("  and names the file only it can see",
              "/usr/bin/passwd" in ev, "evidence: %s" % ev)
    res.check("  but not the one new_file_old_mtime already named",
              "/usr/local/bin/updater" not in ev, "evidence: %s" % ev)
    res.check("  counting only what it reports", old is not None
              and old.count == len(old.evidence),
              "count %s against %d evidence line(s)"
              % (old and old.count, len(old.evidence if old else [])))
    res.check("  and saying where the rest went",
              old is not None and "new_file_old_mtime" in (old.detail or ""),
              "detail: %s" % (old and old.detail))
    still = fired(tri)["new_file_old_mtime"]
    res.check("the file it stood aside for is still reported, in TIMESTOMP",
              "/usr/local/bin/updater" in still, "got %s" % still)


def check_bulk(L, res):
    """Above the bulk threshold a rule is demoted and stops raising events.

    A clock that stepped backwards fails mtime_ahead on every file on the
    host. Reporting that as HIGH, once per file, would bury the run under one
    fact - and it is a fact about the clock, not about an intruder.
    """
    print("\nin bulk - demoted, and off the timeline")
    global BODYFILE
    keep = BODYFILE
    try:
        BODYFILE = [row("/opt/app/f%d" % i, 1000 + i, "-rw-r--r--",
                        e(2026, 3, 20, 1, 0, 0), e(2026, 3, 22, 1, 0, 0),
                        e(2026, 3, 20, 1, 0, 0), e(2026, 1, 1, 0, 0, 0))
                    for i in range(L.Triage.TIMESTOMP_BULK + 1)]
        tri = run(L)
    finally:
        BODYFILE = keep
    f = [x for x in tri.findings if x.category == "Anti-forensics"]
    res.check("one finding, not %d" % (L.Triage.TIMESTOMP_BULK + 1), len(f) == 1)
    res.check("demoted to INFO", f and f[0].severity == "INFO",
              "severity %s" % (f and f[0].severity))
    res.check("count is still exact",
              f and f[0].count == L.Triage.TIMESTOMP_BULK + 1,
              "count %s" % (f and f[0].count))
    res.check("no per-file events",
              not [ev for ev in tri.events if ev.category == "Anti-forensics"])


def check_cap(L, res):
    """The retained rows are capped; the count the finding reports is not.

    Driven at a cap of three rather than at the real five thousand: the
    property under test is that the two numbers come apart, and proving it
    with three rows proves it with five thousand.
    """
    print("\nthe row cap - bounded memory, exact arithmetic")
    global BODYFILE
    keep, cap = BODYFILE, L.Triage.TIMESTOMP_ROW_CAP
    try:
        L.Triage.TIMESTOMP_ROW_CAP = 3
        BODYFILE = [row("/opt/app/f%d" % i, 1000 + i, "-rw-r--r--",
                        e(2026, 3, 20, 1, 0, 0), e(2026, 3, 22, 1, 0, 0),
                        e(2026, 3, 20, 1, 0, 0), e(2026, 1, 1, 0, 0, 0))
                    for i in range(10)]
        tri = run(L)
    finally:
        BODYFILE, L.Triage.TIMESTOMP_ROW_CAP = keep, cap
    res.check("rows stop at the cap",
              len(tri.timestomp["rows"]["mtime_ahead"]) == 3,
              "kept %d" % len(tri.timestomp["rows"]["mtime_ahead"]))
    res.check("the count does not", tri.timestomp["n"]["mtime_ahead"] == 10,
              "counted %d" % tri.timestomp["n"]["mtime_ahead"])
    f = [x for x in tri.findings if x.category == "Anti-forensics"]
    res.check("and the finding reports the count, not the rows kept",
              f and f[0].count == 10, "count %s" % (f and f[0].count))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--built", action="store_true",
                    help="test the built linsight.py instead of src/linsight")
    opts = ap.parse_args()
    L = load(opts.built)

    res = Result()
    check_rules(L, res)
    check_no_window(L, res)
    check_findings(L, res)
    check_events(L, res)
    check_no_double_report(L, res)
    check_bulk(L, res)
    check_cap(L, res)

    print("\n%d passed, %d failed" % (res.passed, len(res.failed)))
    if res.failed:
        print("\nfailures:")
        for what, why in res.failed:
            print("  %s: %s" % (what, why))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
