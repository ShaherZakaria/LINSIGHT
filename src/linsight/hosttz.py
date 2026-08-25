# -*- coding: utf-8 -*-
"""What time zone the host was in, and how we know.

Almost every timestamp in a Linux log is written in the host's local time with
no zone on it. 'Mar 24 22:14:44' is a fact about a clock, and turning it into
a fact about a moment needs the offset that clock was running at. Get it wrong
by an hour and every correlation in the report is out by an hour - against the
firewall logs, against the EDR, against the interview.

So this is not cosmetic metadata. It decides:

  the incident window   which events count as 'recent' relative to collection
  the timeline          where every syslog line lands
  the correlation       whether a login at 22:14 local matches an alert at
                        20:14 UTC or misses it entirely

The offset alone is not enough to report, either. '+01:00' does not say
whether the host was on CET in January or on BST in June, and a log line from
six months before the collection was written at a different offset than the
one the clock is at now. The zone *name* is what carries that, which is why
the name is hunted for as hard as the offset is.

Sources, best first, and each one records itself:

  timedatectl        systemd's own answer, naming the zone and the offset
  /etc/timezone      Debian and Ubuntu write the name here as plain text
  /etc/sysconfig/clock   the same on RHEL, in a shell variable
  /etc/localtime     a symlink into /usr/share/zoneinfo, so its *target* is
                     the zone name - which is what a disk or AD1 backend
                     hands back for a symlink. Failing that, its TZif content
                     gives the offset in force at a given moment even though
                     it never gives the name.
  date               the host's own clock, printing an offset and usually an
                     abbreviation
"""

from __future__ import annotations

import re
import struct

#: Where the zone name is written as text, and how to get it out.
NAME_FILES = (
    ("/etc/timezone", None),
    ("/etc/sysconfig/clock", re.compile(r'^\s*ZONE\s*=\s*"?([^"\s]+)"?')),
    ("/etc/sysconfig/timezone", re.compile(r'^\s*TIMEZONE\s*=\s*"?([^"\s]+)"?')),
    ("/etc/TZ", None),
)

#: Command output that states the zone. Globbed rather than named: which
#: directory a profile writes these into moves between profile generations.
TIMEDATECTL_GLOBS = (
    "live_response/**/timedatectl*.txt",
    "**/timedatectl*.txt",
)
DATE_GLOBS = (
    "live_response/**/date*.txt",
    "**/date.txt",
)

TIMEDATECTL_ZONE = re.compile(r"Time\s*zone\s*:\s*(\S+)", re.I)
TIMEDATECTL_OFFSET = re.compile(r"[(,]\s*([A-Z]{2,5})?,?\s*([+-]\d{4})\s*\)")

#: A zone name looks like Area/Location, or is one of the handful of bare ones
#: that are real. Anything else in /etc/timezone is a damaged file, and
#: reporting it would put a made-up zone in the report header.
ZONE_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9+_-]*(?:/[A-Za-z0-9+._-]+){1,2}$")
BARE_ZONES = ("UTC", "GMT", "UCT", "Universal", "Zulu", "EST", "MST", "HST",
              "EST5EDT", "CST6CDT", "MST7MDT", "PST8PDT", "localtime")

#: /usr/share/zoneinfo prefixes, so a symlink target becomes a zone name.
ZONEINFO_PREFIXES = ("/usr/share/zoneinfo/posix/", "/usr/share/zoneinfo/right/",
                     "/usr/share/zoneinfo/", "/usr/lib/zoneinfo/",
                     "../usr/share/zoneinfo/", "../../usr/share/zoneinfo/")


def _text(col, host_path):
    rel = col.rootfs(host_path)
    if not rel:
        return ""
    try:
        return col.text(rel) or ""
    except Exception:
        return ""


def _zone_from_target(target):
    """'/usr/share/zoneinfo/Europe/Berlin' -> 'Europe/Berlin'."""
    if not target:
        return ""
    target = target.strip().replace("\\", "/")
    for prefix in ZONEINFO_PREFIXES:
        idx = target.find(prefix)
        if idx >= 0:
            return target[idx + len(prefix):].strip("/")
    return ""


def valid_zone(name):
    """Whether this is a zone name rather than whatever else was in the file."""
    if not name:
        return False
    name = name.strip()
    if name in BARE_ZONES:
        return True
    return bool(ZONE_NAME.match(name)) and len(name) < 64


def tzif_offset(raw, at):
    """The UTC offset a TZif file puts in force at `at`, or None.

    /etc/localtime is the compiled zone, so it answers the question that
    actually matters - what offset was this host running at *then* - across
    daylight saving, which a single recorded offset cannot. Both v1 and v2+
    blocks are handled: v2 is what carries transitions past 2038, and it is
    appended after the v1 block rather than replacing it.
    """
    if not raw or raw[:4] != b"TZif":
        return None
    try:
        version = raw[4:5]
        offset = _tzif_block(raw, 20, 4)
        if version in (b"2", b"3", b"4") and offset is not None:
            # skip the v1 block and read the 64-bit one behind it
            second = raw.find(b"TZif", 4)
            if second > 0:
                deeper = _tzif_block(raw, second + 20, 8)
                if deeper is not None:
                    offset = deeper
        if offset is None:
            return None
        transitions, types, ttinfo = offset
    except Exception:
        return None

    from datetime import timedelta
    if not ttinfo:
        return None
    stamp = None
    if at is not None:
        try:
            stamp = int(at.timestamp())
        except Exception:
            stamp = None
    index = 0
    if stamp is not None and transitions:
        # the last transition at or before the moment asked about
        lo, hi = 0, len(transitions)
        while lo < hi:
            mid = (lo + hi) // 2
            if transitions[mid] <= stamp:
                lo = mid + 1
            else:
                hi = mid
        index = types[lo - 1] if lo else (types[0] if types else 0)
    elif types:
        index = types[0]
    if index >= len(ttinfo):
        index = 0
    return timedelta(seconds=ttinfo[index][0])


def _tzif_block(raw, at, width):
    """One TZif header plus its body -> (transitions, type indexes, ttinfo)."""
    if len(raw) < at + 24:
        return None
    counts = struct.unpack_from(">6I", raw, at)
    isutcnt, isstdcnt, leapcnt, timecnt, typecnt, charcnt = counts
    if typecnt == 0 or timecnt > 1 << 20 or typecnt > 1 << 16:
        return None
    pos = at + 24
    end = pos + timecnt * width
    if len(raw) < end + timecnt + typecnt * 6:
        return None
    fmt = ">%d%s" % (timecnt, "q" if width == 8 else "i")
    transitions = list(struct.unpack_from(fmt, raw, pos)) if timecnt else []
    pos = end
    types = list(raw[pos:pos + timecnt])
    pos += timecnt
    ttinfo = []
    for i in range(typecnt):
        gmtoff, isdst, abbrind = struct.unpack_from(">ibB", raw, pos + i * 6)
        ttinfo.append((gmtoff, isdst, abbrind))
    return transitions, types, ttinfo


def _from_timedatectl(col):
    for pattern in TIMEDATECTL_GLOBS:
        try:
            found = col.glob(pattern)
        except Exception:
            continue
        for rel in found:
            try:
                text = col.text(rel) or ""
            except Exception:
                continue
            m = TIMEDATECTL_ZONE.search(text)
            if not m:
                continue
            name = m.group(1).strip()
            if not valid_zone(name):
                continue
            off = None
            mo = TIMEDATECTL_OFFSET.search(text)
            if mo:
                off = _parse_offset(mo.group(2))
            return name, off, rel
    return "", None, ""


def _from_name_files(col):
    for path, rx in NAME_FILES:
        text = _text(col, path)
        if not text:
            continue
        for ln in text.splitlines():
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            name = ln
            if rx is not None:
                m = rx.match(ln)
                if not m:
                    continue
                name = m.group(1)
            if valid_zone(name):
                return name, path
    return "", ""


def _from_localtime_link(col):
    """The zone name, when /etc/localtime was collected as the symlink it is.

    A disk or an AD1 hands back a symlink's target as its content, and the
    target is the zone name spelled out - which is the only way to recover the
    name from a host whose /etc/timezone was never written.
    """
    for path in ("/etc/localtime", "/etc/localtime.bak"):
        rel = col.rootfs(path)
        if not rel:
            continue
        kind = ""
        try:
            kind = col.member_kind(rel)
        except Exception:
            pass
        try:
            raw = col.read_bytes(rel, 4096) or b""
        except Exception:
            raw = b""
        if raw[:4] == b"TZif":
            continue                       # the compiled zone, not a link
        target = raw.decode("utf-8", "replace")
        if kind == "l" or "zoneinfo" in target:
            name = _zone_from_target(target)
            if valid_zone(name):
                return name, path
    return "", ""


def _localtime_candidates(col, zone):
    """Where the host's own compiled zone might be, best first.

    /etc/localtime first, when it is the TZif itself. Then whatever it points
    at, and then the named zone under zoneinfo - because a collection that
    stored the symlink rather than the file still holds the file, one
    directory over, and reading it beats resolving the name against the
    analysis machine's tzdata.
    """
    out = []
    rel = col.rootfs("/etc/localtime")
    if rel:
        out.append((rel, "/etc/localtime"))
        try:
            raw = col.read_bytes(rel, 4096) or b""
        except Exception:
            raw = b""
        if raw[:4] != b"TZif":
            target = _zone_from_target(raw.decode("utf-8", "replace"))
            if valid_zone(target):
                zone = zone or target
    for base in ("/usr/share/zoneinfo/%s", "/usr/lib/zoneinfo/%s",
                 "/usr/share/zoneinfo/posix/%s"):
        if not zone:
            break
        rel = col.rootfs(base % zone)
        if rel:
            out.append((rel, base % zone))
    return out


def _from_date(col):
    """The offset and abbreviation the host's own `date` printed."""
    for pattern in DATE_GLOBS:
        try:
            found = col.glob(pattern)
        except Exception:
            continue
        for rel in found:
            try:
                text = (col.text(rel) or "").strip()
            except Exception:
                continue
            if not text:
                continue
            line = text.splitlines()[0]
            m = re.search(r"([+-]\d{4})\b", line)
            if m:
                return _parse_offset(m.group(1)), line, rel
            m = re.search(r"\b([A-Z]{3,5})\s+\d{4}$", line)
            if m:
                return None, line, rel
    return None, "", ""


def _parse_offset(text):
    from datetime import timedelta
    try:
        sign = -1 if text[0] == "-" else 1
        return sign * timedelta(hours=int(text[1:3]), minutes=int(text[3:5]))
    except (ValueError, IndexError, TypeError):
        return None


def offset_of_zone(name, at):
    """The offset a named zone was at on a given date, if this Python knows it.

    zoneinfo is standard from 3.9 and reads the host's own tzdata, so on an
    analysis box with a current tzdata this resolves historical offsets
    properly - including the daylight saving in force at the time rather than
    the one in force now.
    """
    if not name or name in ("localtime",):
        return None
    try:
        from zoneinfo import ZoneInfo
    except ImportError:
        return None
    try:
        from datetime import datetime, timezone as _tz
        moment = at or datetime.now(_tz.utc)
        return moment.astimezone(ZoneInfo(name)).utcoffset()
    except Exception:
        return None


def resolve_hosttz(col, at=None):
    """Everything this collection says about the host's time zone.

    Returns a dict: the zone name, the offset, where each came from, and the
    abbreviation if anything printed one. Nothing raises - a collection that
    says nothing about its zone gets empty fields, which is a fact the report
    should print rather than a reason to fail.
    """
    out = {"zone": "", "zone_source": "", "offset": None,
           "offset_source": "", "date_line": "", "note": ""}
    try:
        zone, off, rel = _from_timedatectl(col)
        if zone:
            out["zone"], out["zone_source"] = zone, rel
            if off is not None:
                out["offset"], out["offset_source"] = off, rel
        if not out["zone"]:
            zone, path = _from_name_files(col)
            if zone:
                out["zone"], out["zone_source"] = zone, path
        if not out["zone"]:
            zone, path = _from_localtime_link(col)
            if zone:
                out["zone"], out["zone_source"] = zone, path

        # /etc/localtime is the compiled zone: it answers what offset was in
        # force at the moment asked about, across daylight saving, which no
        # single recorded number can. Where it is a symlink - which it is on
        # most hosts - the compiled zone is at the other end, and following it
        # inside the collection reads the host's own tzdata rather than this
        # machine's.
        if out["offset"] is None:
            for path, label in _localtime_candidates(col, out["zone"]):
                raw = col.read_bytes(path, 512 * 1024)
                off = tzif_offset(raw, at)
                if off is not None:
                    out["offset"], out["offset_source"] = off, label
                    break

        if out["offset"] is None and out["zone"]:
            off = offset_of_zone(out["zone"], at)
            if off is not None:
                out["offset"] = off
                out["offset_source"] = "%s, resolved against this machine's " \
                                       "tzdata" % out["zone"]

        if out["offset"] is None:
            off, line, rel = _from_date(col)
            out["date_line"] = line
            if off is not None:
                out["offset"], out["offset_source"] = off, rel
    except Exception:
        return out

    # A zone whose own tzdata disagrees with the offset in /etc/localtime is
    # worth saying out loud: it is what a host whose zone was changed after
    # the logs were written looks like, and it is why a correlation can be an
    # hour out with everything apparently correct.
    if out["zone"] and out["offset"] is not None and \
            out["offset_source"] == "/etc/localtime":
        named = offset_of_zone(out["zone"], at)
        if named is not None and named != out["offset"]:
            out["note"] = ("/etc/localtime was compiled at %s while %s is %s "
                           "on this date - the zone was changed, or the two "
                           "were never in step"
                           % (format_offset(out["offset"]), out["zone"],
                              format_offset(named)))
    return out


def format_offset(delta):
    """A timedelta as '+01:00'."""
    if delta is None:
        return ""
    total = int(delta.total_seconds())
    sign = "-" if total < 0 else "+"
    total = abs(total)
    return "%s%02d:%02d" % (sign, total // 3600, (total % 3600) // 60)


def describe_hosttz(info):
    """The one line METADATA carries."""
    zone = info["zone"]
    off = format_offset(info["offset"])
    if zone and off:
        return "%s (%s)" % (zone, off)
    return zone or off or ""
