# -*- coding: utf-8 -*-
from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from datetime import timedelta
from datetime import timezone
import json
import os
import re
import struct
import sys

from .model import Event, Finding, SEV_RANK
from .term import Progress, status, trunc
from .common import (
    trie_pattern,
    ACCEPTED_LOGIN_RE, BASELINE_SUID, BENIGN_HIDDEN, COMPILED_CMD_PATTERNS,
    DANGEROUS_SUID_NAMES, PRIVILEGED_GROUPS, PRIV_HINT_RE, ROOTKIT_RE,
    SUSPICIOUS_PORTS, SYSTEM_BIN_DIRS, SYSTEM_CFG_DIRS, TMPFS_DIRS,
    _TS_SYSLOG_RE, _ts_text, epoch, hexip_to_str, human_size, is_private_ip,
    match_failed_login, norm_ip, norm_log_ts, parse_lstart, span_add, span_of,
    split_hostport)
from .decode import (
    JOURNAL_MAGIC, decompress_bytes, parse_journal, parse_utmp,
    split_log_line)
from .collect import velo_get, velo_time
from .distro import describe_distro, identify_distro
from .hosttz import describe_hosttz, format_offset, resolve_hosttz



# ---------------------------------------------------------------------------
# the triage engine
# ---------------------------------------------------------------------------

def _line_starts(text):
    """Offsets of every line start, built once per artifact that matched."""
    out = [0]
    at = text.find("\n")
    while at >= 0:
        out.append(at + 1)
        at = text.find("\n", at + 1)
    return out


def _line_of(starts, offset):
    """1-based line number for a character offset."""
    lo, hi = 0, len(starts)
    while lo < hi:
        mid = (lo + hi) // 2
        if starts[mid] <= offset:
            lo = mid + 1
        else:
            hi = mid
    return lo or 1


class Triage:
    def __init__(self, col, opts):
        self.col = col
        self.opts = opts
        self.findings = []
        self.events = []
        self._event_keys = set()   # see event_once
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
        self.tz_source = ""            # what stated it, if anything did
        self.host_tz = {}
        self.iocs = defaultdict(set)         # ioc -> why it is one
        self.ioc_sources = defaultdict(set)  # ioc -> artifacts it came from
        self.ioc_count = defaultdict(int)    # ioc -> times an analyzer saw it
        self.ioc_span = defaultdict(lambda: ['', ''])   # ioc -> first, last
        self.pivot_artifacts = {}     # indicator -> the artifacts naming it
        self.pivot_reported = set()   # the ones that earn a finding
        self.ww_paths = set()         # world-writable paths confirmed from the bodyfile
        self.timestomp = {"rows": defaultdict(list), "n": defaultdict(int)}
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

    def event_once(self, key, ts, category, description, severity="INFO",
                   source=""):
        """One timeline event for an act several artifacts recorded.

        A sudo call reaches this three ways on a host that keeps auth.log, the
        journal and auditd, and one login is in wtmp, in what `last` printed
        and in PAM's own session lines. Every one of those is a record worth
        keeping as a row, and the tables keep all of them with the origin in a
        column, because two records of one act disagreeing is itself the
        finding. The timeline is the other question - it is a list of what
        happened, and the same elevation three times over is three answers to
        "how many times did they become root".

        The key is the caller's, because only the caller knows which fields
        identify the act rather than the record of it. -> True if it was added.
        """
        if key in self._event_keys:
            return False
        self._event_keys.add(key)
        self.event(ts, category, description, severity, source)
        return True

    def resolve_host_timezone(self):
        """Establish the host's time zone, for every layout.

        Runs before the analyzers because almost every Linux log timestamp is
        local with no zone on it, and the offset is what turns 'Mar 24
        22:14:44' from a fact about a clock into a fact about a moment. An
        hour wrong here is an hour wrong in every correlation the report
        supports.

        A collector that stated its own offset keeps it: uac.log and the
        Velociraptor context record what the host's clock was doing at the
        moment of collection, which is a better statement about that moment
        than anything reconstructed from the filesystem. The zone *name* is
        filled in regardless, because the offset alone cannot say whether a
        log line from six months earlier was written on summer time.
        """
        info = resolve_hosttz(self.col, self.collection_time)
        self.host_tz = info
        if info["zone"]:
            self.meta["Time zone"] = describe_hosttz(info)
            if info["zone_source"]:
                self.meta["Time zone source"] = info["zone_source"]
        if info["offset"] is not None and not self.tz_source:
            self.tz_offset = info["offset"]
            self.tz_source = info["offset_source"]
            self.meta["Host UTC offset"] = "%s (from %s)" % (
                format_offset(info["offset"]), info["offset_source"])
        elif info["offset"] is None and not self.tz_source:
            # nothing anywhere stated it. One line saying so, rather than the
            # collector-specific message and this one contradicting each other
            self.meta["Host UTC offset"] = (
                "unknown - nothing in this collection records it, so "
                "host-local log stamps are read as UTC")
        elif info["offset"] is not None and info["offset"] != self.tz_offset:
            # the collector said one thing and the filesystem says another;
            # the collector's own statement stands, and the disagreement is
            # not swallowed
            self.meta["Time zone note"] = (
                "%s says %s while the collector recorded %s at collection "
                "time - log stamps are read at the collector's offset"
                % (info["offset_source"], format_offset(info["offset"]),
                   format_offset(self.tz_offset)))
        if info["note"]:
            self.meta["Time zone note"] = info["note"]
        if not info["zone"] and not self.meta.get("Time zone"):
            self.meta["Time zone"] = (
                "not recorded in this collection - host-local log stamps are "
                "read at %s" % format_offset(self.tz_offset))
        self._timezone_finding(info)

    def _timezone_finding(self, info):
        """Say what the zone is, and say when nothing said."""
        if info["zone"] or info["offset"] is not None:
            evidence = []
            if info["zone_source"]:
                evidence.append("%-28s %s" % (info["zone_source"], info["zone"]))
            if info["offset_source"]:
                evidence.append("%-28s %s" % (info["offset_source"],
                                              format_offset(info["offset"])))
            if info["date_line"]:
                evidence.append("%-28s %s" % ("the host's own date",
                                              info["date_line"]))
            if info["note"]:
                evidence.append(info["note"])
            self.add("INFO", "System",
                     "Host time zone: %s" % (describe_hosttz(info) or "offset only"),
                     "Linux writes most log timestamps in local time with no "
                     "zone on them, so this is what every one of them below is "
                     "read against. An hour wrong here is an hour wrong in "
                     "every correlation this report supports.",
                     evidence=evidence or None,
                     source=info["zone_source"] or info["offset_source"])
        else:
            self.add("MEDIUM", "System", "Host time zone is unknown",
                     "Nothing in this collection records the host's time zone "
                     "or its offset, so every local timestamp below is read as "
                     "UTC. If the host was not on UTC, every one of them is "
                     "wrong by that offset - which is the kind of error that "
                     "makes a timeline agree with itself and disagree with "
                     "every other source.",
                     evidence=["looked for: timedatectl output, /etc/timezone, "
                               "/etc/sysconfig/clock, /etc/localtime, "
                               "the host's `date`"],
                     source="time zone")

    def identify_distribution(self):
        """Establish the distribution, whichever layout the evidence arrived as.

        Called for every collection rather than from one layout's metadata
        pass, because the question is about the host and not about the
        container it reached us in - a UAC tar, a Velociraptor zip, a disk
        image and an AD1 all have to answer it the same way.
        """
        self.distro = identify_distro(self.col)
        label = describe_distro(self.distro)
        info = {}
        if label:
            info["Distribution"] = label
            # A collector often records the OS as 'linux', which is true and
            # useless. Where that is all there is, the distribution is the
            # better answer to the same question.
            current = (self.meta.get("Operating system") or "").strip()
            if current.lower() in ("", "linux", "gnu/linux", "unix",
                                   "linux/unix", "posix"):
                info["Operating system"] = label
        if self.distro["family"]:
            info["Distribution family"] = self.distro["family"]
        if self.distro["version"]:
            info["Distribution version"] = self.distro["version"]
        if self.distro["source"]:
            info["Distribution source"] = "%s%s" % (
                self.distro["source"],
                " (%s)" % self.distro["detail"] if self.distro["detail"] else "")
        if self.distro["kernel"] and not self.meta.get("Kernel release"):
            info["Kernel release"] = "%s%s" % (
                self.distro["kernel"],
                " (from %s)" % self.distro["kernel_source"]
                if self.distro["kernel_source"] else "")
        self.meta.update({k: v for k, v in info.items() if v})
        self._distro_findings()

    def _distro_findings(self):
        """Say what the host was, and say so when the sources disagree.

        The identification itself is INFO: it is context, not a lead. The
        disagreement is not. An /etc/os-release naming one distribution while
        the package database and the kernel name another is what a container
        image examined as a host looks like, what a chroot looks like, and
        what an edited os-release looks like - and an analyst who is not told
        will read every path in this report as if it came off the machine the
        text file claimed.
        """
        d = getattr(self, "distro", None)
        if not d:
            return
        label = describe_distro(d)
        if label:
            lines = []
            for e in d["evidence"]:
                if not (e.name or e.family):
                    continue
                lines.append("%-34s %s%s"
                             % (e.source,
                                e.label() or "%s family" % e.family,
                                "  - %s" % e.detail if e.detail else ""))
            self.add("INFO", "System", "Distribution: %s" % label,
                     "Established from %s. Where the logs are, what the "
                     "package history is called and which rules apply all "
                     "follow from this."
                     % (d["source"] or "the evidence below"),
                     evidence=lines or None,
                     source=d["source"], count=len(lines) or None)
        elif d["evidence"]:
            self.add("INFO", "System", "Distribution could not be named",
                     "Nothing in this collection names the distribution. The "
                     "family below is what the package manager's own files "
                     "say, which still settles where the logs live.",
                     evidence=["%s  %s" % (e.source, e.family)
                               for e in d["evidence"] if e.family] or None,
                     source="distribution")
        if d["conflict"]:
            self.add("MEDIUM", "System", "Distribution evidence disagrees",
                     "Different sources on this host name different "
                     "distribution families. That is what a container image "
                     "read as a host, a chroot, a rescue mount or an edited "
                     "os-release looks like - and until it is resolved, every "
                     "path in this report may belong to a different system "
                     "than the one you think you are reading.",
                     evidence=[d["conflict"]], source="distribution",
                     mitre="T1036 Masquerading")

    def _disk_findings(self):
        """Say, in the findings, what the disk scan could and could not open.

        A LUKS partition, a volume group missing one of its disks, a
        filesystem nothing here parses: each of those is a part of the
        evidence that was not examined, and an examination that does not say
        so reads as one that found nothing there. Severity is deliberately
        INFO for the layout and MEDIUM for the gaps - a gap is not a finding
        about the host, but it is something the analyst has to act on.
        """
        col = self.col
        mounts = getattr(col, "mounts", None) or []
        volumes = getattr(col, "volumes", None) or []
        if mounts:
            self.add("INFO", "Collection", "Disk image read directly",
                     "The filesystem was read from the image rather than from "
                     "a collection: every path below is a path on the host, "
                     "and the bodyfile was built from the inodes, so it "
                     "carries creation times and deleted entries that a "
                     "collected one does not.",
                     evidence=["%s  %s on %s" % (point, fs.describe(), vol.name)
                               for point, vol, fs in mounts],
                     source=os.path.basename(getattr(col, "path", "") or "disk"),
                     count=len(mounts))
        unread = [v for v in volumes
                  if not any(v is mv for _p, mv, _f in mounts)
                  and getattr(v, "fstype", "") not in ("", "lvm2-pv")]
        locked = [v for v in unread if getattr(v, "fstype", "") == "luks"]
        if locked:
            self.add("MEDIUM", "Collection", "Encrypted volume not examined",
                     "A LUKS container on this disk was identified and could "
                     "not be opened. Whatever is on it has not been looked at "
                     "by any check in this report. Unlock it with cryptsetup "
                     "and run linsight against the mapped device.",
                     evidence=[v.describe() for v in locked],
                     source="disk", count=len(locked))
        other = [v for v in unread if v not in locked]
        if other:
            self.add("MEDIUM", "Collection", "Volume present but not parsed",
                     "These volumes hold a filesystem this tool does not "
                     "read. They were not examined, which is not the same as "
                     "their being empty.",
                     evidence=[v.describe() for v in other],
                     source="disk", count=len(other))
        for note in getattr(col, "notes", None) or []:
            if "cap was reached" in note or "stopped at" in note:
                self.add("HIGH", "Collection", "The disk walk was truncated",
                         "Not every file on this disk was read, so an absence "
                         "below is not evidence of absence.",
                         evidence=[note], source="disk")

    def _events_from_findings(self):
        """Put every dated finding on the timeline.

        The timeline used to be built only from the nine analyzers that call
        event() directly, so a collection could carry four CRITICAL findings -
        every one of them dated - and a TIMELINE holding no CRITICAL row at
        all. Isolating CRITICAL in the console then emptied the timeline
        instead of showing the four moments the whole analysis was about, and
        the promise the header chips make - that a technique cell, a timeline
        column and a findings row all count the same set - was false.

        A finding that knows when it happened is a timeline entry by
        definition. The raw events around it are the context; the conclusion
        is the point, and it belongs on the same clock.

        One row at first_seen, not two: a finding spanning October to December
        is one conclusion with a window, and drawing it again at last_seen
        would double every multi-occurrence finding in the chart. The span
        itself is already on the finding, which is where a reader asks for it.
        """
        for f in self.findings:
            if not f.first_seen:
                continue
            try:
                ts = datetime.strptime(f.first_seen, "%Y-%m-%d %H:%M:%S")
            except (ValueError, TypeError):
                continue
            # aware, like every other event: the sort below compares them and
            # one naive stamp in the list raises rather than mis-ordering
            self.events.append(Event(ts.replace(tzinfo=timezone.utc), f.category,
                                     f.title, f.severity, f.source or "(finding)"))

    def ioc(self, value, why, source="", when=""):
        """Record an indicator, why it is one, and the artifact it came from.

        These are two different facts and used to be one argument. `why` is a
        provenance label - 'failed authentication source', 'outbound admin
        protocol' - and is the only thing that knows why a string is in the
        list at all, which is also what IOC_TECHNIQUES keys on. `source` is
        the artifact it was read out of, which is where an analyst goes to
        see it in context. `when` is the time on the row that produced it.

        Counting here rather than in a sweep is the difference between a
        table that answers 'how often, and between when and when' on every
        run and one that answers it only when asked to spend twenty minutes
        re-reading the whole collection. The analyzer is already standing on
        the row: it knows it has seen this address once more, and it knows
        what time that row carries. --count-iocs still measures every
        mention anywhere, which is a wider question and a much slower one -
        those land in the sweep_ columns, next to these rather than instead
        of them.

        Half the callers passed a label and half passed a path, so the why
        column of IOCS read '/var/log/auth.log' for every address any log
        analyzer extracted. That is not why anything is an indicator, it
        duplicated a column that already existed, and because it matched no
        entry in IOC_TECHNIQUES it silently emptied the technique column for
        exactly the indicators most worth mapping - every brute-force source
        on the host among them.
        """
        if value:
            self.iocs[value].add(why)
            if source:
                self.ioc_sources[value].add(source)
            self.ioc_count[value] += 1
            span_add(self.ioc_span[value], when)

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

    def host_identity(self):
        """Host identity read off the filesystem copy itself.

        For the inputs whose own metadata carries it, this changes nothing:
        uac.log states the hostname outright and a Velociraptor collection
        has it recovered from its artifacts. But those are the only two
        things analyze_collection() knows how to read, and a disk image, an
        AD1 and a plain directory tree are none of them - so every disk
        report named its host 'collection' while /etc/hostname sat in the
        evidence, unread, and every syslog line in the export carried the
        name in its second field.
        """
        if self.meta.get("Hostname"):
            return
        rel = self.col.rootfs("/etc/hostname")
        txt = (self.col.text(rel) or "").strip() if rel else ""
        if txt:
            self.meta["Hostname"] = txt.splitlines()[0].strip()

    def analyze_collection(self):
        if self.col.layout == "velociraptor":
            self.analyze_velociraptor_collection()
            self.host_identity()
            return
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
                self.tz_source = "uac.log"
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
        # a disk or an AD1 has no uac.log at all, so none of the above ran
        self.host_identity()
        if last_ts:
            self.collection_time = last_ts
            self.meta["Collection started"] = (
                first_ts.strftime("%Y-%m-%d %H:%M:%S UTC") if first_ts else "")
            self.meta["Collection finished"] = last_ts.strftime("%Y-%m-%d %H:%M:%S UTC")
            # said with its source, the same way every other offset in this
            # report is - the collector's own statement of what the host's
            # clock was doing is the strongest one there is, and worth naming
            self.meta["Host UTC offset"] = "%+03d:%02d (from uac.log)" % (
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

        if not self.collection_time:
            # --file: no uac.log, no `date` capture, and a syslog stamp
            # carries no year - so without an anchor every 'Nov 11 03:02:14'
            # collapses onto 1900 and the timeline is worthless. The newest
            # mtime of the files handed over is the best statement available
            # of when this evidence was current, and saying which anchor was
            # used matters more than the anchor itself.
            hint = getattr(self.col, "time_hint", None)
            if hint:
                self.collection_time = hint
                # a disk image says which anchor it used and why; --file has
                # no such statement to make, so it keeps the wording it had
                note = getattr(self.col, "time_hint_note", "") or (
                    "newest mtime of the files given with --file - no "
                    "collection metadata to date this run")
                self.meta["Collection finished"] = (
                    hint.strftime("%Y-%m-%d %H:%M:%S UTC") + " (%s)" % note)

        if "Host UTC offset" not in self.meta:
            # said out loud, the same way the Velociraptor path does: uac.log is
            # where a UAC collection states its offset, and without one every
            # host-local stamp below is being read as UTC
            self.meta["Host UTC offset"] = ("unknown - uac.log carried none, "
                                            "host-local log stamps read as UTC")

        # a disk image describes itself: the container, the partitioning, the
        # volumes found and the ones that could not be opened. These are facts
        # about the evidence and belong in METADATA next to the collection's
        # own, not only in the log of a run nobody kept
        meta_rows = getattr(self.col, "meta_rows", None)
        if callable(meta_rows):
            for key, value in meta_rows().items():
                self.meta[key] = value
            self._disk_findings()

        routed = getattr(self.col, "routed", None)
        if routed:
            # Routing is a guess from a filename, and a wrong guess is a file
            # parsed as the wrong artifact. It belongs in the report next to
            # the findings it produced, not only on the terminal of whoever
            # ran it.
            self.meta["Loose files"] = "%d routed by --file" % len(routed)
            self.add("INFO", "Collection", "Artifacts routed from loose files",
                     "No collection was parsed: these files were mounted at "
                     "the paths the extractors look for, chosen from each "
                     "file's name unless the command line said otherwise. A "
                     "file identified as the wrong artifact is parsed as the "
                     "wrong artifact - check this list before relying on "
                     "anything below it.",
                     ["%-38s -> %-34s (%s)"
                      % (os.path.basename(src), self.col.host_path(member), how)
                      for src, member, how in routed],
                     source="--file", count=len(routed))
        skipped = getattr(self.col, "skipped", None)
        if skipped:
            self.add("LOW", "Collection", "Loose files that could not be identified",
                     "These were given with --file and not parsed: nothing in "
                     "the name matched a known artifact and the contents are "
                     "not text, so there is no destination that would not be "
                     "a guess. Pass 'path:/host/path' to say what one is.",
                     ["%-38s %s" % (os.path.basename(src), why)
                      for src, why in skipped],
                     source="--file", count=len(skipped))

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

        log_ts() rather than norm_log_ts(): a year-less syslog stamp needs the
        collection year AND the roll-back when that lands it in the future.
        Calling norm_log_ts directly took the hint and skipped the roll-back,
        so a January collection read every December line in auth.log.1 as
        eleven months from now - and the failed-login window, which is the one
        thing this function feeds, was built out of those dates.
        """
        s = self.log_ts(text)
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
                self.ioc(ip, "failed authentication source", "", times[0].strftime("%Y-%m-%d %H:%M:%S") if times else "")
            if len(users) >= self.SPRAY_USER_THRESHOLD:
                spray.append(line)
                spray_ts.extend(times)
                self.ioc(ip, "password spraying source", "", times[0].strftime("%Y-%m-%d %H:%M:%S") if times else "")
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

        named = [m for m in lsmod if ROOTKIT_RE.search(m)]
        named += [d for d in sys_modules if ROOTKIT_RE.search(d)]
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
                       ROOTKIT_RE.search(b)]
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
    #: What "timestomped" means when it is a fact rather than a suspicion.
    #:
    #: Three of the four Linux timestamps can be written from userspace:
    #: utimensat sets atime and mtime to any value a caller likes, and crtime
    #: is only ever as good as the filesystem that recorded it. ctime cannot
    #: be - the kernel stamps it on every inode change and exposes no
    #: interface to set it - and that asymmetry is what turns the comparisons
    #: below into evidence rather than opinion. A forged stamp is not a value
    #: that looks wrong on its own; it is a set of values that cannot all be
    #: true at once.
    #:
    #: Which is also why this splits in two. Forward-dating breaks an
    #: invariant - the same pair the AD1 reader leans on to identify its
    #: unlabelled timestamp attributes, ctime >= mtime and crtime <= ctime -
    #: so it is provable from the inode alone and needs no window, no
    #: baseline and no corroboration. Backdating breaks nothing: "mtime much
    #: older than ctime" is equally what every dpkg install, cp -p, tar -p
    #: and rsync -t leaves behind, and on a Linux host those outnumber real
    #: timestomps by orders of magnitude. The backdating rules are therefore
    #: scoped to the incident window, demoted when they fire in bulk, and
    #: worded as leads rather than as conclusions.
    #:
    #: rule -> (severity, title, what it means, what it means at volume)
    TIMESTOMP_RULES = {
        "mtime_ahead": (
            "HIGH",
            "Content timestamp later than the last metadata change",
            "The kernel sets ctime every time it sets mtime, so on a "
            "filesystem nobody has edited ctime is never earlier than mtime. "
            "An mtime later than its own ctime means mtime was written "
            "directly - touch -d, utimensat, or a stomper - to a moment after "
            "the write it claims to describe. Nothing done through the normal "
            "file interface produces this.",
            "At this volume the host's clock stepped backwards, or the tree "
            "was restored with its mtimes preserved and its metadata rewritten "
            "afterwards. Both produce this on thousands of files at once; a "
            "targeted timestomp does not."),
        "pre_creation": (
            "HIGH",
            "Metadata changed before the file was created",
            "crtime is when the inode came into existence and ctime is the "
            "last time anything about it changed, so ctime cannot precede "
            "crtime. When it does, one of the two was written into the inode "
            "from outside the filesystem's own bookkeeping - debugfs, a raw "
            "image edit, or a stomper that set crtime and did not think about "
            "ctime.",
            "This many means the crtime column itself is unreliable on this "
            "image - a filesystem that does not record creation times, or a "
            "collector that filled the field with something else - rather "
            "than that every file was edited."),
        "new_file_old_mtime": (
            "MEDIUM",
            "Created inside the incident window, timestamped long before it",
            "The file was created during the window and claims an mtime from "
            "long before it. That is the backdating case, and crtime is what "
            "gives it away: the content date can be forged, the moment the "
            "inode was allocated is much harder to. Confirm against the "
            "package database before calling it - dpkg and rpm preserve the "
            "package's build date as mtime and create the file at install "
            "time, which looks identical.",
            "A run this size is an install or an upgrade writing its own "
            "build dates across the tree, not a file someone backdated. "
            "Narrow --window past it, or read PACKAGE_HISTORY for the session "
            "that caused it."),
        "minute_aligned": (
            "MEDIUM",
            "Access and content timestamps set to an exact minute",
            "atime and mtime are identical and land exactly on a minute "
            "boundary while ctime does not. That is the shape `touch -t "
            "YYYYMMDDhhmm` leaves: it writes both stamps to the value given, "
            "which carries no seconds, and cannot touch ctime at all. A "
            "genuine write lands on an arbitrary second - one in sixty of "
            "them by chance.",
            "At this volume it is a build system stamping its output to a "
            "fixed date, or an archive unpacked with minute-resolution times, "
            "rather than a file someone re-dated by hand."),
        "stamp_missing": (
            "MEDIUM",
            "File with its content or metadata timestamp zeroed",
            "The inode carries times, but the one named here is zero. A live "
            "filesystem does not leave mtime or ctime unset on a regular "
            "file; a wiper that could not set a convincing date and settled "
            "for none does.",
            "This many is a collector or a filesystem that did not record the "
            "field at all - check whether the column is empty everywhere "
            "before reading anything into it."),
    }
    TIMESTOMP_SKEW = timedelta(seconds=2)     # bodyfile rounding, coarse clocks
    TIMESTOMP_BACKDATE = timedelta(days=180)  # a gap that stops being a build date
    TIMESTOMP_BULK = 200        # above this the cause is systemic, not targeted
    TIMESTOMP_ROW_CAP = 5000    # rows kept per rule; the count stays exact

    @staticmethod
    def _stomp_gap(delta):
        """A timedelta as the coarsest unit that still says something."""
        secs = abs(int(delta.total_seconds()))
        if secs >= 172800:
            return "%d days" % (secs // 86400)
        if secs >= 7200:
            return "%dh" % (secs // 3600)
        if secs >= 120:
            return "%dm" % (secs // 60)
        return "%ds" % secs

    def _timestomp(self, path, mode, inode, uid, size,
                   atime, mtime, ctime, crtime, ws):
        """Score one bodyfile entry against every timestamp rule.

        Called for every regular file rather than for a pre-narrowed subset,
        because there is nothing to narrow on: the whole test is this file's
        four clocks compared against each other, and a forged stamp announces
        itself nowhere else. That is one call and a handful of datetime
        comparisons per entry, which over a bodyfile of a few hundred thousand
        lines costs a fraction of a second - against a check that cannot be
        run afterwards, because the console gets whole seconds and the answer
        lives in the inode.

        Counts stay exact while the retained rows are capped: a host whose
        clock stepped backwards fails a rule on every file it has, and the
        number is the interesting part of that answer rather than the list.
        """
        rows, n = self.timestomp["rows"], self.timestomp["n"]

        def flag(rule, note):
            n[rule] += 1
            if len(rows[rule]) < self.TIMESTOMP_ROW_CAP:
                rows[rule].append((path, mode, uid, size, inode,
                                   atime, mtime, ctime, crtime, note))

        if mtime and ctime:
            if ctime < mtime - self.TIMESTOMP_SKEW:
                flag("mtime_ahead", "mtime is %s ahead of ctime (m=%s c=%s)"
                     % (self._stomp_gap(mtime - ctime),
                        _ts_text(mtime), _ts_text(ctime)))
            if atime and atime == mtime and atime != ctime \
                    and atime.second == 0 and ctime.second != 0:
                flag("minute_aligned", "a=m=%s exactly, ctime %s"
                     % (_ts_text(mtime), _ts_text(ctime)))
        elif atime or mtime or ctime or crtime:
            flag("stamp_missing", "%s zero (a=%s m=%s c=%s b=%s)"
                 % ("mtime and ctime" if not (mtime or ctime)
                    else "mtime" if not mtime else "ctime",
                    _ts_text(atime) or "-", _ts_text(mtime) or "-",
                    _ts_text(ctime) or "-", _ts_text(crtime) or "-"))

        if crtime:
            if ctime and ctime < crtime - self.TIMESTOMP_SKEW:
                flag("pre_creation", "ctime %s precedes crtime %s by %s"
                     % (_ts_text(ctime), _ts_text(crtime),
                        self._stomp_gap(crtime - ctime)))
            if self.backdated_at_creation(path, mode, mtime, crtime, ws):
                flag("new_file_old_mtime",
                     "created %s, mtime reads %s - %s earlier"
                     % (_ts_text(crtime), _ts_text(mtime),
                        self._stomp_gap(crtime - mtime)))

    def backdated_at_creation(self, path, mode, mtime, crtime, ws):
        """The new_file_old_mtime condition, written once and read twice.

        Backdating, and the only rule here that needs the window: the gap on
        its own is what a packaged file looks like, and it is the file having
        been created during the incident that makes an ancient content date
        worth reading at all.

        It is a method rather than four lines inside the scorer because the
        older bodyfile check - "mtime far older than a ctime inside the
        window" - has to be able to ask it. Both are true of a backdated
        system binary, they are framed differently, and a reader has no way to
        tell that the file named in one is the file named in the other. Where
        this rule can speak, that one stands aside; where the bodyfile carries
        no creation time, this rule cannot speak at all and the older check is
        the only handle on backdating there is.
        """
        return bool(
            ws and mtime and crtime and crtime >= ws
            and mtime < crtime - self.TIMESTOMP_BACKDATE
            and ("x" in mode[1:]
                 or path.startswith(SYSTEM_BIN_DIRS + SYSTEM_CFG_DIRS
                                    + TMPFS_DIRS)))

    #: Report order: the two provable rules first, then the corroborating ones.
    TIMESTOMP_ORDER = ("mtime_ahead", "pre_creation", "new_file_old_mtime",
                       "minute_aligned", "stamp_missing")

    def _timestomp_findings(self, src):
        """Raise one finding per rule that fired, and date it by ctime.

        ctime is the clock the forger could not set, so it is the one an entry
        goes on the timeline under. Dating a stomped file by its own mtime
        would file the finding exactly where the intruder asked for it to be
        filed, which is the opposite of the point.

        Per-file events only while a rule stays below the bulk threshold.
        Above it the cause is a clock step or a package run, and one event
        each would bury the rest of the timeline under a fact that is already
        stated once as a finding.
        """
        rows, n = self.timestomp["rows"], self.timestomp["n"]
        for rule in self.TIMESTOMP_ORDER:
            hits = rows.get(rule) or []
            if not hits:
                continue
            sev, title, detail, bulk_detail = self.TIMESTOMP_RULES[rule]
            total = n[rule]
            bulk = total > self.TIMESTOMP_BULK
            when = [r[7] or r[6] or r[8] for r in hits]
            self.add("INFO" if bulk else sev, "Anti-forensics",
                     "%s: %d file(s)" % (title, total),
                     "%s\n\n%s" % (detail, bulk_detail) if bulk else detail,
                     evidence=["%-58s %s" % (trunc(r[0], 58), r[9])
                               for r in hits[:30]],
                     source=src, mitre="T1070.006 Timestomp",
                     times=when, count=total)
            if not bulk and rule in ("mtime_ahead", "pre_creation"):
                for r in hits:
                    self.event(r[7], "Anti-forensics",
                               "%s: %s" % (title.lower(), r[0]), sev, src)

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
        stomped_in_timestomp = 0      # left to TIMESTOMP, which says it better
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

            # Timestamp forgery, on the pass we are already making. Unlike
            # everything else in this loop these rules need no window and no
            # collection time - they compare the entry against itself - so
            # they are the one part of the bodyfile analysis that still
            # answers on a collection whose clock nothing recorded.
            if is_reg:
                self._timestomp(path, mode, inode, uid, size,
                                atime, mtime, ctime, crtime, ws)

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
                    self.ioc(path, "bodyfile (executable in tmpfs)", src,
                             mtime.strftime("%Y-%m-%d %H:%M:%S")
                             if mtime else "")
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
            #
            # Unless TIMESTOMP has already said it better. Where the bodyfile
            # carries a creation time, new_file_old_mtime names the same file
            # with the stronger claim - created during the window, not merely
            # touched during it - and reporting both puts one file in front of
            # the reader twice under two descriptions, with nothing to say
            # they are the same file. Where there is no crtime that rule
            # cannot fire, and this is the only handle on backdating left.
            if is_reg and mtime and ctime and ws and ctime >= ws and \
                    path.startswith(SYSTEM_BIN_DIRS + SYSTEM_CFG_DIRS) and \
                    (ctime - mtime).days > 180:
                if self.backdated_at_creation(path, mode, mtime, crtime, ws):
                    stomped_in_timestomp += 1
                else:
                    stomped.append("%s  mtime=%s  ctime=%s  (%d days apart)" % (
                        path, mtime.strftime("%Y-%m-%d"),
                        ctime.strftime("%Y-%m-%d"), (ctime - mtime).days))
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
                      "remains when mtime is forged: ctime cannot be set from userspace.")
                     + (" %d further file(s) of this shape are in TIMESTOMP "
                        "instead, under new_file_old_mtime: they carry a "
                        "creation time inside the window, which is the "
                        "stronger statement and would otherwise be the same "
                        "file reported twice." % stomped_in_timestomp
                        if stomped_in_timestomp else ""),
                     stomped[:25], source=src, mitre="T1070.006 Timestomp",
                     times=when["stomped"], count=len(stomped))
        self._timestomp_findings(src)
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
            # see t_dev_files: a device node is not a regular file, and
            # the finding below is about regular files
            kind = self.col.member_kind(rel)
            if kind and kind != "f":
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

    #: An indicator's shape, which decides what counts as a match.
    #:
    #: A raw substring search is wrong for every one of these. '5.191.32.19'
    #: is inside '185.191.32.198', 'evil.com' is inside 'notevil.com', and a
    #: truncated hash is inside the full one - so an indicator list assembled
    #: from three feeds reports hits on addresses the host never contacted.
    #: The keyword engine has the same bug and the same fix; here the boundary
    #: has to know the shape, because what may follow an address is not what
    #: may follow a hostname.
    IOC_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
    IOC_IPV6 = re.compile(r"^[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}$", re.I)
    IOC_HASH = re.compile(r"^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$", re.I)
    IOC_DOMAIN = re.compile(
        r"^(?!-)[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63})+$", re.I)

    #: What may not sit against an indicator of each shape.
    IOC_EDGES = {
        "ipv4": ("0123456789.", "0123456789."),
        "ipv6": ("0123456789abcdef:", "0123456789abcdef:"),
        "hash": ("0123456789abcdefghijklmnopqrstuvwxyz",
                 "0123456789abcdefghijklmnopqrstuvwxyz"),
        "domain": ("abcdefghijklmnopqrstuvwxyz0123456789.-",
                   "abcdefghijklmnopqrstuvwxyz0123456789-"),
        # paths and names: the same one-sided rule the keyword engine uses -
        # an indicator may be the prefix of a longer token but not its tail
        "other": ("abcdefghijklmnopqrstuvwxyz0123456789_", ""),
    }

    @classmethod
    def ioc_kind(cls, term):
        """Which shape an indicator has, for boundary purposes."""
        t = term.strip()
        if cls.IOC_IPV4.match(t):
            return "ipv4"
        if cls.IOC_HASH.match(t):
            return "hash"
        if ":" in t and cls.IOC_IPV6.match(t):
            return "ipv6"
        if "/" not in t and cls.IOC_DOMAIN.match(t):
            return "domain"
        return "other"

    #: Defanged forms, as threat-intelligence feeds actually ship them.
    #:
    #: A feed writes 185.191.32[.]198 so that nothing downstream turns it into
    #: a link. An artifact never does. Pasting a feed straight into --pivot
    #: therefore searches for a string that cannot occur, and answers "not
    #: found" for every indicator in the list - which is the one answer a
    #: pivot must never give wrongly.
    IOC_DEFANGED = (
        ("[.]", "."), ("(.)", "."), ("{.}", "."), ("[dot]", "."),
        ("(dot)", "."), ("[:]", ":"), ("[://]", "://"), ("[at]", "@"),
        ("(at)", "@"), ("hxxps://", "https://"), ("hxxp://", "http://"),
        ("hxxps:", "https:"), ("hxxp:", "http:"),
    )

    @classmethod
    def refang_ioc(cls, term):
        """A defanged indicator as it would really appear. -> (term, changed)"""
        out = term
        for a, b in cls.IOC_DEFANGED:
            if a in out.lower():
                # case-insensitive replace, preserving the rest of the string
                out = re.sub(re.escape(a), b, out, flags=re.I)
        return out, out != term

    def _pivot_terms(self):
        """--pivot values, expanding '@file' into one term per line."""
        terms, refanged = [], 0
        for raw in self.opts.pivot or []:
            if raw.startswith("@"):
                try:
                    with open(raw[1:], encoding="utf-8", errors="replace") as fh:
                        for line in fh:
                            t = line.strip()
                            if not t or t.startswith("#"):
                                continue
                            t, changed = self.refang_ioc(t)
                            if changed:
                                refanged += 1
                            terms.append(t)
                except OSError as e:
                    self.add("MEDIUM", "Pivot", "IOC list could not be read",
                             str(e), source=raw[1:])
            else:
                t, changed = self.refang_ioc(raw)
                refanged += 1 if changed else 0
                terms.append(t)
        if refanged:
            status("[*] pivot: refanged %d defanged indicator(s)" % refanged)
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

    #: How many extracted indicators to carry into the counting pass.
    #:
    #: This is not free, which is why it is behind --count-iocs. Python's re
    #: walks an alternation branch by branch at every position, so folding
    #: thousands of indicators into the pattern multiplies the cost of the
    #: sweep - and the sweep already reads every text artifact in the
    #: collection. On a 31 GB disk image with 85,000 files that turned a four
    #: minute run into a twenty minute one, which is not a trade to make for
    #: everybody by default.
    IOC_COUNT_LIMIT = 4000

    def _ioc_terms(self, already):
        """Indicators worth counting, that are not already being pivoted on.

        Only the ones that are literal text an artifact could contain. The
        analyzers also record shorthand - 'port:8080', 'pid:1417' - which name
        a thing rather than quote one, and grepping the collection for the
        string 'pid:1417' would find nothing and report zero, which reads as
        an indicator that does not appear.
        """
        out = []
        for value in sorted(self.iocs):
            low = value.lower()
            if low in already or ":" in value[:5] and value.split(":", 1)[0] in (
                    "port", "pid"):
                continue
            if len(value) < 4:
                continue           # too short to search for without noise
            out.append(value)
            if len(out) >= self.IOC_COUNT_LIMIT:
                break
        return out

    @classmethod
    def ioc_edge_ok(cls, subject, start, end, kind):
        """Is this match a whole indicator, or the middle of a longer one?

        Called on every hit of the pivot trie. The trie is a fast candidate
        finder and stays a substring search - correcting it here rather than
        in the pattern keeps one pass over the collection, which is what makes
        a thousand-indicator list affordable at all.
        """
        before, after = cls.IOC_EDGES.get(kind, cls.IOC_EDGES["other"])
        if before and start > 0 and subject[start - 1].lower() in before:
            return False
        if after and end < len(subject) and subject[end].lower() in after:
            return False
        return True

    def sweep_terms(self, terms):
        """One pass over every text artifact, matching all terms at once.

        Returns (hits, counts, spans) keyed by the term's index, or None if
        the pattern would not compile. Shared by the --pivot findings and by
        the IOCS counting, because both ask the same question of the same
        bytes and reading the collection twice to answer it would be the most
        expensive mistake in the run.

        Every term is one alternative in one compiled pattern, so a hundred
        indicators cost one pass rather than a hundred. That is not free
        either: Python's re walks the alternation branch by branch at each
        position, so the pattern's size is a real cost on a collection with
        millions of log lines - which is why the caller decides how many
        terms are worth it rather than this deciding for them.
        """
        # One prefix tree rather than one alternation per term: the engine
        # then fails a whole subtree on the first character that does not
        # match, instead of trying every indicator at every position. With a
        # hundred addresses off the same few subnets that is the difference
        # between minutes and tens of minutes over the same bytes.
        #
        # The trie has no per-term groups, so a match is mapped back to its
        # term by the text it matched - which is why the terms are deduplicated
        # case-insensitively before they get here.
        index, kinds = {}, {}
        for i, t in enumerate(terms):
            index.setdefault(t.lower(), i)
            kinds[i] = self.ioc_kind(t)
        try:
            rx = re.compile(trie_pattern(terms), re.I)
        except re.error as e:
            self.add("MEDIUM", "Pivot", "Indicator list could not be compiled",
                     str(e))
            return None
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
            # The name is evidence too. Samba writes one log per client as
            # /var/log/samba/log.10.198.11.107, and an indicator that appears
            # only in a path was counted as appearing nowhere - which reads as
            # an address this host never talked to, on a host that kept a
            # whole logfile for it.
            mp = rx.search(host)
            if mp:
                idx = index.get(mp.group(0).lower())
                if idx is not None and not self.ioc_edge_ok(
                        host, mp.start(), mp.end(), kinds.get(idx, "other")):
                    idx = None
                if idx is not None:
                    counts[idx][host] += 1
                    if len(hits[idx]) < 60:
                        hits[idx].append((host, 0,
                                          "(named by the artifact path)"))
            raw = decompress_bytes(rel, self.col.read_bytes(rel))
            if raw is None:
                continue
            if b"\x00" in raw[:4096]:             # binary, not worth grepping
                continue
            # One scan of the whole artifact, not one call per line. The
            # per-line form made a Python-level regex call for every line in
            # the collection - millions of them, almost all matching nothing -
            # and with a hundred indicators in the alternation that dominated
            # the entire run. finditer walks the buffer in C and only comes
            # back for the matches, which are rare; the line number and the
            # line text are then worked out for those alone.
            text = raw.decode("utf-8", "replace")
            newlines = None
            for m in rx.finditer(text):
                idx = index.get(m.group(0).lower())
                if idx is None:
                    continue
                if not self.ioc_edge_ok(text, m.start(), m.end(),
                                        kinds.get(idx, "other")):
                    continue
                counts[idx][host] += 1
                start = text.rfind("\n", 0, m.start()) + 1
                end = text.find("\n", m.end())
                line = text[start:end if end >= 0 else len(text)]
                # dated from every hit, not from the sixty kept for evidence:
                # a span taken over a truncated sample is a narrower window
                # than the indicator actually spans, which is the one direction
                # a pivot must not be wrong in
                span_add(spans[idx], self.log_ts(split_log_line(line)[0]))
                if len(hits[idx]) < 60 and counts[idx][host] <= 6:
                    if newlines is None:
                        newlines = _line_starts(text)
                    hits[idx].append((host, _line_of(newlines, start),
                                      trunc(line.strip(), 200)))
        return hits, counts, spans

    def count_indicators(self):
        """Measure every extracted indicator across the whole collection.

        Called after the tables are built rather than during the analysis,
        because that is the first moment the indicator list is complete: half
        of them are extracted by the table extractors, so a sweep run inside
        the analyzers would count the analyzer's own indicators and silently
        leave the rest unmeasured.

        Behind --count-iocs, because it is a second full pass over the
        artifacts and on a 31 GB image that is minutes rather than seconds.
        Without it the IOCS table still lists every indicator with its type
        and its provenance; what is missing is the count, and an empty count
        says 'not measured' rather than 'measured and found nowhere'.
        """
        terms = self._ioc_terms(set(t.lower() for t in self.pivot_stats))
        if not terms:
            return
        swept = self.sweep_terms(terms)
        if swept is None:
            return
        hits, counts, spans = swept
        for idx, term in enumerate(terms):
            if hits.get(idx):
                self.pivot_stats[term] = (sum(counts[idx].values()),
                                          spans[idx][0], spans[idx][1])
                self.pivot_artifacts[term] = sorted(counts[idx])
            else:
                # searched for, found nowhere - which is a measurement, and a
                # different answer from having not looked
                self.pivot_stats.setdefault(term, (0, "", ""))

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
        self.pivot_reported = set(terms)
        if not terms:
            return
        swept = self.sweep_terms(terms)
        if swept is None:
            return
        hits, counts, spans = swept
        self.pivot_hits = []
        found = set()
        for idx, term in enumerate(terms):
            ev = hits.get(idx)
            if not ev:
                continue
            total = sum(counts[idx].values())
            self.pivot_stats[term] = (total, spans[idx][0], spans[idx][1])
            self.pivot_artifacts[term] = sorted(counts[idx])
            for host, n, line in ev:
                self.pivot_hits.append((term, host, n, line))
            found.add(term)
            self.add("HIGH", "Pivot", "Cross-artifact hits for '%s'" % term,
                     "%d mention(s) in %d artifact(s) - the same indicator "
                     "followed through process, network, log, hash and "
                     "filesystem evidence."
                     % (total, len(counts[idx])),
                     ["%-52s :%-6d %s" % (h, n, l) for h, n, l in ev[:60]],
                     source="(%d artifacts)" % len(counts[idx]), count=total,
                     times=spans[idx])
            self.ioc(term, "pivot")

        # Say which indicators were searched for and not seen.
        #
        # A pivot that reports only its hits cannot be told apart from a pivot
        # that silently failed to read the list, mis-parsed it, or was cut off
        # by --pivot-limit. Naming the misses turns 'nothing was found' into a
        # statement about this host rather than a gap in the run.
        missed = [t for t in terms if t not in found]
        if missed:
            self.add("INFO", "Pivot",
                     "%d of %d indicator(s) not seen anywhere"
                     % (len(missed), len(terms)),
                     "Searched every text artifact in the collection, "
                     "including compressed rotations. These were not present "
                     "- which is evidence about this host, not a failed "
                     "search.",
                     [trunc(t, 120) for t in missed[:200]],
                     source="(%d searched)" % len(terms), count=len(missed))

    # -- run ----------------------------------------------------------------
    def run(self):
        steps = [
            self.analyze_collection,
            self.resolve_host_timezone,     # before anything reads a log stamp
            self.identify_distribution,     # every layout, not just one
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
        self._events_from_findings()
        self.events.sort(key=lambda e: e.ts)
        return self.findings
