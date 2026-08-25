# -*- coding: utf-8 -*-
from __future__ import annotations

from datetime import datetime
from datetime import timezone
import bz2
import gzip
import ipaddress
import lzma
import re
import struct




# ---------------------------------------------------------------------------
# log decoders: compressed text, utmp/lastlog, and the systemd journal
# ---------------------------------------------------------------------------







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
