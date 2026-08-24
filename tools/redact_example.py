"""Redact a uac_triage export slice for public publication.

Maps every non-private IPv4 to TEST-NET-2 (198.51.100.0/24) consistently, so
the shape of the evidence survives while the real addresses do not. MAC
addresses go to the IANA documentation range. Base64 SSH key material is
dropped. Private/loopback/reserved addresses are left alone: they identify
nothing and removing them would make the example unreadable.
"""
import csv, io, os, re, sys, ipaddress

IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
MAC  = re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b")
SSHKEY = re.compile(r"\b(AAAA[A-Za-z0-9+/]{40,}={0,2})")
# The OMS agent path carries the Azure Log Analytics workspace id, and the
# journal filenames carry the systemd machine id - both name a real tenant
# and a real host. Matched narrowly: a bare 32-hex rule would eat every MD5.
GUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                  r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
MACHINE_ID = re.compile(r"(?<=system@)[0-9a-f]{32}(?=-)")
# The console header echoes the path the run was launched from.
USERPATH = re.compile(r"[A-Za-z]:[\\/]Users[\\/][^\\/:*?\"<>|]+", re.I)

ip_map, mac_map, guid_map = {}, {}, {}

def keep(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True                      # not an address (version string etc.)
    return (a.is_private or a.is_loopback or a.is_link_local
            or a.is_multicast or a.is_unspecified or a.is_reserved)

def sub_ip(m):
    ip = m.group(0)
    if keep(ip):
        return ip
    if ip not in ip_map:
        # 198.18.0.0/15 - RFC 2544 benchmarking, non-routable, and 131k wide.
        # A /24 of TEST-NET overflows past .255 on a web log full of scanners
        # and would emit addresses that are not addresses.
        n = len(ip_map)
        ip_map[ip] = "198.%d.%d.%d" % (18 + (n >> 16), (n >> 8) & 0xFF, n & 0xFF)
    return ip_map[ip]

def sub_mac(m):
    mac = m.group(0).lower()
    if mac.startswith("00:00:00") or mac == "ff:ff:ff:ff:ff:ff":
        return m.group(0)
    if mac not in mac_map:
        mac_map[mac] = "00:00:5e:00:53:%02x" % (len(mac_map) + 1)
    return mac_map[mac]

def sub_guid(m):
    g = m.group(0).lower()
    if g not in guid_map:
        guid_map[g] = "00000000-0000-4000-8000-%012x" % (len(guid_map) + 1)
    return guid_map[g]


def redact(text):
    text = IPV4.sub(sub_ip, text)
    text = MAC.sub(sub_mac, text)
    text = SSHKEY.sub("AAAA<REDACTED-KEY-MATERIAL>", text)
    text = GUID.sub(sub_guid, text)
    text = MACHINE_ID.sub("0" * 32, text)
    text = USERPATH.sub("~", text)
    return text

def copy_text(src, dst):
    with open(src, encoding="utf-8", errors="replace") as f:
        out = redact(f.read())
    with open(dst, "w", encoding="utf-8", newline="") as f:
        f.write(out)

def copy_csv(src, dst, limit):
    """Truncate to `limit` data rows, keeping the header, then redact."""
    with open(src, encoding="utf-8", errors="replace", newline="") as f:
        r = csv.reader(f)
        rows = []
        for i, row in enumerate(r):
            if i > limit:
                break
            rows.append(row)
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerows(rows)
    with open(dst, "w", encoding="utf-8", newline="") as f:
        f.write(redact(buf.getvalue()))
    return max(0, len(rows) - 1)

if __name__ == "__main__":
    src_dir, out_dir, log_src, limit = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
    tables = sys.argv[5].split(",")
    os.makedirs(os.path.join(out_dir, "tables"), exist_ok=True)
    copy_text(log_src, os.path.join(out_dir, "findings-console.txt"))
    copy_text(os.path.join(src_dir, "findings.html"),
              os.path.join(out_dir, "findings.html"))
    kept = []
    for t in tables:
        p = os.path.join(src_dir, "csv", t + ".csv")
        if not os.path.exists(p):
            print("  missing: %s" % t); continue
        n = copy_csv(p, os.path.join(out_dir, "tables", t + ".csv"), limit)
        kept.append((t, n))
    for t, n in kept:
        print("  %-22s %5d rows" % (t, n))
    print("redacted %d public IPv4, %d MAC, %d GUID"
          % (len(ip_map), len(mac_map), len(guid_map)))
