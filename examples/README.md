# Example output

A real run of `linsight.py` against a UAC collection from an Ubuntu 18.04
Azure VM running Apache, collected `2021-12-08 19:15:00 UTC`.

| file | what it is |
|---|---|
| [`findings-console.txt`](findings-console.txt) | the console report, exactly as printed (`--no-color`) |
| [`findings.html`](findings.html) | the self-contained HTML report (`--html`) |
| [`tables/`](tables/) | 21 of the 70 exported tables, truncated to 300 rows each |

## What it found

```
FINDING SUMMARY
  CRITICAL   4
  HIGH      45
  MEDIUM    19
  LOW        3
  INFO       9
  TOTAL     80
```

Headlines from that run:

- 1 address authenticated successfully **after** a run of failures
- 1 process executing from a world-writable directory
- 2 processes running a **deleted** binary — the on-disk file was unlinked while the process kept running
- 198 source addresses with 10+ failed logins; 75 of them tried 5+ different accounts
- an unsigned / out-of-tree kernel module load in `dmesg`
- cross-artifact hits for `/tmp/agettyd`

`tables/00_INDEX.csv` lists all 70 tables the full export produced, so you can see
what is *not* included here.

## Scale

This slice is 1.6 MB. The full export of the same collection was **2.5 GB** —
70 tables, 3,332,933 rows — which is why only a truncated sample is committed.
Reproduce the whole thing with:

```bash
python linsight.py <collection> --export ./out --html report.html
```

## Redaction

This output has been scrubbed before publication by
[`../tools/redact_example.py`](../tools/redact_example.py). Every change it makes is
mechanical and reproducible:

| what | how |
|---|---|
| public IPv4 addresses | 2,887 distinct addresses remapped **consistently** into `198.18.0.0/15` (RFC 2544, non-routable). The same source address is the same fake address everywhere, so the correlation the findings rest on still holds |
| private / loopback / link-local / reserved addresses | **left alone** — they identify nothing, and removing them would make the example unreadable |
| Azure Log Analytics workspace ID | replaced with a placeholder GUID |
| systemd machine ID | zeroed |
| SSH public-key material | replaced with `AAAA<REDACTED-KEY-MATERIAL>` |
| the analyst's local filesystem path in the report header | replaced with `~` |
| MAC addresses | remapped to the IANA documentation range (none were present in this slice) |

What is **not** redacted: the hostname (`ApacheWebServer`), the account names
(`azureuser`, `omsagent`, and the distribution's system accounts), package
versions, and file hashes. Those are either the lab's own naming or public
reference data.

The scrub is verified rather than assumed — after generating this directory,
every file is re-scanned for public IPv4, GUIDs, key material and the original
machine ID, and the run is only accepted at zero hits.
