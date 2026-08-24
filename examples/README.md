# Example output

A real run of `linsight.py` against a UAC collection from an Ubuntu 18.04 Azure
VM running Apache, collected `2021-12-08 19:15:00 UTC`, hunted with 411 Sigma
rules.

The exact command:

```bash
python linsight.py C:\path\to\uac-ApacheWebServer-linux-20211208202503.tar \
       --sigma .\sigma-rules\ --export .\parse
```

| file | what it is |
|---|---|
| [`findings-console.txt`](findings-console.txt) | the console report, exactly as printed (`--no-color`) |
| [`findings.html`](findings.html) | the self-contained HTML findings report |
| [`browser.html`](browser.html) | the self-contained artifact browser — every table, searchable, in one page |
| [`tables/`](tables/) | 24 of the 73 exported tables, truncated to 300 rows each |

`browser.html` and `findings.html` are single files with no external assets:
download and open, no server, no network.

## What it found

```
FINDING SUMMARY
  CRITICAL    4
  HIGH       52
  MEDIUM     25
  LOW        14
  INFO        9
  TOTAL     104
```

Headlines:

- 1 address authenticated successfully **after** a run of failures
- 1 executable in a world-writable temp directory, and 1 process running from one
- 2 processes running a **deleted** binary — unlinked on disk while still executing
- 2 running executables with no corresponding file on disk
- 198 source addresses with 10+ failed logins; 75 of them tried 5+ different accounts
- an unsigned / out-of-tree kernel module load in `dmesg`

## Sigma

407 of the 411 rules loaded; the other 4 are in
[`tables/RULE_ERRORS.csv`](tables/RULE_ERRORS.csv) with the reason each was
rejected rather than silently applied. 764 matches:

| level | count | rule |
|---|---|---|
| medium | 201 | Modifying Crontab |
| low | 85 | Remote File Copy |
| low | 4 | System Network Connections Discovery - Linux |
| high | 3 | Suspicious Activity in Shell Commands |

[`tables/SIGMA_COVERAGE.csv`](tables/SIGMA_COVERAGE.csv) is the other half of
the answer: one row per rule with `applicable` and `why_not`, so a rule that
fired nothing says *why* — wrong product, no such table in this collection —
instead of looking like a clean result.

## Scale

This slice is ~11 MB, most of it `browser.html`. The full export of the same
collection was **2.5 GB** — 73 tables, 3,334,124 rows.
[`tables/00_INDEX.csv`](tables/00_INDEX.csv) lists all 73 so you can see what is
*not* included here.

## Redaction

This output is scrubbed before publication by
[`../tools/redact_example.py`](../tools/redact_example.py). Every change is
mechanical and reproducible:

| what | how |
|---|---|
| public IPv4 | 2,903 distinct addresses remapped **consistently** into `198.18.0.0/15` (RFC 2544, non-routable). The same source is the same fake address in every file, so the correlation the findings rest on still holds |
| private / loopback / link-local / reserved | **left alone** — they identify nothing, and removing them would make the example unreadable |
| Azure Log Analytics workspace ID | placeholder GUID |
| systemd machine ID | zeroed |
| SSH public-key material | `AAAA<REDACTED-KEY-MATERIAL>` |
| MAC addresses | IANA documentation range |
| the analyst's local path in the report header | `~` — including the JSON-escaped form embedded in `browser.html` |
| **Sigma rule IDs** | **kept.** They are public SigmaHQ identifiers and are how you look a rule up; scrubbing them would strip a `SIGMA_MATCHES` row of the only thing that makes it actionable |

Not redacted: the hostname (`ApacheWebServer`), account names (`azureuser`,
`omsagent`, distribution system accounts), package versions and file hashes —
lab naming or public reference data.

**The scrub is verified, not assumed.** After generating this directory every
file is re-scanned for public IPv4, the workspace GUID, the machine ID, key
material and the local path, and the result is only published at zero hits.
Run that check yourself before adding anything here — and never add an export
file through the GitHub web UI, which bypasses it entirely.
