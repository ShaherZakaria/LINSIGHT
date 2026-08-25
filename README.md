<p align="center">
  <img src="assets/logo.svg" alt="linsight" width="540">
</p>

<h1 align="center">linsight</h1>

<p align="center">
  Parse a Linux triage collection and surface the things worth looking at first.
</p>

Point it at a [UAC](https://github.com/tclahr/uac) or [Velociraptor](https://docs.velociraptor.app/docs/offline_triage/) offline collection and it produces two things: a severity-ranked set of **findings**, and every interesting artifact normalised into browsable **tables**. Single file, standard library only, Python 3.8+.

```
python linsight.py ./uac-host-linux-20260324234043.tar.gz
```

No collection? `--file` runs the same parsers over loose files — one `auth.log`, a folder of them, a copied-out `/etc`. See [Without a collection](#without-a-collection).

## Why

A UAC collection is a few thousand files of raw command output. The evidence is all there, but answering "what happened on this host" means opening `ps` output, then `netstat`, then `auth.log`, then cross-referencing PIDs by hand. This does that pass for you and tells you where to look — it does not replace the manual examination, it decides what order to do it in.

## Install

There is nothing to install. Copy `linsight.py` onto the analysis box and run it.

```bash
git clone https://github.com/ShaherZakaria/linsight.git
cd linsight
python linsight.py <collection>
```

No third-party packages are imported. PyYAML is used for Sigma rule parsing *if it happens to be importable*, and a built-in parser handles it otherwise.

## Input

Both collection layouts are detected from the collection itself, never declared:

| layout | command output | copied filesystem |
|---|---|---|
| UAC | `live_response/` | `[root]/` |
| Velociraptor | `results/*.json` | `uploads/<accessor>/` |

It reads an **extracted directory** or the **archive directly** — `.tar`, `.tar.gz`, `.zip`. Reading the archive avoids extracting a multi-GB collection twice.

## Output

### 1. Findings

The analyzers' conclusions, ranked `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO`. Each carries its category, the artifact it came from, its evidence lines, and a UTC timestamp derived from the evidence itself rather than from when you ran the tool.

```bash
python linsight.py ./coll                          # console report
python linsight.py ./coll --min-severity HIGH      # only the loud stuff
python linsight.py ./coll --html report.html       # self-contained HTML
python linsight.py ./coll --json findings.json     # machine-readable
python linsight.py ./coll --timeline timeline.csv  # merged event timeline
```

`--window H` sets the incident window used to decide what counts as "recent" (default 72 hours before collection time).

### 2. Tables

88 artifact types normalised into one grid each — processes, sockets, open files, cron, systemd units, auth log, journal, shell history, packages, persistence, the bodyfile, and so on. Every row keeps a `source` column naming the file it was parsed from.

```bash
python linsight.py ./coll --export ./out       # csv/ + json/ + browser.html
python linsight.py ./coll --csv-dir ./tables   # just the CSVs
python linsight.py ./coll --tables-html b.html # just the console (below)
python linsight.py ./coll --process-map p.csv  # only the merged process table
```

`--scope` narrows the table build to half the collection:

- `live` — the volatile snapshot: process table, sockets, open files, loaded modules, live sessions
- `offline` — what a dead-box exam recovers: filesystem copy, config, logs, persistence, bodyfile
- `full` — both (default)

Findings and the timeline always run over the whole collection; they exist to correlate across the two halves, so narrowing them would cost answers rather than time.

### 3. The console

`--html` writes a document — a page you read top to bottom and hand to someone. The **browser** is the other thing an analyst wants from the same run: a console to work the case in, where the findings, the ATT&CK coverage, the timeline and all 88 tables sit behind one nav and one set of severity chips.

```bash
python linsight.py ./coll --export ./out        # csv/ + json/ + browser.html
python linsight.py ./coll --tables-html b.html  # just the console
```

| view | what it is for |
|---|---|
| **Overview** | twelve panels: severity cards, the offensive tooling named on the host, two clocks (what the collection recorded and what the analysis raised), a day-by-hour heatmap and the same activity folded onto 24 UTC hours, the loudest categories, techniques, tactics and artifacts, what the rule engines and the pivot fired on, and the largest tables — every bar is a click through to what is behind it |
| **Findings** | the `FINDINGS` grid: sort any column, filter per column, and click a row to open its evidence, ATT&CK techniques and time span above the table |
| **ATT&CK** | the techniques the findings actually carry, laid out by tactic and coloured by the worst severity in each cell; click a technique to filter the findings to it |
| **Timeline** | the `TIMELINE` grid under a severity-stacked histogram — click a column to set the time window, shift-click another to extend it, click the lit one to let go. The chart keeps drawing the full span so you can see where the window sits. Every dated finding is on it too, at its `first_utc` and under its own severity, so isolating CRITICAL answers here with the same set the findings list does |
| **Tables** | `HACKTOOL_HITS` and `HACKTOOL_VARIANTS` pinned at the top of the nav, then the remaining artifact grids, each sortable, with a row filter and a per-column filter that combine with AND |

**Findings and Timeline *are* those tables.** There is one findings list, not a view and a table saying the same thing twice — the console half (chips, chart, evidence pane) sits on top of the same grid every other table gets, so sorting and per-column filtering work there too. Nothing is embedded twice, and the two halves have no way to disagree.

The severity chips in the header filter all of them at once, so a technique cell, a timeline column and a findings row all count the same set. `alt`-click a chip to isolate one severity.

Beside them is the **time window**. Clicking `from` or `to` opens a calendar: a month grid where **each day is shaded by how much evidence it holds**, so the three days that matter are visible before you pick one. Pick a day, set the hour and minute from the two selects beside it (`from` defaults to `00:00`, `to` to `23:59`, so a day at each end means those whole days), or take a preset — last 24h / 7d / 30d / all. Everything is UTC, like the rest of the report.

The boxes still accept typing for anyone who prefers it: `2021-12-08`, `2021-12-08 03:00`, or `-24h` / `-7d` counted back from the end of the data. Clicking a column of the activity chart sets the window too; shift-clicking another extends it. Unlike the chips it narrows *every* grid that carries a clock, not just the views — so an incident hour narrows `AUTH_LOG` and `WEB_LOG` with the findings.

It narrows what happened, never what exists. A row is only filtered when it *is* an event (`timestamp_utc`, or a finding's `first_utc`/`last_utc` span). Tables where a timestamp is an attribute of a standing thing — `USERS.last_login_utc`, `SUID_SGID.mtime_utc`, `PROCESS_MASTER.start_utc` — are left whole, because a one-hour window that deletes the account list and every suid binary is not a narrower answer. Each grid says which case it is, and how many of its rows carry no time at all.

`1`–`4` switch views, `/` focuses the row filter, `t` the time window, `j`/`k` walk the rows.

One file, no server, no network: the payload is embedded and the CSS and JS are inline, because the box that reads a triage collection is routinely the box that is not allowed to fetch anything. Open it with a double click — there is nothing to serve it from.

`--html-rows N` caps how many rows of each table the page carries (default 2000); the CSV and JSON exports always hold everything.

## Without a collection

You do not need a UAC or Velociraptor collection. `--file` parses loose files
on their own — one log, a folder of them, or a copied-out fragment of a host
tree:

```bash
python linsight.py --file /var/log/auth.log
python linsight.py --file ./loose-logs/ --file ps.txt
python linsight.py --file ./extracted/etc/passwd
python linsight.py --file capture-2311.txt:/var/log/auth.log
```

This is not a second, smaller parser. Every file is mounted at the path its
parser already looks for, and the whole pipeline then runs unchanged — the same
analyzers, the same 88 tables, Sigma and YARA, the findings, the console. A
file routed to `/var/log/auth.log` is parsed by exactly the code that parses an
auth.log out of a UAC tar, because it *is* that code.

Where a file lands is decided in this order:

| | how |
|---|---|
| `path:/host/path` | you said so — always wins |
| `etc/passwd`, `var/log/syslog` | the path it was given under already looks like a host tree |
| `auth.log`, `wtmp`, `sshd_config`, `ps.txt` | its name matches a known artifact |
| anything else that is text | `/var/log/<name>`, where `VAR_LOG` splits syslog-shaped lines and keeps the rest verbatim |
| anything else | not parsed, and listed as such |

Routing is a guess from a filename, so it is reported at load time, recorded in
`METADATA`, and raised as a finding you can read next to the ones it produced.
A wrong guess is a file parsed as the wrong artifact — and a file that only
reaches the `/var/log` fallback is parsed generically rather than by its real
parser. Both are visible rather than silent:

```
[*] --file auth.log      -> /var/log/auth.log            (name)
[*] --file capture-2311.txt -> /var/log/capture-2311.txt (text fallback)
[!] --file blob.bin skipped: not identified as a known artifact
```

Loose files carry no collection metadata, so there is nothing to date the run
with and a syslog stamp carries no year. The newest mtime of the files given is
used as the anchor, and the report says so rather than quietly picking one.

## Hunting

### Pivot on an indicator

```bash
python linsight.py ./coll --pivot /dev/shm/kit --pivot libymv.so.3
python linsight.py ./coll --pivot @iocs.txt
```

Searches every collected artifact case-insensitively. All terms are matched in one pass, so a long list costs no more than a short one. `@file` reads one indicator per line, `#` for comments.

### YARA

```bash
python linsight.py ./coll --yara ./rules/
python linsight.py ./coll --yara ./rules/ --deep   # + memory image strings
```

Scans the collected filesystem and per-process memory strings. `--deep` adds `memory_dump/*strings*`, which is slow and multi-GB.

### Sigma

```bash
python linsight.py ./coll --sigma ./my-rules/     # your own rules
python linsight.py ./coll --update-sigma          # fetch SigmaHQ, then hunt
python linsight.py ./coll --sigma-cached          # hunt offline from cache
python linsight.py --update-sigma                 # refresh the cache only
```

Rules run against the normalised tables — auth, journal, auditd, processes, cron, web logs — routed by each rule's `logsource`. `--update-sigma` keeps the Linux and web-log rules and skips the ~3000 Windows event-log ones, which could not fire here anyway. The fetch is conditional: an unchanged ruleset is a 304 and no download.

For an air-gapped examination box, `--sigma-source` takes a zip you downloaded elsewhere or a directory, and `--sigma-dir` says where the cache lives (default `~/.linsight/sigma`, or `$LINSIGHT_SIGMA_DIR`).

**`--update-sigma` is the only thing in this tool that touches the network.** Everything else is offline.

A rule the engine cannot represent faithfully is **rejected** and listed in `RULE_ERRORS` rather than half-applied — a rule that silently matches nothing looks exactly like a clean result. `|contains`, `|startswith`, `|endswith`, `|re`, `|all`, `|cased`, `|base64`, `|base64offset`, `|windash` and `|cidr` are applied; `|fieldref`, `|exists`, the numeric comparators and Sigma correlation rules are not.

### Built-in keyword sweep

An offensive-tooling keyword sweep runs by default. `--keywords file` adds case-specific terms; `--no-hunt` skips it entirely (it reads the normalised tables, so it costs the table build even when you asked for no export — roughly 12–65s on a mid-size collection).

## Design notes

**Every analyzer and every table extractor is independent and failure-tolerant.** A missing or malformed artifact degrades that one check, never the run. Removing all 191 files under `live_response/process/` from a test collection drops 5 tables and 1 finding; the run still exits 0 and the other 54 tables are byte-identical.

**Artifacts are globbed for, not named.** UAC's layout moves between profile generations — `suid`/`sgid` and the filesystem surveys live under `system/` in recent profiles and `live_response/system/` in the 2021 ones. A hardcoded path silently produces an empty table on the other profile, which reads as "this host had none of that": a wrong answer, not a missing one.

**Nothing is silently dropped.** Three tables exist to make that accounting honest rather than merely true:

| table | what it answers |
|---|---|
| `COLLECTION_ERRORS` | the `.stderr` UAC saved per command — so an absent artifact says whether the tool was missing, the command was denied, or the profile never ran it |
| `UNPARSED_FILES` | what no extractor claimed, with a reason |
| `FILE_INVENTORY` | one row per collected file, naming the table that took it |

The same rule drives Velociraptor support: which artifacts a collection holds is decided by whoever built the collector, so the artifact set is discovered from `results/` rather than assumed. An artifact with no mapping still reaches the export as its own `VELO_*` table, and `VELO_ARTIFACTS` lists every artifact found with its row count and destination.

**Timestamps are normalised to UTC** using the collected host's own clock, not the analysis box's. A collection taken on a host at UTC-04:00 dates its events correctly.

## Performance

`--low-memory` spills large tables to a temp file instead of holding every row in memory — roughly halves peak memory on a large collection, costs about 20% of the run time. `--timing` reports wall time per table extractor and per output writer, for finding which artifact a slow collection is spending its minutes on.

## Example output

[`examples/`](examples/) holds a complete, redacted run against a 2021 Apache/Azure collection hunted with 411 Sigma rules — the console report, the HTML findings report, the artifact browser, and a slice of the exported tables. It was produced by:

```bash
python linsight.py .\uac-ApacheWebServer-linux-20211208202503.tar --sigma .\sigma-rules\ --export .\parse
```

104 findings, 764 Sigma matches, 73 tables, 3,334,124 rows.

> Anything added to `examples/` must go through [`tools/redact_example.py`](tools/redact_example.py) first. A raw export carries thousands of real addresses, the host's machine ID and, on a cloud host, its tenant identifiers.

## Full options

```
python linsight.py --help
```

## Where this fits

[`COMPARISON.md`](COMPARISON.md) places linsight against Dissect, Plaso/Timesketch
and the rest — including the cases where you should reach for one of those
instead. Short version: Dissect is the better tool for the copied filesystem and
for disk images; linsight parses the `live_response/` command output that neither
Dissect nor Plaso reads, and ranks what it finds.

## Caveats

- Linux collections only. Windows/macOS artifacts are not parsed.
- Findings are leads, not verdicts. Every one names the artifact it came from; confirm against the evidence before acting on it.
- A full export of a mid-size collection is hundreds of MB of CSV. Use `--scope` or `--csv-dir` with a narrower need if you do not want all of it.

## License

MIT — see [LICENSE](LICENSE).
