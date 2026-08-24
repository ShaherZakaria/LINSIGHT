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

89 artifact types normalised into one grid each — processes, sockets, open files, cron, systemd units, auth log, journal, shell history, packages, persistence, the bodyfile, and so on. Every row keeps a `source` column naming the file it was parsed from.

```bash
python linsight.py ./coll --export ./out       # csv/ + json/ + browser.html
python linsight.py ./coll --csv-dir ./tables   # just the CSVs
python linsight.py ./coll --tables-html b.html # just the HTML browser
python linsight.py ./coll --process-map p.csv  # only the merged process table
```

`--scope` narrows the table build to half the collection:

- `live` — the volatile snapshot: process table, sockets, open files, loaded modules, live sessions
- `offline` — what a dead-box exam recovers: filesystem copy, config, logs, persistence, bodyfile
- `full` — both (default)

Findings and the timeline always run over the whole collection; they exist to correlate across the two halves, so narrowing them would cost answers rather than time.

### 3. The GUI

`--html` writes a document. `--gui` writes a console to work the case in — one self-contained page, no server, no network, nothing to install.

```bash
python linsight.py ./coll --gui case.html
```

| view | what it is for |
|---|---|
| **Overview** | severity cards, activity over the collection's span, the loudest categories, techniques and artifacts — every bar is a click through to the findings behind it |
| **Findings** | the ranked list beside a detail pane: filter by severity, category, technique or free text; the search covers evidence lines, not just titles |
| **ATT&CK** | the techniques the findings actually carry, laid out by tactic and coloured by the worst severity in each cell; click a technique to filter the findings to it |
| **Timeline** | the merged event timeline, severity-filtered and searchable |
| **Indicators** | every indicator observed and which artifacts mentioned it |

The severity chips in the header filter every view at once, so a technique cell counts what the chips are showing. `alt`-click a chip to isolate one severity. `1`–`5` switch views, `/` focuses the search box, `j`/`k` walk the finding list.

It carries the triage picture only — the 89 artifact tables stay in the `--export` browser, because folding a few million rows into this page would cost the instant open that makes it worth having.

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

A rule the engine cannot represent faithfully is **rejected** and listed in `RULE_ERRORS` rather than half-applied — a rule that silently matches nothing looks exactly like a clean result.

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
