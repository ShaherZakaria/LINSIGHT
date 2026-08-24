# Vendored Sigma rules

411 rules from [SigmaHQ](https://github.com/SigmaHQ/sigma), filtered to the
Linux and web-log rules this tool can actually route to a table.

```bash
python linsight.py <collection> --sigma ./sigma-rules/ --export ./parse
```

## Provenance

| | |
|---|---|
| source | `https://codeload.github.com/SigmaHQ/sigma/zip/refs/heads/master` |
| fetched | 2026-08-23 |
| considered | 4,265 rules in the upstream ruleset |
| kept here | 411 — the rest declare a product this tool builds no table for |

## Licence

These rules are **not** covered by this repository's MIT licence. They are
SigmaHQ's work, distributed under the **Detection Rule License (DRL) 1.1** —
see [SigmaHQ's LICENSE](https://github.com/SigmaHQ/sigma/blob/master/LICENSE)
and [LICENSE.Detection.Rules.md](https://github.com/SigmaHQ/sigma/blob/master/LICENSE.Detection.Rules.md).
Each rule keeps its own `author:` field; that attribution is the point and must
stay with the file.

## This snapshot goes stale

It is a copy taken on one day, kept here so an evidence workstation with no
route out still has rules to hunt with. It does not update itself. On a machine
that can reach the internet, prefer:

```bash
python linsight.py <collection> --update-sigma     # fetch current, then hunt
python linsight.py <collection> --sigma-cached     # hunt offline from cache
```

`--update-sigma` does a conditional fetch — an unchanged ruleset is a 304 and
no download — and caches into `~/.linsight/sigma`. Use `--sigma-source` to
point it at a zip you carried in by hand, and `--sigma-dir` to say where the
cache lives.

## What runs and what does not

Rules are routed by their `logsource` to the built tables — auth, journal,
auditd, processes, cron, web logs. Two tables report on the ruleset itself
after every run:

- **`RULE_ERRORS`** — rules rejected rather than half-applied. This engine
  implements a faithful subset of Sigma; a rule using `|cidr`, `|fieldref` or a
  numeric comparator is refused, because a rule that silently matches nothing
  is indistinguishable from a clean result.
- **`SIGMA_COVERAGE`** — one row per loaded rule with `applicable` and
  `why_not`, so a rule that fired nothing says why.
