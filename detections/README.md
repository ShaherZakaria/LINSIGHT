# linsight detection rules

Sigma rules written for this tool, against the tables it builds. Run them
like any other rule directory:

```bash
python linsight.py <collection|disk> --sigma ./detections/ --export ./parse
```

They are **not** a replacement for [`../sigma-rules/`](../sigma-rules), which
is a vendored snapshot of SigmaHQ. They are the rules that snapshot does not
have. Both directories can be given at once — `--sigma` is repeatable.

## Licence

These are this repository's own work and carry its MIT licence. The vendored
SigmaHQ set in `../sigma-rules/` is under the Detection Rule License 1.1 and
is kept separate for that reason. Do not mix the two directories.

## Where they came from

Written against a real intrusion — an internet-facing Apache 2.4.49 honeypot
compromised through CVE-2021-41773 within 3 h 20 min of exposure and held by
four separate crimeware families for 63 days — and validated by running them
over that host's UAC collection (2,155 files, 3.4 M parsed rows).

The starting point was a gap analysis. Against the same evidence:

| | rules | applicable | fired | matched rows |
|---|---|---|---|---|
| vendored SigmaHQ | 411 | 148 | 14 | 756 |
| this directory | 14 | 14 | 12 | 1,657 |

What the vendored set did **not** name, and these do:

- **The proxyjacking implant** — the most consequential finding on the host,
  a residential-proxy monetiser that walked the local /24, bound each
  address, and registered it with its operator. Still beaconing at
  acquisition. No upstream rule for it in any form.
- **The deleted-on-disk binary** holding an open C2 session — unlinked
  immediately after launch, running from `/tmp`, re-parented to PID 1.
  Upstream has a generic "execution from tmp" rule at `medium`; it fired
  once, on something else.
- **Traversal that actually executed.** Upstream has one `medium` rule for
  "Path Traversal Exploitation Attempts". It does not read the status code,
  so 653 confirmed unauthenticated command executions and several thousand
  refused probes are one undifferentiated number. Here they are two rules,
  `critical` and `medium`.
- **Whose crontab it is.** Upstream's "Modifying Crontab" fires on every
  `REPLACE`, including the operator's own. The rule here fires only for
  accounts that exist to run a daemon and are never administered by hand.

## The thing these rules are really about

On a host that has been investigated, most of what a name-based ruleset
flags is the **defender**. On the host these were written against, the three
loudest signals were all the operator: ~950 `pkill -9 xmrig` audit events, a
root crontab, and a successful root SSH login.

The first draft of the crimeware rule here matched the string `kinsing`
anywhere in a command line. It fired 201 times, and **every single hit was
the responder** — `egrep kinsing|kdevtmpfsi`, `rm -rf /tmp/kinsing*`, a
`statx` of each file. The malware itself never executed in the audited
window, because the operator had already made every dropped binary
zero-length and read-only.

So that rule now matches only where the name is the thing being **run** —
argv[0] of an execve, or a live process's `comm` or `exe` — and on that host
it correctly fires **zero** times. A rule that is silent when the malware is
present but neutered is telling the truth. A rule that reports the cleanup as
an infection is not.

Two rules here carry explicit `investigating` / `searching` filters for the
same reason, and say in their own `falsepositives` what that trade costs.

## Reading the output

`SIGMA_MATCHES` caps each rule at **201 matches** and then stops evaluating
it, so any rule showing 201 means "at least 201", and its `first_utc` /
`last_utc` span is a **floor, not the range**. The traversal rule below shows
a last match in November only because it stopped counting; the real last
successful exploitation was 17 minutes before the evidence was taken.

`SIGMA_COVERAGE` lists every rule that loaded and whether this collection had
anything for it to read. A rule that could not be represented faithfully is
rejected outright into `RULE_ERRORS` rather than half-applied — a rule that
silently matches nothing looks exactly like a clean result.

## The rules

| rule | level | detects |
|---|---|---|
| `apache_traversal_rce_confirmed` | critical | traversal path + interpreter + HTTP 200 — execution, not attempt |
| `apache_traversal_probe` | medium | the same traversal without the confirmed execution |
| `web_request_body_pipes_download_to_shell` | critical | curl/wget piped to a shell inside a request body or URL |
| `proxyjacking_registration_beacon` | high | `curl --interface … --data-urlencode` — enrolling the host as a proxy exit |
| `proxyjacking_blueheaven_infrastructure` | critical | the named control server, endpoints and hard-coded credential |
| `hidden_staging_directory_under_var_tmp` | high | execution from a dot-hidden tree under a world-writable path |
| `service_account_rewrites_own_crontab` | high | `REPLACE` for daemon / www-data / nginx and friends |
| `service_account_cron_downloads_to_shell` | critical | that account's cron line fetching and running a remote script |
| `deleted_binary_running_from_world_writable` | critical | live process, `exe` deleted, path under `/tmp` or `/dev/shm` |
| `webserver_account_running_interpreter` | high | the web account running a shell, downloader or interpreter |
| `commodity_linux_crimeware_names` | high | kinsing / kdevtmpfsi / xmrig / Mozi **executing** |
| `ld_preload_userland_rootkit` | critical | `/etc/ld.so.preload` or `LD_PRELOAD=` |
| `iot_and_framework_exploit_spray` | low | NETGEAR, HNAP, GPON, ThinkPHP, `_ignition`, `/.env` |
| `open_proxy_abuse_check` | medium | `CONNECT` and absolute-URI requests |

Two are silent on the host they were written against —
`commodity_linux_crimeware_names` and `ld_preload_userland_rootkit` — and
both silences are correct. They are kept because the families they name are
the ones that turn up next.

## Field names are table columns

These rules match linsight's normalised tables, so the field names are that
table's columns, not a vendor schema. `logsource` routes the rule:

| logsource | table | useful fields |
|---|---|---|
| `category: webserver` | `WEB_LOG` | `client_ip` `method` `resource` `status` `user_agent` `message` |
| `service: journald` | `JOURNAL` | `comm` `exe` `cmdline` `uid` `unit` `message` |
| `service: cron` | `VAR_LOG`, `CRON` | `process` `message`; `run_as` `command` |
| `category: process_creation` | `PROCESSES`, `PROCESS_MASTER` | `user` `exe` `args` `ppid` `start_utc` |
| `service: auth` | `AUTH_LOG`, `FAILED_LOGINS` | `user` `source_ip` `event` `result` |

`VAR_LOG` and `JOURNAL` are every log on the host in one table, so a
`service:` on those also narrows the rows to that service — `service: cron`
means the cron lines, not the whole file.

Supported modifiers: `contains` `startswith` `endswith` `re` `all` `cased`
`base64` `base64offset` `windash` `expand` `cidr`. Conditions support
`and` / `or` / `not`, parentheses, `1 of x*` and `all of them`.
