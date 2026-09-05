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

Three investigations of two hosts, in three forms of evidence:

| host | evidence | what it was |
|---|---|---|
| `ApacheWebServer` | UAC collection, 2,155 files, 3.4 M rows | Apache 2.4.49 honeypot on Ubuntu 18.04, taken through CVE-2021-41773 within 3 h 20 min of exposure and held by four crimeware families for 63 days |
| `ApacheWebServer` | the 32 GB VHD behind that collection | the same host as a disk: full `kern.log` history, 506 K web-log rows, 53 K deleted inodes |
| `VulnOSv2` | 1.1 GB E01 | Ubuntu 14.04 web server, SSH brute-forced into a service account and escalated to root in seventeen minutes |

The first fourteen rules came out of the collection. The next seven came out
of the two disk images, and could not have been written from the collection
alone — a UAC collection is what the host agreed to hand over, and both disks
carried log history and account evidence the collection never reached.

The remaining eighteen are **web exploitation** and **Linux exploitation**,
and they split in two. Four of the web rules are from the same evidence as the
rest. Fourteen are not: they were written from CISA KEV entries, vendor
advisories and published family analysis, for vulnerabilities and implants
that never touched either of these hosts — because a ruleset that only knows
the two intrusions it was born from is a ruleset that finds those two
intrusions. Every rule says which kind it is in its own `description`, and the
[advisory-derived section](#rules-written-from-advisories-not-from-this-evidence)
below lists them and says what "validated" can and cannot mean for them.

The starting point was a gap analysis. Against the same evidence:

| evidence | | rules | applicable | fired | matched rows |
|---|---|---|---|---|---|
| `ApacheWebServer` collection | vendored SigmaHQ | 411 | 148 | 14 | 756 |
| `ApacheWebServer` collection | this directory | 21 | 21 | 15 | 2,060 |
| `ApacheWebServer` disk | vendored SigmaHQ | 411 | 33 | 11 | 743 |
| `ApacheWebServer` disk | this directory | 21 | 19 | 15 | 2,101 |
| `VulnOSv2` disk | vendored SigmaHQ | 411 | 33 | 2 | 101 |
| `VulnOSv2` disk | this directory | 21 | 12 | 5 | 17 |

No rule errors on any of them.

Read the last two rows together. The vendored set returns 101 rows on
`VulnOSv2` and **not one of them is the intrusion**: 99 are "Remote File Copy"
matching `scp` inside `ACPI: Added _OSI(3.0 _SCP Extensions)` in `dmesg` and
`update-alternatives ... /usr/bin/rcp` in an install log, all from the 2016
build; the other two are SQL-injection strings in a URI. Seventeen rows that
are the intrusion beat 101 rows that are a substring accident.

Those seventeen are the whole thing and nothing else: an account created at
11:06:38, its password set at 11:09:03, sudo granted at 11:09:18, an SSH
session accepted at 11:13:53, and `su -` at 11:14:04. Nine of the twenty-one
rules are `not applicable` there because Ubuntu 14.04 has no journal — which
the coverage table says outright rather than reporting them as clean.

## What the vendored set does not name

**On the honeypot — the crimeware layer:**

- **The proxyjacking implant** — a residential-proxy monetiser that walked the
  local /24, bound each address, and registered it with its operator. Still
  beaconing at acquisition, and still walking its address list two minutes
  before the collection ran. No upstream rule for it in any form.
- **The deleted-on-disk binary** holding an open C2 session — unlinked
  immediately after launch, running from `/tmp`, re-parented to PID 1.
  Upstream has a generic "execution from tmp" rule at `medium`; it fired
  once, on something else.
- **The eviction sweep** — thirty-eight rival implants killed by name, the
  crontab wiped, the immutable bit cleared off `/etc/crontab`,
  `/var/spool/cron` and `/etc/ld.so.preload`. Upstream reads the `ld.so`
  half of that as an implant being *installed*.
- **Traversal that actually executed.** Upstream has one `medium` rule for
  "Path Traversal Exploitation Attempts". It does not read the status code,
  so confirmed unauthenticated command executions and several thousand
  refused probes are one undifferentiated number. Here they are two rules,
  `critical` and `medium`.
- **Whose crontab it is.** Upstream's "Modifying Crontab" fires on every
  `REPLACE`, including the operator's own. The rule here fires only for
  accounts that exist to run a daemon and are never administered by hand.

**On `VulnOSv2` — the account layer:**

- **A backdoor account wearing a service account's name.** Upstream has
  "Creation Of An User Account", which fires on every `useradd` a host ever
  runs. The rule here fires when one command asks for `--system`, an
  interactive shell and `-G sudo` together, which is not a service account
  being provisioned — it is a login being hidden below the uid threshold.
- **A daemon account authenticating.** `mail` is uid 8 and ships with
  `nologin`; a successful SSH session as it means the shell was changed and a
  credential was set. Upstream has no rule that reads *which* account was
  accepted.
- **A password that was piped in rather than typed.** PAM records the program:
  `passwd` is a prompt, `chpasswd` is a script. Both write the identical
  "password changed for <user>" line, and upstream matches neither.

## The thing these rules are really about

On a host that has been investigated, a name-based ruleset flags the
**defender** as readily as the intruder — and the correction runs both ways.

The first draft of the crimeware rule here matched the string `kinsing`
anywhere in a command line. It fired 201 times, and every hit was cleanup —
`egrep kinsing|kdevtmpfsi`, `rm -rf /tmp/kinsing*`, `chmod 444` and
`chown root.root` across a hundred and eighty `/tmp` paths at a time, a
`statx` of each file. That rule now matches only where the name is the thing
being **run**: argv[0] of an execve, or a live process's `comm` or `exe`.

The two evidence sets then gave that design a control and a positive, on the
same host and the same rule. In the collection's window — 20:04 to 20:28,
after everyone had arrived — every mention of `kinsing_` is argv[1..n] of an
`rm`, a `chmod`, a `chown` or a `statx`, and the rule fires **zero** times.
In the disk's window — 10:05 to 16:14, before acquisition — the same cleanup
is running *and* the rule fires **four** times, on
`EXECVE argc=1 a0="/tmp/kinsing_XAfjBpvE"` at 15:01:51 and
`/tmp/kinsing_sjPMy00N` at 15:58:46, `uid=1`, `comm=kinsing_XAfjBpv`.

Randomised name, `/tmp`, running as `daemon`. Kinsing did execute on that
host; the collection was simply taken after it had stopped. A rule that is
silent through the cleanup and fires on the execution is the whole point, and
neither half of that could have been shown from one evidence source alone.

The disk then corrected the same reasoning in the other direction. This
README previously recorded the ~950 `pkill -9 xmrig` events on that host as
the operator's cleanup. They were not. The disk shows:

- thirty-eight distinct `pkill -9` targets, each run **exactly 946 times**,
  against a hard-coded list — `java.xnj.bionic`, `meminitsrv`, `log_rotari2`,
  `suppoieup`, `gmm-est-fmllr`, `85332b232`. Nobody types those from memory;
  a responder kills `xmrig` because that is the name in the reporting.
- the same sweep in `kern.log` on **20 November through 8 December**, days
  before anyone came to look.
- `uid=1`, `cwd=/tmp` — the `daemon` account, the same one whose crontab was
  fetching `http://185.191.32.198/ap.sh`.
- `crontab -r` 947 times, interleaved.

That is a dropper making room for itself, and it is now
`rival_crimeware_eviction_sweep`. The rule deliberately does **not** match
`xmrig`, `kinsing` or `kdevtmpfsi` on their own — those belong to
`commodity_linux_crimeware_names`, for exactly the reason above. What carries
this rule is the obscurity of the names: a kill list of process names nobody
has heard of is a list compiled by someone who owns the box.

Two rules carry explicit `investigating` / `searching` filters for the same
reason, and say in their own `falsepositives` what that trade costs.

One rule here still cannot make the distinction at all.
`ld_preload_userland_rootkit` fires eight times on the disk, and every hit is
`chattr -i /etc/ld.so.preload` followed by `rm -f /etc/ld.so.preload` — the
eviction sweep tearing out a *rival's* preload rootkit. Installing the file
and destroying it name the same path, and nothing in the record separates
them, so the rule reports both and says so. That is the same failure this
README criticises upstream for, kept deliberately: the file being touched at
all is worth a critical, and a rule that guessed which direction it was going
would be guessing.

## Reading the output

`SIGMA_MATCHES` caps each rule at **201 matches** and then stops evaluating
it, so any rule showing 201 means "at least 201", and its `first_utc` /
`last_utc` span is a **floor, not the range**. Ten of the honeypot's rules
sit on that cap; their real spans run for weeks.

`SIGMA_COVERAGE` lists every rule that loaded and whether this collection had
anything for it to read. A rule that could not be represented faithfully is
rejected outright into `RULE_ERRORS` rather than half-applied — a rule that
silently matches nothing looks exactly like a clean result.

## The rules

**Web exploitation — from this evidence**

| rule | level | detects |
|---|---|---|
| `apache_traversal_rce_confirmed` | critical | traversal path + interpreter + HTTP 200 — execution, not attempt |
| `apache_traversal_probe` | medium | the same traversal without the confirmed execution |
| `web_exploit_endpoint_returned_success` | critical | a path-based vulnerable endpoint that answered 2xx |
| `web_command_parameter_executed` | critical | `?cmd=` / `?exec=` / `?shell=` answered with 2xx |
| `php_cgi_argument_injection` | high | php-cgi switches in the query string (CVE-2012-1823, CVE-2024-4577) |
| `iot_router_command_injection_dropper` | high | a router endpoint carrying a working download-and-run line |
| `web_request_body_pipes_download_to_shell` | critical | curl/wget piped to a shell inside a request body or URL |
| `web_request_carries_a_downloader` | high | wget/curl/tftp named in a request - logged in the error log, or answered 2xx in the access log |
| `web_server_executed_a_downloader` | critical | the downloader's own stderr under `AH01215` - it ran, not just arrived |
| `iot_and_framework_exploit_spray` | low | NETGEAR, HNAP, GPON, ThinkPHP, `_ignition`, `/.env`, phpunit, wls-wsat |
| `open_proxy_abuse_check` | medium | `CONNECT` and absolute-URI requests |

**Web exploitation — from advisories**

| rule | level | detects |
|---|---|---|
| `jndi_injection_log4shell` | critical | `${jndi:` and its obfuscations, in URI, UA, Referer or body |
| `java_expression_injection_ognl_spel` | high | OGNL, SpEL and `class.module.classLoader` — Confluence, Struts, Spring4Shell |
| `ssl_vpn_appliance_exploitation` | critical | Citrix, Fortinet, Pulse, Ivanti, PAN-OS pre-auth paths |
| `file_transfer_appliance_exploitation` | high | GoAnywhere, CrushFTP, Cleo, MOVEit endpoints |
| `ai_stack_unauthenticated_rce` | critical | Langflow `/api/v1/auto_login` + `/validate/code`, Ray job submission |
| `serialized_object_in_web_request` | high | `rO0AB`, `aced0005`, `gASV`, `phar://` where a value belongs |
| `cloud_metadata_ssrf` | high | `169.254.169.254` and the metadata paths, reached over HTTP |

**Implants and staging**

| rule | level | detects |
|---|---|---|
| `proxyjacking_registration_beacon` | high | `curl --interface … --data-urlencode` — enrolling the host as a proxy exit |
| `proxyjacking_blueheaven_infrastructure` | critical | the named control server, endpoints and hard-coded credential |
| `proxyjacking_target_list_worker` | high | the local loop: `mkdir .api`, `grep <addr> .api/ips.txt` |
| `rival_crimeware_eviction_sweep` | high | a hard-coded kill list of other people's implants, `crontab -r`, `chattr -i` on the persistence paths |
| `hidden_staging_directory_under_var_tmp` | high | execution from a dot-hidden tree under a world-writable path |
| `deleted_binary_running_from_world_writable` | critical | live process, `exe` deleted, path under `/tmp` or `/dev/shm` |
| `commodity_linux_crimeware_names` | high | kinsing / kdevtmpfsi / xmrig / Mozi **executing** |
| `ld_preload_userland_rootkit` | critical | `/etc/ld.so.preload` or `LD_PRELOAD=` |

**Linux exploitation and known attacks — from advisories**

| rule | level | detects |
|---|---|---|
| `pwnkit_pkexec_privilege_escalation` | critical | CVE-2021-4034 — `GCONV_PATH=`, and pkexec's own SHELL-variable line |
| `sudo_privilege_escalation_cves` | high | Baron Samedit CVE-2021-3156, CVE-2023-22809, sudo chroot CVE-2025-32463/32462 |
| `glibc_tunables_privilege_escalation` | high | Looney Tunables CVE-2023-4911 — `GLIBC_TUNABLES=` |
| `container_escape_to_host` | critical | docker.sock, `nsenter -t 1`, `release_agent`, runc `/proc/self/exe`, `chroot /host` |
| `fileless_execution_from_memfd` | high | a process whose `exe` is `/memfd:` — a binary that never touched disk |
| `modern_linux_crimeware_names` | high | perfctl, Diicot, RedTail, Hadooken, Sysrv, XorDDoS, Prometei **executing** |
| `ssh_key_and_known_hosts_harvesting` | high | private keys and `known_hosts` read together — worm lateral movement |

**Service accounts**

| rule | level | detects |
|---|---|---|
| `service_account_rewrites_own_crontab` | high | `REPLACE` for daemon / www-data / nginx and friends |
| `service_account_cron_downloads_to_shell` | critical | that account's cron line fetching and running a remote script |
| `webserver_account_running_interpreter` | high | the web account running a shell, downloader or interpreter |
| `system_account_created_with_shell_and_sudo` | critical | one `useradd` asking for `--system`, a shell and `-G sudo` |
| `service_account_added_to_privileged_group` | high | a daemon account put into sudo / wheel / docker / lxd / disk / shadow |
| `service_account_authenticated_over_ssh` | critical | sshd accepting a session for an account that ships with `nologin` |
| `service_account_escalated_via_sudo` | critical | that account then running `sudo` or `su` — including a refusal |
| `password_set_non_interactively` | medium | `chpasswd`, not `passwd` — a password piped in by a script |
| `passwordless_sudo_for_service_account` | high | a `NOPASSWD` sudoers rule whose subject is an account that runs a daemon |
| `system_account_with_interactive_login_shell` | high | a daemon account carrying a real shell in `/etc/passwd` |
| `shell_history_for_a_daemon_account` | high | a `.bash_history` somewhere that is not a human's home directory |
| `service_account_executable_in_world_writable_dir` | critical | an executable under `/tmp`, `/var/tmp` or `/dev/shm` owned by a service account |
| `sshd_permits_root_login` | medium | `PermitRootLogin` left on, or empty passwords allowed |

Four are silent on the honeypot in both its forms — the account rules, because
that host was never taken through an account: it was taken through Apache and
the intruder stayed `daemon`. Seven are silent on `VulnOSv2` for the
mirror-image reason. Neither set is dead weight; each is what the other
investigation needed.

## Rules written from advisories, not from this evidence

Fourteen rules name vulnerabilities, techniques and malware families that
never touched either host — seven web, seven Linux.
They exist because the two intrusions here are a sample of two, and a ruleset
built only from what it has already seen is a ruleset that finds what it has
already seen. They were written from CISA KEV entries, vendor advisories and
published exploit analysis, and they are marked in their own `description` as
not evidence-derived.

That marking matters, because "validated" means something weaker for them.
An evidence-derived rule is validated by firing on the thing it was written
for. These cannot be — nothing here ever sent a `${jndi:` string. What they
have instead is:

- **A negative test.** The seven web rules were run over all 510,892 web-log
  rows from both hosts — a honeypot that spent 63 days absorbing everything the
  internet throws at an open Apache — and match **zero** rows. The seven Linux
  rules were run over the journal, syslog, auth, history, process and cron
  tables of both hosts on the same basis. That is not proof they are right; it
  is proof they are quiet, which is the failure mode a rule written from a blog
  post usually has.
- **A payload test.** Each was checked against the payload or artifact strings
  in its own references, so it fires on the published form.

Treat them as a starting position rather than as tested detections. Three carry
selections that will be noisy on a host that genuinely runs the software —
`file_transfer_appliance_exploitation` on a real CrushFTP or MOVEit server,
`ssl_vpn_appliance_exploitation` on a live gateway, and `container_escape_to_host`
anywhere the Docker socket is mounted into a CI or monitoring container — and
all three say so.

The Linux set was chosen against the vendored snapshot rather than in the
abstract. SigmaHQ's Linux rules are broad on generic tradecraft — discovery,
GTFOBins, shell spawning, history tampering, steganography, even the Triple
Cross eBPF rootkit — and its "Linux HackTool Execution" rule already names
linpeas, the C2 frameworks and the web scanners. What it has no rule of any
kind for is **named local privilege-escalation CVEs**: no PwnKit, no Baron
Samedit, no Looney Tunables, no sudo chroot. Nor container escape, nor memfd
execution, nor any family newer than 2021. Those seven gaps are these seven
rules.

## Writing rules for this engine

One thing to know before adding a rule here, because it is silent when you get
it wrong: **`?` is a Sigma single-character wildcard**, not a literal question
mark. `'/shell?'` matches `/shellX` and `/shells/`. `'?cmd='` matches `xcmd=`.
Write `'/shell\?'` and `'\?cmd='`.

This is not hypothetical. `iot_and_framework_exploit_spray` shipped with
`'/shell?'` and was matching any path beginning `/shell`; the fix is what
turned up the 38 JAWS `/shell?cd+/tmp;wget...` drops the rule had been
counting as something else. Worse, a filter written as
`resource|startswith: '/?'` matches **every** path, which silently reduced
`web_exploit_endpoint_returned_success` to matching nothing at all — and a
rule that matches nothing looks exactly like a clean result.

`*` is the multi-character wildcard and needs escaping for the same reason.

## Field names are table columns

These rules match linsight's normalised tables, so the field names are that
table's columns, not a vendor schema. `logsource` routes the rule:

**What happened** — the event tables. A rule with `product: linux` and no
`service`/`category` at all runs against every one of these.

| logsource | table | useful fields |
|---|---|---|
| `category: webserver` | `WEB_LOG` | `client_ip` `method` `resource` `status` `user_agent` `message` |
| `service: journald` | `JOURNAL` | `comm` `exe` `cmdline` `uid` `unit` `message` |
| `service: cron` | `VAR_LOG`, `CRON` | `process` `message`; `run_as` `command` |
| `category: process_creation` | `PROCESSES`, `PROCESS_MASTER` | `user` `exe` `args` `ppid` `start_utc` |
| `service: auth`, `service: sshd` | `AUTH_LOG`, `FAILED_LOGINS` | `user` `source_ip` `event` `result` `message` |
| `service: sudo` | `PRIVILEGE_ACTIVITY`, `AUTH_LOG` | `event` `actor` `target_user` `target_group` `command` `tty` `working_dir` `detail` |

`VAR_LOG` and `JOURNAL` are every log on the host in one table, so a
`service:` on those also narrows the rows to that service — `service: cron`
means the cron lines, not the whole file.

`PRIVILEGE_ACTIVITY` is the one to reach for on a disk image. It merges sudo,
su, pkexec, useradd/usermod/groupadd and password changes from every log that
recorded them, into one row per event with the actor and the target split out
— which is why the `VulnOSv2` chain reads as five rules in sequence rather
than as a search through `auth.log`.

**What is on the host** — the state tables. These are **opt-in**: a rule
reaches them only by naming one of their logsources. A bare `product: linux`
rule does not, because `BODYFILE` and `FILE_INVENTORY` are a quarter of a
million rows of path names on a disk image, and a keyword rule pointed at them
both costs minutes and reports a filename as though it were an event.

| logsource | table | useful fields |
|---|---|---|
| `category: file_event` | `BODYFILE`, `FILE_INVENTORY`, `DELETED_FILES`, `SUID_SGID`, `HIDDEN_PATHS`, `SENSITIVE_FILES`, `OPEN_FILES` | `path` `mode` `owner` `uid` `size` `mtime_utc` `ctime_utc` `crtime_utc` `dtime_utc` |
| `service: user_account` | `USERS`, `GROUPS` | `username` `uid` `shell` `home` `login_capable` `password_status` `privileged_groups` `authorized_keys` |
| `service: sudoers_file` | `SUDOERS` | `file` `line_no` `rule` `nopasswd` |
| `service: ssh_config` | `SSH` | `type` `path` `owner_hint` `detail` |
| `service: etc_config` | `ETC_CONFIGS` | `path` `line_no` `text` |
| `service: web_config` | `WEB_CONFIG` | `server` `path` `enabled` `directive` `value` `text` |
| `service: init` / `profile` | `INIT_AND_PROFILE` | `path` `line_no` `text` |
| `service: package` | `PACKAGES`, `PACKAGE_HISTORY` | `name` `version` `action` `package` `commandline` `requested_by` |
| `service: editor_history` | `EDITOR_HISTORY` | `user` `tool` `kind` `value` `file` |

This is what makes a rule possible for the majority of what a disk
investigation actually finds. `/var/tmp/dk86` and `/tmp/apache-xTRhUVX` — the
dropped payloads on the two hosts here — appear in no process listing and no
log line on either image. They are rows in `BODYFILE`, and until these streams
existed, no rule in this directory could see them.

Note that `FILE_INVENTORY` prefixes its paths with the volume, as
`[root]/home/user/.bash_history`. Use `path|contains` rather than
`path|startswith` in any filter meant to work across both it and `BODYFILE`.

Supported modifiers: `contains` `startswith` `endswith` `re` `all` `cased`
`base64` `base64offset` `windash` `expand` `cidr`. Conditions support
`and` / `or` / `not`, parentheses, `1 of x*` and `all of them`.
