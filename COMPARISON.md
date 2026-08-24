# Where linsight fits

An honest placement of this tool against the alternatives, including the cases
where you should reach for something else. If a comparison table has the
author's own tool winning every row, it is marketing rather than analysis — so
the rows Dissect and Plaso win are marked as won.

## The landscape

Most "Linux DFIR tools" do not do what linsight does, so a flat feature
comparison misleads. They fall into four groups:

| group | tools | what they actually do |
|---|---|---|
| **Collectors** | UAC, Velociraptor offline collector, CyLR | Gather artifacts and stop. UAC hands you ~2,000 files; it does not analyse them. |
| **Evidence frameworks** | **Dissect**, Plaso/log2timeline → Timesketch, Autopsy / Sleuth Kit | Abstract over disk images and filesystems, then parse the files inside. Mature, tested, court-exercised. |
| **Rule engines** | Sigma backends, Zircolite, Chainsaw, Hayabusa | Run detections over structured logs. Hayabusa and Chainsaw are Windows EVTX; Zircolite handles auditd and Sysmon-for-Linux. |
| **Commercial platforms** | Cado Response, Binalyze AIR, Cyber Triage, THOR | Automated triage with ranked findings — closest in concept. Licensed, and usually want an agent or their cloud. |

## The gap linsight fills

A UAC collection has two halves:

```
uac-host-linux-20260324/
├── [root]/           the copied filesystem      <- everyone parses this
└── live_response/    the output of commands     <- nobody parses this
```

Plaso will parse `[root]/var/log/auth.log` perfectly well. It will not parse
`live_response/process/ps_-axo_pid_user_lstart_args.txt`, because that is the
text output of a command, not a log format. Neither will Dissect: its model is
*a target is an operating system with a filesystem*, and its plugins read
files from that filesystem.

Roughly half of what UAC collects is command output — `ps`, `lsof`, `netstat`,
`ss`, `lsmod`, `/proc/<pid>/*`. That is the volatile snapshot, and it is
usually where the answer is.

Linsight parses it and correlates across it. The merged process table is built
by falling back across four different `ps` spellings, then filling `exe` from
lsof, `/proc/*/maps`, the journal, argv and cgroup — whichever the profile
happened to capture.

## Head to head

| | linsight | Dissect | Plaso + Timesketch | Zircolite |
|---|---|---|---|---|
| Reads the UAC `[root]/` filesystem half | yes | yes | partial | no |
| Parses `live_response/` command output | **yes** | no | no | no |
| Disk images (E01 / VMDK / VHDX) | no | **yes — its core strength** | **yes** | no |
| Severity-ranked findings | **yes** | no, records only | no, a timeline | rule hits only |
| Sigma | built in, no install | verify current status | via plugins | **its core** |
| Install footprint | **none** | pip + dependencies | heavy | pip + dependencies |
| Usable on a sealed evidence box | **yes** | if wheels are staged | painful | if wheels are staged |
| Tests / CI / maintainer team | **none — one author** | **vendor team, tested** | **tested, 10+ years** | **tested** |
| OS coverage | Linux | **Windows, Linux, macOS, ESXi** | **broad** | logs |

## Reasons to use it

1. **It parses what nothing else parses.** The command-output half of a UAC or
   Velociraptor collection. This is a structural gap, not a marketing claim.
2. **Zero dependencies.** On a locked-down evidence workstation where you
   cannot install packages, this is decisive — it is a file copy, not a build.
3. **Time to first lead.** It returns a handful of CRITICAL findings rather
   than three million timeline rows to sort.
4. **It tells you what it did not parse.** `UNPARSED_FILES`,
   `COLLECTION_ERRORS` and `FILE_INVENTORY` account for every collected file.
   Most tools silently drop what they do not understand, which is how a clean
   result and a blind spot come to look identical.
5. **It degrades rather than dying.** Removing all 191 files under
   `live_response/process/` from a test collection costs 5 tables and 1
   finding; the run still exits 0 and the other 54 tables are byte-identical.


