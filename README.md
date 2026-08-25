<p align="center">
  <img src="assets/logo.svg" alt="linsight" width="540">
</p>

<h1 align="center">linsight</h1>

<p align="center">
  Parse a Linux triage collection or a disk image, and surface the things worth looking at first.
</p>

Point it at a [UAC](https://github.com/tclahr/uac) or [Velociraptor](https://docs.velociraptor.app/docs/offline_triage/) offline collection, at a disk image, or at a disk, and it produces two things: a severity-ranked set of **findings**, and every interesting artifact normalised into browsable **tables**. Single file, standard library only, Python 3.8+.

```
python linsight.py ./uac-host-linux-20260324234043.tar.gz
python linsight.py ./web01.E01
```

It also reads **AD1** — the logical images FTK Imager writes. See [AD1 logical images](#ad1-logical-images).

No collection and no image? `--file` runs the same parsers over loose files — one `auth.log`, a folder of them, a copied-out `/etc`. See [Without a collection](#without-a-collection).

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

A directory that is a **mounted filesystem root** — one whose top level is
`etc/`, `var/`, `usr/` — is recognised as one and read as the host tree it is.
That is what a forensic mounter, `losetup` or a plugged-in disk gives you.

The other two kinds of input are a disk ([Disks](#disks)) and an AD1
([AD1 logical images](#ad1-logical-images)).

### Saying what the input is

What the argument is gets worked out from the thing itself. These force it,
for when that goes wrong or when you would rather be explicit — each replaces
the positional argument:

```bash
python linsight.py -d ./uac-host-linux-20260324/     # a directory
python linsight.py --archive ./collection.tar.gz     # a .tar/.tar.gz/.zip
python linsight.py --disk ./image.dd                 # a disk or device
python linsight.py --ad1 ./case.ad1                  # an FTK logical image
python linsight.py --file ./auth.log                 # loose artifacts
```

Passing two of them, or one of them plus the positional argument, is an error
rather than a silent preference — a wrong guess should become a message
naming what could not be read, not a report containing the wrong half of the
evidence.

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

## Disks

Point it at a disk image and everything above runs unchanged:

```bash
python linsight.py ./web01.dd
python linsight.py ./evidence.E01           # the whole segment set
python linsight.py ./vm.qcow2 --html report.html
sudo python linsight.py /dev/sda            # the disk still in the machine
```

This is not a second tool bolted on. A disk holds `/etc/passwd`, `/var/log/auth.log*`
and `/home/*/.bash_history` — the paths every parser here already asks for — so a
disk is a fourth backend behind the same collection interface. The 147 analyzers,
the 88 tables, Sigma and YARA, the timeline and the console all run over an image
without knowing one is involved.

Nothing is mounted, no loop device is created, no kernel driver touches the
evidence, and nothing is written to the image. On an image file it needs no root.

### What it reads

| layer | formats |
|---|---|
| container | raw/dd, split raw (`.001`/`.002`, `.aa`/`.ab`), **E01** (multi-segment, compressed), **qcow2** (v2/v3, compressed clusters, backing chains), **vmdk** (sparse, streamOptimized, 2 GB split, flat descriptors), **vhdx**, **vhd** (dynamic and fixed), and block devices (`/dev/sda`, `\\.\PhysicalDrive0`) |
| volume | MBR including the extended chain, GPT, **LVM2** (linear and striped, volume groups spanning several PVs), LUKS1/LUKS2 (identified, never opened) |
| filesystem | **ext2 / ext3 / ext4** (extent trees and indirect blocks, inline data), **XFS** v4 and v5 (shortform, block, leaf and node directories; extent and B+tree forks; bigtime and nrext64), **btrfs** (chunk tree, subvolumes, inline and compressed extents — zlib, zstd, lzo) |

Anything it recognises but cannot read faithfully — a VirtualBox VDI, an Ex01,
a differencing VHDX, a striped btrfs across several disks — fails by name and
says what would convert it. That is deliberate: a disk that quietly reads as
empty produces an examination that finds nothing, and "found nothing" is the
one answer a triage tool must never invent.

### Look before you walk

```bash
python linsight.py ./web01.E01 --list-volumes
```

```
web01.E01
  container    E01, 4 segment(s), 3216 chunk(s), 78% compressed
  size         512.0 GB (549755813888 bytes)
  partitioning gpt

  volume            scheme  type       filesystem  size      offset      label
  ----------------  ------  ---------  ----------  --------  ----------  -----
  p1                gpt     efi-system  fat        512.0 MB  1048576     EFI
  p2                gpt     linux       ext4       1.0 GB    537919488   boot
  p3                gpt     linux-lvm   lvm2-pv    510.5 GB  1611661312
  rhel/root         lvm     lvm-lv      xfs        450.0 GB
  rhel/home         lvm     lvm-lv      xfs        56.0 GB
  rhel/swap         lvm     lvm-lv      swap       4.0 GB
```

One pass over the metadata, not a walk of the filesystem — seconds on a disk
that takes twenty minutes to examine.

### Which volume gets read

The root filesystem is the one that holds `/etc`, asked of the filesystem rather
than of the partition table: `/boot` and `/` are both type `linux` in a GPT and
only one of them has `/etc/passwd` in it. Everything else `/etc/fstab` places —
matched by UUID, by label, or by device-mapper name — is mounted where the host
had it, so `/boot/grub/grub.cfg` and `/home/analyst/.bash_history` end up at the
paths the rules match on. `--disk-volume NAME` overrides the choice.

A volume that cannot be opened is a row in `DISK_LAYOUT` and a `MEDIUM` finding,
not an absence:

```
[MEDIUM] Encrypted volume not examined
    A LUKS container on this disk was identified and could not be opened.
    Whatever is on it has not been looked at by any check in this report.
      | p2 | linux-luks | luks | LUKS2 'vault', uuid 4f2c...
```

### Two things a collection cannot give you

**A real bodyfile.** It is built here from the inodes rather than parsed from one
a collector produced, so `BODYFILE` carries **crtime** on ext4, XFS v5 and btrfs.
A binary whose creation time falls inside the incident window and whose mtime
reads 2019 is a timestomp — stated, not suspected.

**Deleted files.** `DELETED_FILES` lists inodes with a deletion time and no
remaining links, recovered from the inode tables. The name is gone with the
directory entry that was overwritten, so these are dated, sized and owned rather
than named — which still answers "was something removed from `/tmp` during the
window", a question no mounted filesystem can answer at all.

And one it cannot: nothing that existed only in RAM. There is no process list on
a dead disk, no socket table, no loaded-module list. Those tables come out empty
and the report says why, rather than leaving an empty `PROCESSES` to be read as a
host that had no processes.

### A disk you have already mounted

If the image is mounted — by a forensic mounter, `losetup`, or because you are
looking at the machine itself — point `--file` at the mountpoint. A directory
whose top level looks like a host tree is mounted as it stands:

```bash
python linsight.py --file /mnt/evidence
python linsight.py --file E:```

That path costs the crtime and the deleted inodes, because those come from
reading the filesystem structures rather than from the kernel's view of them.
Read the image directly when you can.

### Scale

The walk holds one record per name, so a large disk is bounded rather than
unbounded: `--disk-max-files` stops it (default 3,000,000) and a truncated walk
becomes a `HIGH` finding, because an absence in a partial read is not evidence of
absence. `--no-deleted` skips the inode-table sweep, which is the slowest part of
loading a multi-terabyte disk.

### Testing

The disk stack is tested against images built by the tools that own the formats —
`mkfs.ext4`, `mkfs.xfs`, `mkfs.btrfs`, `sfdisk`, `qemu-img`, `ewfacquire`,
`cryptsetup` — not against images this project writes and reads back:

```bash
sh tools/mkfixtures.sh tests/fixtures        # ext2/3/4, XFS v4/v5, btrfs, LUKS, MBR/GPT
sh tools/mkcontainers.sh tests/fixtures      # E01, qcow2, vmdk, vhdx, vhd, vdi
python3 tools/mklvm.py tests/fixtures/ext4.img tests/fixtures/lvm-ext4.dd
python tests/test_disk.py                    # and --built for the shipped file
```

The first two need a Linux box: `mkfs.ext4`, `mkfs.xfs`, `mkfs.btrfs`, `sfdisk`,
`cryptsetup` for the filesystems, and `qemu-img` and `ewfacquire` for the
containers. None of them needs root — every `mkfs` here populates from a
directory, and `cryptsetup luksFormat` writes a header to a plain file.
`mklvm.py` is pure Python and runs anywhere. Whatever is missing is skipped by
name, so a partial fixture set still tests what it has.

Every container is checked byte-for-byte against the raw image it was made from,
which is the only way to prove a container reader is right rather than merely
self-consistent. Every filesystem reader has to return the same planted tree,
with the same content, modes and symlink targets. Fixtures are not committed;
anything missing is skipped by name, and a run that tests nothing fails.

The one exception is LVM: `pvcreate` needs root, so `tools/mklvm.py` writes the
LVM2 metadata from the on-disk format. That fixture covers the linear layout a
default install produces. Striped and mirrored segments are implemented against
the format and are not covered by it.

## AD1 logical images

An AD1 is what FTK Imager writes when someone acquires *files* rather than a
disk — a "Custom Content Image": give me `/etc`, `/var/log` and the home
directories off this box. Point linsight at one:

```bash
python linsight.py ./FirstHack.ad1
python linsight.py ./case.ad1 --sigma ./sigma-rules/ --export ./out
```

It is a tree of files with their metadata, which is what the collection layer
already takes, so an AD1 is a fifth backend beside directory, tar, zip and
disk. Multi-segment sets (`.ad1`, `.ad2`, … past `.ad9` into `.ad10`) are
gathered from any one of them and read as a single stream.

Three things come out of the format that a tar of the same files would not
have:

| | |
|---|---|
| **four timestamps** | atime, mtime, ctime **and crtime** per entry, so `BODYFILE` and the timeline carry creation times off a logical image the same way they do off a disk |
| **stored hashes** | FTK records an MD5 and a SHA-1 for every file as it acquires it. Those land in `FILE_HASHES` — a VT-ready hash list for the whole acquisition, with nothing else run |
| **owner and mode** | uid, gid and the mode string as the source filesystem had them, not as whatever unpacked the image left them |

### How it is verified

The stored hashes are also the answer key. Every file the reader extracts is
hashed and compared with the MD5 and SHA-1 the imager wrote beside it — a
reader with the format even slightly wrong cannot produce thousands of matching
digests. On the image this was developed against: **1,860 files, 270 MB, zero
mismatches.**

That check needs no fixture from this project. Drop any AD1 into
`tests/fixtures/` and `python tests/test_disk.py` verifies it against its own
hashes, which is how to confirm the reader handles an image it has not seen.

The format is not documented by the vendor; it was read off real images. Two
things follow. The four timestamps are unlabelled, so they were not guessed:
they are pinned by two invariants the source filesystem cannot break — `ctime
>= mtime`, since ctime updates whenever mtime does, and `crtime <= ctime`,
since a file cannot be changed before it exists. Only one assignment survives
both across a whole acquisition. And an AD1 whose version or shape this reader
has not been shown fails by name and says to export it with FTK Imager, rather
than returning a partial tree.

Encrypted AccessData images (`ADCRYPTEDFILE`) are identified and refused —
decrypt in FTK Imager first.

## Files, by what they are called

Two of the tables answer questions that need only a filename, which means they
answer them for a collection that took names and metadata but never the
contents.

### Credential material

`SENSITIVE_FILES` lists what on this host was named for a secret — private
keys and keystores, password databases, cloud and registry credentials,
`.env` files, copies of `/etc/shadow`, wallets, database dumps. Nothing is
opened; the name is the evidence, and each row says why it matched so you can
weigh it. It also becomes a finding, one per kind rather than one per file.

On a real Ubuntu workstation collection it returns 31 rows and they are almost
all real: an OpenVPN CA key and server key, client `.p12` and `.key` files,
two SSH private keys, `/etc/ppp/chap-secrets`, and an AWS VPN client's
temporary credentials.

Getting that signal needs the noise gone, so distribution and packaging paths
are excluded outright, along with the things every host has and none of which
is a secret:

| excluded | why |
|---|---|
| `/usr/share`, `/lib`, `site-packages`, `node_modules`, `vendor`, `test/` | Python ships `secrets.py`, OpenSSL ships test keys |
| `/etc/pam.d`, `/etc/apparmor.d`, `/etc/xdg` | configuration *about* authentication, not credentials |
| `/boot/grub` | the bootloader ships `password.mod` — code for handling passwords |
| `/etc/shadow-`, `/etc/passwd-`, `/etc/gshadow-` | shadow-utils' own rotation backups. A copy anywhere *else* still fires |
| `certs/`, `ca-certificates/`, `ca-trust/` | public certificates by definition — unless the path also says `private/` |

### Tool names in filenames

A downloaded tool is called `mimikatz_name.zip`, `linpeas_linux_amd64`,
`metasploit-framework`. `_` is a word character, so a ``-anchored match
cannot see the tool in any of those — and every one of them was being missed.
Path and command-line cells now match on a boundary that lets a separator, a
digit or a version sit next to the name and still refuses a letter, so
`mimikatz_name` fires and `johnson` and `cdkit` do not.

Free log text keeps the strict boundary, and the ambiguous tier — `john`,
`nmap`, `empire`, `beacon` — keeps it everywhere. Loosening a word that is
also a word is how a wordlist directory becomes a page of findings.

The sweep also reads the collection's own file list now. `BODYFILE` needs a
collector that produced one and `SUID_SGID` needs a survey that ran, so on a
collection with neither — and on loose files — a tool sitting on disk under
its own name was named nowhere the sweep looked.

### Times on every file

`FILE_INVENTORY` carries `mtime_utc`, `atime_utc`, `ctime_utc`, `crtime_utc`
and a `time_source` saying what they mean, because that differs:

| `time_source` | |
|---|---|
| `filesystem` | read from the inode by the disk backend — all four |
| `the AD1's recorded metadata` | as FTK recorded them at acquisition — all four |
| `bodyfile` | the host's own mtime, from the bodyfile the collector produced |
| `archive` | the mtime preserved into the tar or zip — the host's, when it was collected with the flags to keep it |
| `collected file` | the extracted copy's own mtime, and the weakest of the five |

## Which time zone

Almost every Linux log timestamp is local with no zone on it. `Mar 24
22:14:44` is a fact about a clock; turning it into a fact about a *moment*
needs the offset that clock was running at. An hour wrong here is an hour
wrong in every correlation the report supports — against the firewall, against
the EDR, against the interview.

So it is established for every collection, and recorded with its source:

```
  host offset    : +01:00 (from /etc/localtime)
  time zone      : Europe/Berlin (+01:00)
```

| key | |
|---|---|
| `Time zone` | `Europe/Berlin (+01:00)` |
| `Time zone source` | the file it was read from |
| `Host UTC offset` | the offset, and what stated it |
| `Time zone note` | only when the sources disagree |

Sources, best first: `timedatectl` output, `/etc/timezone`,
`/etc/sysconfig/clock`, `/etc/localtime`, and the host's own `date`.

Two of those are worth spelling out.

**`/etc/localtime` is the compiled zone**, so it answers the question that
actually matters — what offset was this host running at *then* — across
daylight saving, which no single recorded number can. The TZif reader handles
v1 and the 64-bit v2 block behind it, and returns Berlin as `+01:00` in January
and `+02:00` in July.

**`/etc/localtime` is also a symlink** into `/usr/share/zoneinfo`, and a disk
or AD1 backend hands a symlink's target back as its content — so the target
*is* the zone name. That is how a host that never wrote `/etc/timezone` still
gets named.

A collector that stated its own offset keeps it: `uac.log` and the Velociraptor
context record what the host's clock was doing at the moment of collection,
which beats anything reconstructed afterwards. The zone name is filled in
regardless, because an offset alone cannot say whether a log line from six
months earlier was written on summer time.

When they disagree, that is a line in the report rather than a silent pick —
`/etc/localtime` compiled at one offset while the zone name resolves to
another is what a host whose zone was changed after the logs were written
looks like. And when nothing records it at all, that is a `MEDIUM` finding,
because the alternative is a timeline that agrees with itself and disagrees
with every other source.

## Which distribution

Every run establishes what the host was, and says how it knows. It lands in
`METADATA`, on the console header, and as an `INFO` finding carrying every
source that had an opinion:

```
  distribution   : Kali GNU/Linux 2017.1 (kali-rolling)
  kernel         : 4.13.0-kali1-amd64 (from /boot)
```

| key | |
|---|---|
| `Distribution` | `Ubuntu 24.04.3 LTS` |
| `Distribution family` | `debian` — which decides whether auth went to `auth.log` or `secure`, and whether package history is `dpkg.log` or `yum.log` |
| `Distribution version` | `24.04` |
| `Distribution source` | the file it was believed from, and what that file was |
| `Kernel release` | recovered from `uname` output, `/proc/version`, or the filenames under `/boot` |

`/etc/os-release` would make this a six-line feature. It is not enough on its
own, and each fallback below exists because a real case needed it:

- a **pre-2014 host** has no `os-release`, only `/etc/redhat-release` and
  friends — RHEL 6 is still in cases
- a **UAC collection** may not contain it at all. On the Ubuntu collection this
  was tested against, `/etc/os-release` is a symlink that was not followed, and
  `/etc/lsb-release` answered instead
- a **logical image often has no `/etc`**. The AD1 above holds `/boot`, `/root`
  and `/var` — and still says Kali, from the `lsb-release` the installer left in
  `/var/log`, the kernel filename under `/boot`, and `dpkg.log`
- a **profile that ran only `uname -n`** records a hostname and no kernel
  version; the kernel is then recovered from `/boot/config-*` or
  `/boot/initrd.img-*`, which are named after it

### When the sources disagree

They are all collected, not just the first one that answers, and a
disagreement between *strong* sources — `os-release`, a release file, the
package database, a distribution-stamped kernel — is a `MEDIUM` finding:

```
[MEDIUM] Distribution evidence disagrees
    That is what a container image read as a host, a chroot, a rescue mount
    or an edited os-release looks like - and until it is resolved, every path
    in this report may belong to a different system than the one you think
    you are reading.
```

Weak sources never raise one. A stray `/etc/yum.conf` or an `alien` install on
a Debian box is not a Red Hat machine, and a `-amd64` kernel suffix names a
flavour rather than a product — so those support an answer and can never
contradict one. A false alarm about tampering is worse than silence.

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
instead. Short version: linsight reads the same three inputs an incident
actually arrives as — a triage collection, a disk, or a handful of loose files —
and ranks what it finds. Dissect remains the deeper filesystem toolkit and the
one to reach for on formats linsight refuses; Plaso builds the exhaustive
supertimeline. Neither parses the `live_response/` command output, which is
where the volatile half of a UAC collection lives.

## Caveats

- Linux only. Windows and macOS artifacts are not parsed, and an NTFS or APFS volume on a disk is named in `DISK_LAYOUT` and left unread. An AD1 of a Windows host will mount and its files will be listed, but almost nothing in it has a parser here.
- On a disk, only what survives a shutdown is there. Process, socket and module tables come out empty; the report says so.
- Findings are leads, not verdicts. Every one names the artifact it came from; confirm against the evidence before acting on it.
- A full export of a mid-size collection is hundreds of MB of CSV. Use `--scope` or `--csv-dir` with a narrower need if you do not want all of it.

## License

MIT — see [LICENSE](LICENSE).
