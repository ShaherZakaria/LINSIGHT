# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import copy
import os
import re
import sys

from .model import SEVERITIES
from .common import human_size
from .term import status
from .collect import Collection, FilesCollection, parse_file_spec
from .image import ImageError, looks_like_disk, open_image
from .disk import DEFAULT_MAX_FILES, DiskCollection, DiskError
from .ad1 import Ad1Collection, Ad1Error, looks_like_ad1
from .volume import READABLE_FS, scan
from .rules import (
    sigma_cache_count, sigma_cache_dir, sigma_cache_manifest,
    update_sigma_rules)
from .triage import Triage
from .tables import Table, TableBuilder
from .writers import (
    _check_output_paths, console_html, export_tables, write_merged_tables)
from .serve import CaseDB, ReopenedCase, live_assets, serve
from .ask import ASK_URL, ask
from .skills import SKILLS, render
from .mcp import CaseError, _open, serve_mcp
from .correlate import (
    Correlator, HostCase, _label_for, fold_correlation, merge_tables,
    merge_triage, write_correlation)
from .report import (
    print_banner, print_console, write_html, write_json, write_timeline)



# ---------------------------------------------------------------------------


#: Files a directory can hold that are the evidence rather than part of it.
#: A folder holding one Webserver.E01 is not a collection with two files in
#: it, and reading it as one produces an empty report - which is the failure
#: this whole function exists to prevent.
CONTAINER_EXTENSIONS = (
    ".dd", ".raw", ".img", ".bin", ".e01", ".ex01", ".s01", ".001",
    ".qcow2", ".qcow", ".vmdk", ".vhdx", ".vhd", ".vdi",
    ".ad1", ".tar", ".tgz", ".zip", ".gz", ".bz2", ".xz",
)

#: How many extension-less files to sniff before giving up. A collection
#: directory holds thousands of command outputs and none of them is a disk;
#: opening every one to prove that would cost more than the whole parse.
SNIFF_LIMIT = 64


def _collection_markers(path):
    """Whether this directory is a collection, by the files a collector left.

    Asked before anything else, because a UAC collection that happens to
    contain a disk image somewhere inside it is still a UAC collection - and
    reading the image instead would throw away the live_response half that
    nothing else can parse.
    """
    for marker in ("uac.log", "live_response", "results", "uploads",
                   "collection_context.json", "uploads.json", "bodyfile"):
        if os.path.exists(os.path.join(path, marker)):
            return marker
    for entry in _listdir(path)[:200]:
        if entry.startswith("[") and entry.endswith("]"):
            return entry                  # UAC's [root] / [mountpoint]
    return ""


def _listdir(path):
    try:
        return sorted(os.listdir(path))
    except OSError:
        return []


def _containers_in(path):
    """[(kind, full path)] for the evidence containers sitting in a directory."""
    found = []
    sniffed = 0
    for name in _listdir(path):
        full = os.path.join(path, name)
        if not os.path.isfile(full):
            continue
        ext = os.path.splitext(name)[1].lower()
        known = ext in CONTAINER_EXTENSIONS
        if not known:
            if sniffed >= SNIFF_LIMIT:
                continue
            sniffed += 1
        try:
            if looks_like_ad1(full):
                found.append(("ad1", full))
                continue
            if looks_like_disk(full):
                found.append(("disk", full))
                continue
        except Exception:
            continue
        if known and ext in (".tar", ".tgz", ".zip", ".gz", ".bz2", ".xz"):
            found.append(("archive", full))
    return found


def _one_evidence_set(found):
    """Collapse the segments of one split set into the one thing they are.

    A directory holding Webserver.E01 through .E12, or image.001 through .014,
    holds one disk - and offering to read fourteen of them, or refusing
    because there are fourteen, would both be wrong.
    """
    if len(found) <= 1:
        return found
    stems = set()
    for kind, full in found:
        base = os.path.basename(full)
        stem = re.sub(r"\.(?:[eEsSlL]\d{2}|\d{3}|ad\d+|[a-z]{2})$", "", base)
        stem = re.sub(r"\.(?:dd|raw|img|bin)\.\d+$", "", stem)
        stems.add((kind, stem.lower()))
    if len(stems) == 1:
        return [sorted(found, key=lambda kv: kv[1])[0]]
    return found


def identify_input(path):
    """What to read, and why - for the plain argument, with nothing declared.

    Returns (kind, target, why). `kind` is one of 'disk', 'ad1',
    'collection' or 'files'. The reason travels with it because the analyst
    has to be able to see the decision: reading the wrong thing produces a
    report, not an error, and a report about the wrong evidence is the most
    expensive output this tool can produce.
    """
    if not os.path.exists(path) and looks_like_disk(path):
        return "disk", path, "a device path"
    if os.path.isfile(path):
        if looks_like_ad1(path):
            return "ad1", path, "an AD1 logical image header"
        if looks_like_disk(path):
            return "disk", path, "a disk container header"
        return "collection", path, "an archive"
    if not os.path.isdir(path):
        return "collection", path, ""

    marker = _collection_markers(path)
    if marker:
        return "collection", path, "a collection directory - %s is in it" % marker
    if os.path.isdir(path):
        found = _one_evidence_set(_containers_in(path))
        if len(found) == 1:
            kind, full = found[0]
            return kind, full, ("the only piece of evidence in that directory "
                                "is %s" % os.path.basename(full))
        if len(found) > 1:
            names = ", ".join(os.path.basename(f) for _k, f in found[:6])
            raise SystemExit(
                "[!] %s holds more than one piece of evidence: %s%s\n"
                "    Name the one to read, rather than have this pick:\n"
                "      python linsight.py <that file>"
                % (path, names, " ..." if len(found) > 6 else ""))
    return "collection", path, "a directory"


def list_volumes(path):
    """Print what is on a disk, and stop.

    The cheap question to ask first of an unfamiliar image: which container is
    it, how is it partitioned, what is inside the LVM, what is encrypted, and
    which volume is the one a walk would read. It costs a pass over the
    metadata rather than a walk of the filesystem, so it answers in a second
    on a disk that would take twenty minutes to examine.
    """
    try:
        image = open_image(path)
    except ImageError as exc:
        print("[!] %s" % exc, file=sys.stderr)
        return 2
    try:
        volumes, notes, scheme = scan(image)
        print("%s" % image.path)
        print("  container    %s" % image.description)
        print("  size         %s (%d bytes)"
              % (human_size(image.size), image.size))
        if len(image.parts) > 1:
            print("  segments     %d files, %s .. %s"
                  % (len(image.parts), os.path.basename(image.parts[0]),
                     os.path.basename(image.parts[-1])))
        print("  partitioning %s" % scheme)
        print("")
        head = ("volume", "scheme", "type", "filesystem", "size", "offset",
                "label")
        rows = [head]
        for vol in volumes:
            rows.append((vol.name, vol.scheme, vol.type_name or "-",
                         vol.fstype or "-", human_size(vol.size),
                         str(getattr(vol, "offset", "-")),
                         vol.label or "-"))
        widths = [max(len(r[i]) for r in rows) for i in range(len(head))]
        for i, row in enumerate(rows):
            print("  " + "  ".join(c.ljust(widths[j])
                                   for j, c in enumerate(row)).rstrip())
            if i == 0:
                print("  " + "  ".join("-" * w for w in widths))
        for vol in volumes:
            if vol.detail:
                print("\n  %s: %s" % (vol.name, vol.detail))
        for note in notes:
            print("\n  [!] %s" % note)
        readable = [v for v in volumes if v.fstype in READABLE_FS]
        print("")
        if readable:
            print("  %d volume(s) can be read: %s"
                  % (len(readable), ", ".join(v.name for v in readable)))
            print("  run without --list-volumes to examine, or --disk-volume "
                  "NAME to pick one")
        else:
            print("  no volume on this disk holds a filesystem this tool "
                  "reads (ext2/3/4, xfs, btrfs)")
        return 0
    finally:
        image.close()


def _skill_args(opts):
    """What a playbook was pointed at, from --skill-arg name=value."""
    out = {}
    for pair in opts.skill_arg or []:
        name, _sep, value = str(pair).partition("=")
        if not _sep:
            raise CaseError("--skill-arg wants name=value, not %r" % pair)
        out[name.strip()] = value.strip()
    return out


def _list_skills():
    """The playbooks, so --skill has something to name."""
    print("")
    print("playbooks - run one with --skill NAME, and point it with "
          "--skill-arg name=value")
    print("")
    for sk in SKILLS:
        need = [a for a, _d, r in sk["args"] if r]
        print("  %-22s %s%s" % (sk["name"], sk["about"],
                                (" (needs --skill-arg %s=...)"
                                 % need[0]) if need else ""))
    print("")
    return 0


def _ask_once(opts):
    """One question, answered against a case that already exists.

    The steps are printed under the answer for the same reason the panel shows
    them: a local model's answer is worth what the queries behind it are
    worth, and an analyst who cannot see them has been handed a rumour rather
    than a finding.
    """
    path = opts.db or _case_db_beside(opts)
    question = opts.ask or ""
    try:
        if opts.skill:
            # The playbook goes to the model in place of the question, and
            # what the analyst typed goes on the end of it. A skill run from
            # the command line is the same thing the button in the page does,
            # by the same route, so the two cannot drift apart.
            db = _open(path)
            try:
                question = render(opts.skill, db, _skill_args(opts))
            finally:
                db.close()
            if opts.ask:
                question += (chr(10) * 2 + "The analyst asked it this way, "
                             "so answer that, using the method above: "
                             + opts.ask)
        out = ask(path, question,
                  opts.llm_url or ASK_URL, opts.llm_model)
    except CaseError as e:
        status("[!] ask: %s" % e)
        return 2
    except KeyboardInterrupt:
        status("[!] ask: interrupted")
        return 130
    answer = (out.get("answer") or "").strip()
    print("")
    print(answer or "(the model answered with nothing)")
    bad = out.get("unsupported") or []
    if bad:
        print("")
        print("!! %d figure(s) above appear in NO query result: %s"
              % (len(bad), ", ".join(bad)))
        print("   Those did not come from this case. Treat the answer as "
              "unreliable and check the queries below yourself.")
    steps = out.get("steps") or []
    if steps:
        print("")
        print("-- what it looked at, in order " + "-" * 46)
        for st in steps:
            print("   %s" % st.get("note") or st.get("tool"))
            sql = (st.get("args") or {}).get("sql")
            if sql:
                print("      %s" % str(sql).replace(chr(10), " "))
    print("")
    status("[*] ask: answered by %s against %s"
           % (out.get("model") or "?", os.path.basename(path)))
    return 0


def _case_db_beside(opts):
    """The database --serve or --db would have written, if any.

    --export DIR puts case.db in DIR, which is where an examiner who
    ran the triage yesterday will look for it today. Falling back to
    the working directory means "linsight --mcp" works from inside
    the export without naming anything.
    """
    for cand in (os.path.join(opts.export or "", "case.db"),
                 os.path.join(os.getcwd(), "case.db")):
        if cand and os.path.isfile(cand):
            return cand
    return os.path.join(opts.export or os.getcwd(), "case.db")


#: A file --serve will open as a case. The extension is checked rather than
#: the contents because the message for "that is not a case" should name what
#: was given, not what SQLite made of it.
CASE_SUFFIX = (".db", ".sqlite", ".sqlite3")

#: Extensions that settle a --serve value as a path rather than an address,
#: for the one case where it does not exist: cases, collections and images.
#: Only these, because a host name is full of dots too - 127.0.0.1 has the
#: extension ".1" and web01.corp.local has ".local", and neither is a file.
NOT_A_BIND = CASE_SUFFIX + (".tar", ".gz", ".tgz", ".bz2", ".xz", ".zip",
                            ".e01", ".ex01", ".dd", ".raw", ".img", ".bin",
                            ".ad1", ".qcow2", ".vmdk", ".vhd", ".vhdx", ".iso")


def _serve_value(opts):
    """What --serve was given: ("bind", text), ("case", path) or ("lost", text).

    The flag takes an address to bind to and, since a case can be reopened,
    also a case to reopen - so the two have to be told apart from the value
    alone. A port is a port before the disk is consulted, which keeps a
    directory called "8000" an address. Anything that exists on disk is the
    case, which is also what settles a Windows path with a drive letter in
    it being a path rather than a host called "C".

    The third answer is the one worth having. `--serve` takes an optional
    value, so `linsight --serve collection.tar.gz` hands argparse the
    collection as this flag's value and leaves the run with nothing to parse.
    Binding to a host named collection.tar.gz is not a useful reading of
    that, and neither is "a collection is required".
    """
    text = (getattr(opts, "serve", "") or "").strip()
    if not text or text.isdigit():
        return "bind", text
    if os.path.isdir(text):
        return "case", os.path.join(text, "case.db")
    if os.path.isfile(text):
        if os.path.splitext(text)[1].lower() in CASE_SUFFIX:
            return "case", text
        return "lost", text
    sep = [c for c in (os.sep, os.altsep) if c]
    if (any(c in text for c in sep)
            or os.path.splitext(text)[1].lower() in NOT_A_BIND):
        # a path, and by here not one that holds anything
        return "lost", text
    return "bind", text                 # a bare host name, or host:port


def _reopen_case(ap, opts):
    """The investigation server over a case an earlier run wrote.

    Parsing is the long half of a run - minutes on a triage collection, an
    hour on a disk image - and what it produces is a database holding every
    row the console shows. Stopping the server and starting it again should
    cost the second half and not both, so --serve given a case rather than a
    port reads the tables back out of it and serves those.

    Nothing is parsed and nothing is rewritten. The marks and notes carry on
    in the same case file beside the same database, which is the point: this
    is the same investigation being resumed, not a new one over the same
    evidence.
    """
    kind, value = _serve_value(opts)
    path = value if kind == "case" else (opts.db or _case_db_beside(opts))
    if kind == "lost":
        ap.error("--serve %s is neither an address to bind to nor a case "
                 "that exists.\n    If that is a collection, --serve read it "
                 "as its own value: put it before the flag, or give --serve "
                 "a port.\n    If it is a case, there is nothing at that "
                 "path." % value)
    if not os.path.isfile(path):
        ap.error("no case database at %s\n    Name a collection to parse, "
                 "or point --serve at the export directory of a run that "
                 "already happened." % path)

    db = CaseDB(path)
    try:
        tables, meta, console = db.reopen()
    except CaseError as e:
        ap.error(str(e))
    if not tables:
        ap.error("%s holds no artifact tables - it is not a case this tool "
                 "wrote" % path)
    status("[*] reopening %s: %d table(s), %s row(s), nothing re-parsed"
           % (path, len(tables), "{:,}".format(sum(len(t) for t in tables))))

    tri = ReopenedCase(meta, console.get("collection") or path)
    case = opts.case or os.path.join(os.path.dirname(path) or ".", "case.json")

    def _page():
        # rebuilt per request, exactly as a parsing run's is: a rebuilt
        # linsight.py reaches an already-running server on a refresh
        css, js = live_assets()
        return console_html(tables, opts.html_rows, console, tri, opts,
                            served=True, css=css, js=js)

    serve(_page, case, value if kind == "bind" else "127.0.0.1:8000",
          tables=None,            # the rows are in the database already
          meta=meta, console=console, db_path=path,
          llm={"url": getattr(opts, "llm_url", None) or ASK_URL,
               "model": getattr(opts, "llm_model", None) or ""})
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Parse a UAC or Velociraptor Linux collection, or a disk "
                    "image, and highlight critical / interesting events.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n"
               "  python linsight.py ./uac-host-linux-20260324\n"
               "  python linsight.py collection.tar.gz --html report.html\n"
               "  python linsight.py evidence.E01 --export ./out\n"
               "  python linsight.py ./disk.dd --list-volumes\n"
               "  python linsight.py ./coll --pivot @iocs.txt\n"
               "  python linsight.py ./coll --sigma ./detections\n"
               "  python linsight.py ./coll --update-sigma\n"
               "  python linsight.py --file capture.txt:/var/log/auth.log\n"
               "  python linsight.py ./coll --export ./out --serve\n"
               "  python linsight.py --serve ./out"
               "            # reopen it, parsing nothing\n"
               "\n"
               "more: README.md\n")
    ap.add_argument("--file", dest="files", action="append", metavar="PATH[:DEST]",
                    help="parse loose files instead of a collection (repeatable; PATH "
                         "may be a directory). Append ':/host/path' when the name does "
                         "not say what a file is: --file capture.txt:/var/log/auth.log")
    ap.add_argument("collections", nargs="*", metavar="COLLECTION|DISK",
                    help="a collection (directory, .tar, .tar.gz, .zip) or a disk "
                         "(raw/dd, E01, qcow2, vmdk, vhdx, vhd, or /dev/sda). Which it "
                         "is, is detected. Repeatable: several are read one after "
                         "another into one merged export, or one export each under "
                         "--split. Optional "
                         "only with --update-sigma on its own.")
    dg = ap.add_argument_group(
        "disks",
        "Read a disk image directly - no loop device, no mount, no root, nothing written to the evidence.")
    dg.add_argument("--disk", metavar="PATH", action="append",
                    help="read PATH as a disk even when it does not look like one "
                         "(repeatable)")

    ig = ap.add_argument_group(
        "saying what the input is",
        "Force one reader when the automatic detection guesses wrong, or when you would rather be explicit.")
    ig.add_argument("-d", "--dir", metavar="PATH", dest="dir_input",
                    action="append",
                    help="read PATH as a directory: an extracted collection, or a "
                         "mounted filesystem root (repeatable)")
    ig.add_argument("--archive", metavar="PATH", action="append",
                    help="read PATH as a collection archive (.tar, .tar.gz, .zip) "
                         "(repeatable)")
    ig.add_argument("--ad1", metavar="PATH", action="append",
                    help="read PATH as an AccessData/FTK logical image, with its "
                         ".ad2/.ad3 parts (repeatable)")
    dg.add_argument("--list-volumes", action="store_true",
                    help="print the disk's volumes and stop - run this first on an "
                         "unfamiliar image")
    dg.add_argument("--disk-volume", metavar="NAME",
                    help="read this volume (part1, p2, vg/lv) instead of the one holding "
                         "/etc")
    dg.add_argument("--disk-max-files", type=int, default=DEFAULT_MAX_FILES,
                    metavar="N",
                    help="stop the filesystem walk after N names (default 3,000,000); a "
                         "truncated walk becomes a finding")
    dg.add_argument("--no-deleted", action="store_true",
                    help="skip the deleted-inode scan - the slowest part of a large disk")
    ap.add_argument("--min-severity", default="INFO", choices=SEVERITIES,
                    help="lowest severity to print on the console (default INFO)")
    ap.add_argument("--window", type=int, default=72, metavar="H",
                    help="incident window in hours before collection time (default 72)")
    ap.add_argument("--max-evidence", type=int, default=25,
                    help="evidence lines printed per finding on the console (default 25)")
    ap.add_argument("--json", metavar="PATH", help="write full findings as JSON")
    ap.add_argument("--html", metavar="PATH",
                    help="write a self-contained HTML findings report (artifact tables "
                         "go to --export, which this report points at)")
    ap.add_argument("--timeline", metavar="PATH", help="write the event timeline as CSV")
    ap.add_argument("--show-timeline", action="store_true",
                    help="also print the timeline on the console")
    ap.add_argument("--timeline-show", type=int, default=60,
                    help="timeline rows to print with --show-timeline (default 60)")
    ap.add_argument("--timeline-limit", type=int, default=3000,
                    help="max file events kept in the timeline (default 3000)")
    ap.add_argument("--pivot", action="append", metavar="TERM",
                    help="search every artifact for TERM, case-insensitively "
                         "(repeatable). '@file' reads an indicator list - one per line, "
                         "'#' comments, defanged forms accepted - all matched in a "
                         "single pass.")
    ap.add_argument("--count-iocs", action="store_true",
                    help="also count every indicator the analyzers extracted, not just "
                         "the pivoted ones. Same single pass, larger pattern: minutes on "
                         "a big image.")
    ap.add_argument("--pivot-limit", type=int, default=500,
                    help="max indicators to search for (default 500)")
    ap.add_argument("--deep", action="store_true",
                    help="also scan memory_dump/*strings* (slow, multi-GB)")
    rg = ap.add_argument_group(
        "detection rules",
        "Hunt with your own rules. Both engines are built in. A rule this engine cannot represent faithfully is rejected into RULE_ERRORS rather than half-applied.")
    rg.add_argument("--yara", action="append", metavar="PATH",
                    help="YARA rule file or directory (repeatable); scans collected "
                         "files and per-process memory strings")
    rg.add_argument("--no-hunt", action="store_true",
                    help="skip the built-in offensive-tool keyword sweep")
    rg.add_argument("--keywords", action="append", metavar="PATH",
                    help="file of extra terms to hunt for, one per line (repeatable)")
    rg.add_argument("--sigma", action="append", metavar="PATH",
                    help="Sigma rule file or directory (repeatable), routed to the "
                         "normalised tables by each rule's logsource")
    rg.add_argument("--update-sigma", action="store_true",
                    help="fetch the current SigmaHQ ruleset into the cache and hunt with "
                         "it. Conditional - unchanged means no download. The only option "
                         "that uses the network.")
    rg.add_argument("--sigma-cached", action="store_true",
                    help="hunt with the cached ruleset, offline")
    rg.add_argument("--sigma-dir", metavar="DIR",
                    help="where the cache lives (default: your own temp directory, or "
                         "$LINSIGHT_SIGMA_DIR)")
    rg.add_argument("--sigma-source", metavar="URL|ZIP|DIR",
                    help="what --update-sigma reads instead of SigmaHQ's zip: a URL, a "
                         "downloaded zip, or a directory")
    rg.add_argument("--sigma-all", action="store_true",
                    help="cache every rule found, including ones for platforms this tool "
                         "builds no table for")
    mg = ap.add_argument_group(
        "several collections at once",
        "Read more than one collection or image in one command. Each gets its own "
        "directory of output; --correlate then asks what is true of more than one "
        "of them.")
    mg.add_argument("--split", metavar="DIR", dest="out",
                    help="keep the collections apart instead of merging them: "
                         "one directory of output per input, as DIR/<name>/, "
                         "named after the input's own file or folder. On its "
                         "own it writes a full export per input - csv/, json/ "
                         "and browser.html.")
    mg.add_argument("--correlate", action="store_true",
                    help="also work out what is true of more than one of them - "
                         "the indicators, findings and file hashes several hosts "
                         "share, and which host saw each first. Adds CROSS_IOCS, "
                         "CROSS_FINDINGS, CROSS_HASHES and HOSTS to the export; "
                         "under --split it writes DIR/_correlation/ instead. "
                         "Needs two or more inputs.")
    tg = ap.add_argument_group(
        "artifact tables",
        "Normalise every artifact into browsable grids - one table per artifact type, each row keeping its source file.")
    tg.add_argument("--scope", choices=TableBuilder.SCOPES, default="full",
                    help="which half of the collection to build tables from: 'live' "
                         "(processes, sockets, modules), 'offline' (filesystem, config, "
                         "logs), or 'full' (default). Findings and the timeline always "
                         "use everything.")
    tg.add_argument("--export", metavar="DIR",
                    help="write every table into DIR - csv/, json/ and browser.html")
    tg.add_argument("--csv-dir", metavar="DIR",
                    help="write one CSV per table into DIR")
    tg.add_argument("--tables-json", metavar="PATH",
                    help="write every table as a single JSON document")
    tg.add_argument("--tables-html", metavar="PATH",
                    help="write the self-contained console: findings, timeline, "
                         "indicators and every table")
    tg.add_argument("--process-map", metavar="PATH",
                    help="write only the one-row-per-PID process table (.csv/.html/.json "
                         "by extension)")
    tg.add_argument("--serve", nargs="?", const="127.0.0.1:8000",
                    metavar="[HOST:]PORT|CASE",
                    help="open the investigation server instead of writing a "
                         "page: the same console, plus marking, labelling, "
                         "scoring and notes saved to a case file. Builds the "
                         "SQLite database and skips the CSV/JSON exports "
                         "unless --csv-dir or --tables-json ask for them. "
                         "Loopback only unless a host is named. Given an "
                         "export directory or a case.db instead of an address "
                         "- and no collection to parse - it reopens that case "
                         "instead: the same console over the rows already in "
                         "the database, in seconds rather than the length of "
                         "the parse. Name the case with --db if you want to "
                         "choose the port as well.")
    tg.add_argument("--ask", metavar="QUESTION",
                    help="put one question to a local model with the "
                         "case behind it, and print what it found and "
                         "the queries it ran. Reads a case an earlier "
                         "run wrote; parses nothing. Same engine as "
                         "the Ask panel and --mcp.")
    tg.add_argument("--skill", nargs="?", const="", metavar="NAME",
                    help="run an investigative playbook instead of a bare "
                         "question - the sequence an examiner follows, with "
                         "the tables and the joins named for the model. "
                         "Name it with no value to list them. Combines with "
                         "--ask, which then says how to answer it.")
    tg.add_argument("--skill-arg", action="append", metavar="NAME=VALUE",
                    help="what to point a playbook at: "
                         "--skill-arg address=209.141.62.185. Repeatable. "
                         "A playbook that needs one and is not given it is "
                         "refused rather than pointed at a guess.")
    tg.add_argument("--llm-url", metavar="URL",
                    help="an OpenAI-compatible endpoint for the Ask "
                         "panel - Ollama, LM Studio, llama.cpp, vLLM. "
                         "Default http://127.0.0.1:11434/v1, which is "
                         "Ollama. The server calls it; the page never "
                         "does, and nothing leaves the machine.")
    tg.add_argument("--llm-model", metavar="NAME",
                    help="which model to ask. Default: whatever the "
                         "runtime lists first. It must support tool "
                         "calling, because the model queries the case "
                         "rather than being handed it.")
    tg.add_argument("--mcp", nargs="?", const="", metavar="DB",
                    help="answer MCP over stdin/stdout against a case "
                         "database an earlier run wrote, so a model can "
                         "query the case itself - read-only, and "
                         "nothing leaves the machine. Defaults to "
                         "case.db beside --export. Parses nothing: "
                         "point it at a case that already exists.")
    tg.add_argument("--db", metavar="PATH",
                    help="write every artifact table into a SQLite database "
                         "as well - one SQL table each, plus the marks when "
                         "--serve is used. Implied by --serve, which defaults "
                         "it to case.db beside the export. It also names the "
                         "case to reopen when --serve is given a port rather "
                         "than a path.")
    tg.add_argument("--case", metavar="PATH",
                    help="where --serve keeps its marks and notes (default: "
                         "case.json beside the export, or beside the case "
                         "being reopened, or in the working directory)")
    tg.add_argument("--html-rows", type=int, default=0, metavar="N",
                    help="rows per table embedded in the HTML browser (0, the default, "
                         "embeds every row)")

    ap.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    ap.add_argument("--quiet", action="store_true", help="suppress the console report")
    ap.add_argument("--debug", action="store_true", help="re-raise analyzer exceptions")
    ap.add_argument("--low-memory", action="store_true",
                    help="spill large tables to a temp file - roughly half the peak "
                         "memory, about a fifth more time")
    ap.add_argument("--timing", action="store_true",
                    help="report wall time per table extractor and per output writer")
    opts = ap.parse_args(argv)

    # set before any table is built, because a table that has already buffered
    # its rows cannot be made to have spilled them
    if opts.low_memory and "LINSIGHT_SPILL_AFTER" not in os.environ:
        Table.SPILL_AFTER = 20000

    # Before the banner, and before anything else can print: stdout is
    # the protocol here, and one stray line of it is a client that
    # cannot parse the stream and an error that looks like anything but
    # this. Nothing is parsed either - the case has to exist already.
    if opts.mcp is not None:
        path = opts.mcp or opts.db or _case_db_beside(opts)
        return serve_mcp(path, quiet=opts.quiet)

    if opts.skill == "":
        return _list_skills()
    if opts.ask or opts.skill:
        return _ask_once(opts)

    opts.color = (not opts.no_color) and sys.stdout.isatty()
    if opts.color and os.name == "nt":
        try:                                    # enable VT sequences on Windows
            import ctypes
            k = ctypes.windll.kernel32
            k.SetConsoleMode(k.GetStdHandle(-11), 7)
        except Exception:
            opts.color = False

    if not opts.quiet:
        print_banner(opts.color)

    # Rules first: refreshing the cache is the one thing worth doing without a
    # collection at all, and a fetch that fails should say so before a tar is
    # opened rather than after four minutes of parsing.
    # Flags that only mean something next to another flag: silently ignoring
    # one of these ends with a hunt that ran the wrong rules, or none
    if opts.sigma_source and not opts.update_sigma:
        ap.error("--sigma-source is where --update-sigma fetches from; to hunt "
                 "with rules already on disk use --sigma")
    if opts.sigma_all and not opts.update_sigma:
        ap.error("--sigma-all is what --update-sigma keeps; --sigma reads every "
                 "rule it is given already")
    if opts.sigma_dir and not (opts.update_sigma or opts.sigma_cached):
        ap.error("--sigma-dir is the cache --update-sigma writes and "
                 "--sigma-cached reads; to hunt with any other directory of "
                 "rules use --sigma")
    opts.sigma_note = ""
    if opts.update_sigma or opts.sigma_cached:
        cache = sigma_cache_dir(opts.sigma_dir)
        # The same rule the output paths follow: a ruleset written under the
        # collection contaminates it, and the next run would read it back as a
        # collected artifact.
        #
        # Against every input, because there can be several and
        # because this runs before any of them is resolved. It used to
        # read opts.collection - which the run sets on itself later,
        # and which stopped existing at all when the positional became
        # plural, so --sigma-cached and --update-sigma raised
        # AttributeError before reading a single byte of evidence.
        for cand in _input_paths(opts):
            if not os.path.isdir(cand):
                continue        # only a directory can hold the cache
            base = os.path.abspath(cand)
            if cache == base or cache.startswith(base + os.sep):
                ap.error("refusing to keep the rule cache inside the "
                         "collection:\n      %s\n    choose a --sigma-dir "
                         "outside\n      %s" % (cache, base))
        if opts.update_sigma:
            update_sigma_rules(cache, opts.sigma_source, opts.sigma_all,
                               quiet=opts.quiet)
        elif not sigma_cache_count(cache):
            ap.error("no cached Sigma rules in %s - run --update-sigma once to "
                     "fetch them" % cache)
        m = sigma_cache_manifest(cache)
        # Kept in the report metadata as well as on stderr: which ruleset, of
        # which date, produced a hit is part of the hit.
        opts.sigma_note = ("%d rule(s) from %s%s"
                           % (sigma_cache_count(cache),
                              m.get("source") or cache,
                              ", fetched %s UTC" % m["fetched_utc"]
                              if m.get("fetched_utc") else ""))
        if not opts.update_sigma:
            status("[*] sigma: cached %s" % opts.sigma_note)
        opts.sigma = (opts.sigma or []) + [cache]

    targets = _resolve_targets(ap, opts)
    if not targets:
        if opts.update_sigma:
            return 0                    # a rule refresh on its own
        # A finished case is an input too. It holds every row a run produced,
        # so --serve with nothing to parse is not a run missing its evidence -
        # it is a console over evidence that has already been parsed once.
        if opts.serve:
            return _reopen_case(ap, opts)
        ap.error("a collection, a disk or --file is required (or "
                 "--update-sigma on its own to refresh the rule cache, or "
                 "--serve over a case an earlier run wrote)")
    if _serve_value(opts)[0] == "case":
        ap.error("--serve %s names a case to reopen, and %s was given to "
                 "parse as well. Reopening serves the case as it stands and "
                 "parsing would overwrite it - drop one of the two."
                 % (opts.serve, targets[0][1] or "--file"))

    if opts.list_volumes:
        disks = [t for t in targets if t[0] == "disk"]
        if len(targets) > 1:
            ap.error("--list-volumes reads one disk; pass one")
        if not disks:
            ap.error("--list-volumes needs a disk; pass an image, a device, "
                     "or --disk PATH")
        return list_volumes(disks[0][1])

    _check_multi(ap, opts, targets)

    # One input keeps the flags exactly as they were typed: a single run has
    # nowhere to collide with, and rewriting its paths under --out when --out
    # was not given would be a change of behaviour for every existing command.
    if len(targets) == 1 and not opts.out:
        return _run_one(ap, opts, targets[0][0], targets[0][1])

    labels, taken = [], set()
    for _kind, path in targets:
        labels.append(_label_for(path, taken))
    status("[*] %d collection(s) to read: %s"
           % (len(targets), ", ".join(labels)))

    # Two shapes, and they answer different questions. --split keeps each
    # collection in a directory of its own, which is what you want when the
    # hosts are separate cases. The default merges them into one export with a
    # host column on every row, which is what you want when they are one case:
    # an unfiltered console then shows every host at once, and choosing one
    # narrows every grid - rather than opening three exports and joining by
    # eye. The cost is that the merged set is held whole; --low-memory spills
    # it, which is what that flag is for.
    merging = not opts.out
    cases, tris, per_host, worst = [], [], [], 0
    for i, ((kind, path), label) in enumerate(zip(targets, labels)):
        status("")
        status("[*] === %s (%d of %d): %s ===" % (label, i + 1, len(labels), path))
        hopts = _host_opts(opts, label)
        if merging:
            # every output is written once at the end, over the merged set
            for attr in ("export",) + OUTPUT_PATHS:
                setattr(hopts, attr, None)
            hopts.serve = None
        rc, tri, tables = _run_one(ap, hopts, kind, path, collect=True)
        worst = max(worst, rc)
        if tri is None:
            continue
        cases.append(HostCase(label, path, tri, tables))
        tris.append(tri)
        if merging:
            per_host.append((label, tables))

    if not merging:
        if opts.correlate:
            status("")
            write_correlation(cases, os.path.join(opts.out, "_correlation"), opts)
        return worst

    status("")
    tables, hostcol = merge_tables(per_host)
    cor = None
    if opts.correlate:
        cor = Correlator(cases, opts)
        # the cross-host tables join the export rather than becoming a second
        # one: the console carrying every host's rows is also where "which of
        # these hosts share this" is the natural next question
        cross = cor.run()
        tables += [t for t in cross
                   if t.name not in ("FINDINGS", "TIMELINE")]
        # and its findings join the merged FINDINGS rather than being dropped
        # with the table that held them - the console reads its findings out
        # of that table, so anything not in it is computed and never shown
        fold_correlation(tables, cross, hostcol)
    status("[*] merged %d table(s) from %d collections, %s row(s) total"
           % (len(tables), len(per_host),
              "{:,}".format(sum(len(t) for t in tables))))
    merged = merge_triage(cases, opts, tris)
    if cor is not None:
        merged.findings.extend(cor.tri.findings)
        merged.findings.sort(key=lambda f: (SEVERITIES.index(f.severity),
                                            f.category, f.title))
    _write_merged(merged, tables, labels, hostcol, opts)
    return worst


def _write_merged(tri, tables, labels, hostcol, opts):
    """Every output this run asked for, once, over the merged table set."""
    if opts.json:
        write_json(tri, opts.json)
    if opts.html:
        write_html(tri, opts.html, opts, None)
    if opts.timeline:
        write_timeline(tri, opts.timeline)
    if not any((opts.export, opts.csv_dir, opts.tables_json, opts.tables_html,
                opts.process_map, opts.serve, opts.db)):
        return
    meta = {"collection": ", ".join(labels),
            "hostname": tri.meta.get("Hostname", ""),
            "collected": "", "scope": getattr(opts, "scope", "full"),
            "layout": "merged", "hosts": list(labels),
            "host_column": hostcol,
            "tables": len(tables),
            "rows_total": sum(len(t) for t in tables)}
    write_merged_tables(tri, tables, meta, opts)


def _resolve_targets(ap, opts):
    """Every input this run was given, as [(forced kind, path)].

    The forcing flags each name a reader, and each may be repeated: a run over
    three images is three --disk, or three plain arguments, and mixing the two
    is refused because "which of these did I mean to force" has no good
    answer. What is not refused any more is repeating one flag - argparse used
    to overwrite silently, so `--disk a.dd --disk b.dd` read b.dd and reported
    on it as though a.dd had never been named.

    --file is the exception that stays singular: several loose files are one
    synthetic collection by construction, not several inputs.
    """
    named = [("--disk", "disk", list(opts.disk or [])),
             ("-d/--dir", "dir", list(opts.dir_input or [])),
             ("--archive", "archive", list(opts.archive or [])),
             ("--ad1", "ad1", list(opts.ad1 or []))]
    used = [(flag, kind, vals) for flag, kind, vals in named if vals]
    if opts.collections and (used or opts.files):
        ap.error("%s says what to read; do not also pass it as a plain argument"
                 % (used[0][0] if used else "--file"))
    if opts.files and used:
        ap.error("--file and %s each name what to read; pass one" % used[0][0])

    if opts.files:
        return [("files", "")]

    targets = []
    for _flag, kind, vals in used:
        for path in vals:
            if kind != "disk" and not os.path.exists(path):
                ap.error("%s not found: %s" % (kind, path))
            if kind == "dir" and not os.path.isdir(path):
                ap.error("-d/--dir wants a directory; %s is a file. For an "
                         "archive use --archive, for a disk image use --disk."
                         % path)
            if kind == "archive" and os.path.isdir(path):
                ap.error("--archive wants a .tar/.tar.gz/.zip; %s is a "
                         "directory - use -d instead" % path)
            targets.append((kind, path))

    # With nothing declared, each argument identifies itself - and says so.
    # A directory holding one Webserver.E01 is not a collection with two files
    # in it; reading it as one built five empty tables and reported a host
    # with nothing on it.
    for raw in opts.collections:
        if not os.path.exists(raw):
            ap.error("collection not found: %s" % raw)
        kind, target, why = identify_input(raw)
        if why and not opts.quiet:
            status("[*] reading %s - %s"
                   % (os.path.basename(target.rstrip("/\\")) or target, why))
        targets.append((kind if kind in ("disk", "ad1") else "", target))
    return targets


#: Every output flag that names a path, and the attribute holding it. Under
#: --out each becomes a name inside that input's own directory, so three runs
#: cannot write three reports over one another.
OUTPUT_PATHS = ("csv_dir", "tables_json", "tables_html", "json", "html",
                "timeline", "process_map", "db", "case")


def _check_multi(ap, opts, targets):
    """Refuse the combinations that cannot mean what they look like."""
    if opts.correlate and len(targets) < 2:
        ap.error("--correlate compares collections with each other; it needs "
                 "at least two")
    if len(targets) > 1 and opts.out and opts.serve:
        # merged, --serve is one console over every host and works; split, it
        # would have to serve three at once from one blocking process
        ap.error("--serve and --split are different answers to the same "
                 "question: --serve wants one console, --split writes one "
                 "export per collection. Drop --split to serve the merged "
                 "set, or drop --serve and open the export you want")


def _host_opts(opts, label):
    """This input's own copy of the options, writing into its own directory.

    Shallow: the lists and dictionaries on opts are read, never mutated, so
    the copies share them. What is rewritten is every path an output would be
    written to - and only its basename is kept, because an absolute path
    given once cannot name three different files.
    """
    o = copy.copy(opts)
    o.collections, o.disk, o.dir_input, o.archive, o.ad1 = [], None, None, None, None
    if not opts.out:
        # Console-only: nothing is written, so there is nothing to move. The
        # per-host header above is the whole separation these runs need.
        return o
    hdir = os.path.join(opts.out, label)
    # Made here rather than by each writer: --export creates its own directory
    # but --html and --tables-json do not, and a run that parses a disk for a
    # minute and then fails on a missing parent has wasted the minute.
    os.makedirs(hdir, exist_ok=True)
    if opts.export:
        # --export already means "a directory of everything"; under --out that
        # directory is the host's own, rather than one nested inside it
        o.export = hdir
    for attr in OUTPUT_PATHS:
        value = getattr(opts, attr, None)
        if value:
            setattr(o, attr, os.path.join(hdir, os.path.basename(str(value))))
    if not any(getattr(o, a, None) for a in ("export",) + OUTPUT_PATHS):
        # --out on its own has to mean something, and the something an
        # analyst wants from it is the export they would have asked for
        o.export = hdir
    return o


def _input_paths(opts):
    """Every path this run was pointed at, however it was named.

    The positionals and the flags that declare a kind, flattened.
    Called before anything is resolved, so it asks for nothing but
    the strings the command line carried.
    """
    out = []
    for attr in ("collections", "disk", "archive", "ad1"):
        got = getattr(opts, attr, None) or []
        out.extend(got if isinstance(got, list) else [got])
    for raw in getattr(opts, "files", None) or []:
        out.append(parse_file_spec(raw)[0])
    return [p for p in out if p]


#: Names above which a run spills its tables to disk on its own.
#:
#: Table memory tracks the number of files, not the size of the image: the
#: measured cost is ~157 bytes per name for the index alone, and the tables
#: built from those names are several times that again. On the collection this
#: was measured against, spilling held the run to 802 MB instead of 1,805 MB
#: for 45s of a 220s run.
#:
#: Half a million names is where that trade turns over. Below it the run fits
#: comfortably in memory on any machine that can hold the image's index at
#: all, and the time matters more; above it the run is long enough that a
#: fifth more of it is a better outcome than being killed at 90%.
AUTOSPILL_NAMES = 500000


def _autospill(col, opts):
    """Turn spilling on for a large input, and say so.

    --low-memory exists and is the right switch when the examiner knows the
    box is tight. This is for when they do not: the flag has to be given
    before the walk, and how big the walk turns out to be is not knowable
    until it is done. A 500 GB disk of a build server is millions of files and
    an unattended run that dies at 90% for want of a flag nobody could have
    known to pass.

    Never overrides a decision already made - an explicit --low-memory, or
    LINSIGHT_SPILL_AFTER from the environment, both stand.
    """
    if getattr(opts, "low_memory", False):
        return
    if "LINSIGHT_SPILL_AFTER" in os.environ:
        return
    if Table.SPILL_AFTER != Table.SPILL_NEVER:
        return
    n = len(getattr(col, "_names", ()) or ())
    if n < AUTOSPILL_NAMES:
        return
    Table.SPILL_AFTER = 20000
    status("[*] %s names: spilling tables to disk as they are built "
           "(about a fifth more time, roughly half the peak memory). "
           "--low-memory does this on request; nothing was lost." % "{:,}".format(n))


def _run_one(ap, opts, forced, target, collect=False):
    """Read one collection and write whatever this run asked for.

    Returns the exit code on a single-input run, and (code, triage, tables)
    when a caller is gathering several - the correlation needs what each run
    concluded, and the tables are handed over rather than re-read.
    """
    disk_path = target if forced == "disk" else ""
    ad1_path = target if forced == "ad1" else ""
    opts.collection = target
    if forced == "dir":
        opts.dir_input = target
    elif forced == "archive":
        opts.archive = target

    # An AD1 is a logical image - a tree of files, not a disk - so it lands on
    # the collection side. Like every other container it is recognised rather
    # than declared.
    if ad1_path:
        try:
            col = Ad1Collection(ad1_path, quiet=opts.quiet,
                                max_files=max(0, opts.disk_max_files))
        except Ad1Error as exc:
            ap.error(str(exc))
        status("[*] read %s file(s) out of %s"
               % (format(len(col._names) - 1, ","),
                  os.path.basename(col.path)))
    elif disk_path:
        try:
            col = DiskCollection(
                disk_path, quiet=opts.quiet,
                max_files=max(1, opts.disk_max_files),
                want_volume=opts.disk_volume,
                deleted_limit=0 if opts.no_deleted else 200000)
        except (DiskError, ImageError) as exc:
            ap.error(str(exc))
        status("[*] read %s file(s) off %s, %d filesystem(s) mounted"
               % (format(len(col._names) - 1, ","),
                  os.path.basename(col.path), len(col.mounts)))
    elif opts.files:
        specs = []
        for raw in opts.files:
            path, dest = parse_file_spec(raw)
            if not os.path.exists(path):
                ap.error("--file not found: %s" % path)
            specs.append((path, dest))
        col = FilesCollection(specs, quiet=opts.quiet)
        status("[*] loaded %d loose file(s) as a synthetic collection"
               % len(col._names))
    else:
        if not os.path.exists(opts.collection):
            ap.error("collection not found: %s" % opts.collection)
        col = Collection(opts.collection)
        status("[*] loaded %s collection: %d files, root prefix '%s', rootfs dirs %s"
              % (col.kind, len(col._names), col.prefix or "(none)",
                 ", ".join(col.rootfs_dirs)))

    _autospill(col, opts)
    _check_output_paths(col, opts)      # before any work, for every output flag

    tri = Triage(col, opts)
    tri.run()
    if opts.sigma_note:
        tri.meta["Sigma ruleset"] = opts.sigma_note

    # Rule hits are findings, and the console report, --json and --html are all
    # written from the finding list - so when rules are in play the tables have
    # to be built first. The build is reused by the export below rather than
    # repeated.
    tb = None
    asked_for_rules = bool(opts.yara or opts.sigma or opts.keywords)
    # --process-map on its own is a targeted extraction of one table, not a
    # triage run: building all 70 tables to hunt would turn a seconds-long
    # command into a minute. Explicit rule flags still win over that.
    map_only = bool(opts.process_map) and not any(
        (opts.export, opts.csv_dir, opts.tables_json, opts.tables_html))
    if (asked_for_rules or not opts.no_hunt) and not (map_only and
                                                      not asked_for_rules):
        _check_output_paths(col, opts)
        tb = TableBuilder(col, tri)
        tb.build(verbose=not opts.quiet, scope=getattr(opts, "scope", "full"))

    if not opts.quiet:
        print_console(tri, opts)
    if opts.json:
        write_json(tri, opts.json)
    if opts.html:
        write_html(tri, opts.html, opts, tb)
    if opts.timeline:
        write_timeline(tri, opts.timeline)

    if any((opts.export, opts.csv_dir, opts.tables_json,
            opts.tables_html, opts.process_map, getattr(opts, "serve", None))):
        export_tables(tri, col, opts, tb)

    crit = sum(1 for f in tri.findings if f.severity == "CRITICAL")
    high = sum(1 for f in tri.findings if f.severity == "HIGH")
    code = 2 if crit else (1 if high else 0)
    return (code, tri, (tb.tables if tb is not None else [])) if collect else code


if __name__ == "__main__":
    sys.exit(main())
