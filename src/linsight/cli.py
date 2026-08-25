# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import os
import sys

from .model import SEVERITIES
from .common import human_size
from .term import status
from .collect import Collection, FilesCollection, parse_file_spec
from .image import ImageError, looks_like_disk, open_image
from .disk import DEFAULT_MAX_FILES, DiskCollection, DiskError
from .volume import READABLE_FS, scan
from .rules import (
    sigma_cache_count, sigma_cache_dir, sigma_cache_manifest,
    update_sigma_rules)
from .triage import Triage
from .tables import Table, TableBuilder
from .writers import _check_output_paths, export_tables
from .report import (
    print_banner, print_console, write_html, write_json, write_timeline)



# ---------------------------------------------------------------------------


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


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Parse a UAC or Velociraptor Linux collection, or a disk "
                    "image, and highlight critical / interesting events.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n"
               "  python linsight.py ./uac-host-linux-20260324\n"
               "  python linsight.py collection.tar.gz --html report.html --json out.json\n"
               "  python linsight.py ./coll --min-severity HIGH --timeline timeline.csv\n"
               "  python linsight.py ./coll --pivot /dev/shm/kit --pivot libymv.so.3\n"
               "  python linsight.py ./disk.dd            # a raw disk image\n"
               "  python linsight.py evidence.E01         # the whole E01 set\n"
               "  python linsight.py vm.qcow2 --html report.html\n"
               "  python linsight.py ./disk.dd --list-volumes  # what is on it\n"
               "  sudo python linsight.py /dev/sda        # the live disk\n"
               "  python linsight.py --file /var/log/auth.log\n"
               "  python linsight.py --file ./loose-logs/ --file ps.txt\n"
               "  python linsight.py --file capture.txt:/var/log/auth.log\n"
               "  python linsight.py ./coll --export ./triage_out\n"
               "  python linsight.py ./coll --csv-dir ./tables --quiet\n"
               "  python linsight.py ./coll --export ./live --scope live\n"
               "  python linsight.py ./coll --export ./disk --scope offline\n"
               "  python linsight.py ./coll --update-sigma   # fetch SigmaHQ, then hunt\n"
               "  python linsight.py ./coll --sigma-cached   # hunt offline with the cache\n"
               "  python linsight.py --update-sigma          # refresh the cache only\n")
    ap.add_argument("--file", dest="files", action="append", metavar="PATH[:DEST]",
                    help="parse loose files instead of a collection. Repeatable, "
                         "and PATH may be a directory. Each file is mounted at "
                         "the path its parser looks for, chosen from the name "
                         "('auth.log' -> /var/log/auth.log, 'ps.txt' -> the "
                         "process listing); a directory whose top level looks "
                         "like a host tree (etc/, var/, ...) is mounted as it "
                         "stands. Append ':/host/path' to say what a file is "
                         "when the name does not: "
                         "--file capture.txt:/var/log/auth.log")
    ap.add_argument("collection", nargs="?", metavar="COLLECTION|DISK",
                    help="a collection directory, .tar, .tar.gz or .zip (UAC "
                         "output or a Velociraptor offline collector zip), or "
                         "a disk: a raw/dd image, an E01 set, a qcow2, vmdk, "
                         "vhdx or vhd, or a device such as /dev/sda. Which of "
                         "the two it is, and for a collection which tool "
                         "produced it, is detected rather than declared. "
                         "Optional only when --update-sigma is refreshing "
                         "rules on its own")
    dg = ap.add_argument_group(
        "disks",
        "Point the same parsers at a disk instead of a collection. The image "
        "is read directly - no loop device, no mount, no root, nothing "
        "written to the evidence. Partition tables, LVM volume groups and "
        "LUKS containers are walked through; the root filesystem is the one "
        "that holds /etc, and whatever /etc/fstab places is mounted where the "
        "host had it. A volume that cannot be opened is reported by name, "
        "because an encrypted partition and an absence of evidence must not "
        "look alike in the output.")
    dg.add_argument("--disk", metavar="PATH",
                    help="read PATH as a disk even when it would not be "
                         "recognised as one - a headerless image, a damaged "
                         "partition table, a device node")
    dg.add_argument("--list-volumes", action="store_true",
                    help="print what is on the disk - container, partitions, "
                         "logical volumes, filesystems - and stop. The first "
                         "thing to run against an unfamiliar image: it costs "
                         "one pass over the metadata, not a filesystem walk.")
    dg.add_argument("--disk-volume", metavar="NAME",
                    help="read this volume (part1, p2, vg/lv) instead of the "
                         "one that holds /etc")
    dg.add_argument("--disk-max-files", type=int, default=DEFAULT_MAX_FILES,
                    metavar="N",
                    help="stop the filesystem walk after N names (default "
                         "%s). A truncated walk becomes a HIGH finding, "
                         "because an absence in a partial read is not evidence "
                         "of absence." % format(DEFAULT_MAX_FILES, ","))
    dg.add_argument("--no-deleted", action="store_true",
                    help="skip the deleted-inode scan. It reads every inode "
                         "table on the filesystem, which on a multi-terabyte "
                         "disk is the slowest part of the load.")
    ap.add_argument("--min-severity", default="INFO", choices=SEVERITIES,
                    help="lowest severity to print on the console (default INFO)")
    ap.add_argument("--window", type=int, default=72, metavar="H",
                    help="incident window in hours before collection time (default 72)")
    ap.add_argument("--max-evidence", type=int, default=25,
                    help="evidence lines printed per finding on the console (default 25)")
    ap.add_argument("--json", metavar="PATH", help="write full findings as JSON")
    ap.add_argument("--html", metavar="PATH", help="write a self-contained HTML report")
    ap.add_argument("--timeline", metavar="PATH", help="write the event timeline as CSV")
    ap.add_argument("--show-timeline", action="store_true",
                    help="also print the timeline on the console")
    ap.add_argument("--timeline-show", type=int, default=60,
                    help="timeline rows to print with --show-timeline (default 60)")
    ap.add_argument("--timeline-limit", type=int, default=3000,
                    help="max file events kept in the timeline (default 3000)")
    ap.add_argument("--pivot", action="append", metavar="TERM",
                    help="search every collected artifact for TERM, case-"
                         "insensitively (repeatable). Use '@file' to read a "
                         "list of indicators, one per line, '#' for comments - "
                         "all terms are matched in one pass, so a long list "
                         "costs no more than a short one.")
    ap.add_argument("--pivot-limit", type=int, default=500,
                    help="max indicators to search for (default 500)")
    ap.add_argument("--deep", action="store_true",
                    help="also scan memory_dump/*strings* (slow, multi-GB)")
    rg = ap.add_argument_group(
        "detection rules",
        "Hunt with your own rules. Both engines are built in - nothing to "
        "install - and cover the constructs Linux IR rules use; PyYAML is used "
        "for Sigma if it happens to be importable. A rule the engine cannot "
        "represent faithfully is rejected and listed in RULE_ERRORS rather "
        "than half-applied, because a rule that silently matches nothing looks "
        "exactly like a clean result. Sigma rules go stale the same way: "
        "--update-sigma keeps a local copy of the public ruleset current, and "
        "is the only thing here that uses the network.")
    rg.add_argument("--yara", action="append", metavar="PATH",
                    help="YARA rule file or directory (repeatable). Scans the "
                         "collected filesystem and the per-process memory "
                         "strings; add --deep for the memory image strings.")
    rg.add_argument("--no-hunt", action="store_true",
                    help="skip the built-in offensive-tool keyword sweep. The "
                         "sweep reads the normalised tables, so it costs the "
                         "table build even when no export was asked for - on a "
                         "mid-size collection that is roughly 12s to 65s. Use "
                         "this when you want the analyzer findings only.")
    rg.add_argument("--keywords", action="append", metavar="PATH",
                    help="file of extra terms to hunt for, one per line "
                         "(repeatable). Matched the same way as the built-in "
                         "tool names, across every artifact - use it for "
                         "case-specific names, hostnames or filenames.")
    rg.add_argument("--sigma", action="append", metavar="PATH",
                    help="Sigma rule file or directory (repeatable). Runs "
                         "against the normalised tables - auth, journal, "
                         "auditd, processes, cron, web logs - routed by each "
                         "rule's logsource.")
    rg.add_argument("--update-sigma", action="store_true",
                    help="fetch the current SigmaHQ ruleset into a local cache "
                         "and hunt with it. Keeps the rules that can reach a "
                         "table this tool builds - the Linux and web-log ones - "
                         "and skips the ~3000 Windows event log rules, which "
                         "would only slow the load and fill RULE_ERRORS. The "
                         "fetch is conditional: an unchanged ruleset is a 304 "
                         "and no download. Works with no collection argument "
                         "when you just want the cache refreshed.")
    rg.add_argument("--sigma-cached", action="store_true",
                    help="hunt with the cached ruleset as last fetched, without "
                         "touching the network - the offline half of "
                         "--update-sigma.")
    rg.add_argument("--sigma-dir", metavar="DIR",
                    help="where the cached ruleset lives (default "
                         "~/.linsight/sigma, or $LINSIGHT_SIGMA_DIR). It is a "
                         "plain directory of .yml files, so --sigma takes it "
                         "too.")
    rg.add_argument("--sigma-source", metavar="URL|ZIP|DIR",
                    help="what --update-sigma reads instead of SigmaHQ's "
                         "master zip: another ruleset's URL, a zip already "
                         "downloaded, or a directory - for the evidence "
                         "workstation with no route out, and for your own "
                         "rule repository.")
    rg.add_argument("--sigma-all", action="store_true",
                    help="cache every rule --update-sigma finds, including the "
                         "ones for platforms this tool builds no table for. "
                         "SIGMA_COVERAGE then says, rule by rule, why each one "
                         "could not fire here.")
    tg = ap.add_argument_group(
        "artifact tables",
        "Normalise every interesting artifact into browsable grids - one table "
        "per artifact type, with a source column keeping the originating file.")
    tg.add_argument("--scope", choices=TableBuilder.SCOPES, default="full",
                    help="which half of the collection to build tables from: "
                         "'live' = the volatile snapshot (processes, sockets, "
                         "open files, modules, live sessions); 'offline' = what "
                         "a dead-box exam recovers (filesystem, config, logs, "
                         "persistence, bodyfile); 'full' = both (default). "
                         "Findings and the timeline always use the whole "
                         "collection - they are cross-artifact by nature.")
    tg.add_argument("--export", metavar="DIR",
                    help="write every table format into DIR "
                         "(csv/ and json/, one file per table, plus "
                         "browser.html - the console)")
    tg.add_argument("--csv-dir", metavar="DIR",
                    help="write one CSV per table into DIR")
    tg.add_argument("--tables-json", metavar="PATH",
                    help="write every table as a single JSON document")
    tg.add_argument("--tables-html", metavar="PATH",
                    help="write the self-contained console: findings, ATT&CK, "
                         "timeline, indicators and every artifact table")
    tg.add_argument("--process-map", metavar="PATH",
                    help="write ONLY the correlated one-row-per-PID process table "
                         "to a single file (.csv/.html/.json by extension)")
    tg.add_argument("--html-rows", type=int, default=2000, metavar="N",
                    help="rows per table embedded in the HTML browser (default 2000; "
                         "the CSV and JSON exports always get everything)")

    ap.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    ap.add_argument("--quiet", action="store_true", help="suppress the console report")
    ap.add_argument("--debug", action="store_true", help="re-raise analyzer exceptions")
    ap.add_argument("--low-memory", action="store_true",
                    help="spill large tables to a temp file instead of holding "
                         "every row in memory - roughly halves peak memory on a "
                         "large collection and costs about 20%% of the run time")
    ap.add_argument("--timing", action="store_true",
                    help="report wall time per table extractor and per output "
                         "writer - use it to find which artifact a slow "
                         "collection is spending its minutes on")
    opts = ap.parse_args(argv)

    # set before any table is built, because a table that has already buffered
    # its rows cannot be made to have spilled them
    if opts.low_memory and "LINSIGHT_SPILL_AFTER" not in os.environ:
        Table.SPILL_AFTER = 20000

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
        if opts.collection and os.path.isdir(opts.collection):
            base = os.path.abspath(opts.collection)
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

    if opts.files and opts.collection:
        ap.error("--file parses loose files instead of a collection; pass one "
                 "or the other, not both")
    if opts.disk and (opts.files or opts.collection):
        ap.error("--disk names the disk to read; do not also pass a "
                 "collection or --file")

    # A disk is recognised rather than declared: a .dd, an .E01, a qcow2 or a
    # device given as the ordinary argument goes to the disk backend, and
    # --disk only exists for the image that carries no recognisable header at
    # all. Requiring a flag would mean an analyst who forgets it gets "no
    # readable files found", which reads as a fault in the evidence.
    disk_path = opts.disk
    if not disk_path and opts.collection and looks_like_disk(opts.collection):
        disk_path = opts.collection

    if not disk_path and not opts.collection and not opts.files:
        if opts.update_sigma:
            return 0                    # a rule refresh on its own
        ap.error("a collection, a disk or --file is required (or "
                 "--update-sigma on its own to refresh the rule cache)")

    if opts.list_volumes:
        if not disk_path:
            ap.error("--list-volumes needs a disk; pass an image, a device, "
                     "or --disk PATH")
        return list_volumes(disk_path)

    if disk_path:
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
        write_html(tri, opts.html, opts)
    if opts.timeline:
        write_timeline(tri, opts.timeline)

    if any((opts.export, opts.csv_dir, opts.tables_json,
            opts.tables_html, opts.process_map)):
        export_tables(tri, col, opts, tb)

    crit = sum(1 for f in tri.findings if f.severity == "CRITICAL")
    high = sum(1 for f in tri.findings if f.severity == "HIGH")
    return 2 if crit else (1 if high else 0)


if __name__ == "__main__":
    sys.exit(main())
