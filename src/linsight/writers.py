# -*- coding: utf-8 -*-
from __future__ import annotations

from datetime import datetime
from datetime import timezone
import csv
import html as htmllib
import io
import json
import zlib
import itertools
import base64
import os
import sys
import time

from .constants import VERSION
from .term import status
from .common import NDJSON_TIME_COLUMNS, human_size
from .tables import TableBuilder, _s
from .gui import APP_CSS, APP_JS, ATTACK_ORDER, ATTACK_TACTICS, _triage_payload
from .ask import ASK_URL
from .graph import build_svg, write_correlation_svg
from .serve import CaseDB, live_assets, serve



# ---------------------------------------------------------------------------
# table writers: CSV, JSON, HTML browser
# ---------------------------------------------------------------------------

def write_tables_csv(tables, dirpath):
    os.makedirs(dirpath, exist_ok=True)
    index = os.path.join(dirpath, "00_INDEX.csv")
    with open(index, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh)
        w.writerow(["table", "title", "category", "rows", "columns", "csv_file",
                    "description"])
        for t in tables:
            w.writerow([t.name, t.title, t.category, len(t), len(t.columns),
                        t.name + ".csv", t.description])
    for t in tables:
        path = os.path.join(dirpath, t.name + ".csv")
        with open(path, "w", newline="", encoding="utf-8-sig") as fh:
            w = csv.writer(fh)
            w.writerow(t.columns)
            for row in t.iter_rows():
                w.writerow([_s(v) for v in row])
    return len(tables) + 1


def _table_json_body(t, fh):
    """One table as a JSON object, streamed row by row.

    Never json.dumps the whole table: BODYFILE and the log tables run to
    hundreds of thousands of rows, and building the string first doubles the
    peak for no benefit when the rows are written once and never re-read.
    """
    fh.write('{\n "name": %s,\n "title": %s,\n "category": %s,\n'
             % (json.dumps(t.name), json.dumps(t.title), json.dumps(t.category)))
    fh.write(' "description": %s,\n' % json.dumps(t.description))
    fh.write(' "sources": %s,\n' % json.dumps(t.sources))
    fh.write(' "columns": %s,\n' % json.dumps(t.columns))
    fh.write(' "row_count": %d,\n "rows": [' % len(t))
    for j, row in enumerate(t.iter_rows()):
        fh.write("%s%s" % ("," if j else "", json.dumps([_s(v) for v in row])))
    fh.write("]\n}\n")


# Columns a table may carry its event time in, best first.

# A row's own moment, for the console's time window - and deliberately only
# the two columns that mean "this row IS a thing that happened".
#
# The window narrows what happened, never what exists. Half the tables here
# carry a timestamp that is an attribute of a standing thing rather than an
# event: USERS.last_login_utc (2 of 33 accounts have one), SUID_SGID.mtime_utc,
# PROCESS_MASTER.start_utc. Filtering those on a one-hour window deletes the
# account list, every suid binary, and every process that was already running
# when the hour began - which is not a narrower answer, it is a wrong one.
#
# A table with neither column is left alone entirely, and the console says so
# rather than showing an empty grid. Ordered by preference: a table carrying
# both a stamp of its own and a first/last span is filtered on the stamp,
# because that is when the row happened rather than when the thing it belongs
# to was first seen.
CONSOLE_TIME_COLUMNS = ("timestamp_utc", "timestamp")

# Context added to every event. Prefixed because the row's own fields win and
# must: SIGMA_MATCHES and HACKTOOL_HITS both have a column literally called
# 'table', and an unprefixed context field would overwrite the evidence with
# the name of the file it came from.
NDJSON_PREFIX = "triage_"


def _epoch_utc(text):
    """'2026-08-17 09:41:02' or ISO8601 -> epoch seconds, or None.

    Splunk takes _time as epoch. Emitting it beats leaving Splunk to guess from
    the raw line, which on a row whose first field is a pid picks up a number
    that is not a time at all.
    """
    s = str(text or "").strip()
    if not s:
        return None
    s = s.replace("T", " ").replace("Z", "").split("+")[0].split(".")[0].strip()
    try:
        dt = datetime.strptime(s[:19], "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None
    return dt.replace(tzinfo=timezone.utc).timestamp()


def write_tables_ndjson(tables, dirpath, meta=None):
    """One JSON object per row - newline-delimited, one file per table.

    A self-describing JSON document per table cannot be ingested by Splunk (or
    anything else that reads a line at a time): the whole table is one event,
    the rows array runs to 43 MB on a single line for BODYFILE against a
    default TRUNCATE of 10,000 bytes, and positional row arrays leave every
    field unnamed. One object per line fixes all three, and the per-table
    metadata that the document used to carry moves to 00_INDEX.json.

    Empty values are omitted rather than written as "": an absent field costs
    nothing to search and keeps the events small, which is the convention every
    log platform expects.
    """
    os.makedirs(dirpath, exist_ok=True)
    meta = meta or {}
    ctx = {}
    for key, val in ((NDJSON_PREFIX + "host", meta.get("hostname")),
                     (NDJSON_PREFIX + "collected", meta.get("collected")),
                     (NDJSON_PREFIX + "collection",
                      os.path.basename(str(meta.get("collection") or ""))),
                     (NDJSON_PREFIX + "layout", meta.get("layout"))):
        if val:
            ctx[key] = val

    index = [{"name": t.name, "title": t.title, "category": t.category,
              "rows": len(t), "columns": t.columns, "description": t.description,
              "sources": t.sources, "ndjson_file": t.name + ".ndjson"}
             for t in tables]
    with open(os.path.join(dirpath, "00_INDEX.json"), "w", encoding="utf-8") as fh:
        json.dump({"tool": "linsight.py", "version": VERSION,
                   "generated_from": meta, "tables": index}, fh, indent=1)

    for t in tables:
        cols = [str(c) for c in t.columns]
        ncol = len(cols)
        ti = next((cols.index(c) for c in NDJSON_TIME_COLUMNS if c in cols), -1)
        path = os.path.join(dirpath, t.name + ".ndjson")
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            for row in t.iter_rows():
                ev = {NDJSON_PREFIX + "table": t.name}
                ev.update(ctx)
                for i in range(min(ncol, len(row))):
                    v = row[i]
                    if v not in (None, ""):
                        ev[cols[i]] = _s(v)
                if 0 <= ti < len(row):
                    epoch = _epoch_utc(row[ti])
                    if epoch is not None:
                        ev["_time"] = epoch
                fh.write(json.dumps(ev, ensure_ascii=False,
                                    separators=(",", ":"), default=str) + "\n")
    return len(tables) + 1


def write_tables_json(tables, path, meta=None):
    """Streamed - the bodyfile table alone can be a couple of hundred thousand rows."""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write('{\n"tool": "linsight.py",\n"version": %s,\n' % json.dumps(VERSION))
        fh.write('"generated_from": %s,\n' % json.dumps(meta or {}))
        fh.write('"index": %s,\n' % json.dumps(
            [{"name": t.name, "title": t.title, "category": t.category,
              "rows": len(t), "columns": t.columns, "description": t.description}
             for t in tables], indent=1))
        fh.write('"tables": {\n')
        for i, t in enumerate(tables):
            fh.write("%s%s: {\n" % (",\n" if i else "", json.dumps(t.name)))
            fh.write('  "title": %s,\n  "category": %s,\n  "description": %s,\n'
                     % (json.dumps(t.title), json.dumps(t.category),
                        json.dumps(t.description)))
            fh.write('  "sources": %s,\n' % json.dumps(t.sources))
            fh.write('  "columns": %s,\n' % json.dumps(t.columns))
            fh.write('  "row_count": %d,\n  "rows": [' % len(t))
            for j, row in enumerate(t.iter_rows()):
                fh.write("%s%s" % ("," if j else "",
                                   json.dumps([_s(v) for v in row])))
            fh.write("]\n }")
        fh.write("\n}\n}\n")


# -- HTML browser ------------------------------------------------------------


def _script_json(obj):
    """JSON safe to embed inside a <script> element.

    json.dumps leaves '<' alone, so a cell containing '</script>' closes the
    script early and the rest of the payload is parsed as HTML: the page ends
    up with dozens of script elements, __TABLES__ never gets assigned and the
    browser renders an empty shell. A forensic export is exactly the input that
    hits this - the collection had a saved GitHub page sitting in /etc/php, and
    the artifact tables carry web content, log lines and shell history verbatim
    by design.

    Escaping every '<' as \\u003c is still valid JSON (the parser decodes it
    back to '<') and removes the whole class of hazard at once: </script>,
    <!-- and <script all stop being HTML tokens. '<' only ever appears inside
    string values here, so nothing structural is touched.
    """
    return json.dumps(obj).replace("<", "\\u003c")


#: A table whose rows are smaller than this stays inline in the page, as
#: plain JSON. Most tables are tiny - forty of the fifty-nine on a workstation
#: collection are under a few kilobytes - and compressing those buys nothing
#: while making the page need a decompressor before it can show anything at
#: all. Above it, compression is worth roughly twenty times its own weight.
PACK_MIN = 8192


def _packed_rows(table, limit):
    """(inline rows, base64 of gzipped rows) - exactly one of the two.

    Compressed per table rather than in one block, because the point is that
    the page opens without decoding all of it. A collection with three
    quarters of a million rows makes a 228 MB page, and a browser asked to
    parse that much JSON before it can draw anything either takes a minute
    over it or gives up. One table at a time, decoded when it is opened, is
    what makes 'every row is in the page' and 'the page opens' both true.

    The JSON is fed to the compressor a row at a time and never assembled -
    VAR_LOG alone runs to a million rows, and holding its text and its
    compressed form and the base64 of that at once is three copies of the
    largest thing in the export.
    """
    rows = (table.iter_rows() if limit is None
            else itertools.islice(table.iter_rows(), limit))
    co = zlib.compressobj(6, zlib.DEFLATED, 16 + zlib.MAX_WBITS)
    out, plain, n, small = [], [], 0, True
    for r in rows:
        text = "%s%s" % ("," if n else "[", _script_json([_s(v) for v in r]))
        n += 1
        if small:
            plain.append(text)
            if sum(len(x) for x in plain) > PACK_MIN:
                small = False
                out.append(co.compress("".join(plain).encode("utf-8")))
                plain = []
        else:
            out.append(co.compress(text.encode("utf-8")))
    if small:
        return json.loads("".join(plain) + "]") if n else [], ""
    out.append(co.compress(("]" if n else "[]").encode("utf-8")))
    out.append(co.flush())
    return None, base64.b64encode(b"".join(out)).decode("ascii")


# Artifact tables the console lists above the per-category nav, in this order.
# "is any of the known toolkit on this host at all" is the first question asked
# of a triage collection, and the answer was three categories down the sidebar
# under D for Detection - far enough that it read as a footnote to the parsing
# rather than as the point of it.
PINNED_TABLES = ("HACKTOOL_HITS", "HACKTOOL_VARIANTS")


def console_html(tables, html_cap=2000, meta=None, tri=None, opts=None,
                 served=False, css=None, js=None):
    """The console as a string, for --serve to hand out without a file."""
    buf = io.StringIO()
    _write_console(buf, tables, html_cap, meta, tri, opts, served, css, js)
    return buf.getvalue()


def write_tables_html(tables, path, html_cap=2000, meta=None, tri=None,
                      opts=None, served=False):
    """The console: triage views and every artifact table in one page.

    Self-contained by design - no server, no CDN, no fetch. The box that reads
    a triage collection is routinely the box that is not allowed to fetch
    anything, so the payload is embedded and the CSS and JS are inline.

    `tri` is optional: without it the page is the artifact browser alone, which
    is what a single-table export (--process-map p.html) should still produce.
    """
    with open(path, "w", encoding="utf-8") as fh:
        _write_console(fh, tables, html_cap, meta, tri, opts, served)


def _write_console(fh, tables, html_cap, meta, tri, opts, served,
                   css=None, js=None):
    """Build the payload and emit the page - shared by the file and the server."""
    esc, index, tbls, packed = htmllib.escape, [], {}, {}
    for t in tables:
        index.append({"name": t.name, "title": t.title,
                      "category": t.category or "Other", "rows": len(t)})
        limit = html_cap or None
        rows, blob = (None, "") if served else _packed_rows(t, limit)
        d = {"name": t.name, "title": t.title, "category": t.category,
             "description": t.description, "sources": t.sources,
             "columns": t.columns, "row_count": len(t),
             "rows_included": min(len(t), limit) if limit else len(t),
             "cap": 500}
        if blob:
            packed[t.name] = blob
        elif rows is not None:
            d["rows"] = rows
        # Served, the rows key is left off entirely rather than set to an
        # empty list. The page treats "rows is undefined" as "not loaded yet"
        # and asks the database; an empty list is a loaded table with nothing
        # in it, so shipping one made all 47 tables look empty and nothing
        # ever fetched.
        tbls[t.name] = d
    views = {v: n for v, n in (("findings", "FINDINGS"),
                               ("timeline", "TIMELINE"))
             if n in tbls}
    payload = {"meta": [], "tactics": ATTACK_TACTICS, "order": ATTACK_ORDER,
               "version": VERSION, "index": index, "tables": tbls,
               "views": views,
               "pinned": [n for n in PINNED_TABLES if n in tbls],
               "tcols": list(CONSOLE_TIME_COLUMNS),
               "spancols": ["first_utc", "last_utc"],
               # Told to the page rather than sniffed by it: a console served
               # by --serve keeps its marks in the case file over the API, and
               # the same page opened from disk keeps them in localStorage.
               "served": bool(served),
               # A merged multi-collection export: which collections are in
               # it, and the column every row carries saying which one. The
               # page needs both told to it rather than sniffed - the rows
               # are packed per table and decoded on demand, and scanning
               # every one at boot to find out is the cost that design exists
               # to avoid.
               "hosts": list((meta or {}).get("hosts") or []),
               "hostcol": (meta or {}).get("host_column") or "",
               # The correlation drawn, for the tab that otherwise opens with
               # twelve grids and no shape. Built here rather than in the page
               # because it is the same drawing the export writes to
               # correlation.svg, and two implementations of one picture is
               # one of them being wrong later.
               "corrsvg": build_svg(tables, meta) if len(
                   (meta or {}).get("hosts") or []) > 1 else ""}
    if tri is not None:
        payload.update(_triage_payload(tri, opts))
    elif meta:
        payload["meta"] = [[k, str(v)] for k, v in meta.items() if v]
    host = (tri.meta.get("Hostname") if tri is not None else None) or \
           (meta or {}).get("Hostname") or "collection"
    src = tri.col.path if tri is not None else (meta or {}).get("Collection", "")
    _emit_console(fh, esc, host, src, payload, packed, css, js)


def _emit_console(fh, esc, host, src, payload, packed, css=None, js=None):
    css = css or APP_CSS
    js = js or APP_JS
    if True:
        fh.write("<!doctype html><html><head><meta charset='utf-8'>"
                 "<meta name='viewport' content='width=device-width,initial-scale=1'>"
                 "<title>linsight - %s</title><style>%s</style></head><body>"
                 % (esc(str(host)), css))
        fh.write("<header><div class='brand'><b>linsight</b>"
                 "<span>PARSE LINUX DEEP. HUNT THE MALICIOUS.</span></div>"
                 "<div class='host'><b>%s</b> &nbsp;<code>%s</code></div>"
                 "<div class='tf'>"
                 "<input id='t0' type='search' placeholder='from'"
                 " title='click for a calendar - or type YYYY-MM-DD, "
                 "YYYY-MM-DD HH:MM, -24h, -7d'>"
                 "<span class='ar'>&rarr;</span>"
                 "<input id='t1' type='search' placeholder='to'"
                 " title='click for a calendar - or type YYYY-MM-DD, "
                 "YYYY-MM-DD HH:MM, -24h, -7d'>"
                 "<button class='clr' id='tclr' title='clear the time window'>"
                 "&times;</button></div>"
                 "<button class='themebtn' id='theme' "
                 "title='light / dark'>&#9681;</button>"
                 "<div class='hf' id='hf'></div>"
                 "<div class='chips' id='chips'></div></header>"
                 "<div class='cal' id='cal'></div>"
                 % (esc(str(host)), esc(str(src))))
        fh.write("<div class='layout'><nav id='nav'></nav>"
                 "<main id='main'></main></div>")
        fh.write("<script>window.__LINSIGHT__=%s;</script>" % _script_json(payload))
        # written a table at a time rather than through json.dumps: this is
        # the large half of the file, and base64 is already JSON-safe - it
        # has no quote, no backslash and no '<' to escape.
        fh.write("<script>window.__ROWS__={")
        for i, (name, blob) in enumerate(sorted(packed.items())):
            fh.write('%s%s:"%s"' % ("," if i else "", json.dumps(name), blob))
        fh.write("};</script>")
        fh.write("<script>%s</script></body></html>" % js)


def write_single_table(table, path, html_cap=100000):
    """Write one table to one file; the format follows the extension."""
    ext = os.path.splitext(path)[1].lower()
    if ext == ".json":
        write_tables_json([table], path)
    elif ext in (".html", ".htm"):
        write_tables_html([table], path, html_cap)
    else:
        with open(path, "w", newline="", encoding="utf-8-sig") as fh:
            w = csv.writer(fh)
            w.writerow(table.columns)
            for row in table.iter_rows():
                w.writerow([_s(v) for v in row])
    return ext or ".csv"


def _check_output_paths(col, opts):
    """Never write output into the evidence.

    It contaminates the collection, and the next run would then parse the
    previous run's own tables back in as artifacts.
    """
    if col is None or col.kind != "dir":
        return
    base = os.path.abspath(col.path)
    for path in (opts.export, opts.csv_dir, opts.tables_json, opts.tables_html,
                 opts.json, opts.html, opts.timeline, opts.process_map):
        if not path:
            continue
        full = os.path.abspath(path)
        if full == base or full.startswith(base + os.sep):
            raise SystemExit(
                "[!] refusing to write inside the collection:\n"
                "      %s\n"
                "    output would become part of the evidence - choose a path "
                "outside\n      %s" % (full, base))


def export_tables(tri, col, opts, tb=None):
    """Build every table once, then write whichever formats were requested."""
    _check_output_paths(col, opts)          # fail before a minute of parsing
    prebuilt = tb is not None
    tb = tb or TableBuilder(col, tri)

    # --process-map on its own only needs the one extractor, not all 60
    only_map = opts.process_map and not any(
        (opts.export, opts.csv_dir, opts.tables_json, opts.tables_html))
    if only_map:
        # a prebuilt builder already has it; rebuilding would append a second
        # PROCESS_MASTER to the same builder and re-do the correlation
        if not prebuilt:
            tb.build(only=["t_process_master"], verbose=not opts.quiet)
        master = next((t for t in tb.tables if t.name == "PROCESS_MASTER"), None)
        if master is None:
            raise SystemExit("[!] no process artifacts found in this collection")
        ext = write_single_table(master, opts.process_map, opts.html_rows)
        print("[+] process map written to %s (%d processes, %d columns, %s)"
              % (opts.process_map, len(master), len(master.columns), ext),
              file=sys.stderr)
        return [master]

    scope = getattr(opts, "scope", "full")
    # rules were run before the console report, so the tables already exist -
    # rebuilding would re-scan every artifact and double every rule finding
    tables = tb.tables if prebuilt else tb.build(verbose=not opts.quiet,
                                                 scope=scope)
    meta = {
        "collection": col.path,
        "hostname": tri.meta.get("Hostname", tri.meta.get("hostname", "")),
        "collected": tri.meta.get("Collection finished", ""),
        "scope": scope,
        "layout": col.layout,
        "tables": len(tables),
        "rows_total": sum(len(t) for t in tables),
    }
    status("[*] built %d tables, %s rows total%s"
          % (len(tables), "{:,}".format(meta["rows_total"]),
             "" if scope == "full" else
             " (--scope %s: %s artifacts only)"
             % (scope, "live response" if scope == "live" else "on-disk")))

    return _emit_outputs(tri, tables, meta, opts, tb)


def write_merged_tables(tri, tables, meta, opts):
    """The same writers, over a table set somebody else built.

    A merged multi-host export has no TableBuilder behind it - the tables were
    built once per collection and joined afterwards - so the half of
    export_tables that decides what to write is shared and the half that
    builds is not.
    """
    _check_output_paths(None, opts)
    status("[*] writing the merged export: %d table(s), %s row(s)"
           % (len(tables), "{:,}".format(meta.get("rows_total", 0))))
    return _emit_outputs(tri, tables, meta, opts, None)


def _emit_outputs(tri, tables, meta, opts, tb=None):
    """Whichever formats were asked for, over the tables as they now stand."""
    outdir = opts.export
    # Serving, the database is what the console reads and what an examiner
    # queries; the CSV and NDJSON directories exist for tools outside this
    # one. Writing all three means serialising every row three times - on a
    # 3.4M-row collection that is minutes of the wait before the server comes
    # up, spent on files nothing in the session will open. Asked for
    # explicitly they are still written; derived from --export they are not.
    serving = bool(getattr(opts, "serve", None))
    csv_dir = opts.csv_dir or (None if serving else
                               (os.path.join(outdir, "csv") if outdir else None))
    # --export writes one .json per table, mirroring the CSV directory.
    # --tables-json FILE still writes the single combined document, for a
    # consumer that wants one file to load.
    json_dir = None if serving else (os.path.join(outdir, "json")
                                     if outdir else None)
    json_path = opts.tables_json
    html_path = opts.tables_html or (os.path.join(outdir, "browser.html") if outdir else None)

    if outdir:
        os.makedirs(outdir, exist_ok=True)
    writer_times = []
    # The correlation, drawn. Written whenever the table set holds the
    # cross-host tables and there is somewhere to put it - it costs
    # milliseconds, it is the first thing anybody opens on a multi-host case,
    # and asking for it with a flag would mean most runs never see it.
    if outdir:
        t0 = time.perf_counter()
        if write_correlation_svg(tables, os.path.join(outdir,
                                                      "correlation.svg"), meta):
            writer_times.append(("draw correlation", time.perf_counter() - t0))
    if csv_dir:
        t0 = time.perf_counter()
        n = write_tables_csv(tables, csv_dir)
        writer_times.append(("write CSV", time.perf_counter() - t0))
        print("[+] %d CSV files written to %s" % (n, csv_dir), file=sys.stderr)
    if json_dir:
        t0 = time.perf_counter()
        n = write_tables_ndjson(tables, json_dir, meta)
        writer_times.append(("write NDJSON (per table)", time.perf_counter() - t0))
        status("[+] %d NDJSON files written to %s (one JSON object per row)"
               % (n, json_dir))
    if json_path:
        t0 = time.perf_counter()
        write_tables_json(tables, json_path, meta)
        writer_times.append(("write JSON (combined)", time.perf_counter() - t0))
        print("[+] combined table JSON written to %s" % json_path, file=sys.stderr)
    # A database without a server. --db asked for one; whether a server is
    # also wanted is a separate question, and answering "no database" because
    # --serve was absent is the sort of silent nothing this tool is supposed
    # not to do.
    if getattr(opts, "db", None) and not getattr(opts, "serve", None):
        t0 = time.perf_counter()
        CaseDB(opts.db).build(tables, tri.meta if tri is not None else meta)
        writer_times.append(("write SQLite", time.perf_counter() - t0))
    if getattr(opts, "serve", None):
        # The server is the output. Building a page as well would write a
        # second, immediately stale copy of the same console beside the live
        # one, and leave the examiner unsure which of the two holds the marks.
        case = (opts.case or (os.path.join(outdir, "case.json") if outdir
                              else "case.json"))
        def _page():
            # Rebuilt per request so that a rebuilt linsight.py reaches an
            # already-running server on a refresh. In served mode the payload
            # carries no rows, so this is a few hundred kilobytes of string
            # work rather than the whole export.
            css, js = live_assets()
            return console_html(tables, opts.html_rows, meta, tri, opts,
                                served=True, css=css, js=js)
        dbp = getattr(opts, "db", None)
        if dbp is None:
            dbp = os.path.join(outdir, "case.db") if outdir else "case.db"
        # Print the breakdown before handing the process to the server:
        # serve() blocks until Ctrl-C, so the report at the end of this
        # function was unreachable and --timing silently did nothing with
        # --serve - which is the one run where knowing the cost matters most,
        # because it is the long one.
        if getattr(opts, "timing", False):
            print_timing(tb, writer_times)
        serve(_page, case, opts.serve, tables=tables,
              meta=(tri.meta if tri is not None else meta),
              db_path=(dbp or None),
              llm={"url": getattr(opts, "llm_url", None) or ASK_URL,
                   "model": getattr(opts, "llm_model", None) or ""})
        return writer_times
    if html_path:
        t0 = time.perf_counter()
        write_tables_html(tables, html_path, opts.html_rows, meta, tri, opts)
        writer_times.append(("write HTML browser", time.perf_counter() - t0))
        # The page carries every row by default, so its size is a fact worth
        # printing rather than a surprise on opening it. The rows are gzipped
        # per table and decoded when that table is opened, so the size on
        # disk is roughly a twentieth of the evidence in it and opening the
        # page no longer means parsing all of it - but a search across all
        # tables does decode all of them, and that is held in memory.
        try:
            size = os.path.getsize(html_path)
        except OSError:
            size = 0
        rows = sum(len(t) for t in tables)
        print("[+] console written to %s (%d findings, %d tables, %s rows, %s)"
              % (html_path, len(tri.findings), len(tables), format(rows, ","),
                 human_size(size)), file=sys.stderr)
        if size > 40 * 1024 * 1024:
            status("[!] that page is %s because it holds every row, packed. "
                   "It opens without decoding all of it, but searching every "
                   "table does. --html-rows N caps the rows embedded in it; "
                   "the CSV and JSON exports are unaffected either way."
                   % human_size(size))
    if opts.process_map:
        master = next((t for t in tables if t.name == "PROCESS_MASTER"), None)
        if master is None:
            status("[!] no PROCESS_MASTER table to write")
        else:
            ext = write_single_table(master, opts.process_map, opts.html_rows)
            print("[+] process map written to %s (%d processes, %d columns, %s)"
                  % (opts.process_map, len(master), len(master.columns), ext),
                  file=sys.stderr)
    if getattr(opts, "timing", False):
        print_timing(tb, writer_times)
    return tables


def print_timing(tb, writer_times, top=15):
    """Where the run actually went, per extractor and per writer.

    A collection that takes minutes is usually one artifact, not the tool being
    slow overall, and the answer changes per collection - a web server's
    access_log, a host with a year of journal. Guessing which costs a rerun;
    this prints it.
    """
    rows = ([(lab, sec, n) for lab, sec, n in tb.timings]
            + [(lab, sec, None) for lab, sec in writer_times])
    total = sum(r[1] for r in rows)
    rows.sort(key=lambda r: -r[1])
    print("\n[*] timing: %.1fs accounted for, slowest %d:"
          % (total, min(top, len(rows))), file=sys.stderr)
    for lab, sec, n in rows[:top]:
        if sec < 0.05:
            break
        share = "%5.1f%%" % (100 * sec / total) if total else "     "
        print("      %-24s %7.2fs %s%s"
              % (lab, sec, share,
                 "" if n is None else "  %s rows" % format(n, ",")),
              file=sys.stderr)
