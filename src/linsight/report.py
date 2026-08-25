# -*- coding: utf-8 -*-
from __future__ import annotations

from collections import defaultdict
import csv
import html as htmllib
import json
import sys

from .constants import (
    AUTHOR, BANNER_ASCII, BANNER_BLOCK, SCALE_ASCII, SCALE_BLOCK, VERSION)
from .model import SEVERITIES, SEV_RANK
from .term import c, can_encode, trunc



# ---------------------------------------------------------------------------
# reporting
# ---------------------------------------------------------------------------





def print_banner(color, stream=None):
    """The mark, once, before any work - and never on stdout.

    stdout carries the report; a caller redirecting it to a file wants the
    findings in that file, not a masthead, and one piping it into another tool
    wants it even less. stderr is where the [*] status lines already go.
    """
    out = stream or sys.stderr
    # opts.color is decided by stdout, and this writes to stderr: one can be a
    # terminal while the other is a pipe, and colouring a pipe puts raw escape
    # sequences in whatever reads it.
    try:
        color = color and out.isatty()
    except Exception:
        color = False

    block = can_encode(out, BANNER_BLOCK)
    art = BANNER_BLOCK if block else BANNER_ASCII
    cell = SCALE_BLOCK if block else SCALE_ASCII
    scale = "".join(c(cell, sev, color) for sev in SEVERITIES)
    try:
        # normalised: one constant carries a leading newline and one does not,
        # and the masthead must not jump a line depending on the code page
        out.write("\n" + c(art.strip("\n"), "head", color) + "\n")
        out.write(" %s  %s\n" % (scale, c("parse linux deep. hunt the malicious.", "bold", color)))
        out.write(c(" v%s   developed by %s\n\n" % (VERSION, AUTHOR), "dim", color))
        out.flush()
    except Exception:
        pass          # a closed or undecodable stderr must not end the run


def print_console(tri, opts):
    color = opts.color
    out = sys.stdout
    findings = [f for f in tri.findings if SEV_RANK[f.severity] <= SEV_RANK[opts.min_severity]]
    counts = defaultdict(int)
    for f in tri.findings:
        counts[f.severity] += 1

    out.write("\n" + c("=" * 100, "head", color) + "\n")
    out.write(c("  LINUX TRIAGE REPORT", "bold", color) + "   v%s\n" % VERSION)
    out.write("  %-14s : %s\n" % ("collection", tri.col.path))
    # A disk image and an AD1 both name themselves: their layout is 'uac'
    # internally, because that is where the parsers look for a copied
    # filesystem, and printing that here would say the evidence came out of
    # UAC when it did not.
    layout = getattr(tri.col, "display_layout", "") or {
        "uac": "UAC",
        "velociraptor": "Velociraptor offline collector"}.get(
            tri.col.layout, tri.col.layout)
    out.write("  %-14s : %s\n" % ("layout", layout))
    for k, label in (("Hostname", "hostname"),
                     ("Hostname (from archive name)", "hostname"),
                     ("Distribution", "distribution"),
                     ("uname", "kernel"),
                     ("Kernel release", "kernel"),
                     ("Operating system", "os"), ("System architecture", "arch"),
                     ("Collection finished", "collected"), ("Host UTC offset", "host offset"),
                     ("Time zone", "time zone"), ("Command line", "collector command")):
        value = tri.meta.get(k)
        # 'os' and 'distribution' are the same answer once the distribution is
        # known, and printing it twice in a five-line header is noise
        if value and not (k == "Operating system"
                          and value == tri.meta.get("Distribution")):
            out.write("  %-14s : %s\n" % (label, trunc(str(value), 110)))
    out.write(c("=" * 100, "head", color) + "\n\n")

    out.write(c("  FINDING SUMMARY", "bold", color) + "\n")
    for sev in SEVERITIES:
        if counts[sev]:
            out.write("    %s  %d\n" % (c("%-9s" % sev, sev, color), counts[sev]))
    out.write("    %-9s  %d\n" % ("TOTAL", len(tri.findings)))

    top = [f for f in tri.findings if f.severity in ("CRITICAL", "HIGH")]
    if top:
        out.write("\n" + c("  HEADLINES", "bold", color) + "\n")
        for f in top[:12]:
            out.write("    %s %s\n" % (c("[%s]" % f.severity, f.severity, color), f.title))
    out.write("\n")

    for sev in SEVERITIES:
        block = [f for f in findings if f.severity == sev]
        if not block:
            continue
        out.write(c("-" * 100, "head", color) + "\n")
        out.write(c(" %s FINDINGS (%d)" % (sev, len(block)), sev, color) + "\n")
        out.write(c("-" * 100, "head", color) + "\n")
        for i, f in enumerate(block, 1):
            out.write("\n%s %s\n" % (c("[%s/%s]" % (sev[:4], i), sev, color),
                                     c(f.title, "bold", color)))
            out.write("    category : %s\n" % f.category)
            if f.mitre:
                out.write("    att&ck   : %s\n" % f.mitre)
            if f.source:
                out.write("    artifact : %s\n" % f.source)
            seen = f.seen_text()
            if seen:
                out.write("    seen     : %s\n" % seen)
            if f.detail:
                for line in wrap(f.detail, 92):
                    out.write("    %s\n" % c(line, "dim", color))
            shown = f.evidence[: opts.max_evidence]
            for e in shown:
                out.write("      | %s\n" % e)
            if len(f.evidence) > len(shown):
                out.write("      | ... %d more (use --max-evidence or --json)\n"
                          % (len(f.evidence) - len(shown)))
        out.write("\n")

    if opts.show_timeline and tri.events:
        # a console timeline is only useful if it fits on a screen: prefer the
        # events that were scored above INFO, and fall back when there are none
        notable = [e for e in tri.events if e.severity != "INFO"]
        shown_events = notable if len(notable) >= 10 else tri.events
        label = "notable events" if shown_events is notable else "events"
        out.write(c("-" * 100, "head", color) + "\n")
        out.write(c(" EVENT TIMELINE (last %d of %d %s; full list via --timeline)"
                    % (min(len(shown_events), opts.timeline_show), len(shown_events), label),
                    "head", color) + "\n")
        out.write(c("-" * 100, "head", color) + "\n")
        for e in shown_events[-opts.timeline_show:]:
            out.write("  %s  %-9s %-10s %s\n" % (
                e.ts.strftime("%Y-%m-%d %H:%M:%S"),
                c("%-9s" % e.severity, e.severity, color) if e.severity != "INFO" else "%-9s" % "",
                e.category, trunc(e.description, 110)))
        out.write("\n")


def wrap(text, width):
    out = []
    for para in text.split("\n"):
        line = ""
        for word in para.split():
            if len(line) + len(word) + 1 > width:
                out.append(line)
                line = word
            else:
                line = (line + " " + word).strip()
        out.append(line)
    return out


def write_json(tri, path):
    data = {
        "tool": "linsight.py", "version": VERSION,
        "collection": tri.col.path,
        "metadata": tri.meta,
        "summary": {s: sum(1 for f in tri.findings if f.severity == s) for s in SEVERITIES},
        "findings": [f.as_dict() for f in tri.findings],
        "events": [e.as_dict() for e in tri.events],
        "iocs": {k: sorted(v) for k, v in sorted(tri.iocs.items())},
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    print("[+] JSON written to %s" % path, file=sys.stderr)


def write_timeline(tri, path):
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["timestamp_utc", "severity", "category", "description", "source"])
        for e in tri.events:
            w.writerow([e.ts.strftime("%Y-%m-%d %H:%M:%S"), e.severity, e.category,
                        e.description, e.source])
    print("[+] timeline (%d events) written to %s" % (len(tri.events), path), file=sys.stderr)


HTML_CSS = """
:root{--bg:#f7f8fa;--fg:#1b1f24;--card:#fff;--line:#e3e6ea;--muted:#5b6570}
@media (prefers-color-scheme:dark){:root{--bg:#14171b;--fg:#e6e9ed;--card:#1c2026;--line:#2b3138;--muted:#98a2ad}}
*{box-sizing:border-box}
body{margin:0;padding:24px;background:var(--bg);color:var(--fg);
 font:14px/1.55 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
h1{font-size:22px;margin:0 0 4px} h2{font-size:16px;margin:28px 0 10px}
.meta{color:var(--muted);font-size:13px;margin-bottom:18px}
.meta code{font-size:12px}
.cards{display:flex;flex-wrap:wrap;gap:10px;margin:16px 0 26px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;
 padding:10px 16px;min-width:104px}
.card b{display:block;font-size:22px;line-height:1.1}
.card span{font-size:11px;letter-spacing:.06em;color:var(--muted)}
.f{background:var(--card);border:1px solid var(--line);border-left-width:5px;
 border-radius:8px;margin:0 0 10px;padding:12px 16px}
.f>summary{cursor:pointer;font-weight:600;list-style:none;display:flex;gap:10px;align-items:baseline}
.f>summary::-webkit-details-marker{display:none}
.tag{font-size:10px;font-weight:700;letter-spacing:.06em;padding:2px 7px;border-radius:4px;
 color:#fff;white-space:nowrap}
.CRITICAL{border-left-color:#b3132a}.CRITICAL .tag{background:#b3132a}
.HIGH{border-left-color:#d9531e}.HIGH .tag{background:#d9531e}
.MEDIUM{border-left-color:#c99700}.MEDIUM .tag{background:#c99700}
.LOW{border-left-color:#2b7fb8}.LOW .tag{background:#2b7fb8}
.INFO{border-left-color:#6b7684}.INFO .tag{background:#6b7684}
.detail{color:var(--muted);margin:8px 0}
.kv{font-size:12px;color:var(--muted);margin:2px 0}
pre{background:rgba(127,127,127,.09);border-radius:6px;padding:10px;overflow-x:auto;
 font:12px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace;margin:8px 0 0}
table{border-collapse:collapse;width:100%;font-size:12.5px;display:block;overflow-x:auto}
th,td{text-align:left;padding:5px 10px;border-bottom:1px solid var(--line);white-space:nowrap}
th{color:var(--muted);font-weight:600}
td.d{white-space:normal}
"""


def write_html(tri, path, opts):
    esc = htmllib.escape
    counts = {s: sum(1 for f in tri.findings if f.severity == s) for s in SEVERITIES}
    parts = ["<!doctype html><html><head><meta charset='utf-8'>",
             "<meta name='viewport' content='width=device-width,initial-scale=1'>",
             "<title>UAC triage - %s</title><style>%s</style></head><body>"
             % (esc(tri.meta.get("Hostname", "collection")), HTML_CSS)]
    parts.append("<h1>UAC triage report</h1><div class='meta'>")
    parts.append("<div><code>%s</code></div>" % esc(tri.col.path))
    for k, v in tri.meta.items():
        if v:
            parts.append("<div>%s: <code>%s</code></div>" % (esc(k), esc(str(v))))
    parts.append("</div><div class='cards'>")
    for s in SEVERITIES:
        parts.append("<div class='card %s'><b>%d</b><span>%s</span></div>" % (s, counts[s], s))
    parts.append("</div>")

    for sev in SEVERITIES:
        block = [f for f in tri.findings if f.severity == sev]
        if not block:
            continue
        parts.append("<h2>%s findings (%d)</h2>" % (sev.title(), len(block)))
        for f in block:
            openattr = " open" if sev in ("CRITICAL", "HIGH") else ""
            parts.append("<details class='f %s'%s><summary><span class='tag'>%s</span>%s</summary>"
                         % (sev, openattr, sev, esc(f.title)))
            if f.detail:
                parts.append("<div class='detail'>%s</div>" % esc(f.detail))
            parts.append("<div class='kv'>category: %s" % esc(f.category))
            if f.mitre:
                parts.append(" &nbsp;|&nbsp; ATT&amp;CK: %s" % esc(f.mitre))
            if f.source:
                parts.append(" &nbsp;|&nbsp; artifact: <code>%s</code>" % esc(f.source))
            parts.append("</div>")
            seen = f.seen_text()
            if seen:
                parts.append("<div class='kv'>seen: %s</div>" % esc(seen))
            if f.evidence:
                shown = f.evidence[:400]
                parts.append("<pre>%s</pre>" % esc("\n".join(shown)))
                if len(f.evidence) > len(shown):
                    parts.append("<div class='kv'>... %d more lines</div>"
                                 % (len(f.evidence) - len(shown)))
            parts.append("</details>")

    if tri.events:
        parts.append("<h2>Event timeline (%d)</h2><table><tr><th>time (UTC)</th><th>sev</th>"
                     "<th>category</th><th>event</th></tr>" % len(tri.events))
        for e in tri.events[-opts.timeline_limit:]:
            parts.append("<tr><td>%s</td><td>%s</td><td>%s</td><td class='d'>%s</td></tr>"
                         % (e.ts.strftime("%Y-%m-%d %H:%M:%S"), e.severity,
                            esc(e.category), esc(trunc(e.description, 300))))
        parts.append("</table>")

    parts.append("<p class='kv'>generated by linsight.py v%s</p></body></html>" % VERSION)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("".join(parts))
    print("[+] HTML report written to %s" % path, file=sys.stderr)
