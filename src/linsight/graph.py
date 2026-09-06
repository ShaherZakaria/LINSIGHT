# -*- coding: utf-8 -*-
"""The correlation, drawn: one SVG built from the cross-host tables.

The Correlation tab answers "what is true of more than one of these machines"
in twelve grids. This draws the same thing as one picture, because the first
question anybody asks of a multi-host case is which way it went, and a reader
gets that from an arrow faster than from a table of pairs.

Everything on the page is derived from the tables the correlator produced -
the hosts from HOSTS, the arrows from CROSS_SESSIONS, CROSS_COMMANDS,
CROSS_TRANSFERS and CROSS_IOCS, the notes under each host from its own
findings and from what the cross tables marked notable. Nothing about any
particular case is written into this file: hand it a different correlation and
it draws that one, with that one's counts.

Standalone SVG on purpose. It opens in any browser, embeds in a report, needs
no fonts and no JavaScript, and carries its own light and dark palette so it
reads on either surface - which a PNG cannot do and an HTML page cannot be
pasted into a document.
"""

from __future__ import annotations

import math
import os

from .term import status

#: Colour by the job it does, not by the entity. Validated as a categorical
#: set against both surfaces (worst all-pairs CVD dE 9.2 light / 9.4 dark);
#: `bad` is the fixed status-critical step and never doubles as a series.
#: Every edge also carries a written label, because three of these sit under
#: 3:1 on the light surface and colour must not be the only thing saying what
#: a line means.
LIGHT = {"surface": "#fcfcfb", "panel": "#ffffff", "line": "#d9d8d3",
         "ink": "#0b0b0b", "ink2": "#52514e", "ink3": "#75746f",
         "host": "#2a78d6", "move": "#eb6834", "admin": "#1baf7a",
         "bad": "#d03b3b", "dim": "#a3a29c"}
DARK = {"surface": "#1a1a19", "panel": "#232322", "line": "#3a3a37",
        "ink": "#ffffff", "ink2": "#c3c2b7", "ink3": "#9a998f",
        "host": "#3987e5", "move": "#d95926", "admin": "#199e70",
        "bad": "#d03b3b", "dim": "#6b6a64"}

CARD_W, CARD_H = 268, 150
EXT_W, EXT_H = 214, 128
MARGIN = 40


def _esc(text):
    return (str(text).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def _graph_rows(tables, name, wanted=None):
    """Rows of one table as dicts, or [] where the table was not built."""
    t = next((x for x in (tables or []) if getattr(x, "name", "") == name), None)
    if t is None:
        return []
    at = dict((c, i) for i, c in enumerate(t.columns))
    if wanted and not all(c in at for c in wanted):
        return []
    out = []
    for row in t.iter_rows():
        out.append(dict((c, (row[i] if i < len(row) else "") or "")
                        for c, i in at.items()))
    return out


def _int(value):
    try:
        return int(str(value).replace(",", "").strip() or 0)
    except (TypeError, ValueError):
        return 0


def _short(text, n):
    text = str(text)
    return text if len(text) <= n else text[: n - 1] + "…"


class _Edge(object):
    """One arrow: a pair of nodes, what passed between them, how much."""

    __slots__ = ("a", "b", "kind", "n", "label")

    def __init__(self, a, b, kind, n, label):
        self.a, self.b, self.kind, self.n, self.label = a, b, kind, n, label


def _host_nodes(tables):
    """One node per collection, with what its own run concluded about it."""
    nodes = []
    for r in _graph_rows(tables, "HOSTS"):
        label = r.get("collection") or r.get("host") or ""
        if not label:
            continue
        sev = []
        for key, name in (("critical", "critical"), ("high", "high")):
            n = _int(r.get(key))
            if n:
                sev.append("%d %s" % (n, name))
        notes = []
        if r.get("hostname") and r["hostname"] != label:
            notes.append(r["hostname"])
        if r.get("distribution"):
            notes.append(_short(r["distribution"], 30))
        nodes.append({"key": label, "kind": "host", "title": label,
                      "sub": r.get("input_address") or r.get("hostname") or "",
                      "lines": ([", ".join(sev)] if sev else []) + notes,
                      "findings": _int(r.get("findings"))})
    return nodes


def _own_addresses(tables):
    """Every address the collections in this case answer on."""
    own = set()
    for r in _graph_rows(tables, "HOSTS"):
        for a in (r.get("addresses") or "").split(","):
            a = a.strip()
            if a:
                own.add(a)
    return own


def _external_nodes(tables, host_labels, cap=2):
    """Addresses that reached more than one collection but are not one of them.

    A shared indicator that is an address and belongs to none of the machines
    in the case is, by construction, somewhere else that touched several of
    them. That is the node a reader looks for first, and it is derivable -
    CROSS_IOCS already ranks them by how many hosts saw them.

    "Not one of them" has to be checked against the addresses, not the
    labels. A cluster's own nodes appear in each other's indicators far more
    often than an intruder does, so filtering on the collection *name* drew
    two of the machines as outsiders and pushed the one address that really
    was outside off the picture - on a three-host cluster, .100 and .102 were
    drawn as strangers and the attacker was not drawn at all.
    """
    own = _own_addresses(tables)
    out = []
    for r in _graph_rows(tables, "CROSS_IOCS"):
        if r.get("type") not in ("ipv4", "ipv6"):
            continue
        value = (r.get("indicator") or "").strip()
        if not value or value in host_labels or value in own:
            continue
        hosts = [h.strip() for h in (r.get("hosts") or "").split(",") if h.strip()]
        if len(hosts) < 2 or set(hosts) - set(host_labels):
            continue
        lines = [_short(r.get("why") or "seen on several hosts", 34)]
        if r.get("total_mentions"):
            lines.append("%s mention(s)" % r["total_mentions"])
        if r.get("spread"):
            lines.append("spread %s" % r["spread"])
        out.append({"key": value, "kind": "ext", "title": value,
                    "sub": "not one of these collections", "lines": lines,
                    "rank": (len(hosts), _int(r.get("total_mentions")))})
    out.sort(key=lambda n: n["rank"], reverse=True)
    return out[:cap]


def _edges(tables, known):
    """Every arrow the cross tables support, aggregated per pair and kind."""
    agg = {}

    def bump(a, b, kind, n, label):
        if a not in known or b not in known or a == b:
            return
        got = agg.get((a, b, kind))
        if got is None:
            agg[(a, b, kind)] = _Edge(a, b, kind, n, label)
        else:
            got.n += n

    for r in _graph_rows(tables, "CROSS_SESSIONS"):
        ok = "fail" not in (r.get("result") or "").lower()
        bump(r.get("from_collection"), r.get("to_collection"),
             "session" if ok else "refused", 1, "")
    for r in _graph_rows(tables, "CROSS_COMMANDS"):
        bump(r.get("from_collection"), r.get("to_collection"), "command", 1, "")
    for r in _graph_rows(tables, "CROSS_TRANSFERS"):
        bump(r.get("from_collection"), r.get("to_collection"), "move", 1, "")
    for r in _graph_rows(tables, "CROSS_IOCS"):
        a, b = (r.get("first_host") or ""), (r.get("last_host") or "")
        if a and b and a != b:
            bump(a, b, "move", 1, "")

    out = []
    for (a, b, kind), e in agg.items():
        e.label = {"session": "%d sign-in%s", "refused": "%d refused",
                   "command": "%d remote command%s",
                   "move": "%d shared file/indicator%s"}[kind]
        e.label = (e.label % (e.n, "" if e.n == 1 else "s")
                   if "%s" in e.label else e.label % e.n)
        out.append(e)
    out.sort(key=lambda e: -e.n)
    return out


def _layout(hosts, exts, width):
    """Externals down the left, collections on an arc to the right of them.

    A ring rather than a row: with three or more collections a row puts every
    arrow on top of the same horizontal line, and the pair counts stop being
    readable. Two collections degenerate to a row, which is correct for two.
    """
    top = 150
    for i, n in enumerate(exts):
        n["x"] = MARGIN + EXT_W // 2
        n["y"] = top + i * (EXT_H + 30) + EXT_H // 2
    left = MARGIN + (EXT_W + 90 if exts else 0)
    span = width - left - MARGIN - CARD_W // 2
    cx = left + CARD_W // 2 + span * 0.45
    if len(hosts) == 1:
        hosts[0]["x"], hosts[0]["y"] = cx, top + CARD_H
        return
    if len(hosts) == 2:
        for i, n in enumerate(hosts):
            n["x"] = cx
            n["y"] = top + CARD_H // 2 + i * (CARD_H + 60)
        return
    r = max(150, min(span * 0.5, 40 + len(hosts) * 32))
    cy = top + CARD_H + r - 40
    for i, n in enumerate(hosts):
        ang = -math.pi / 2 + 2 * math.pi * i / len(hosts)
        n["x"] = cx + math.cos(ang) * r * 1.35
        n["y"] = cy + math.sin(ang) * r


def _trim(x1, y1, x2, y2, w1, h1, w2, h2):
    """Shorten a segment so it starts and ends outside both cards."""
    dx, dy = x2 - x1, y2 - y1
    d = math.hypot(dx, dy) or 1.0

    def edge(w, h):
        # distance from a card's centre to its border along this direction
        sx = (w / 2 + 8) / abs(dx / d) if dx else float("inf")
        sy = (h / 2 + 8) / abs(dy / d) if dy else float("inf")
        return min(sx, sy)

    a, b = edge(w1, h1), edge(w2, h2)
    if a + b >= d - 12:
        a = b = max(0.0, (d - 12) / 2)
    return (x1 + dx / d * a, y1 + dy / d * a,
            x2 - dx / d * b, y2 - dy / d * b)


def _style():
    def block(scope, pal):
        return "%s{%s}" % (scope, "".join(
            "--%s:%s;" % (k, v) for k, v in sorted(pal.items())))
    return """<style>
%s
@media (prefers-color-scheme: dark){:root:not([data-theme="light"]){%s}}
%s
.bg{fill:var(--surface)}
.card{fill:var(--panel);stroke:var(--line);stroke-width:1}
.t1{fill:var(--ink);font-size:14px;font-weight:650}
.t2{fill:var(--ink2);font-size:11.5px}
.t3{fill:var(--ink3);font-size:10.5px}
.lbl{fill:var(--ink2);font-size:10.5px;font-weight:600}
.hd{fill:var(--ink);font-size:19px;font-weight:700}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.e{fill:none;stroke-width:2}
.e-session{stroke:var(--admin)}
.e-refused{stroke:var(--dim);stroke-dasharray:5 4}
.e-command{stroke:var(--host)}
.e-move{stroke:var(--move);stroke-dasharray:9 4}
.e-ext{stroke:var(--bad)}
</style>""" % (block(":root", LIGHT),
               "".join("--%s:%s;" % (k, v) for k, v in sorted(DARK.items())),
               block(':root[data-theme="dark"]', DARK))


def build_svg(tables, meta=None):
    """The correlation as one SVG document. -> str, or '' if there is nothing."""
    hosts = _host_nodes(tables)
    if len(hosts) < 2:
        return ""
    labels = [n["key"] for n in hosts]
    exts = _external_nodes(tables, labels)
    known = set(labels) | set(n["key"] for n in exts)
    edges = _edges(tables, known)

    width = 1180
    _layout(hosts, exts, width)
    height = int(max([n["y"] + CARD_H for n in hosts]
                     + [n["y"] + EXT_H for n in exts] + [520])) + 190

    s = ['<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" '
         'width="%d" height="%d" role="img" aria-label="Correlation between '
         '%d collections" font-family="ui-sans-serif,-apple-system,Segoe UI,'
         'Roboto,Helvetica,Arial,sans-serif">' % (width, height, width, height,
                                                  len(hosts))]
    s.append("<title>Correlation across %d collections</title>" % len(hosts))
    s.append(_style())
    s.append('<rect class="bg" width="%d" height="%d"/>' % (width, height))
    s.append("<defs>")
    for kind, var in (("session", "--admin"), ("refused", "--dim"),
                      ("command", "--host"), ("move", "--move"),
                      ("ext", "--bad")):
        s.append('<marker id="a-%s" viewBox="0 0 10 10" refX="9" refY="5" '
                 'markerWidth="6" markerHeight="6" orient="auto-start-reverse">'
                 '<path d="M0,0 L10,5 L0,10 z" fill="var(%s)"/></marker>'
                 % (kind, var))
    s.append("</defs>")

    title = (meta or {}).get("hostname") or "%d collections" % len(hosts)
    s.append('<text class="hd" x="%d" y="46">Correlation — %s</text>'
             % (MARGIN, _esc(_short(title, 78))))
    s.append('<text class="t2" x="%d" y="70">Every node and count is read from '
             'the cross-host tables of this run. An arrow is drawn only where '
             'a table recorded the relation.</text>' % MARGIN)

    by_key = dict((n["key"], n) for n in hosts + exts)
    for e in edges:
        a, b = by_key[e.a], by_key[e.b]
        aw, ah = ((EXT_W, EXT_H) if a["kind"] == "ext" else (CARD_W, CARD_H))
        bw, bh = ((EXT_W, EXT_H) if b["kind"] == "ext" else (CARD_W, CARD_H))
        x1, y1, x2, y2 = _trim(a["x"], a["y"], b["x"], b["y"], aw, ah, bw, bh)
        cls = "e-ext" if a["kind"] == "ext" else "e-" + e.kind
        mk = "ext" if a["kind"] == "ext" else e.kind
        s.append('<path class="e %s" d="M%.0f,%.0f L%.0f,%.0f" '
                 'marker-end="url(#a-%s)"><title>%s → %s: %s</title></path>'
                 % (cls, x1, y1, x2, y2, mk, _esc(e.a), _esc(e.b),
                    _esc(e.label)))
        mx, my = (x1 + x2) / 2, (y1 + y2) / 2
        s.append('<text class="lbl" x="%.0f" y="%.0f" text-anchor="middle">%s'
                 '</text>' % (mx, my - 6, _esc(e.label)))

    for n in hosts + exts:
        w, h = ((EXT_W, EXT_H) if n["kind"] == "ext" else (CARD_W, CARD_H))
        x, y = n["x"] - w / 2, n["y"] - h / 2
        accent = "--bad" if n["kind"] == "ext" else "--host"
        s.append('<g><rect class="card" x="%.0f" y="%.0f" width="%d" '
                 'height="%d" rx="10"/>' % (x, y, w, h))
        s.append('<rect x="%.0f" y="%.0f" width="4" height="%d" rx="2" '
                 'fill="var(%s)"/>' % (x, y, h, accent))
        s.append('<text class="t1" x="%.0f" y="%.0f">%s</text>'
                 % (x + 14, y + 25, _esc(_short(n["title"], 26))))
        if n.get("sub"):
            s.append('<text class="t3 mono" x="%.0f" y="%.0f">%s</text>'
                     % (x + 14, y + 42, _esc(_short(n["sub"], 30))))
        yy = y + 64
        for line in n["lines"][:4]:
            s.append('<text class="t2" x="%.0f" y="%.0f">%s</text>'
                     % (x + 14, yy, _esc(_short(line, 32))))
            yy += 17
        s.append("</g>")

    s.append(_legend(width, height, edges, tables))
    s.append("</svg>")
    return "\n".join(s)


def _legend(width, height, edges, tables):
    """What the lines mean, and what the picture was drawn from."""
    kinds = [("e-session", "session", "a sign-in from one collection to another"),
             ("e-refused", "refused", "a sign-in that was refused"),
             ("e-command", "command", "a command naming another collection"),
             ("e-move", "move", "a file or indicator seen on both"),
             ("e-ext", "ext", "something outside the case reaching into it")]
    used = set(e.kind for e in edges)
    y = height - 150
    out = ['<g><rect class="card" x="%d" y="%d" width="%d" height="118" '
           'rx="10"/>' % (MARGIN, y, width - 2 * MARGIN)]
    out.append('<text class="t1" x="%d" y="%d">How to read the lines</text>'
               % (MARGIN + 18, y + 26))
    col, row = 0, 0
    for cls, kind, text in kinds:
        if kind not in used and kind != "ext":
            continue
        lx = MARGIN + 18 + col * 540
        ly = y + 52 + row * 24
        out.append('<path class="e %s" d="M%d,%d L%d,%d" '
                   'marker-end="url(#a-%s)"/>' % (cls, lx, ly - 4, lx + 44,
                                                  ly - 4, kind))
        out.append('<text class="t2" x="%d" y="%d">%s</text>'
                   % (lx + 56, ly, _esc(text)))
        row += 1
        if row > 2:
            row, col = 0, col + 1
    counts = []
    for name in ("CROSS_SESSIONS", "CROSS_COMMANDS", "CROSS_TRANSFERS",
                 "CROSS_IOCS", "CROSS_KEYS", "CROSS_ACCOUNTS",
                 "CROSS_PERSISTENCE", "CROSS_PRIVILEGE"):
        n = len(_graph_rows(tables, name))
        if n:
            counts.append("%s %d" % (name.replace("CROSS_", "").lower(), n))
    out.append('<text class="t3" x="%d" y="%d">drawn from: %s</text>'
               % (MARGIN + 18, y + 104, _esc(", ".join(counts) or "no cross "
                                             "table held a row")))
    out.append("</g>")
    return "\n".join(out)


def write_correlation_svg(tables, path, meta=None):
    """Write the diagram beside the rest of the export. -> path, or ''."""
    svg = build_svg(tables, meta)
    if not svg:
        return ""
    d = os.path.dirname(os.path.abspath(path))
    if d:
        os.makedirs(d, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(svg)
    status("[+] correlation diagram written to %s" % path)
    return path
