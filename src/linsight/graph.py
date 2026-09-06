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

CARD_W, CARD_H = 210, 74
EXT_W, EXT_H = 190, 74
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


#: Width of an average character as a fraction of the font size. SVG has no
#: text metrics without a renderer, so the fit is estimated - generously, so
#: the estimate errs toward wrapping early rather than toward overflowing a
#: card, which is the failure a reader actually sees.
CHAR_W = 0.56


def _fits(text, px, size):
    return len(str(text)) * size * CHAR_W <= px


def _wrap(text, px, size, lines=1):
    """Break text to fit a width, on word boundaries. -> [line, ...]

    Truncating by character count cut words in half - 'authentication source,
    failed a…' - and still overflowed, because a character count is not a
    width. This measures, breaks where there is a space, and only ellipsises
    when the last line it is allowed still does not fit.
    """
    text = " ".join(str(text or "").split())
    if not text:
        return []
    budget = max(4, int(px / (size * CHAR_W)))
    out, rest = [], text
    while rest and len(out) < lines:
        if len(rest) <= budget:
            out.append(rest)
            return out
        cut = rest.rfind(" ", 0, budget + 1)
        if cut <= 0 or len(out) + 1 == lines:
            break
        out.append(rest[:cut])
        rest = rest[cut + 1:].strip()
    if rest:
        if len(rest) <= budget:
            out.append(rest)
        else:
            # no space to break at, or out of lines: cut, and say it was cut
            out.append(rest[: max(1, budget - 1)].rstrip() + "…")
    return out


def _short(text, n):
    """A single line, cut on a word boundary where there is one."""
    text = " ".join(str(text or "").split())
    if len(text) <= n:
        return text
    cut = text.rfind(" ", 0, n)
    return (text[:cut] if cut > n // 2 else text[: n - 1]).rstrip() + "…"


class _Edge(object):
    """One arrow: a pair of nodes, what passed between them, how much."""

    __slots__ = ("a", "b", "kind", "n", "label", "lane", "along", "flip",
                 "first")

    def __init__(self, a, b, kind, n, label):
        self.a, self.b, self.kind, self.n, self.label = a, b, kind, n, label
        self.lane, self.along, self.flip = 0.0, 0.5, False
        self.first = ""


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
        # The address under the name, because the address is what every arrow
        # in this picture is about - a login is from 192.168.2.100 until a row
        # says whose that is. The hostname goes in the body: it is what the
        # machine calls itself, which is worth reading and is not what the
        # edges join on. Printing it in both places, which this did, wasted
        # the widest line on the card saying one thing twice.
        # Name, address, and what its own run concluded - nothing else. A
        # relationship diagram is read for its arrows; a paragraph inside
        # every node competes with them and wins, which is what made the
        # first two versions of this unreadable.
        notes = []
        if sev:
            notes.append(", ".join(sev))
        nodes.append({"key": label, "kind": "host", "title": label,
                      "sub": r.get("addresses") or r.get("hostname") or "",
                      "lines": notes,
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
        # `why` is every provenance label that indicator collected, joined.
        # On a busy address that is three sentences of comma-separated text;
        # as one wrapped block it filled the card and still got cut. One
        # reason per line, the three most specific, and the count says how
        # many there were.
        why = [w.strip() for w in (r.get("why") or "").split(",") if w.strip()]
        lines = [_short(why[0], 26)] if why else ["seen on several hosts"]
        tail = []
        if r.get("total_mentions"):
            tail.append("%s mention(s)" % r["total_mentions"])
        if r.get("spread"):
            tail.append("over %s" % r["spread"])
        if tail:
            lines.append(" · ".join(tail))
        out.append({"key": value, "kind": "ext", "title": value,
                    "sub": "outside the case", "lines": lines,
                    "rank": (len(hosts), _int(r.get("total_mentions")))})
    out.sort(key=lambda n: n["rank"], reverse=True)
    return out[:cap]


#: Which relation a pair's line is coloured and named by when it carries
#: several. A sign-in is the strongest claim - one machine authenticated to
#: another - then movement of a file, then a command that names a host, then
#: an attempt that was refused.
KIND_ORDER = ("session", "move", "command", "refused")

#: The short form each relation takes when a pair carries more than one, so a
#: line reads "84 sign-ins · 13 cmd" rather than three sentences stacked.
SHORT = {"session": "%d sign-in%s", "refused": "%d refused",
         "command": "%d cmd", "move": "%d file%s"}


def _edges(tables, known):
    """One arrow per direction, naming everything that direction carries.

    Not one arrow per relation. Two machines in one case are related several
    ways at once, and drawn separately those lines start and end at the same
    two cards - on a three-host cluster that was nineteen lines over six
    routes, with five labels printed at a single point. The pair is the fact a
    reader wants ("these two talk, this way round, this much"); which tables
    say so is the label, and the full detail is a click away in the grids.
    """
    agg, firsts = {}, {}

    def stamp(a, b, when):
        """The earliest time anything passed this way, for the arrow label."""
        when = (when or "").strip()
        if when and (not firsts.get((a, b)) or when < firsts[(a, b)]):
            firsts[(a, b)] = when

    for name, kind, ok_col in (("CROSS_SESSIONS", None, "result"),
                               ("CROSS_COMMANDS", "command", None),
                               ("CROSS_TRANSFERS", "move", None)):
        for r in _graph_rows(tables, name):
            a, b = r.get("from_collection"), r.get("to_collection")
            if a not in known or b not in known or a == b:
                continue
            k = kind
            if k is None:
                k = ("refused" if "fail" in (r.get(ok_col) or "").lower()
                     else "session")
            agg.setdefault((a, b), {}).setdefault(k, 0)
            agg[(a, b)][k] += 1
            stamp(a, b, r.get("timestamp_utc") or r.get("first_utc"))
    for r in _graph_rows(tables, "CROSS_IOCS"):
        a, b = (r.get("first_host") or ""), (r.get("last_host") or "")
        if a in known and b in known and a != b:
            agg.setdefault((a, b), {}).setdefault("move", 0)
            agg[(a, b)]["move"] += 1
            stamp(a, b, r.get("first_utc"))

    out = []
    for (a, b), kinds in agg.items():
        parts = []
        for k in KIND_ORDER:
            n = kinds.get(k)
            if not n:
                continue
            fmt = SHORT[k]
            parts.append(fmt % ((n, "" if n == 1 else "s")
                                if "%s" in fmt else n))
        lead = next(k for k in KIND_ORDER if kinds.get(k))
        e = _Edge(a, b, lead, sum(kinds.values()), " · ".join(parts))
        e.first = firsts.get((a, b), "")
        out.append(e)
    out.sort(key=lambda e: -e.n)
    return _fan(out)


def _findings(tables):
    """The correlation's own findings, dated, earliest first.

    In a merged export FINDINGS holds every host's findings too, so the
    correlation's are the ones whose category says so - the same column the
    console filters on. In a --split correlation the whole table is theirs.
    """
    out = []
    for r in _graph_rows(tables, "FINDINGS"):
        if (r.get("category") or "") != "Correlation":
            continue
        when = (r.get("first_utc") or "").strip()
        if not when:
            continue
        out.append((when, r.get("severity") or "INFO",
                    r.get("title") or "", r.get("artifact") or ""))
    out.sort()
    return out


def _moment(tables):
    """The first time one of these machines signed in to another.

    The turn in a multi-host case, and the one line a reader wants before any
    table: not that the machines are related, but when the relation started
    and which way it ran. Derived rather than narrated - the earliest row of
    CROSS_SESSIONS that succeeded.
    """
    best = None
    for r in _graph_rows(tables, "CROSS_SESSIONS"):
        when = (r.get("timestamp_utc") or "").strip()
        if not when or "fail" in (r.get("result") or "").lower():
            continue
        if best is None or when < best[0]:
            best = (when, r.get("from_collection") or "",
                    r.get("to_collection") or "", r.get("user") or "",
                    r.get("service") or "")
    return best


def _per_host(tables, labels):
    """What the correlation says about each collection, one line each."""
    out = {}
    for label in labels:
        outbound = inbound = 0
        for r in _graph_rows(tables, "CROSS_SESSIONS"):
            if "fail" in (r.get("result") or "").lower():
                continue
            if r.get("from_collection") == label:
                outbound += 1
            elif r.get("to_collection") == label:
                inbound += 1
        notable = 0
        for name in ("CROSS_PERSISTENCE", "CROSS_PRIVILEGE"):
            for r in _graph_rows(tables, name):
                if r.get("notable") != "yes":
                    continue
                if label in [h.strip() for h in
                             (r.get("hosts") or "").split(",")]:
                    notable += 1
        bits = []
        if outbound or inbound:
            bits.append("%d sign-in%s out, %d in"
                        % (outbound, "" if outbound == 1 else "s", inbound))
        bits.append("%d marked notable" % notable if notable
                    else "nothing marked notable")
        out[label] = " · ".join(bits)
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


def _fan(edges):
    """Give every edge its own line.

    Two machines in one case are related several ways at once - they signed in
    to each other, one ran a command naming the other, a file is on both - and
    each direction has its own count. Drawn from centre to centre they are all
    the same segment: on a three-host cluster that put nineteen edges on six
    lines, arrowheads pointing both ways through each other and five labels
    printed at one point.

    So each ordered pair is offset perpendicular to its own line, and the two
    directions take opposite sides. The perpendicular is computed from the
    pair sorted by name, not from the direction being drawn, or a->b and b->a
    would compute mirrored perpendiculars and land back on top of each other.
    """
    for e in edges:
        # One line per direction, the two sides of the same route. Computed
        # from the pair sorted by name rather than from the direction being
        # drawn: a->b and b->a have mirrored perpendiculars, so taking each
        # edge's own would put both back on the same line.
        # Both halves are needed. The perpendicular is measured from the
        # pair sorted by name (`flip`), so the two directions share one
        # reference; the lane sign then puts them on opposite sides of it.
        # Flipping only one of the two cancels: mirror the reference and
        # mirror the side, and the return arrow lands back on the outbound
        # line, which is the thing this exists to prevent.
        e.flip = e.a > e.b
        e.lane = -16.0 if e.flip else 16.0
        e.along = 0.5
    return edges


def _offset(x1, y1, x2, y2, lane, flip):
    """Push a segment sideways by `lane`, on a side that does not depend on
    which way the arrow points.

    The perpendicular of b->a is the perpendicular of a->b mirrored, so
    offsetting each edge by its own perpendicular and flipping the sign for
    the return direction cancels out exactly - both directions land back on
    one line, which is the thing the lanes exist to prevent. `flip` is decided
    once from the pair sorted by name, and the perpendicular is taken from the
    segment as drawn, so the two directions end up on opposite sides.
    """
    dx, dy = x2 - x1, y2 - y1
    d = math.hypot(dx, dy) or 1.0
    if flip:                       # measure from the canonical direction
        dx, dy = -dx, -dy
    px, py = -dy / d * lane, dx / d * lane
    return x1 + px, y1 + py, x2 + px, y2 + py


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
    graph_bottom = int(max([n["y"] + CARD_H / 2 for n in hosts]
                           + [n["y"] + EXT_H / 2 for n in exts])) + 36
    height = graph_bottom + 118 + 30

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
        ox1, oy1, ox2, oy2 = _offset(a["x"], a["y"], b["x"], b["y"], e.lane,
                                     e.flip)
        x1, y1, x2, y2 = _trim(ox1, oy1, ox2, oy2, aw, ah, bw, bh)
        cls = "e-ext" if a["kind"] == "ext" else "e-" + e.kind
        mk = "ext" if a["kind"] == "ext" else e.kind
        s.append('<path class="e %s" d="M%.0f,%.0f L%.0f,%.0f" '
                 'marker-end="url(#a-%s)"><title>%s → %s: %s</title></path>'
                 % (cls, x1, y1, x2, y2, mk, _esc(e.a), _esc(e.b),
                    _esc(e.label)))
        # along the line rather than at its midpoint: several lanes share a
        # direction, and three labels stacked at one midpoint is the blob
        # this replaced
        mx = x1 + (x2 - x1) * e.along
        my = y1 + (y2 - y1) * e.along
        s.append('<text class="lbl" x="%.0f" y="%.0f" text-anchor="middle">%s'
                 '</text>' % (mx, my - 6, _esc(e.label)))
        if e.first:
            # when this route opened. The counts say how much passed; the
            # first stamp says when it started, which is the question asked
            # of a correlation before any other.
            s.append('<text class="t3" x="%.0f" y="%.0f" '
                     'text-anchor="middle">from %s</text>'
                     % (mx, my + 8, _esc(e.first[:16])))

    for n in hosts + exts:
        w, h = ((EXT_W, EXT_H) if n["kind"] == "ext" else (CARD_W, CARD_H))
        x, y = n["x"] - w / 2, n["y"] - h / 2
        accent = "--bad" if n["kind"] == "ext" else "--host"
        s.append('<g><rect class="card" x="%.0f" y="%.0f" width="%d" '
                 'height="%d" rx="10"/>' % (x, y, w, h))
        s.append('<rect x="%.0f" y="%.0f" width="4" height="%d" rx="2" '
                 'fill="var(%s)"/>' % (x, y, h, accent))
        inner = w - 28
        s.append('<text class="t1" x="%.0f" y="%.0f">%s</text>'
                 % (x + 14, y + 25,
                    _esc(_wrap(n["title"], inner, 14)[0])))
        if n.get("sub"):
            s.append('<text class="t3 mono" x="%.0f" y="%.0f">%s</text>'
                     % (x + 14, y + 42,
                        _esc(_wrap(n["sub"], inner, 10.5)[0])))
        yy = y + 64
        room = int((y + h - 12 - yy) / 17)
        for line in n["lines"]:
            if room <= 0:
                break
            for part in _wrap(line, inner, 11.5, lines=min(2, room)):
                s.append('<text class="t2" x="%.0f" y="%.0f">%s</text>'
                         % (x + 14, yy, _esc(part)))
                yy += 17
                room -= 1
        s.append("</g>")

    s.append(_legend(MARGIN, graph_bottom, width - 2 * MARGIN, edges, tables))
    s.append("</svg>")
    return "\n".join(s)


def _moment_and_legend(width, y, edges, tables):
    """The turn on the left, what the lines mean on the right."""
    out = []
    m = _moment(tables)
    half = (width - 2 * MARGIN - 20) // 2
    lx = MARGIN + (half + 20 if m else 0)
    if m:
        when, a, b, user, service = m
        out.append('<g><rect class="card" x="%d" y="%d" width="%d" height="104"'
                   ' rx="10"/>' % (MARGIN, y, half))
        out.append('<rect x="%d" y="%d" width="4" height="104" rx="2" '
                   'fill="var(--bad)"/>' % (MARGIN, y))
        out.append('<text class="t1" x="%d" y="%d">The first sign-in between '
                   'these machines</text>' % (MARGIN + 18, y + 26))
        out.append('<text class="t2 mono" x="%d" y="%d" fill="var(--bad)">%s'
                   '</text>' % (MARGIN + 18, y + 52, _esc(when)))
        out.append('<text class="t2" x="%d" y="%d">%s</text>'
                   % (MARGIN + 18, y + 72,
                      _esc(_wrap("%s \u2192 %s%s%s" % (
                          a, b, " as %s" % user if user else "",
                          " over %s" % service if service else ""),
                          half - 36, 11.5)[0])))
        out.append('<text class="t3" x="%d" y="%d">%s</text>'
                   % (MARGIN + 18, y + 90,
                      _esc(_wrap("Both clocks and both address lists have to "
                                 "be right for this.", half - 36, 10.5)[0])))
        out.append("</g>")
    out.append(_legend(lx, y, half if m else width - 2 * MARGIN, edges,
                       tables))
    return "\n".join(out)


def _timeline(width, y, rows):
    """The dated correlation findings, in the order they happened."""
    out = ['<g><text class="t1" x="%d" y="%d">What the correlation found, '
           'in order</text>' % (MARGIN, y + 22)]
    x0, x1 = MARGIN + 20, width - MARGIN - 20
    ty = y + 46
    out.append('<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="var(--line)" '
               'stroke-width="2"/>' % (x0, ty, x1, ty))
    step = (x1 - x0) / max(1, len(rows) - 1) if len(rows) > 1 else 0
    seat = int((x1 - x0) / max(1, len(rows)))
    for i, (when, sev, title, _src) in enumerate(rows):
        x = x0 + step * i if len(rows) > 1 else (x0 + x1) / 2
        colour = "--bad" if sev in ("CRITICAL", "HIGH") else "--host"
        out.append('<circle cx="%.0f" cy="%d" r="6" fill="var(%s)" '
                   'stroke="var(--surface)" stroke-width="2"><title>%s</title>'
                   '</circle>' % (x, ty, colour, _esc("%s  %s" % (when, title))))
        out.append('<text class="t3 mono" x="%.0f" y="%d" text-anchor="middle">'
                   '%s</text>' % (x, ty + 22, _esc(when[5:16])))
        # The point is labelled with the table it came from, not with the
        # finding's sentence: "5 route(s) of two hops between these
        # collections were travelled end to end" has no short form that fits
        # a timeline seat, and cutting it produces "these collections were
        # travelled...". The sentence is on the point, as its tooltip.
        seat_label = (_src or "").replace("CROSS_", "").replace("_", " ").lower()
        for j, part in enumerate(_wrap(seat_label or title, seat + 20, 10.5,
                                       lines=2)):
            out.append('<text class="t2" x="%.0f" y="%d" text-anchor="middle">'
                       '%s</text>' % (x, ty + 38 + j * 14, _esc(part)))
    out.append("</g>")
    return "\n".join(out)


def _strip(width, y, hosts, per_host):
    """One cell per collection: what the correlation says about each."""
    out = ['<g><text class="t1" x="%d" y="%d">Each collection, as the '
           'correlation sees it</text>' % (MARGIN, y + 20)]
    n = max(1, len(hosts))
    gap = 12
    w = (width - 2 * MARGIN - gap * (n - 1)) // n
    for i, node in enumerate(hosts):
        x = MARGIN + i * (w + gap)
        out.append('<rect class="card" x="%d" y="%d" width="%d" height="52" '
                   'rx="8"/>' % (x, y + 32, w))
        out.append('<rect x="%d" y="%d" width="4" height="52" rx="2" '
                   'fill="var(--host)"/>' % (x, y + 32))
        out.append('<text class="t1" x="%d" y="%d" font-size="13px">%s</text>'
                   % (x + 14, y + 54, _esc(_wrap(node["title"], w - 28, 13)[0])))
        out.append('<text class="t3" x="%d" y="%d">%s</text>'
                   % (x + 14, y + 72,
                      _esc(_wrap(per_host.get(node["key"], ""), w - 28,
                                 10.5)[0])))
    out.append("</g>")
    return "\n".join(out)


def _legend(x0, y, box_w, edges, tables):
    """What the lines mean, and what the picture was drawn from."""
    kinds = [("e-session", "session", "a sign-in from one collection to another"),
             ("e-refused", "refused", "a sign-in that was refused"),
             ("e-command", "command", "a command naming another collection"),
             ("e-move", "move", "a file or indicator seen on both"),
             ("e-ext", "ext", "something outside the case reaching into it")]
    used = set(e.kind for e in edges)
    out = ['<g><rect class="card" x="%d" y="%d" width="%d" height="104" '
           'rx="10"/>' % (x0, y, box_w)]
    out.append('<text class="t1" x="%d" y="%d">How to read the lines</text>'
               % (x0 + 18, y + 26))
    shown = [k for k in kinds if k[1] in used or k[1] == "ext"]
    per_col = 3
    colw = (box_w - 36) // max(1, (len(shown) + per_col - 1) // per_col)
    for i, (cls, kind, text) in enumerate(shown):
        lx = x0 + 18 + (i // per_col) * colw
        ly = y + 50 + (i % per_col) * 18
        out.append('<path class="e %s" d="M%d,%d L%d,%d" '
                   'marker-end="url(#a-%s)"/>' % (cls, lx, ly - 4, lx + 34,
                                                  ly - 4, kind))
        out.append('<text class="t2" x="%d" y="%d">%s</text>'
                   % (lx + 44, ly, _esc(_wrap(text, colw - 60, 11.5)[0])))
    counts = []
    for name in ("CROSS_SESSIONS", "CROSS_COMMANDS", "CROSS_TRANSFERS",
                 "CROSS_IOCS", "CROSS_KEYS", "CROSS_ACCOUNTS",
                 "CROSS_PERSISTENCE", "CROSS_PRIVILEGE"):
        n = len(_graph_rows(tables, name))
        if n:
            counts.append("%s %d" % (name.replace("CROSS_", "").lower(), n))
    for i, part in enumerate(_wrap("drawn from: " + (", ".join(counts)
                                   or "no cross table held a row"),
                                   box_w - 36, 10.5, lines=2)):
        out.append('<text class="t3" x="%d" y="%d">%s</text>'
                   % (x0 + 18, y + 82 + i * 13, _esc(part)))
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
