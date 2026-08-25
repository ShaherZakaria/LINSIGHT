# -*- coding: utf-8 -*-
from __future__ import annotations

import sys

from .model import COLORS

def trunc(s, n=180):
    s = s.strip()
    return s if len(s) <= n else s[: n - 3] + "..."
_PROGRESS = []                  # the bars currently drawing, outermost first
def status(msg, stream=None):
    """A [*]/[!] line that does not land on top of the progress bar.

    print() straight to stderr while a bar is drawn appends to it, which is how
    '[ 92%] building tables sigma[*] sigma: 407 rule(s) loaded' happens. Erase
    the bar first; the next step() redraws it.
    """
    for p in _PROGRESS:
        p.erase()
    print(msg, file=stream or sys.stderr)
class Progress:
    """A one-line percentage on stderr, rewritten in place.

    Only when stderr is a terminal: redirected to a file, a carriage-return
    progress bar turns one line into thousands and buries the [*] and [!] lines
    that matter. Everything here is cosmetic, so it never raises - a broken
    console must not end a parse that has run for four minutes.

    A nested bar - Sigma runs inside the table build - renders its parent's
    percentage alongside its own, because a bar that reads 92% and then 62% a
    moment later looks like the run went backwards.
    """

    def __init__(self, total, label, enabled=True, stream=None, parent=None):
        self.total = max(1, int(total or 1))
        self.label = label
        self.parent = parent
        self.n = 0
        self.width = 0
        self.stream = stream or sys.stderr
        try:
            self.on = bool(enabled) and self.stream.isatty()
        except Exception:
            self.on = False

    def pct(self):
        return min(100, int(100.0 * self.n / self.total))

    def step(self, name="", n=None):
        self.n = self.n + 1 if n is None else n
        if not self.on:
            return
        if self not in _PROGRESS:
            _PROGRESS.append(self)
        if self.parent is not None and self.parent.on:
            line = "  [%3d%%] %s %s %d%% %s" % (
                self.parent.pct(), self.parent.label, self.label,
                self.pct(), trunc(str(name), 34))
        else:
            line = "  [%3d%%] %s %s" % (self.pct(), self.label,
                                        trunc(str(name), 46))
        try:
            pad = max(0, self.width - len(line))
            self.stream.write("\r" + line + " " * pad)
            self.stream.flush()
            self.width = len(line)
        except Exception:
            self.on = False

    def erase(self):
        """Blank the line but stay live, so status() can print over it."""
        if not self.on or not self.width:
            return
        try:
            self.stream.write("\r" + " " * self.width + "\r")
            self.stream.flush()
            self.width = 0
        except Exception:
            self.on = False

    def done(self):
        if self in _PROGRESS:
            _PROGRESS.remove(self)
        if not self.on:
            return
        self.erase()
        self.on = False
def c(text, style, enabled):
    return "%s%s%s" % (COLORS[style], text, COLORS["reset"]) if enabled else text
def can_encode(stream, text):
    """Whether `stream` can actually render `text` in its own encoding.

    Asked before writing rather than caught after: a UnicodeEncodeError part
    way through leaves half a masthead on the terminal, and a console on cp437
    or cp1252 cannot draw block characters at all.
    """
    enc = getattr(stream, "encoding", None)
    if not enc:
        return False
    try:
        text.encode(enc)
        return True
    except (UnicodeEncodeError, LookupError, TypeError):
        return False
