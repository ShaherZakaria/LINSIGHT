# -*- coding: utf-8 -*-
from __future__ import annotations



# ---------------------------------------------------------------------------
# severity / finding model
# ---------------------------------------------------------------------------

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

COLORS = {
    "CRITICAL": "\033[1;97;41m",
    "HIGH": "\033[1;31m",
    "MEDIUM": "\033[1;33m",
    "LOW": "\033[1;36m",
    "INFO": "\033[0;37m",
    "head": "\033[1;36m",
    "dim": "\033[2m",
    "bold": "\033[1m",
    "reset": "\033[0m",
}


class Finding:
    """One triage observation, with when it was seen and how often.

    first_seen / last_seen are the span of the dated occurrences behind the
    finding, normalised to UTC by the analyzer that raised it and never
    re-derived from the evidence text here: a line the parser wrote is already
    UTC while a line copied out of a log is host-local wall clock, and once
    both are strings in the same list nothing tells them apart.

    count is how many occurrences the finding covers, which is not
    len(evidence) - evidence is capped for readability, so "6204 files
    modified" is a count of 6204 carrying 60 lines. An undated artifact (a
    config file, a group membership) leaves the span empty rather than
    borrowing the collection time.
    """

    __slots__ = ("severity", "category", "title", "detail", "evidence",
                 "source", "mitre", "first_seen", "last_seen", "count")

    def __init__(self, severity, category, title, detail="", evidence=None,
                 source="", mitre="", first_seen="", last_seen="", count=None):
        self.severity = severity
        self.category = category
        self.title = title
        self.detail = detail
        self.evidence = list(evidence or [])
        self.source = source
        self.mitre = mitre
        self.first_seen = first_seen
        self.last_seen = last_seen
        self.count = len(self.evidence) if count is None else count

    def as_dict(self):
        return {
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "detail": self.detail,
            "evidence": self.evidence,
            "source": self.source,
            "mitre": self.mitre,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "count": self.count,
        }

    def seen_text(self):
        """'45 occurrence(s), 2026-06-11 10:02:14 .. 2026-06-11 11:40:03 UTC'."""
        parts = []
        if self.count:
            parts.append("%d occurrence(s)" % self.count)
        if self.first_seen and self.last_seen and self.first_seen != self.last_seen:
            parts.append("%s .. %s UTC" % (self.first_seen, self.last_seen))
        elif self.first_seen or self.last_seen:
            parts.append("%s UTC" % (self.first_seen or self.last_seen))
        return ", ".join(parts)


class Event:
    __slots__ = ("ts", "category", "description", "severity", "source")

    def __init__(self, ts, category, description, severity="INFO", source=""):
        self.ts = ts                      # aware datetime (UTC)
        self.category = category
        self.description = description
        self.severity = severity
        self.source = source

    def as_dict(self):
        return {
            "timestamp": self.ts.strftime("%Y-%m-%d %H:%M:%S UTC") if self.ts else "",
            "category": self.category,
            "description": self.description,
            "severity": self.severity,
            "source": self.source,
        }
