#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
linsight.py - parse a Linux triage collection and highlight the critical /
interesting events.

Two collection layouts are understood, detected from the collection itself:

  UAC           (Unix-like Artifacts Collector) - command output under
                live_response/, the copied filesystem under [root]
  Velociraptor  offline collector - artifact results as JSONL under results/,
                the copied filesystem under uploads/<accessor>/

Works on an extracted collection directory OR directly on the .tar / .tar.gz /
.zip either tool produced. Pure standard library, Python 3.8+.

    python linsight.py <collection>                      # console report
    python linsight.py <collection> --html report.html   # + HTML report
    python linsight.py <collection> --json out.json --timeline tl.csv
    python linsight.py <collection> --min-severity HIGH  # only the loud stuff
    python linsight.py <collection> --pivot /dev/shm/kit # cross-artifact hunt
    python linsight.py <collection> --deep               # scan memory strings
    python linsight.py <collection> --update-sigma       # fetch SigmaHQ, hunt
    python linsight.py <collection> --sigma-cached       # ... offline, cached

Two output layers:

  findings  - the analyzers' severity-ranked conclusions (console/--html/--json)
  tables    - every interesting artifact normalised into a browsable grid, one
              table per artifact type, written as one CSV and one JSON per
              table plus an HTML browser:

    python linsight.py <collection> --export ./out     # csv/ json/ browser
    python linsight.py <collection> --csv-dir ./csv    # just the CSVs

The table layer can be narrowed to half the collection with --scope:

    --scope live      the volatile snapshot - process table, sockets, open
                      files, loaded modules, live sessions. State that existed
                      only while the host was running.
    --scope offline   what a dead-box examination recovers - the filesystem
                      copy, its configuration, its logs, persistence, bodyfile.
    --scope full      both (the default).

Findings, the timeline and the IOC list always run over the whole collection:
they exist to correlate across the two halves, so narrowing them would cost
answers rather than time. What --scope saves is the table build, which is where
the minutes go.

Design: every analyzer and every table extractor is independent and
failure-tolerant. A missing or malformed artifact degrades that one check,
never the run. Nothing is silently dropped: FILE_INVENTORY records which table
parsed each collected file, and UNPARSED_FILES lists whatever nothing claimed.

Three tables exist to make that accounting honest rather than merely true:

  COLLECTION_ERRORS  the .stderr UAC saved for each command, so an artifact
                     that is absent says whether the tool was missing, the
                     command was denied, or the profile never ran it
  UNPARSED_FILES     what no extractor claimed, with a reason - the rows that
                     read 'no extractor for this artifact' are the real
                     residue, the rest are classified (distribution reference
                     data, vendored source, application state)
  FILE_INVENTORY     one row per collected file naming the table that took it

UAC's own layout moves between profile generations - suid/sgid and the
filesystem surveys live under system/ in recent profiles and
live_response/system/ in the 2021 ones - so the extractors glob for artifacts
rather than naming a single path. A path spelled out in full silently produces
an empty table on the other profile, which reads as "this host had none of
that" and is a wrong answer, not a missing one.

The same rule drives Velociraptor support. Which artifacts a Velociraptor
collection holds is decided by whoever built the collector, so the artifact set
is discovered from results/ rather than assumed: an artifact this parser maps
lands in the matching table, and one it does not still reaches the export as
its own VELO_* table. VELO_ARTIFACTS lists every artifact found, its row count
and where it went, so 'no mapping for this artifact' is a visible line rather
than a missing table. The copied filesystem is read identically under either
layout, so /etc, /var/log, persistence, the histories and the YARA scan do not
care which tool collected them.
"""

from __future__ import annotations

import argparse
import atexit
import base64
import bz2
import csv
import fnmatch
import gzip
import html as htmllib
import io
import ipaddress
import itertools
import json
import lzma
import os
import re
import shutil
import sqlite3
import struct
import sys
import time
import tarfile
import tempfile
import urllib.parse
import zipfile
from collections import defaultdict
from datetime import datetime, timedelta, timezone

VERSION = "1.0"
AUTHOR = "Shaher Elrobaa"

# Two mastheads, because a Windows console still running a legacy code page
# raises UnicodeEncodeError on block characters and a masthead that can abort
# the run is worse than no masthead. The block form is used only when the
# stream says it can encode it; print_banner() checks rather than guesses, so
# the failure is never a half-written line.
BANNER_BLOCK = """\
 ██╗     ██╗███╗   ██╗███████╗██╗ ██████╗ ██╗  ██╗████████╗
 ██║     ██║████╗  ██║██╔════╝██║██╔════╝ ██║  ██║╚══██╔══╝
 ██║     ██║██╔██╗ ██║███████╗██║██║  ███╗███████║   ██║
 ██║     ██║██║╚██╗██║╚════██║██║██║   ██║██╔══██║   ██║
 ███████╗██║██║ ╚████║███████║██║╚██████╔╝██║  ██║   ██║
 ╚══════╝╚═╝╚═╝  ╚═══╝╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝
"""

BANNER_ASCII = r"""
 _ _           _       _     _
| (_)_ __  ___(_) __ _| |__ | |_
| | | '_ \/ __| |/ _` | '_ \| __|
| | | | | \__ \ | (_| | | | | |_
|_|_|_| |_|___/_|\__, |_| |_|\__|
                 |___/
"""

# The severity scale, drawn - the same ranking the report is built on, and the
# same palette the HTML report and the logo use.
SCALE_BLOCK = "███"
SCALE_ASCII = "==="
