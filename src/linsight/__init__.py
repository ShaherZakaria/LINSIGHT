# -*- coding: utf-8 -*-
"""linsight - parse a Linux triage collection, or a disk, and surface the
things worth looking at first.

This package is the source form. What goes on the analysis box is the
single-file build at the repository root, produced by tools/build.py from
exactly these modules in exactly this order - so what is reviewed here and
what runs there are the same code, concatenated.

Module order is dependency order: a module may name what is defined above it
and nothing below it. That rule is what lets the build be a concatenation
rather than a bundler, and the build fails loudly if it is ever broken.
"""

from .constants import VERSION, AUTHOR

__version__ = VERSION
__author__ = AUTHOR
