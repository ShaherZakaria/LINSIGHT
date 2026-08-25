# -*- coding: utf-8 -*-
"""python -m linsight - the package form of the same entry point."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
