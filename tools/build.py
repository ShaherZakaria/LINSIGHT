#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build the single-file linsight.py from src/linsight/.

linsight is meant to be copied onto an analysis box and run - one file, no
install, no package directory to keep together. Keeping that property while
the source is a dozen modules means the build has to be a concatenation, not
a bundler: the modules are emitted in dependency order and every reference
still resolves, because in one file there are no module boundaries left to
resolve across.

What that costs is a rule the source has to obey, and this script enforces it:

  MODULES is dependency order. A module may name what is defined above it and
  nothing below it. There is exactly one exception - a relative import written
  inside a function body, which exists precisely for the reference that points
  the other way (rules.sigma_rule_wanted needs TableBuilder). Those are
  stripped like the rest, and in the flat file the name is simply a global.

Everything else is mechanical: relative imports are dropped, standard library
imports are hoisted and de-duplicated, and each module keeps a banner so the
built file still reads as the sectioned script it was.

    python tools/build.py            # write ./linsight.py
    python tools/build.py --check    # exit 1 if ./linsight.py is out of date
"""

import argparse
import ast
import io
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PKG = os.path.join(ROOT, "src", "linsight")
TARGET = os.path.join(ROOT, "linsight.py")

# Dependency order, and the order the sections appear in the built file. A
# module named here that does not exist yet is skipped and reported, so the
# disk stack can land one module at a time without breaking the build.
MODULES = [
    ("constants", "the module docstring, the imports and the mastheads"),
    ("model",     "severity / finding model"),
    ("term",      "console primitives: colour, status lines, progress"),
    ("common",    "shared knowledge / heuristics"),
    ("decode",    "log decoders: compressed text, utmp/lastlog, the journal"),
    ("collect",   "collection access (directory / tar / zip backends)"),
    ("distro",    "which Linux distribution this is, and how we know"),
    ("image",     "disk images: raw, split raw, E01, qcow2, vmdk, vhdx, device"),
    ("volume",    "volume layer: MBR, GPT, LVM2, LUKS"),
    ("fsbase",    "what every filesystem reader has to answer"),
    ("fs_ext",    "the ext2 / ext3 / ext4 reader"),
    ("fs_xfs",    "the XFS reader"),
    ("fs_btrfs",  "the btrfs reader"),
    ("disk",      "the disk backend: a filesystem on a disk, as a collection"),
    ("ad1",       "AccessData logical images (AD1), as a collection"),
    ("rules",     "detection rules: a YARA subset and a Sigma subset"),
    ("triage",    "the triage engine"),
    ("tables",    "artifact tables - every artifact as a browsable grid"),
    ("gui",       "the GUI: one self-contained page carrying the triage picture"),
    ("writers",   "table writers: CSV, JSON, HTML browser"),
    ("report",    "reporting"),
    ("cli",       "the command line"),
]

BANNER = "# " + "-" * 73

CODING = re.compile(r"^#\s*-\*-\s*coding:.*$\n?", re.M)
REL_IMPORT_LINE = re.compile(r"^\s*from\s+\.\w*\s+import\s")


def module_path(name):
    return os.path.join(PKG, name + ".py")


def read(name):
    with io.open(module_path(name), encoding="utf-8") as fh:
        return fh.read()


def strip_imports(text, name, hoist):
    """Remove what the flat file must not repeat, and collect what it hoists.

    A relative import is dropped wherever it sits, indented or not: in one
    file the name it would have bound is already a global. A standard library
    import is dropped only at module level - an indented one is a deliberate
    lazy import (zstd, the third-party fallbacks) and has to stay exactly
    where it was written.
    """
    tree = ast.parse(text, filename=name + ".py")
    drop = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            for a in node.names:
                hoist.add(("import %s as %s" % (a.name, a.asname)) if a.asname
                          else "import %s" % a.name)
            drop.update(range(node.lineno, node.end_lineno + 1))
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                # 'from .x import y as z' cannot survive a concatenation: the
                # import line is what creates z, and in one file only y exists.
                # Catching it here is the difference between a NameError at
                # import time and one four minutes into a run.
                for a in node.names:
                    if a.asname:
                        raise SystemExit(
                            "[!] %s.py: 'from .%s import %s as %s' renames a "
                            "name across modules, which the single-file build "
                            "cannot do - export it under the name callers use."
                            % (name, node.module, a.name, a.asname))
            if not node.level and node.module != "__future__":
                for a in node.names:
                    hoist.add("from %s import %s%s"
                              % (node.module, a.name,
                                 " as %s" % a.asname if a.asname else ""))
            drop.update(range(node.lineno, node.end_lineno + 1))
    lines = text.splitlines(True)
    text = "".join(ln for i, ln in enumerate(lines, 1) if i not in drop)
    # relative imports inside function bodies, which the top-level walk above
    # never saw
    text = "".join(ln for ln in text.splitlines(True)
                   if not REL_IMPORT_LINE.match(ln))
    return CODING.sub("", text)


def docstring_of(text):
    """Split off the leading module docstring, verbatim."""
    tree = ast.parse(text)
    if (tree.body and isinstance(tree.body[0], ast.Expr)
            and isinstance(tree.body[0].value, ast.Constant)
            and isinstance(tree.body[0].value.value, str)):
        end = tree.body[0].end_lineno
        lines = text.splitlines(True)
        return "".join(lines[:end]), "".join(lines[end:])
    return "", text


def top_level_names(text, name):
    """Every name this module binds at module level."""
    out = []
    for node in ast.parse(text, filename=name + ".py").body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef)):
            out.append(node.name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                for sub in ast.walk(target):
                    if isinstance(sub, ast.Name):
                        out.append(sub.id)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            out.append(node.target.id)
    return out


def check_collisions(seen):
    """Refuse to build when two modules bind the same top-level name.

    In a package this is harmless - each module has its own namespace, and a
    private helper called _u32 in two readers is two different functions. In
    the concatenation it is one namespace, the second definition wins, and the
    first module silently starts calling the wrong function.

    That is not a theoretical risk. The XFS reader's _u32 is big-endian and
    the btrfs reader's is little-endian; concatenated in that order, XFS reads
    every structure through the wrong decoder and reports an empty disk. The
    package tests pass and the shipped file does not work, which is the worst
    shape a bug can take, so it is a build failure rather than a warning.
    """
    clashes = {n: mods for n, mods in seen.items() if len(mods) > 1}
    if not clashes:
        return
    lines = ["[!] the same top-level name is bound by more than one module.",
             "    In one file there is one namespace, so the last definition",
             "    wins and the earlier module calls the wrong one. Give each",
             "    a distinct name.", ""]
    for n in sorted(clashes):
        lines.append("      %-24s %s" % (n, ", ".join(clashes[n])))
    raise SystemExit("\n".join(lines))


def build():
    hoist = set()
    bodies = []
    doc = ""
    missing = []
    seen = {}
    for name, title in MODULES:
        if not os.path.exists(module_path(name)):
            missing.append(name)
            continue
        text = read(name)
        if name == "constants":
            doc, text = docstring_of(text)
        text = strip_imports(text, name, hoist).strip("\n")
        for bound in top_level_names(text, name):
            where = seen.setdefault(bound, [])
            if name not in where:      # rebinding within one module is fine
                where.append(name)
        if text:
            bodies.append((name, title, text))
    check_collisions(seen)

    def sort_key(stmt):
        # 'import x' before 'from x import y', then alphabetical by module -
        # a stable order, so a rebuild after an unrelated edit is an empty diff
        parts = stmt.split()
        return (0 if parts[0] == "import" else 1, parts[1], stmt)

    out = ["#!/usr/bin/env python3\n", "# -*- coding: utf-8 -*-\n"]
    if doc:
        out.append(doc.rstrip("\n") + "\n")
    out.append("\n")
    out.append("# Built from src/linsight/ by tools/build.py. Edit the modules\n")
    out.append("# there, then run 'python tools/build.py' to regenerate this.\n")
    out.append("\n")
    out.append("from __future__ import annotations\n")
    out.append("\n")
    for stmt in sorted(hoist, key=sort_key):
        out.append(stmt + "\n")
    out.append("\n")
    for name, title, text in bodies:
        if name != "constants":
            out.append("\n" + BANNER + "\n# " + title + "\n" + BANNER + "\n\n")
        out.append(text + "\n")
    out.append('\n\nif __name__ == "__main__":\n    sys.exit(main())\n')
    return "".join(out), missing


def main(argv=None):
    ap = argparse.ArgumentParser(description="Build single-file linsight.py.")
    ap.add_argument("--check", action="store_true",
                    help="do not write; exit 1 if linsight.py is out of date")
    ap.add_argument("-o", "--output", default=TARGET)
    opts = ap.parse_args(argv)

    text, missing = build()
    try:
        compile(text, opts.output, "exec")
    except SyntaxError as exc:
        print("[!] built file does not compile: %s" % exc, file=sys.stderr)
        return 2
    if missing:
        print("[*] modules not present yet, skipped: %s" % ", ".join(missing),
              file=sys.stderr)

    old = None
    if os.path.exists(opts.output):
        with io.open(opts.output, encoding="utf-8") as fh:
            old = fh.read()
    rel = os.path.relpath(opts.output, ROOT)
    if opts.check:
        if old != text:
            print("[!] %s is out of date - run 'python tools/build.py'" % rel,
                  file=sys.stderr)
            return 1
        print("[+] %s is up to date" % rel)
        return 0
    if old == text:
        print("[=] %s unchanged" % rel)
        return 0
    with io.open(opts.output, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    print("[+] %s written (%d lines, %.0f KB)"
          % (rel, text.count("\n"), len(text.encode("utf-8")) / 1024.0))
    return 0


if __name__ == "__main__":
    sys.exit(main())
