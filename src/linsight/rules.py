# -*- coding: utf-8 -*-
from __future__ import annotations

from datetime import datetime
from datetime import timezone
import base64
import io
import ipaddress
import json
import os
import re
import shutil
import sys
import time
import zipfile

from .constants import VERSION
from .term import status
from .common import human_size



# ---------------------------------------------------------------------------
# detection rules: a YARA subset and a Sigma subset, both pure stdlib
#
# The point of this tool is that it runs from one file with nothing installed,
# on a machine that may be an evidence workstation with no package manager
# access. yara-python and pysigma are therefore not dependencies - these are
# self-contained engines covering the constructs that Linux IR rules actually
# use. Where a real library is importable it wins: PyYAML is used for Sigma
# when present, because a real parser beats a good-enough one.
#
# Both engines share one rule: anything they cannot represent faithfully is
# REJECTED with a reason and reported in RULE_ERRORS, never partially applied.
# A detection rule that silently matches nothing is worse than one that was
# never loaded, because it looks like a clean result.
# ---------------------------------------------------------------------------

# YARA
class RuleError(Exception):
    pass


# ---------------------------------------------------------------------------
# string compilation
# ---------------------------------------------------------------------------

WORD = rb"A-Za-z0-9_"


def _wide(raw):
    """Interleave NUL bytes the way YARA's 'wide' modifier does.

    Runs on the raw bytes and is escaped afterwards, never the other way round:
    interleaving into an already-escaped pattern would drop NULs inside the
    escape sequences themselves. Slicing rather than iterating because
    iterating a bytes object yields ints.
    """
    return b"".join(raw[i:i + 1] + b"\x00" for i in range(len(raw)))


def _hex_to_regex(body):
    """'{ 4D 5A ?? [0-4] 90 ( AA | BB ) }' -> a bytes regex."""
    toks = re.findall(r"\[\s*\d*\s*-?\s*\d*\s*\]|\(|\)|\||[0-9A-Fa-f?]{2}|\S", body)
    out = []
    for t in toks:
        if t == "(":
            out.append(b"(?:")
        elif t == ")":
            out.append(b")")
        elif t == "|":
            out.append(b"|")
        elif t.startswith("["):
            inner = t[1:-1].strip()
            if inner in ("-", ""):
                out.append(b".*?")            # unbounded jump
            elif "-" in inner:
                lo, hi = [p.strip() for p in inner.split("-", 1)]
                lo = lo or "0"
                out.append(("." + "{%s,%s}" % (lo, hi or "")).encode())
            else:
                out.append(("." + "{%s}" % inner).encode())
        elif len(t) == 2 and re.match(r"^[0-9A-Fa-f?]{2}$", t):
            if t == "??":
                out.append(b".")
            elif t[1] == "?":                 # high nibble fixed: 4? -> [\x40-\x4f]
                hi = int(t[0], 16)
                out.append(("[\\x%02x-\\x%02x]" % (hi * 16, hi * 16 + 15)).encode())
            elif t[0] == "?":                 # low nibble fixed: ?A -> one of 16
                lo = int(t[1], 16)
                out.append(b"[" + b"".join(
                    ("\\x%02x" % (h * 16 + lo)).encode() for h in range(16)) + b"]")
            else:
                out.append(("\\x%02x" % int(t, 16)).encode())
        else:
            raise RuleError("unsupported hex token %r" % t)
    return b"".join(out)


class YString:
    """One '$id = ...' definition, compiled to one or more bytes patterns."""

    def __init__(self, ident, kind, raw, mods):
        self.ident = ident
        self.kind = kind
        self.raw = raw
        self.mods = mods
        self.patterns = self._compile()

    def _compile(self):
        flags = re.DOTALL
        if "nocase" in self.mods:
            flags |= re.IGNORECASE
        pats = []
        if self.kind == "text":
            body = self.raw.encode("utf-8", "surrogateescape")
            forms = []
            # 'wide' alone means UTF-16LE only; 'wide ascii' means either
            if "wide" in self.mods:
                forms.append(re.escape(_wide(body)))
            if "wide" not in self.mods or "ascii" in self.mods:
                forms.append(re.escape(body))
            for f in forms:
                if "fullword" in self.mods:
                    f = b"(?<![" + WORD + b"])" + f + b"(?![" + WORD + b"])"
                pats.append(re.compile(f, flags))
        elif self.kind == "hex":
            pats.append(re.compile(_hex_to_regex(self.raw), re.DOTALL))
        elif self.kind == "regex":
            body = self.raw.encode("utf-8", "surrogateescape")
            if "wide" in self.mods:
                raise RuleError("wide regex strings are not supported")
            pats.append(re.compile(body, flags))
        return pats

    def find(self, data):
        out = []
        for p in self.patterns:
            for m in p.finditer(data):
                out.append((m.start(), m.group(0)))
                if len(out) > 64:
                    return out          # a rule needs counts, not every hit
        return out


# ---------------------------------------------------------------------------
# condition parsing - a small recursive-descent parser over a token list
# ---------------------------------------------------------------------------

COND_TOKEN = re.compile(r"""
    \s*(
      \(|\)|,
    | \#[A-Za-z_][A-Za-z0-9_]*
    | \$[A-Za-z0-9_]*\*?
    | <=|>=|==|!=|<|>
    | \b(?:and|or|not|all|any|of|them|filesize|true|false|at|in)\b
    | \b(?:uint8|uint16|uint32|int8|int16|int32)\b
    | 0x[0-9A-Fa-f]+ | \d+(?:KB|MB|GB)? | \.\.
    | \S
    )""", re.X)


def _tokenize_cond(text):
    toks, pos = [], 0
    for m in COND_TOKEN.finditer(text):
        toks.append(m.group(1))
    return toks


class Cond:
    """Condition AST node. kind drives eval; children/value carry the operands."""

    def __init__(self, kind, **kw):
        self.kind = kind
        self.__dict__.update(kw)


class CondParser:
    def __init__(self, toks, idents):
        self.t = toks
        self.i = 0
        self.idents = idents

    def peek(self):
        return self.t[self.i] if self.i < len(self.t) else None

    def take(self, expect=None):
        v = self.peek()
        if v is None:
            raise RuleError("condition ended early")
        if expect and v != expect:
            raise RuleError("expected %r, found %r" % (expect, v))
        self.i += 1
        return v

    def parse(self):
        node = self.or_expr()
        if self.peek() is not None:
            raise RuleError("unparsed condition tail at %r" % self.peek())
        return node

    def or_expr(self):
        n = self.and_expr()
        while self.peek() == "or":
            self.take()
            n = Cond("or", a=n, b=self.and_expr())
        return n

    def and_expr(self):
        n = self.unary()
        while self.peek() == "and":
            self.take()
            n = Cond("and", a=n, b=self.unary())
        return n

    def unary(self):
        if self.peek() == "not":
            self.take()
            return Cond("not", a=self.unary())
        return self.primary()

    def _num(self, tok):
        mult = 1
        for suf, m in (("KB", 1024), ("MB", 1024 ** 2), ("GB", 1024 ** 3)):
            if tok.endswith(suf):
                tok, mult = tok[: -len(suf)], m
                break
        return int(tok, 16) if tok.lower().startswith("0x") else int(tok) * mult

    def _expand(self, pat):
        """'$a*' -> every declared identifier with that prefix."""
        if pat == "them" or pat == "$*":
            return list(self.idents)
        if pat.endswith("*"):
            pre = pat[1:-1]
            return [i for i in self.idents if i.startswith(pre)]
        return [pat[1:]] if pat[1:] in self.idents else []

    def _set(self):
        """'them' or '( $a*, $b )' after an 'of'."""
        if self.peek() == "them":
            self.take()
            return list(self.idents)
        self.take("(")
        names = []
        while True:
            tok = self.take()
            if tok.startswith("$"):
                names.extend(self._expand(tok))
            elif tok == ")":
                break
            elif tok == ",":
                continue
            else:
                raise RuleError("unexpected %r in string set" % tok)
        return names

    def primary(self):
        tok = self.peek()
        if tok == "(":
            self.take()
            n = self.or_expr()
            self.take(")")
            return n
        if tok in ("true", "false"):
            self.take()
            return Cond("const", value=(tok == "true"))
        if tok in ("all", "any"):
            self.take()
            self.take("of")
            names = self._set()
            return Cond("of", n=(len(names) if tok == "all" else 1), names=names)
        if tok and re.match(r"^\d+(KB|MB|GB)?$|^0x", tok) and \
                self.i + 1 < len(self.t) and self.t[self.i + 1] == "of":
            n = self._num(self.take())
            self.take("of")
            return Cond("of", n=n, names=self._set())
        if tok and tok.startswith("#"):
            self.take()
            name = tok[1:]
            op = self.take()
            if op not in ("<", ">", "<=", ">=", "==", "!="):
                raise RuleError("expected a comparison after #%s" % name)
            return Cond("count", name=name, op=op, value=self._num(self.take()))
        if tok == "filesize":
            self.take()
            op = self.take()
            return Cond("filesize", op=op, value=self._num(self.take()))
        if tok in ("uint8", "uint16", "uint32", "int8", "int16", "int32"):
            self.take()
            self.take("(")
            off = self._num(self.take())
            self.take(")")
            op = self.take()
            return Cond("uint", size=int(re.sub(r"\D", "", tok)) // 8,
                        off=off, op=op, value=self._num(self.take()))
        if tok and tok.startswith("$"):
            self.take()
            names = self._expand(tok)
            if tok.endswith("*"):
                return Cond("of", n=1, names=names)
            if not names:
                raise RuleError("condition references undeclared %s" % tok)
            # '$a at 0' / '$a in (0..100)'
            if self.peek() == "at":
                self.take()
                return Cond("at", name=names[0], off=self._num(self.take()))
            if self.peek() == "in":
                self.take()
                self.take("(")
                lo = self._num(self.take())
                self.take("..")
                hi = self._num(self.take())
                self.take(")")
                return Cond("in", name=names[0], lo=lo, hi=hi)
            return Cond("str", name=names[0])
        raise RuleError("unsupported condition token %r" % tok)


_CMP = {"<": lambda a, b: a < b, ">": lambda a, b: a > b,
        "<=": lambda a, b: a <= b, ">=": lambda a, b: a >= b,
        "==": lambda a, b: a == b, "!=": lambda a, b: a != b}


def eval_cond(node, hits, data):
    k = node.kind
    if k == "const":
        return node.value
    if k == "and":
        return eval_cond(node.a, hits, data) and eval_cond(node.b, hits, data)
    if k == "or":
        return eval_cond(node.a, hits, data) or eval_cond(node.b, hits, data)
    if k == "not":
        return not eval_cond(node.a, hits, data)
    if k == "str":
        return bool(hits.get(node.name))
    if k == "of":
        return sum(1 for n in node.names if hits.get(n)) >= node.n
    if k == "count":
        return _CMP[node.op](len(hits.get(node.name, [])), node.value)
    if k == "filesize":
        return _CMP[node.op](len(data), node.value)
    if k == "at":
        return any(off == node.off for off, _ in hits.get(node.name, []))
    if k == "in":
        return any(node.lo <= off <= node.hi for off, _ in hits.get(node.name, []))
    if k == "uint":
        if node.off + node.size > len(data):
            return False
        v = int.from_bytes(data[node.off:node.off + node.size], "little")
        return _CMP[node.op](v, node.value)
    raise RuleError("cannot evaluate %s" % k)


# ---------------------------------------------------------------------------
# rule file parsing
# ---------------------------------------------------------------------------

RULE_HEAD = re.compile(r"\brule\s+([A-Za-z_]\w*)\s*(:\s*[^\{]+)?\{", re.S)
STRING_DEF = re.compile(r"""
    (\$[A-Za-z0-9_]*)\s*=\s*
    (?: "((?:[^"\\]|\\.)*)"        # text
      | \{([^}]*)\}                # hex
      | /((?:[^/\\\n]|\\.)+)/      # regex
    )([ \t]*[A-Za-z0-9 \t]*)""", re.X)
MODULE_USE = re.compile(r"\b(pe|elf|math|hash|cuckoo|magic|dotnet|time)\s*\.")


class YRule:
    def __init__(self, name, tags, meta, strings, cond_src, cond, source):
        self.name = name
        self.tags = tags
        self.meta = meta
        self.strings = strings
        self.cond_src = cond_src
        self.cond = cond
        self.source = source

    def match(self, data):
        hits = {}
        for s in self.strings:
            found = s.find(data)
            if found:
                hits[s.ident] = found
        try:
            if eval_cond(self.cond, hits, data):
                return hits
        except RuleError:
            return None
        return None


def _split_blocks(text):
    """Yield (name, tags, body) for each rule, brace-balanced."""
    for m in RULE_HEAD.finditer(text):
        depth, i = 1, m.end()
        while i < len(text) and depth:
            c = text[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
            elif c == '"':                       # skip string literals
                i += 1
                while i < len(text) and text[i] != '"':
                    i += 2 if text[i] == "\\" else 1
            i += 1
        tags = (m.group(2) or "").lstrip(":").split()
        yield m.group(1), tags, text[m.end():i - 1]


def parse_yara(text, source=""):
    """-> (rules, errors). Errors are per rule, never fatal for the file."""
    rules, errors = [], []
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    text = re.sub(r"(?m)//.*$", "", text)
    for name, tags, body in _split_blocks(text):
        try:
            mcond = re.search(r"\bcondition\s*:(.*)$", body, re.S)
            if not mcond:
                raise RuleError("no condition section")
            cond_src = mcond.group(1).strip()
            if MODULE_USE.search(cond_src):
                raise RuleError("uses a YARA module (%s) - not supported"
                                % MODULE_USE.search(cond_src).group(1))
            meta = {}
            mmeta = re.search(r"\bmeta\s*:(.*?)(?=\bstrings\s*:|\bcondition\s*:)",
                              body, re.S)
            if mmeta:
                for km in re.finditer(r'(\w+)\s*=\s*(?:"([^"]*)"|(\S+))',
                                      mmeta.group(1)):
                    meta[km.group(1)] = km.group(2) if km.group(2) is not None \
                        else km.group(3)
            strings = []
            mstr = re.search(r"\bstrings\s*:(.*?)(?=\bcondition\s*:)", body, re.S)
            if mstr:
                for sm in STRING_DEF.finditer(mstr.group(1)):
                    ident = sm.group(1)[1:]
                    mods = (sm.group(5) or "").split()
                    bad = [m for m in mods if m not in
                           ("nocase", "wide", "ascii", "fullword", "private")]
                    if bad:
                        raise RuleError("unsupported string modifier %s" % bad[0])
                    if sm.group(2) is not None:
                        raw = sm.group(2).encode().decode("unicode_escape")
                        strings.append(YString(ident, "text", raw, mods))
                    elif sm.group(3) is not None:
                        strings.append(YString(ident, "hex", sm.group(3), mods))
                    else:
                        strings.append(YString(ident, "regex", sm.group(4), mods))
            idents = [s.ident for s in strings]
            cond = CondParser(_tokenize_cond(cond_src), idents).parse()
            rules.append(YRule(name, tags, meta, strings, cond_src, cond, source))
        except RuleError as e:
            errors.append((name, str(e)))
        except Exception as e:                    # a malformed rule is data
            errors.append((name, "%s: %s" % (type(e).__name__, e)))
    return rules, errors

# SIGMA
try:                                    # a real parser when one is installed
    import yaml as _yaml
except Exception:
    _yaml = None




# ---------------------------------------------------------------------------
# minimal YAML subset loader
# ---------------------------------------------------------------------------

def _scalar(text):
    t = text.strip()
    if t in ("~", "null", "Null", "NULL", ""):
        return None
    if t in ("true", "True", "TRUE", "yes"):
        return True
    if t in ("false", "False", "FALSE", "no"):
        return False
    if len(t) >= 2 and t[0] == t[-1] and t[0] in "'\"":
        body = t[1:-1]
        return body.replace('\\"', '"') if t[0] == '"' else body.replace("''", "'")
    if re.match(r"^-?\d+$", t):
        return int(t)
    if re.match(r"^-?\d+\.\d+$", t):
        return float(t)
    return t


def _strip_comment(line):
    """Drop a trailing '#' comment that is not inside quotes."""
    out, q = [], None
    for ch in line:
        if q:
            out.append(ch)
            if ch == q:
                q = None
        elif ch in "'\"":
            q = ch
            out.append(ch)
        elif ch == "#" and (not out or out[-1] in " \t"):
            break
        else:
            out.append(ch)
    return "".join(out).rstrip()


def load_yaml(text):
    """Parse the YAML subset Sigma uses. Returns a list of documents."""
    if _yaml is not None:
        return [d for d in _yaml.safe_load_all(text) if d is not None]
    docs, cur = [], []
    for raw in text.splitlines():
        if raw.strip() in ("---", "..."):
            if cur:
                docs.append(cur)
            cur = []
            continue
        cur.append(raw)
    if cur:
        docs.append(cur)
    return [_parse_block(_clean(d), 0)[0] for d in docs if any(l.strip() for l in d)]


def _clean(lines):
    out = []
    for raw in lines:
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        line = _strip_comment(raw)
        if line.strip():
            out.append(line)
    return out


def _indent(line):
    return len(line) - len(line.lstrip(" "))


def _parse_block(lines, i, base=None):
    """Parse one mapping or sequence starting at lines[i]. -> (value, next_i)."""
    if i >= len(lines):
        return None, i
    if base is None:
        base = _indent(lines[i])
    if lines[i].lstrip().startswith("- "):
        seq = []
        while i < len(lines) and _indent(lines[i]) == base and \
                lines[i].lstrip().startswith("- "):
            item = lines[i].lstrip()[2:].strip()
            if item and ":" in item and not item.startswith(("'", '"')) and \
                    re.match(r"^[\w|.\-]+\s*:", item):
                # '- field: value' opens a mapping inside the sequence
                sub = [" " * (base + 2) + lines[i].lstrip()[2:]]
                j = i + 1
                while j < len(lines) and _indent(lines[j]) > base:
                    sub.append(lines[j])
                    j += 1
                val, _ = _parse_block(sub, 0, base + 2)
                seq.append(val)
                i = j
            elif item:
                seq.append(_scalar(item))
                i += 1
            else:
                sub, j = [], i + 1
                while j < len(lines) and _indent(lines[j]) > base:
                    sub.append(lines[j])
                    j += 1
                val, _ = _parse_block(sub, 0)
                seq.append(val)
                i = j
        return seq, i
    mapping = {}
    while i < len(lines) and _indent(lines[i]) == base:
        line = lines[i].strip()
        m = re.match(r"^(.+?)\s*:\s*(.*)$", line)
        if not m:
            raise RuleError("cannot parse YAML line %r" % line)
        key, rest = _scalar(m.group(1)), m.group(2)
        if rest in ("|", ">", "|-", ">-", "|+", ">+"):
            block, j = [], i + 1
            while j < len(lines) and _indent(lines[j]) > base:
                block.append(lines[j].strip())
                j += 1
            mapping[key] = ("\n" if rest[0] == "|" else " ").join(block)
            i = j
        elif rest == "":
            j = i + 1
            if j < len(lines) and _indent(lines[j]) > base:
                val, j = _parse_block(lines, j, _indent(lines[j]))
                mapping[key] = val
            elif j < len(lines) and _indent(lines[j]) == base and \
                    lines[j].lstrip().startswith("- "):
                val, j = _parse_block(lines, j, base)
                mapping[key] = val
            else:
                mapping[key] = None
            i = j
        elif rest.startswith("[") and rest.endswith("]"):
            inner = rest[1:-1].strip()
            mapping[key] = [_scalar(p) for p in inner.split(",")] if inner else []
            i += 1
        else:
            mapping[key] = _scalar(rest)
            i += 1
    return mapping, i


# ---------------------------------------------------------------------------
# value matching
# ---------------------------------------------------------------------------

SUPPORTED_MODS = {"contains", "startswith", "endswith", "re", "all", "cased",
                  "base64", "base64offset", "windash", "expand", "cidr"}
# modifiers whose semantics this engine cannot honour - reject, never ignore
REJECT_MODS = {"fieldref", "exists", "gt", "gte", "lt", "lte",
               "utf16", "utf16le", "utf16be", "wide"}

_CIDR_IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def _ip_of(text):
    """The IP address a field value carries, or None.

    A Sigma cidr rule names an address field, but the tables here fill those
    from whatever the artifact wrote: ss and netstat give '10.0.0.5:443', a
    v6 peer arrives as '[fe80::1]:22', auth.log and the web logs give a bare
    address. The whole value is parsed first - that is the common case and the
    only unambiguous one - then the bracketed and port-suffixed forms, and
    only then the first dotted quad in the text.

    Anything else is left unmatched rather than guessed at. A cidr test that
    quietly matches the wrong number out of a log line is worse than a rule
    that does not fire: the first invents a hit, the second is visible as a
    gap in SIGMA_COVERAGE.
    """
    s = (text or "").strip()
    if not s:
        return None
    try:
        return ipaddress.ip_address(s)
    except ValueError:
        pass
    if s.startswith("["):                       # [fe80::1]:22
        try:
            return ipaddress.ip_address(s[1:].split("]")[0])
        except (ValueError, IndexError):
            pass
    if s.count(":") == 1:                       # 10.0.0.5:443 - one colon, so
        try:                                    # never a bare v6 address
            return ipaddress.ip_address(s.split(":")[0])
        except ValueError:
            pass
    m = _CIDR_IPV4_RE.search(s)
    if m:
        try:
            return ipaddress.ip_address(m.group(0))
        except ValueError:
            pass
    return None


def _anchored(inner, at_start, at_end, flags):
    """Compile a Sigma value, with anchors in the pattern rather than the call.

    A '*' at an end that is not anchored is redundant, and leaving it in is the
    single biggest performance trap here: '.*foo.*' matched with search() makes
    the engine retry from every offset in the subject and backtrack inside each
    attempt, which on a 12,000-character log line is quadratic. Stripping those
    wildcards changes nothing about what matches - search already scans - and
    took a run that had not finished in twenty minutes down to seconds.
    """
    while not at_start and inner.startswith(".*"):
        inner = inner[2:]
    while not at_end and inner.endswith(".*"):
        inner = inner[:-2]
    return re.compile(("^" if at_start else "") + inner +
                      ("$" if at_end else ""), flags)


def _wildcard_re(pat, cased):
    """Sigma value with * and ? wildcards -> compiled regex."""
    out, i = [], 0
    while i < len(pat):
        c = pat[i]
        if c == "\\" and i + 1 < len(pat) and pat[i + 1] in "*?\\":
            out.append(re.escape(pat[i + 1]))
            i += 2
            continue
        out.append(".*" if c == "*" else "." if c == "?" else re.escape(c))
        i += 1
    return re.compile("^" + "".join(out) + "$",
                      0 if cased else re.IGNORECASE)


# Sigma's field names come from a mostly Windows-shaped taxonomy; the tables
# here are Linux artifacts. A rule that says Image means the executable path,
# which this export calls exe on one table and comm on another. Each name is
# tried in order against the row and the first one the row actually has wins,
# so one rule works across PROCESSES, AUDIT_LOG and PROCESS_MASTER without
# being rewritten. A field that resolves to nothing simply does not match -
# never a fallback to searching the whole row, which would turn a precise
# field rule into a keyword rule and invent hits.
SIGMA_FIELD_SYNONYMS = {
    "image": ["exe", "comm", "path"],
    "processname": ["comm", "exe"],
    "originalfilename": ["comm", "exe"],
    "commandline": ["args", "proctitle", "command", "text"],
    "parentimage": ["parent_exe", "ppid_exe"],
    "parentcommandline": ["parent_args"],
    "user": ["user", "acct", "owner", "username"],
    "targetusername": ["acct", "target_user", "user"],
    "targetuser": ["target_user", "acct"],
    "logonuser": ["user", "acct"],
    "currentdirectory": ["cwd"],
    "processid": ["pid"],
    "parentprocessid": ["ppid"],
    "sourceip": ["remote_ip", "client_ip", "addr", "remote_host"],
    "destinationip": ["remote_addr", "peer", "addr"],
    "destinationport": ["remote_port", "port"],
    "c-uri": ["resource"], "cs-uri-query": ["resource"],
    "c-useragent": ["user_agent"], "sc-status": ["status"],
    "cs-method": ["method"], "cs-ip": ["client_ip"],
    "message": ["message", "text", "detail", "proctitle"],
    "cmd": ["command", "args", "proctitle"],
    "type": ["record_type", "rtype", "type", "kind"],
    "comm": ["comm", "exe"],
    "exe": ["exe", "comm", "path"],
    "name": ["name", "path", "file"],
    "path": ["path", "name", "file"],
    "syscall": ["syscall"], "key": ["key"], "auid": ["auid"], "uid": ["uid"],
}


class Matcher:
    """One 'field|mods: value(s)' entry from a detection block."""

    def __init__(self, field, mods, values):
        self.field = field
        # the declared name first, then the synonyms, then the raw name again
        self.candidates = [field] + [c for c in
                                     SIGMA_FIELD_SYNONYMS.get(field, [])
                                     if c != field]
        self.mods = mods
        bad = [m for m in mods if m in REJECT_MODS]
        if bad:
            raise RuleError("modifier '%s' is not supported" % bad[0])
        unknown = [m for m in mods if m not in SUPPORTED_MODS]
        if unknown:
            raise RuleError("unknown modifier '%s'" % unknown[0])
        self.all = "all" in mods
        self.cased = "cased" in mods
        self.values = values if isinstance(values, list) else [values]
        self.tests = [self._compile(v) for v in self.values]

    def _compile(self, v):
        if v is None:
            return None                       # 'field: null' -> field absent
        s = str(v)
        if "cidr" in self.mods:
            # A bare address is a /32 (or /128), which is what Sigma means by
            # it, and strict=False accepts '10.0.0.5/8' rather than rejecting
            # the rule over a host bit the author left set.
            try:
                return ("cidr", ipaddress.ip_network(s, strict=False))
            except ValueError as e:
                raise RuleError("bad cidr value '%s': %s" % (s, e))
        if "base64offset" in self.mods:
            forms = []
            for off in (0, 1, 2):
                enc = base64.b64encode((" " * off + s).encode()).decode()
                trim = enc[off and 2 or 0:len(enc) - 3 if off else len(enc)]
                forms.append(re.compile(re.escape(trim.rstrip("=")),
                                        0 if self.cased else re.IGNORECASE))
            return ("any", forms)
        if "base64" in self.mods:
            s = base64.b64encode(s.encode()).decode()
        flags = 0 if self.cased else re.IGNORECASE
        if "re" in self.mods:
            # a user-supplied regex: its own casing is meaningful, so it keeps
            # the flag rather than being lowercased
            return ("re", re.compile(s, flags))
        # Case-insensitive Sigma values are matched by lowering both sides
        # instead of setting re.IGNORECASE. The flag case-folds at every
        # position of every attempt, and profiling this run put 22.4s of 88s in
        # re.Pattern.search at ~8us a call; the values here are re.escape'd
        # literals plus wildcards, so lowering the source is equivalent. Same
        # fix as the hacktool sweep and the Sigma keyword blocks.
        low = not self.cased
        src = s.lower() if low else s
        inner = _wildcard_re(src, True).pattern[1:-1]          # drop ^ and $
        kind = "re_low" if low else "re"
        cflags = 0
        if "contains" in self.mods:
            return (kind, _anchored(inner, False, False, cflags))
        if "startswith" in self.mods:
            return (kind, _anchored(inner, True, False, cflags))
        if "endswith" in self.mods:
            return (kind, _anchored(inner, False, True, cflags))
        return (kind, _anchored(inner, True, True, cflags))

    def test(self, row):
        got = None
        for cand in self.candidates:
            if cand in row:
                got = row[cand]
                break
        results = []
        hay_low = None                      # lowered once, shared by the tests
        for t in self.tests:
            if t is None:
                results.append(got in (None, ""))
                continue
            if got in (None, ""):
                results.append(False)
                continue
            hay = str(got)
            kind, pat = t
            # anchors live in the pattern, so every form is a plain search
            if kind == "cidr":
                ip = _ip_of(hay)
                # a v4 address is never inside a v6 network and vice versa;
                # `in` raises on the mismatch rather than returning False
                results.append(bool(ip) and ip.version == pat.version
                               and ip in pat)
            elif kind == "any":
                results.append(any(p.search(hay) for p in pat))
            elif kind == "re_low":
                if hay_low is None:
                    hay_low = hay.lower()
                results.append(bool(pat.search(hay_low)))
            else:
                results.append(bool(pat.search(hay)))
            if not self.all and results[-1]:
                return True                    # OR: stop at the first hit
            if self.all and not results[-1]:
                return False                   # AND: stop at the first miss
        return all(results) if self.all else any(results)


class Row(dict):
    """A row dict that caches the strings every rule on a table re-derives.

    Sigma tests each rule mapped to a table against each row, and two subjects
    are the same for all of those rules: the whole-row keyword haystack, and
    the log/process/unit string a service filter reads. Building them inside
    the rule's test made them per (row, rule) instead of per row - on VAR_LOG
    that is 1.19M joins multiplied by the rule count, for one join's worth of
    information. A dict subclass keeps `cand in row` and `row[cand]` working
    unchanged for every field matcher.
    """

    __slots__ = ("_hay", "_hayl", "_where")

    def hay(self):
        try:
            return self._hay
        except AttributeError:
            self._hay = " ".join(str(v) for k, v in self.items()
                                 if v not in (None, "")
                                 and k not in Keywords.PROVENANCE)
            return self._hay

    def hay_lower(self):
        try:
            return self._hayl
        except AttributeError:
            self._hayl = self.hay().lower()
            return self._hayl

    def where(self):
        try:
            return self._where
        except AttributeError:
            self._where = ("%s %s %s" % (self.get("log", ""),
                                         self.get("process", ""),
                                         self.get("unit", ""))).lower()
            return self._where


class Keywords:
    """A bare list under detection - matched against the whole row."""

    def __init__(self, values, mods=()):
        self.values = values if isinstance(values, list) else [values]
        # Two costs removed here, both measured on a real SigmaHQ ruleset over
        # this export's log tables, where every planned rule turned out to be a
        # keyword rule at 6.4us per row per rule:
        #
        #   re.IGNORECASE case-folds at every position of the whole-row
        #   haystack, the longest subject in the export. These patterns are
        #   re.escape'd literals plus wildcards, so lowering the pattern source
        #   and matching a lowered haystack is equivalent and far cheaper.
        #
        #   One alternation per keyword block, so a rule listing ten keywords
        #   costs one pass over the haystack rather than ten.
        inners, always = [], False
        for v in self.values:
            low = str(v).lower()
            inner = _wildcard_re(low, True).pattern[1:-1]
            # same wildcard-stripping as _anchored: an unanchored leading or
            # trailing .* is redundant under search() and is the quadratic
            # backtracking trap
            while inner.startswith(".*"):
                inner = inner[2:]
            while inner.endswith(".*"):
                inner = inner[:-2]
            if inner:
                inners.append(self._left_bounded(low, inner))
            else:
                always = True       # a bare '*' keyword matches any row
        self.always = always
        self.pat = (None if always or not inners else
                    re.compile("|".join("(?:%s)" % i for i in inners)))


    # A keyword may not start in the middle of a word.
    #
    # Keyword blocks are substring searches over the whole row, and on a
    # free-text log table that reads a keyword out of the middle of an
    # unrelated token. The PROVENANCE fix below is one instance of this - 'rm'
    # found inside 'SIGTERM'. The general case is worse: SigmaHQ's stable
    # 'Remote File Copy' rule lists the keyword 'scp ', and on a 2016 Ubuntu
    # build it matched the kernel line 'ACPI: Added _OSI(3.0 _SCP Extensions)'
    # in every rotation of kern.log, syslog and dmesg - 80-odd rows of a
    # firmware string reported as file transfer.
    #
    # So a keyword whose first character is a word character must not be
    # preceded by one. Deliberately one-sided: requiring a boundary on the
    # right as well would stop the keyword 'xmrig' matching 'xmrig_v2', and a
    # keyword that is the *prefix* of a longer token is usually the hit you
    # want. A keyword that is the *suffix* of one - the 'rm' of 'SIGTERM', the
    # 'scp' of '_SCP' - essentially never is.
    #
    # This is also closer to what a real Sigma backend does. Elasticsearch and
    # Splunk resolve a keyword to a full-text match over analysed tokens, not
    # to a substring scan, and neither would return '_SCP Extensions' for
    # 'scp'.
    WORD_CHAR = "0123456789abcdefghijklmnopqrstuvwxyz_"

    @classmethod
    def _left_bounded(cls, low, inner):
        """Forbid a word character immediately before a word-initial keyword."""
        lead = low.lstrip("*")
        if lead[:1] and lead[0] in cls.WORD_CHAR:
            return "(?<![%s])%s" % (cls.WORD_CHAR, inner)
        return inner

    # Columns this export adds to say where a row came from. They are not part
    # of the event, and folding them into the keyword haystack invents matches:
    # a row from /var/log/syslog gained the literal text '/var/log/syslog', so
    # a rule hunting 'rm /var/log/syslog' fired on 'SIGTERM /var/log/syslog'
    # - case-insensitively, SIGTE-RM. Field matchers can still name these
    # columns explicitly; only the whole-row keyword search skips them.
    PROVENANCE = frozenset(("log", "source", "source_file", "file", "rule_file",
                            "line_no", "timestamp_raw", "path"))

    def test(self, row):
        if self.always:
            return True
        if self.pat is None:
            return False
        hay = (row.hay_lower() if isinstance(row, Row) else
               " ".join(str(v) for k, v in row.items()
                        if v not in (None, "") and k not in self.PROVENANCE).lower())
        return self.pat.search(hay) is not None


class Selection:
    """A named detection block: a map of matchers (AND), or a list of maps (OR)."""

    def __init__(self, spec, alias):
        self.groups = []
        if isinstance(spec, list):
            if spec and not isinstance(spec[0], dict):
                self.groups = [[Keywords(spec)]]
                return
            blocks = spec
        else:
            blocks = [spec]
        for blk in blocks:
            if not isinstance(blk, dict):
                raise RuleError("unsupported detection block %r" % type(blk).__name__)
            grp = []
            for key, val in blk.items():
                parts = str(key).split("|")
                field = alias(parts[0])
                grp.append(Matcher(field, [p.lower() for p in parts[1:]], val))
            self.groups.append(grp)

    def test(self, row):
        # list-of-maps is OR across blocks, AND within a block
        return any(all(m.test(row) for m in grp) for grp in self.groups)


# ---------------------------------------------------------------------------
# condition expression
# ---------------------------------------------------------------------------

COND_TOK = re.compile(r"\s*(\(|\)|\band\b|\bor\b|\bnot\b|\bof\b|\bthem\b|"
                      r"\ball\b|\d+|[A-Za-z_][\w]*\*?)")


class SigmaCond:
    def __init__(self, kind, **kw):
        self.kind = kind
        self.__dict__.update(kw)


class SigmaCondParser:
    def __init__(self, text, names):
        self.t = [m.group(1) for m in COND_TOK.finditer(text)]
        self.i = 0
        self.names = names

    def peek(self):
        return self.t[self.i] if self.i < len(self.t) else None

    def take(self, expect=None):
        v = self.peek()
        if v is None:
            raise RuleError("condition ended early")
        if expect and v != expect:
            raise RuleError("expected %r, found %r" % (expect, v))
        self.i += 1
        return v

    def parse(self):
        n = self.or_expr()
        if self.peek() is not None:
            raise RuleError("unparsed condition tail %r" % self.peek())
        return n

    def or_expr(self):
        n = self.and_expr()
        while self.peek() == "or":
            self.take()
            n = SigmaCond("or", a=n, b=self.and_expr())
        return n

    def and_expr(self):
        n = self.unary()
        while self.peek() == "and":
            self.take()
            n = SigmaCond("and", a=n, b=self.unary())
        return n

    def unary(self):
        if self.peek() == "not":
            self.take()
            return SigmaCond("not", a=self.unary())
        return self.primary()

    def _expand(self, pat):
        if pat == "them":
            return list(self.names)
        if pat.endswith("*"):
            return [n for n in self.names if n.startswith(pat[:-1])]
        return [pat] if pat in self.names else []

    def primary(self):
        tok = self.peek()
        if tok == "(":
            self.take()
            n = self.or_expr()
            self.take(")")
            return n
        if tok == "all":
            self.take()
            self.take("of")
            names = self._expand(self.take())
            return SigmaCond("of", n=len(names), names=names)
        if tok and tok.isdigit():
            n = int(self.take())
            self.take("of")
            names = self._expand(self.take())
            return SigmaCond("of", n=n, names=names)
        if tok:
            self.take()
            names = self._expand(tok)
            if not names:
                raise RuleError("condition references unknown selection %r" % tok)
            if tok.endswith("*") or tok == "them":
                return SigmaCond("of", n=1, names=names)
            return SigmaCond("sel", name=names[0])
        raise RuleError("empty condition")


#: Modifiers whose values are not plain text in the row, so no literal can be
#: read out of them for the gate below.
_GATE_SKIP = frozenset(("re", "base64", "base64offset", "cidr", "expand",
                        "windash", "utf16", "utf16le", "utf16be", "wide"))


def _literal_of(value):
    """The longest run of ordinary characters in a Sigma value, lowered.

    A value is a literal with '*' and '?' as wildcards, so the longest stretch
    between them is text that must appear verbatim if the value matches at
    all. '/etc/cron.d/*' gives '/etc/cron.d/'; a bare '*' gives nothing.
    """
    best = ""
    cur = []
    i = 0
    v = str(value).lower()
    while i < len(v):
        c = v[i]
        if c == chr(92) and i + 1 < len(v):
            cur.append(v[i + 1])
            i += 2
            continue
        if c in "*?":
            if len("".join(cur)) > len(best):
                best = "".join(cur)
            cur = []
        else:
            cur.append(c)
        i += 1
    if len("".join(cur)) > len(best):
        best = "".join(cur)
    return best


def _gate_of_matcher(m):
    """(selectivity, literals) one matcher insists on, or None for nothing.

    A keyword block has no modifiers and searches the whole row, which is
    exactly what this gate does - so it gates perfectly. A Matcher carries
    modifiers, some of which mean the value is not plain text in the row at
    all.
    """
    if _GATE_SKIP & set(getattr(m, "mods", ())):
        return None
    if getattr(m, "always", False):
        return None                     # a bare '*' keyword matches anything
    # The gate reads the whole-row haystack, and that haystack leaves out the
    # columns this export adds to say where a row came from. A matcher on one
    # of those - 'path' above all - can be satisfied by text the haystack
    # never contains, so gating on its literal discards real matches. It cost
    # the one row that named /tmp/apache-xTRhUVX, which is the payload the
    # rule exists for.
    if set(getattr(m, "candidates", ())) & Keywords.PROVENANCE:
        return None
    lits = []
    for v in getattr(m, "values", ()):
        if v is None:
            return None                 # 'field: null' asks for an absence
        lit = _literal_of(v)
        if len(lit) < 4:                # too common to be worth testing
            return None
        lits.append(lit)
    if not lits:
        return None
    if getattr(m, "all", False):
        # every value must be present, so insisting on the longest one alone
        # is both sound and the most selective single test available
        best = max(lits, key=len)
        return (len(best), [best])
    return (min(len(x) for x in lits), lits)


def _gate_and(a, b):
    """Both must hold, so the more selective of the two is enough."""
    if a is None:
        return b
    if b is None:
        return a
    return a if a[0] >= b[0] else b


def _gate_or(a, b):
    """Either may fire, so the row must hold something from either side.

    A branch that insists on nothing sinks the whole gate: there would be a
    way for the rule to match with none of the literals present.
    """
    if a is None or b is None:
        return None
    return (min(a[0], b[0]), a[1] + b[1])


def _gate_of_selection(sel):
    """A selection is an OR over its groups and an AND inside each one."""
    out = None
    for group in sel.groups:
        best = None
        for m in group:
            best = _gate_and(best, _gate_of_matcher(m))
        if best is None:
            return None
        out = best if out is None else _gate_or(out, best)
    return out


def _gate_node(node, sels):
    """Walk the condition the way eval_sigma does, collecting what it forces."""
    k = node.kind
    if k == "sel":
        sel = sels.get(node.name)
        return _gate_of_selection(sel) if sel is not None else None
    if k == "and":
        return _gate_and(_gate_node(node.a, sels), _gate_node(node.b, sels))
    if k == "or":
        return _gate_or(_gate_node(node.a, sels), _gate_node(node.b, sels))
    if k == "of":
        if node.n <= 0:                 # '0 of them' is true of every row
            return None
        gates = [_gate_of_selection(sels[n]) if n in sels else None
                 for n in node.names]
        if node.n >= len(node.names):   # all of them: an AND
            out = None
            for g in gates:
                out = _gate_and(out, g)
            return out
        out = None                      # any n of them: an OR
        for g in gates:
            if g is None:
                return None
            out = g if out is None else _gate_or(out, g)
        return out
    return None                         # 'not' forces nothing, nor does the
                                        # unknown - both mean "no gate"


def _gate_for(cond, sels):
    """One OR-group of literals a row must contain, or None.

    The point is to answer "could this rule possibly match this row" with a
    handful of str.__contains__ calls instead of a regex per matcher. Python's
    substring search is C and very fast; the rule engine underneath is not.

    It is a pure skip: when the gate passes, the rule is evaluated exactly as
    it was, so a match set cannot change. What makes that safe is that every
    step above weakens rather than strengthens - an AND may keep either side,
    an OR must keep both, and anything not understood gives up entirely. The
    result is a necessary condition for the rule, never a sufficient one.

    The first version of this only looked at selections an AND forced, and
    gave up on 'sel_a or sel_b' and on any selection written as a list of
    maps. That is how a rule comes to be evaluated against all 1.19M rows of
    VAR_LOG: 31 of the 44 rules written for this collection are shaped that
    way, and they cost more than the 334-rule SigmaHQ set put together.
    """
    got = _gate_node(cond, sels)
    return got[1] if got else None


def eval_sigma(node, sels, row):
    k = node.kind
    if k == "and":
        return eval_sigma(node.a, sels, row) and eval_sigma(node.b, sels, row)
    if k == "or":
        return eval_sigma(node.a, sels, row) or eval_sigma(node.b, sels, row)
    if k == "not":
        return not eval_sigma(node.a, sels, row)
    if k == "sel":
        return sels[node.name].test(row)
    if k == "of":
        return sum(1 for n in node.names if sels[n].test(row)) >= node.n
    raise RuleError("cannot evaluate %s" % k)


# ---------------------------------------------------------------------------
# rules
# ---------------------------------------------------------------------------

LEVEL_SEVERITY = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
                  "low": "LOW", "informational": "INFO"}


class SigmaRule:
    def __init__(self, doc, alias, source=""):
        self.source = source
        self.title = str(doc.get("title") or "untitled")
        self.id = str(doc.get("id") or "")
        self.level = str(doc.get("level") or "medium").lower()
        self.severity = LEVEL_SEVERITY.get(self.level, "MEDIUM")
        self.status = str(doc.get("status") or "")
        self.description = str(doc.get("description") or "")
        ls = doc.get("logsource") or {}
        self.product = str(ls.get("product") or "")
        self.service = str(ls.get("service") or "")
        self.category = str(ls.get("category") or "")
        tags = doc.get("tags") or []
        self.tags = [str(t) for t in tags] if isinstance(tags, list) else [str(tags)]
        self.mitre = ", ".join(t.split(".", 1)[1].upper() for t in self.tags
                               if t.lower().startswith("attack.t"))
        det = doc.get("detection")
        if not isinstance(det, dict):
            raise RuleError("no detection block")
        cond = det.get("condition")
        if cond is None:
            raise RuleError("no condition")
        if isinstance(cond, list):
            cond = " or ".join("(%s)" % c for c in cond)
        self.condition_src = str(cond)
        if "|" in self.condition_src:
            raise RuleError("aggregation conditions are not supported")
        self.selections = {}
        for name, spec in det.items():
            if name == "condition":
                continue
            self.selections[name] = Selection(spec, alias)
        self.cond = SigmaCondParser(self.condition_src,
                                    list(self.selections)).parse()
        # A cheap "could this row possibly match" test, worked out once here
        # rather than per row. None means the rule insists on nothing a
        # substring search can check, and it is evaluated as before.
        self.gate = _gate_for(self.cond, self.selections)

    def test(self, row):
        return eval_sigma(self.cond, self.selections, row)


def parse_sigma(text, alias=lambda f: f.lower(), source=""):
    """-> (rules, errors); one YAML file may hold several documents."""
    rules, errors = [], []
    try:
        docs = load_yaml(text)
    except Exception as e:
        return [], [(source or "?", "YAML: %s" % e)]
    for doc in docs:
        if not isinstance(doc, dict) or "detection" not in doc:
            continue
        title = str(doc.get("title") or doc.get("id") or "untitled")
        try:
            rules.append(SigmaRule(doc, alias, source))
        except RuleError as e:
            errors.append((title, str(e)))
        except Exception as e:
            errors.append((title, "%s: %s" % (type(e).__name__, e)))
    return rules, errors


# ---------------------------------------------------------------------------
# keeping the Sigma ruleset current
#
# --sigma points at rule files, and rule files go stale: SigmaHQ merges rules
# every week, so hunting with the copy someone downloaded once, six months ago,
# is a clean result that means nothing. --update-sigma refreshes a local cache,
# and that cache is nothing but a directory of .yml files, so everything past
# the fetch is the ordinary --sigma path with no special case in it.
#
# This is the only place the tool touches the network, it only does so when
# asked, and it is substitutable: --sigma-source takes a local .zip or a
# directory, which is how an evidence workstation with no route out still gets
# this week's rules off a USB stick.
# ---------------------------------------------------------------------------

SIGMA_SOURCE = "https://codeload.github.com/SigmaHQ/sigma/zip/refs/heads/master"

# Directories in the SigmaHQ repo that are not rules to hunt with: deprecated
# and unsupported are kept for reference only, the placeholders match on
# %placeholder% values a real environment is meant to fill in, and the rest is
# the repo's own test and documentation material.
SIGMA_SKIP_TREES = frozenset((
    "deprecated", "unsupported", "unsupported_rules", "rules-placeholder",
    "tests", "regression_data", "documentation", "images", "other", ".github",
))

_SIGMA_LOGSOURCE = re.compile(r"(?m)^logsource:[ \t]*\r?\n((?:[ \t]+[^\n]*\r?\n?)+)")
_SIGMA_LS_FIELD = re.compile(
    r"""(?m)^[ \t]+(product|category|service)[ \t]*:[ \t]*['"]?([^'"\r\n#]*)""")


def sigma_logsource(text):
    """{product, category, service} read straight out of a rule's text.

    Deliberately not a YAML parse: this only decides which of 4,200 files are
    worth keeping, and the regex does that in 0.2s where parsing every document
    takes 9s to reach the same answer.
    """
    m = _SIGMA_LOGSOURCE.search(text)
    if not m:
        return {}
    return dict((k, v.strip().lower())
                for k, v in _SIGMA_LS_FIELD.findall(m.group(1)))


def sigma_rule_wanted(text):
    """Could this rule ever be routed to a table this tool builds?

    The cache is filtered when it is fetched rather than when it is loaded
    because SigmaHQ is 4,200 rules and 3,000 of them read Windows event logs.
    Keeping those costs a slower load on every run and fills RULE_ERRORS with
    rejected Windows constructs that bury the rejections worth reading.
    """
    ls = sigma_logsource(text)
    if ls.get("product", "") not in ("", "linux", "unix"):
        return False
    want = ls.get("service") or ls.get("category") or ""
    if not want:                        # a bare 'product: linux' rule
        return True
    # imported here rather than at module scope: the table layer is built
    # on top of the rule engine, so naming it up there would close the loop
    from .tables import TableBuilder
    for _tname, aliases, _ts in TableBuilder.SIGMA_STREAMS:
        for alias in aliases:
            if want == alias or want in alias or alias in want:
                return True
    return False


def sigma_cache_dir(explicit=None):
    """Where the fetched ruleset lives - outside any collection, by design."""
    path = explicit or os.environ.get("LINSIGHT_SIGMA_DIR")
    if path:
        return os.path.abspath(os.path.expanduser(path))
    return os.path.join(os.path.expanduser("~"), ".linsight", "sigma")


def sigma_cache_manifest(dest):
    """What the last --update-sigma wrote there, or {}."""
    try:
        with open(os.path.join(dest, "manifest.json"), "r", encoding="utf-8") as fh:
            m = json.load(fh)
        return m if isinstance(m, dict) else {}
    except (OSError, ValueError):
        return {}


def sigma_cache_count(dest):
    """Rules currently cached, counted from the files rather than the manifest."""
    n = 0
    for _root, _dirs, files in os.walk(dest):
        n += sum(1 for f in files if f.lower().endswith((".yml", ".yaml")))
    return n


def _sigma_safe_rel(name):
    """Archive member -> a relative path safe to join, or None.

    An archive is untrusted input even when the name it came from is trusted,
    and a member called ../../.ssh/authorized_keys is the whole reason to look.
    """
    parts = []
    for part in name.replace("\\", "/").split("/"):
        if not part or part == ".":
            continue
        if part == ".." or ":" in part:
            return None
        parts.append(part)
    return "/".join(parts) if parts else None


def _win_long(path):
    r"""Windows caps a path at 260 characters unless it is spelled \\?\.

    SigmaHQ nests rules five directories deep under names like
    rules-emerging-threats/2023/TA/UNC4841-Barracuda-ESG-Zero-Day-Exploitation,
    so a cache anywhere but the shortest home directory loses a handful of
    rules to the cap - and they are the emerging-threat ones, which is what a
    fresh ruleset was fetched for.
    """
    if os.name != "nt" or path.startswith("\\\\?\\"):
        return path
    full = os.path.abspath(path)
    return "\\\\?\\" + full if len(full) > 240 else path


def _rename_retry(src, dst, tries=5):
    """os.rename, retried - Windows refuses one over a tree just written.

    Renaming a directory of 4,000 second-old files comes back as access denied
    often enough to matter: whatever holds the handle (Defender, the indexer)
    lets go in a moment, and the alternative is losing a good fetch to it.
    """
    for i in range(tries):
        try:
            os.rename(src, dst)
            return
        except PermissionError:
            if i == tries - 1:
                raise
            time.sleep(0.2 * (i + 1))


def _sigma_fetch(url, etag=None, timeout=60, quiet=False):
    """-> (data, etag). data is None when the server says 'not modified'."""
    import urllib.error
    import urllib.request

    req = urllib.request.Request(url, headers={
        "User-Agent": "linsight/%s" % VERSION,
        "Accept": "application/zip, */*",
    })
    if etag:
        req.add_header("If-None-Match", etag)
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
    except urllib.error.HTTPError as e:
        if e.code == 304:                       # cache already holds this one
            return None, etag
        raise SystemExit("[!] sigma update failed: HTTP %s %s\n    %s"
                         % (e.code, e.reason, url))
    except Exception as e:
        raise SystemExit(
            "[!] sigma update failed: %s: %s\n    %s\n"
            "    no route out? fetch the ruleset elsewhere and pass the zip:\n"
            "      --update-sigma --sigma-source ./sigma-master.zip"
            % (type(e).__name__, e, url))
    with resp:
        total = int(resp.headers.get("Content-Length") or 0)
        show = (not quiet) and sys.stderr.isatty()
        chunks, got = [], 0
        while True:
            chunk = resp.read(65536)
            if not chunk:
                break
            chunks.append(chunk)
            got += len(chunk)
            if show:
                sys.stderr.write("\r[*] sigma: downloading %s%s   "
                                 % (human_size(got),
                                    " of %s" % human_size(total) if total else ""))
                sys.stderr.flush()
        if show:
            sys.stderr.write("\r" + " " * 60 + "\r")
        return b"".join(chunks), (resp.headers.get("ETag") or etag)


def _sigma_members(data, source_dir):
    """(relative path, text) for every rule file in the source.

    The zip GitHub serves wraps everything in one sigma-master/ directory; that
    prefix is dropped so a cached rule reads rules/linux/... - the path it has
    in the repo, which is what makes SIGMA_MATCHES.rule_file traceable.
    """
    if source_dir:
        for root, _dirs, files in os.walk(source_dir):
            for f in sorted(files):
                if not f.lower().endswith((".yml", ".yaml")):
                    continue
                full = os.path.join(root, f)
                rel = os.path.relpath(full, source_dir).replace(os.sep, "/")
                try:
                    with open(_win_long(full), "r", encoding="utf-8",
                              errors="replace") as fh:
                        yield rel, fh.read()
                except OSError:
                    continue
        return
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        names = [n for n in z.namelist() if n.lower().endswith((".yml", ".yaml"))]
        roots = set(n.split("/")[0] for n in z.namelist() if "/" in n)
        strip = (roots.pop() + "/") if len(roots) == 1 else ""
        for name in sorted(names):
            rel = _sigma_safe_rel(name[len(strip):]
                                  if strip and name.startswith(strip) else name)
            if not rel:
                continue
            try:
                yield rel, z.read(name).decode("utf-8", "replace")
            except Exception:                   # one unreadable member, not a run
                continue


def update_sigma_rules(dest, source=None, keep_all=False, timeout=60, quiet=False):
    """Refresh the cached Sigma ruleset in dest. -> rules cached.

    Written to a staging directory and swapped in at the end, so a fetch that
    dies half way leaves the previous ruleset intact rather than a directory
    holding a third of one.
    """
    source = source or SIGMA_SOURCE
    url = source if re.match(r"^https?://", source) else ""
    local = "" if url else os.path.abspath(os.path.expanduser(source))
    data, source_dir, etag = None, "", ""

    if url:
        have, old = sigma_cache_count(dest), sigma_cache_manifest(dest)
        # Only claim to hold this ruleset when the rules are still on disk: an
        # etag from a manifest whose directory was emptied means a 304 and no
        # rules, which is the one outcome an update must never produce.
        prev = old.get("etag") if have and old.get("url") == url else None
        status("[*] sigma: fetching %s" % url)
        data, etag = _sigma_fetch(url, prev, timeout, quiet)
        if data is None:
            status("[*] sigma: cache is already current - %d rule(s) in %s"
                   % (have, dest))
            return have
        if not zipfile.is_zipfile(io.BytesIO(data)):
            # A captive portal or a proxy login page answers 200 with HTML,
            # and the only honest reading of that is "no ruleset was fetched"
            raise SystemExit(
                "[!] sigma update failed: %s answered with %s of %s, not a zip"
                % (url, human_size(len(data)),
                   "HTML - a proxy or portal login page?"
                   if data.lstrip()[:1] == b"<" else "something else"))
    elif os.path.isdir(local):
        status("[*] sigma: reading rules from %s" % local)
        source_dir = local
    elif os.path.isfile(local):
        status("[*] sigma: reading rules from %s" % local)
        try:
            with open(local, "rb") as fh:
                data = fh.read()
        except OSError as e:
            raise SystemExit("[!] sigma update failed: %s" % e)
        if not zipfile.is_zipfile(io.BytesIO(data)):
            raise SystemExit("[!] --sigma-source file is not a zip: %s" % local)
    else:
        raise SystemExit("[!] --sigma-source is neither a URL, a zip nor a "
                         "directory: %s" % source)

    staging = dest.rstrip("/\\") + ".new"
    shutil.rmtree(_win_long(staging), ignore_errors=True)
    kept = seen = 0
    try:
        for rel, text in _sigma_members(data, source_dir):
            seen += 1
            if rel.split("/")[0] in SIGMA_SKIP_TREES:
                continue
            if not keep_all and not sigma_rule_wanted(text):
                continue
            out = _win_long(os.path.join(staging, rel.replace("/", os.sep)))
            try:
                os.makedirs(os.path.dirname(out), exist_ok=True)
                with open(out, "w", encoding="utf-8") as fh:
                    fh.write(text)
            except OSError as e:
                status("[!] sigma: cannot write %s: %s" % (out, e))
                continue
            kept += 1
        if not kept:
            raise SystemExit(
                "[!] sigma update found no rules this tool can route in %s\n"
                "    a ruleset for another platform is still worth caching - "
                "add --sigma-all" % source)
        manifest = {
            "source": source,
            "url": url,
            "etag": etag or "",
            "fetched_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            "rules": kept,
            "considered": seen,
            "filtered": not keep_all,
            "tool_version": VERSION,
        }
        with open(os.path.join(staging, "manifest.json"), "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2, sort_keys=True)

        # swap: the old ruleset stays readable until the new one is complete
        backup = dest.rstrip("/\\") + ".old"
        shutil.rmtree(_win_long(backup), ignore_errors=True)
        parent = os.path.dirname(os.path.abspath(dest))
        if parent:
            os.makedirs(parent, exist_ok=True)
        if os.path.isdir(dest):
            _rename_retry(dest, backup)
        try:
            _rename_retry(staging, dest)
        except OSError:
            if os.path.isdir(backup) and not os.path.exists(dest):
                os.rename(backup, dest)         # put the old ruleset back
            raise
        shutil.rmtree(_win_long(backup), ignore_errors=True)
    finally:
        shutil.rmtree(_win_long(staging), ignore_errors=True)

    status("[+] sigma: %d rule(s) cached in %s%s"
           % (kept, dest,
              " (of %d in the source; the rest target a platform this tool "
              "builds no table for)" % seen if kept < seen else ""))
    return kept
