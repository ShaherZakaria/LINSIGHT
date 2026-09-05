"""An MCP server over a finished case, so a model can investigate it.

The database is the whole point. A collection parses to three and a half
million rows and a 870 MB case.db; no model reads that, and pasting a slice of
it into a prompt produces confident answers about whichever slice was pasted.
So nothing is summarised here and nothing is pre-digested - the model is given
the schema and a read-only SELECT, and has to go and look. What it reports can
then be checked against the same query.

Read-only is enforced twice, because one of them is not enough: the connection
is opened with mode=ro so the file cannot be written through it whatever
arrives, and the statement itself has to be a single SELECT or WITH. A model
writing to an evidence database is not a risk worth carrying for the
convenience of not checking.

Speaks JSON-RPC 2.0 over stdio, one message per line, which is what MCP's
stdio transport is. Nothing is written to stdout that is not a response -
progress and errors go to stderr - because a stray print corrupts the stream
and the failure looks like the model has gone mad rather than like a bug here.
"""

import json
import os
import re
import sqlite3
import sys
import time

PROTOCOL = "2024-11-05"
ROW_CAP = 200                   # rows returned unless the caller asks for more
ROW_MAX = 2000
CELL_CAP = 600                  # a log line can be 2 KB; a model does not need
                                # every byte of forty of them at once


QUERY_SECONDS = 30              # how long one statement may run before it
                                # is stopped and handed back as a mistake
SEARCH_SECONDS = 60             # the whole-case sweep touches every column of
                                # every table, so it gets its own, larger one


class CaseError(Exception):
    """Something the caller did, reported to the model rather than raised."""


# ---------------------------------------------------------------- database

def _open(path):
    if not path or not os.path.isfile(path):
        raise CaseError("no database at %r - run with --db or --serve first, "
                        "which writes case.db beside the export" % path)
    db = sqlite3.connect("file:%s?mode=ro" % path.replace("\\", "/"), uri=True)
    db.execute("PRAGMA query_only = ON")
    return db


def _tables(db):
    """name -> row count, from the manifest the export writes."""
    out = {}
    try:
        for name, rows in db.execute("SELECT name, rows FROM _tables"):
            out[str(name)] = rows
    except sqlite3.Error:
        for (name,) in db.execute("SELECT name FROM sqlite_master "
                                  "WHERE type='table' AND name NOT LIKE '\\_%' "
                                  "ESCAPE '\\'"):
            out[str(name)] = None
    return out


def _cols(db, name):
    return [c[1] for c in db.execute('PRAGMA table_info("%s")' % name)]


def _check(name, known):
    if name not in known:
        raise CaseError("no table called %r. case_tables lists them." % name)
    return name


def _budget(db, seconds=None):
    """Stop a statement that is not going to finish.

    A model writing SQL against forty tables eventually writes a join with no
    ON clause, and against three and a half million rows that is not a slow
    query, it is a server that has stopped answering. SQLite will cancel one
    mid-flight if asked often enough, so ask: the callback runs every hundred
    thousand VM steps and returns non-zero once the clock is out.

    The cancellation surfaces as OperationalError('interrupted'), which the
    caller turns back into a sentence the model can act on. A model told its
    query was too broad narrows it. A model told nothing waits, and so does
    the examiner.
    """
    # Read at call time, not bound as a default: a default argument is
    # evaluated once at import, and a constant that cannot be turned down for
    # a test is a constant nobody tests.
    end = time.monotonic() + (QUERY_SECONDS if seconds is None else seconds)

    def tick():
        return 1 if time.monotonic() > end else 0

    db.set_progress_handler(tick, 100000)


def _unbudget(db):
    db.set_progress_handler(None, 0)


def _cell(v):
    if v is None:
        return ""
    s = v if isinstance(v, str) else str(v)
    return s if len(s) <= CELL_CAP else s[:CELL_CAP - 3] + "..."


def _rows(cur, cap):
    cols = [d[0] for d in cur.description]
    out = []
    for r in cur:
        out.append(dict(zip(cols, [_cell(v) for v in r])))
        if len(out) >= cap:
            break
    return cols, out


def _limit(args, default=ROW_CAP):
    try:
        n = int(args.get("limit") or default)
    except (TypeError, ValueError):
        n = default
    return max(1, min(ROW_MAX, n))


# ---------------------------------------------------------------- the tools

def t_tables(db, args):
    """Every table, its size and its columns - the map the model works from."""
    known = _tables(db)
    want = args.get("table")
    if want:
        _check(want, known)
        names = [want]
    else:
        names = sorted(known)
    out = []
    for n in names:
        out.append({"table": n, "rows": known.get(n),
                    "columns": _cols(db, n)})
    return {"tables": out, "total": len(known)}


def t_query(db, args):
    """One read-only SELECT, which is the tool the rest are shortcuts for."""
    sql = str(args.get("sql") or "").strip().rstrip(";").strip()
    if not sql:
        raise CaseError("sql is required")
    head = sql.lstrip("( \t\r\n")[:6].lower()
    if not (head.startswith("select") or head.startswith("with")):
        raise CaseError("read-only: the statement must be a SELECT or a WITH")
    if ";" in sql:
        raise CaseError("one statement at a time")
    cap = _limit(args)
    _budget(db)
    try:
        cur = db.execute(sql)
        cols, rows = _rows(cur, cap)
    except sqlite3.OperationalError as e:
        if "interrupt" in str(e).lower():
            raise CaseError(
                "that query ran for %d seconds without finishing and was "
                "stopped. It is almost always a join with no condition "
                "linking the two tables, or a LIKE over the largest table in "
                "the case. Narrow it: name the columns instead of *, add a "
                "WHERE on a time or an identifier, and join on one of the "
                "columns the schema lists as shared." % QUERY_SECONDS)
        raise CaseError(_sql_error(db, sql, e))
    except sqlite3.Error as e:
        raise CaseError(_sql_error(db, sql, e))
    finally:
        _unbudget(db)
    out = {"columns": cols, "rows": rows, "returned": len(rows),
           "capped": len(rows) >= cap}
    if out["capped"]:
        # A flag gets read past; a sentence does not. Asked to break a claim,
        # llama3.1:8b ran a query with LIMIT 20, got twenty rows back beside
        # "capped": true, and reported "AUTH_LOG has 20 rows". It has 26,807.
        # Reporting the page size as the population is the same wrong-number
        # mistake as reporting an empty page as an absence, and it is fixed
        # the same way - by saying it in words, in the result.
        out["note"] = ("this is the first %d row(s) and there are more - %d "
                       "is the limit, not the count. Do not report it as a "
                       "total. If you need the number, run the same query as "
                       "SELECT COUNT(*) with the same WHERE and no LIMIT."
                       % (len(rows), cap))
    if not rows:
        # An empty result is the one answer a model reports without checking,
        # and the one it is most often wrong about. So it does not come back
        # empty: it comes back with what the columns it filtered on really
        # contain, and with the sentence that has to be said out loud.
        out["note"] = ("0 rows is not evidence that the host has none. It "
                       "usually means a filter value is wrong. Do not report "
                       "this as an absence - correct the query and run it "
                       "again, or say the data cannot answer it.")
        why = _why_empty(db, sql)
        if why:
            out["check_your_values"] = why
    return out


# What a statement filtered on, so an empty result can answer the question the
# model is about to get wrong. Deliberately crude - this is not a SQL parser
# and does not need to be. It has to find the column names on the left of a
# literal comparison, and being wrong about one costs a hint that is not shown.
_FROM = re.compile(r'(?:from|join)\s+"?([A-Za-z_][A-Za-z_0-9]*)"?', re.I)
_FILTER = re.compile(r'"?([A-Za-z_][A-Za-z_0-9]*)"?\s*(?:=|==|like)\s*'
                     r"'([^']*)'", re.I)


def _sql_error(db, sql, err):
    """A rejected statement, with the columns that would have worked.

    'no such column: timestamp_utc' is true and useless. LOGINS keeps its times
    in start and end - the one table in the case that does - and a model told
    only that its column does not exist has no way to find that out except by
    spending another turn on case_tables. llama3.1:8b did not spend it: it gave
    up on the query and replied with the SQL as prose.

    So the rejection carries the answer. Naming the columns costs nothing, it
    is already in the schema, and it turns a dead end into the next query.
    """
    text = str(err)
    if "no such column" not in text.lower():
        return "sqlite: %s" % text
    known = _tables(db)
    named = []
    for name in _FROM.findall(sql or ""):
        if name in known and name not in named:
            named.append(name)
    if not named:
        return "sqlite: %s" % text
    parts = ["sqlite: %s." % text,
             "These are the columns those tables really have -"]
    for name in named[:4]:
        parts.append("  %s: %s" % (name, ", ".join(_cols(db, name))))
    parts.append("Pick from those and run it again. Two names are worth "
                 "knowing before you guess: times are not all called "
                 "timestamp_utc - LOGINS keeps them in start and end - and "
                 "whether an attempt was granted or refused is result, "
                 "never outcome or status. state is something else, how a "
                 "session ended.")
    return chr(10).join(parts)


def _why_empty(db, sql, seconds=5):
    """What the columns a query filtered on actually contain.

    The most expensive answer an analyst can be given is a wrong negative, and
    this is where they come from. Asked which address failed the most SSH
    logins, llama3.1:8b filtered FAILED_LOGINS on kind = 'SSH' - a column that
    only ever holds 'btmp' - got nothing back, and reported that the host had
    recorded no failed SSH logins at all. There were 210.

    The instruction to check the vocabulary before believing an empty result
    was already in the system prompt, three hundred words earlier, and the
    model went straight past it. So the correction moves to where it cannot be
    missed: the empty result itself carries the values that column really
    holds. A model that is shown 'btmp' does not need to be told to ask.

    Bounded, and silent when it cannot finish: a hint is worth having and
    never worth waiting for.
    """
    tables, cols_of = [], {}
    known = _tables(db)
    for name in _FROM.findall(sql or ""):
        if name in known and name not in cols_of:
            tables.append(name)
            cols_of[name] = _cols(db, name)

    seen, out = set(), []
    for col, value in _FILTER.findall(sql or ""):
        for name in tables:
            if col not in cols_of[name] or (name, col) in seen:
                continue
            seen.add((name, col))
            _budget(db, seconds)
            try:
                rows = list(db.execute(
                    'SELECT "%s" AS v, COUNT(*) n FROM "%s" '
                    'WHERE "%s" <> \'\' GROUP BY 1 ORDER BY 2 DESC LIMIT 8'
                    % (col, name, col)))
            except sqlite3.Error:
                continue                    # too slow, or not a real column
            finally:
                _unbudget(db)
            if rows:
                out.append({"table": name, "column": col,
                            "you_filtered_for": value,
                            "it_actually_holds":
                                [{"value": _cell(v), "rows": n}
                                 for v, n in rows]})
        if len(out) >= 4:                   # enough to correct with
            break
    return out


def t_findings(db, args):
    """The analysis tables, severity first - where an examiner starts."""
    known = _tables(db)
    sev = str(args.get("severity") or "").upper()
    order = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    name = "FINDINGS" if "FINDINGS" in known else None
    if not name:
        raise CaseError("this case has no FINDINGS table")
    cols = _cols(db, name)
    where, params = "", []
    if sev:
        if sev not in order:
            raise CaseError("severity must be one of %s" % ", ".join(order))
        where, params = ' WHERE severity = ?', [sev]
    cap = _limit(args)
    cur = db.execute('SELECT * FROM "%s"%s' % (name, where), params)
    _c, rows = _rows(cur, cap)
    rank = dict((s, i) for i, s in enumerate(order))
    if "severity" in cols:
        rows.sort(key=lambda r: rank.get(str(r.get("severity", "")), 99))
    return {"columns": cols, "rows": rows, "returned": len(rows)}


def t_timeline(db, args):
    """What happened between two timestamps, across every dated table.

    The question an examiner asks after finding one event is always what else
    was happening around it, and the answer is never in one table.
    """
    t0 = str(args.get("from") or "").strip()
    t1 = str(args.get("to") or "").strip()
    if not t0 or not t1:
        raise CaseError("from and to are required, as 'YYYY-MM-DD HH:MM:SS'")
    known = _tables(db)
    cap = _limit(args, 40)
    out, looked = [], 0
    for name in sorted(known):
        cols = _cols(db, name)
        stamp = next((c for c in ("timestamp_utc", "start_utc", "first_utc")
                      if c in cols), None)
        if not stamp:
            continue
        looked += 1
        try:
            cur = db.execute(
                'SELECT * FROM "%s" WHERE "%s" >= ? AND "%s" <= ? '
                'ORDER BY "%s" LIMIT ?' % (name, stamp, stamp, stamp),
                [t0, t1, cap])
        except sqlite3.Error:
            continue
        _c, rows = _rows(cur, cap)
        if rows:
            out.append({"table": name, "time_column": stamp,
                        "rows": rows, "returned": len(rows)})
    return {"from": t0, "to": t1, "tables_with_events": len(out),
            "tables_searched": looked, "events": out}


def t_search(db, args):
    """One term across every column of every table.

    Slow and deliberately so - it is the move that finds an address in the
    three tables nobody thought to look in. Bounded by a clock rather than by
    a table count, and it says which tables the clock cost it: an incomplete
    sweep reported as a complete one is how a present indicator becomes an
    absent one.
    """
    term = str(args.get("term") or "").strip()
    if len(term) < 2:
        raise CaseError("term must be at least two characters")
    known = _tables(db)
    only = args.get("tables") or []
    if only:
        for n in only:
            _check(n, known)
    # Smallest first. The sweep is bounded by a clock, so the order decides
    # what is inside the bound when it runs out - and forty small tables
    # answered is a better partial result than one 3.5-million-row BODYFILE
    # scanned while the other thirty-nine went unlooked-at.
    names = sorted(only or known, key=lambda n: (known.get(n) or 0, n))
    cap = _limit(args, 5)
    like = "%" + term.replace("%", "\\%").replace("_", "\\_") + "%"
    hits, unsearched = [], []
    end = time.monotonic() + SEARCH_SECONDS
    for name in names:
        if time.monotonic() > end:
            unsearched.append(name)
            continue
        cols = _cols(db, name)
        if not cols:
            continue
        where = " OR ".join('"%s" LIKE ? ESCAPE \'\\\'' % c for c in cols)
        _budget(db, max(1, end - time.monotonic()))
        try:
            cur = db.execute('SELECT COUNT(*) FROM "%s" WHERE %s'
                             % (name, where), [like] * len(cols))
            n = cur.fetchone()[0]
            if n:
                cur = db.execute('SELECT * FROM "%s" WHERE %s LIMIT ?'
                                 % (name, where), [like] * len(cols) + [cap])
                _c, rows = _rows(cur, cap)
                hits.append({"table": name, "matches": n, "sample": rows})
        except sqlite3.Error:
            unsearched.append(name)             # interrupted, or unscannable
        finally:
            _unbudget(db)
    hits.sort(key=lambda h: -h["matches"])
    out = {"term": term, "tables_with_matches": len(hits),
           "total_matches": sum(h["matches"] for h in hits), "hits": hits}
    if unsearched:
        # Said rather than swallowed. A search that quietly covered half the
        # case reads exactly like one that covered all of it and found
        # nothing, and that is the difference between a lead and a wrong
        # negative.
        out["not_searched"] = unsearched
        out["note"] = ("the %d second budget ran out before these tables "
                       "were searched, so this is not a complete answer. "
                       "Search them directly with the tables argument, or "
                       "query them with a WHERE on the column you expect "
                       "the term in." % SEARCH_SECONDS)
    return out


def t_values(db, args):
    """What a column actually contains, most common first.

    The gap between a schema and a query is the vocabulary. Told the columns
    of LOGIN_RECORDS, a model wrote outcome = 'success', got nothing back, and
    reported that the host had recorded no successful sign-in - when that
    column only ever holds 'FAILED LOGIN' and the successes were in AUTH_LOG
    under result = 'success'. A wrong negative is the most expensive answer an
    analyst can be given, and this is what stops it.
    """
    known = _tables(db)
    name = _check(str(args.get("table") or ""), known)
    col = str(args.get("column") or "")
    cols = _cols(db, name)
    if col not in cols:
        raise CaseError("%s has no column %r. Its columns are: %s"
                        % (name, col, ", ".join(cols)))
    cap = _limit(args, 25)
    cur = db.execute('SELECT "%s" AS value, COUNT(*) AS rows FROM "%s" '
                     'GROUP BY 1 ORDER BY 2 DESC LIMIT ?' % (col, name), [cap])
    out = [{"value": _cell(v), "rows": n} for v, n in cur]
    total = db.execute('SELECT COUNT(DISTINCT "%s") FROM "%s"'
                       % (col, name)).fetchone()[0]
    return {"table": name, "column": col, "distinct_values": total,
            "showing": len(out), "values": out}


def t_row(db, args):
    """The rows where named columns hold exactly the given values.

    What a finding quotes is a summary with the long fields shortened. This is
    how the model gets the row itself, at full length, to check the quote
    against rather than trusting it.
    """
    known = _tables(db)
    name = _check(str(args.get("table") or ""), known)
    keys = args.get("keys") or {}
    if not isinstance(keys, dict) or not keys:
        raise CaseError("keys must be an object of column -> exact value")
    cols = _cols(db, name)
    use = [(k, v) for k, v in keys.items() if k in cols]
    if not use:
        raise CaseError("none of %s is a column of %s. Its columns are: %s"
                        % (", ".join(map(str, keys)), name, ", ".join(cols)))
    where = " AND ".join('"%s" = ?' % k for k, _ in use)
    cap = _limit(args, 5)
    cur = db.execute('SELECT * FROM "%s" WHERE %s LIMIT ?' % (name, where),
                     [str(v) for _, v in use] + [cap])
    _c, rows = _rows(cur, cap)
    return {"table": name, "matched_on": [k for k, _ in use],
            "rows": rows, "returned": len(rows)}


TOOLS = [
    ("case_tables",
     "Every table in the case with its row count and columns. Start here: the "
     "table names and column names are what every other tool takes.",
     {"type": "object",
      "properties": {"table": {"type": "string",
                               "description": "one table, instead of all"}}},
     t_tables),
    ("case_query",
     "Run one read-only SELECT against the case database. This is the real "
     "tool - the others are shortcuts. Standard SQLite; the schema comes from "
     "case_tables.",
     {"type": "object",
      "properties": {"sql": {"type": "string",
                             "description": "a single SELECT or WITH"},
                     "limit": {"type": "integer",
                               "description": "max rows (default 200)"}},
      "required": ["sql"]},
     t_query),
    ("case_findings",
     "The findings the triage raised, most severe first. The starting point "
     "for 'what is wrong with this host'.",
     {"type": "object",
      "properties": {"severity": {"type": "string",
                                  "description": "CRITICAL|HIGH|MEDIUM|LOW|INFO"},
                     "limit": {"type": "integer"}}},
     t_findings),
    ("case_timeline",
     "Every dated row between two timestamps, across every table that carries "
     "a time. Use it after finding one event, to see what surrounded it.",
     {"type": "object",
      "properties": {"from": {"type": "string",
                              "description": "'YYYY-MM-DD HH:MM:SS' UTC"},
                     "to": {"type": "string"},
                     "limit": {"type": "integer",
                               "description": "max rows per table (default 40)"}},
      "required": ["from", "to"]},
     t_timeline),
    ("case_search",
     "Search one term across every column of every table - an address, a "
     "hash, a filename, a username. Slower than a targeted query, and it "
     "finds the tables you would not have thought to look in.",
     {"type": "object",
      "properties": {"term": {"type": "string"},
                     "tables": {"type": "array", "items": {"type": "string"},
                                "description": "restrict to these tables"},
                     "limit": {"type": "integer",
                               "description": "sample rows per table (default 5)"}},
      "required": ["term"]},
     t_search),
    ("case_values",
     "What a column actually contains, most common value first. Use it before "
     "filtering on a value you have not seen - a WHERE that matches nothing "
     "usually means the value is wrong, not that the data is absent.",
     {"type": "object",
      "properties": {"table": {"type": "string"},
                     "column": {"type": "string"},
                     "limit": {"type": "integer",
                               "description": "how many values (default 25)"}},
      "required": ["table", "column"]},
     t_values),
    ("case_row",
     "The full rows where the named columns hold exactly these values. Use it "
     "to pull the real row behind a finding's quoted summary, which is "
     "shortened to fit a cell.",
     {"type": "object",
      "properties": {"table": {"type": "string"},
                     "keys": {"type": "object",
                              "description": "column -> exact value"},
                     "limit": {"type": "integer"}},
      "required": ["table", "keys"]},
     t_row),
]

GUIDE = """This is a finished forensic triage of one Linux host, parsed into a
SQLite database of normalised tables. Investigate it; do not summarise it.

How to work:
  1. case_tables first. The names and columns are the map.
  2. case_findings for what the triage already raised.
  3. case_query for anything else. It is a real SELECT over real rows.
  4. case_row to pull the whole row behind a finding, because what a finding
     quotes is shortened to fit a cell.

What to hold to:
  - Every claim you make should be answerable by a query you ran. Say which
    table and which rows, so the analyst can check you.
  - A table with no rows is not the same as a clean host: it can mean the
    collector never ran that artifact. FINDINGS and SIGMA_COVERAGE say which.
  - Timestamps are UTC throughout.
  - You are read-only, by construction. Nothing you do can alter the case."""


# ------------------------------------------------------------------ protocol

def _send(msg):
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def _result(rid, payload):
    _send({"jsonrpc": "2.0", "id": rid, "result": payload})


def _error(rid, code, message):
    _send({"jsonrpc": "2.0", "id": rid,
           "error": {"code": code, "message": message}})


def _content(payload):
    return {"content": [{"type": "text",
                         "text": json.dumps(payload, indent=1, default=str)}]}


def serve_mcp(path, quiet=False):
    """Read JSON-RPC from stdin until it closes. Returns an exit status."""
    try:
        db = _open(path)
    except CaseError as e:
        sys.stderr.write("[!] mcp: %s\n" % e)
        return 2
    known = _tables(db)
    if not quiet:
        sys.stderr.write("[*] mcp: %s, %d table(s) - waiting for a client\n"
                         % (os.path.basename(path), len(known)))
    # Imported in the body rather than at the top: skills is built after this
    # module, so at module level the name does not exist yet. This is the one
    # exception the build documents, and it exists for exactly this case.
    from .skills import SKILL_BY_NAME, all_tools, available, render
    tools = all_tools()
    call = dict((t[0], t[3]) for t in tools)

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            continue                      # not ours; a stray line is not fatal
        rid = msg.get("id")
        method = msg.get("method") or ""
        params = msg.get("params") or {}

        if method == "initialize":
            want = str(params.get("protocolVersion") or PROTOCOL)
            _result(rid, {
                "protocolVersion": want,
                "capabilities": {"tools": {}, "prompts": {}, "resources": {}},
                "serverInfo": {"name": "linsight", "version": "1.0"},
                "instructions": GUIDE})
            continue
        if method in ("notifications/initialized", "initialized"):
            continue                      # a notification: no id, no reply
        if method == "ping":
            _result(rid, {})
            continue
        if method == "tools/list":
            _result(rid, {"tools": [
                {"name": n, "description": d, "inputSchema": s}
                for n, d, s, _fn in tools]})
            continue

        # The playbooks, as the protocol's own prompts. A client that speaks
        # MCP already has a menu for these, so shipping them this way means an
        # examiner in Claude Desktop picks "Everything one address did" from a
        # list instead of being told the tool exists and left to phrase it.
        if method == "prompts/list":
            _result(rid, {"prompts": [
                {"name": sk["name"], "description": sk["title"] + " - "
                                                   + sk["about"],
                 "arguments": sk["args"]}
                for sk in available(db)]})
            continue
        if method == "prompts/get":
            name = params.get("name")
            args = params.get("arguments") or {}
            try:
                text = render(name, db, args)
            except CaseError as e:
                _error(rid, -32602, str(e))
                continue
            _result(rid, {
                "description": (SKILL_BY_NAME.get(name)
                                or {}).get("title") or str(name),
                "messages": [{"role": "user",
                              "content": {"type": "text", "text": text}}]})
            continue

        # Resources: the two things a client wants attached to the context
        # rather than fetched with a tool call. The schema is the map, and it
        # is what stops a model inventing a table name; the guide is how to
        # work. Both are small, and both are read far more often than they
        # change - which is what a resource is for.
        if method == "resources/list":
            _result(rid, {"resources": [
                {"uri": "case://schema",
                 "name": "Case schema",
                 "description": "Every table in this case, its row count and "
                                "its columns.",
                 "mimeType": "application/json"},
                {"uri": "case://findings",
                 "name": "Findings",
                 "description": "What the triage raised, most severe first.",
                 "mimeType": "application/json"},
                {"uri": "case://guide",
                 "name": "How to work this case",
                 "description": "The method, and what not to conclude.",
                 "mimeType": "text/plain"}]})
            continue
        if method == "resources/read":
            uri = str(params.get("uri") or "")
            try:
                if uri == "case://schema":
                    text = json.dumps(t_tables(db, {}), indent=1, default=str)
                    mime = "application/json"
                elif uri == "case://findings":
                    text = json.dumps(t_findings(db, {"limit": 200}), indent=1,
                                      default=str)
                    mime = "application/json"
                elif uri == "case://guide":
                    text, mime = GUIDE, "text/plain"
                else:
                    _error(rid, -32602, "no resource at %r" % uri)
                    continue
            except CaseError as e:
                _error(rid, -32602, str(e))
                continue
            _result(rid, {"contents": [{"uri": uri, "mimeType": mime,
                                        "text": text}]})
            continue
        if method == "tools/call":
            name = params.get("name")
            args = params.get("arguments") or {}
            fn = call.get(name)
            if fn is None:
                _error(rid, -32602, "no tool called %r" % name)
                continue
            try:
                _result(rid, _content(fn(db, args)))
            except CaseError as e:
                # a mistake the model can correct, so it goes back as content
                # rather than as a protocol error it cannot see the text of
                _result(rid, {"content": [{"type": "text", "text": str(e)}],
                              "isError": True})
            except sqlite3.Error as e:
                _result(rid, {"content": [{"type": "text",
                                           "text": "sqlite: %s" % e}],
                              "isError": True})
            continue
        if rid is not None:
            _error(rid, -32601, "unsupported method %r" % method)
    return 0
