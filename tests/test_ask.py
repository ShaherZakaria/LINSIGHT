#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Test the model-facing half: the MCP server, the playbooks, the ask loop.

    python tests/test_ask.py                  # against src/linsight
    python tests/test_ask.py --built          # against the built linsight.py

No fixtures and no model. The case is a SQLite database this file writes in a
temporary directory, which means this suite runs everywhere and always - the
disk suite skips for want of a few gigabytes of images, and a test that skips
is a test that was not run.

What is worth asserting here is not that the tools return something. It is the
three ways this surface can be wrong in a way nobody notices:

  read-only    the connection and the statement are both meant to refuse a
               write. A model that can UPDATE an evidence database is the one
               failure in here that cannot be undone.
  bounded      a query with no join condition must be stopped and handed back
               as a correctable mistake, and a partial search must say which
               tables it did not reach. Both alternatives - hanging, and
               reporting an incomplete sweep as complete - look like success.
  grounded     a playbook must name the tables this case actually has. A
               playbook that sends a model to query a table the collector
               never wrote produces "no evidence of persistence" from a host
               where persistence was never looked for.
"""

import argparse
import json
import os
import sqlite3
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def load(built):
    """Import the package, or the built single file, as one flat namespace."""
    if built:
        import importlib.util
        path = os.path.join(ROOT, "linsight.py")
        if not os.path.exists(path):
            raise SystemExit("[!] %s does not exist - run tools/build.py"
                             % path)
        spec = importlib.util.spec_from_file_location("linsight_built", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    sys.path.insert(0, os.path.join(ROOT, "src"))
    import linsight.mcp, linsight.skills, linsight.ask          # noqa

    class Flat(object):
        pass

    flat = Flat()
    for mod in (linsight.mcp, linsight.skills, linsight.ask):
        for name in dir(mod):
            if not name.startswith("__"):
                setattr(flat, name, getattr(mod, name))
    return flat


# ---------------------------------------------------------------------------
# a case, small enough to reason about and shaped like a real one
# ---------------------------------------------------------------------------

#: name -> (columns, rows). WEB_LOG is present and empty on purpose: "present
#: but empty" and "not collected at all" are different statements about a host
#: and the playbooks have to tell them apart.
CASE = {
    "FINDINGS": (
        ["severity", "category", "title", "artifact", "count", "first_utc",
         "evidence"],
        [("CRITICAL", "Persistence", "cron runs a binary in /tmp", "CRON", 1,
          "2026-03-08 02:14:09", "* * * * * /tmp/.x"),
         ("HIGH", "Authentication", "SSH brute force", "FAILED_LOGINS", 210,
          "2026-03-08 01:02:00", "root from 209.141.62.185")]),
    "FAILED_LOGINS": (
        ["timestamp_utc", "kind", "user", "source_host", "source_ip",
         "service"],
        [("2026-03-08 01:02:00", "btmp", "root", "", "209.141.62.185", "sshd"),
         ("2026-03-08 01:02:04", "btmp", "root", "", "209.141.62.185", "sshd"),
         ("2026-03-08 01:03:11", "btmp", "admin", "", "45.9.148.99", "sshd")]),
    "AUTH_LOG": (
        ["timestamp_utc", "event", "user", "target_user", "source_ip",
         "result"],
        [("2026-03-08 01:40:22", "Accepted password", "root", "",
          "209.141.62.185", "success")]),
    "CRON": (
        ["file", "owner", "kind", "schedule", "run_as", "command"],
        [("/var/spool/cron/crontabs/root", "root", "crontab", "* * * * *",
          "root", "/tmp/.x")]),
    "SOCKETS": (
        ["proto", "state", "local_port", "peer_addr", "peer_port", "pid",
         "process", "exe", "user"],
        [("tcp", "ESTAB", "45210", "209.141.62.185", "443", "9001", "x",
          "/tmp/.x", "root")]),
    "WEB_LOG": (
        ["timestamp_utc", "client_ip", "method", "resource", "status"],
        []),
}


def make_case(path):
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE _tables (name TEXT, rows INTEGER)")
    for name, (cols, rows) in CASE.items():
        db.execute('CREATE TABLE "%s" (%s)'
                   % (name, ", ".join('"%s" TEXT' % c for c in cols)))
        db.executemany('INSERT INTO "%s" VALUES (%s)'
                       % (name, ", ".join("?" * len(cols))),
                       [tuple(str(v) for v in r) for r in rows])
        db.execute("INSERT INTO _tables VALUES (?, ?)", (name, len(rows)))
    db.commit()
    db.close()
    return path


# ---------------------------------------------------------------------------
# harness
# ---------------------------------------------------------------------------

class Result(object):
    def __init__(self):
        self.passed = 0
        self.failed = []

    def ok(self, what):
        self.passed += 1
        print("  [ok] %s" % what)

    def bad(self, what, why):
        self.failed.append((what, why))
        print("  [!!] %s: %s" % (what, why))

    def check(self, what, cond, why="did not hold"):
        if cond:
            self.ok(what)
        else:
            self.bad(what, why)


def rpc(L, db_path, messages):
    """Drive serve_mcp over a real pipe and return the replies it wrote.

    Through stdin and stdout rather than by calling the handlers, because the
    thing most likely to be wrong about a stdio server is the stdio - a stray
    print, an unflushed line, a notification answered with an id.
    """
    import io as _io
    stdin, stdout = sys.stdin, sys.stdout
    sys.stdin = _io.StringIO("".join(json.dumps(m) + "\n" for m in messages))
    sys.stdout = _io.StringIO()
    try:
        L.serve_mcp(db_path, quiet=True)
        raw = sys.stdout.getvalue()
    finally:
        sys.stdin, sys.stdout = stdin, stdout
    return [json.loads(line) for line in raw.splitlines() if line.strip()]


def call(L, db_path, name, args):
    """One tools/call, unwrapped to the payload the tool returned."""
    got = rpc(L, db_path, [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
         "params": {"name": name, "arguments": args}}])
    reply = [m for m in got if m.get("id") == 2][0]
    body = reply.get("result") or {}
    text = ((body.get("content") or [{}])[0].get("text") or "")
    if body.get("isError"):
        return {"error": text}
    try:
        return json.loads(text)
    except ValueError:
        return {"text": text}


# ---------------------------------------------------------------------------
# the protocol
# ---------------------------------------------------------------------------

def check_protocol(L, db_path, res):
    print("\nprotocol")
    got = rpc(L, db_path, [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "prompts/list"},
        {"jsonrpc": "2.0", "id": 4, "method": "resources/list"}])
    by_id = dict((m.get("id"), m) for m in got)

    res.check("a notification draws no reply",
              len(got) == 4 and None not in by_id,
              "%d replies for 4 requests and 1 notification" % len(got))

    caps = ((by_id.get(1) or {}).get("result") or {}).get("capabilities") or {}
    res.check("initialize advertises tools, prompts and resources",
              set(caps) >= set(("tools", "prompts", "resources")),
              "advertised %s" % sorted(caps))

    tools = ((by_id.get(2) or {}).get("result") or {}).get("tools") or []
    names = [t.get("name") for t in tools]
    res.check("tools/list carries the playbook tool",
              "case_skill" in names, "tools are %s" % names)
    res.check("every tool has a schema the model can call it by",
              all(isinstance(t.get("inputSchema"), dict) for t in tools))

    prompts = ((by_id.get(3) or {}).get("result") or {}).get("prompts") or []
    res.check("prompts/list offers every skill",
              len(prompts) == len(L.SKILLS),
              "%d prompts for %d skills" % (len(prompts), len(L.SKILLS)))
    args = dict((p["name"], p.get("arguments") or []) for p in prompts)
    res.check("a skill that needs an address says so",
              any(a.get("name") == "address" and a.get("required")
                  for a in args.get("profile_address", [])),
              "profile_address declares %s" % args.get("profile_address"))

    uris = [r.get("uri") for r in
            (((by_id.get(4) or {}).get("result") or {}).get("resources") or [])]
    res.check("resources/list offers the schema, the findings and the guide",
              set(uris) == set(("case://schema", "case://findings",
                                "case://guide")), "offered %s" % uris)


def check_prompts(L, db_path, res):
    print("\nprompts")
    got = rpc(L, db_path, [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "prompts/get",
         "params": {"name": "profile_address",
                    "arguments": {"address": "209.141.62.185"}}},
        {"jsonrpc": "2.0", "id": 3, "method": "prompts/get",
         "params": {"name": "profile_address", "arguments": {}}},
        {"jsonrpc": "2.0", "id": 4, "method": "prompts/get",
         "params": {"name": "no_such_skill", "arguments": {}}},
        {"jsonrpc": "2.0", "id": 5, "method": "resources/read",
         "params": {"uri": "case://schema"}},
        {"jsonrpc": "2.0", "id": 6, "method": "resources/read",
         "params": {"uri": "case://nothing"}}])
    by_id = dict((m.get("id"), m) for m in got)

    msgs = ((by_id.get(2) or {}).get("result") or {}).get("messages") or []
    text = ((msgs or [{}])[0].get("content") or {}).get("text") or ""
    res.check("a filled placeholder is really substituted",
              "209.141.62.185" in text and "<ADDRESS>" not in text,
              "rendered %r" % text[:120])

    res.check("a missing required argument is refused, not guessed",
              (by_id.get(3) or {}).get("error") is not None,
              "returned %s" % json.dumps(by_id.get(3))[:160])
    res.check("an unknown skill is refused by name",
              (by_id.get(4) or {}).get("error") is not None)

    schema = ((by_id.get(5) or {}).get("result") or {}).get("contents") or []
    res.check("the schema resource lists this case's tables",
              schema and "FAILED_LOGINS" in (schema[0].get("text") or ""))
    res.check("an unknown resource is refused",
              (by_id.get(6) or {}).get("error") is not None)


# ---------------------------------------------------------------------------
# read-only, which is the one that cannot be undone
# ---------------------------------------------------------------------------

def check_read_only(L, db_path, res):
    print("\nread-only")
    for sql in ("UPDATE CRON SET command = 'x'",
                "DELETE FROM FINDINGS",
                "DROP TABLE CRON",
                "INSERT INTO CRON VALUES ('a','b','c','d','e','f')",
                "PRAGMA writable_schema = ON",
                "ATTACH DATABASE 'x.db' AS x"):
        out = call(L, db_path, "case_query", {"sql": sql})
        res.check("refuses %s" % sql.split()[0].lower(),
                  bool(out.get("error")), "returned %s" % json.dumps(out)[:120])

    out = call(L, db_path, "case_query",
               {"sql": "SELECT 1; DROP TABLE CRON"})
    res.check("refuses a second statement", bool(out.get("error")))

    # The statement check is the first line; the connection is the second, and
    # it has to hold on its own. A SELECT that writes through a side effect is
    # the shape that gets past a keyword check.
    db = L._open(db_path)
    wrote = None
    try:
        db.execute("CREATE TABLE evil (x)")
        wrote = "CREATE succeeded on a mode=ro connection"
    except sqlite3.Error:
        pass
    res.check("the connection itself refuses a write", wrote is None, wrote)

    out = call(L, db_path, "case_query",
               {"sql": "WITH x AS (SELECT 1 AS n) SELECT * FROM x"})
    res.check("a WITH is still allowed", out.get("returned") == 1,
              "returned %s" % json.dumps(out)[:120])


# ---------------------------------------------------------------------------
# bounded
# ---------------------------------------------------------------------------

def check_bounded(L, db_path, res):
    print("\nbounded")
    keep = L.QUERY_SECONDS
    L.QUERY_SECONDS = 2
    try:
        db = L._open(db_path)
        try:
            out = None
            try:
                out = L.t_query(db, {"sql": "WITH RECURSIVE c(x) AS ("
                                            "SELECT 1 UNION ALL "
                                            "SELECT x + 1 FROM c) "
                                            "SELECT COUNT(*) FROM c"})
            except L.CaseError as e:
                out = {"error": str(e)}
            res.check("a query that will not finish is stopped",
                      bool(out.get("error")),
                      "returned %s" % json.dumps(out)[:120])
            res.check("and is told how to narrow it",
                      "narrow" in str(out.get("error", "")).lower(),
                      "said %r" % str(out.get("error"))[:160])
        finally:
            db.close()
    finally:
        L.QUERY_SECONDS = keep

    out = call(L, db_path, "case_search", {"term": "209.141.62.185"})
    res.check("the sweep finds the address in more than one table",
              out.get("tables_with_matches", 0) >= 3,
              "found it in %s" % [h["table"] for h in out.get("hits", [])])
    res.check("a complete sweep does not claim tables it skipped",
              "not_searched" not in out,
              "reported %s unsearched" % out.get("not_searched"))


# ---------------------------------------------------------------------------
# grounded
# ---------------------------------------------------------------------------

def check_empty(L, db_path, res):
    """The wrong negative, which is the most expensive answer there is."""
    print("")
    print("an empty result")
    # The exact query llama3.1:8b wrote, and the exact way it went wrong: kind
    # holds 'btmp', it filtered for 'SSH', got nothing, and reported that the
    # host had no failed SSH logins at all.
    out = call(L, db_path, "case_query",
               {"sql": "SELECT source_ip, COUNT(*) n FROM FAILED_LOGINS "
                       "WHERE kind = 'SSH' GROUP BY source_ip"})
    res.check("an empty result says it is not an absence",
              "not evidence" in (out.get("note") or ""),
              "said %r" % out.get("note"))
    why = out.get("check_your_values") or []
    res.check("and hands back what the filtered column really holds",
              any(w["column"] == "kind"
                  and any(v["value"] == "btmp"
                          for v in w["it_actually_holds"]) for w in why),
              "offered %s" % json.dumps(why)[:200])
    res.check("naming the value that was filtered for, to compare against",
              any(w.get("you_filtered_for") == "SSH" for w in why))

    # A query that returns rows must not pay for any of that.
    out = call(L, db_path, "case_query",
               {"sql": "SELECT * FROM FAILED_LOGINS WHERE kind = 'btmp'"})
    res.check("a query that found rows carries no hint",
              out.get("returned") == 3 and "check_your_values" not in out
              and "note" not in out,
              "returned %s" % json.dumps(out)[:160])

    # An empty result the vocabulary cannot explain still says the important
    # part. The column is right, the value is simply not in the data.
    out = call(L, db_path, "case_query",
               {"sql": "SELECT * FROM FAILED_LOGINS "
                       "WHERE source_ip = '8.8.8.8'"})
    res.check("an honestly empty result still refuses to be an absence",
              "not evidence" in (out.get("note") or ""))
    res.check("and shows the addresses that are there instead",
              any(v["value"] == "209.141.62.185"
                  for w in out.get("check_your_values") or []
                  for v in w["it_actually_holds"]),
              "offered %s" % json.dumps(out.get("check_your_values"))[:200])

    # A capped result is a page, not a population.
    out = call(L, db_path, "case_query",
               {"sql": "SELECT * FROM FAILED_LOGINS", "limit": 2})
    res.check("a capped result says the limit is not the count",
              out.get("capped") is True
              and "not the count" in (out.get("note") or ""),
              "said %r" % out.get("note"))
    res.check("and says how to get the real number",
              "COUNT(*)" in (out.get("note") or ""))
    out = call(L, db_path, "case_query",
               {"sql": "SELECT * FROM FAILED_LOGINS", "limit": 50})
    res.check("a result that fits carries no cap warning",
              out.get("returned") == 3 and not out.get("capped")
              and "note" not in out,
              "returned %s" % json.dumps(out)[:140])

    # A rejected column names the ones that would have worked. LOGINS is the
    # table this actually happened on - it keeps its times in start and end.
    out = call(L, db_path, "case_query",
               {"sql": "SELECT timestamp_utc FROM CRON"})
    err = out.get("error") or ""
    res.check("a rejected column comes back with the real ones",
              "no such column" in err and "schedule" in err and "run_as" in err,
              "said %r" % err[:200])
    out = call(L, db_path, "case_query", {"sql": "SELECT * FROM NOPE"})
    res.check("but a missing table is left as the plain sqlite error",
              "no such table" in (out.get("error") or "").lower()
              and "columns those tables" not in (out.get("error") or ""),
              "said %r" % str(out.get("error"))[:160])

    # A filter on a column that is not in the query's tables is not guessed at.
    out = call(L, db_path, "case_query",
               {"sql": "SELECT * FROM CRON WHERE source_ip = '1.2.3.4'"})
    res.check("a column the query's tables do not have gets no invented hint",
              not out.get("check_your_values"),
              "offered %s" % json.dumps(out.get("check_your_values"))[:160])


def check_skills(L, db_path, res):
    print("\nplaybooks")
    db = L._open(db_path)
    try:
        need = dict((s["name"], [a for a, _d, r in s["args"] if r])
                    for s in L.SKILLS)
        filler = {"address": "1.2.3.4", "user": "root",
                  "when": "2026-03-08 02:00:00", "claim": "the host is clean"}
        bad = []
        for name, wants in need.items():
            text = L.render(name, db,
                            dict((w, filler[w]) for w in wants))
            if "<" in text and ">" in text:
                for w in ("<ADDRESS>", "<USER>", "<WHEN>", "<CLAIM>"):
                    if w in text:
                        bad.append("%s left %s unfilled" % (name, w))
        res.check("every playbook renders with its arguments filled",
                  not bad, "; ".join(bad))

        text = L.render("persistence", db, {})
        res.check("a playbook names the tables this case has",
                  "CRON" in text.split("In this case:")[-1],
                  "grounding said %r"
                  % text.split("In this case:")[-1][:160])
        res.check("and separates present-but-empty from never-collected",
                  "WEB_LOG" not in text and "SYSTEMD_UNITS" in text.split(
                      "Not in this case at all")[-1],
                  "grounding said %r"
                  % text.split("In this case:")[-1][:200])

        text = L.render("web_intrusion", db, {})
        res.check("an empty table is called empty, not absent",
                  "Present but empty" in text and "WEB_LOG" in text.split(
                      "Present but empty")[-1].split(".")[0],
                  "grounding said %r"
                  % text.split("In this case:")[-1][:200])

        # No playbook may contain something that reads as a result. Given a
        # worked verdict with real-looking numbers in it - "AUTH_LOG has 4
        # rows, the earliest 2021-12-08 18:22:14" - llama3.1:8b copied it back
        # verbatim as its own finding. The true answer was 26,807 rows from
        # 2021-11-07. An example an 8B can lift is not an example, it is a
        # prepared wrong answer, so the plans carry shapes and never values.
        import re as _re
        date = _re.compile(r"20\d\d-\d\d-\d\d")
        num = _re.compile(r"\d{1,3},\d{3}|\d+ rows?")
        sql = ("SELECT", "FROM", "WHERE", "JOIN", "OR ", "AND ", "GROUP",
               "ORDER", "ON ")
        leaked = []
        for sk in L.SKILLS:
            for line in sk["plan"].split(chr(10)):
                body = line.strip()
                if not body or body.upper().startswith(sql):
                    continue
                if date.search(body) or num.search(body):
                    leaked.append("%s: %s" % (sk["name"], body[:70]))
        res.check("no playbook carries a value a model could copy as its own",
                  not leaked, "; ".join(leaked))

        got = L.t_skill(db, {})
        res.check("the tool lists the playbooks when asked for none",
                  len(got.get("skills") or []) == len(L.SKILLS))
        got = L.t_skill(db, {"name": "challenge",
                             "claim": "root logged in from 209.141.62.185"})
        res.check("and fills one in when named",
                  "209.141.62.185" in (got.get("playbook") or ""))

        avail = L.available(db)
        web = [a for a in avail if a["name"] == "web_intrusion"][0]
        res.check("availability reports the missing tables rather than hiding "
                  "the skill",
                  "WEB_LOG" in web["missing"] and "PROCESSES" in web["missing"]
                  and "FINDINGS" in web["has"],
                  "has=%s missing=%s" % (web["has"], web["missing"]))
    finally:
        db.close()


# ---------------------------------------------------------------------------
# the loop, in the parts that need no model
# ---------------------------------------------------------------------------

def check_loop(L, db_path, res):
    print("\nthe ask loop")
    db = L._open(db_path)
    try:
        brief = L._schema_brief(db)
        res.check("the schema brief names every table with rows",
                  all(t in brief for t in CASE),
                  "missing %s" % [t for t in CASE if t not in brief])
        res.check("and says which columns join the tables together",
                  "source_ip" in brief.split("How the tables join.")[-1],
                  "join map said %r"
                  % brief.split("How the tables join.")[-1][:200])
        res.check("an empty table is listed as empty",
                  "WEB_LOG" in brief.split("Empty here")[-1],
                  "empty section said %r"
                  % brief.split("Empty here")[-1][:160])
    finally:
        db.close()

    known = set(t[0] for t in L.all_tools())
    res.check("the ask loop is handed the playbook tool",
              "case_skill" in known, "has %s" % sorted(known))

    # A model with no tool-calling template writes the call into the message.
    # It is read - but only when it names a tool that exists.
    got = L._loose_call('{"name": "case_query", "arguments": {"sql": "SELECT 1"}}',
                        known)
    res.check("a call written as prose is still read", bool(got))
    got = L._loose_call('Let me try again. {"name": "case_skill", '
                        '"arguments": {"name": "persistence"}}', known)
    res.check("even after the model narrates first", bool(got))
    res.check("a tool that does not exist is not invented",
              L._loose_call('{"name": "case_magic", "arguments": {}}',
                            known) is None)
    res.check("a sentence merely mentioning a tool is an answer, not a call",
              L._loose_call("I used case_query and found nothing.",
                            known) is None)

    # A message that is a SELECT and nothing else is a call, not an answer.
    got = L._loose_sql("SELECT * FROM CRON", known)
    res.check("a bare SELECT is run rather than shown to the analyst",
              got and got[0]["function"]["name"] == "case_query",
              "read %s" % got)
    fenced = "```sql" + chr(10) + "SELECT user FROM LOGINS" + chr(10) + "```"
    got = L._loose_sql(fenced, known)
    res.check("even inside a fence", bool(got))
    res.check("but a sentence quoting its own SQL is an explanation",
              L._loose_sql("I ran SELECT * FROM CRON and found one job.",
                           known) is None)
    res.check("and two statements are still refused",
              L._loose_sql("SELECT 1; DROP TABLE CRON", known) is None)

    prior = L._prior([{"role": "user", "content": "a"},
                      {"role": "assistant", "content": "b"},
                      {"role": "tool", "content": "should not carry"},
                      {"role": "user", "content": "c"},
                      {"role": "assistant", "content": "d"},
                      {"role": "user", "content": "e"},
                      {"role": "assistant", "content": "f"}])
    res.check("the conversation carried forward is the last exchanges only",
              len(prior) == L.ASK_HISTORY and prior[-1]["content"] == "f",
              "carried %s" % prior)
    res.check("and never the tool traffic",
              all(m["role"] in ("user", "assistant") for m in prior))


# ---------------------------------------------------------------------------
# the loop end to end, against a model that is not there
# ---------------------------------------------------------------------------

class FakeModel(object):
    """An OpenAI-shaped chat endpoint that replies from a script.

    The half of the ask loop worth testing is the half a real model makes
    untestable: does a tool call actually reach the database, does the result
    go back in a shape the next turn can read, does the thread survive to the
    next question, and does a model that never stops querying still leave the
    examiner with something. Scripted replies settle all four, in a second, on
    a machine with no model installed at all.
    """

    def __init__(self, script):
        from http.server import BaseHTTPRequestHandler, HTTPServer
        import threading
        self.script = list(script)
        self.seen = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n).decode("utf-8"))
                outer.seen.append(body)
                reply = (outer.script.pop(0) if outer.script
                         else {"content": "nothing left to say"})
                msg = {"role": "assistant",
                       "content": reply.get("content") or ""}
                if reply.get("call"):
                    name, args = reply["call"]
                    msg["tool_calls"] = [
                        {"id": "c%d" % len(outer.seen), "type": "function",
                         "function": {"name": name,
                                      "arguments": json.dumps(args)}}]
                out = json.dumps({"choices": [{"message": msg}]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

        self.httpd = HTTPServer(("127.0.0.1", 0), H)
        self.url = "http://127.0.0.1:%d/v1" % self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever)
        self.thread.daemon = True
        self.thread.start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def check_end_to_end(L, db_path, res):
    print("\nthe loop, against a scripted model")

    m = FakeModel([
        {"call": ("case_skill", {"name": "profile_address",
                                 "address": "209.141.62.185"})},
        {"call": ("case_query", {"sql": "SELECT COUNT(*) AS n FROM "
                                        "FAILED_LOGINS WHERE source_ip = "
                                        "'209.141.62.185'"})},
        {"content": "2 failed logins from 209.141.62.185 (FAILED_LOGINS)."}])
    try:
        out = L.ask(db_path, "what did 209.141.62.185 do?", m.url, "fake")
    finally:
        m.close()
    res.check("a scripted tool call reaches the database and comes back",
              out.get("answer", "").startswith("2 failed logins"),
              "answered %r" % out.get("answer"))
    res.check("both steps are recorded for the analyst to check",
              [x["tool"] for x in out.get("steps") or []]
              == ["case_skill", "case_query"],
              "steps were %s" % [x["tool"] for x in out.get("steps") or []])
    res.check("the thread comes back to be carried into the next question",
              len(out.get("history") or []) == 2
              and out["history"][-1]["role"] == "assistant",
              "history was %s" % out.get("history"))

    # The follow-up. What proves it is not the answer - the script decides
    # that - but whether the earlier exchange was actually put in front of the
    # model, which is the thing that silently does not happen.
    m = FakeModel([{"content": "the same address, yes."}])
    try:
        out2 = L.ask(db_path, "and what else did it touch?", m.url, "fake",
                     history=out.get("history"))
        sent = m.seen[0]["messages"]
    finally:
        m.close()
    said = [x["content"] for x in sent if x["role"] in ("user", "assistant")]
    res.check("a follow-up carries the previous question and answer",
              any("209.141.62.185 do?" in t for t in said)
              and any(t.startswith("2 failed logins") for t in said),
              "the model was sent %s" % [t[:40] for t in said])
    res.check("and the tool traffic is not carried with it",
              not any(x["role"] == "tool" for x in sent),
              "sent %s" % [x["role"] for x in sent])
    res.check("the thread grows rather than restarting",
              len(out2.get("history") or []) == 4,
              "history was %s" % out2.get("history"))

    # A playbook is not a question. What the thread records has to be what the
    # analyst asked, or the next turn's window is filled with a plan the model
    # has already followed instead of with what came back.
    m = FakeModel([{"content": "one crontab entry."}])
    try:
        out3 = L.ask(db_path, "a two thousand word playbook " * 90, m.url,
                     "fake", remember="what persists here?")
    finally:
        m.close()
    said = [x["content"] for x in out3.get("history") or []
            if x["role"] == "user"]
    res.check("a playbook is recorded in the thread as what was asked",
              said == ["what persists here?"],
              "the thread remembered %s" % [t[:40] for t in said])

    # A model that never stops querying. The rounds run out; the work must not
    # go with them.
    m = FakeModel([{"call": ("case_query", {"sql": "SELECT 1"})}] * 3
                  + [{"content": "I found 1 crontab entry running /tmp/.x."}])
    try:
        out = L.ask(db_path, "anything?", m.url, "fake", rounds=3)
        last = m.seen[-1]
    finally:
        m.close()
    res.check("running out of rounds still produces an answer",
              "crontab" in out.get("answer", ""),
              "answered %r" % out.get("answer"))
    res.check("and says it was cut short", out.get("truncated") is True)
    res.check("the salvage turn is asked with no tools to reach for",
              not last.get("tools"),
              "the last request carried tools")

    # A model that is stuck repeats itself. The second identical call is not
    # re-run - it is answered with the fact that it was already run, and with
    # what to do instead.
    same = {"call": ("case_query", {"sql": "SELECT * FROM CRON WHERE "
                                           "owner = 'nobody'"})}
    m = FakeModel([same, same, same, {"content": "I could not establish it."}])
    try:
        out = L.ask(db_path, "loop on purpose", m.url, "fake")
        fed = [x["content"] for x in m.seen[-1]["messages"]
               if x["role"] == "tool"]
    finally:
        m.close()
    res.check("a repeated call is not run a second time",
              sum("already run this exact call" in t for t in fed) == 2,
              "fed back %s" % [t[:60] for t in fed])
    res.check("and the repeat says what the first run returned",
              any("0 rows" in t for t in fed), "fed back %s" % fed)
    res.check("and tells it not to answer from a result it did not get",
              any("did not get" in t for t in fed))
    res.check("the loop still finishes", bool(out.get("answer")))

    # A tool that does not exist, and a query that fails. Both have to come
    # back as text the model can correct from - a traceback here kills the
    # panel and the examiner sees a spinner that never stops.
    m = FakeModel([
        {"call": ("case_nonsense", {})},
        {"call": ("case_query", {"sql": "SELECT * FROM NO_SUCH_TABLE"})},
        {"content": "neither of those worked."}])
    try:
        out = L.ask(db_path, "break it", m.url, "fake")
        turns = m.seen
    finally:
        m.close()
    fed = [x["content"] for x in turns[-1]["messages"] if x["role"] == "tool"]
    res.check("an unknown tool is handed back as an error, not raised",
              any("no tool called" in t for t in fed), "fed back %s" % fed)
    res.check("a bad table is handed back as the sqlite error",
              any("no such table" in t.lower() for t in fed),
              "fed back %s" % fed)
    res.check("and the panel still answers", bool(out.get("answer")))


def check_unsupported(L, db_path, res):
    """Figures the model wrote down that no query ever returned."""
    print("")
    print("checking the answer against the evidence")
    corpus = ('{"hits": [{"table": "WEB_LOG", "matches": 1456}, '
              '{"table": "FAILED_LOGINS", "matches": 210}], '
              '"rows": [{"source_ip": "209.141.62.185", '
              '"timestamp_utc": "2021-12-01 19:57:11"}]}')

    res.check("a figure that came from a result is not flagged",
              not L._unsupported("210 failed logins and 1,456 web requests "
                                 "from 209.141.62.185", corpus))
    res.check("a thousands separator is not a difference",
              not L._unsupported("1,456 requests", corpus))
    res.check("a timestamp that was returned is not flagged",
              not L._unsupported("the earliest was 2021-12-01 19:57:11",
                                 corpus))

    # The shape of the real failure: one search, then a page of invented
    # per-table statistics.
    bad = L._unsupported("BODYFILE (26,192 rows), earliest 2021-10-07 "
                         "06:20:53, from 10.1.2.3", corpus)
    res.check("an invented count is caught", "26,192" in bad, "caught %s" % bad)
    res.check("an invented timestamp is caught",
              any(b.startswith("2021-10-07") for b in bad), "caught %s" % bad)
    res.check("an invented address is caught", "10.1.2.3" in bad,
              "caught %s" % bad)

    res.check("small numbers are left alone rather than buried in noise",
              not L._unsupported("2 of the 8 tables", corpus),
              "flagged %s" % L._unsupported("2 of the 8 tables", corpus))
    res.check("an empty answer flags nothing", not L._unsupported("", corpus))

    # And it has to reach the caller, on a real run, from the real results.
    m = FakeModel([
        {"call": ("case_query", {"sql": "SELECT COUNT(*) AS n FROM CRON"})},
        {"content": "There are 4,096 cron jobs, first seen 2019-01-01."}])
    try:
        out = L.ask(db_path, "how many cron jobs?", m.url, "fake")
    finally:
        m.close()
    res.check("a real run reports what it could not support",
              "4,096" in (out.get("unsupported") or [])
              and any(b.startswith("2019-01-01")
                      for b in out.get("unsupported") or []),
              "reported %s" % out.get("unsupported"))

    m = FakeModel([
        {"call": ("case_query", {"sql": "SELECT COUNT(*) AS n FROM "
                                        "FAILED_LOGINS"})},
        {"content": "3 failed logins."}])
    try:
        out = L.ask(db_path, "how many?", m.url, "fake")
    finally:
        m.close()
    res.check("and reports nothing when the answer is backed by the rows",
              not out.get("unsupported"),
              "flagged %s" % out.get("unsupported"))


def check_timeout(L, db_path, res):
    """A slow model and an absent one are different problems."""
    print("")
    print("reaching the model")
    import socket
    import urllib.error
    for e, why in (
            (urllib.error.URLError(socket.timeout("timed out")), "urllib"),
            (TimeoutError("timed out"), "bare"),
            (urllib.error.URLError(TimeoutError()), "wrapped")):
        res.check("a timeout is recognised as one (%s)" % why, L._timed_out(e))
    refused = urllib.error.URLError(
        ConnectionRefusedError(61, "Connection refused"))
    res.check("a refused connection is not called a timeout",
              not L._timed_out(refused))

    # And the message an examiner reads has to say which it was. "Is it
    # running?" against a model that is running and merely slow sends them to
    # check the wrong thing.
    m = None
    try:
        out = L.ask(db_path, "anything", "http://127.0.0.1:9/v1", "fake")
    except L.CaseError as e:
        m = str(e)
    res.check("a refused connection asks whether it is running",
              m and "Is it running?" in m, "said %r" % m)


def check_server(L, db_path, res):
    print("\nthe server's half")
    try:
        sys.path.insert(0, os.path.join(ROOT, "src"))
        from linsight.serve import _skills, _playbook
    except ImportError as e:
        res.bad("the server exposes the playbooks", "cannot import: %s" % e)
        return

    class Store(object):
        class db(object):
            path = db_path

    got = _skills(Store())
    res.check("the page is offered every playbook",
              len(got) == len(L.SKILLS),
              "offered %d of %d" % (len(got), len(L.SKILLS)))
    res.check("each carries which of its tables this case has",
              all("has" in g and "missing" in g for g in got))

    text = _playbook(Store(), "profile_address",
                     {"address": "45.9.148.99"}, "who is this?")
    res.check("a playbook reaches the model filled in",
              "45.9.148.99" in text and "<ADDRESS>" not in text)
    res.check("and carries the analyst's own wording with it",
              "who is this?" in text, "rendered %r" % text[-200:])

    bad = None
    try:
        _playbook(Store(), "profile_address", {}, "")
    except L.CaseError as e:
        bad = str(e)
    res.check("a playbook with no argument is refused rather than guessed",
              bad is not None and "address" in bad, "said %r" % bad)


def check_reopen(L, res):
    """A case reopened has to be the same console over the same evidence.

    This is the half of --serve that parses nothing: the tables come back out
    of the database as shells, and the page is built from the shells while
    the rows stay in SQLite. What can go wrong quietly is that a shell lies
    about its size - the navigation reads len() - or that the page ships the
    rows after all, which is the ten-megabyte file the server exists to
    avoid.
    """
    print("\nreopening a case without parsing it")
    try:
        sys.path.insert(0, os.path.join(ROOT, "src"))
        from linsight.serve import CaseDB, ReopenedCase
        from linsight.tables import Table
        from linsight.writers import console_html
    except ImportError as e:
        res.bad("a case can be reopened", "cannot import: %s" % e)
        return

    tmp = tempfile.mkdtemp(prefix="linsight-reopen-")
    tables = []
    for name, (cols, rows) in sorted(CASE.items()):
        t = Table(name, name.title().replace("_", " "), cols,
                  "Authentication", "what %s holds" % name)
        for r in rows:
            t.add(*r)
        tables.append(t)
    # the two the page reads while it is being built, not on demand
    hosts = Table("HOSTS", "Hosts", ["hostname", "addresses"], "Collection")
    hosts.add("web01", "10.0.0.4 10.0.0.5")
    tables.append(hosts)

    meta = {"Hostname": "web01", "Time zone": "UTC",
            "Collection finished": "2026-03-08 04:00:00 UTC"}
    console = {"collection": "/ev/web01.tar.gz", "hostname": "web01",
               "hosts": ["web01", "db02"], "host_column": "host",
               "rows_total": sum(len(t) for t in tables)}

    path = os.path.join(tmp, "case.db")
    CaseDB(path).build(tables, meta, quiet=True, console=console)
    back, got_meta, got_console = CaseDB(path).reopen()

    res.check("every table comes back",
              [t.name for t in back] == [t.name for t in tables],
              "got %s" % [t.name for t in back])
    res.check("with its heading, its category and its columns",
              all(b.title == t.title and b.category == t.category
                  and b.columns == t.columns
                  for b, t in zip(back, tables)))
    res.check("and its true row count, which is what the navigation shows",
              [len(b) for b in back] == [len(t) for t in tables],
              "got %s, wanted %s"
              % ([len(b) for b in back], [len(t) for t in tables]))
    big = next(b for b in back if b.name == "FAILED_LOGINS")
    res.check("while holding none of the rows - they stay in SQLite",
              len(big) == 3 and list(big.iter_rows()) == [],
              "held %d" % len(list(big.iter_rows())))
    eager = next(b for b in back if b.name == "HOSTS")
    res.check("except the few the page reads to say who owns an address",
              [list(r) for r in eager.iter_rows()]
              == [["web01", "10.0.0.4 10.0.0.5"]],
              "held %s" % [list(r) for r in eager.iter_rows()])
    res.check("the examiner's header survives", got_meta == meta,
              "got %s" % got_meta)
    res.check("and so does what the page is told rather than sniffs",
              got_console == console, "got %s" % got_console)

    tri = ReopenedCase(got_meta, got_console.get("collection"))
    page = console_html(back, 0, got_console, tri, None, served=True)
    res.check("the console builds from the shells",
              "window.__LINSIGHT__=" in page and "web01" in page)
    res.check("marked served, so the page asks for a table when it is opened",
              '"served": true' in page or '"served":true' in page)
    res.check("and ships no rows at all",
              "window.__ROWS__={};" in page,
              "payload carried rows")
    res.check("the merged export's host filter survives the round trip",
              '"db02"' in page, "hosts were not in the payload")

    bad = os.path.join(tmp, "notes.db")
    with open(bad, "w") as fh:
        fh.write("this is not a database")
    err = None
    try:
        CaseDB(bad).reopen()
    except L.CaseError as e:
        err = str(e)
    res.check("a file that is not a case is refused in a sentence",
              err is not None and "not a case" in err, "said %r" % err)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--built", action="store_true",
                    help="test the built linsight.py instead of src/linsight")
    opts = ap.parse_args()
    L = load(opts.built)

    res = Result()
    tmp = tempfile.mkdtemp(prefix="linsight-ask-")
    db_path = make_case(os.path.join(tmp, "case.db"))
    print("case: %s" % db_path)

    check_protocol(L, db_path, res)
    check_prompts(L, db_path, res)
    check_read_only(L, db_path, res)
    check_bounded(L, db_path, res)
    check_empty(L, db_path, res)
    check_skills(L, db_path, res)
    check_loop(L, db_path, res)
    check_end_to_end(L, db_path, res)
    check_unsupported(L, db_path, res)
    check_timeout(L, db_path, res)
    if not opts.built:
        check_server(L, db_path, res)
        check_reopen(L, res)

    print("\n%d passed, %d failed" % (res.passed, len(res.failed)))
    if res.failed:
        print("\nfailures:")
        for what, why in res.failed:
            print("  %s: %s" % (what, why))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
