"""A local model, given the case and told to go and look.

The same tools the MCP server exposes, driven from inside the investigation
server so the panel in the page can use them. The model never receives the
case: it receives the schema and a read-only SELECT, and has to ask. Three and
a half million rows do not fit in a context window, and a model handed a
sample of them answers confidently about the sample.

The loop is the whole implementation. Send the question with the tool
definitions; if the reply asks for a tool, run it, append the result, and send
it back. Stop when the model answers in words instead, or when it has had
enough turns - a model that cannot finish in eight rounds is not converging
and its ninth query will not save it.

Nothing leaves the machine. The page talks to this server because its own CSP
forbids it from talking to anything else, and this server talks to a model on
localhost. That is a property worth keeping: the case is evidence, and the
first rule of evidence is that you know where it went.
"""

import json
import re
import urllib.error
import urllib.request

from .mcp import CaseError, _open
from .skills import all_tools

# A local 7B on CPU is not fast, and the number was set against bare
# questions. A playbook is several thousand tokens of prompt before the schema
# is added, and prompt processing is the slow half on a CPU: profile_address
# against a 3.4-million-row case went past 180 seconds on the first turn and
# came back as "cannot reach a model", which sent the examiner to check
# whether Ollama was running. It was running. It was thinking.
ASK_TIMEOUT = 600
ASK_ROUNDS = 8              # tool calls before we stop and take what we have
ASK_URL = "http://127.0.0.1:11434/v1"

# What the model is sent, measured against the window it has to hold it in.
#
# On a real case the fixed part of every turn is 4,757 tokens - 954 for the
# system prompt, 2,884 for the schema of 79 tables, 919 for the tool
# definitions - against a num_ctx of 16,384. That leaves room for two tool
# results, and one `SELECT * FROM AUTH_LOG` at the default row cap is 87,163
# characters, near 22,000 tokens on its own.
#
# What happens then is not an error. Ollama does not refuse a prompt that is
# longer than num_ctx: it drops the front of it, which is the system prompt,
# the schema and the question, and answers from what is left - the tail of a
# JSON blob. The reply that comes back is fluent, cites real rows, and is not
# an answer to anything that was asked. That is what "it answers something
# else" looks like from the outside, and no change of model fixes it.
#
# So the conversation is kept inside the window here, where it can be done
# knowingly: rows are capped before a result is serialised, a result too big
# even then loses whole rows rather than its own closing brace, and when the
# thread outgrows the window the oldest results are dropped and say so.
ASK_ROWS = 40               # rows one tool result may carry back
ASK_CHARS_PER_TOKEN = 4     # near enough to budget with, and no tokeniser
ASK_REPLY_TOKENS = 1200     # left free for the model's own answer
ASK_RESULT_TOKENS = 2000    # the most one result may take of the rest

SYSTEM = """You are helping a forensic analyst work a Linux triage case that
is already parsed into a SQLite database of normalised tables.

Investigate. Do not summarise, and do not guess. Every claim you make must
come from a query you actually ran, and you must say which table and which
values it came from so the analyst can check you.

How to work:
  - The schema is below. Use those exact table and column names. Never invent
    a table name: if it is not in the list, it does not exist here.
  - case_query for anything specific. It is a real SELECT over real rows.
  - case_tables(table="NAME") when you need the columns of one not listed.
  - case_findings for what the triage already raised.
  - case_row to pull a full row when a finding quotes a shortened one.
  - If a query errors, read the error and fix the query. Do not abandon the
    question and do not answer from memory - the answer is in the database.
  - If a WHERE returns 0 rows, your value is probably wrong, not missing.
    Call case_values(table, column) to see what that column really holds, and
    try again. Never report something as absent on the strength of one
    equality filter that matched nothing.
  - The same fact lives in more than one table. A sign-in is in AUTH_LOG,
    LOGINS, LOGIN_RECORDS and USERS.last_login_utc, and they do not agree by
    accident - if one is empty, try the next before concluding anything.
  - Call the tool. Do not write the call out as text in your reply.
  - If the question is broad - "what happened here", "is this compromised",
    "tell me about this address" - call case_skill FIRST. It returns the
    sequence an examiner follows for that kind of question, with the tables
    and the joins already named. Following one is the difference between
    seven queries that build an answer and one query read back in different
    words.

What to hold to:
  - An empty table is not a clean host. It can mean the collector never ran
    that artifact. Say so rather than reporting an absence as a result.
  - Timestamps are UTC.
  - If the data does not answer the question, say that. A wrong lead costs an
    analyst more time than no lead.
  - Be brief. Lead with the answer, then the evidence for it.

Correlating, which is most of the job:
  - "in BOTH A and B" is a JOIN or an INTERSECT. It is never a UNION. UNION
    means "in either", and answering a both-question with one returns a value
    that may appear in neither of the two tables you were asked about. Asked
    which address was in FAILED_LOGINS and WEB_LOG, a UNION returned
    99.72.192.47, which has 6 rows in the first and 0 in the second - a wrong
    answer that reads exactly like a right one.
  - The same fact is named differently in different tables. The address is
    source_ip in FAILED_LOGINS and AUTH_LOG, client_ip in WEB_LOG, remote_ip
    in LOGIN_RECORDS, peer_addr in NETSTAT and SOCKETS. Join the columns that
    mean the same thing, not the ones that are spelled the same.
  - Count each side and say both numbers. "209.141.62.185: 210 failed logins
    and 1,456 web requests" is checkable; "the top address" is not.

    The shape to use:
      SELECT f.source_ip, f.n AS failed, w.n AS web
        FROM (SELECT source_ip, COUNT(*) n FROM FAILED_LOGINS
               WHERE source_ip <> '' GROUP BY source_ip) f
        JOIN (SELECT client_ip, COUNT(*) n FROM WEB_LOG
               WHERE client_ip <> '' GROUP BY client_ip) w
          ON w.client_ip = f.source_ip
       ORDER BY f.n + w.n DESC LIMIT 5

  - Empty strings are not nulls here. Every column is text and an absent
    value is '', so exclude it with <> '' rather than IS NOT NULL.
  - Before you answer that something appears in two places, run one count per
    place. If either is 0, it does not appear in both and your join was
    wrong."""


# The questions an examiner actually asks, and the tables that answer them.
# Given the schema alone a model still has to guess which of LOGINS,
# LOGIN_RECORDS, LASTLOG and AUTH_LOG holds a sign-in - and it guessed
# 'auth_events', which exists nowhere, then gave up. Naming the route is the
# difference between one query and three wrong ones. Only tables this case
# actually has are shown.
ROUTES = (
    ("who signed in, and when",
     ("LOGINS", "LOGIN_RECORDS", "LASTLOG", "USERS", "AUTH_LOG")),
    ("failed logins, brute force",
     ("FAILED_LOGINS", "AUTH_LOG", "USERS")),
    ("what was running, what ran",
     ("PROCESSES", "PROCESS_MASTER", "SHELL_HISTORY", "AUDIT_LOG")),
    ("network connections and listeners",
     ("SOCKETS", "NETSTAT", "PROC_NET", "FIREWALL")),
    ("web requests, exploitation, webshells",
     ("WEB_LOG", "WEB_CONFIG")),
    ("persistence",
     ("CRON", "SYSTEMD_UNITS", "INIT_AND_PROFILE", "KERNEL_MODULES")),
    ("privilege escalation and sudo",
     ("PRIVILEGE_ACTIVITY", "SUDOERS", "SUID_SGID", "USERS")),
    ("files on disk, timestamps, hashes",
     ("BODYFILE", "FILE_HASHES", "COLLECTED_FILES", "HIDDEN_PATHS")),
    ("library hijack, preloaded objects",
     ("PROC_ENVIRON", "PROC_ENVIRON_VARIABLES", "KERNEL_MODULES")),
    ("what the triage already found",
     ("FINDINGS", "SIGMA_MATCHES", "HACKTOOL_HITS", "IOC_HITS")),
)


# Columns that are the same fact in more than one table. Derived from the
# schema rather than listed by hand, so a case with different artifacts gets
# a different map and none of it is ever stale.
JOIN_KEYS = ("pid", "ppid", "user", "username", "target_user", "uid",
             "source_ip", "client_ip", "remote_ip", "source_host",
             "remote_host", "path", "exe", "command", "inode", "tool",
             "md5", "sha256", "local_port", "peer_port", "port")


def _schema_brief(db):
    """The whole schema, and how its tables join.

    All 75 tables with all their columns is under 2,000 tokens - cheaper than
    the partial version it replaces, and it removes the last reason to guess.
    The join map is the other half: a host is one story told by forty
    artifacts, and an analyst's real questions are correlations - which
    address both brute-forced SSH and got a 2xx, which pid owns the socket
    that is talking to it. A model that does not know pid is in eighteen
    tables cannot ask that, however good its SQL is.
    """
    from .mcp import _tables, _cols
    known = _tables(db)
    live, empty, cols_of = [], [], {}
    for name in sorted(known):
        cols_of[name] = _cols(db, name)
        (live if known.get(name) else empty).append(name)

    out = ["EVERY table in this case. The list is complete: a name that is "
           "not here does not exist, so never invent one.", ""]
    for name in live:
        out.append("  %s [%s rows] (%s)"
                   % (name, "{:,}".format(known[name] or 0),
                      ", ".join(cols_of[name])))
    if empty:
        out.append("")
        out.append("Empty here - the collector produced nothing for them, "
                   "which is not the same as the host being clean: "
                   + ", ".join(empty))

    where = {}
    for name in live:
        for c in cols_of[name]:
            if c in JOIN_KEYS:
                where.setdefault(c, []).append(name)
    joins = [(c, t) for c, t in where.items() if len(t) > 1]
    if joins:
        out.append("")
        out.append("How the tables join. These columns hold the same fact in "
                   "each table listed, so they are what you correlate on:")
        for col, names in sorted(joins, key=lambda x: -len(x[1])):
            out.append("  %-14s %s" % (col, ", ".join(sorted(names))))

    out.append("")
    out.append("Where to look, by question:")
    for q, names in ROUTES:
        have = [n for n in names if n in known]
        if have:
            out.append("  %-38s %s" % (q, ", ".join(have)))
    out.append("")
    out.append("Correlating is the point. A host is one story told by many "
               "artifacts: an address in WEB_LOG is the same address in "
               "FAILED_LOGINS, a pid in PROCESSES is the same pid in "
               "PROC_ENVIRON and SOCKETS. Join on the columns above rather "
               "than answering from one table when the question spans two.")
    return chr(10).join(out)


def _timed_out(e):
    """Whether this failure was the clock, not the connection.

    Python has moved the timeout around between versions - socket.timeout,
    then TimeoutError, wrapped in URLError on the way out of urllib, and the
    wrapping differs again by transport. So the cause chain is walked and the
    text is checked, rather than one exception type being named and being
    right on one interpreter.
    """
    seen = []
    while e is not None and len(seen) < 6:
        if isinstance(e, TimeoutError):
            return True
        seen.append(e)
        e = getattr(e, "reason", None) or getattr(e, "__cause__", None)
    return any("timed out" in str(x).lower() for x in seen)


def _llm_post(url, payload, timeout=ASK_TIMEOUT):
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


# Tuned for a CPU-only host. num_ctx because the model advertises 131,072 and
# is given the server default unless asked - the schema alone is nearly three
# thousand tokens. num_batch because prompt processing is the slow half on a
# CPU and a bigger batch is straightforwardly faster. num_thread at the
# physical core count rather than the logical one: on this EPYC the second
# thread of a core adds contention, not throughput. keep_alive is the one that
# an examiner actually feels - without it the 4.9 GB is unloaded between
# questions and every question pays to read it back off disk.
ASK_OPTIONS = {"num_ctx": 16384, "num_batch": 512, "temperature": 0}
ASK_KEEPALIVE = "30m"


def _native(messages):
    """The same conversation, in the shape Ollama's own API expects.

    The two protocols disagree about one field: OpenAI carries tool-call
    arguments as a JSON string, Ollama as an object. Sending a string back
    gets 400 "Value looks like object, but can't find closing '}' symbol",
    which is Ollama trying to parse the string as JSON one layer too late.
    """
    out = []
    for m in messages:
        calls = m.get("tool_calls")
        if not calls:
            out.append(m)
            continue
        fixed = []
        for c in calls:
            fn = dict(c.get("function") or {})
            args = fn.get("arguments")
            if isinstance(args, str):
                try:
                    fn["arguments"] = json.loads(args or "{}")
                except ValueError:
                    fn["arguments"] = {}
            fixed.append({"function": fn})
        out.append({"role": m.get("role", "assistant"),
                    "content": m.get("content") or "",
                    "tool_calls": fixed})
    return out


def _chat(url, model, messages, tools, timeout=ASK_TIMEOUT):
    """One exchange, normalised to {content, tool_calls}.

    Ollama gets its own endpoint rather than the OpenAI-compatible one, for a
    single reason: num_ctx. The model advertises 131,072 tokens of context and
    Ollama gives it the server default - a few thousand - unless asked. The
    schema alone is two thousand, so the compatible endpoint drops the tables
    out of the window part way through and the model starts inventing names
    again. /api/chat takes options; /v1 does not.

    Anything else - LM Studio, llama.cpp, vLLM - keeps the OpenAI path, where
    the window is the server's business and this has no way to set it anyway.
    """
    base = url.rstrip("/")
    if base.endswith("/v1"):
        base = base[:-3].rstrip("/")
    # An empty tool list is sent as no tool list at all. Several runtimes read
    # "tools": [] as a malformed request rather than as "none", and the turn
    # that has its tools taken away deliberately - the last one - is exactly
    # the turn that must not fail.
    if ":11434" in base:
        payload = {"model": model, "messages": _native(messages),
                   "stream": False, "keep_alive": ASK_KEEPALIVE,
                   "options": ASK_OPTIONS}
        if tools:
            payload["tools"] = tools
        body = _llm_post(base + "/api/chat", payload, timeout)
        msg = body.get("message") or {}
        calls = []
        for c in msg.get("tool_calls") or []:
            fn = c.get("function") or {}
            args = fn.get("arguments")
            calls.append({"id": c.get("id") or fn.get("name") or "call",
                          "function": {"name": fn.get("name"),
                                       "arguments": args if isinstance(args, str)
                                       else json.dumps(args or {})}})
        return {"content": msg.get("content") or "", "tool_calls": calls}
    payload = {"model": model, "messages": messages, "temperature": 0}
    if tools:
        payload["tools"] = tools
    body = _llm_post(url.rstrip("/") + "/chat/completions", payload, timeout)
    msg = ((body.get("choices") or [{}])[0].get("message") or {})
    return {"content": msg.get("content") or "",
            "tool_calls": msg.get("tool_calls") or []}


def llm_models(url=ASK_URL, timeout=10):
    """What the runtime has, so the page can offer a choice rather than a box."""
    try:
        with urllib.request.urlopen(url.rstrip("/") + "/models",
                                    timeout=timeout) as r:
            body = json.loads(r.read().decode("utf-8", "replace"))
    except (urllib.error.URLError, OSError, ValueError):
        return []
    return [m.get("id") for m in (body.get("data") or []) if m.get("id")]


def _schema(tools):
    return [{"type": "function",
             "function": {"name": n, "description": d, "parameters": s}}
            for n, d, s, _fn in tools]


def _objects(text):
    """Every balanced {...} in a string, in the order they were written.

    All of them rather than the last one, because of what a model does with a
    long plan: handed the ten-step challenge playbook, llama3.1:8b transcribed
    it - every step, each with its SQL in a fenced JSON block - and finished
    with {"name": "STANDS", ...}, which is a verdict and not a tool. Reading
    only the last object found that, failed to match a tool, and returned two
    minutes of narration to the analyst as though it were an answer, with four
    perfectly good calls sitting unread above it.
    """
    out, depth, start = [], 0, -1
    for i, c in enumerate(text or ""):
        if c == "{":
            if depth == 0:
                start = i
            depth += 1
        elif c == "}" and depth:
            depth -= 1
            if not depth and start >= 0:
                out.append(text[start:i + 1])
    return out


def _loose_call(text, known, solo=None):
    """A tool call a model wrote into its message instead of the tool field.

    Not every local model has a tool-calling template, and several that
    advertise one still answer with the JSON as prose: qwen2.5-coder returns
    {"name": "case_query", "arguments": {...}} as content, with tool_calls
    empty. The intent is unambiguous and the alternative is telling the
    analyst their model is unsupported, so it is read - but only when it names
    a tool that exists, and only when the message is that object and nothing
    else. A model that merely mentions a tool in a sentence is answering, not
    calling.
    """
    body = (text or "").strip()
    if body.startswith("```"):                  # ```json ... ```
        body = body.split(chr(10), 1)[-1].rsplit("```", 1)[0].strip()

    # The first object that names a tool that exists, not the last object in
    # the message. A model that narrates before it calls has still decided
    # what to call; a model that writes the whole plan out has decided what to
    # call first, and running that one turn puts real rows in front of it,
    # which is what stops the transcribing.
    for chunk in ([body] if body.startswith("{") and body.endswith("}")
                  else _objects(body)):
        try:
            got = json.loads(chunk)
        except ValueError:
            continue
        if not isinstance(got, dict):
            continue
        name = got.get("name") or got.get("tool")
        if name not in known:
            continue                        # a verdict, a row, a stray object
        args = got.get("arguments")
        if args is None:
            args = got.get("parameters") or {}
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except ValueError:
                # The argument written where the object of arguments should
                # be: qwen2.5-coder answered "when was the last sign-in" with
                #   {"name": "case_query", "arguments": "SELECT MAX(...)"}
                # and this dropped it, so a query that had found the right
                # table and the right column was printed to the analyst as
                # the answer. A tool with one required parameter has only one
                # thing that string can be. A tool with two does not, and
                # guessing which is which would be worse than not reading it.
                one = (solo or {}).get(name)
                if not one or not args.strip():
                    continue
                args = {one: args.strip()}
        if not isinstance(args, dict):
            continue
        return [{"id": "loose-0",
                 "function": {"name": name, "arguments": json.dumps(args)}}]
    return None


# name(key="value", key=value) - a call written the way it would be typed,
# which is neither the tool field nor the JSON object the other two readers
# handle.
_CALL_RE = re.compile(r"^([A-Za-z_][A-Za-z_0-9]*)\s*\((.*)\)$", re.S)
_ARG_RE = re.compile(r"""([A-Za-z_][A-Za-z_0-9]*)\s*=\s*"""
                     r"""("[^"]*"|'[^']*'|[^,()]+)""")


def _loose_pycall(text, known):
    """A tool call a model wrote as a call rather than as an object.

    The third spelling, and the one that costs the most when it is missed.
    Asked when the host was last signed in to, llama3.1:8b ran one query and
    then replied with

        case_values(table="USERS", column="last_login_utc")

    as its whole message. Nothing about that is an answer - it is the next
    step, written out instead of taken - and with no reader for it the panel
    showed the analyst a function call where the sign-in should have been.
    _loose_call reads the same intent spelled as JSON and _loose_sql reads it
    spelled as SQL; this reads it spelled as Python, which is how a model
    that has been shown a tool signature tends to write it.

    Same guard as the other two: the message has to be that call and nothing
    else, and it has to name a tool that exists. A model explaining which
    tool it used is answering, and re-running that would cost it a turn.
    """
    body = (text or "").strip()
    if body.startswith("```"):
        body = body.split(chr(10), 1)[-1].rsplit("```", 1)[0].strip()
    body = body.rstrip(";").strip()
    m = _CALL_RE.match(body)
    if not m or m.group(1) not in known:
        return None
    args = {}
    for key, raw in _ARG_RE.findall(m.group(2) or ""):
        val = raw.strip().strip("\"'")
        args[key] = val
    if not args and (m.group(2) or "").strip():
        return None                     # positional, or something else again
    return [{"id": "loose-call",
             "function": {"name": m.group(1), "arguments": json.dumps(args)}}]


def _loose_sql(text, known):
    """A message that is not an answer but the query the model meant to run.

    The other half of _loose_call, and it comes from the same place: asked to
    challenge a conclusion, llama3.1:8b worked the plan, had a query rejected
    for a column that does not exist, and then replied with nothing but

        SELECT timestamp_utc FROM LOGINS WHERE source_host = '' ...

    as its message. That is not an answer to anything - it is a tool call that
    lost its wrapper on the way out, and returning it to the analyst as the
    model's conclusion is the worst outcome available. So it is run, and the
    rows go back, and the model gets to finish.

    Only when the message is that statement and nothing else. A model that
    quotes the SQL it ran inside a sentence is explaining itself, which is
    exactly what it was asked to do, and re-running that would turn every good
    answer into another turn.
    """
    if "case_query" not in known:
        return None
    body = (text or "").strip()
    if body.startswith("```"):
        body = body.split(chr(10), 1)[-1].rsplit("```", 1)[0].strip()
    body = body.strip().rstrip(";").strip()
    head = body.lstrip("( \t\r\n")[:6].lower()
    if not (head.startswith("select") or head.startswith("with")):
        return None
    if ";" in body:
        return None
    return [{"id": "loose-sql",
             "function": {"name": "case_query",
                          "arguments": json.dumps({"sql": body})}}]


# The three kinds of value that make a forensic claim, and the three a model
# invents most readily. Small numbers are left alone deliberately: "2 of the 8
# tables" is arithmetic over results rather than a figure from one, and
# flagging it would bury the figures that matter under noise.
_FACT = re.compile(
    r"\b\d{1,3}(?:\.\d{1,3}){3}\b"                      # an address
    r"|\b\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}(?::\d{2})?)?"  # a timestamp
    r"|\b\d[\d,]{2,}\b")                                # a count, 3 digits up


def _plain(text):
    """Comparable form: no thousands separators, one kind of space."""
    return (text or "").replace(",", "").replace("T", " ")


def _unsupported(answer, corpus):
    """Figures in the answer that appear in no result the model was sent.

    This does not stop a model inventing. It stops an examiner believing the
    invention, which is the part that matters and the part that can actually
    be enforced.

    It is needed because of what llama3.1:8b did with profile_address on a
    3.4-million-row case: it ran case_search, once, got eight tables back with
    their real counts - and then wrote a hundred and fifty lines of per-table
    statistics for tables the search had not returned. BODYFILE with 26,192
    rows and a source_ip column it does not have. SUDOERS with 42. Earliest
    and latest timestamps for every one of them. Four figures in that report
    were real and the rest were composed, and nothing about the prose said
    which was which.

    Every number, address and timestamp in the answer is looked up in the raw
    tool results. What is not there did not come from the case, and is named.
    """
    if not (answer or "").strip():
        return []
    hay = _plain(corpus)
    bad, seen = [], set()
    for hit in _FACT.findall(answer):
        token = hit.strip().rstrip(".")
        flat = _plain(token)
        if not flat or flat in seen:
            continue
        seen.add(flat)
        if flat not in hay:
            bad.append(token)
    return bad[:40]


def _signature(name, args):
    """One call, normalised, so the same call twice is recognisable."""
    if isinstance(args, dict):
        body = json.dumps(args, sort_keys=True, default=str)
    else:
        body = str(args)
    return name + " " + " ".join(body.split()).lower()


REPEAT = ("You have already run this exact call in this investigation and it "
          "returned %s. Running it again returns the same thing. "
          "It was not re-run.%s"
          + chr(10) + chr(10) +
          "Change something or stop. If the last few queries all came back "
          "empty, the shape of the query is wrong, not the host: read the "
          "columns you are filtering on with case_values, drop the narrowest "
          "condition, or say plainly that you could not establish it. Do not "
          "answer from a result you did not get.")


def _repeat_note(out, extra=""):
    got = "nothing"
    if isinstance(out, dict):
        if out.get("error"):
            got = "an error"
        elif out.get("returned"):
            got = "%s row(s)" % out["returned"]
        elif "returned" in out:
            got = "0 rows"
    return REPEAT % (got, extra)


def _brief(name, args, out):
    """One line saying what the step did, for the trace the analyst reads.

    The trace is not decoration. A model that says 'the host was compromised
    on the 8th' is worth exactly as much as the queries behind it, and this is
    where they are shown.
    """
    if isinstance(out, dict):
        for k in ("returned", "total", "total_matches", "tables_with_events"):
            if k in out:
                return "%s -> %s %s" % (name, out[k], k.replace("_", " "))
    return name


# How much of the conversation before this question is carried forward. Only
# the questions and the answers - never the tool traffic, which is where all
# the tokens are and none of the meaning is. Two exchanges is what a follow-up
# actually needs ("and what about that address?" refers to the last answer,
# not to the one before the one before), and it keeps the window for the
# schema, which is what the model cannot do without.
ASK_HISTORY = 4                 # messages, so two question-and-answer pairs


def _prior(history):
    """Earlier turns, trimmed to what a follow-up needs to resolve."""
    out = []
    for m in history or []:
        role = str((m or {}).get("role") or "")
        text = str((m or {}).get("content") or "").strip()
        if role in ("user", "assistant") and text:
            # 4,000 characters each was a quarter of the window spent on
            # what was said last time before this turn had asked anything.
            out.append({"role": role, "content": text[:1200]})
    return out[-ASK_HISTORY:]


_DROPPED = ("[this result was dropped to keep the conversation inside the "
            "model's context window. The query did run - if you need it "
            "again, run it again, narrower.]")


def _result_body(out, cap):
    """One tool result, serialised small enough to send.

    It loses rows, not characters. Slicing the JSON string - which is what
    this did - handed the model an object with no closing brace and half a
    value in the last row, and a model that cannot parse a result reports
    what it can see of it. Dropping whole rows keeps the result a result,
    and says how many were taken out.
    """
    body = json.dumps(out, default=str)
    if len(body) <= cap or not isinstance(out, dict):
        return body[:cap]
    rows = out.get("rows")
    if not isinstance(rows, list) or len(rows) < 2:
        return body[:cap]
    keep = list(rows)
    while len(keep) > 1:
        keep = keep[:max(1, int(len(keep) * 0.6))]
        small = dict(out)
        small["rows"] = keep
        small["returned"] = len(keep)
        small["note"] = (
            "these are the first %d of the %d row(s) the query matched here; "
            "the rest were cut to fit the context window, not by the query. "
            "Do not report %d as a total - run the same WHERE as "
            "SELECT COUNT(*) if you need the number."
            % (len(keep), len(rows), len(keep)))
        body = json.dumps(small, default=str)
        if len(body) <= cap:
            return body
    return body[:cap]


def _fit(messages, ctx=None):
    """The conversation, trimmed to the window rather than truncated by it.

    Everything the model still needs to answer stays: the system message with
    the schema, the question, and the most recent results. What goes is the
    oldest tool results, and they go by name - a result replaced with a line
    saying it was dropped is a result the model knows it ran, where a missing
    one reads as a query it never made.
    """
    ctx = ctx or ASK_OPTIONS.get("num_ctx") or 8192
    budget = max(2000, (ctx - ASK_REPLY_TOKENS)) * ASK_CHARS_PER_TOKEN
    total = sum(len(m.get("content") or "") for m in messages)
    if total <= budget:
        return messages
    out = [dict(m) for m in messages]
    # oldest first, and never the last pair: that is the result the model is
    # being asked to read.
    for i in range(1, max(1, len(out) - 2)):
        if total <= budget:
            break
        if out[i].get("role") != "tool":
            continue
        was = len(out[i].get("content") or "")
        if was <= len(_DROPPED):
            continue
        out[i]["content"] = _DROPPED
        total -= was - len(_DROPPED)
    return out


def _final(url, model, messages):
    """One last turn with the tools taken away.

    A model that has used every round has usually done the work and simply
    not stopped querying - and throwing that away to tell the analyst it ran
    out is the worst of both, a minute spent and nothing to show. So it is
    asked once more, with no tools to reach for, to answer from what is
    already in front of it. If even that fails there is nothing to salvage
    and the honest message stands.
    """
    messages = messages + [{"role": "user", "content":
        "Stop querying. Answer now, using ONLY the rows already returned "
        "above." + chr(10) + chr(10) +
        "Every value you state - an address, a username, a path, a timestamp "
        "- must appear in one of those results. If it is not there you do not "
        "know it, and you must not write it down. Do not fill a gap with a "
        "plausible value; a fabricated address in a forensic report is worse "
        "than no report." + chr(10) + chr(10) +
        "If the queries above returned no rows, then the answer is that you "
        "did not establish it, and you should say which query you would run "
        "next. Otherwise: what you established, the table each part came "
        "from, and what you did not reach."}]
    try:
        msg = _chat(url, model, _fit(messages), [])
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError):
        return None
    text = (msg.get("content") or "").strip()
    return text or None


def ask(db_path, question, url=ASK_URL, model=None, rounds=ASK_ROUNDS,
        history=None, remember=None):
    """Answer one question against the case.

    -> {answer, steps, model, history}. `history` is the conversation to carry
    into the next question and is what makes a follow-up work: asked "and what
    else did it touch?" with no history, a model has no antecedent for "it"
    and profiles whichever address it happens to see first.

    `remember` is what this turn is recorded as in that thread, and it exists
    because a playbook is not a question. When the analyst presses a button,
    `question` is two thousand words of method - carrying that forward would
    fill the next turn's window with a plan it has already followed, instead
    of with what was asked and what came back.
    """
    question = (question or "").strip()
    if not question:
        raise CaseError("ask something")
    if not model:
        got = llm_models(url)
        if not got:
            raise CaseError(
                "no model is loaded. Ollama is answering but has nothing to "
                "run - pull one that supports tool calling, for example "
                "'ollama pull qwen2.5-coder:7b', then choose it here.")
        model = got[0]

    db = _open(db_path)
    tools = all_tools()
    call = dict((t[0], t[3]) for t in tools)
    # Tools that take exactly one required argument, and what it is called.
    # From the schemas, so a tool added later is covered without this being
    # remembered.
    solo = dict((t[0], ((t[2] or {}).get("required") or [""])[0])
                for t in tools
                if len((t[2] or {}).get("required") or []) == 1)
    schema = _schema(tools)
    # The schema goes in the system message rather than being left for the
    # model to discover. Asked cold, llama3.1 queried 'auth_events' and then
    # 'login_events', neither of which exists, and gave up - while the answer
    # sat in LOGINS, LASTLOG and USERS.last_login_utc. A list of names costs a
    # few hundred tokens and removes the guessing entirely.
    messages = ([{"role": "system",
                  "content": SYSTEM + chr(10) + chr(10) + _schema_brief(db)}]
                + _prior(history)
                + [{"role": "user", "content": question}])
    steps = []
    carry = _prior(history) + [{"role": "user",
                                "content": remember or question}]
    # What has already been run, and what it gave back. A model that is stuck
    # repeats itself rather than stopping: asked to challenge a conclusion,
    # llama3.1:8b wrote `WHERE start > (SELECT MAX(start) ...)` - which cannot
    # return a row, by construction - and ran it four times unchanged, burned
    # every round it had, and then invented an address and a 2023 timestamp
    # for a collection taken in 2021. Catching the second identical call costs
    # nothing and buys back the rounds it would have spent on the third.
    done = {}
    # Everything the model was sent back, kept so the answer can be checked
    # against it rather than taken on trust.
    corpus = []

    for _turn in range(max(1, rounds)):
        try:
            msg = _chat(url, model, _fit(messages), schema)
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", "replace")[:300]
            raise CaseError("the model runtime refused: %s %s" % (e.code, detail))
        except (urllib.error.URLError, OSError) as e:
            # A timeout and a refused connection are different problems and
            # must not read the same. "Is it running?" is actively misleading
            # when the answer is yes and the model is simply slow.
            if _timed_out(e):
                raise CaseError(
                    "the model did not answer within %d seconds. It is "
                    "running - it is thinking. A playbook is a long prompt "
                    "and prompt processing is the slow half on a CPU, so the "
                    "first turn is the one that runs out. Ask something "
                    "narrower, or run a smaller model." % ASK_TIMEOUT)
            raise CaseError("cannot reach a model at %s (%s). Is it running?"
                            % (url, e))
        except ValueError:
            raise CaseError("the model runtime sent something that is not JSON")

        calls = msg.get("tool_calls") or []
        if not calls:
            calls = (_loose_call(msg.get("content"), call, solo)
                     or _loose_pycall(msg.get("content"), call)
                     or _loose_sql(msg.get("content"), call) or [])
        if not calls:
            answer = (msg.get("content") or "").strip()
            return {"answer": answer, "steps": steps, "model": model,
                    "unsupported": _unsupported(answer, chr(10).join(corpus)),
                    "history": carry + [{"role": "assistant",
                                         "content": answer}]}

        messages.append({"role": "assistant",
                         "content": msg.get("content") or "",
                         "tool_calls": calls})
        for c in calls:
            fn = (c.get("function") or {})
            name = fn.get("name") or ""
            raw = fn.get("arguments")
            try:
                args = json.loads(raw) if isinstance(raw, str) else (raw or {})
            except ValueError:
                args = {}
            handler = call.get(name)
            # The row cap the tools default to is written for an MCP client
            # with a hundred thousand tokens to spend. Here 200 rows of
            # LOGINS is 54,215 characters against a 16,384-token window, and
            # a model cannot read what it cannot be sent.
            if isinstance(args, dict):
                try:
                    want = int(args.get("limit") or ASK_ROWS)
                except (TypeError, ValueError):
                    want = ASK_ROWS
                args = dict(args, limit=max(1, min(want, ASK_ROWS)))
            sig = _signature(name, args)
            if sig in done:
                out = {"error": _repeat_note(done[sig])}
            elif handler is None:
                out = {"error": "no tool called %r" % name}
            else:
                try:
                    out = handler(db, args)
                except CaseError as e:
                    # back to the model as data: it can correct a bad column
                    # name itself, and usually does on the next turn
                    out = {"error": str(e)}
                except Exception as e:              # never kill the panel
                    out = {"error": "%s: %s" % (type(e).__name__, e)}
            if sig not in done:
                done[sig] = out
            steps.append({"tool": name, "args": args,
                          "note": _brief(name, args, out)})
            body = _result_body(out, ASK_RESULT_TOKENS * ASK_CHARS_PER_TOKEN)
            corpus.append(body)
            messages.append({"role": "tool",
                             "tool_call_id": c.get("id") or name,
                             "content": body})

    answer = _final(url, model, messages)
    if answer and (_loose_call(answer, call, solo)
                   or _loose_pycall(answer, call)
                   or _loose_sql(answer, call)):
        # The last turn is asked to answer with the tools taken away, and a
        # model that has spent eight rounds without converging sometimes
        # replies with the ninth query rather than an answer. Asked which
        # address failed the most SSH logins, llama3.1:8b guessed at the
        # vocabulary five times and finished with {"name": "case_query",
        # "parameters": {...}} as its report. There is no round left to run
        # it in, and printing it puts a tool call in front of an analyst
        # where a finding should be - so it is not printed. What it looked
        # at is below it either way.
        answer = None
    if not answer:
        answer = ("I ran out of turns before I could answer that, and could "
                  "not summarise what I had. What I looked at is below - try "
                  "asking for one of those, narrower.")
    return {"answer": answer, "steps": steps, "model": model,
            "truncated": True,
            "unsupported": _unsupported(answer, chr(10).join(corpus)),
            "history": carry + [{"role": "assistant", "content": answer}]}
