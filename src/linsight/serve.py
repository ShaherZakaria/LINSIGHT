"""The investigation server: the console, plus a case file it writes to.

`--export` gives you a page. This gives you a workspace. The difference is
that the findings and the artifacts are only half of an investigation - the
other half is what the examiner decided about them, and a static page has
nowhere to put that.

Everything here is standard library. The box that reads a triage collection is
routinely the box that may not install anything, and a server that needs a
package manager is a server that does not run on the machine the evidence is
on.

Bound to the loopback interface by default and deliberately: this hands out
the parsed contents of somebody's compromised host, and that must not become a
service on the network by accident.
"""

from __future__ import annotations

import json
import os
import ast
import calendar
import socket
import sqlite3
import sys
import urllib.parse
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .ask import ASK_URL, ask, llm_models
from .mcp import CaseError, _open
from .skills import available, render
from .constants import VERSION
from .tables import _s
from .term import status

#: How large a request body the API will read. A mark is a few hundred bytes;
#: anything approaching this is a bug or an attempt at one.
MAX_BODY = 1 << 20

#: The states a row can be marked with. The key is what the page stores, the
#: label is what a report prints, and the colour is what the row turns.
MARK_STATES = (
    ("key", "Key evidence", "#ff5f56"),
    ("interesting", "Interesting", "#f5d067"),
    ("suspect", "Suspicious", "#ff9f43"),
    ("benign", "Reviewed - benign", "#3fb950"),
)


class CaseStore:
    """Marks, labels and notes for one investigation, saved as JSON.

    Written on every change rather than at exit. An investigation that loses
    an afternoon of annotation because the process was killed is worse than
    one that costs a few milliseconds per click, and the file is small.

    The row key is chosen by the page - table name plus a hash of the row's
    values - so a mark survives a re-run that produces the same row in a
    different position, and does not survive a row whose content changed. That
    is the correct behaviour for both: the mark belongs to the evidence, not
    to the offset it happened to sit at.
    """

    def __init__(self, path, db=None):
        self.path = os.path.abspath(path)
        self.db = db
        self.lock = threading.Lock()
        self.data = {"version": VERSION, "created": _now(), "case": {},
                     "marks": {}}
        self.load()

    def load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                got = json.load(fh)
            if isinstance(got, dict) and isinstance(got.get("marks"), dict):
                self.data = got
                self.data.setdefault("case", {})
                self.data.setdefault("version", VERSION)
        except (OSError, ValueError):
            pass                    # a missing or unreadable case starts empty
        return self.data

    def save(self):
        tmp = self.path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self.data, fh, indent=1, sort_keys=True)
            os.replace(tmp, self.path)
        except OSError as e:
            status("[!] case: could not write %s: %s" % (self.path, e))

    def set_mark(self, key, state="", note="", labels=None, where=None):
        """Add, change or clear one mark. -> the stored entry, or None."""
        with self.lock:
            marks = self.data.setdefault("marks", {})
            if not state and not note and not labels:
                marks.pop(key, None)
                self.save()
                if self.db:
                    self.db.put_mark(key, None)
                return None
            entry = marks.get(key) or {"created": _now()}
            entry["state"] = state
            entry["note"] = note or ""
            entry["labels"] = sorted(set(labels or []))
            entry["updated"] = _now()
            if where:
                entry["where"] = where
            marks[key] = entry
            self.save()
        if self.db:
            self.db.put_mark(key, entry)
        return entry

    def set_case(self, field, value):
        with self.lock:
            self.data.setdefault("case", {})[field] = value
            self.save()

    def snapshot(self):
        with self.lock:
            return json.loads(json.dumps(self.data))


class CaseDB:
    """The whole investigation in one SQLite file: evidence and annotation.

    The case JSON holds what the examiner decided. This holds that *and* every
    parsed row, which is what makes the file worth handing to somebody: open
    it in any SQLite client and the tables are the tables, queryable with SQL
    that has nothing to do with this tool.

    Written once when the server starts, then kept current for marks alone.
    The artifact tables do not change while the server is up - the evidence is
    what it is - so re-writing them on every annotation would be a great deal
    of I/O to say nothing new.

    Column names are quoted rather than validated because they come from the
    table builder, not from a request; the values are bound, never formatted,
    so a log line containing a quote is a value and not a syntax error.
    """

    def __init__(self, path):
        self.path = os.path.abspath(path)
        self.lock = threading.Lock()
        self._conn = None

    def connect(self):
        if self._conn is None:
            self._conn = sqlite3.connect(self.path, check_same_thread=False)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
        return self._conn

    def build(self, tables, meta=None, quiet=False):
        """Write every artifact table, one SQL table each. -> rows written."""
        db = self.connect()
        total = 0
        with self.lock:
            db.execute("DROP TABLE IF EXISTS _tables")
            db.execute("CREATE TABLE _tables (name TEXT PRIMARY KEY, "
                       "title TEXT, category TEXT, description TEXT, rows INT)")
            db.execute("DROP TABLE IF EXISTS _meta")
            db.execute("CREATE TABLE _meta (key TEXT, value TEXT)")
            for k, v in (meta or {}).items():
                db.execute("INSERT INTO _meta VALUES (?,?)", (str(k), str(v)))
            db.execute("""CREATE TABLE IF NOT EXISTS marks (
                            key TEXT PRIMARY KEY, state TEXT, note TEXT,
                            labels TEXT, tbl TEXT, what TEXT, when_utc TEXT,
                            row_json TEXT, created TEXT, updated TEXT)""")
            for t in tables:
                name = _sql_name(t.name)
                cols = [str(c) for c in t.columns] or ["value"]
                db.execute('DROP TABLE IF EXISTS "%s"' % name)
                db.execute('CREATE TABLE "%s" (%s)'
                           % (name, ",".join('"%s" TEXT' % c.replace('"', '')
                                             for c in cols)))
                ins = ('INSERT INTO "%s" VALUES (%s)'
                       % (name, ",".join("?" * len(cols))))
                n = 0
                for row in t.iter_rows():
                    # _s, not str: the project's own cell formatter. str() on a
                    # datetime keeps the '+00:00' offset, so the database held
                    # '2016-04-03 16:05:47+00:00' where every CSV and NDJSON
                    # export held '2016-04-03 16:05:47'. The console then could
                    # not parse its own timeline out of its own database.
                    vals = [None if v is None else _s(v) for v in row[:len(cols)]]
                    vals += [None] * (len(cols) - len(vals))
                    db.execute(ins, vals)
                    n += 1
                db.execute("INSERT INTO _tables VALUES (?,?,?,?,?)",
                           (name, t.title, t.category, t.description, n))
                total += n
            db.commit()
        if not quiet:
            status("[+] sqlite: %d row(s) in %d table(s) -> %s"
                   % (total, len(tables), self.path))
        return total

    def rows(self, name, offset=0, limit=0):
        """One table out of the database. -> {columns, rows, total} or None.

        The page used to carry every row itself, which made a disk image a
        ten-megabyte HTML file that took ten seconds to open and could not be
        screenshotted. The database already holds all of it, so the page can
        ask for a table when the examiner opens it and hold nothing until
        then.
        """
        db = self.connect()
        with self.lock:
            row = db.execute("SELECT name, rows FROM _tables WHERE name=?",
                             (name,)).fetchone()
            if not row:
                return None
            real, total = row
            cols = [c[1] for c in db.execute('PRAGMA table_info("%s")' % real)]
            sql = 'SELECT * FROM "%s"' % real
            if limit and limit > 0:
                sql += " LIMIT %d OFFSET %d" % (int(limit), int(offset))
            elif offset:
                sql += " LIMIT -1 OFFSET %d" % int(offset)
            out = [list(r) for r in db.execute(sql)]
        return {"name": real, "columns": cols, "rows": out, "total": total}

    #: Columns a table can carry its clock in, in the order they are trusted.
    TIME_COLS = ("timestamp_utc", "start_utc", "mtime_utc", "when_utc",
                 "first_utc", "last_utc", "dtime_utc", "ctime_utc")

    def find(self, name, pairs, limit=3):
        """The rows where every quoted field holds exactly its quoted value.

        A Sigma match quotes eight of a row's fields, shortening the long ones
        to fit the cell it lives in. Showing the whole of that row used to mean
        unpacking the artifact table in the browser - four seconds for
        WEB_LOG, nine for JOURNAL, on the thread that draws the page. The
        database already holds every row, so one indexed lookup here costs a
        few milliseconds and returns the fields at full length.

        Values carrying '...' were shortened and cannot be matched on; the
        caller drops them, and this refuses to run without something left.
        """
        db = self.connect()
        with self.lock:
            row = db.execute("SELECT name FROM _tables WHERE name=?",
                             (name,)).fetchone()
            if not row:
                return None
            real = row[0]
            cols = [c[1] for c in db.execute('PRAGMA table_info("%s")' % real)]
            use = [(k, v) for k, v in pairs if k in cols and "..." not in v]
            if not use:
                return {"columns": cols, "rows": []}
            where = " AND ".join('"%s"=?' % k for k, _ in use)
            sql = ('SELECT * FROM "%s" WHERE %s LIMIT ?'
                   % (real, where))
            got = db.execute(sql, [v for _, v in use] + [max(1, int(limit))])
            return {"columns": cols, "rows": [list(r) for r in got]}

    def context(self, when, minutes=15, per_table=40):
        """Everything the host recorded around one moment. -> [{table, rows}]

        The question an examiner asks the instant something looks wrong: what
        else was happening. Answering it means every table with a clock, not
        the one that happens to be open, and that is a query rather than a
        scan - which is the whole reason for the database.

        Ordered by how close each row is to the moment, so the first screen is
        the seconds either side rather than the first table alphabetically.
        """
        db = self.connect()
        out = []
        with self.lock:
            names = [r[0] for r in db.execute("SELECT name FROM _tables")]
            for name in names:
                cols = [c[1] for c in db.execute('PRAGMA table_info("%s")' % name)]
                tc = next((c for c in self.TIME_COLS if c in cols), None)
                if not tc:
                    continue
                sql = ('SELECT * FROM "%s" WHERE "%s" >= ? AND "%s" <= ? '
                       'ORDER BY "%s" LIMIT %d' % (name, tc, tc, tc, per_table))
                lo, hi = _shift(when, -minutes), _shift(when, minutes)
                try:
                    rows = [list(r) for r in db.execute(sql, (lo, hi))]
                except sqlite3.Error:
                    continue
                if rows:
                    out.append({"table": name, "time_column": tc,
                                "columns": cols, "rows": rows})
        out.sort(key=lambda d: -len(d["rows"]))
        return {"when": when, "minutes": minutes, "tables": out,
                "total": sum(len(d["rows"]) for d in out)}

    def put_mark(self, key, entry):
        db = self.connect()
        with self.lock:
            if entry is None:
                db.execute("DELETE FROM marks WHERE key=?", (key,))
            else:
                w = entry.get("where") or {}
                db.execute(
                    "INSERT OR REPLACE INTO marks VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (key, entry.get("state", ""), entry.get("note", ""),
                     " ".join(entry.get("labels") or []), w.get("table", ""),
                     w.get("what", ""), w.get("when", ""),
                     json.dumps({"columns": w.get("columns") or [],
                                 "row": w.get("row") or []}),
                     entry.get("created", ""), entry.get("updated", "")))
            db.commit()

    def close(self):
        if self._conn is not None:
            try:
                self._conn.close()
            except sqlite3.Error:
                pass
            self._conn = None


def _sql_name(name):
    """A table name safe to quote into SQL - the builder's names already are."""
    return "".join(ch if (ch.isalnum() or ch == "_") else "_" for ch in str(name))


#: The last read of the on-disk assets, keyed by the file's identity, so a
#: page load costs one stat rather than a re-read of the whole script.
_ASSETS = {}


def _asset_file():
    """The source file that carries APP_CSS and APP_JS, if it can be found.

    Single-file build: linsight.py, the script that is running. Package
    checkout: src/linsight/gui.py beside this module. Either way it is read
    from disk rather than from the imported constants, which is the entire
    point - the constants were fixed when the process started.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    for path in (os.path.join(here, "gui.py"),
                 os.path.abspath(sys.argv[0] or "")):
        try:
            if not path or not os.path.isfile(path):
                continue
            # The whole file, not a head. In the single-file build APP_CSS
            # sits about a megabyte in, so reading the first few hundred
            # kilobytes found no marker, rejected the only file that had
            # one, and fell back to the compiled-in assets - which is the
            # exact behaviour this function exists to avoid, arrived at
            # silently.
            with open(path, "r", encoding="utf-8") as fh:
                text = fh.read()
            if 'APP_CSS = """' in text or 'APP_JS = """' in text:
                return path
        except OSError:
            continue
    return ""


def _block(text, name):
    """The VALUE of a NAME = triple-quoted assignment, not its source.

    The distinction is the whole thing. Reading the file gives the text
    of the literal, in which a JavaScript regex is written the way
    Python needs it - a doubled backslash. Handing that to a browser
    produces a pattern with literal backslashes in it, and the page dies
    on "Range out of order in character class" before it defines a
    single function. ast.literal_eval applies exactly the unescaping the
    interpreter would have applied, so the served asset is identical to
    the compiled-in one.
    """
    key = name + " = " + '"""'
    i = text.find(key)
    if i < 0:
        return ""
    i += len(key) - 3
    j = text.find('"""', i + 3)
    if j <= i:
        return ""
    try:
        return ast.literal_eval(text[i:j + 3])
    except (ValueError, SyntaxError):
        return ""


def live_assets():
    """(css, js) as they are on disk now, or (None, None) to use the built-in.

    --serve holds one console in memory for the life of the process, so a
    rebuilt tool never reached a running server and an examiner kept looking
    at the stylesheet the server was born with. Re-reading here costs one file
    read per page load and means a rebuild is a browser refresh away.

    Failure is silent and falls back to the compiled-in assets: a console that
    refuses to load because a source file moved is worse than one that is a
    version behind.
    """
    path = _asset_file()
    if not path:
        return None, None
    try:
        info = os.stat(path)
        stamp = (path, info.st_mtime_ns, info.st_size)
    except OSError:
        return None, None
    if _ASSETS.get("stamp") == stamp:
        return _ASSETS["css"], _ASSETS["js"]
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except OSError:
        return None, None
    css = _block(text, "APP_CSS") or None
    js = _block(text, "APP_JS") or None
    _ASSETS.update(stamp=stamp, css=css, js=js)
    return css, js


def _shift(when, minutes):
    """'2019-10-05 11:14:04' +/- minutes, as the same string shape.

    String arithmetic on a UTC stamp, because that is what the tables store
    and comparing them as text is exact for this format - no timezone is
    reintroduced on the way through a date type.
    """
    try:
        t = time.strptime(str(when)[:19], "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return str(when)
    return time.strftime("%Y-%m-%d %H:%M:%S",
                         time.gmtime(calendar.timegm(t) + minutes * 60))


def _now():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())


def _skills(store):
    """The playbooks, told which of their tables this case actually has.

    Offered whether or not the tables are there. A button that vanishes on a
    host with no web logs teaches an examiner nothing; a playbook that runs
    and says "this collection has no WEB_LOG" teaches them the shape of their
    evidence, which is the more useful of the two.
    """
    if not store.db:
        return []
    try:
        db = _open(store.db.path)
    except CaseError:
        return []
    try:
        return available(db)
    finally:
        db.close()


def _playbook(store, name, args, question):
    """A skill, rendered against this case and addressed to the model."""
    db = _open(store.db.path)
    try:
        text = render(name, db, args or {})
    finally:
        db.close()
    asked = (question or "").strip()
    if asked:
        text += (chr(10) * 2 + "The analyst asked it this way, so answer "
                 "that, using the method above: " + asked)
    return text


def _handler(page, store):
    class Handler(BaseHTTPRequestHandler):
        server_version = "linsight/" + VERSION
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            pass                    # the console is the output, not the log

        # -- helpers --------------------------------------------------------
        def _send(self, code, body, ctype="application/json"):
            if isinstance(body, str):
                body = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            # This page is the evidence; nothing about it should be cached by
            # anything, and nothing on it should reach the network.
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Security-Policy",
                             "default-src 'self' 'unsafe-inline'; "
                             "connect-src 'self'; img-src 'self' data:")
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def _body(self):
            try:
                n = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                return {}
            if n <= 0 or n > MAX_BODY:
                return {}
            try:
                return json.loads(self.rfile.read(n).decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                return {}

        # -- routes ---------------------------------------------------------
        def do_GET(self):
            path = self.path.split("?")[0]
            if path in ("/", "/index.html"):
                body = page() if callable(page) else page
                return self._send(200, body, "text/html; charset=utf-8")
            if path == "/api/case":
                return self._send(200, json.dumps(store.snapshot()))
            if path == "/api/context":
                q = urllib.parse.parse_qs(self.path.partition("?")[2])
                when = (q.get("when") or [""])[0]
                try:
                    mins = max(1, min(1440, int((q.get("minutes") or ["15"])[0])))
                except ValueError:
                    mins = 15
                if not store.db or not when:
                    return self._send(400, json.dumps(
                        {"error": "need a database and a 'when'"}))
                return self._send(200, json.dumps(store.db.context(when, mins)))
            if path == "/api/rows":
                # The page asks for a table by name and gets it out of the
                # database. Names are checked against _tables rather than
                # escaped into the query: a name that is not one this run
                # built is not a table, and there is nothing to sanitise.
                q = urllib.parse.parse_qs(self.path.partition("?")[2])
                name = (q.get("table") or [""])[0]
                try:
                    off = max(0, int((q.get("offset") or ["0"])[0]))
                    lim = int((q.get("limit") or ["0"])[0])
                except ValueError:
                    off, lim = 0, 0
                if not store.db:
                    return self._send(404, json.dumps(
                        {"error": "this run has no database"}))
                got = store.db.rows(name, off, lim)
                if got is None:
                    return self._send(404, json.dumps(
                        {"error": "no table called %r here" % name}))
                return self._send(200, json.dumps(got))
            if path == "/api/find":
                # The pairs arrive as JSON so a value may hold anything at all
                # - a shell command with '=' and ';' in it is the usual case.
                q = urllib.parse.parse_qs(self.path.partition("?")[2])
                name = (q.get("table") or [""])[0]
                try:
                    pairs = json.loads((q.get("keys") or ["[]"])[0])
                except ValueError:
                    return self._send(400, json.dumps({"error": "bad keys"}))
                if not store.db:
                    return self._send(404, json.dumps(
                        {"error": "this run has no database"}))
                if not isinstance(pairs, list):
                    return self._send(400, json.dumps({"error": "bad keys"}))
                clean = [(str(p[0]), str(p[1])) for p in pairs
                         if isinstance(p, list) and len(p) == 2]
                got = store.db.find(name, clean)
                if got is None:
                    return self._send(404, json.dumps(
                        {"error": "no table called %r here" % name}))
                return self._send(200, json.dumps(got))
            if path == "/api/llm":
                # The panel asks this before offering a box to type in: a
                # model that is not there is worth saying once, clearly,
                # rather than as a failed request per question.
                cfg = getattr(store, "llm", None) or {}
                models = llm_models(cfg.get("url") or ASK_URL)
                return self._send(200, json.dumps(
                    {"url": cfg.get("url") or ASK_URL,
                     "model": cfg.get("model") or (models[0] if models else ""),
                     "models": models,
                     "db": bool(store.db),
                     "skills": _skills(store)}))
            if path == "/api/states":
                return self._send(200, json.dumps(
                    [{"key": k, "label": l, "colour": c}
                     for k, l, c in MARK_STATES]))
            return self._send(404, json.dumps({"error": "no such path"}))

        def do_POST(self):
            path = self.path.split("?")[0]
            body = self._body()
            if path == "/api/ask":
                cfg = getattr(store, "llm", None) or {}
                if not store.db:
                    return self._send(404, json.dumps(
                        {"error": "this run has no database to query"}))
                body = body or {}
                try:
                    # A skill named here replaces the question with its
                    # playbook. The analyst still sees what they typed - the
                    # page keeps that - but what the model receives is the
                    # method, which is the whole point of pressing a button
                    # instead of phrasing a question.
                    asked = str(body.get("question") or "")
                    skill = str(body.get("skill") or "").strip()
                    question = asked
                    if skill:
                        question = _playbook(store, skill, body.get("args"),
                                             asked)
                    out = ask(store.db.path, question,
                              cfg.get("url") or ASK_URL,
                              body.get("model") or cfg.get("model"),
                              history=body.get("history"),
                              remember=(asked or skill) if skill else None)
                except CaseError as e:
                    return self._send(200, json.dumps({"error": str(e)}))
                except Exception as e:
                    return self._send(200, json.dumps(
                        {"error": "%s: %s" % (type(e).__name__, e)}))
                return self._send(200, json.dumps(out))
            if path == "/api/mark":
                key = str(body.get("key") or "")
                if not key:
                    return self._send(400, json.dumps({"error": "no key"}))
                entry = store.set_mark(
                    key, str(body.get("state") or ""),
                    str(body.get("note") or ""),
                    [str(x) for x in (body.get("labels") or [])],
                    body.get("where") or None)
                return self._send(200, json.dumps({"ok": True, "entry": entry}))
            if path == "/api/case":
                for k, v in (body or {}).items():
                    store.set_case(str(k), v)
                return self._send(200, json.dumps({"ok": True}))
            return self._send(404, json.dumps({"error": "no such path"}))

    return Handler


def _claim(sock, host, port):
    """Try to take a port, refusing to take one somebody else is serving.

    SO_REUSEADDR is the reflex here and it is wrong on Windows: it lets a bind
    to 127.0.0.1:8000 succeed over a process already listening on
    0.0.0.0:8000, and quietly takes that address away from it. That is how
    this tool ended up answering on a port Splunk was serving - both were
    listening, and localhost went to whichever bound last.

    SO_EXCLUSIVEADDRUSE is the Windows way to say "only if it is really free".
    Elsewhere the default behaviour already refuses, so nothing is set: a
    forensic tool must not be able to shadow a service by starting up.
    """
    opt = getattr(socket, "SO_EXCLUSIVEADDRUSE", None)
    if opt is not None:
        try:
            sock.setsockopt(socket.SOL_SOCKET, opt, 1)
        except OSError:
            pass
    sock.bind((host, port))


def _free_port(host, port):
    """The requested port, or the next one genuinely free after it."""
    for candidate in range(port, port + 40):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                _claim(s, host, candidate)
                return candidate
            except OSError:
                continue
    raise SystemExit("[!] serve: no free port in %d-%d" % (port, port + 39))


def parse_bind(text):
    """'8000', ':8000', '127.0.0.1:8000' -> (host, port)."""
    host, port = "127.0.0.1", 8000
    text = (text or "").strip()
    if text:
        if ":" in text:
            h, _, p = text.rpartition(":")
            host = h or host
            port = int(p) if p.isdigit() else port
        elif text.isdigit():
            port = int(text)
        else:
            host = text
    return host, port


def serve(page, case_path, bind="127.0.0.1:8000", open_browser=True,
          tables=None, meta=None, db_path=None, llm=None):
    """Run the investigation server until interrupted."""
    host, port = parse_bind(bind)
    db = None
    if db_path:
        db = CaseDB(db_path)
        if tables:
            db.build(tables, meta)
    store = CaseStore(case_path, db)
    # Where the Ask panel looks for a model. Held on the store because
    # the request handler has one of those and nothing else.
    store.llm = llm or {"url": ASK_URL, "model": ""}
    asked = port
    port = _free_port(host, port)
    class _Server(ThreadingHTTPServer):
        # HTTPServer sets this to 1, which on Windows is the same hijack the
        # probe above refuses. The probe having proved the port free, there is
        # nothing left for it to buy.
        allow_reuse_address = False

    httpd = _Server((host, port), _handler(page, store))
    url = "http://%s:%d/" % (host, port)

    if port != asked:
        status("[*] port %d was in use - taking %d instead" % (asked, port))
    status("[+] investigation server on %s" % url)
    status("    case file: %s (%d mark(s) loaded)"
           % (store.path, len(store.data.get("marks") or {})))
    if host not in ("127.0.0.1", "localhost", "::1"):
        status("[!] bound to %s - this serves the parsed contents of the "
               "evidence to anyone who can reach that address" % host)
    status("    Ctrl-C to stop")
    if open_browser:
        threading.Thread(target=lambda: (time.sleep(0.4),
                                         webbrowser.open(url)),
                         daemon=True).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        status("\n[*] case saved to %s" % store.path)
    finally:
        httpd.server_close()
        if db:
            db.close()
    return store
