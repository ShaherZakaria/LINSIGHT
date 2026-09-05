"""Playbooks: the moves an examiner makes, written down so a model can run them.

A 7B model with a schema and a SELECT can answer a question. It cannot decide
which question to ask next, and that is most of the job. Asked "what happened
to this host" it queries FINDINGS, reads the top row back in different words,
and stops - which is a summary, and the one thing the tool is not for.

So the method goes in the file rather than in the analyst's head. Each skill
is a sequence an examiner actually follows, with the tables named, the join
written out, and the trap that particular sequence falls into called out where
it falls. Handed one, the same 7B runs seven queries instead of one and the
answer has a shape: what is established, what it rests on, what is still open.

Three consumers, one definition:

  - MCP prompts. `prompts/list` and `prompts/get` are how the protocol ships
    exactly this, so a client - Claude Desktop, Claude Code - offers them by
    name and no linsight-specific glue is needed at the other end.
  - The case_skill tool, for the local model in the Ask panel, which has no
    prompt menu and has to be able to fetch a playbook mid-conversation.
  - The buttons in the page, so an analyst who does not want to phrase a
    question can press the thing they meant.

Every playbook is rendered against the case in front of it. A skill that names
CRON and SYSTEMD_TIMERS on a host where the collector caught neither says so,
in the text, rather than sending the model to query an empty table and report
the emptiness as a finding.
"""

from .mcp import TOOLS, CaseError, _tables


# One placeholder syntax, and it is not str.format: the playbooks are full of
# SQL and JSON, and a stray brace in either turns a format() into a traceback
# at exactly the moment an examiner is waiting on an answer. <ANGLE> tokens
# also survive being left unfilled - a model that receives <ADDRESS> asks which
# address, where a model that receives '' silently profiles nothing.
def _fill(text, args):
    for key, value in (args or {}).items():
        text = text.replace("<%s>" % str(key).upper(), str(value))
    return text


# ---------------------------------------------------------------- the skills
#
# Fields:
#   name    what the tool and the protocol call it
#   title   what a human sees in a menu
#   about   one line: when you would reach for this
#   args    (name, description, required) - what it needs to be pointed at
#   tables  every table the plan mentions, so the renderer can say which of
#           them this case actually has before the model starts guessing
#   plan    the playbook itself

SKILLS = (

    {"name": "triage_host",
     "title": "What is wrong with this host",
     "about": "Start here. The findings, then the rows underneath them.",
     "args": (),
     "tables": ("FINDINGS", "SIGMA_MATCHES", "HACKTOOL_HITS", "IOC_HITS",
                "YARA_MATCHES", "COLLECTION_ERRORS"),
     "plan": """Establish what this host looks like, from the evidence up.

1. case_findings(severity="CRITICAL"), then again with "HIGH". These are what
   the triage raised, not what is true - they are leads with row counts.

2. Take the three most serious. For each, the finding names an artifact and a
   count; go to that table and read the rows themselves:
       SELECT * FROM <the artifact table> WHERE ... LIMIT 20
   A finding's `evidence` column is shortened to fit a cell. case_row pulls the
   whole row when a quote matters.

3. SIGMA_MATCHES and HACKTOOL_HITS are a second opinion from a different
   engine. Where they agree with a finding, say so - two engines on the same
   rows is worth more than one:
       SELECT rule, severity, "table", count, first_utc, last_utc
         FROM SIGMA_MATCHES ORDER BY count DESC LIMIT 20

4. Now place it in time. Take first_utc of the earliest serious finding and
   run case_timeline over the hour around it. What surrounds an event is
   usually what explains it.

5. Answer in three parts, in this order:
     - what is established, each line with the table and the count behind it
     - what is suspected and what would confirm it
     - what this collection cannot tell you

Before you write step 5, check COLLECTION_ERRORS. An artifact the collector
failed to read is a hole in the evidence, and a hole reported as an absence is
a wrong answer that reads exactly like a right one."""},

    {"name": "profile_address",
     "title": "Everything one address did",
     "about": "One IP, across every table that records an address.",
     "args": (("address", "the IP address, e.g. 209.141.62.185", True),),
     "tables": ("FAILED_LOGINS", "AUTH_LOG", "WEB_LOG", "LOGIN_RECORDS",
                "LOGINS", "SOCKETS", "NETSTAT", "PRIVILEGE_ACTIVITY",
                "IOC_HITS", "ARP_NEIGHBORS"),
     "plan": """Build the whole record of <ADDRESS> on this host.

The address is spelled differently in every table it appears in. That is the
one thing to get right here, and it is the thing most answers get wrong:

    source_ip     FAILED_LOGINS, AUTH_LOG, PRIVILEGE_ACTIVITY
    client_ip     WEB_LOG
    remote_ip     LOGIN_RECORDS
    source_host   LOGINS, FAILED_LOGINS   (a name OR an address, both appear)
    peer_addr     SOCKETS, NETSTAT
    indicator     IOC_HITS

1. case_search(term="<ADDRESS>") first, and read the table list it returns
   before writing any SQL. It searches every column of every table, so it
   finds the two tables you would not have thought of. The counts it gives you
   are the counts to reconcile against later.

2. Authentication. Both halves, and both numbers:
       SELECT COUNT(*) FROM FAILED_LOGINS WHERE source_ip = '<ADDRESS>'
       SELECT timestamp_utc, user, event, result FROM AUTH_LOG
        WHERE source_ip = '<ADDRESS>' ORDER BY timestamp_utc
   The question that matters is not how many failures. It is whether anything
   succeeded after them, and as which account.

3. Web, if WEB_LOG has rows for it. What was requested, and what came back:
       SELECT status, COUNT(*) n FROM WEB_LOG WHERE client_ip = '<ADDRESS>'
        GROUP BY status ORDER BY n DESC
       SELECT timestamp_utc, method, resource, status, user_agent FROM WEB_LOG
        WHERE client_ip = '<ADDRESS>' AND CAST(status AS INTEGER) < 400
        ORDER BY timestamp_utc LIMIT 40
   A 404 is someone knocking. A 200 on the same path is someone in.

4. Sessions and sockets. LOGINS records the origin as a hostname in
   source_host, so match it loosely there and exactly everywhere else:
       SELECT user, service, terminal, source_host, start, "end", duration
         FROM LOGINS WHERE source_host LIKE '%<ADDRESS>%'
       SELECT proto, state, local_port, peer_addr, peer_port, process, exe, user
         FROM SOCKETS WHERE peer_addr = '<ADDRESS>'
   A row in SOCKETS is a connection that was live when the collector ran, which
   is a much stronger statement than a line in a log.

5. Bound the activity: the earliest and latest timestamp for <ADDRESS> in each
   table that has one, so the answer carries a window rather than a verb.

Report per-table counts, both sides of every claim, taken from your own
results: "<N> failed logins and <M> web requests" is checkable once you have
run the two counts. "significant activity" is not, at any N."""},

    {"name": "profile_user",
     "title": "Everything one account did",
     "about": "One account: how it signed in, what it ran, what it can do.",
     "args": (("user", "the username, e.g. www-data", True),),
     "tables": ("USERS", "LOGINS", "LOGIN_RECORDS", "LASTLOG", "AUTH_LOG",
                "SHELL_HISTORY", "PRIVILEGE_ACTIVITY", "SUDOERS", "CRON",
                "PROCESSES", "USER_ARTIFACTS"),
     "plan": """Build the whole record of the account <USER>.

1. The account itself. USERS is one row per account and it already carries the
   joins - do not rebuild them by hand:
       SELECT * FROM USERS WHERE username = '<USER>'
   Read shell, login_capable, uid, privileged_groups, authorized_keys,
   sudo_rules, last_login_utc. A service account with a real shell, or with an
   authorized_keys file, is the finding on its own.

2. How it signed in. Four tables record a sign-in and they do not agree by
   accident - if one is empty, go to the next before concluding anything:
       SELECT user, service, terminal, source_host, start, "end", duration,
              result, state FROM LOGINS WHERE user = '<USER>' ORDER BY start
       SELECT timestamp_utc, event, result, source_ip FROM AUTH_LOG
        WHERE user = '<USER>' OR target_user = '<USER>' ORDER BY timestamp_utc
   Note LOGINS times are `start` and `end`, not timestamp_utc, and that it
   holds refused logins as well as granted ones - `lastb` reads there too.
   result = 'success' is the sign-ins; state is how a session ended, not
   whether it was allowed. For the last time this account got in:
       SELECT MAX(start) FROM LOGINS
        WHERE user = '<USER>' AND result = 'success' 

3. What it ran:
       SELECT timestamp_utc, shell, file, line_no, command FROM SHELL_HISTORY
        WHERE user = '<USER>' ORDER BY file, line_no
   History has no timestamps unless the shell was configured to keep them, so
   most rows will have an empty timestamp_utc. File order is still order.
   Then the live picture:
       SELECT pid, ppid, start_utc, exe, args FROM PROCESSES WHERE user='<USER>'

4. What it did with privilege. actor is who elevated, target_user is who they
   became - check both, because <USER> can be either end of it:
       SELECT timestamp_utc, event, actor, target_user, command, result
         FROM PRIVILEGE_ACTIVITY
        WHERE actor = '<USER>' OR target_user = '<USER>' ORDER BY timestamp_utc

5. What it left behind: CRON where owner or run_as is <USER>, and
   USER_ARTIFACTS for the per-user files the collector picked up.

If a WHERE on username returns nothing, call case_values(table, column) before
you report the account as absent. Some tables carry the uid, some the name,
and some the name with a domain on it."""},

    {"name": "intrusion_window",
     "title": "Reconstruct one moment",
     "about": "What every artifact was recording around a given time.",
     "args": (("when", "'YYYY-MM-DD HH:MM:SS' UTC, the moment to centre on",
               True),),
     "tables": ("AUTH_LOG", "WEB_LOG", "SHELL_HISTORY", "AUDIT_LOG",
                "PRIVILEGE_ACTIVITY", "BODYFILE", "JOURNAL", "FINDINGS"),
     "plan": """Reconstruct what was happening at <WHEN>.

1. case_timeline from fifteen minutes before <WHEN> to fifteen minutes after.
   It asks every table that carries a clock, which is the point - the tables
   you would have thought to check are not usually the ones that explain it.

2. Read what came back as one sequence, not table by table. The order across
   tables is the story: a request, then a process, then a file, then a
   connection outward is an intrusion. The same four in a different order is a
   backup job.

3. Widen only where it is thin. If the window is empty, go to two hours; if it
   is a wall of one table, narrow to five minutes and query that table
   directly.

4. BODYFILE is the filesystem's own account of the same window and it is
   usually the largest table in the case. Bound it hard:
       SELECT mtime_utc, path, size FROM BODYFILE
        WHERE mtime_utc BETWEEN '<WHEN minus 15m>' AND '<WHEN plus 15m>'
        ORDER BY mtime_utc LIMIT 100
   A file written inside the window, in a directory a web server can write to,
   is worth more than anything a log says about it.

5. Say what happened, in order, with a timestamp and a table on every line.
   Where two tables record the same event, say both - that is corroboration,
   and it is the difference between a timeline and a guess.

Timestamps are UTC everywhere in this database. If a row's time looks hours
off, it is not a time zone bug in the data, it is a different event."""},

    {"name": "persistence",
     "title": "What survives a reboot",
     "about": "Every mechanism that would run this again tomorrow.",
     "args": (),
     "tables": ("CRON", "SYSTEMD_UNITS", "SYSTEMD_TIMERS", "INIT_AND_PROFILE",
                "KERNEL_MODULES", "USERS", "PROC_ENVIRON_VARIABLES",
                "SERVICES", "REMOTE_ACCESS"),
     "plan": """Find everything on this host that would run again without a
person doing anything.

Work through the mechanisms. Each is one query, and the point is coverage -
an intrusion usually installs more than one, and finding the first is not
finding them all.

1. Scheduled work:
       SELECT file, owner, kind, schedule, run_as, command, running_pids
         FROM CRON ORDER BY owner
   running_pids joins the command against the live process table. A scheduled
   job that is also running right now is a different problem from one that is
   merely configured.
       SELECT * FROM SYSTEMD_TIMERS

2. Units, which is where a modern implant lives:
       SELECT unit, path, scope, exec_start, user, restart, wanted_by,
              running_pids FROM SYSTEMD_UNITS
        WHERE exec_start <> '' ORDER BY scope, unit
   Read exec_start, not the unit name. A unit called `sysstat-collect` that
   execs something out of /tmp or /dev/shm or a home directory is the answer.
   Check exec_start_pre too - it runs first and is read less often.

3. Shell startup, which needs no privilege at all:
       SELECT * FROM INIT_AND_PROFILE

4. The kernel:
       SELECT module, filename, license, signer, intree, description
         FROM KERNEL_MODULES WHERE intree <> 'Y' OR signer = ''
   An out-of-tree unsigned module on a stock distribution kernel is either a
   driver somebody built or a rootkit, and the filename usually says which.

5. The loader:
       SELECT * FROM PROC_ENVIRON_VARIABLES WHERE variable LIKE 'LD_%'
   plus /etc/ld.so.preload if the collection has it - case_search("ld.so.preload").

6. Keys, which are the quietest of all:
       SELECT username, home, shell, authorized_keys, has_private_key
         FROM USERS WHERE authorized_keys <> ''
   An authorized_keys on an account that should never log in interactively is
   persistence, whatever else it looks like.

For each mechanism you find, say: where it is configured, what it runs, whose
it is, and whether it is running now. A path under /tmp, /dev/shm, /var/tmp or
a home directory in any of these is the thing to lead with."""},

    {"name": "web_intrusion",
     "title": "Follow a web exploitation chain",
     "about": "Request, response, and what ran on the host afterwards.",
     "args": (),
     "tables": ("WEB_LOG", "WEB_CONFIG", "PROCESSES", "SHELL_HISTORY",
                "AUDIT_LOG", "SOCKETS", "BODYFILE", "FINDINGS"),
     "plan": """Work a web-facing intrusion from the request to what it ran.

1. What was probed. Exploitation is shaped differently from browsing:
       SELECT resource, COUNT(*) n, MIN(timestamp_utc) first,
              MAX(timestamp_utc) last FROM WEB_LOG
        WHERE resource LIKE '%..%' OR resource LIKE '%cgi-bin%'
           OR resource LIKE '%.php%' OR resource LIKE '%wp-%'
           OR resource LIKE '%/etc/passwd%' OR resource LIKE '%eval%'
           OR resource LIKE '%cmd=%'
        GROUP BY resource ORDER BY n DESC LIMIT 40

2. What worked. This is the whole question, and it is one column:
       SELECT timestamp_utc, client_ip, method, resource, status, size,
              user_agent FROM WEB_LOG
        WHERE CAST(status AS INTEGER) BETWEEN 200 AND 399
          AND (resource LIKE '%..%' OR resource LIKE '%cmd=%'
               OR resource LIKE '%.php%')
        ORDER BY timestamp_utc LIMIT 40
   status is text in this database, so compare it as CAST(status AS INTEGER)
   or against the string. A 200 to a traversal path is not a probe, it is a
   read. Note size: two 200s to the same path with different sizes usually
   means one of them returned something.

3. Who. Take the client_ip from step 2 and count what else it did. If it also
   appears in FAILED_LOGINS, that is one actor on two services, and it is
   a JOIN, never a UNION:
       SELECT w.client_ip, w.n AS web, f.n AS failed
         FROM (SELECT client_ip, COUNT(*) n FROM WEB_LOG
                WHERE client_ip <> '' GROUP BY client_ip) w
         JOIN (SELECT source_ip, COUNT(*) n FROM FAILED_LOGINS
                WHERE source_ip <> '' GROUP BY source_ip) f
           ON f.source_ip = w.client_ip ORDER BY w.n DESC LIMIT 10

4. What it became. Take the timestamp of the first successful request and run
   case_timeline over the ten minutes after it. A web server that spawns a
   shell, a curl, a python, or anything at all out of /tmp is the handoff from
   request to execution:
       SELECT pid, ppid, user, start_utc, exe, args FROM PROCESSES
        WHERE user IN ('www-data','apache','nginx','httpd','daemon')
   and the same accounts in SHELL_HISTORY, which should be empty for them.

5. What it left. Files written under the web root around that time, from
   BODYFILE - WEB_CONFIG gives you the root to look under.

State the chain as a chain: this address requested this, got this status at
this time, and this ran N seconds later. Where you cannot join two links, say
which link is missing rather than closing the gap with a verb."""},

    {"name": "privilege_escalation",
     "title": "How they got root",
     "about": "Sudo, SUID, group changes, and accounts that should not exist.",
     "args": (),
     "tables": ("PRIVILEGE_ACTIVITY", "SUDOERS", "SUID_SGID", "USERS",
                "GROUPS", "AUTH_LOG", "CAPABILITIES"),
     "plan": """Establish whether privilege was escalated on this host, and how.

1. What was actually used:
       SELECT timestamp_utc, event, actor, target_user, command, result, tty
         FROM PRIVILEGE_ACTIVITY ORDER BY timestamp_utc
   Read `result`. A failed sudo followed by a successful one, same actor, same
   minute, is a password being found. Read `command` - sudo to a shell, an
   editor, or anything with -e or ! in it is sudo to root by another name.

2. What is permitted:
       SELECT file, line_no, rule, nopasswd FROM SUDOERS
        WHERE nopasswd <> '' OR rule LIKE '%ALL%'
   A NOPASSWD rule for a service account is escalation waiting to be used, and
   it does not need a log line to be true.

3. What is on disk:
       SELECT path, kind, owner, mode, mtime_utc, md5, in_distro_baseline
         FROM SUID_SGID WHERE in_distro_baseline <> 'yes'
   The baseline column is the whole value of this table - the twenty expected
   SUID binaries are not the answer, the twenty-first is. Check mtime_utc
   against the rest of the intrusion window, and call case_values on
   in_distro_baseline before filtering on it, so the filter matches what that
   column really holds.

4. Who is privileged, whether or not they used it:
       SELECT username, uid, shell, login_capable, privileged_groups,
              password_status, last_login_utc FROM USERS
        WHERE privileged_groups <> '' OR uid = 0 ORDER BY uid
   More than one account with uid 0 is a backdoor, not a configuration.

5. Who was created or changed, and when:
       SELECT timestamp_utc, event, actor, target_user, target_group, detail
         FROM PRIVILEGE_ACTIVITY
        WHERE event LIKE '%USER%' OR event LIKE '%GROUP%'
        ORDER BY timestamp_utc

6. Capabilities, if the collection has them - a binary with cap_setuid needs
   no SUID bit and is missed by anyone only looking for one.

Say which of these is evidence of escalation having happened and which is
capability for it to happen. They are different findings and an analyst needs
them separated."""},

    {"name": "egress",
     "title": "What was talking outward",
     "about": "Outbound connections, listeners, and the transfers in history.",
     "args": (),
     "tables": ("SOCKETS", "NETSTAT", "PROC_NET", "PROCESSES",
                "SHELL_HISTORY", "FIREWALL", "ROUTES", "IOC_HITS"),
     "plan": """Establish what this host was talking to, and what was listening.

1. Established connections, with the process on the end of them:
       SELECT proto, state, local_addr, local_port, peer_addr, peer_port,
              pid, process, exe, user FROM SOCKETS
        WHERE state = 'ESTAB' AND peer_addr <> '' ORDER BY peer_addr
   Exclude the host's own networks by reading the addresses rather than by
   assuming: 10., 172.16-31., 192.168., 127., ::1 are local. Anything else is
   the internet, and the interesting rows are the ones where exe is not a
   thing that should be talking to it.

2. Listeners, which is how it was reached in the first place:
       SELECT proto, local_addr, local_port, process, exe, user FROM SOCKETS
        WHERE state = 'LISTEN' ORDER BY CAST(local_port AS INTEGER)
   A listener on 0.0.0.0 that is not the service this host exists to run is
   the finding. A high port held by a shell, a python, or a binary in /tmp is
   the finding whatever it is bound to.

3. NETSTAT is the same picture from a different command. Where SOCKETS is
   empty, use it - and where both have rows, agreement between them is worth
   saying. case_values(table="SOCKETS", column="state") first if a filter on
   'ESTAB' returns nothing: the two commands spell the states differently.

4. Transfers, which leave no socket behind once they finish:
       SELECT user, file, line_no, command FROM SHELL_HISTORY
        WHERE command LIKE '%curl%' OR command LIKE '%wget%'
           OR command LIKE '%scp%' OR command LIKE '%rsync%'
           OR command LIKE '%nc %' OR command LIKE '%ncat%'
           OR command LIKE '%base64%' OR command LIKE '%/dev/tcp/%'
        ORDER BY user, file, line_no
   /dev/tcp is a bash builtin and needs no binary on the host at all.

5. What the host was configured to allow - FIREWALL - and where it routes.

For every connection you report, give the process and the account behind it.
A peer address on its own is a lead. A peer address, a pid, a binary path and
the account that owns it is a finding."""},

    {"name": "challenge",
     "title": "Try to break a conclusion",
     "about": "Take a claim and attack it. Report what survives.",
     "args": (("claim", "the statement to test, in one sentence", True),),
     "tables": (),
     "plan": """Your job here is to refute this claim, not to support it:

    <CLAIM>

Assume it is wrong and go and find the row that proves it. An analyst is about
to put this in a report, and the cheapest place to find the error is here.

1. Write the ONE query that would find a counterexample - a single row whose
   existence makes the claim false - and run it. Not a query that confirms the
   claim: a query that breaks it. For a claim that nothing of some kind
   happened, that is the query for a thing of that kind happening, with no
   condition on it beyond the kind:

       "nobody logged in successfully from the internet"
           -> SELECT timestamp_utc, user, source_ip, result FROM AUTH_LOG
               WHERE result = 'success' AND source_ip <> ''
               ORDER BY timestamp_utc LIMIT 20
       "there is no persistence"
           -> SELECT owner, schedule, command FROM CRON LIMIT 40
       "this address only failed"
           -> the same address in AUTH_LOG with result = 'success'

   Keep it short and keep it wide. A counterexample query with three
   conditions on it is not looking for the counterexample, it is looking for a
   particular one you imagined. Never compare a column to an aggregate of
   itself - `WHERE start > (SELECT MAX(start) ...)` cannot return a row, and
   an empty result from a query that could not have returned one tells you
   nothing at all.

2. Rows came back? The claim is WRONG. One more query and then stop - the
   count, because the query above had a LIMIT on it and the number of rows it
   handed you is that limit, not the population:

       SELECT COUNT(*) FROM <the same table> WHERE <the same conditions>

   Then quote two or three of the rows, with the table and that count, and
   stop. Do not keep querying to soften it.

3. Nothing came back? Then you are not finished, because an empty result is
   the answer this job gets wrong. Before you say it stands, run these:

   a. Is the table there at all? case_tables. An empty or absent table means
      the collector never ran that artifact, and "no evidence" from a
      collection that never looked is UNSUPPORTED, not STANDS.
   b. Is the value right? case_values on every column you filtered on. A
      column that only holds 'FAILED LOGIN' returns nothing for 'failure'.
      The empty result you were shown lists these for you - read it.
   c. Does the triage disagree? case_findings. If a finding says the opposite
      of your empty query, trust the finding and go and read its rows: your
      query is wrong.
   d. Is it in another table? The same fact is in more than one. A sign-in is
      in AUTH_LOG, LOGINS, LOGIN_RECORDS and USERS.last_login_utc.

4. Give one verdict, and put the evidence in the same sentence. These are
   the shapes to fill in from YOUR results - the counts and the times below
   are blanks, not values, and copying them back is reporting a number you
   never queried:

     WRONG        - wrong: <TABLE> has <COUNT> rows matching <THE FILTER>,
                    the earliest at <TIMESTAMP FROM YOUR RESULT>
     STANDS       - stands: <TABLE> has <TOTAL> rows and none of them
                    <WHAT THE CLAIM SAYS CANNOT BE THERE>
     UNSUPPORTED  - unsupported: this collection has no <TABLE>, so nothing
                    here can settle it

   A verdict on its own is not an answer. If you cannot put a table and a
   number from your own results next to it, you have not established it and
   the verdict is UNSUPPORTED.

Do not hedge into agreement, and do not state a value - an address, a user, a
time - that did not appear in a result above. A claim you could not break
after genuinely trying is worth stating plainly, and that is only true if you
tried."""},

    {"name": "collection_quality",
     "title": "What this collection cannot tell you",
     "about": "The holes: what the collector missed, and what that costs.",
     "args": (),
     "tables": ("COLLECTION_ERRORS", "COLLECTION_LOG", "UNPARSED_FILES",
                "SIGMA_COVERAGE", "LOG_INVENTORY", "FILE_INVENTORY"),
     "plan": """Establish the limits of this evidence before anyone relies on it.

Every answer from this case is bounded by what the collector managed to read,
and that boundary is almost never stated. State it.

1. What failed outright:
       SELECT * FROM COLLECTION_ERRORS
   A permission denied on /root or /var/log is not a detail. It means every
   answer about that path is "unknown", not "clean".

2. What was collected but not parsed:
       SELECT * FROM UNPARSED_FILES LIMIT 50
   These are files linsight held and could not turn into rows. They may still
   be readable by hand and they are invisible to every query you have run.

3. Which tables are empty, and what each of them would have answered.
   case_tables gives the row counts; the empty ones are the map of the blind
   spots. For each, name the question that now cannot be answered - no
   AUDIT_LOG means process execution is only known from history and ps, no
   BODYFILE means file timestamps are only known for the files that were
   copied.

4. How far back the logs go:
       SELECT MIN(timestamp_utc), MAX(timestamp_utc) FROM AUTH_LOG
   and the same for WEB_LOG and JOURNAL. Rotation is the most common reason an
   intrusion appears to start on a Monday. If the earliest log entry is close
   to the earliest suspicious event, the start of the intrusion is very
   probably before the evidence.

5. SIGMA_COVERAGE, if present: which rules could run against which tables. A
   rule that never ran is not a rule that found nothing.

Write this as a list an analyst can put at the front of a report: what is
known, what is unknown, and which of the unknowns are worth going back to the
host for."""},
)

SKILL_BY_NAME = dict((s["name"], s) for s in SKILLS)


# Prepended to every rendered playbook, and it is not decoration. Handed the
# ten-step challenge plan, llama3.1:8b wrote the whole thing back out - each
# step, each query in a fenced JSON block, a verdict at the bottom - without
# calling a single tool. It had understood the method perfectly and executed
# none of it. A numbered plan reads as something to transcribe unless it says
# otherwise, so it says otherwise, first, before the model has read far enough
# to start copying.
HOW = """Run this plan. Do not write it out.

Make ONE tool call now - the first step below - and stop. You will be sent the
rows it returns, and then you take the next step. Work through it that way,
one call at a time, until you have what the last step asks for.

The SQL in this plan is for you to run through case_query, not to repeat back.
A step you write out as text has not been done, and a message with no tool call
in it ends the investigation and is shown to the analyst as your answer.

Adapt it where the case needs it. It names the tables and the joins because
those are what a schema alone does not tell you - the column names are real,
the values in them may not be what you assume.

Every number, address, username and timestamp in your answer must come from a
result you were sent back. Nothing in this plan is data: where it shows the
shape of an answer, the values in it are blanks to fill from your own rows.
Copying one back is reporting a figure you never queried."""


# ---------------------------------------------------------------- rendering

def available(db):
    """Every skill, with the tables this case actually has for it.

    Nothing is hidden on the grounds of a missing table. A host with no
    WEB_LOG can still be asked about web intrusion, and the honest answer is
    that the collection has no web logs - which is a result, and one an
    examiner needs said out loud rather than inferred from a greyed-out
    button.
    """
    known = _tables(db) if db is not None else {}
    out = []
    for s in SKILLS:
        out.append({"name": s["name"], "title": s["title"],
                    "about": s["about"],
                    "args": [{"name": a, "description": d, "required": r}
                             for a, d, r in s["args"]],
                    "has": [t for t in s["tables"] if known.get(t)],
                    "missing": [t for t in s["tables"] if not known.get(t)]})
    return out


def render(name, db, args=None):
    """One playbook, filled in and grounded in this case."""
    skill = SKILL_BY_NAME.get(name)
    if skill is None:
        raise CaseError("no skill called %r. They are: %s"
                        % (name, ", ".join(sorted(SKILL_BY_NAME))))
    missing = [a for a, _d, req in skill["args"]
               if req and not str((args or {}).get(a) or "").strip()]
    if missing:
        raise CaseError("%s needs %s. Ask the analyst for it rather than "
                        "picking one." % (name, " and ".join(missing)))

    known = _tables(db) if db is not None else {}
    body = [HOW, "", _fill(skill["plan"], args)]

    named = list(skill["tables"])
    have = [t for t in named if known.get(t)]
    empty = [t for t in named if t in known and not known.get(t)]
    absent = [t for t in named if t not in known]
    if named:
        body.append("")
        body.append("In this case: " + (
            "%s %s rows." % (", ".join(have),
                             "has" if len(have) == 1 else "have") if have
            else "none of the tables this playbook names have rows."))
        if empty:
            body.append("Present but empty, so the collector produced nothing "
                        "for them: " + ", ".join(empty) + ". Do not report "
                        "their emptiness as a finding about the host.")
        if absent:
            body.append("Not in this case at all - do not query them: "
                        + ", ".join(absent) + ".")
    return chr(10).join(body)


# ---------------------------------------------------------------- the tool
#
# Registered here rather than in mcp.py because of the build: skills sits
# after mcp in dependency order, so mcp cannot name t_skill at module level.
# Both consumers reach it through all_tools() instead.

def t_skill(db, args):
    """Fetch a playbook, or the list of them.

    A small model reaches this when the analyst asked something broad. Handing
    it the method costs one turn and saves the four it would otherwise spend
    querying FINDINGS from three angles.
    """
    name = str(args.get("name") or "").strip()
    if not name:
        return {"skills": [{"name": s["name"], "title": s["title"],
                            "about": s["about"],
                            "needs": [a for a, _d, r in s["args"] if r]}
                           for s in SKILLS],
                "note": "call case_skill again with one of these names to get "
                        "the playbook, then follow it with the other tools"}
    extra = dict((k, v) for k, v in args.items() if k != "name")
    return {"skill": name, "playbook": render(name, db, extra)}


SKILL_TOOL = (
    "case_skill",
    "An investigative playbook: the sequence an examiner follows for a kind "
    "of question, with the tables and the joins named. Call it with no "
    "arguments to see what there is, then by name to get the method. Use it "
    "whenever the question is broad ('what happened here', 'is this host "
    "compromised') rather than a single lookup.",
    {"type": "object",
     "properties": {
         "name": {"type": "string",
                  "description": "the playbook, e.g. triage_host, "
                                 "profile_address, persistence, challenge. "
                                 "Omit to list them."},
         "address": {"type": "string",
                     "description": "for profile_address"},
         "user": {"type": "string", "description": "for profile_user"},
         "when": {"type": "string",
                  "description": "for intrusion_window, a UTC timestamp"},
         "claim": {"type": "string", "description": "for challenge"}}},
    t_skill)


def all_tools():
    """The case tools plus the playbooks, which is what both callers want."""
    return list(TOOLS) + [SKILL_TOOL]
