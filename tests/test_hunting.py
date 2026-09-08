#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Test what the tool-name sweep will and will not call a tool.

    python tests/test_hunting.py            # against src/linsight
    python tests/test_hunting.py --built    # against the built linsight.py

Half the offensive toolkit is named after ordinary things - john, empire,
beacon, nmap, hydra, quasar, cdk - and a host that has never been touched is
full of those words. The sweep's ambiguous tier exists for exactly that, and
the rule it had was 'match these only in a command line or a path, where the
word is naming something executable'. It is not, and that is what this suite
is about:

  /home/john/notes.txt      a path, and the word is an account
  ssh john@db01             a command, and the word is an account
  node_modules/quasar       a path, and the word is a Vue framework
  /srv/app/cdk.json         a path, and the word is a file that is read
  engines-1.1/gost.so       a path, and the word is a cipher standard
  /usr/share/nmap/*.nse     a path, and the word is the distribution's

Every one of those was a CRITICAL or HIGH finding, on a host where nothing had
happened. So the test is not 'is this a path' but 'is this the thing being
run, or the file being named', and the checks below are in two halves that
have to hold together:

  the false ones must go     or the findings list is noise and gets ignored
  the true ones must stay    or the suppression is not a filter, it is a
                             blindfold - and the failure mode is silent

The second half is the one worth having. A password cracker sitting in the
home directory of the account it is named after is precisely what this sweep
exists to find, and 'anything under /home/john is john the account' would
throw it away. So /home/john/john is asserted to survive, beside the
/home/john/notes.txt that must not.
"""

import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

#: The host: an account called john, a Ghost CMS account, a node application.
#: Every name here collides with something in the tool lists, and only three
#: of the files are actually a tool.
PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "john:x:1000:1000:John Smith:/home/john:/bin/bash\n"
    "ghost:x:997:997:Ghost CMS:/var/lib/ghost:/usr/sbin/nologin\n"
    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
)

HISTORY = (
    "sudo john -w rockyou shadow\n"       # the cracker, run
    "nmap -sS 10.0.0.0/24\n"              # the scanner, run
    "ls /home/john\n"                     # an account's home, listed
    "ssh john@db01\n"                     # an account, connected as
    "cat /home/john/notes.txt\n"          # an account's file, read
)

FILES = (
    # (path under the root, what it is)
    ("etc/passwd", PASSWD),
    ("etc/crontab", "* * * * * root /opt/empire/empire --headless\n"),
    ("home/john/.bash_history", HISTORY),
    ("home/john/notes.txt", "the migration notes\n"),
    ("home/john/john", "#!/bin/sh\n"),                     # a tool, in his home
    ("root/linpeas.sh", "#!/bin/sh\n"),                    # a tool
    ("tmp/masscan", "#!/bin/sh\n"),                        # a tool
    ("tmp/pupy/pupysh.py", "#!/usr/bin/env python\n"),     # a tool
    ("usr/local/bin/hydra", "#!/bin/sh\n"),                # a tool
    ("opt/empire/empire", "#!/bin/sh\n"),                  # a tool
    ("srv/app/cdk.json", "{}\n"),                          # AWS CDK
    ("var/www/app/node_modules/quasar/dist/quasar.js", "// vue\n"),
    ("var/lib/ghost/content/themes/package.json", "{}\n"),
    ("usr/share/nmap/scripts/http-enum.nse", "-- nse\n"),
    ("var/log/syslog", "Dec  5 06:26:02 h app: beacon received from monitor\n"),
    # GOST is a Russian cryptographic standard before it is a Go tunnel, and
    # an OpenSSL build that supports it ships every one of these
    ("usr/lib/x86_64-linux-gnu/engines-1.1/gost.so", "ELF\n"),
    ("usr/lib64/engines-3/gost.so", "ELF\n"),
    ("etc/ssl/gost.cnf", "[gost_section]\n"),
    ("usr/local/bin/gost", "#!/bin/sh\n"),              # and this is the tunnel
)

#: What has to be reported, and at what strength. The severity matters as
#: much as the presence: a tool in a distribution-owned path is a different
#: statement from the same name in /tmp, and both are different from an
#: account.
MUST_FIND = (
    ("john", "sudo john -w rockyou shadow", "CRITICAL"),
    ("john", "/home/john/john", "CRITICAL"),
    ("nmap", "nmap -sS 10.0.0.0/24", "HIGH"),
    ("hydra", "/usr/local/bin/hydra", "CRITICAL"),
    ("empire", "/opt/empire/empire", "CRITICAL"),
    ("empire", "/opt/empire/empire --headless", "CRITICAL"),
    ("linpeas", "/root/linpeas.sh", "HIGH"),
    ("masscan", "/tmp/masscan", "HIGH"),
    ("pupy", "/tmp/pupy/pupysh.py", "CRITICAL"),
    ("gost", "/usr/local/bin/gost", "CRITICAL"),
)

#: What must raise no finding at all. Each is a real thing on a real host.
MUST_NOT_FIND = (
    ("john", "/home/john/notes.txt", "an account's file"),
    ("john", "/home/john/.bash_history", "an account's file"),
    ("john", "ssh john@db01", "an account, connected as"),
    ("john", "cat /home/john/notes.txt", "an account's file, read"),
    ("quasar", "node_modules", "a dependency directory"),
    ("cdk", "cdk.json", "an AWS CDK project file"),
    ("nmap", "http-enum.nse", "the distribution's own nmap"),
    ("beacon", "beacon received", "a word in a log line"),
    ("gost", "engines-1.1/gost.so", "the OpenSSL GOST engine"),
    ("gost", "engines-3/gost.so", "the same engine, on an RPM distribution"),
    ("gost", "/etc/ssl/gost.cnf", "that engine's own configuration"),
)


def load(built):
    """The package, or the built single file, as one flat namespace."""
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
    import linsight.collect, linsight.common, linsight.tables, linsight.triage

    class Flat(object):
        pass

    flat = Flat()
    for mod in (linsight.common, linsight.collect, linsight.tables,
                linsight.triage):
        for name in dir(mod):
            if not name.startswith("__"):
                setattr(flat, name, getattr(mod, name))
    return flat


def write_root(path):
    for name, data in FILES:
        full = os.path.join(path, name.replace("/", os.sep))
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8") as fh:
            fh.write(data)
    return path


class Opts(object):
    """The handful of flags the table build reads, and nothing else."""
    quiet = True
    debug = False
    scope = "full"
    sigma = None
    keywords = None
    no_hunt = False
    pivot = None
    hash_algos = ()


def sweep(L, root):
    """Every HACKTOOL_HITS row this host produces, as dicts."""
    col = L.Collection(root)
    tri = L.Triage(col, Opts())
    tri.run()
    tb = L.TableBuilder(col, tri)
    tb.build(verbose=False)
    hits = [t for t in tb.tables if t.name == "HACKTOOL_HITS"]
    if not hits:
        return [], tri
    cols = hits[0].columns
    return [dict(zip(cols, r)) for r in hits[0].iter_rows()], tri


class Result(object):
    def __init__(self):
        self.passed = 0
        self.failed = []

    def check(self, what, cond, why="did not hold"):
        if cond:
            self.passed += 1
            print("  [ok] %s" % what)
        else:
            self.failed.append((what, why))
            print("  [!!] %s: %s" % (what, why))


# ---------------------------------------------------------------------------
# checks
# ---------------------------------------------------------------------------

def check_position(L, res):
    """The rule itself, before any collection is built."""
    print("\nwhere a name has to sit before it is naming a tool")
    cases = (
        # (cell, name, kind, is it naming something to run)
        ("/home/john/notes.txt", "john", "path", False),
        ("/home/john/john", "john", "path", True),
        ("/tmp/john", "john", "path", True),
        ("/usr/local/bin/nmap-7.94", "nmap", "path", True),
        ("john --wordlist=x", "john", "command", True),
        ("sudo john -w rockyou", "john", "command", True),
        ("./nmap -sS", "nmap", "command", True),
        ("cat /etc/x; john -w", "john", "command", True),
        ("ssh john@db01", "john", "command", False),
        ("cat /home/john/x.txt", "john", "command", False),
        ("grep empire /var/log/x", "empire", "command", False),
        ("/var/www/empire-blog/index.php", "empire", "path", False),
        ("openssl ciphers GOST2001-GOST89", "gost", "command", False),
        ("/usr/local/bin/gost -L=:8080", "gost", "command", True),
    )
    for text, name, kind, want in cases:
        low = text.lower()
        # the last occurrence, which is what finditer reaches: a rejected
        # directory must not stop the basename behind it being found
        i = low.rfind(name)
        got = L.executable_position(low, i, i + len(name), kind)
        res.check("%-32s %-7s -> %s" % (text, name, "tool" if want else "word"),
                  got == want, "returned %s" % got)
    res.check("a dependency directory is recognised anywhere in a path",
              L.in_library_dir("/var/www/app/node_modules/quasar/dist/q.js")
              and not L.in_library_dir("/tmp/quasar"))
    print("\n  and whether the file it names is a program or something read")
    for name, want in (("/usr/local/bin/gost", True),        # a program
                       ("/usr/local/bin/nmap-7.94", True),   # a version is not
                       ("/opt/empire/empire.py", True),      # a script
                       ("/mod/quasar.ko", True),             # a module
                       ("/usr/lib/engines-1.1/gost.so", False),   # a library
                       ("/srv/app/cdk.json", False),              # a config
                       ("/app/quasar.conf.js", False),            # a config
                       ("/static/beacon.min.js", False),          # a script
                       ("/home/x/john.txt", False)):              # a document
        res.check("%-32s %s" % (name, "program" if want else "read, not run"),
                  L.program_suffix(name) == want)


def check_true_positives(L, rows, res):
    """Everything that is a tool is still reported, at its own strength."""
    print("\nthe tools, which all have to survive the filtering")
    for tool, detail, sev in MUST_FIND:
        got = [r for r in rows if r["tool"] == tool and detail in r["detail"]]
        res.check("%-8s %s" % (tool, detail),
                  bool(got) and got[0]["severity"] == sev,
                  "not reported" if not got
                  else "reported %s, wanted %s" % (got[0]["severity"], sev))


def check_false_positives(L, rows, tri, res):
    """And nothing that is not one raises a finding."""
    print("\nthe ordinary host, which has to raise nothing")
    loud = [r for r in rows
            if r["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")]
    for tool, detail, what in MUST_NOT_FIND:
        bad = [r for r in loud if r["tool"] == tool and detail in r["detail"]]
        res.check("%-8s %-24s (%s)" % (tool, detail, what), not bad,
                  "reported %s: %s" % (bad[0]["severity"], bad[0]["detail"])
                  if bad else "")
    titles = [f.title for f in tri.findings]
    for tool in ("quasar", "cdk"):
        res.check("no finding is raised for %s at all" % tool,
                  not [t for t in titles if tool in t.lower()])


def check_visible(L, rows, res):
    """A suppressed hit is demoted and says why, rather than vanishing."""
    print("\nwhat was suppressed, and whether it says so")
    home = [r for r in rows if r["tool"] == "john"
            and r["detail"].strip() == "ls /home/john"]
    res.check("the account's own home is still in HACKTOOL_HITS", bool(home))
    if home:
        res.check("at INFO", home[0]["severity"] == "INFO",
                  "was %s" % home[0]["severity"])
        res.check("saying an account of that name explains it",
                  "account" in home[0]["context"],
                  "context reads %r" % home[0]["context"])


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--built", action="store_true",
                    help="test the built linsight.py instead of src/linsight")
    opts = ap.parse_args()
    L = load(opts.built)

    import tempfile
    res = Result()
    tmp = tempfile.mkdtemp(prefix="linsight-hunt-")
    print("host: %s" % tmp)
    root = write_root(os.path.join(tmp, "root"))

    check_position(L, res)
    rows, tri = sweep(L, root)
    check_true_positives(L, rows, res)
    check_false_positives(L, rows, tri, res)
    check_visible(L, rows, res)

    print("\n%d passed, %d failed" % (res.passed, len(res.failed)))
    if res.failed:
        print("\nfailures:")
        for what, why in res.failed:
            print("  %s: %s" % (what, why))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
