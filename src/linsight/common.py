# -*- coding: utf-8 -*-
from __future__ import annotations

from datetime import datetime
from datetime import timedelta
from datetime import timezone
import ipaddress
import re

from .term import trunc



# ---------------------------------------------------------------------------
# shared knowledge / heuristics
# ---------------------------------------------------------------------------

TMPFS_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/", "/dev/mqueue/")
SYSTEM_BIN_DIRS = ("/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/local/bin/",
                   "/usr/local/sbin/", "/usr/lib/", "/lib/", "/lib64/", "/usr/lib64/")
SYSTEM_CFG_DIRS = ("/etc/", "/boot/", "/usr/lib/systemd/", "/lib/systemd/")

# ports commonly used by implants / handlers
SUSPICIOUS_PORTS = {
    23: "telnet", 1080: "socks proxy", 1337: "common backdoor", 2323: "telnet alt",
    3333: "common backdoor/miner", 4444: "metasploit default", 4445: "metasploit alt",
    5555: "common backdoor/adb", 6666: "IRC bot / backdoor", 6667: "IRC",
    7777: "common backdoor", 8888: "common backdoor/proxy", 9001: "tor / backdoor",
    9050: "tor socks", 9051: "tor control", 12345: "netbus/backdoor",
    31337: "elite/backdoor", 54321: "backdoor", 14444: "miner pool",
    3332: "miner pool", 5900: "vnc",
}

# baseline of SUID/SGID binaries shipped by mainstream Linux distributions
BASELINE_SUID = {
    "/usr/bin/sudo", "/usr/bin/su", "/usr/bin/passwd", "/usr/bin/gpasswd",
    "/usr/bin/chfn", "/usr/bin/chsh", "/usr/bin/newgrp", "/usr/bin/mount",
    "/usr/bin/umount", "/usr/bin/pkexec", "/usr/bin/fusermount", "/usr/bin/fusermount3",
    "/usr/bin/ntfs-3g", "/usr/bin/at", "/usr/bin/crontab", "/usr/bin/expiry",
    "/usr/bin/chage", "/usr/bin/wall", "/usr/bin/write", "/usr/bin/screen",
    "/usr/bin/dotlockfile", "/usr/bin/ssh-agent", "/usr/bin/bwrap",
    "/usr/bin/vmware-user-suid-wrapper", "/usr/bin/staprun", "/usr/bin/mount.nfs",
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper", "/usr/lib/xorg/Xorg.wrap",
    "/usr/lib/openssh/ssh-keysign", "/usr/lib/polkit-1/polkit-agent-helper-1",
    "/usr/lib/eject/dmcrypt-get-device", "/usr/lib/snapd/snap-confine",
    "/usr/lib/x86_64-linux-gnu/utempter/utempter",
    "/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic",
    "/usr/libexec/camel-lock-helper-1.2", "/usr/libexec/dbus-1/dbus-daemon-launch-helper",
    "/usr/libexec/openssh/ssh-keysign", "/usr/libexec/polkit-agent-helper-1",
    "/usr/libexec/utempter/utempter", "/usr/libexec/spice-gtk-x86_64/spice-client-glib-usb-acl-helper",
    "/usr/sbin/pppd", "/usr/sbin/unix_chkpwd", "/usr/sbin/mount.nfs",
    "/usr/sbin/pam_timestamp_check", "/usr/sbin/usernetctl", "/usr/sbin/exim4",
    "/usr/sbin/postdrop", "/usr/sbin/postqueue", "/usr/sbin/grub2-set-bootflag",
    "/bin/su", "/bin/mount", "/bin/umount", "/bin/ping", "/bin/ping6",
    "/bin/fusermount", "/sbin/unix_chkpwd", "/sbin/mount.nfs", "/sbin/pam_timestamp_check",
    "/usr/bin/ping", "/usr/bin/ping6", "/usr/bin/traceroute6.iputils",
    "/usr/bin/arping", "/usr/bin/mtr-packet", "/usr/bin/kismet_cap_linux_bluetooth",
}

# interpreters / living-off-the-land binaries that must never be SUID
DANGEROUS_SUID_NAMES = {
    "bash", "sh", "dash", "zsh", "ksh", "csh", "tcsh", "python", "python2",
    "python3", "perl", "ruby", "php", "lua", "node", "awk", "gawk", "mawk",
    "find", "vim", "vi", "nano", "emacs", "less", "more", "man", "cp", "mv",
    "dd", "tar", "zip", "unzip", "rsync", "nmap", "env", "docker", "systemctl",
    "openssl", "socat", "nc", "ncat", "netcat", "busybox", "strace", "gdb",
}

# command fragments that are interesting in cron jobs, units, histories
SUSPICIOUS_CMD_PATTERNS = [
    (r"/dev/tcp/", "bash reverse shell primitive", "HIGH"),
    (r"\bnc\b\s+(-[a-z]*e|.*\s-e\b)", "netcat with -e (reverse shell)", "CRITICAL"),
    (r"\b(ncat|netcat|socat)\b", "netcat/socat usage", "HIGH"),
    (r"\bbash\s+-i\b", "interactive shell spawn", "HIGH"),
    (r"base64\s+(-d|--decode)", "base64 decoding of payload", "HIGH"),
    (r"\becho\s+[A-Za-z0-9+/=]{40,}", "long encoded blob", "HIGH"),
    (r"(curl|wget)[^|;\n]*\|\s*(ba)?sh", "download piped to shell", "CRITICAL"),
    (r"\b(curl|wget)\b", "remote download", "MEDIUM"),
    (r"python[0-9.]*\s+-c\b", "inline python", "HIGH"),
    (r"perl\s+-e\b", "inline perl", "HIGH"),
    # only the modes that matter: +x, world-writable 777, and setuid/setgid.
    # 0755/0700 appear all over stock init scripts.
    (r"\bchmod\s+(-R\s+)?(\+x|a\+x|u\+s|g\+s|0?777|[24][0-7]{3})\b",
     "granting execute / world-write / setuid", "MEDIUM"),
    (r"\bchattr\s+[+-]i\b", "immutable attribute change", "HIGH"),
    (r"history\s+-c|>\s*~?/?\.bash_history|unset\s+HISTFILE|HISTFILE=/dev/null",
     "shell history tampering", "HIGH"),
    (r"\bshred\b|\bwipe\b|\bsrm\b", "secure deletion utility", "HIGH"),
    (r"\bcrontab\s+-r\b", "crontab wipe", "HIGH"),
    (r"\b(setenforce\s+0|systemctl\s+(stop|disable|mask)\s+(auditd|rsyslog|firewalld|ufw))",
     "security control disabled", "HIGH"),
    (r"iptables\s+-F|nft\s+flush", "firewall rules flushed", "HIGH"),
    (r"\bldd\b.*ld\.so\.preload|ld\.so\.preload", "LD_PRELOAD persistence", "CRITICAL"),
    (r"LD_PRELOAD=", "LD_PRELOAD injection", "CRITICAL"),
    (r"\binsmod\b|\bmodprobe\b\s+[^-]", "kernel module load", "MEDIUM"),
    (r"\bxmrig\b|stratum\+tcp|\bminerd\b|cryptonight", "cryptominer indicator", "CRITICAL"),
    (r"\.onion\b|\btor2web\b|\bngrok\b|\bpastebin\.com\b|\btransfer\.sh\b",
     "anonymising / paste service", "HIGH"),
    # a temp path only matters when it is being *run*; distro scripts mention
    # /tmp constantly in tests and variable assignments
    (r"(?:^|[;&|`]\s*|\$\(\s*|\b(?:exec|source|\.|sh|bash|dash|zsh|sudo|nohup|setsid|python[0-9.]*|perl)\s+)"
     r"(?:/tmp/|/var/tmp/|/dev/shm/|/run/shm/)\S+",
     "execution from a world-writable dir", "HIGH"),
    (r"\bnohup\b.*&|\bsetsid\b|\bdisown\b", "detached background execution", "MEDIUM"),
    (r"\bssh\b.*-[fNL]\s|-R\s+\d+:", "ssh tunnel / port forward", "HIGH"),
    (r"\bsshpass\b", "non-interactive ssh password use", "HIGH"),
    (r"\buseradd\b|\badduser\b|\busermod\b.*-G", "account manipulation", "HIGH"),
    (r"authorized_keys", "ssh key persistence", "HIGH"),
]
COMPILED_CMD_PATTERNS = [(re.compile(p, re.I), d, s) for p, d, s in SUSPICIOUS_CMD_PATTERNS]

# Named offensive tooling, by what its presence would mean. ROOTKIT_NAMES below
# covers kernel implants; this covers the userland toolkit an operator brings.
#
# Split into two tiers on purpose. UNAMBIGUOUS names are not words anyone uses
# for anything else, so a hit anywhere - a log line, a filename, a package - is
# worth reporting. AMBIGUOUS names are ordinary English or common binaries
# ('john', 'empire', 'beacon', 'havoc', 'sliver'), and matching those in free
# log text produces noise, not findings; they are only ever matched in a
# command line or a path, where the word is naming something executable.
HACKTOOL_UNAMBIGUOUS = {
    "credential access": [
        "mimikatz", "mimipenguin", "mimidump", "lazagne", "secretsdump",
        "gosecretsdump", "hashdump", "pypykatz", "kerberoast", "asreproast",
        "dumpert", "nanodump", "procdump", "keethief", "lsassy", "hekatomb",
        "certipy", "gettgtpkinit", "krbrelayx", "ticketer", "getnpusers",
        "getuserspns", "dcsync", "ntdsutil", "ntds.dit", "creddump7",
        "chntpw", "unshadow", "hashcat", "johntheripper",
    ],
    "privilege escalation enumeration": [
        "linpeas", "winpeas", "linenum", "lse.sh", "linux-smart-enumeration",
        "unix-privesc-check", "linux-exploit-suggester", "les.sh", "pspy",
        "gtfoblookup", "beroot", "privesccheck", "suid3num", "traitor",
        "sudo_killer", "sudokiller",
    ],
    "active directory attack": [
        "bloodhound", "sharphound", "azurehound", "rusthound", "soaphound",
        "crackmapexec", "netexec", "smbmap", "smbexec", "wmiexec", "psexec",
        "atexec", "dcomexec", "evil-winrm", "kerbrute", "rubeus", "impacket",
        "responder", "ntlmrelayx", "mitm6", "petitpotam", "printnightmare",
        "zerologon", "noPac", "adidnsdump", "windapsearch", "ldapdomaindump",
    ],
    "command and control": [
        "meterpreter", "msfvenom", "msfconsole", "metasploit", "cobaltstrike",
        "cobalt strike", "teamserver", "beacon.dll", "sliver-client",
        "sliver-server", "mythic", "poshc2", "covenant", "brute ratel",
        "bruteratel", "havoc-client", "merlin", "koadic", "pupy", "villain",
        "hoaxshell", "chisel", "ligolo", "revsocks", "gost", "frpc", "frps",
        "sshuttle", "ngrok", "cloudflared tunnel", "pivotnacci", "reGeorg",
        "neo-regeorg", "tunna",
    ],
    "scanning and exploitation": [
        "masscan", "zmap", "nuclei", "gobuster", "feroxbuster", "dirbuster",
        "wfuzz", "sqlmap", "nikto", "wpscan", "joomscan", "commix", "xsstrike",
        "searchsploit", "exploitdb", "routersploit", "arachni", "whatweb",
        "enum4linux", "smbclient -N", "onesixtyone", "snmpwalk -c public",
    ],
    "webshell": [
        "c99shell", "r57shell", "b374k", "weevely", "wso shell", "antsword",
        "behinder", "godzilla webshell", "chinachopper", "china chopper",
        "phpspy", "wsomanager", "indoxploit", "alfashell", "marijuana shell",
    ],
    "cryptomining": [
        "xmrig", "minerd", "cpuminer", "nbminer", "phoenixminer", "ethminer",
        "lolminer", "t-rex miner", "nanominer", "xmr-stak", "cgminer",
    ],
    "container escape": [
        "deepce", "amicontained", "cdk-team", "botb ", "break-out-the-box",
        "kubeletctl", "peirates",
    ],
    "exfiltration staging": [
        "rclone copy", "megatools", "transfer.sh", "filebin", "0x0.st",
        "termbin", "oshi.at",
    ],
}
# ordinary words that are also tool names - command/path context only
HACKTOOL_AMBIGUOUS = {
    "credential access": ["john", "hydra", "medusa", "patator", "crowbar",
                          "cewl", "ophcrack"],
    "active directory attack": ["certify", "seatbelt", "sharpview"],
    "command and control": ["empire", "sliver", "havoc", "merlin", "beacon",
                            "silenttrinity", "quasar"],
    "scanning and exploitation": ["nmap", "dirb", "ffuf", "amass", "subfinder",
                                  "arjun", "dalfox"],
    "container escape": ["cdk"],
}


def trie_pattern(terms):
    r"""Many literals as one prefix-tree regex, rather than one alternation.

    'a|ab|ac' makes the engine try every branch at every position. Python's re
    does not factor common prefixes, so a hundred indicators is a hundred
    attempts per character - and the indicators an examination produces share
    prefixes heavily, because they are mostly addresses off the same handful
    of subnets and paths under the same handful of directories.

    Folding them into 10\.198\.(?:11\.(?:107|200)|136\.103) means the engine
    fails the whole group on the first character that does not match, which is
    what makes scanning gigabytes with a large indicator list practical rather
    than theoretical.
    """
    root = {}
    for term in terms:
        node = root
        for ch in term:
            node = node.setdefault(ch, {})
        node[""] = {}                     # end of a term
    return _trie_regex(root)


def _trie_regex(node):
    if not node:
        return ""
    if list(node) == [""]:
        return ""
    alts, optional = [], False
    for ch in sorted(node):
        if ch == "":
            optional = True
            continue
        rest = _trie_regex(node[ch])
        alts.append(re.escape(ch) + rest)
    if not alts:
        return ""
    if len(alts) == 1:
        body = alts[0]
        # a single continuation needs no group unless it is optional
        return ("(?:%s)?" % body) if optional else body
    body = "(?:%s)" % "|".join(alts)
    return body + "?" if optional else body


def _trie_alt(names):
    """One alternation, factored so a shared prefix is scanned once.

    A flat 'a|b|c' of 169 names makes the engine try each branch in turn at
    every position of every log line, and the names overlap heavily -
    'lazagne', 'linpeas', 'linenum' each re-scan 'l'. Factoring them into a
    trie turns that into a single walk: 'l(?:azagne|inpeas|inenum)'. Same
    language, same leftmost match, measured 2.8x faster over this collection's
    log text - which is the whole cost of the sweep, since it is bytes scanned
    and not names listed that drives it.

    Longest-wins is preserved without sorting by length. Where one name is a
    prefix of another the tail is made optional, and the regex engine is
    greedy, so 'nmap(?:-ng)?' still prefers 'nmap-ng' where both could match.
    """
    root = {}
    for w in names:
        node = root
        for ch in w:
            node = node.setdefault(ch, {})
        node[""] = True                       # a name ends here

    def render(node):
        if len(node) == 1 and "" in node:
            return ""                         # leaf: nothing left to match
        alts = []
        optional = False
        for ch in sorted(node):
            if ch == "":
                optional = True               # a shorter name stops here
                continue
            alts.append(re.escape(ch) + render(node[ch]))
        if len(alts) == 1:
            # '(?:...)?' round the whole tail, never 'xy?' - that would make
            # only the last character optional and quietly match 'x' alone
            return "(?:%s)?" % alts[0] if optional else alts[0]
        body = "(?:%s)" % "|".join(alts)
        return body + "?" if optional else body

    return render(root)


def _tool_regex(groups, loose=False):
    """One alternation for the whole tier, so a cell costs a single pass.

    This is what the function always claimed to do and did not: it compiled one
    alternation *per category*, so every cell was scanned nine times for the
    unambiguous tier and five for the ambiguous one. Nine passes over a web
    server's three million log rows is 213 seconds to produce 38 findings -
    over half the entire run. The cost driver is the number of cells, never the
    number of tool names, which is the same lesson --pivot already learned when
    it compiled 400 indicators into one alternation.

    Returns (regex, name -> category), because the category can no longer come
    from which pattern matched.
    """
    cats = {}
    for cat, names in groups.items():
        for n in names:
            cats.setdefault(n.lower(), cat)
    alt = _trie_alt(cats)
    # Case-sensitive against already-lowercased names, with the caller
    # lowercasing the cell once. re.I is not a free flag: it case-folds at
    # every position of every alternative, and measured on this collection's
    # log lines it costs 78us per line against 19us for one str.lower() plus a
    # case-sensitive scan - the single biggest cost in the whole run.
    #
    # not preceded/followed by a word character, so 'john' does not fire on
    # 'johnson' and 'cdk' does not fire on 'cdkit'; a leading '/' or '-' is
    # fine because that is how these appear in paths and argv
    if loose:
        # The same rule, relaxed for the one place it was wrong: a filename.
        # '_' is a word character, so the strict form cannot see the tool in
        # 'mimikatz_name.zip' - and a downloaded tool is named exactly like
        # that, or 'linpeas_linux_amd64', or 'nmap-7.94.tar.gz'. Only a letter
        # may not follow, which still stops 'johnson' and 'cdkit', while an
        # underscore, a hyphen, a dot or a version number may.
        return re.compile(r"(?<![A-Za-z0-9])(%s)(?![A-Za-z])" % alt), cats
    return re.compile(r"(?<![\w.])(%s)(?![\w-])" % alt), cats


HACKTOOL_RE, HACKTOOL_CAT = _tool_regex(HACKTOOL_UNAMBIGUOUS)
HACKTOOL_CTX_RE, HACKTOOL_CTX_CAT = _tool_regex(HACKTOOL_AMBIGUOUS)
# The unambiguous names again, with filename punctuation allowed around them.
# Used where the cell is a path or a command line - somewhere a filename can
# legitimately be - and never on free log text, where the strict form is what
# keeps an ordinary sentence from firing. The ambiguous tier never gets this:
# 'nmap' and 'john' are words, and loosening their boundaries in a path is how
# a wordlist directory becomes a page of findings.
HACKTOOL_PATH_RE, HACKTOOL_PATH_CAT = _tool_regex(HACKTOOL_UNAMBIGUOUS,
                                                  loose=True)
# how bad a name is, before the context it was found in is considered
HACKTOOL_SEVERITY = {
    "credential access": "CRITICAL", "active directory attack": "HIGH",
    "command and control": "CRITICAL", "privilege escalation enumeration": "HIGH",
    "scanning and exploitation": "HIGH", "webshell": "CRITICAL",
    "cryptomining": "CRITICAL", "container escape": "HIGH",
    "exfiltration staging": "HIGH",
}

#: A word boundary for filenames. '_' counts as a word character to , which
#: is why 'db_secrets.txt' does not match secrets - so a separator, a
#: digit or a path element may touch the word, and only a letter may not.
NAME_EDGE = r"(?<![A-Za-z])(?:%s)(?![A-Za-z])"

# Filenames that say what a file is for, when what it is for is a secret.
#
# This is a name check, not a content check: nothing here is opened. What it
# answers is the question an analyst asks early and cannot otherwise ask at
# all - what credential material was sitting on this host, and where - and it
# answers it for a collection that never had the file's contents in it.
#
# (pattern, what it is, how bad, why)
SENSITIVE_FILE_PATTERNS = (
    # -- private keys, which are the whole prize -------------------------
    (r"(^|/)id_(rsa|dsa|ecdsa|ed25519|xmss)$", "ssh private key", "HIGH",
     "an unencrypted SSH private key grants whatever it was trusted for"),
    (r"\.(pem|key|pfx|p12|jks|keystore|ppk)$", "private key / keystore", "HIGH",
     "key material, usable wherever the certificate was trusted"),
    (r"(^|/)(server|client|ca|root|priv|private)[._-]?key", "private key",
     "HIGH", "key material named for what it signs"),
    # -- password stores -------------------------------------------------
    (r"\.(kdbx|kdb|psafe3|agilekeychain|opvault|1pif)$", "password database",
     "HIGH", "a password manager's vault"),
    (r"(^|/)wallet\.dat$", "cryptocurrency wallet", "HIGH",
     "a wallet file is bearer access to its funds"),
    # -- credentials in configuration ------------------------------------
    (r"(^|/)\.?(netrc|pgpass|my\.cnf|pypirc|npmrc)$",
     "credentials in a config file", "MEDIUM",
     "these formats hold plaintext passwords by design"),
    (r"(^|/)\.git-credentials$", "stored git credentials", "HIGH",
     "git writes these in plaintext"),
    (r"(^|/)credentials$|(^|/)\.aws/", "cloud credentials", "HIGH",
     "long-lived cloud keys"),
    (r"(^|/)(kubeconfig|\.kube/config)$", "kubernetes credentials", "HIGH",
     "cluster-admin in a file"),
    (r"(^|/)\.docker/config\.json$", "docker registry credentials", "MEDIUM",
     "registry tokens, often base64 rather than encrypted"),
    (r"(^|/)\.env$|(^|/)\.env\.", "environment file", "MEDIUM",
     "application secrets are conventionally kept here"),
    (r"(^|/)\.?(ovpn|openvpn)|\.ovpn$", "vpn profile", "MEDIUM",
     "may embed the key that gets onto the network"),
    # -- named for what they hold ----------------------------------------
    #
    # These use NAME_EDGE rather than  on both sides. '_' is a word
    # character, so secret cannot see the word in 'db_secrets.txt' - and
    # a file someone named for its contents is called exactly that. The edge
    # below lets a separator or a digit sit next to the word and still
    # excludes a letter, so 'secretariat' and 'tokenizer' stay out.
    (NAME_EDGE % "secrets?", "named 'secret'", "MEDIUM",
     "named for its contents"),
    (NAME_EDGE % "passwords?", "named 'password'", "MEDIUM",
     "named for its contents"),
    (NAME_EDGE % "passwd(?!$)", "named 'passwd'", "MEDIUM",
     "a passwd file somewhere other than /etc"),
    (NAME_EDGE % "creds?|credentials?", "named 'credentials'", "MEDIUM",
     "named for its contents"),
    (NAME_EDGE % ("api[._-]?keys?|access[._-]?keys?|secret[._-]?keys?|"
                  "private[._-]?keys?|auth[._-]?tokens?|bearer[._-]?tokens?"),
     "named for a key or token", "MEDIUM", "named for its contents"),
    (NAME_EDGE % "tokens?", "named 'token'", "LOW", "named for its contents"),
    # -- copies of the account database ----------------------------------
    (r"(^|/)(shadow|passwd|gshadow)[.~-]", "copy of an account database",
     "HIGH", "a copy of /etc/shadow outside /etc is staged loot"),
    (r"(^|/)(shadow|passwd)\.(bak|old|orig|save|copy|txt|[0-9]+)$",
     "copy of an account database", "HIGH",
     "a copy of /etc/shadow outside /etc is staged loot"),
    # -- database and memory dumps ---------------------------------------
    (r"\.(sql|sqldump|dmp|dump)$", "database or memory dump", "MEDIUM",
     "a dump is the data, already extracted"),
    (r"(^|/)(lsass|ntds)", "credential store dump", "HIGH",
     "the Windows credential stores, staged on a Linux host"),
)
SENSITIVE_FILE_RE = tuple(
    (re.compile(p, re.I), what, sev, why)
    for p, what, sev, why in SENSITIVE_FILE_PATTERNS)

# Where a name like this is the distribution's own word rather than a finding.
# Python ships secrets.py, OpenSSL ships test keys, and every package manager
# has a 'credentials' example - matching those produces a page of noise that
# buries the one key in /home that mattered.
SENSITIVE_FILE_BENIGN = re.compile(
    r"^/(usr/(share|src|lib|include|local/lib)|lib|lib64|opt/[^/]+/lib|"
    r"snap|var/lib/(dpkg|rpm|apt|pacman)|etc/alternatives|"
    r"var/cache/(apt|yum|dnf|pacman)|"
    # the bootloader ships password.mod and legacy_password_test.mod, which
    # are code for handling passwords rather than anybody's password
    r"boot/(grub2?|efi|loader)|"
    # configuration *about* authentication, which every host has and none of
    # which is a credential: PAM stacks, AppArmor profiles, XDG autostart
    r"etc/(pam\.d|pam\.conf\.d|apparmor\.d|xdg|security)|"
    r"etc/(fwupd|pki/fwupd[^/]*))/|"
    r"(^|/)(test|tests|testdata|fixtures?|examples?|samples?|docs?|"
    r"node_modules|site-packages|dist-packages|vendor|\.git)/", re.I)

#: The account databases' own rotation backups. shadow-utils writes these on
#: every change and every host has them, so they are the baseline rather than
#: staged loot - a copy of /etc/shadow anywhere else still is.
SENSITIVE_FILE_EXPECTED = re.compile(
    r"^/etc/(passwd|shadow|group|gshadow|subuid|subgid)-$", re.I)

#: Directories that hold public certificates by definition. A .pem here is the
#: public half, which is not a secret - unless the path also says 'private',
#: which is where a CA keeps the half that is.
PUBLIC_CERT_DIR = re.compile(
    r"/(certs|certs_by_serial|ca-certificates|ca-trust|issued|reqs)/", re.I)
PRIVATE_KEY_DIR = re.compile(r"/private/", re.I)

# known Linux rootkit / offensive tool module and file names
ROOTKIT_NAMES = [
    "diamorphine", "reptile", "suterusu", "adore", "adore-ng", "knark", "modhide",
    "kbeast", "enyelkm", "sebek", "phalanx", "jynx", "azazel", "beurk", "vlany",
    "bedevil", "bdvl", "umbreon", "rkduck", "syslogk", "pinkit", "khook",
    "brootus", "nurupo", "wukong", "hiddenwasp", "drovorub", "symbiote",
    "medusa", "tinyshell", "bpfdoor", "ebpfkit", "boopkit", "tripleCross",
]

BENIGN_HIDDEN = re.compile(
    r"(^|/)\.(placeholder|updated|pwd\.lock|X11-unix|ICE-unix|XIM-unix|font-unix|"
    r"Test-unix|cache|config|local|gnupg|ssh|profile|bashrc|bash_logout|bash_profile|"
    r"face|face\.icon|nosearch|gsd-[a-z-]+\.settings-ported|os-release-stage|"
    r"registry|features|dbus-keyrings|Xauthority|ICEauthority|wget-hsts|selected_editor|"
    r"lesshst|viminfo|python_history|sudo_as_admin_successful|motd\.legacy)($|/)")

def norm_ip(ip):
    """Canonical text form so /proc/net, ss and lsof addresses compare equal."""
    if ip is None:
        return ""
    ip = ip.strip().strip("[]")
    if ip in ("*", ""):
        return "0.0.0.0"
    if "%" in ip:                       # scope id, e.g. fe80::1%eth0
        ip = ip.split("%")[0]
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return ip


def is_private_ip(ip):
    """True for anything that is not a routable public address."""
    ip = norm_ip(ip)
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True                     # hostnames / '*' - not evidence of egress
    return not addr.is_global


def hexip_to_str(hexip):
    """/proc/net/{tcp,udp} address (little-endian hex) -> canonical IP string."""
    try:
        if len(hexip) == 8:
            raw = bytes.fromhex(hexip)[::-1]
            return str(ipaddress.IPv4Address(raw))
        if len(hexip) == 32:
            words = [bytes.fromhex(hexip[i:i + 8])[::-1] for i in range(0, 32, 8)]
            return str(ipaddress.IPv6Address(b"".join(words)))
    except Exception:
        pass
    return hexip


def split_hostport(addr):
    """'127.0.0.1:3333' / '[::1]:22' / '*:22' -> (canonical host, port|None)."""
    addr = (addr or "").strip()
    if addr.startswith("["):
        host, sep, port = addr.rpartition("]:")
        if not sep:
            return norm_ip(addr), None
        return norm_ip(host), _port(port)
    host, sep, port = addr.rpartition(":")
    if not sep:
        return norm_ip(addr), None
    if host.count(":") >= 2:            # bare IPv6 without brackets
        return norm_ip(addr), None
    return norm_ip(host), _port(port)


def _port(p):
    try:
        return int(p)
    except (TypeError, ValueError):
        return None


MONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}


def parse_lstart(s):
    """'Tue Mar 24 19:25:30 2026' -> naive-UTC-tagged datetime (host local clock)."""
    m = re.match(r"\w{3}\s+(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})", s.strip())
    if not m:
        return None
    mon = MONTHS.get(m.group(1))
    if not mon:
        return None
    try:
        return datetime(int(m.group(6)), mon, int(m.group(2)), int(m.group(3)),
                        int(m.group(4)), int(m.group(5)), tzinfo=timezone.utc)
    except ValueError:
        return None


def epoch(ts):
    try:
        # auditd stamps are 'seconds.milliseconds', so parse as float and let
        # int() drop the fraction rather than rejecting the whole timestamp
        v = int(float(ts))
    except (TypeError, ValueError):
        return None
    if v <= 0:
        return None
    try:
        return datetime.fromtimestamp(v, timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def _printable(raw):
    """Matched bytes rendered for a report: printable ASCII kept, rest hexed.

    A YARA hit is often binary, and pasting raw bytes into a CSV produces a
    cell no tool can display and some can't even quote. This keeps the part a
    human can read and makes the rest explicit rather than mangled.
    """
    if isinstance(raw, str):
        raw = raw.encode("utf-8", "replace")
    out = []
    for b in raw:
        out.append(chr(b) if 32 <= b < 127 else "\\x%02x" % b)
    return "".join(out)




# Groups whose membership is equivalent to root on most systems: sudo/wheel by
# definition, docker/lxd because the daemon runs as root, disk/shadow because
# they read the raw device and the hashes.
PRIVILEGED_GROUPS = frozenset((
    "sudo", "wheel", "admin", "adm", "root", "docker", "lxd", "lxc",
    "disk", "shadow", "video", "kvm", "libvirt", "systemd-journal",
    "sys", "staff", "operator"))


# The daemons whose messages are privilege use. Matched against the syslog
# identifier as well as the text, because a sudo record names the command it
# ran but never the word "sudo".
PRIV_HINT_RE = re.compile(
    r"\b(sudo|su|pkexec|polkit|usermod|useradd|userdel|groupadd|groupdel|"
    r"gpasswd|chage|passwd|visudo|run0)\b", re.I)


# Message shapes that mean "authentication did not succeed", with the reason
# named. FOR577 opens its account-attack section with "check for large numbers
# of failed logins", so these feed both the FAILED_LOGINS table and the
# brute-force analyzer and live at module scope for both to share.
FAILED_LOGIN_RULES = [
    ("bad password", re.compile(
        r"Failed (?P<method>password) for (?:invalid user )?(?P<user>\S+)"
        r" from (?P<ip>\S+)(?: port (?P<port>\d+))?")),
    ("bad key", re.compile(
        r"Failed (?P<method>publickey|none|keyboard-interactive\S*) for "
        r"(?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)"
        r"(?: port (?P<port>\d+))?")),
    ("unknown account", re.compile(
        r"Invalid user (?P<user>\S*)\s*from (?P<ip>\S+)"
        r"(?: port (?P<port>\d+))?")),
    ("unknown account", re.compile(
        r"(?:check pass; user unknown|"
        r"illegal user (?P<user>\S+) from (?P<ip>\S+))")),
    ("pam authentication failure", re.compile(
        r"authentication failure;")),
    ("too many attempts", re.compile(
        r"(?:maximum authentication attempts exceeded|"
        r"Too many authentication failures)(?: for (?P<user>\S+))?"
        r"(?: from (?P<ip>\S+))?(?: port (?P<port>\d+))?")),
    ("root login refused", re.compile(
        r"(?:ROOT LOGIN REFUSED|Root login rejected|"
        r"User root from (?P<ip>\S+) not allowed)")),
    ("account not permitted", re.compile(
        r"(?:User (?P<user>\S+) from (?P<ip>\S+) not allowed because|"
        r"Authentication refused|pam_access\(.*\): access denied)")),
    ("aborted before authenticating", re.compile(
        r"(?:Connection closed by (?:authenticating|invalid) user "
        r"(?P<user>\S+) (?P<ip>\S+)(?: port (?P<port>\d+))?|"
        r"Received disconnect from (?P<ip2>\S+).*\[preauth\])")),
    ("sudo password failure", re.compile(
        r"^\s*(?P<user>\S+)\s*:\s*(?P<detail>\d+ incorrect password "
        r"attempts?)")),
    ("sudo not permitted", re.compile(
        r"^\s*(?P<user>\S+)\s*:\s*(?P<detail>user NOT in sudoers|"
        r"command not allowed)")),
    ("su failure", re.compile(
        r"FAILED su(?: \(to (?P<target>\S+)\))?(?: for (?P<target2>\S+))?"
        r"(?: by (?P<user>\S+))?")),
    ("failed login", re.compile(
        r"(?:FAILED LOGIN|LOGIN FAILURE|authentication error)"
        r"(?:.*?FROM (?P<ip>\S+))?(?:.*?FOR (?P<user>\S+))?")),
]


#: Punctuation a log wraps an address in, none of which is part of it.
_ADDR_WRAP = " \t\r\n\"'<>(),;"
_ADDR_BRACKET_RE = re.compile(r"^\[([0-9A-Fa-f:.]+)\](?::\d+)?$")
_ADDR_V4_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?$")
#: What a daemon writes when it has no address to write.
_ADDR_NONE = ("", "-", "?", "::", "unknown", "unknown-host", "n/a")


def clean_addr(value):
    r"""A host or address as the log meant it, without what surrounds it.

    Every one of these patterns captures the address with '\S+', because a
    log writes hostnames and v4 and v6 addresses in the same slot and none of
    them has a fixed shape. '\S+' also takes whatever punctuation follows:
    sshd's 'Received disconnect from 192.168.56.101: 11: disconnected by
    user' yields '192.168.56.101:'.

    That is not a cosmetic problem. The trailing colon makes a second
    indicator for a host already in the list, of a shape that matches nothing
    when it is searched for, and ioc_type reads it as a filename because it
    is a dot-bearing token that is not an address. One host became two rows
    in IOCS, one of them useless, and the useless one was typed wrongly.

    The port goes too, where it can be told apart from the address: a source
    port belongs in its own column and is not part of who connected.
    """
    s = (value or "").strip().strip(_ADDR_WRAP)
    # ':' ends an address only in the '::' form, which is not a host on its own
    while s and s[-1] in ".,;:":
        s = s[:-1]
    if s.lower() in _ADDR_NONE:
        return ""
    m = _ADDR_BRACKET_RE.match(s)          # [2001:db8::1]:443
    if m:
        return m.group(1)
    m = _ADDR_V4_RE.match(s)               # 1.2.3.4:51004
    if m:
        return m.group(1)
    return s


def match_failed_login(proc, msg):
    """One log message -> (kind, user, ip, port, method, detail), or None."""
    for label, erx in FAILED_LOGIN_RULES:
        em = erx.search(msg)
        if not em:
            continue
        if label.startswith("sudo") and "sudo" not in (proc or "").lower():
            continue
        g = em.groupdict()
        pick = lambda *k: next((g[x].strip() for x in k
                                if g.get(x) and g[x].strip()), "")
        return (label, pick("user", "target", "target2"),
                clean_addr(pick("ip", "ip2")), pick("port"), pick("method"),
                pick("detail"))
    return None


# 'Accepted publickey for bob from 1.2.3.4 port 51004 ssh2'
ACCEPTED_LOGIN_RE = re.compile(
    r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+)"
    r"(?: port (?P<port>\d+))?")


# every timestamp shape that turns up in a /var/log text file
_TS_ISO_RE = re.compile(r"^(\d{4})-(\d\d)-(\d\d)[T ]\s*(\d\d):(\d\d):(\d\d)"
                        r"(?:[.,]\d+)?\s*(Z|[+-]\d\d:?\d\d)?$")
_TS_SYSLOG_RE = re.compile(r"^(\w{3})\s+(\d{1,2})\s+(\d\d):(\d\d):(\d\d)$")
_TS_CLF_RE = re.compile(r"^(\d\d)/(\w{3})/(\d{4}):(\d\d):(\d\d):(\d\d)"
                        r"\s*([+-]\d{4})?$")
_TS_BANNER_RE = re.compile(r"^\w{3}\s+(\w{3})\s+(\d{1,2})\s+(\d\d):(\d\d):(\d\d)"
                           r"\s+(?:\S+\s+)?(\d{4})$")


def _tz_delta(z):
    """'+0200' / '-04:00' / 'Z' -> timedelta of that offset from UTC."""
    if not z or z == "Z":
        return timedelta(0)
    z = z.replace(":", "")
    try:
        sign = -1 if z[0] == "-" else 1
        return sign * timedelta(hours=int(z[1:3]), minutes=int(z[3:5]))
    except (ValueError, IndexError):
        return timedelta(0)


_TS_SPAN_RE = re.compile(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$")


def _ts_text(v):
    """A datetime, an epoch or an already-UTC string -> 'YYYY-MM-DD HH:MM:SS'."""
    if v is None or v == "":
        return ""
    if isinstance(v, datetime):
        return v.strftime("%Y-%m-%d %H:%M:%S")
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        # only a plausible epoch: a bare small integer reaching a finding is a
        # count, a pid or a port far more often than it is a time
        if v < 100000000 or v > 4102444800:
            return ""
        try:
            return datetime.fromtimestamp(v, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        except (OverflowError, OSError, ValueError):
            return ""
    s = str(v).strip().replace("T", " ")
    if s.endswith("Z"):
        s = s[:-1].strip()
    return s[:19] if _TS_SPAN_RE.match(s[:19]) else ""


_IOC_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_IOC_IPV4_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
_IOC_IPV6_RE = re.compile(r"^[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}$")
_IOC_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)"
                            r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
                            r"[A-Za-z]{2,24}$")
_HASH_BY_LEN = {32: "md5", 40: "sha1", 64: "sha256"}


def ioc_type(value):
    """What kind of thing an indicator is - 'ipv4', 'sha256', 'path', ...

    Shape only, and deliberately so: an indicator arrives as a bare string
    from a --pivot list or from an analyzer, with nothing else to go on. The
    point is a column an analyst can filter on, so an unrecognised shape says
    'string' rather than being forced into a category it does not fit.
    """
    s = str(value or "").strip()
    if not s:
        return ""
    low = s.lower()
    for prefix, kind in (("port:", "port"), ("pid:", "pid")):
        if low.startswith(prefix):
            return kind
    if "://" in s:
        return "url"
    if s.startswith("/"):
        return "path"
    if s.isdigit():
        return "number"
    if _IOC_HEX_RE.match(s):
        # a hash is one of three lengths; anything else all-hex is only worth
        # naming when it is long enough not to be an ordinary short word, and
        # 'dead', 'added' and 'beef' are all valid hex
        kind = _HASH_BY_LEN.get(len(s)) or ("hex string" if len(s) >= 16 else "")
        if kind:
            return kind
    m = _IOC_IPV4_RE.match(s)
    if m and all(int(g) < 256 for g in m.groups()):
        return "ipv4"
    if ":" in s and _IOC_IPV6_RE.match(s):
        return "ipv6"
    if "@" in s and _IOC_DOMAIN_RE.match(s.rsplit("@", 1)[-1]):
        return "email"
    if _IOC_DOMAIN_RE.match(s):
        return "domain"
    if "." in s and " " not in s and "/" not in s:
        return "filename"
    return "string"


# Why an indicator was extracted -> the technique that makes it worth chasing.
# Keyed on the provenance labels Triage.ioc() records, which is the only thing
# that knows why a term is in the list at all: the term itself is a string. A
# label with no entry - a plain --pivot value, a path a table happened to
# mention - contributes nothing rather than a guessed technique.
IOC_TECHNIQUES = (
    ("/etc/ld.so.preload", "T1574.006 Hijack Execution Flow: LD_PRELOAD"),
    ("hidden_pids", "T1564 Hide Artifacts / T1014 Rootkit"),
    ("hidden ", "T1564.001 Hidden Files and Directories"),
    ("regular file under /dev", "T1564 Hide Artifacts"),
    ("bodyfile (executable in tmpfs)", "T1036 Masquerading"),
    ("running process pid", "T1059 Command and Scripting Interpreter"),
    ("running-process hash", "T1070.004 Indicator Removal: File Deletion"),
    ("hash mismatch", "T1554 Compromise Host Software Binary"),
    ("listening socket", "T1571 Non-Standard Port"),
    ("network connection", "T1071 Application Layer Protocol"),
    ("outbound admin protocol", "T1021 Remote Services"),
    ("authorized_keys", "T1098.004 SSH Authorized Keys"),
    ("interactive login", "T1078 Valid Accounts"),
    ("failed authentication source", "T1110 Brute Force"),
    ("authentication source", "T1078 Valid Accounts"),
    ("smb client", "T1021.002 Remote Services: SMB/Windows Admin Shares"),
    ("password spraying source", "T1110.003 Password Spraying"),
    ("systemd unit", "T1543.002 Systemd Service"),
    ("suid", "T1548.001 Setuid and Setgid"),
    ("sgid", "T1548.001 Setuid and Setgid"),
    ("hacktool:", "T1588.002 Obtain Capabilities: Tool"),
)


def ioc_mitre(labels):
    """ATT&CK technique(s) implied by where an indicator was picked up."""
    out = []
    for label in sorted(labels or ()):
        for prefix, tech in IOC_TECHNIQUES:
            if label.startswith(prefix):
                if tech not in out:
                    out.append(tech)
                break
    return "; ".join(out)


def span_add(span, ts):
    """Fold one timestamp into a mutable ['first', 'last'] pair, in place.

    The counterpart to span_of for the sweeps: a pivot term or a noisy Sigma
    rule can match six figures of rows, and only the two ends are ever wanted.
    """
    if ts:
        if not span[0] or ts < span[0]:
            span[0] = ts
        if not span[1] or ts > span[1]:
            span[1] = ts
    return span


# Distinct reference strings kept per tool per table before the tail is folded
# into one overflow row. A tool named in BODYFILE matches a different path on
# nearly every row it hits, and an unbounded dict there is a copy of the
# filesystem in memory; 200 is already past the point a breakdown reads.
HACKTOOL_VARIANT_CAP = 200
HACKTOOL_VARIANT_OTHER = "(further distinct references, not itemised)"


def variant_add(bag, val, column, ts):
    """Fold one hit into a {reference text: [count, span, columns]} bag.

    The per-hit rows keep twelve samples per table, so they cannot be counted
    after the fact - and the count is the point: masscan/1.0 and masscan/1.3
    are two scanners wearing one tool name, and how often each was seen is
    only knowable while every row is still going past.
    """
    text = trunc(str(val), 200)
    rec = bag.get(text)
    if rec is None:
        if len(bag) >= HACKTOOL_VARIANT_CAP:
            text = HACKTOOL_VARIANT_OTHER
            rec = bag.get(text)
        if rec is None:
            rec = bag[text] = [0, ["", ""], set()]
    rec[0] += 1
    span_add(rec[1], ts)
    if column:
        rec[2].add(column)
    return bag


def span_of(times):
    """(first, last) as 'YYYY-MM-DD HH:MM:SS' UTC over a bag of timestamps.

    Everything an analyzer holds is already UTC - the datetimes it puts on the
    timeline are aware, its strings came back from norm_log_ts - so the span is
    a plain min/max and no conversion happens here. Unparseable entries drop
    out instead of skewing the span, and an empty input gives an empty span,
    which every renderer prints as nothing at all.
    """
    vals = sorted(v for v in (_ts_text(t) for t in (times or [])) if v)
    return (vals[0], vals[-1]) if vals else ("", "")


def norm_log_ts(text, tz_offset=None, year_hint=None):
    """Any log timestamp -> 'YYYY-MM-DD HH:MM:SS' UTC, or '' if unparseable.

    A stamp that carries its own offset is converted with it.  A naive stamp is
    the host's local wall clock, so tz_offset (host local - UTC) is subtracted -
    the same normalisation the timeline already applies.  Syslog's 'Mar 24
    15:47:28' carries no year; year_hint supplies one so rotations do not all
    collapse onto 1900.
    """
    s = (text or "").strip()
    if not s:
        return ""
    off = tz_offset or timedelta(0)
    m = _TS_ISO_RE.match(s)
    if m:
        try:
            dt = datetime(*(int(m.group(i)) for i in range(1, 7)),
                          tzinfo=timezone.utc)
        except ValueError:
            return ""
        dt -= _tz_delta(m.group(7)) if m.group(7) else off
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    m = _TS_CLF_RE.match(s)
    if m:
        mon = MONTHS.get(m.group(2))
        if not mon:
            return ""
        try:
            dt = datetime(int(m.group(3)), mon, int(m.group(1)), int(m.group(4)),
                          int(m.group(5)), int(m.group(6)), tzinfo=timezone.utc)
        except ValueError:
            return ""
        return (dt - _tz_delta(m.group(7))).strftime("%Y-%m-%d %H:%M:%S")
    m = _TS_BANNER_RE.match(s)
    if m:
        mon = MONTHS.get(m.group(1))
        if not mon:
            return ""
        try:
            dt = datetime(int(m.group(6)), mon, int(m.group(2)), int(m.group(3)),
                          int(m.group(4)), int(m.group(5)), tzinfo=timezone.utc)
        except ValueError:
            return ""
        return (dt - off).strftime("%Y-%m-%d %H:%M:%S")
    m = _TS_SYSLOG_RE.match(s)
    if m:
        mon = MONTHS.get(m.group(1))
        if not mon or not year_hint:
            return ""
        try:
            dt = datetime(int(year_hint), mon, int(m.group(2)), int(m.group(3)),
                          int(m.group(4)), int(m.group(5)), tzinfo=timezone.utc)
        except ValueError:
            return ""
        return (dt - off).strftime("%Y-%m-%d %H:%M:%S")
    return ""
def human_size(n):
    try:
        n = float(n)
    except (TypeError, ValueError):
        return ""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return "%.0f %s" % (n, unit) if unit == "B" else "%.1f %s" % (n, unit)
        n /= 1024.0
    return ""
NDJSON_TIME_COLUMNS = ("timestamp_utc", "timestamp", "start_utc",
                       "last_utc", "first_utc")
