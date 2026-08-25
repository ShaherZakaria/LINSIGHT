# -*- coding: utf-8 -*-
"""Which Linux distribution is this, and how do we know.

The answer changes what an analyst does next. Where the logs are, whether
authentication went to auth.log or secure, whether the package history is in
dpkg.log or yum.log, which paths a persistence check should care about, and
which Sigma rules are even applicable - all of it follows from the family. A
report that does not say what the host was makes the reader work it out again
from the evidence.

/etc/os-release answers it on any system built this decade, and this module
would be six lines if that were the whole story. It is not:

  - a collection of a pre-2014 host has no os-release at all, only the
    family's own release file, and RHEL 6 is still in cases
  - a *logical* image often does not include /etc. The AD1 this was built
    against holds /boot, /root and /var and nothing else - and still says
    Kali plainly, in the kernel filename, in the package manager's logs, and
    in the lsb-release the installer left behind in /var/log
  - a container image, a chroot, or a rescue mount can carry an os-release
    describing something other than what is actually installed

So the distribution is established from as many independent sources as the
evidence offers, each recorded with what it was read from, and the report
says which one was believed. When they disagree that is not an inconvenience
to be smoothed over - an /etc/os-release that does not match the package
database or the kernel is worth an analyst's attention, and it is raised.
"""

from __future__ import annotations

import os
import re

#: Family, and how to recognise it from an os-release ID or ID_LIKE. The
#: family is what the rest of the tool can act on: a "rhel" host keeps
#: authentication in /var/log/secure, a "debian" one in /var/log/auth.log.
FAMILY_BY_ID = {
    "debian": "debian", "ubuntu": "debian", "kali": "debian",
    "linuxmint": "debian", "raspbian": "debian", "pop": "debian",
    "elementary": "debian", "devuan": "debian", "parrot": "debian",
    "zorin": "debian", "mx": "debian", "deepin": "debian",
    "rhel": "rhel", "centos": "rhel", "fedora": "rhel", "rocky": "rhel",
    "almalinux": "rhel", "ol": "rhel", "oracle": "rhel", "scientific": "rhel",
    "amzn": "rhel", "cloudlinux": "rhel", "virtuozzo": "rhel",
    "openeuler": "rhel", "anolis": "rhel", "circle": "rhel",
    "sles": "suse", "sled": "suse", "opensuse": "suse",
    "opensuse-leap": "suse", "opensuse-tumbleweed": "suse", "suse": "suse",
    "arch": "arch", "manjaro": "arch", "endeavouros": "arch",
    "garuda": "arch", "artix": "arch",
    "alpine": "alpine",
    "gentoo": "gentoo", "funtoo": "gentoo",
    "slackware": "slackware",
    "void": "void",
    "nixos": "nixos",
    "photon": "photon",
    "clear-linux-os": "clear",
    "openwrt": "openwrt",
}

#: Release files that are not os-release, per family. Each is (path, family,
#: how to read it). These are what a host older than os-release has, and what
#: a minimal or stripped image sometimes keeps when os-release is gone.
RELEASE_FILES = (
    ("/etc/redhat-release", "rhel"),
    ("/etc/centos-release", "rhel"),
    ("/etc/rocky-release", "rhel"),
    ("/etc/almalinux-release", "rhel"),
    ("/etc/oracle-release", "rhel"),
    ("/etc/fedora-release", "rhel"),
    ("/etc/system-release", "rhel"),
    ("/etc/SuSE-release", "suse"),
    ("/etc/SUSE-brand", "suse"),
    ("/etc/alpine-release", "alpine"),
    ("/etc/gentoo-release", "gentoo"),
    ("/etc/slackware-version", "slackware"),
    ("/etc/arch-release", "arch"),
    ("/etc/manjaro-release", "arch"),
    ("/etc/void-release", "void"),
    ("/etc/photon-release", "photon"),
    ("/etc/openwrt_release", "openwrt"),
    ("/etc/debian_version", "debian"),
)

#: The package manager's own files, split by how much weight they carry. This
#: survives an /etc that was never collected, and it is evidence of what is
#: actually installed rather than of what a text file claims. The database can
#: contradict a text file; a log or a config file only supports one, because a
#: host with 'alien' installed, or a stray /etc/yum.conf, is not a Red Hat
#: machine and must not be reported as a conflict.
PACKAGE_EVIDENCE = (
    ("debian", ("/var/lib/dpkg/status", "/var/lib/dpkg/available"),
     ("/var/log/dpkg.log", "/var/log/apt/history.log",
      "/etc/apt/sources.list")),
    ("rhel", ("/var/lib/rpm/Packages", "/var/lib/rpm/rpmdb.sqlite"),
     ("/var/log/yum.log", "/var/log/dnf.log", "/etc/yum.conf",
      "/etc/dnf/dnf.conf")),
    ("suse", (), ("/var/log/zypper.log", "/etc/zypp/zypp.conf")),
    ("alpine", ("/lib/apk/db/installed",), ("/etc/apk/repositories",)),
    ("arch", ("/var/lib/pacman/local/ALPM_DB_VERSION",), ("/etc/pacman.conf",)),
    ("gentoo", (), ("/etc/portage/make.conf",)),
    ("void", (), ("/etc/xbps.d",)),
    ("nixos", (), ("/etc/nixos/configuration.nix",)),
)

#: Kernel release strings carry the distribution that built them. This is the
#: source that survives everything else - a kernel filename under /boot is
#: enough on its own, and it is what named the host in the logical image this
#: module was written against.
KERNEL_HINTS = (
    (re.compile(r"-kali\d*", re.I), "Kali GNU/Linux", "debian"),
    (re.compile(r"\.el(\d+)(?:_\d+)?\.", re.I), "RHEL", "rhel"),
    (re.compile(r"\.fc(\d+)\.", re.I), "Fedora", "rhel"),
    (re.compile(r"\.amzn(\d*)\.", re.I), "Amazon Linux", "rhel"),
    (re.compile(r"-pve\b", re.I), "Proxmox VE", "debian"),
    (re.compile(r"\.oe(\d+)", re.I), "openEuler", "rhel"),
    (re.compile(r"-tegra\b|-raspi\b", re.I), "Ubuntu", "debian"),
    (re.compile(r"-default\b", re.I), "SUSE", "suse"),
    (re.compile(r"-MANJARO\b", re.I), "Manjaro", "arch"),
    (re.compile(r"-arch\d*\b", re.I), "Arch Linux", "arch"),
)

#: The same idea for suffixes that only narrow the family. '-generic' is
#: Ubuntu's flavour name and '-amd64' is Debian's, but both turn up on hosts
#: that are neither, so they answer only when nothing specific did: a second
#: opinion from a weaker source is noise in the evidence list, not support.
KERNEL_FAMILY_HINTS = (
    (re.compile(r"-(?:generic|aws|azure|gcp|oracle|lowlatency|kvm)\b", re.I),
     "Ubuntu", "debian"),
    (re.compile(r"-(?:amd64|686|686-pae|rt-amd64|cloud-amd64)\b", re.I),
     "Debian", "debian"),
)

#: Kernels that say this is not a machine at all. None of them names a
#: distribution, and all of them change what the rest of the report means.
KERNEL_ENVIRONMENT = (
    (re.compile(r"-microsoft-standard(?:-WSL2)?", re.I),
     "the kernel is Microsoft's WSL kernel, so this is a WSL environment "
     "rather than a host"),
    (re.compile(r"-linuxkit\b", re.I),
     "a LinuxKit kernel - this is Docker Desktop's VM rather than a host"),
    (re.compile(r"-cos\b", re.I),
     "a Container-Optimized OS kernel"),
)

#: Where a kernel release string can be found, as patterns rather than paths.
#: Which directory a UAC profile writes uname into moves between profile
#: generations, and some profiles run only 'uname -n' - so these are globbed,
#: and every one of them is allowed to come up empty.
KERNEL_SOURCES = (
    "live_response/**/uname_-a.txt",
    "live_response/**/uname*.txt",
    "**/uname_-a.txt",
    "live_response/**/proc_version.txt",
)

OS_RELEASE_PATHS = ("/etc/os-release", "/usr/lib/os-release",
                    "/etc/initrd-release")

#: os-release copies that survive when /etc does not. The installer leaves one
#: behind in /var/log on Debian and Ubuntu, and it names the medium the host
#: was installed from - which is a fact about the build worth having anyway.
SALVAGE_PATHS = ("/var/log/installer/lsb-release",
                 "/var/log/installer/media-info",
                 "/etc/lsb-release",
                 "/var/lib/snapd/hostfs/etc/os-release",
                 "/usr/lib/os.release.d/os-release")


class Evidence(object):
    """One source's answer, and where it came from."""

    __slots__ = ("name", "version", "family", "source", "detail", "rank",
                 "strong")

    def __init__(self, name="", version="", family="", source="", detail="",
                 rank=99, strong=True):
        self.name = name
        self.version = version
        self.family = family
        self.source = source
        self.detail = detail
        self.rank = rank
        #: whether this source is good enough to contradict another. A
        #: package manager's database is; a stray /etc/yum.conf on a Debian
        #: box, or a '-amd64' kernel suffix, is not - and a conflict raised
        #: from one of those is a false alarm about tampering, which is worse
        #: than saying nothing.
        self.strong = strong

    def label(self):
        if self.name and self.version:
            return "%s %s" % (self.name, self.version)
        return self.name or self.version or ""

    def __repr__(self):
        return "<Evidence %s from %s>" % (self.label(), self.source)


def _lines(col, host_path):
    """Lines of a file on the collected host, or []."""
    rel = col.rootfs(host_path)
    if not rel:
        return []
    try:
        return col.lines(rel) or []
    except Exception:
        return []


def _shell_vars(lines):
    """KEY=value / KEY="value" pairs, the way os-release is written."""
    out = {}
    for ln in lines:
        s = ln.strip()
        if not s or s.startswith("#") or "=" not in s:
            continue
        key, _, value = s.partition("=")
        out[key.strip().upper()] = value.strip().strip('"').strip("'")
    return out


def _from_os_release(col):
    """The standard answer, wherever a copy of it survives."""
    out = []
    for path in OS_RELEASE_PATHS:
        data = _shell_vars(_lines(col, path))
        if not data:
            continue
        ident = (data.get("ID") or "").lower()
        name = data.get("PRETTY_NAME") or data.get("NAME") or ident
        version = data.get("VERSION_ID") or data.get("VERSION") or \
            data.get("BUILD_ID") or ""
        family = FAMILY_BY_ID.get(ident, "")
        if not family:
            for like in (data.get("ID_LIKE") or "").lower().split():
                family = FAMILY_BY_ID.get(like, "")
                if family:
                    break
        detail = []
        if data.get("VERSION_CODENAME"):
            detail.append("codename %s" % data["VERSION_CODENAME"])
        if data.get("VARIANT"):
            detail.append("variant %s" % data["VARIANT"])
        if data.get("CPE_NAME"):
            detail.append(data["CPE_NAME"])
        out.append(Evidence(name, version, family or ident, path,
                            ", ".join(detail), rank=0))
        out[-1].name = name
        # keep the raw id for the family line even when PRETTY_NAME is fancy
        if ident and not family:
            out[-1].family = ident
    return out


def _from_release_files(col):
    """The family's own release file, for a host older than os-release."""
    out = []
    for path, family in RELEASE_FILES:
        lines = _lines(col, path)
        text = ""
        for ln in lines:
            if ln.strip():
                text = ln.strip()
                break
        if path == "/etc/arch-release" and col.rootfs(path) and not text:
            out.append(Evidence("Arch Linux", "", "arch", path,
                                "the file is empty, which is how Arch says so",
                                rank=2))
            continue
        if not text:
            continue
        if path == "/etc/debian_version":
            # Debian points at itself here, but Ubuntu and Kali also ship it
            # with their base version, so it is family evidence and a weak
            # name - it is ranked below the release files that name a product
            out.append(Evidence("Debian", text, "debian", path,
                                "base version", rank=3))
            continue
        if path == "/etc/alpine-release":
            out.append(Evidence("Alpine Linux", text, "alpine", path, "",
                                rank=1))
            continue
        if "=" in text and path in ("/etc/openwrt_release", "/etc/SUSE-brand"):
            data = _shell_vars(lines)
            name = data.get("DISTRIB_DESCRIPTION") or data.get("DISTRIB_ID") \
                or text
            out.append(Evidence(name, data.get("DISTRIB_RELEASE", ""), family,
                                path, "", rank=1))
            continue
        name, version = _split_release_line(text)
        out.append(Evidence(name, version, family, path, "", rank=1))
    return out


def _split_release_line(text):
    """'CentOS Linux release 7.9.2009 (Core)' -> ('CentOS Linux', '7.9.2009')."""
    m = re.match(r"^(.*?)\s+release\s+(\S+)", text, re.I)
    if m:
        return m.group(1).strip(), m.group(2).strip()
    m = re.match(r"^(.*?)\s+(\d[\d.]*)\s*(?:\(|$)", text)
    if m:
        return m.group(1).strip(), m.group(2).strip()
    return text, ""


def _from_lsb(col):
    """/etc/lsb-release, and the copy the installer leaves under /var/log.

    The installer's copy is the one that matters here: it is written once at
    build time and lives outside /etc, so it survives a logical acquisition
    that took only /var, and it survives an /etc that was tampered with.
    """
    out = []
    for path in SALVAGE_PATHS:
        lines = _lines(col, path)
        if not lines:
            continue
        if path.endswith("media-info"):
            text = lines[0].strip()
            if text:
                out.append(Evidence(text, "", "", path,
                                    "the medium this host was installed from",
                                    rank=4))
            continue
        data = _shell_vars(lines)
        if not data:
            continue
        if "ID" in data and "DISTRIB_ID" not in data:
            ident = data.get("ID", "").lower()
            out.append(Evidence(data.get("PRETTY_NAME") or ident,
                                data.get("VERSION_ID", ""),
                                FAMILY_BY_ID.get(ident, ident), path, "",
                                rank=1))
            continue
        name = data.get("DISTRIB_DESCRIPTION") or data.get("DISTRIB_ID", "")
        ident = (data.get("DISTRIB_ID") or "").lower()
        version = data.get("DISTRIB_RELEASE", "")
        detail = ""
        if "/installer/" in path:
            # This file describes the installation medium, not the running
            # system: 'Kali GNU/Linux installer', release '2017.1
            # (kali-rolling) - installer build 20171009'. The host is what
            # that medium installed, so the medium's own words move into the
            # detail rather than being printed as the name of the OS.
            name = re.sub(r"\s+installer$", "", name.strip())
            version, sep, build = version.partition(" - installer")
            version = version.strip()
            detail = "recorded at install time"
            if sep:
                detail += ", from the installer%s" % build
        out.append(Evidence(name, version,
                            FAMILY_BY_ID.get(ident, ident), path, detail,
                            rank=2 if "/installer/" in path else 1))
    return out


def _from_packages(col):
    """Which package manager's files are here - what is actually installed."""
    out = []
    for family, database, supporting in PACKAGE_EVIDENCE:
        found = ""
        for path in database:
            if col.rootfs(path):
                found = path
                break
        if found:
            out.append(Evidence("", "", family, found,
                                "the package database", rank=5, strong=True))
            continue
        for path in supporting:
            if col.rootfs(path):
                out.append(Evidence("", "", family, path,
                                    "the package manager left files here",
                                    rank=7, strong=False))
                break
    return out


def kernel_release(col):
    """The kernel version string, from wherever this collection carries it."""
    for pattern in KERNEL_SOURCES:
        try:
            found = col.glob(pattern)
        except Exception:
            found = []
        for rel in found:
            try:
                lines = col.lines(rel) or []
            except Exception:
                continue
            for ln in lines:
                # 'uname -n' is a hostname and has no version in it; only a
                # line that actually carries one answers this
                m = re.search(r"\b(\d+\.\d+\.\d+\S*)", ln)
                if m:
                    return m.group(1), rel
    for path in ("/proc/version", "/proc/sys/kernel/osrelease"):
        for ln in _lines(col, path):
            m = re.search(r"\b(\d+\.\d+\.\d+\S*)", ln)
            if m:
                return m.group(1), path
    # Nothing ran uname and /proc was not copied. The kernel is still named by
    # the files it was installed as - and not only by vmlinuz: a collection
    # that skipped the kernel image itself still tends to carry its config and
    # its initrd, which are named the same way.
    best = ""
    for pattern in ("/boot/vmlinuz-*", "/boot/System.map-*", "/boot/config-*",
                    "/boot/initrd.img-*", "/boot/initramfs-*",
                    "/lib/modules/*", "/usr/lib/modules/*"):
        try:
            names = col.rootfs_glob(pattern)
        except Exception:
            continue
        for rel in names:
            base = os.path.basename(col.host_path(rel.rstrip("/")))
            m = re.match(r"^(?:vmlinuz|System\.map|config|initrd\.img|"
                         r"initramfs)-(.+?)(?:\.img|\.old)?$", base)
            release = m.group(1) if m else base
            if not re.match(r"^\d+\.\d+", release):
                continue
            if not best or _version_key(release) > _version_key(best):
                best = release
        if best:
            return best, "/boot" if pattern.startswith("/boot") else "/lib/modules"
    return "", ""


def _version_key(release):
    """Sort kernel releases by number, not by string.

    '6.9.0' sorts after '6.10.0' lexically and before it in every sense that
    matters, and a collection with two kernels installed has to report the one
    that was actually running.
    """
    numbers = [int(n) for n in re.findall(r"\d+", release)[:5]]
    return (numbers, release)


def _from_kernel(release, source):
    """What the kernel release string says the distribution is.

    A distribution builds its own kernels and stamps itself into the version:
    '-kali1', '.el9.', '.fc38.'. That survives an /etc that was never
    collected and an /etc that was edited, which makes it both the source of
    last resort and a check on the others.
    """
    if not release:
        return []
    where = source or "the kernel release"
    out = []
    for rx, name, family in KERNEL_HINTS:
        m = rx.search(release)
        if not m:
            continue
        version = m.group(1) if (m.groups() and m.group(1)) else ""
        out.append(Evidence(name, version, family, where,
                            "kernel %s" % release, rank=4))
    if not out:
        for rx, name, family in KERNEL_FAMILY_HINTS:
            if rx.search(release):
                out.append(Evidence(name, "", family, where,
                                    "kernel %s - a flavour suffix, which "
                                    "narrows the family but does not name the "
                                    "product" % release, rank=6, strong=False))
                break
    for rx, note in KERNEL_ENVIRONMENT:
        if rx.search(release):
            out.append(Evidence("", "", "", where, note, rank=8))
            break
    return out


# ---------------------------------------------------------------------------
# putting it together
# ---------------------------------------------------------------------------

def identify_distro(col):
    """Everything this collection says about which distribution it came from.

    Returns a dict with the answer, the family, the version, every source that
    had an opinion, and whether they agreed. Nothing here raises: a collection
    that says nothing about its distribution gets an empty answer, which is a
    fact worth printing rather than a reason to fail.
    """
    result = {"name": "", "version": "", "family": "", "source": "",
              "detail": "", "kernel": "", "kernel_source": "",
              "evidence": [], "conflict": ""}
    try:
        found = []
        found.extend(_from_os_release(col))
        found.extend(_from_release_files(col))
        found.extend(_from_lsb(col))
        release, ksource = kernel_release(col)
        result["kernel"] = release
        result["kernel_source"] = ksource
        found.extend(_from_kernel(release, ksource))
        found.extend(_from_packages(col))
    except Exception:
        return result

    result["evidence"] = found
    named = [e for e in found if e.name]
    if named:
        named.sort(key=lambda e: e.rank)
        best = named[0]
        result["name"] = best.name
        result["version"] = best.version
        result["source"] = best.source
        result["detail"] = best.detail
        result["family"] = best.family
    # the family is worth answering even when nothing named the product: the
    # package manager alone settles where the logs are
    if not result["family"]:
        for e in found:
            if e.family:
                result["family"] = e.family
                if not result["source"]:
                    result["source"] = e.source
                break
    result["conflict"] = _conflict(found)
    return result


def _conflict(found):
    """Whether the sources disagree about the family, and how.

    An /etc/os-release that says one thing while the package database and the
    kernel say another is worth an analyst's attention: it is what a container
    image mounted as a host looks like, what a chroot looks like, and what a
    tampered os-release looks like. It is reported rather than resolved.
    """
    families = {}
    for e in found:
        if e.strong and e.family and e.family in FAMILY_BY_ID.values():
            families.setdefault(e.family, []).append(e.source)
    if len(families) < 2:
        return ""
    return "; ".join("%s (%s)" % (fam, ", ".join(sorted(set(src))[:3]))
                     for fam, src in sorted(families.items()))


def describe_distro(info):
    """The one-line answer for METADATA."""
    label = info["name"]
    if info["version"] and info["version"] not in label:
        label = ("%s %s" % (label, info["version"])).strip()
    if not label:
        if info["family"]:
            return "unidentified, %s family" % info["family"]
        return ""
    return label
