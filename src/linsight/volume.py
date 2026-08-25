# -*- coding: utf-8 -*-
"""The volume layer: what a disk is cut into before a filesystem starts.

Between "here are the bytes of a disk" and "here is a filesystem" sits a layer
that is easy to skip and expensive to skip wrongly. A RHEL, Ubuntu or SUSE
server install puts the root filesystem inside LVM by default, so a partition
scan that stops at the partition table finds a physical volume, no filesystem,
and reports a disk with nothing on it. That is the failure this module exists
to prevent - it is not a missing feature, it is a wrong answer.

So the scan goes all the way down:

    disk -> MBR or GPT partitions -> LVM2 physical volumes -> logical volumes
                                  -> LUKS containers (identified, not opened)
                                  -> filesystems

and every level is reported, including the levels that hold nothing. A LUKS
partition is named as encrypted rather than passed over in silence, because
"the evidence is behind a passphrase" and "there was no evidence" have to look
different in the output.

Each volume that comes out is itself an Image - the same read(offset, length)
the filesystem readers already take - so a filesystem does not know or care
whether it sits on a partition, on a logical volume striped over three disks,
or on the bare device.
"""

from __future__ import annotations

import re
import struct
import uuid

from .image import Image, ImageError

SECTOR = 512


def _vol_u16(b, o=0):
    return struct.unpack_from("<H", b, o)[0]


def _vol_u32(b, o=0):
    return struct.unpack_from("<I", b, o)[0]


def _vol_u64(b, o=0):
    return struct.unpack_from("<Q", b, o)[0]


def _guid(raw):
    """A GPT type GUID as its canonical string (first three fields LE)."""
    try:
        return str(uuid.UUID(bytes_le=raw)).upper()
    except (ValueError, TypeError):
        return ""


# ---------------------------------------------------------------------------
# what a volume is
# ---------------------------------------------------------------------------

class Volume(Image):
    """A window onto a parent image: one partition, or the whole disk.

    Subclassing Image is the point. A filesystem reader is handed one of these
    and reads from offset 0 of "its" disk; whether that maps onto a partition
    1 MiB into a dd file or onto four stripes of a logical volume is settled
    here and nowhere else.
    """

    def __init__(self, parent, offset, length, scheme="whole", index=0,
                 type_name="", label="", path=""):
        self.parent = parent
        self.offset = offset
        self.scheme = scheme
        self.index = index
        self.type_name = type_name
        self.label = label
        self.fstype = ""
        self.detail = ""
        self.chunk = parent.chunk
        Image.__init__(self, path or parent.path, length,
                       "%s %s" % (scheme, index) if scheme != "whole" else "disk")
        self.cache_entries = 8       # the parent already caches; do not double

    def _read_raw(self, offset, length):
        if self.size:
            length = min(length, max(0, self.size - offset))
        if length <= 0:
            return b""
        return self.parent.read(self.offset + offset, length)

    @property
    def name(self):
        if self.scheme == "lvm":
            return self.label
        if self.scheme == "whole":
            return "disk"
        return "%s%d" % ("p" if self.scheme == "gpt" else "part", self.index)

    def describe(self):
        bits = [self.name]
        if self.label and self.scheme != "lvm":
            bits.append("'%s'" % self.label)
        if self.type_name:
            bits.append(self.type_name)
        bits.append(self.fstype or "no filesystem recognised")
        if self.detail:
            bits.append(self.detail)
        return " | ".join(bits)


# ---------------------------------------------------------------------------
# partition tables
# ---------------------------------------------------------------------------

MBR_TYPES = {
    0x00: "empty", 0x05: "extended", 0x0B: "fat32", 0x0C: "fat32-lba",
    0x07: "ntfs/exfat", 0x0F: "extended-lba", 0x82: "linux-swap",
    0x83: "linux", 0x85: "linux-extended", 0x8E: "linux-lvm",
    0xA5: "freebsd", 0xEE: "gpt-protective", 0xEF: "efi-system",
    0xFD: "linux-raid",
}

GPT_TYPES = {
    "0FC63DAF-8483-4772-8E79-3D69D8477DE4": "linux",
    "E6D6D379-F507-44C2-A23C-238F2A3DF928": "linux-lvm",
    "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F": "linux-swap",
    "CA7D7CCB-63ED-4C53-861C-1742536059CC": "linux-luks",
    "A19D880F-05FC-4D3B-A006-743F0F84911E": "linux-raid",
    "44479540-F297-41B2-9AF7-D131D5F0458A": "linux-root-x86",
    "4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709": "linux-root-x86-64",
    "B921B045-1DF0-41C3-AF44-4C6F280D3FAE": "linux-root-arm64",
    "933AC7E1-2EB4-4F13-B844-0E14E2AEF915": "linux-home",
    "3B8F8425-20E0-4F3B-907F-1A25A76F98E8": "linux-srv",
    "BC13C2FF-59E6-4262-A352-B275FD6F7172": "linux-extended-boot",
    "C12A7328-F81F-11D2-BA4B-00A0C93EC93B": "efi-system",
    "21686148-6449-6E6F-744E-656564454649": "bios-boot",
    "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7": "microsoft-basic-data",
    "E3C9E316-0B5C-4DB8-817D-F92DF00215AE": "microsoft-reserved",
    "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC": "windows-recovery",
}

EXTENDED = (0x05, 0x0F, 0x85, 0xC5)


def read_mbr(image, quiet=True):
    """MBR primary partitions, and the logical partitions in the EBR chain."""
    sector = image.read(0, SECTOR)
    if len(sector) < SECTOR or sector[510:512] != b"\x55\xAA":
        return []
    out = []
    extended_at = 0
    for i in range(4):
        raw = sector[446 + i * 16:462 + i * 16]
        ptype = raw[4]
        start = _vol_u32(raw, 8)
        count = _vol_u32(raw, 12)
        if not count or not ptype:
            continue
        if ptype == 0xEE:                          # a GPT disk; read_gpt has it
            return []
        if ptype in EXTENDED:
            extended_at = start
            continue
        out.append(Volume(image, start * SECTOR, count * SECTOR, "mbr",
                          len(out) + 1, MBR_TYPES.get(ptype, "type 0x%02x" % ptype)))
    if extended_at:
        out.extend(_read_ebr_chain(image, extended_at, len(out)))
    return out


def _read_ebr_chain(image, base, first_index):
    """The linked list of extended boot records, guarded against a loop."""
    out = []
    at = base
    seen = set()
    while at and at not in seen and len(out) < 128:
        seen.add(at)
        sector = image.read(at * SECTOR, SECTOR)
        if len(sector) < SECTOR or sector[510:512] != b"\x55\xAA":
            break
        nxt = 0
        for i in range(2):
            raw = sector[446 + i * 16:462 + i * 16]
            ptype = raw[4]
            start = _vol_u32(raw, 8)
            count = _vol_u32(raw, 12)
            if not count or not ptype:
                continue
            if ptype in EXTENDED:
                nxt = base + start
                continue
            out.append(Volume(image, (at + start) * SECTOR, count * SECTOR,
                              "mbr", first_index + len(out) + 1,
                              MBR_TYPES.get(ptype, "type 0x%02x" % ptype)))
        at = nxt
    return out


def read_gpt(image):
    """GPT partitions from the primary header, falling back to the backup."""
    for header_lba in (1,):
        head = image.read(header_lba * SECTOR, SECTOR)
        if head[:8] == b"EFI PART":
            break
    else:
        head = b""
    if head[:8] != b"EFI PART":
        # the backup header lives in the last sector
        if image.size >= SECTOR:
            head = image.read(image.size - SECTOR, SECTOR)
        if head[:8] != b"EFI PART":
            return []
    entry_lba = _vol_u64(head, 72)
    count = _vol_u32(head, 80)
    entry_size = _vol_u32(head, 84)
    if not (0 < count <= 8192) or not (128 <= entry_size <= 4096):
        return []
    raw = image.read(entry_lba * SECTOR, count * entry_size)
    out = []
    for i in range(count):
        e = raw[i * entry_size:(i + 1) * entry_size]
        if len(e) < 128 or e[:16] == b"\x00" * 16:
            continue
        first, last = _vol_u64(e, 32), _vol_u64(e, 40)
        if last < first:
            continue
        name = e[56:128].decode("utf-16-le", "replace").split("\x00", 1)[0]
        guid = _guid(e[:16])
        out.append(Volume(image, first * SECTOR, (last - first + 1) * SECTOR,
                          "gpt", i + 1, GPT_TYPES.get(guid, guid.lower()), name))
    return out


# ---------------------------------------------------------------------------
# LUKS
# ---------------------------------------------------------------------------

LUKS_MAGIC = b"LUKS\xba\xbe"


def luks_detail(vol):
    """'' if this is not LUKS, else a description of what is locked up in it."""
    head = vol.read(0, 4096)
    if head[:6] != LUKS_MAGIC:
        return ""
    version = struct.unpack_from(">H", head, 6)[0]
    if version == 1:
        cipher = head[8:40].split(b"\x00", 1)[0].decode("ascii", "replace")
        mode = head[40:72].split(b"\x00", 1)[0].decode("ascii", "replace")
        digest = head[72:104].split(b"\x00", 1)[0].decode("ascii", "replace")
        uuid_s = head[168:208].split(b"\x00", 1)[0].decode("ascii", "replace")
        return "LUKS1 %s-%s, %s, uuid %s" % (cipher, mode, digest, uuid_s)
    if version == 2:
        label = head[24:72].split(b"\x00", 1)[0].decode("utf-8", "replace")
        uuid_s = head[168:208].split(b"\x00", 1)[0].decode("ascii", "replace")
        return "LUKS2%s, uuid %s" % (" '%s'" % label if label else "", uuid_s)
    return "LUKS v%d" % version


# ---------------------------------------------------------------------------
# LVM2
# ---------------------------------------------------------------------------

LVM_LABEL = b"LABELONE"
LVM_MDA_MAGIC = b" LVM2 x[5A%r0N*>"


class LvmPhysicalVolume:
    """One LVM2 physical volume: its identity, its data area, its metadata."""

    def __init__(self, vol, pv_uuid, data_offset, metadata):
        self.volume = vol
        self.uuid = pv_uuid
        self.data_offset = data_offset
        self.metadata = metadata


def read_lvm_label(vol):
    """The LVM2 label in the first four sectors, or None.

    A label is looked for in sectors 0-3 rather than at sector 1, because
    where it lands depends on how the PV was created and a PV whose label sits
    in sector 0 is common enough that assuming sector 1 loses whole volume
    groups.
    """
    for sector in range(4):
        head = vol.read(sector * SECTOR, SECTOR)
        if head[:8] != LVM_LABEL:
            continue
        if head[24:32] != b"LVM2 001":
            continue
        contents = _vol_u32(head, 20)
        body = vol.read(sector * SECTOR + contents, SECTOR)
        pv_uuid = body[:32].decode("ascii", "replace")
        # disk_locn lists: data areas then metadata areas, each zero-terminated
        at = 40
        data_offset = 0
        while at + 16 <= len(body):
            off, size = _vol_u64(body, at), _vol_u64(body, at + 8)
            at += 16
            if off == 0 and size == 0:
                break
            if not data_offset:
                data_offset = off
        mdas = []
        while at + 16 <= len(body):
            off, size = _vol_u64(body, at), _vol_u64(body, at + 8)
            at += 16
            if off == 0 and size == 0:
                break
            mdas.append((off, size))
        text = ""
        for off, size in mdas:
            text = _read_mda(vol, off, size)
            if text:
                break
        if not text:
            return None
        return LvmPhysicalVolume(vol, pv_uuid, data_offset, text)
    return None


def _read_mda(vol, offset, size):
    """The current metadata text out of one metadata area."""
    head = vol.read(offset, 512)
    if head[4:20] != LVM_MDA_MAGIC:
        return ""
    start = _vol_u64(head, 24)
    at = 40
    while at + 24 <= len(head):
        rloc_off, rloc_size = _vol_u64(head, at), _vol_u64(head, at + 8)
        at += 24
        if rloc_off == 0 and rloc_size == 0:
            break
        if rloc_size == 0 or rloc_size > (16 << 20):
            continue
        # the metadata area is a ring buffer: a record can wrap past its end
        area_size = _vol_u64(head, 32) or size
        if rloc_off + rloc_size <= area_size:
            raw = vol.read(start + rloc_off, rloc_size)
        else:
            first = area_size - rloc_off
            raw = (vol.read(start + rloc_off, first)
                   + vol.read(start + 512, rloc_size - first))
        text = raw.decode("utf-8", "replace")
        if "{" in text:
            return text
    return ""


_LVM_TOKEN = re.compile(r'"(?:[^"\\]|\\.)*"|[\[\]{}=,]|#[^\n]*|[^\s\[\]{}=,]+')


def parse_lvm_metadata(text):
    """LVM's own config format -> nested dicts.

    It is not JSON and not YAML: bare keys, '=' for scalars, braces for
    sections, brackets for lists, '#' comments. Small enough to tokenise here
    rather than reach for anything.
    """
    tokens = [t for t in _LVM_TOKEN.findall(text) if not t.startswith("#")]
    pos = [0]

    def value():
        tok = tokens[pos[0]]
        if tok == "[":
            pos[0] += 1
            items = []
            while pos[0] < len(tokens) and tokens[pos[0]] != "]":
                if tokens[pos[0]] == ",":
                    pos[0] += 1
                    continue
                items.append(value())
            pos[0] += 1
            return items
        pos[0] += 1
        if tok.startswith('"'):
            return tok[1:-1].replace('\\"', '"').replace("\\\\", "\\")
        try:
            return int(tok)
        except ValueError:
            return tok

    def section():
        out = {}
        while pos[0] < len(tokens):
            tok = tokens[pos[0]]
            if tok == "}":
                pos[0] += 1
                return out
            pos[0] += 1
            if pos[0] >= len(tokens):
                break
            nxt = tokens[pos[0]]
            if nxt == "{":
                pos[0] += 1
                out[tok.strip('"')] = section()
            elif nxt == "=":
                pos[0] += 1
                out[tok.strip('"')] = value()
        return out

    return section()


class LvmVolume(Image):
    """A logical volume, assembled from the extents its segments name.

    Linear and striped segments are mapped properly. A mirror or a RAID
    segment is read from its first leg, which is the correct copy of the data
    for every layout LVM offers - and is recorded in `detail` so the report
    says which leg was read rather than implying there was only one.
    """

    def __init__(self, vg_name, lv_name, extent_size, segments, pvs):
        self.vg_name = vg_name
        self.lv_name = lv_name
        self.scheme = "lvm"
        self.index = 0
        self.label = "%s/%s" % (vg_name, lv_name)
        self.type_name = "lvm-lv"
        self.fstype = ""
        self.detail = ""
        self._map = []                 # (lv_start, lv_end, pv, pv_offset)
        self.extent_size = extent_size
        total = 0
        stripe_note = ""
        for seg in segments:
            count = seg.get("extent_count", 0)
            length = count * extent_size
            stripes = seg.get("stripes") or []
            kind = seg.get("type", "striped")
            pairs = [(stripes[i], stripes[i + 1])
                     for i in range(0, len(stripes) - 1, 2)]
            if kind in ("mirror", "raid1") or seg.get("mirror_count"):
                pairs = pairs[:1]
                stripe_note = "mirrored, first leg read"
            if len(pairs) <= 1:
                if pairs:
                    pv_name, pv_extent = pairs[0]
                    pv = pvs.get(pv_name)
                    if pv is not None:
                        self._map.append((total, total + length, pv,
                                          pv_extent * extent_size))
                total += length
                continue
            # striped: round-robin in stripe_size chunks across the legs
            stripe_size = seg.get("stripe_size", 128) * SECTOR
            self._map.append(("stripe", total, total + length, pairs, pvs,
                              stripe_size, extent_size))
            stripe_note = "striped over %d" % len(pairs)
            total += length
        self.detail = stripe_note
        Image.__init__(self, self.label, total, "lvm logical volume")
        self.chunk = 1 << 16
        self.cache_entries = 8
        # a logical volume has no offset on any one disk - it is a map, not a
        # window - and the report says so rather than printing a misleading 0
        self.offset = ""

    @property
    def name(self):
        return self.label

    def describe(self):
        bits = [self.label, "lvm-lv", self.fstype or "no filesystem recognised"]
        if self.detail:
            bits.append(self.detail)
        return " | ".join(bits)

    def _pv_read(self, pv, offset, length):
        return pv.volume.read(pv.data_offset + offset, length)

    def _read_raw(self, offset, length):
        if self.size:
            length = min(length, max(0, self.size - offset))
        if length <= 0:
            return b""
        out = bytearray()
        end = offset + length
        for entry in self._map:
            if entry[0] == "stripe":
                _tag, start, stop, pairs, pvs, stripe_size, ext = entry
                if stop <= offset or start >= end:
                    continue
                here = offset + len(out)
                want = min(stop, end) - here
                out += self._read_striped(here - start, want, pairs, pvs,
                                          stripe_size, ext)
                continue
            start, stop, pv, pv_off = entry
            if stop <= offset or start >= end:
                continue
            here = offset + len(out)
            want = min(stop, end) - here
            out += self._pv_read(pv, pv_off + (here - start), want)
        if len(out) < length:
            out += b"\x00" * (length - len(out))
        return bytes(out)

    def _read_striped(self, rel, length, pairs, pvs, stripe_size, ext):
        out = bytearray()
        legs = len(pairs)
        pos = rel
        while len(out) < length:
            index = pos // stripe_size
            leg = index % legs
            round_ = index // legs
            within = pos % stripe_size
            take = min(stripe_size - within, length - len(out))
            pv_name, pv_extent = pairs[leg]
            pv = pvs.get(pv_name)
            if pv is None:
                out += b"\x00" * take
            else:
                at = pv_extent * ext + round_ * stripe_size + within
                out += self._pv_read(pv, at, take)
            pos += take
        return bytes(out)


def build_lvm_volumes(pvs_found):
    """Every logical volume the physical volumes on this disk describe.

    A volume group can span disks. When only some of its physical volumes are
    here, the logical volumes that live entirely on the ones present are still
    readable, and the rest are reported as incomplete rather than half-read -
    an LV missing an extent is a filesystem with a hole in it, and a hole in a
    filesystem is a parse that fails in a way that looks like absence.
    """
    volumes = []
    incomplete = []
    groups = {}                     # vg name -> (metadata, {pv name: PV})
    for pv in pvs_found:
        try:
            meta = parse_lvm_metadata(pv.metadata)
        except Exception:
            continue
        for vg_name, vg in meta.items():
            if not isinstance(vg, dict) or "logical_volumes" not in vg:
                continue
            entry = groups.setdefault(vg_name, [vg, {}])
            for pv_name, pv_meta in (vg.get("physical_volumes") or {}).items():
                if not isinstance(pv_meta, dict):
                    continue
                if pv_meta.get("id", "").replace("-", "") == pv.uuid.replace("-", ""):
                    pv.data_offset = pv_meta.get("pe_start", 2048) * SECTOR
                    entry[1][pv_name] = pv

    for vg_name, (vg, pvs) in groups.items():
        extent_size = vg.get("extent_size", 8192) * SECTOR
        for lv_name, lv in (vg.get("logical_volumes") or {}).items():
            if not isinstance(lv, dict):
                continue
            segments = [lv[k] for k in sorted(lv, key=_segment_key)
                        if k.startswith("segment") and isinstance(lv[k], dict)]
            if not segments:
                continue
            needed = set()
            for seg in segments:
                stripes = seg.get("stripes") or []
                needed.update(stripes[i] for i in range(0, len(stripes) - 1, 2))
            missing = sorted(n for n in needed if n not in pvs)
            if missing:
                incomplete.append("%s/%s needs %s, which %s not on this disk"
                                  % (vg_name, lv_name, ", ".join(missing),
                                     "are" if len(missing) > 1 else "is"))
                continue
            volumes.append(LvmVolume(vg_name, lv_name, extent_size, segments, pvs))
    return volumes, incomplete


def _segment_key(name):
    m = re.match(r"segment(\d+)$", name)
    return (0, int(m.group(1))) if m else (1, name)


# ---------------------------------------------------------------------------
# filesystem identification
# ---------------------------------------------------------------------------

def identify_fs(vol):
    """Name the filesystem on a volume from its superblock magic alone.

    Identification is separate from reading on purpose: a filesystem this tool
    cannot walk still has to appear in the report by name, so that an NTFS
    volume on a dual-boot host reads as "not parsed" instead of vanishing.
    """
    head = vol.read(0, 65536 + 4096)
    if len(head) >= 1080 and head[1080:1082] == b"\x53\xef":
        return _ext_flavour(head)
    if head[:4] == b"XFSB":
        return "xfs"
    if len(head) >= 0x10000 + 0x48 and head[0x10000 + 0x40:0x10000 + 0x48] == b"_BHRfS_M":
        return "btrfs"
    if head[:6] == LUKS_MAGIC:
        return "luks"
    if head[:8] == LVM_LABEL or head[SECTOR:SECTOR + 8] == LVM_LABEL:
        return "lvm2-pv"
    if len(head) >= 4096 and head[4086:4096] == b"SWAPSPACE2":
        return "swap"
    if head[3:11] == b"NTFS    ":
        return "ntfs"
    if head[54:59] == b"FAT12" or head[54:59] == b"FAT16" or head[82:87] == b"FAT32":
        return "fat"
    if head[:4] == b"\x28\xb5\x2f\xfd":
        return ""
    if len(head) >= 0x2000 and head[0x400:0x404] == b"F2FS":
        return "f2fs"
    if head[:2] == b"\x18\xf9" or head[:4] == b"hsqs" or head[:4] == b"sqsh":
        return "squashfs"
    if len(head) >= 0x10000 and head[0x8000:0x8006] == b"\x01CD001":
        return "iso9660"
    return ""


def _ext_flavour(head):
    """ext2, ext3 or ext4, from the feature flags rather than the name."""
    incompat = _vol_u32(head, 1024 + 96)
    compat = _vol_u32(head, 1024 + 92)
    if incompat & 0x40 or incompat & 0x80:          # extents, 64bit
        return "ext4"
    if compat & 0x4 or incompat & 0x4:              # has_journal
        return "ext3"
    return "ext2"


# ---------------------------------------------------------------------------
# the scan
# ---------------------------------------------------------------------------

def scan(image):
    """Every volume on this disk, including the ones inside other volumes.

    Returns (volumes, notes). `notes` carries what the scan could see but not
    open - an encrypted partition, a volume group missing a disk - so that
    nothing found is ever indistinguishable from nothing there.
    """
    notes = []
    partitions = read_gpt(image) or read_mbr(image)
    scheme = "gpt" if partitions and partitions[0].scheme == "gpt" else \
             ("mbr" if partitions else "none")
    if not partitions:
        whole = Volume(image, 0, image.size, "whole", 0, "whole disk")
        partitions = [whole]

    out = []
    pvs = []
    for vol in partitions:
        vol.fstype = identify_fs(vol)
        if vol.fstype == "luks":
            vol.detail = luks_detail(vol)
            notes.append("%s is encrypted (%s) - decrypt with cryptsetup and "
                         "point linsight at the mapped device"
                         % (vol.name, vol.detail or "LUKS"))
            out.append(vol)
            continue
        if vol.fstype == "lvm2-pv":
            pv = read_lvm_label(vol)
            if pv is None:
                notes.append("%s carries an LVM2 label whose metadata could "
                             "not be read" % vol.name)
            else:
                pvs.append(pv)
            out.append(vol)
            continue
        out.append(vol)

    if pvs:
        lvs, incomplete = build_lvm_volumes(pvs)
        notes.extend(incomplete)
        for lv in lvs:
            lv.fstype = identify_fs(lv)
            if lv.fstype == "luks":
                lv.detail = ((lv.detail + "; ") if lv.detail else "") + \
                            (luks_detail(lv) or "LUKS")
                notes.append("%s is encrypted (%s)" % (lv.label, lv.detail))
        out.extend(lvs)
        if not lvs and not incomplete:
            notes.append("an LVM2 physical volume was found but it describes "
                         "no logical volumes")
    return out, notes, scheme


#: filesystems this tool can walk, best first when choosing a root
READABLE_FS = ("ext4", "ext3", "ext2", "xfs", "btrfs")
