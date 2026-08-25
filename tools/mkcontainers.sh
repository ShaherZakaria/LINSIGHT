#!/bin/sh
# Wrap a raw fixture in every container format the image layer claims to read.
#
# These are produced by the tools that actually write these formats - qemu-img
# and ewfacquire - and not by this project. That is the point: a fixture this
# repository generates and then reads back only proves the reader agrees with
# itself, which is exactly the kind of test that passes while the tool cannot
# open a real image from a real imager.
#
#   sh tools/mkcontainers.sh [outdir]        # default tests/fixtures
#
# Neither tool needs root. Both can be unpacked from their .deb into a
# directory if the box will not install them - see tools/mkfixtures.sh for the
# same trick and the same reason.

set -e
OUT=${1:-tests/fixtures}
SRC="$OUT/mbr-ext4.dd"
[ -f "$SRC" ] || { echo "[!] $SRC not there - run tools/mkfixtures.sh first" >&2; exit 1; }

if [ -d "$HOME/lt/root" ]; then
    PATH="$HOME/lt/root/usr/bin:$HOME/lt/root/usr/sbin:$HOME/lt/root/sbin:$PATH"
    LD_LIBRARY_PATH="$HOME/lt/root/usr/lib/x86_64-linux-gnu:$HOME/lt/root/lib/x86_64-linux-gnu:$LD_LIBRARY_PATH"
    export PATH LD_LIBRARY_PATH
fi

have() { command -v "$1" >/dev/null 2>&1; }

if have qemu-img; then
    echo "[*] qemu-img: $(qemu-img --version | head -1)"
    # qcow2 v3 (the default), v2, and one with the clusters deflated - the
    # compressed path is a different branch of the reader entirely
    rm -f "$OUT/disk.qcow2" "$OUT/disk-v2.qcow2" "$OUT/disk-compressed.qcow2"
    qemu-img convert -f raw -O qcow2 "$SRC" "$OUT/disk.qcow2"
    qemu-img convert -f raw -O qcow2 -o compat=0.10 "$SRC" "$OUT/disk-v2.qcow2"
    qemu-img convert -f raw -O qcow2 -c "$SRC" "$OUT/disk-compressed.qcow2"
    echo "  qcow2 v3 / v2 / compressed"

    # a backing chain: an overlay holding one changed cluster over a base. A
    # reader that opens only the top layer of one of these returns a disk with
    # holes in it, so the fixture exists to catch exactly that.
    rm -f "$OUT/disk-overlay.qcow2"
    qemu-img create -f qcow2 -b "$(basename "$OUT/disk.qcow2")" -F qcow2 \
        "$OUT/disk-overlay.qcow2" >/dev/null
    echo "  qcow2 overlay over a backing file"

    # vmdk: the monolithic sparse form, the stream-optimised (deflated) form,
    # and the 2 GB split that VMware writes for FAT-era datastores
    rm -f "$OUT"/disk*.vmdk
    qemu-img convert -f raw -O vmdk "$SRC" "$OUT/disk.vmdk"
    qemu-img convert -f raw -O vmdk -o subformat=streamOptimized \
        "$SRC" "$OUT/disk-stream.vmdk"
    qemu-img convert -f raw -O vmdk -o subformat=twoGbMaxExtentSparse \
        "$SRC" "$OUT/disk-split.vmdk"
    qemu-img convert -f raw -O vmdk -o subformat=monolithicFlat \
        "$SRC" "$OUT/disk-flat.vmdk"
    echo "  vmdk sparse / streamOptimized / twoGbMaxExtentSparse / flat"

    rm -f "$OUT/disk.vhdx" "$OUT/disk.vhd" "$OUT/disk-fixed.vhd"
    qemu-img convert -f raw -O vhdx "$SRC" "$OUT/disk.vhdx"
    qemu-img convert -f raw -O vpc "$SRC" "$OUT/disk.vhd"
    qemu-img convert -f raw -O vpc -o subformat=fixed "$SRC" "$OUT/disk-fixed.vhd"
    echo "  vhdx, vhd dynamic, vhd fixed"

    rm -f "$OUT/disk.vdi"
    qemu-img convert -f raw -O vdi "$SRC" "$OUT/disk.vdi"
    echo "  vdi (which linsight refuses by name, and is here to prove it does)"
else
    echo "[!] qemu-img not found - no qcow2/vmdk/vhdx fixtures"
fi

if have ewfacquire; then
    echo "[*] ewfacquire"
    rm -f "$OUT"/disk.E* "$OUT"/disk-split.E*
    # -u unattended, -c deflate:best compression, -S segment size, -f encase6
    ewfacquire -u -t "$OUT/disk" -f encase6 -c deflate:fast -S 1GiB \
        -C 1 -D linsight -e analyst -E 1 -N "compressed single segment" \
        -m fixed -M logical "$SRC" >/dev/null 2>&1 && echo "  disk.E01"
    # a multi-segment set, because chunk numbering runs across segments and a
    # reader that restarts it per segment reads the same 64 MB over and over
    ewfacquire -u -t "$OUT/disk-split" -f encase6 -c deflate:fast -S 32MiB \
        -C 2 -D linsight -e analyst -E 2 -N "multi segment" \
        -m fixed -M logical "$SRC" >/dev/null 2>&1 && \
        echo "  disk-split.E01 (+ $(ls "$OUT"/disk-split.E?? 2>/dev/null | wc -l) segments)"
    # and one with no compression at all: the uncompressed chunk path never
    # runs on a compressed set, so without this it is never exercised
    rm -f "$OUT"/disk-raw.E*
    ewfacquire -u -t "$OUT/disk-raw" -f encase6 -c none -S 1GiB \
        -C 3 -D linsight -e analyst -E 3 -N "uncompressed" \
        -m fixed -M logical "$SRC" >/dev/null 2>&1 && echo "  disk-raw.E01"
else
    echo "[!] ewfacquire not found - no E01 fixtures"
fi

echo "[+] containers in $OUT"
ls -la "$OUT" | grep -Ei "qcow2|vmdk|vhdx|vhd$|\.E[0-9]|vdi" || true
