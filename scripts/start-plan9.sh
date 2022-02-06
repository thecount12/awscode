#!/bin/sh
# 9qemu: wrapper script for launching Plan 9 in qemu
# usage: 9qemu disk [args...]

disk=$1 && shift
if [ $(uname -s) = Linux ]; then
    # non-linux systems may not have this
    kvm=-enable-kvm
fi
flags="-net nic,model=virtio,macaddr=52:54:00:12:34:56 \
    -net user,hostfwd=tcp::17010-:17010,hostfwd=tcp::17019-:17019,\
    hostfwd=tcp::17020-:17020,hostfwd=tcp::12567-:567 \
    -device virtio-scsi-pci,id=scsi -device scsi-hd,drive=vd0 \
    -device sb16 -vga std -drive if=none,id=vd0,file=$disk"

qemu-system-x86_64 $kvm -m 2G $flags $*
