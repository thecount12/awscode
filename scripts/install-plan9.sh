#!/bin/sh
# script to install plan9

kvm=-enable-kvm

flags="−net nic,model=virtio,macaddr=52:54:00:00:EE:03 −net user \
−device virtio−scsi−pci,id=scsi \
−drive if=none,id=vd0,file=9front.qcow2.img \
−device scsi−hd,drive=vd0 \
−drive if=none,id=vd1,file=9front.iso \
−device scsi−cd,drive=vd1,bootindex=0"


qemu-system-x86_64 -cpu host $kvm -m 2G $flags

