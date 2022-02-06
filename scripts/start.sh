#!/bin/bash
# script to start plan9 server
# should use screen to get this started
# works on plan9 on AWS
# sudo ./start.sh needed for port 80

qemu-system-x86_64 -nographic -hda 9front.img -m 1024 -netdev \
user,id=mynet0,hostfwd=tcp::17010-:17010,hostfwd=tcp::17019-:17019,\
hostfwd=tcp::17020-:17020,hostfwd=tcp::567-:567,\
hostfwd=tcp::564-:564,\
hostfwd=tcp::80-:80 \
-device e1000,netdev=mynet0

