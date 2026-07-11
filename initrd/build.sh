#!/bin/sh

cd "$(dirname "$(realpath "$0")")"

rm -rf ./initrd
install -m 755 -o +0 -g +0 -d ./initrd
cd ./initrd

install -m 755 -o +0 -g +0 -d ./dev
install -m 755 -o +0 -g +0 -d ./new_root
install -m 755 -o +0 -g +0 -d ./proc
install -m 755 -o +0 -g +0 -d ./run
install -m 755 -o +0 -g +0 -d ./sys
install -m 755 -o +0 -g +0 -d ./tmp
install -m 755 -o +0 -g +0 -d ./usr
install -m 755 -o +0 -g +0 -d ./usr/bin
install -m 755 -o +0 -g +0 -d ./usr/lib
install -m 755 -o +0 -g +0 -d ./var

ln -s usr/bin ./bin
ln -s usr/bin ./sbin
ln -s bin ./usr/sbin
ln -s usr/lib ./lib
ln -s usr/lib ./lib64
ln -s lib ./usr/lib64
ln -s ../run ./var/run

# Install busybox
install -m 755 -o +0 -g +0 "$(which busybox)" ./usr/bin/busybox
while IFS= read -r line; do
    busybinPath="./usr/bin/$line"
    if [ ! -f "$busybinPath" ]; then
        ln -s busybox "$busybinPath"
    fi
done < <(./usr/bin/busybox --list)

# Binaries
cryptsetup
blkid
dmsetup
kmod
mount
setleds
switch_root
systemd-tmpfiles
udevadm
umount


