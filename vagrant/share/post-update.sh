#!/bin/bash
set -x
mkdir -p /vagrant/sysroot
rsync -rl --copy-unsafe-links /lib /vagrant/sysroot/
rsync -rl --copy-unsafe-links /lib64 /vagrant/sysroot/
mkdir -p /vagrant/sysroot/usr/lib/debug
rsync -rl --copy-unsafe-links /usr/lib/debug /vagrant/sysroot/usr/lib/
rsync -rl --copy-unsafe-links /usr/lib/debug/lib/x86_64-linux-gnu/* /vagrant/sysroot/lib/x86_64-linux-gnu/.debug/
rsync -rl --copy-unsafe-links /usr/lib/debug/lib/i386-linux-gnu/* /vagrant/sysroot/lib/i386-linux-gnu/.debug/
rsync -rl --copy-unsafe-links /usr/lib/x86_64-linux-gnu /vagrant/sysroot/usr/lib/
mkdir -p /vagrant/libcs
cp /lib/x86_64-linux-gnu/libc-2.*.so /vagrant/libcs/libc-amd64.so
cp /lib/i386-linux-gnu/libc-2.*.so /vagrant/libcs/libc-i386.so
