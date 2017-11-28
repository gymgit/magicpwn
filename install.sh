#!/bin/bash
# TODO
# install basics virtalenv, python, gdb, build tools, binwalk...

# start/create venv
workon ctf || mkvirtualenv -p /usr/bin/python2 ctf

# pip install/upgrade packages
pip install --upgrade pip
pip install --upgrade angr pwntools

# get tools
git clone https://github.com/zardus/preeny.git

curl -O http://lcamtuf.coredump.cx/afl/releases/afl-latest.tgz
mkdir afl-latest && tar xf afl-latest.tgz -C afl-latest --strip-components=1
cd afl-latest
make
cd qemu-mode
./build_qemu_support.sh
# TODO CPU support + fix regexp issue

git clone https://github.com/wapiflapi/villoc.git
