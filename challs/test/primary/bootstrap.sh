#!/bin/bash
VAGRANT_SHARE="/home/gym/ctf/vagrant/share"
set -e

if [[ $# -ne 1 && $# -ne 2 ]]; then
    echo "Usage: $0 BINARY [LIBC]"
    exit 1
fi

if [[ $# -eq 2 ]]; then
    echo "[+] Copy libc: $2 to vagrant share: $VAGRANT_SHARE"
    cp $2 $VAGRANT_SHARE
fi

echo "[+] Chmod binary: $1"
chmod +x $1

echo "[+] Copy binary: $1 to vagrant share: $VAGRANT_SHARE"
cp $1 $VAGRANT_SHARE

if [ -e "./notes.txt" ]; then
    echo "[+] notes.txt already exists"
else
    echo "[+] Setting up notes.txt"
    echo "### Primitives/Capabilities" >> notes.txt
    echo "" >> notes.txt
    echo "### Vulns" >> notes.txt
    echo "" >> notes.txt
    echo "### Exploit" >> notes.txt
    echo "" >> notes.txt
    echo "### Notes" >> notes.txt
    echo "## Menu" >> notes.txt
    echo "" >> notes.txt
    echo "## Funcs" >> notes.txt
    echo "" >> notes.txt
    echo "### File" >> notes.txt
    file $1 >> notes.txt
    echo "" >> notes.txt
    echo "### Checsec" >> notes.txt
    checksec --file $1 | sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]//g" >> notes.txt
fi

echo "[+] File $1"
file $1
echo "[+] Checkses $1"
checksec --file $1


