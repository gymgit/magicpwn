#!/bin/bash
set -e

if [ "$#" -ne 1 ];then
    echo "Usage $0 vm/name"
    exit 1
fi

folder="${1##*/}"
name=$1
box_path="$HOME/ctf/vagrant/$folder"

echo "Getting the vagrant box: $name"
vagrant box add $name
echo "Creating folder for vm at $box_path"
mkdir -p $box_path
echo "Copy over default vagrant file"
cp $HOME/ctf/vagrant/_Vagrantfile $box_path/Vagrantfile
echo "Copy over ssh pub key"
cp $HOME/.ssh/id_rsa.pub $box_path
echo "VM skeleton is created review $folder/Vagrantfile then use 'vagrant up' to finish the provisioning"
