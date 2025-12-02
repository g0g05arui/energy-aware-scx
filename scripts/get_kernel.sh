#!/bin/bash

sudo dkms remove emulab-ipod-dkms/3.5.0 --all
sudo rm -rf /var/lib/dkms/emulab-ipod-dkms
sudo apt purge emulab-ipod-dkms

sudo apt --fix-broken install
sudo dpkg --configure -a

wget https://raw.githubusercontent.com/pimlie/ubuntu-mainline-kernel.sh/master/ubuntu-mainline-kernel.sh
sudo install ubuntu-mainline-kernel.sh /usr/local/bin/
sudo ubuntu-mainline-kernel.sh -i v6.14.1

sudo update-grub 

sudo reboot
