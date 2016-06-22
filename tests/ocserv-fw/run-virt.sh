#!/usr/bin/env bash

# Copyright (C) 2016  Lance LeFlore

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.


# Note: Should you change OCSERV_CLIENT_IPADDR in run-assertions.sh, be certain 
# to also change it in the virt-builder firstboot-commands below.

set -euf -o pipefail

export GUESTNAME="ocserv-fw-test"
export VDISK_PATH="/var/lib/libvirt/images/${GUESTNAME}.img"
# Helpful libguestfs environment variables should we run into trouble:
#export LIBGUESTFS_BACKEND=direct
#export LIBGUESTFS_DEBUG=1
#export LIBGUESTFS_TRACE=1

sudo virt-builder centos-7.2 \
  --output ${VDISK_PATH} \
  --size 8G \
  --format qcow2 \
  --arch x86_64 \
  --hostname ${GUESTNAME} \
  --root-password password:changeme \
  --install bind-utils,curl \
  --upload run-assertions.sh:/usr/bin \
  --upload assertions.sh:/usr/bin \
  --upload ../../src/ocserv-fw:/usr/bin \
  --run-command 'rm -f /etc/systemd/system/basic.target.wants/firewalld.service' \
  --selinux-relabel \
  --firstboot-command 'iptables -P FORWARD DROP' \
  --firstboot-command 'echo 1 > /proc/sys/net/ipv4/ip_forward' \
  --firstboot-command 'iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -j MASQUERADE' \
  --firstboot-command 'run-assertions.sh &> /root/ocserv-fw.log'

sudo virt-install \
  --name ${GUESTNAME} \
  --ram 2048 \
  --cpu host \
  --vcpus 1 \
  --video qxl \
  --channel spicevmc \
  --noautoconsole \
  --os-type=linux \
  --os-variant=centos7.0 \
  --disk ${VDISK_PATH} \
  --boot hd,network,cdrom,menu=off \
  --network network=default
