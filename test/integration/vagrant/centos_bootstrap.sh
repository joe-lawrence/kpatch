#!/bin/bash

UNAME=$(uname -r)

sudo yum install -y gcc kernel-devel-${UNAME%.*} elfutils elfutils-devel
sudo yum install -y rpmdevtools pesign yum-utils zlib-devel \
  binutils-devel newt-devel python-devel perl-ExtUtils-Embed \
  audit-libs audit-libs-devel numactl-devel pciutils-devel bison
sudo yum-config-manager --enable debug
sudo yum-builddep -y kernel-${UNAME%.*}
sudo yum install -y ncurses-devel		# bug in builddep?
sudo debuginfo-install -y kernel-${UNAME%.*}
sudo yum install -y epel-release
sudo yum install -y ccache
ccache --max-size=5G

sudo yum install -y git patchutils
