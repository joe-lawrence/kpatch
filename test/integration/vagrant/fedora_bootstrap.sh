#!/bin/bash

UNAME=$(uname -r)

sudo dnf install -y gcc kernel-devel-${UNAME%.*} elfutils elfutils-devel
sudo dnf install -y rpmdevtools pesign yum-utils openssl wget numactl-devel
sudo dnf builddep -y kernel-${UNAME%.*}
sudo dnf debuginfo-install -y kernel-${UNAME%.*}
sudo dnf install -y ccache
ccache --max-size=5G

sudo dnf install -y git patchutils
