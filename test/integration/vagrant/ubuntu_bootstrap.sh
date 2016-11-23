apt-get install -y make gcc libelf-dev

apt-get install -y dpkg-dev
apt-get build-dep -y linux

# optional, but highly recommended
apt-get install -y ccache
ccache --max-size=5G

# Add ddebs repository
codename=$(lsb_release -sc)
sudo tee /etc/apt/sources.list.d/ddebs.list << EOF
deb http://ddebs.ubuntu.com/ ${codename} main restricted universe multiverse
deb http://ddebs.ubuntu.com/ ${codename}-security main restricted universe multiverse
deb http://ddebs.ubuntu.com/ ${codename}-updates main restricted universe multiverse
deb http://ddebs.ubuntu.com/ ${codename}-proposed main restricted universe multiverse
EOF

# add APT key
wget -Nq http://ddebs.ubuntu.com/dbgsym-release-key.asc -O- | sudo apt-key add -
sudo apt-get update && sudo apt-get install -y linux-image-$(uname -r)-dbgsym

sudo apt-get install -y git patchutils
