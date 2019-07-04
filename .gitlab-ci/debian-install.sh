#!/bin/bash

set -e -o xtrace

apt-get update
apt-get -y --no-install-recommends install \
	build-essential git automake autoconf libtool pkg-config libexpat1-dev \
	libffi-dev libxml2-dev mesa-common-dev libglu1-mesa-dev libegl1-mesa-dev \
	libgles2-mesa-dev libwayland-dev libudev-dev libgbm-dev libxkbcommon-dev \
	libvpx-dev libva-dev curl python3-pip python3-setuptools ninja-build weston \
	liblz4-dev libzstd-dev wayland-protocols libavcodec-dev libavutil-dev \
	libswscale-dev

pip3 install --user git+https://github.com/mesonbuild/meson.git@0.47

