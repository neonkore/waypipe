#!/bin/bash

set -e -o xtrace

dpkg --print-foreign-architectures
dpkg --add-architecture i386

apt-get update

# Actual package dependencies
apt-get -y --no-install-recommends install wayland-protocols:i386 pkg-config:i386 libwayland-dev:i386 libgbm-dev:i386 liblz4-dev:i386 libzstd-dev:i386 libavcodec-dev:i386 libavutil-dev:i386 libswscale-dev:i386 weston:i386  libdrm-dev:i386
apt-get -y --no-install-recommends install gcc-8-multilib:i386 gcc-8:i386 make:i386

# Build scripts, architecture doesn't matter
apt-get -y --no-install-recommends install git python3-pip python3-wheel python3-setuptools ninja-build scdoc
pip3 install --user git+https://github.com/mesonbuild/meson.git@0.47

