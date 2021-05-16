#!/bin/sh
set -e

echo "This script is a backup build system in case meson/ninja are unavailable."
echo "No optional features or optimizations are included. Waypipe will be slow."
echo "Requirements: python3, gcc, libc+pthreads"
echo "Enter to continue, interrupt to exit."
read unused

mkdir -p build-minimal
cd build-minimal

echo "Generating code..."
for proto in \
    gtk-primary-selection \
    input-method-unstable-v2 \
    linux-dmabuf-unstable-v1 \
    presentation-time \
    primary-selection-unstable-v1 \
    virtual-keyboard-unstable-v1 \
    wayland-drm \
    wayland \
    wlr-data-control-unstable-v1 \
    wlr-export-dmabuf-unstable-v1 \
    wlr-gamma-control-unstable-v1 \
    wlr-screencopy-unstable-v1 \
    xdg-shell
do
   python3 ../protocols/symgen.py data ../protocols/function_list.txt ../protocols/$proto.xml protocol-$proto.c
   python3 ../protocols/symgen.py header ../protocols/function_list.txt ../protocols/$proto.xml protocol-$proto.h
done
echo '#define WAYPIPE_VERSION "minimal"' > config-waypipe.h

echo "Compiling..."
gcc -D_DEFAULT_SOURCE -I. -I../protocols/ -lpthread -o waypipe protocol-*.c \
    ../src/bench.c ../src/client.c ../src/dmabuf.c ../src/handlers.c \
    ../src/interval.c ../src/kernel.c ../src/mainloop.c ../src/parsing.c \
    ../src/platform.c ../src/server.c ../src/shadow.c ../src/util.c \
    ../src/video.c ../src/waypipe.c

cd ..
echo "Done. See ./build-minimal/waypipe"
