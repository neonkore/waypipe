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
python3 ../protocols/symgen.py data ../protocols/function_list.txt protocols.c \
    ../protocols/*.xml
python3 ../protocols/symgen.py header ../protocols/function_list.txt protocols.h \
    ../protocols/*.xml
echo '#define WAYPIPE_VERSION "minimal"' > config-waypipe.h

echo "Compiling..."
gcc -D_DEFAULT_SOURCE -I. -I../protocols/ -lpthread -o waypipe protocols.c \
    ../src/bench.c ../src/client.c ../src/dmabuf.c ../src/handlers.c \
    ../src/interval.c ../src/kernel.c ../src/mainloop.c ../src/parsing.c \
    ../src/platform.c ../src/server.c ../src/shadow.c ../src/util.c \
    ../src/video.c ../src/waypipe.c

cd ..
echo "Done. See ./build-minimal/waypipe"
