#!/bin/bash
set -e

git submodule update --init

if [ "$OS" = "Windows_NT" ]; then
    ./mingw64.sh
    exit 0
fi

make clean || echo clean

rm -f config.status
./autogen.sh

if [[ "$OSTYPE" == "darwin"* ]]; then
    ./nomacro.pl
    ./configure \
        CFLAGS="-march=native -O2 -Ofast -flto -DUSE_ASM" \
        --with-crypto=/opt/homebrew/opt/openssl \
        --with-curl=/opt/homebrew/opt/curl
    make -j4
    strip cpuminer
    exit 0
fi

# Linux build

# Ubuntu 10.04 (gcc 4.4)
# extracflags="-O3 -march=native -Wall -D_REENTRANT -funroll-loops -fvariable-expansion-in-unroller -fmerge-all-constants -fbranch-target-load-optimize2 -fsched2-use-superblocks -falign-loops=16 -falign-functions=16 -falign-jumps=16 -falign-labels=16"

# Debian 7.7 / Ubuntu 14.04 (gcc 4.7+)
extracflags="$extracflags -Ofast -flto -fuse-linker-plugin"

if [ ! "0" = `cat /proc/cpuinfo | grep -c avx` ]; then
    # march native doesn't always works, ex. some Pentium Gxxx (no avx)
    extracflags="$extracflags -march=native"
fi

./configure --with-crypto --with-curl CFLAGS="-O2 $extracflags -DUSE_ASM"

make -j 4

strip -s cpuminer
