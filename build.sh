#!/bin/sh

make clean
./autogen.sh
./configure --enable-symlinks --with-haskell-flags='-hide-package=monads-tf'
make -j2
