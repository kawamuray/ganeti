#!/bin/sh

make clean
./autogen.sh
./configure --enable-symlinks --with-haskell-flags="\
-hide-package=monads-tf \
-hide-package=regex-pcre-builtin \
"
make -j2
