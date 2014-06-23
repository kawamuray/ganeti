#!/bin/sh

make clean
./autogen.sh
./configure \
    --enable-symlinks \
    --with-os-search-path=/usr/local/share/ganeti/os \
    --with-ssh-initscript=/etc/init.d/sshd \
    --with-haskell-flags="\
-hide-package=monads-tf \
-hide-package=regex-pcre-builtin \
"
make -j4
