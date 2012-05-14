#! /bin/sh
set -e
git submodule init
git submodule update
test -d m4 || mkdir m4
autoreconf -f -i -s 
