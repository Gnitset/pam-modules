#! /bin/sh

aclocal &&
 libtoolize --automake -c &&
 autoheader &&
 automake -a -c &&
 autoconf
