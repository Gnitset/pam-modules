#! /bin/sh

aclocal &&
 libtoolize --automake -c &&
 autoheader &&
 automake -a -c &&
 autoconf

if [ ! -d scripts ]; then
	mkdir scripts
fi
