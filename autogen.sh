#! /bin/sh

if [ ! -d scripts ]; then
	mkdir scripts
fi
aclocal &&
 libtoolize --automake -c &&
 autoheader &&
 automake -a -c &&
 autoconf

