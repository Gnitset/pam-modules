# Copyright (C) 2001, Sergey Poznyakoff
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

pamdir=@PAMDIR@
pam_PROGRAMS = pam_regex.la
pam_regex_la_SOURCES = pam_regex.c
pam_regex_la_LDADD = -lpam 
AM_CPPFLAGS=-DSYSCONFDIR=\"${sysconfdir}\"
INCLUDES=-I$(top_builddir)
NORMAL_UNINSTALL = -rm -f $(DESTDIR)$(pamdir)/pam_regex.a $(DESTDIR)$(pamdir)/pam_regex.so.0.0.0

pam_regex.lo: $(srcdir)/pam_regex.c
	$(LIBTOOL) --mode=compile $(CC) -c -DHAVE_CONFIG_H \
                $(CFLAGS) $(AM_CFLAGS) $(AM_CPPFLAGS) $(INCLUDES) $<

pam_regex.la$(EXEEXT): pam_regex.lo
	$(LIBTOOL) --mode=link $(CC) -module -export-dynamic \
                 -o $@ $< $(pam_regex_la_LDADD) \
                 -rpath $(pamdir)
