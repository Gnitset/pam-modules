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
pam_PROGRAMS = pam_fshadow.la
pam_fshadow_la_SOURCES = pam_fshadow.c
pam_fshadow_la_LDADD = -lpam 
AM_CPPFLAGS=-DSYSCONFDIR=\"${sysconfdir}\"
INCLUDES=-I$(top_builddir)
NORMAL_UNINSTALL = -rm -f $(DESTDIR)$(pamdir)/pam_fshadow.a $(DESTDIR)$(pamdir)/pam_fshadow.so.0.0.0

pam_fshadow.lo: $(srcdir)/pam_fshadow.c
	$(LIBTOOL) --mode=compile $(CC) -c -DHAVE_CONFIG_H \
                $(CFLAGS) $(AM_CFLAGS) $(AM_CPPFLAGS) $(INCLUDES) $<

pam_fshadow.la$(EXEEXT): pam_fshadow.lo
	$(LIBTOOL) --mode=link $(CC) -module -export-dynamic \
                 -o $@ $< $(pam_fshadow_la_LDADD) \
                 -rpath $(pamdir)
