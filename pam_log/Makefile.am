# Copyright (C) 2006 Sergey Poznyakoff
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA 02110-1301 USA 

pamdir=@PAMDIR@
pam_PROGRAMS = pam_log.la
AM_INSTALLCHECK_STD_OPTIONS_EXEMPT = pam_log.la
pam_log_la_SOURCES = pam_log.c
pam_log_la_LDADD = -lpam 
AM_LDFLAGS = -version-info @VI_CURRENT@:@VI_REVISION@:@VI_AGE@
AM_CPPFLAGS=-DSYSCONFDIR=\"${sysconfdir}\"
INCLUDES=@PAM_COMMON_INCLUDES@
NORMAL_UNINSTALL = -rm -f $(DESTDIR)$(pamdir)/pam_log.a $(DESTDIR)$(pamdir)/pam_log.so.@VI_CURRENT@.@VI_REVISION@.@VI_AGE@

pam_log.lo: $(srcdir)/pam_log.c
	$(LIBTOOL) --mode=compile $(CC) -c -DHAVE_CONFIG_H \
                $(CFLAGS) $(AM_CFLAGS) $(AM_CPPFLAGS) $(INCLUDES) $<

pam_log.la$(EXEEXT): pam_log.lo
	$(LIBTOOL) --mode=link $(CC) -module -export-dynamic \
                 $(AM_LDFLAGS) \
                 -o $@ $< $(pam_log_la_LDADD) $(AM_LDADD) $(LDADD)\
                 -rpath $(pamdir)
