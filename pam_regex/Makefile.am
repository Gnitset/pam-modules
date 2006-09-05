# Copyright (C) 2001, 2006 Sergey Poznyakoff
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
pam_PROGRAMS = pam_regex.la
pam_regex_la_SOURCES = pam_regex.c
AM_INSTALLCHECK_STD_OPTIONS_EXEMPT = pam_regex.la
pam_regex_la_LDADD = -lpam 
AM_LDFLAGS = -version-info @VI_CURRENT@:@VI_REVISION@:@VI_AGE@
AM_CPPFLAGS=-DSYSCONFDIR=\"${sysconfdir}\"
INCLUDES=@PAM_COMMON_INCLUDES@
NORMAL_UNINSTALL = -rm -f $(DESTDIR)$(pamdir)/pam_regex.a $(DESTDIR)$(pamdir)/pam_regex.so.@VI_CURRENT@.@VI_REVISION@.@VI_AGE@

pam_regex.lo: $(srcdir)/pam_regex.c
	$(LIBTOOL) --mode=compile $(CC) -c -DHAVE_CONFIG_H \
                $(CFLAGS) $(AM_CFLAGS) $(AM_CPPFLAGS) $(INCLUDES) $<

pam_regex.la$(EXEEXT): pam_regex.lo
	$(LIBTOOL) --mode=link $(CC) -module -export-dynamic \
                 $(AM_LDFLAGS) \
                 -o $@ $< $(pam_regex_la_LDADD) $(AM_LDADD) $(LDADD)\
                 -rpath $(pamdir)
