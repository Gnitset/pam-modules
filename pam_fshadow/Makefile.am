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
pam_PROGRAMS = pam_fshadow.la
AM_INSTALLCHECK_STD_OPTIONS_EXEMPT = pam_fshadow.la
pam_fshadow_la_SOURCES = pam_fshadow.c
pam_fshadow_la_LDADD = -lpam  
AM_LDFLAGS = -version-info @VI_CURRENT@:@VI_REVISION@:@VI_AGE@
AM_CPPFLAGS=-DMODULE_NAME=\"pam_fshadow\" -DSYSCONFDIR=\"${sysconfdir}\"
INCLUDES=@PAM_COMMON_INCLUDES@
NORMAL_UNINSTALL = -rm -f $(DESTDIR)$(pamdir)/pam_fshadow.a $(DESTDIR)$(pamdir)/pam_fshadow.so.@VI_CURRENT@.@VI_REVISION@.@VI_AGE@

pam_fshadow.lo: $(srcdir)/pam_fshadow.c
	$(LIBTOOL) --mode=compile $(CC) -c -DHAVE_CONFIG_H \
                $(CFLAGS) $(AM_CFLAGS) $(AM_CPPFLAGS) $(INCLUDES) $<

pam_fshadow.la$(EXEEXT): pam_fshadow.lo
	$(LIBTOOL) --mode=link $(CC) -module -export-dynamic \
                   $(AM_LDFLAGS) \
                 -o $@ $< $(pam_fshadow_la_LDADD) $(AM_LDADD) $(LDADD) \
                 -rpath $(pamdir)
