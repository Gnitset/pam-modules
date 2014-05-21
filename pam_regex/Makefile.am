# This file is part of pam-modules.
# Copyright (C) 2001, 2006, 2008-2012, 2014 Sergey Poznyakoff
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program.  If not, see <http://www.gnu.org/licenses/>.

include $(top_srcdir)/Make.rules

pamdir=@PAMDIR@
PAM_REGEX = 
pam_LTLIBRARIES = pam_regex.la
pam_regex_la_SOURCES = pam_regex.c
AM_CPPFLAGS += -DMODULE_NAME=\"pam_regex\" -DSYSCONFDIR=\"${sysconfdir}\"
