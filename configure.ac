# This file is part of pam-modules.       -*- autoconf -*-
# Copyright (C) 2005, Sergey Poznyakoff
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

AC_PREREQ(2.53)

AC_INIT(pam-modules, 0.1, gray@mirddin.farlep.net)
AC_CONFIG_SRCDIR(pam_fshadow/pam_fshadow.c)
AC_CONFIG_AUX_DIR([scripts])
AM_INIT_AUTOMAKE(no-exeext)
AM_CONFIG_HEADER(config.h)

dnl Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AM_PROG_LIBTOOL

dnl Checks for libraries.

dnl Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS(fcntl.h syslog.h unistd.h)
AC_CHECK_HEADER(shadow.h,
                [],
                [AC_MSG_ERROR(shadow.h is not present on your system)])

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST

dnl Checks for library functions.
AC_CHECK_FUNCS(strerror)
AC_CHECK_FUNC(fgetspent,
              [],
              [AC_MSG_ERROR(fgetspent is not present on your system)])
AC_CHECK_FUNC(fgetpwent,
              [],
              [AC_MSG_ERROR(fgetspent is not present on your system)])

## **************
## Directories
## **************
PAMDIR='$(prefix)/lib/security'
AC_ARG_WITH(pamdir,
	[  --with-pamdir=DIR             install PAM modiles in DIR [PREFIX/lib/security]],
	[PAMDIR=$withval])
AC_SUBST(PAMDIR)

AC_OUTPUT(Makefile
          doc/Makefile 
	  pam_fshadow/Makefile
          pam_regex/Makefile)
