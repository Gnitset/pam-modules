# This file is part of pam-modules.       -*- autoconf -*-
# Copyright (C) 2005, 2006 Sergey Poznyakoff
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

AC_INIT(pam-modules, 1.0, gray@gnu.org.ua)
AC_CONFIG_SRCDIR(pam_fshadow/pam_fshadow.c)
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE(no-exeext)
AM_CONFIG_HEADER(config.h)

dnl Library versioning
AC_SUBST(VI_CURRENT,1)
AC_SUBST(VI_REVISION,0)
AC_SUBST(VI_AGE,0)
AC_SUBST(PAM_COMMON_INCLUDES, '-I${top_builddir} -I${top_srcdir}')
	
dnl Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AM_PROG_LIBTOOL

dnl Checks for libraries.
AC_CHECK_LIB(crypt, crypt)
		    
dnl Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS(fcntl.h syslog.h unistd.h crypt.h)
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

# Check for SQL support	      
MYSQL=probe
PGSQL=probe

AC_ARG_WITH(mysql,
          [  --without-mysql        Configure to work without MySQL],
	  [MYSQL=$withval])
AC_ARG_WITH(postgres,
          [  --without-postgres     Configure to work without Postgres],
	  [PGSQL=$withval])
AC_ARG_WITH(sql,
	  [  --without-sql          Do not build SQL dependent modules],
	  [MYSQL=$withval
	   PGSQL=$withval])
	   
if test "$MYSQL" != no; then
  RA_CHECK_LIB(mysqlclient, mysql_real_connect, "-lm",
              [ AC_DEFINE(USE_SQL_MYSQL,1,
                          [Define this if you are going to use MySQL])
                AC_DEFINE(HAVE_LIBMYSQL,1,
                          [Define this if you have mysqlclient library])
                MYSQLLIBS="$ra_cv_lib_mysqlclient"
		SQL_MODULES="$SQL_MODULES pam_mysql.la" ],
              [ test "$MYSQL" = yes && AC_MSG_ERROR([MySQL libraries required, but not present])
	         MYSQL=no ],
              [/usr/local/lib/mysql /usr/lib/mysql])
fi

if test "$PGSQL" != no; then
  RA_CHECK_LIB(pq, PQconnectStart, [],
  	      [ AC_DEFINE(USE_SQL_PGSQL,1,
                          [Define this if you are going to use PostgreSQL])
                AC_DEFINE(HAVE_LIBPQ,1,
                          [Define this if you have libp]) 
                PGSQLLIBS="$ra_cv_lib_pq"
		SQL_MODULES="$SQL_MODULES pam_pgsql.la" ],
              [ test "$PGSQL" = yes && AC_MSG_ERROR([PostgreSQL libraries required, but not present])
	        PGSQL=no ],
              [/usr/local/pgsql/lib /usr/pgsql/lib])
fi

AC_SUBST(MYSQLLIBS)	
AC_SUBST(PGSQLLIBS)
AC_SUBST(SQL_MODULES)
	      
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
          pam_regex/Makefile
	  pam_log/Makefile
	  pam_sql/Makefile)
