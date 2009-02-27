# This file is part of pam-modules.       -*- autoconf -*-
# Copyright (C) 2005, 2006, 2007, 2008, 2009 Sergey Poznyakoff
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

AC_PREREQ(2.53)

AC_INIT(pam-modules, 1.6, bug-pam-modules@gnu.org.ua)
AC_CONFIG_SRCDIR(pam_fshadow/pam_fshadow.c)
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE(no-exeext)
AM_CONFIG_HEADER(config.h)

dnl Library versioning
AC_SUBST(VI_CURRENT,1)
AC_SUBST(VI_REVISION,0)
AC_SUBST(VI_AGE,0)

dnl Modules
build_fshadow=probe
build_regex=probe
build_log=probe
build_pgsql=probe

dnl Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL

LT_PREREQ(2.2.5a)
LT_INIT

dnl Checks for libraries.
AC_CHECK_LIB(pam, pam_get_item,:,
		  [AC_MSG_ERROR([Required library libpam is not found])])
AC_CHECK_LIB(crypt, crypt)
AC_SUBST(PAM_MISC)
AH_TEMPLATE([HAVE_PAM_MISC_SETENV],[Define if pam_misc_setenv is available.])
AC_CHECK_LIB(pam_misc, pam_misc_setenv,
             [PAM_MISC=-lpam_misc
	      AC_DEFINE([HAVE_PAM_MISC_SETENV],1)],:,[-lpam])
			    
dnl Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS(security/pam_appl.h security/pam_modules.h,
                 :,
		 AC_MSG_ERROR([Required PAM header files not found]))
AC_CHECK_HEADERS(fcntl.h syslog.h unistd.h crypt.h security/_pam_aconf.h \
                 security/pam_misc.h termios.h)
AC_CHECK_HEADER(shadow.h,
                [],
                [build_fshadow=no])

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST

AC_CHECK_HEADERS([shadow.h])
AC_CHECK_FUNCS(fgetspent)
AC_CHECK_TYPES(struct spwd, , ,
    [ #include <shadow.h> ])
AC_CHECK_MEMBERS([struct spwd.sp_expire], , ,
    [ #include <shadow.h> ])

dnl Checks for library functions.
AC_CHECK_FUNCS(strerror tcgetattr)

AC_CHECK_FUNC(fgetpwent,
              [],
              [build_fshadow=no])

PM_ENABLE(fshadow)
PM_ENABLE(log)
PM_ENABLE(regex)

# Check for SQL support	      

AC_ARG_WITH(mysql,
            AC_HELP_STRING([--without-mysql],
	                   [Configure to work without MySQL]),
	    [build_mysql=$withval])	
AC_ARG_WITH(pgsql,
            AC_HELP_STRING([--without-pgsql],
	                   [Configure to work without Postgres]),
	    [build_pgsql=$withval])
AC_ARG_WITH(postgres,
            AC_HELP_STRING([--without-postgres],
	                   [Same as --without-pgsql]),
 	    [build_pgsql=$withval])
AC_ARG_WITH(sql,
	    AC_HELP_STRING([--without-sql],
	                   [Do not build SQL dependent modules]),
	  [build_mysql=$withval	
	   build_pgsql=$withval])	
	   
if test "$build_mysql" != no; then
  PM_CHECK_LIB(mysqlclient, mysql_real_connect, "-lm",
              [ AC_DEFINE(USE_SQL_MYSQL,1,
                          [Define this if you are going to use MySQL])
                AC_DEFINE(HAVE_LIBMYSQL,1,
                          [Define this if you have mysqlclient library])
                MYSQLLIBS="$pm_cv_lib_mysqlclient"
		SQL_MODULES="$SQL_MODULES pam_mysql.la"
		build_mysql=yes ],
              [ test "$build_mysql" = yes && AC_MSG_ERROR([MySQL libraries required, but not present])
	        build_mysql=no ],
              [/usr/lib/mysql /usr/local/lib/mysql])
fi

if test "$build_pgsql" != no; then
  PM_CHECK_LIB(pq, PQconnectStart, [],
  	      [ save_CPPFLAGS=$CPPFLAGS
	        for dir in /usr/local/pgsql/include /usr/pgsql/include
		do
			CPPFLAGS="$save_CPPFLAGS -I$dir"
			AC_CHECK_HEADER([libpq-fe.h], [break])
			CPPFLAGS="$save_CPPFLAGS"
		done
	        AC_DEFINE(USE_SQL_PGSQL,1,
                          [Define this if you are going to use PostgreSQL])
                AC_DEFINE(HAVE_LIBPQ,1,
                          [Define this if you have libpq]) 
                PGSQLLIBS="$pm_cv_lib_pq"
		SQL_MODULES="$SQL_MODULES pam_pgsql.la"
		build_pgsql=yes ],
              [ test "$build_pgsql" = yes && AC_MSG_ERROR([PostgreSQL libraries required, but not present])
	        build_pgsql=no ],
              [/usr/pgsql/lib /usr/local/pgsql/lib])
fi

AC_SUBST(MYSQLLIBS)	
AC_SUBST(PGSQLLIBS)
AC_SUBST(SQL_MODULES)

## *****************
## debugging support
## *****************
AC_ARG_ENABLE(debug,                     
    AC_HELP_STRING([--enable-debug], [enable debugging mode]),
    [if test "$enableval" = yes; then
       if test "$GCC" = yes; then
	 AC_MSG_CHECKING(whether gcc accepts -ggdb)
         save_CFLAGS=$CFLAGS
         CFLAGS="-ggdb -Wall"
         AC_TRY_COMPILE([],void f(){},
           AC_MSG_RESULT(yes),
           [if test x"$ac_cv_prog_cc_g" = xyes; then
              CFLAGS="-g -Wall"
            else
              CFLAGS=
            fi
            AC_MSG_RESULT(no)])
         CFLAGS="`echo $save_CFLAGS | sed 's/-O[[0-9]]//g'` $CFLAGS"
	 AC_DEFINE_UNQUOTED([DEBUG_MODE],1,[Define to enable debugging])
       fi
     fi])
   
## **************
## Directories
## **************
PAMDIR='$(prefix)/lib/security'
AC_ARG_WITH(pamdir,
	    AC_HELP_STRING([--with-pamdir=DIR],
	                   [install PAM modiles in DIR (PREFIX/lib/security)]),
	    [PAMDIR=$withval])
AC_SUBST(PAMDIR)

## **************
## Summary
## **************
   
AC_CONFIG_COMMANDS([status],[
echo ""
delim="-------------------------------------------------------------------"
echo $delim | tr '-' '*'
echo "Modules to build:"
res=
for module in fshadow regex log pgsql mysql
do
	modname=pam_$module
	eval enable=\${build_$module}
	str=`echo ${modname}" yes" | sed 's/./-/g'`
	dstr=`echo $delim | sed "s/^$str//" | tr '-' '.'`
	echo ${modname}$dstr $enable
	res="$res$enable"
done
echo $delim | tr '-' '*'
case "$res" in
*yes*) ;;
*)
       AC_MSG_ERROR([Nothing to build?])
esac
],[
build_fshadow=$build_fshadow
build_regex=$build_regex
build_log=$build_log
build_pgsql=$build_pgsql
build_mysql=$build_mysql])  	  
		
AC_OUTPUT(Makefile
          doc/Makefile
	  lib/Makefile
	  pam_fshadow/Makefile
          pam_regex/Makefile
	  pam_log/Makefile
	  pam_sql/Makefile
	  pamck/Makefile)
