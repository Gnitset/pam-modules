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

AC_DEFUN([PM_ENABLE],[
  AC_ARG_ENABLE($1,
                AC_HELP_STRING([--disable-$1], [Disable pam_$1]),
                [build_$1=$enableval],
		[build_$1=m4_if([$2],[],yes,probe)])
  m4_pushdef([upmodname],translit($1, [a-z.-], [A-Z__]))
  m4_if([$2],[],,[if test $build_$1 != no; then
    $2
    test $build_$1 = probe && build_$1=no
  fi])
  AM_CONDITIONAL([PAM_COND_]upmodname, [test "$[]build_$1" = "yes"])
  m4_popdef([upmodname])
])

dnl PM_FLUSHLEFT -- remove all whitespace at the beginning of lines
dnl This is useful for c-code which may include cpp statements
dnl
define([PM_FLUSHLEFT],
 [changequote(`,')dnl
patsubst(`$1', `^[ 	]+')
changequote([,])])dnl

dnl PM_RESULT_ACTIONS -- generate shell code for the result of a test
dnl   $1 -- CVAR  -- cache variable to check
dnl   $2 -- NAME  -- if not empty, used to generate a default value TRUE:
dnl                  `AC_DEFINE(HAVE_NAME)'
dnl   $2 -- TRUE  -- what to do if the CVAR is not `no'
dnl   $3 -- FALSE -- what to do otherwise; defaults to `:'
dnl
AC_DEFUN([PM_RESULT_ACTIONS], [
[if test "$$1" != "" -a "$$1" != no; then
  ]ifelse([$3], ,
          [AC_DEFINE(HAVE_]translit($2, [a-z ./<>], [A-Z___])[,1,[FIXME])],
          [$3])[
else
  ]ifelse([$4], , [:], [$4])[
fi]])dnl

dnl PM_CHECK_STRUCT_FIELD -- See if a structure has a particular field
dnl   $1 - NAME  -- name of structure
dnl   $2 - FIELD -- name of field to test
dnl   $3 - INCLS -- C program text to inculde necessary files for testing
dnl   $4 - TRUE  -- what to do if struct NAME has FIELD; defaults to 
dnl		    `AC_DEFINE(HAVE_NAME_FIELD)'
dnl   $5 - FALSE -- what to do if not; defaults to `:'
dnl
dnl NOTE: We still don't use AC_CHECK_MEMBERS, since it has (as of
dnl autoconf 2.53) a bug which prevents it from recognizing members
dnl of aggregate type.

AC_DEFUN([PM_CHECK_STRUCT_FIELD], [
  define([pm_CVAR], [pm_cv_struct_]translit($1_$2, [A-Z], [a-z]))dnl
  AC_CACHE_CHECK([whether struct $1 has $2 field], pm_CVAR,
    AC_TRY_COMPILE(PM_FLUSHLEFT([$3]),
      [struct $1 pm_x; int pm_y = sizeof pm_x.$2;],
      pm_CVAR[=yes], pm_CVAR[=no]))
  PM_RESULT_ACTIONS(pm_CVAR, [$1_$2], [$4], [$5])dnl
  undefine([pm_CVAR])])dnl

dnl Arguments:
dnl   $1     --    Library to look for
dnl   $2     --    Function to check in the library
dnl   $3     --    Any additional libraries that might be needed
dnl   $4     --    Action to be taken when test succeeds
dnl   $5     --    Action to be taken when test fails
dnl   $6     --    Directories where the library may reside
AC_DEFUN([PM_CHECK_LIB],
[m4_ifval([$4], , [AH_CHECK_LIB([$1])])dnl
AS_VAR_PUSHDEF([pm_Lib], [pm_cv_lib_$1])dnl
AC_CACHE_CHECK([for $2 in -l$1], [pm_Lib],
[AS_VAR_SET([pm_Lib], [no])
 pm_check_lib_save_LIBS=$LIBS
 for path in "" $6
 do
   if test -n "$path"; then
     pm_ldflags="-L$path -l$1 $3"
   else
     pm_ldflags="-l$1 $3"
   fi
   LIBS="$pm_ldflags $pm_check_lib_save_LIBS"
   AC_LINK_IFELSE([AC_LANG_CALL([], [$2])],
                  [AS_VAR_SET([pm_Lib], ["$pm_ldflags"])
		   break])
 done		  
 LIBS=$pm_check_lib_save_LIBS])
AS_IF([test "AS_VAR_GET([pm_Lib])" != no],
      [m4_default([$4], [AC_DEFINE_UNQUOTED(AS_TR_CPP(HAVE_LIB$1))
  LIBS="-l$1 $LIBS"
])],
      [$5])dnl
AS_VAR_POPDEF([pm_Lib])dnl
])# PM_CHECK_LIB


