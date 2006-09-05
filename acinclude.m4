dnl RA_FLUSHLEFT -- remove all whitespace at the beginning of lines
dnl This is useful for c-code which may include cpp statements
dnl
define([RA_FLUSHLEFT],
 [changequote(`,')dnl
patsubst(`$1', `^[ 	]+')
changequote([,])])dnl

dnl RA_RESULT_ACTIONS -- generate shell code for the result of a test
dnl   $1 -- CVAR  -- cache variable to check
dnl   $2 -- NAME  -- if not empty, used to generate a default value TRUE:
dnl                  `AC_DEFINE(HAVE_NAME)'
dnl   $2 -- TRUE  -- what to do if the CVAR is not `no'
dnl   $3 -- FALSE -- what to do otherwise; defaults to `:'
dnl
AC_DEFUN([RA_RESULT_ACTIONS], [
[if test "$$1" != "" -a "$$1" != no; then
  ]ifelse([$3], ,
          [AC_DEFINE(HAVE_]translit($2, [a-z ./<>], [A-Z___])[,1,[FIXME])],
          [$3])[
else
  ]ifelse([$4], , [:], [$4])[
fi]])dnl

dnl RA_CHECK_STRUCT_FIELD -- See if a structure has a particular field
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

AC_DEFUN([RA_CHECK_STRUCT_FIELD], [
  define([ra_CVAR], [ra_cv_struct_]translit($1_$2, [A-Z], [a-z]))dnl
  AC_CACHE_CHECK([whether struct $1 has $2 field], ra_CVAR,
    AC_TRY_COMPILE(RA_FLUSHLEFT([$3]),
      [struct $1 ra_x; int ra_y = sizeof ra_x.$2;],
      ra_CVAR[=yes], ra_CVAR[=no]))
  RA_RESULT_ACTIONS(ra_CVAR, [$1_$2], [$4], [$5])dnl
  undefine([ra_CVAR])])dnl

dnl Arguments:
dnl   $1     --    Library to look for
dnl   $2     --    Function to check in the library
dnl   $3     --    Any additional libraries that might be needed
dnl   $4     --    Action to be taken when test succeeds
dnl   $5     --    Action to be taken when test fails
dnl   $6     --    Directories where the library may reside
AC_DEFUN([RA_CHECK_LIB],
[
  save_LIBS=$LIBS
  AC_CACHE_CHECK([for -l$1], ra_cv_lib_$1,
  [
   for path in $6
   do
      LIBS="$save_LIBS -L$path"
      AC_CHECK_LIB($1, $2,
                   [ra_cv_lib_$1="$3 -L$path -l$1"
                    break],
                   [ra_cv_lib_$1=no],$3)
   done
  ])
  RA_RESULT_ACTIONS([ra_cv_lib_$1],[LIB$1],[$4],[$5])
  LIBS=$save_LIBS
])


