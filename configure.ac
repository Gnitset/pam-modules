dnl Process this file with autoconf to produce a configure script.
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
	  pam_fshadow/Makefile
          pam_regex/Makefile)
