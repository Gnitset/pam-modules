# Copyright (C) 2005-2006, 2008-2011 Sergey Poznyakoff
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

include $(top_srcdir)/Make.rules

pamdir=@PAMDIR@
pam_LTLIBRARIES = @SQL_MODULES@ 
EXTRA_LTLIBRARIES = pam_mysql.la pam_pgsql.la
EXTRA_DIST=pam_sql.c
AM_CPPFLAGS=-DSYSCONFDIR=\"${sysconfdir}\" 
pam_mysql_la_SOURCES = pam_mysql.c
pam_mysql_la_LIBADD = @PAM_MISC@ @MYSQLLIBS@ ./pam_sql.lo
pam_pgsql_la_SOURCES = pam_pgsql.c
pam_pgsql_la_LIBADD = @PAM_MISC@ @PGSQLLIBS@ ./pam_sql.lo
noinst_HEADERS=pam_sql.h


