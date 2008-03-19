# Copyright (C) 2005, 2006, 2008 Sergey Poznyakoff
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

pamdir=@PAMDIR@
pam_PROGRAMS = @SQL_MODULES@ 
AM_INSTALLCHECK_STD_OPTIONS_EXEMPT = pam_mysql.la pam_pgsql.la
EXTRA_PROGRAMS = pam_mysql.la pam_pgsql.la
EXTRA_DIST = sha1.h sha1.c pam_sql.c md5.c md5.h
LDADD = ../lib/libgraypam.la
pam_mysql_la_SOURCES = pam_mysql.c pam_sql.c
pam_mysql_la_LDADD = -lpam @PAM_MISC@ @MYSQLLIBS@
pam_pgsql_la_SOURCES = pam_pgsql.c pam_sql.c
pam_pgsql_la_LDADD = -lpam @PAM_MISC@ @PGSQLLIBS@
AM_LDFLAGS = -version-info @VI_CURRENT@:@VI_REVISION@:@VI_AGE@

AM_CPPFLAGS=-DSYSCONFDIR=\"${sysconfdir}\" 
INCLUDES=@PAM_COMMON_INCLUDES@
NORMAL_UNINSTALL = list='$(pam_PROGRAMS)' ;\
                   for mod in $$list ;\
                   do \
                      name=`expr $$mod : '\(.*\)\.la'`; \
                      rm -f $(DESTDIR)$(pamdir)/$${name}.a \
                            $(DESTDIR)$(pamdir)/$${name}.so.@VI_CURRENT@.@VI_REVISION@.@VI_AGE@; \
                   done

pam_mysql.lo: $(srcdir)/pam_sql.c $(srcdir)/sha1.c $(srcdir)/sha1.h
pam_pgsql.lo: $(srcdir)/pam_sql.c 

pam_mysql.lo: $(srcdir)/pam_mysql.c 
	$(LIBTOOL) --mode=compile $(CC) -o$@ -c -DHAVE_CONFIG_H \
		$(CFLAGS) $(AM_CFLAGS) $(INCLUDES) $(CPPFLAGS) $(AM_CPPFLAGS) \
		-DMODULE_NAME=\"pam_mysql\" $<

pam_pgsql.lo: $(srcdir)/pam_pgsql.c
	$(LIBTOOL) --mode=compile $(CC) -o$@ -c -DHAVE_CONFIG_H \
		$(CFLAGS) $(AM_CFLAGS) $(INCLUDES) $(CPPFLAGS) $(AM_CPPFLAGS) \
		-DMODULE_NAME=\"pam_pgsql\" $<

pam_mysql.la$(EXEEXT): pam_mysql.lo sha1.lo md5.lo
	$(LIBTOOL) --mode=link $(CC) -module -export-dynamic \
		$(AM_LDFLAGS) $(pam_mysql_la_LDFLAGS) $(LDFLAGS) \
		-o $@ pam_mysql.lo sha1.lo md5.lo $(pam_mysql_la_LDADD) $(AM_LDADD) $(LDADD) \
		-rpath $(pamdir)

pam_pgsql.la$(EXEEXT): pam_pgsql.lo
	$(LIBTOOL) --mode=link $(CC) -module -export-dynamic \
		$(AM_LDFLAGS) $(pam_pgsql_la_LDFLAGS) $(LDFLAGS) \
		-o $@ $< $(pam_pgsql_la_LDADD) $(AM_LDADD) $(LDADD) \
		-rpath $(pamdir)
