# This file is part of pam-modules.
# Copyright (C) 2005, 2007-2008, 2010-2012, 2014 Sergey Poznyakoff
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

info_TEXINFOS=pam-modules.texi
pam_modules_TEXINFOS=fdl.texi macros.texi
dist_man_MANS = pamck.1

if PAM_COND_FSHADOW
  dist_man_MANS += pam_fshadow.8
endif
if PAM_COND_REGEX
  dist_man_MANS += pam_regex.8
endif
if PAM_COND_LOG
  dist_man_MANS += pam_log.8
endif
if PAM_COND_LDAPHOME
  dist_man_MANS += pam_ldaphome.8
endif
if PAM_COND_UMOTD
  dist_man_MANS += pam_umotd.8
endif
if PAM_COND_MYSQL
  dist_man_MANS += pam_mysql.8
endif
if PAM_COND_PGSQL
  dist_man_MANS += pam_pgsql.8
endif
if PAM_COND_GROUPMEMBER
  dist_man_MANS += pam_groupmember.8
endif

config.so: $(top_srcdir)/configure.ac $(top_srcdir)/doc/Makefile.am
	$(AM_V_GEN){\
                echo ".ds ET $(sysconfdir)"; \
        } > config.so

BUILD_MANS=pam_fshadow.8 pam_mysql.8 pam_pgsql.8 pam_ldaphome.8
CLEANFILES=$(BUILD_MANS) config.so

pam_fshadow.8 pam_mysql.8 pam_pgsql.8 pam_ldaphome.8: config.so

.8in.8:
	$(AM_V_GEN){\
                echo '.\" -*- buffer-read-only: t -*- vi: set ro:';\
                echo '.\" THIS FILE IS GENERATED AUTOMATICALLY; DO NOT EDIT!';\
                soelim -I$(top_builddir)/doc $<;\
        } > $@

EXTRA_DIST = \
 gendocs_template\
 $(BUILD_MANS:.8=.8in)

clean-local:
	rm -rf manual

AM_MAKEINFOFLAGS=@IMPRIMATUR_MAKEINFOFLAGS@
imprimatur_INPUT=$(info_TEXINFOS) $(pam_modules_TEXINFOS)
CHECK_DOCS=$(top_srcdir)/@IMPRIMATUR_MODULE_DIR@/check-docs.sh
include ../imprimatur/imprimatur.mk

# Checking
check-log-options:
	@$(CHECK_DOCS) "pam_log options" \
	   '/struct pam_opt .*\[\] = /,/^}/s/[ \t]*{ *PAM_OPTSTR(\([^,)]*\)).*/\1/p' \
	   '/@set MODULE pam_log/,/@set MODULE/{s/@value{MODULE}/pam_log/g;there;:here;s/@opindex *\([^@,]*\),.*@command{pam_log}.*/\1/;t lab;b;: lab;{s/^-//;s/^no//;p;}}' \
	   $(top_srcdir)/pam_log/*.c -- \
	   $(MAKEINFO) $(AM_MAKEINFOFLAGS) $(MAKEINFOFLAGS) -I $(srcdir) -E - \
		$(info_TEXINFOS) ; 


check-all-options:
	@for mod in fshadow regex sql ldaphome; \
	do \
	  $(CHECK_DOCS) "pam_$$mod options" \
	   '/struct pam_opt .*\[\] = /,/^}/s/[ \t]*{ *PAM_OPTSTR(\([^,)]*\)).*/\1/;t lab;b;: lab {/audit/d;/debug/d;/waitdebug/d;p}' \
	   '/@set MODULE pam_'$$mod'/,/@set MODULE/{s/@value{MODULE}/pam_'$$mod'/g;there;:here;s/@opindex *\([^@,]*\),.*@command{pam_'$$mod'}.*/\1/;t lab;b;: lab;{s/^-//;s/^no//;p;}}' \
	   $(top_srcdir)/pam_$$mod/*.c -- \
	   $(MAKEINFO) $(AM_MAKEINFOFLAGS) $(MAKEINFOFLAGS) -I $(srcdir) -E - \
		$(info_TEXINFOS) ; \
        done

check-sql-config:
	@$(CHECK_DOCS) 'SQL configuration keywords' \
	   's/.*check_boolean_config *("\([^"]*\)".*/\1/p;s/.*find_config *("\([^"]*\)".*/\1/p' \
	   's/@kwindex *\([^@,]*\).*/\1/p' \
	   $(top_srcdir)/pam_sql/*.c -- \
	   $(MAKEINFO) $(AM_MAKEINFOFLAGS) $(MAKEINFOFLAGS) -I $(srcdir) -E - \
		$(info_TEXINFOS) 

check-ldaphome-config:
	@$(CHECK_DOCS) 'pam_ldaphome configuration keywords' \
	   's/.*gray_env_get(.[^,]*, *"\(.[^"]*\)".*/\1/p;s/.*get_intval(.[^,]*, *"\(.[^"]*\)".*/\1/p' \
	   's/@deffn  *{pam_ldaphome config}  *\([a-zA-Z_][a-zA-Z0-9_-]*\) .*/\1/p' \
	   $(top_srcdir)/pam_ldaphome/pam_ldaphome.c -- \
	   $(MAKEINFO) $(AM_MAKEINFOFLAGS) $(MAKEINFOFLAGS) -I $(srcdir) -E - \
		$(info_TEXINFOS) 


check-options: \
 check-all-options\
 check-log-options\
 check-ldaphome-config

all-check-docs: imprimatur-basic-checks check-options check-sql-config

check-docs: 
	$(MAKE) -k all-check-docs
#

master-menu: imprimatur-master-menu
untabify: imprimatur-untabify
final: imprimatur-final

#

# The rendering level is one of PUBLISH, DISTRIB or PROOF.
# Just call `make RENDITION=PROOF [target]' if you want PROOF rendition.
RENDITION = DISTRIB

GENDOCS=gendocs.sh

TEXI2DVI=texi2dvi -t '@set $(RENDITION)' -E

# Make sure you set TEXINPUTS.
# TEXINPUTS=/usr/share/texmf/pdftex/plain/misc/ is ok for most distributions
.PHONY: manual
manual:
	TEXINPUTS=$(srcdir):$(top_srcdir)/build-aux:$(TEXINPUTS) \
	 MAKEINFO="$(MAKEINFO) $(MAKEINFOFLAGS) $(AM_MAKEINFOFLAGS)" \
	 TEXI2DVI="$(TEXI2DVI) -t @finalout" \
	 $(GENDOCS) --texi2html $(PACKAGE) '$(PACKAGE_NAME) manual'

manual.tar.bz2: manual
	tar cfj manual.tar.bz2 manual

man-tar: manual.tar.bz2

