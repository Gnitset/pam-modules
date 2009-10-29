# This file is part of pam-modules.
# Copyright (C) 2005, 2007, 2008 Sergey Poznyakoff
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
pam_modules_TEXINFOS=fdl.texi macros.texi rendition.texi

EXTRA_DIST = \
 check-docs.sh\
 gendocs_template\
 mastermenu.el\
 untabify.el

clean-local:
	rm -rf manual

# Checking
check-format:
	@if test -n "`cat $(info_TEXINFOS) $(pam_modules_TEXINFOS) | tr -d -c '\t'`"; then \
		echo "Sources contain tabs; run make untabify"; \
		false; \
	fi

check-refs:
	@for file in $(info_TEXINFOS) $(mailfromd_TEXINFOS); \
	do \
	  sed -e = $$file | \
           sed -n 'N;/@FIXME-.*ref/{s/\(^[0-9][0-9]*\).*@FIXME-.*ref{\([^}]*\)}.*/'$$file':\1: \2/gp}'; \
	done > $@-t; \
	if [ -s $@-t ]; then \
	  echo "Unresolved cross-references:"; \
	  cat $@-t;\
	  rm $@-t; \
	else \
	  rm -f $@-t; \
	fi

check-fixmes:
	@for file in $(info_TEXINFOS); \
	do \
	  sed -e = $$file | \
           sed -n 'N;/@FIXME{/{s/\(^[0-9][0-9]*\).*@FIXME{\([^}]*\).*/'$$file':\1: \2/gp}'; \
	done > $@-t; \
	if [ -s $@-t ]; then \
	  echo "Unresolved FIXMEs:"; \
	  cat $@-t; \
	  rm $@-t; \
	  false; \
	else \
          rm -f $@-t; \
	fi

check-unrevised:
	@grep -Hn @UNREVISED $(info_TEXINFOS) > $@-t; \
	if [ -s $@-t ]; then \
	  echo "Unrevised nodes:"; \
	  cat $@-t; \
	  rm $@-t; \
	  false;\
	else \
          rm $@-t; \
	fi

check-log-options:
	@check-docs.sh "pam_log options" \
	   '/struct pam_opt .*\[\] = /,/^}/s/[ \t]*{ *PAM_OPTSTR(\([^,)]*\)).*/\1/p' \
	   '/@set MODULE pam_log/,/@set MODULE/{s/@value{MODULE}/pam_log/g;there;:here;s/@opindex *\([^@,]*\),.*@command{pam_log}.*/\1/;t lab;b;: lab;{s/^-//;s/^no//;p;}}' \
	   $(top_srcdir)/pam_log/*.c -- \
	   $(MAKEINFO) $(AM_MAKEINFOFLAGS) $(MAKEINFOFLAGS) -I $(srcdir) -E - \
		$(info_TEXINFOS) ; 


check-all-options:
	@for mod in fshadow regex sql; \
	do \
	  check-docs.sh "pam_$$mod options" \
	   '/struct pam_opt .*\[\] = /,/^}/s/[ \t]*{ *PAM_OPTSTR(\([^,)]*\)).*/\1/;t lab;b;: lab {/audit/d;/debug/d;/waitdebug/d;p}' \
	   '/@set MODULE pam_'$$mod'/,/@set MODULE/{s/@value{MODULE}/pam_'$$mod'/g;there;:here;s/@opindex *\([^@,]*\),.*@command{pam_'$$mod'}.*/\1/;t lab;b;: lab;{s/^-//;s/^no//;p;}}' \
	   $(top_srcdir)/pam_$$mod/*.c -- \
	   $(MAKEINFO) $(AM_MAKEINFOFLAGS) $(MAKEINFOFLAGS) -I $(srcdir) -E - \
		$(info_TEXINFOS) ; \
        done

check-sql-config:
	@check-docs.sh 'SQL configuration keywords' \
	   's/.*check_boolean_config *("\([^"]*\)".*/\1/p;s/.*find_config *("\([^"]*\)".*/\1/p' \
	   's/@kwindex *\([^@,]*\).*/\1/p' \
	   $(top_srcdir)/pam_sql/*.c -- \
	   $(MAKEINFO) $(AM_MAKEINFOFLAGS) $(MAKEINFOFLAGS) -I $(srcdir) -E - \
		$(info_TEXINFOS) 

check-options: check-all-options check-log-options

all-check-docs: check-format check-refs check-fixmes check-unrevised check-options check-sql-config

check-docs: 
	$(MAKE) -k all-check-docs
#

master-menu:
	emacs -batch -l mastermenu.el -f make-master-menu $(info_TEXINFOS)

untabify:
	emacs -batch -l untabify.el $(info_TEXINFOS) $(pam_modules_TEXINFOS)

final: untabify master-menu

#

# The rendering level is one of PUBLISH, DISTRIB or PROOF.
# Just call `make RENDITION=PROOF [target]' if you want PROOF rendition.
RENDITION = DISTRIB

MAKEINFOFLAGS=-D$(RENDITION)

GENDOCS=gendocs.sh

TEXI2DVI=texi2dvi -t '@set $(RENDITION)' -E

# Make sure you set TEXINPUTS.
# TEXINPUTS=/usr/share/texmf/pdftex/plain/misc/ is ok for most distributions
.PHONY: manual
manual:
	TEXINPUTS=$(srcdir):$(top_srcdir)/build-aux:$(TEXINPUTS) \
	 MAKEINFO="$(MAKEINFO) $(MAKEINFOFLAGS)" \
	 TEXI2DVI="$(TEXI2DVI) -t @finalout" \
	 $(GENDOCS) --texi2html $(PACKAGE) '$(PACKAGE_NAME) manual'


manual.tar.bz2: manual
	tar cfj manual.tar.bz2 manual

man-tar: manual.tar.bz2

