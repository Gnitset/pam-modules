# This file is part of pam-modules.
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

AUTOMAKE_OPTIONS = gnits 1.8
ACLOCAL_AMFLAGS = -I m4 -I imprimatur

if PAM_COND_FSHADOW
  FSHADOW_DIR=pam_fshadow
endif
if PAM_COND_REGEX
  REGEX_DIR=pam_regex
endif
if PAM_COND_LOG
  LOG_DIR=pam_log
endif
if PAM_COND_LDAPHOME
  LDAPHOME_DIR=pam_ldaphome
endif
if PAM_COND_UMOTD
  UMOTD_DIR=pam_umotd
endif
if PAM_COND_GROUPMEMBER
  GROUPMEMBER_DIR=pam_groupmember
endif
SUBDIRS = \
 imprimatur\
 doc\
 examples\
 lib\
 $(FSHADOW_DIR)\
 $(REGEX_DIR)\
 $(LOG_DIR)\
 pam_sql\
 $(LDAPHOME_DIR)\
 $(UMOTD_DIR)\
 $(GROUPMEMBER_DIR)\
 pamck

EXTRA_DIST=ChangeLog.svn

#  Name of the previous ChangeLog file.
prev_change_log = ChangeLog.svn
#  Start Git ChangeLog from this date. 
gen_start_date = 2012-05-13

.PHONY: ChangeLog
ChangeLog:
	$(AM_V_GEN)if test -d .git; then                                     \
          git log --pretty='format:%ct  %an  <%ae>%n%n%s%n%n%b%n' |          \
	    awk -f $(top_srcdir)/git2chg.awk                                 \
              -vsince="$(gen_start_date)" -vappend="$(prev_change_log)"      \
              > ChangeLog.tmp;                                               \
          cmp ChangeLog ChangeLog.tmp > /dev/null 2>&1 ||                    \
            mv ChangeLog.tmp ChangeLog;                                      \
          rm -f ChangeLog.tmp;                                               \
	fi
