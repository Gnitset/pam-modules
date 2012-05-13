# Copyright (C) 2001, 2006, 2008-2011 Sergey Poznyakoff
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
SUBDIRS = \
 doc\
 lib\
 $(FSHADOW_DIR)\
 $(REGEX_DIR)\
 $(LOG_DIR)\
 pam_sql\
 $(LDAPHOME_DIR)\
 pamck
