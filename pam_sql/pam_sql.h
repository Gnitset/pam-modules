/* This file is part of pam-modules.
   Copyright (C) 2005, 2006 Sergey Poznyakoff

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
   MA 02110-1301 USA */

#define debug_level gpam_sql_debug_level
#include <graypam.h>
#if defined(HAVE_CRYPT_H)
# include <crypt.h>
#else
extern char *crypt(const char *, const char *);
#endif
#include <md5.h>
#include <sha1.h>

#define CHKVAR(v) \
 	if (!(v)) {							\
	        _pam_log(LOG_ERR, "%s: %s not defined",			\
			 gpam_sql_config_file, #v);			\
		return PAM_SERVICE_ERR;					\
	}								\
       	DEBUG(100,("Config: %s=%s", #v, v));


extern long gpam_sql_debug_level;
extern char *gpam_sql_module_name;
extern char *gpam_sql_config_file;

int gpam_sql_verify_user_pass(pam_handle_t *pamh, const char *passwd,
			      const char *query);
int gpam_sql_acct(pam_handle_t *pamh, const char *query);
		    
char *gpam_sql_find_config(const char *name);
const char *gpam_sql_get_query(pam_handle_t *pamh, const char *name,
			       gray_slist_t *pslist, int required);
int gpam_sql_check_boolean_config(const char *name, int defval);

