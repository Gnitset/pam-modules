/* This file is part of pam-modules.
   Copyright (C) 2014 Sergey Poznyakoff
 
   This program is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by the
   Free Software Foundation; either version 3 of the License, or (at your
   option) any later version.
 
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
 
   You should have received a copy of the GNU General Public License along
   with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#ifdef HAVE__PAM_ACONF_H
#include <security/_pam_aconf.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>

#include "graypam.h"

#ifndef LINUX_PAM
#include <security/pam_appl.h>
#endif				/* LINUX_PAM */
#include <security/pam_modules.h>

#define SENSE_ALLOW   0
#define SENSE_DENY    1
const char *sense_choice[] = { "allow", "deny", NULL };

static int sense;
static int cntl_flags;
static long debug_level;
static char *groups;

struct pam_opt pam_opt[] = {
	{ PAM_OPTSTR(debug), pam_opt_long, &debug_level },
	{ PAM_OPTSTR(debug), pam_opt_const, &debug_level, { 1 } },
	{ PAM_OPTSTR(audit), pam_opt_const, &debug_level, { 100 } },
	{ PAM_OPTSTR(waitdebug), pam_opt_null, NULL, { 0 },
	  gray_wait_debug_fun },
	{ PAM_OPTSTR(sense), pam_opt_enum, &sense, { enumstr: sense_choice } },
	{ PAM_OPTSTR(groups), pam_opt_string, &groups },
	{ NULL }
};

static char **
split(const char *str, int delim)
{
	const char *p;
	size_t c = 1, i;
	char **v;
	
	for (p = str; *p; p++)
		if (*p == delim)
			++c;

	++c;

	v = gray_calloc(c, sizeof(*v));
	
	for (p = str, i = 0; *p; p++) {
		if (*p == delim) {
			size_t len = p - str;
			char *elt = gray_malloc(len + 1);
			memcpy(elt, str, len);
			elt[len] = 0;
			v[i++] = elt;
			str = ++p;
		}
	}
	v[i++] = gray_strdup(str);
	v[i] = 0;
	return v;
}

static int
check_groups(char **groupnames, struct passwd *pw)
{
	int i, j;
	struct group *gr;

	for (i = 0; groupnames[i]; i++) {
		char *gs = groupnames[i];

		if (gs[0] == '+') {
			char *ep;
			unsigned long n = strtoul(gs + 1, &ep, 10);
			if (*ep) {
				_pam_log(LOG_NOTICE, "not a valid number: %s",
					 gs);
				continue;
			}
			gr = getgrgid(n);
			if (gr)
				DEBUG(1,("got group %s <- %d",
					 gr->gr_name, gr->gr_gid));
			
		} else {
			gr = getgrnam(gs);
			if (gr)
				DEBUG(1,("got group %s -> %d",
					 gr->gr_name, gr->gr_gid));
		}
		
		if (!gr) {
			_pam_log(LOG_NOTICE, "no such group: %s", gs);
			continue;
		}
		if (gr->gr_gid == pw->pw_gid) {
			DEBUG(1,("primary gid matches %s", gr->gr_name));
			return 0;
		}
		
		for (j = 0; gr->gr_mem[j]; j++)
			if (strcmp(gr->gr_mem[j], pw->pw_name) == 0) {
				DEBUG(1,("supplementary gid matches %s",
					 gr->gr_name));
				return 0;
			}
	}
	return 1;
}
		
static void
argv_free(char **wv)
{
	int i;

	for (i = 0; wv[i]; i++)
		free(wv[i]);
	free(wv);
}

static int
check_membership0(pam_handle_t *pamh, int argc, const char **argv)
{
	char *name;
	char **groupnames;
	int rc;
	struct passwd *pw;
	static int retval[] = { PAM_SUCCESS, PAM_AUTH_ERR };
	
	gray_pam_init(PAM_AUTHINFO_UNAVAIL);
	gray_log_init(0, MODULE_NAME, LOG_AUTHPRIV);
	gray_parseopt(pam_opt, argc, argv);
	if (!groups) {
		_pam_log(LOG_ERR, "no group names given");
		return PAM_SERVICE_ERR;
	}
	/*
	 * get username
	 */
	rc = pam_get_user(pamh, (const char**)&name, "login: ");
	if (rc == PAM_SUCCESS) {
		DEBUG(10, ("username [%s] obtained", name));
	} else {
		_pam_log(LOG_NOTICE, "can't get username");
		return PAM_AUTHINFO_UNAVAIL;
	}

	pw = getpwnam(name);
	if (!pw)
		return PAM_USER_UNKNOWN;
	
	groupnames = split(groups, ',');
	rc = check_groups(groupnames, pw);
	argv_free(groupnames);

	if (sense == SENSE_DENY)
		rc = !rc;
	
	return retval[rc];
}

static int
check_membership(pam_handle_t *pamh, int argc, const char **argv,
		 const char *func)
{
	int rc;
	
	DEBUG(90,("enter %s", func));
	rc = check_membership0(pamh, argc, argv);
	DEBUG(90,("leave %s=%d", func, rc));
	return rc;
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh,
		    int flags,
		    int argc,
		    const char **argv)
{
	return check_membership(pamh, argc, argv, __FUNCTION__);
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return check_membership(pamh, argc, argv, __FUNCTION__);
}

PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh,int flags,int argc,const char **argv)
{
	return check_membership(pamh, argc, argv, __FUNCTION__);
}

PAM_EXTERN int
pam_sm_acct_mgmt (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return check_membership(pamh, argc, argv, __FUNCTION__);
}

PAM_EXTERN int
pam_sm_open_session (pam_handle_t *pamh, int flags, int argc,
                     const char **argv)
{
	return check_membership(pamh, argc, argv, __FUNCTION__);
}

PAM_EXTERN int
pam_sm_close_session (pam_handle_t *pamh, int flags, int argc,
		      const char **argv)
{
	return check_membership(pamh, argc, argv, __FUNCTION__);
}

#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_log_modstruct = {
    "pam_log",
    pam_sm_authenticate,
    pam_sm_setcred,
    pam_sm_acct_mgmt,
    pam_sm_open_session,
    pam_sm_close_session,
    pam_sm_chauthtok,
};

#endif

/* end of module definition */

	
	

	
