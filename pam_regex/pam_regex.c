/* This file is part of pam-modules.
   Copyright (C) 2001, 2006, 2007, 2008 Sergey Poznyakoff
 
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
#include <ctype.h>
#include <syslog.h>
#include <errno.h>
#include <regex.h>

#include "graypam.h"

/* indicate the following groups are defined */
#define PAM_SM_AUTH

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
static const char *regex = NULL;
static int regex_flags = REG_NOSUB|REG_EXTENDED;
static const char *transform = NULL;
static const char *user_name;

struct pam_opt pam_opt[] = {
	{ PAM_OPTSTR(debug), pam_opt_long, &debug_level },
	{ PAM_OPTSTR(debug), pam_opt_const, &debug_level, 1 },
	{ PAM_OPTSTR(audit), pam_opt_bitmask, &cntl_flags, CNTL_AUDIT },
	{ PAM_OPTSTR(waitdebug), pam_opt_null, NULL, 0, gray_wait_debug_fun },
	{ PAM_OPTSTR(sense), pam_opt_enum, &sense, sense_choice },
	{ PAM_OPTSTR(transform), pam_opt_string, &transform },
	{ PAM_OPTSTR(user), pam_opt_string, &user_name },
	{ PAM_OPTSTR(regex), pam_opt_string, &regex },
	{ PAM_OPTSTR(extended), pam_opt_bitmask, &regex_flags,
	  REG_EXTENDED },
	{ PAM_OPTSTR(basic), pam_opt_bitmask_rev, &regex_flags,
	  REG_EXTENDED },
	{ PAM_OPTSTR(icase), pam_opt_bitmask, &regex_flags,
	  REG_ICASE },
	{ PAM_OPTSTR(ignore-case), pam_opt_bitmask, &regex_flags,
	  REG_ICASE },
	{ PAM_OPTSTR(case), pam_opt_bitmask_rev, &regex_flags,
	  REG_ICASE },
	
	{ NULL }
};


static void
_pam_parse(pam_handle_t *pamh, int argc, const char **argv)
{
	gray_log_init(0, MODULE_NAME, LOG_AUTHPRIV);
	gray_parseopt(pam_opt, argc, argv);
	if (!regex && !transform)
		_pam_log(LOG_ERR, "neither regex nor transform are specified");
	if (user_name && transform)
		_pam_log(LOG_ERR, "Both `user' and `transform' are given");
}

/*
 * PAM framework looks for these entry-points to pass control to the
 * authentication module.
 */

/* Fun starts here :)

 * pam_sm_authenticate() performs authentication
 *
 */

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh,
		    int flags,
		    int argc,
		    const char **argv)
{
	int retval, rc;
	char *name;
	regex_t rx;
	
	_pam_parse(pamh, argc, argv);
	
	DEBUG(90,("enter pam_sm_authenticate"));

	gray_pam_init(PAM_AUTHINFO_UNAVAIL);

	/*
	 * get username
	 */
	retval = pam_get_user(pamh, (const char**)&name, "login: ");
	if (retval == PAM_SUCCESS) {
		DEBUG(10, ("username [%s] obtained", name));
	} else {
		_pam_log(LOG_NOTICE, "can't get username");
		return PAM_AUTHINFO_UNAVAIL;
	}

	if (transform) {
		char *newname;
		gray_slist_t slist;

		gray_set_transform_expr(transform);
		slist = gray_slist_create();
		gray_transform_name_to_slist(slist, name, &newname);
		DEBUG(90,("new name: %s", newname));
		MAKE_STR(pamh, newname, name);
		retval = pam_set_item(pamh, PAM_USER, name);
		if (retval != PAM_SUCCESS) {
			_pam_log(LOG_ERR, "retval %d", retval);
			return PAM_AUTHINFO_UNAVAIL;
		}
	}

	if (regex) {
		for (;;) {

			if (rc = regcomp(&rx, regex, regex_flags)) {
				char errbuf[512];
				regerror (rc, &rx, errbuf, sizeof (errbuf));
				_pam_log(LOG_ERR, "can't compile regex: %s",
					 errbuf);
				retval = PAM_AUTHINFO_UNAVAIL;
				break;
			}

			retval = regexec(&rx, name, 0, NULL, 0);
			if (retval) {
				DEBUG(1,("%s does not match %s",name,regex));
			}

			switch (sense) {
			case SENSE_ALLOW:
				break;
				
			case SENSE_DENY:
				retval = !retval;
				break;
				
			}
			
			if (retval != PAM_SUCCESS) {
				_pam_log(LOG_NOTICE, "rejecting %s", name);
				retval = PAM_AUTH_ERR;
			} else 
				_pam_log(LOG_NOTICE, "allowing %s", name);
			if (user_name) 
				pam_set_item(pamh, PAM_USER, strdup(user_name));
			break;
		}
	}

	DEBUG(90,("exit pam_sm_authenticate: %d", retval));
	return retval;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh,
	       int flags,
	       int argc,
	       const char **argv)
{
	return PAM_SUCCESS;
}

#ifdef PAM_STATIC

struct pam_module _pam_radius_modstruct = {
	"pam_regex",                      /* name of the module */
	pam_sm_authenticate,                 
	pam_sm_setcred,
	NULL,
	NULL,
	NULL,
	NULL
};

#endif

