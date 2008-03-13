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

#define CNTL_AUTHTOK       0x0010
#define CNTL_REGEX_FLAGS   0x0012

#define SENSE_ALLOW   0
#define SENSE_DENY    1

static int sense;
static int cntl_flags;
static const char *regex = NULL;
static int regex_flags = REG_NOSUB;
static const char *transform = NULL;
static const char *user_name;

static void
_pam_parse(pam_handle_t *pamh, int argc, const char **argv)
{
	int ctrl = 0;

	gray_log_init(0, MODULE_NAME, LOG_AUTHPRIV);
	
	/* step through arguments */
	for (; argc-- > 0; ++argv) {

		/* generic options */

		if (!strncmp(*argv, "debug", 5)) {
			ctrl |= CNTL_DEBUG;
			if ((*argv)[5] == '=') 
				CNTL_SET_DEBUG_LEV(ctrl, atoi(*argv + 6));
			else
				CNTL_SET_DEBUG_LEV(ctrl, 1);
		} else if (!strcmp(*argv, "audit"))
			ctrl |= CNTL_AUDIT;
		else if (!strncmp(*argv, "waitdebug", 9)) 
			WAITDEBUG(*argv + 9);
		else if (!strcmp(*argv, "use_authtok"))
			ctrl |= CNTL_AUTHTOK;
		else if (!strncmp(*argv, "sense=", 6)) {
			if (strcmp(*argv + 6, "deny") == 0)
				sense = SENSE_DENY;
			else if (strcmp(*argv + 6, "allow") == 0)
				sense = SENSE_ALLOW;
			else
				_pam_log(LOG_ERR,"unknown sense value: %s",
					 *argv + 6);
		} else if (!strncmp(*argv, "transform=", 10))
			transform = *argv + 10;
		else if (!strncmp(*argv, "user=",5)) 
			user_name = *argv + 5;
		else if (!strncmp(*argv, "regex=", 6))
			regex = *argv + 6;
		else if (!strcmp(*argv, "extended")) {
			regex_flags |= REG_EXTENDED;
			ctrl |= CNTL_REGEX_FLAGS;
		} else if (!strcmp(*argv, "basic")) {
			regex_flags &= ~REG_EXTENDED;
			ctrl |= CNTL_REGEX_FLAGS;
		} else if (!strcmp(*argv, "icase")
			   || !strcmp(*argv, "ignore-case")) {
			regex_flags |= REG_ICASE;
			ctrl |= CNTL_REGEX_FLAGS;
		} else if (!strcmp(*argv, "case")) {
			regex_flags &= ~REG_ICASE;
			ctrl |= CNTL_REGEX_FLAGS;
		} else {
			_pam_log(LOG_ERR,
				 "unknown option: %s", *argv);
		}
	}
	if (!regex)
		_pam_log(LOG_ERR, "regex not specified");
	if (user_name && transform)
		_pam_log(LOG_ERR, "Both `user' and `transform' are given");
	if (!(ctrl & CNTL_REGEX_FLAGS))
		regex_flags |= REG_EXTENDED;
	cntl_flags = ctrl;
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
	
	DEBUG(100,("enter pam_sm_authenticate"));

	if (!regex)
		return PAM_AUTHINFO_UNAVAIL;

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
		DEBUG(100,("new name: %s", newname));
		MAKE_STR(pamh, newname, name);
		pam_set_item(pamh, PAM_AUTHTOK, name);
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
				if (user_name) 
					retval = pam_set_item(pamh, PAM_USER,
							      strdup(user_name));
			} else 
				_pam_log(LOG_NOTICE, "allowing %s", name);
			break;
		}
	}

	DEBUG(100,("exit pam_sm_authenticate: %d", retval));
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

