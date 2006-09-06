/* This file is part of pam-modules.
   Copyright (C) 2001, 2006 Sergey Poznyakoff
 
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
   MA 02110-1301 USA  */

#if defined(HAVE_CONFIG_H)
# include <config.h>
#endif
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

/* indicate the following groups are defined */
#define PAM_SM_AUTH

#ifndef LINUX_PAM
#include <security/pam_appl.h>
#endif				/* LINUX_PAM */
#include <security/pam_modules.h>

#include <common.c>

#define CNTL_DEBUG        0x0001
#define CNTL_AUDIT        0x0002
#define CNTL_AUTHTOK      0x0004

#define CNTL_SENSE_DENY   0x0010
#define CNTL_REGEX_FLAGS  0x0020

#define CNTL_DEBUG_LEV() (cntl_flags>>16)
#define CNTL_SET_DEBUG_LEV(cntl,n) (cntl |= ((n)<<16))

static int cntl_flags;
static const char *regex = NULL;
static int regex_flags = REG_NOSUB;
static const char *user_name = NULL;

#define DEBUG(m,c) if (CNTL_DEBUG_LEV()>=(m)) _pam_debug c
#define AUDIT(c) if (cntl_flags&CNTL_AUDIT) _pam_debug c

static void
make_str(pam_handle_t *pamh, const char *str, const char *name, char **ret)
{
	int retval;
	char *newstr = XSTRDUP(str);

	retval = pam_set_data(pamh, name, (void *)newstr, _cleanup_string);
	if (retval != PAM_SUCCESS) {
		_pam_log(LOG_CRIT, 
			 "can't keep data [%s]: %s",
			 name,
			 pam_strerror(pamh, retval));
		_pam_delete(newstr);
	} else {
		*ret = newstr;
		newstr = NULL;
	}
}

#define MAKE_STR(pamh, str, var) \
 make_str(pamh,str,#var,&var)
	
static void
_pam_parse(pam_handle_t *pamh, int argc, const char **argv)
{
	int ctrl = 0;

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
				ctrl |= CNTL_SENSE_DENY;
			else if (strcmp(*argv + 6, "allow"))
				_pam_log(LOG_ERR,"unknown sense value: %s",
					 *argv + 6);
		} else if (!strncmp(*argv, "regex=", 6))
			regex = *argv + 6;
		else if (!strcmp(*argv, "extended")) {
			regex_flags |= REG_EXTENDED;
			ctrl |= CNTL_REGEX_FLAGS;
		} else if (!strcmp(*argv, "basic")) {
			regex_flags &= ~REG_EXTENDED;
			ctrl |= CNTL_REGEX_FLAGS;
		} else if (!strcmp(*argv, "icase")) {
			regex_flags |= REG_ICASE;
			ctrl |= CNTL_REGEX_FLAGS;
		} else if (!strcmp(*argv, "case")) {
			regex_flags &= ~REG_ICASE;
			ctrl |= CNTL_REGEX_FLAGS;
		} else if (!strncmp(*argv, "user=",5)) {
			user_name = *argv + 5;
		} else {
			_pam_log(LOG_ERR,
				 "unknown option: %s", *argv);
		}
	}
	if (!regex)
		_pam_log(LOG_ERR, "regex not specified");
	if (!ctrl & CNTL_REGEX_FLAGS)
		regex_flags |= REG_EXTENDED;
	cntl_flags = ctrl;
}

/*
 * PAM framework looks for these entry-points to pass control to the
 * authentication module.
 */

/* Fun starts here :)

 * pam_sm_authenticate() performs RADIUS authentication
 *
 */

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh,
		    int flags,
		    int argc,
		    const char **argv)
{
	int retval;
	char *name;
	char *password;
	regex_t rx;

	_pam_parse(pamh, argc, argv);
	
	DEBUG(100,("enter pam_sm_authenticate"));

	if (!regex)
		return PAM_AUTHINFO_UNAVAIL;
	
	for (;;) {

		/*
		 * get username
		 */
		retval = pam_get_user(pamh, (const char**)&name, "login: ");
		if (retval == PAM_SUCCESS) {
			DEBUG(10, ("username [%s] obtained", name));
		} else {
			_pam_log(LOG_NOTICE, "can't get username");
			break;
		}

		if (regcomp(&rx, regex, regex_flags)) {
			_pam_log(LOG_NOTICE, "can't compile regex: %s", regex);
			retval = PAM_AUTHINFO_UNAVAIL;
			break;
		}

		retval = regexec(&rx, name, 0, NULL, 0);
		if (retval) {
			DEBUG(1,("%s does not match %s",name,regex));
		}
		if (cntl_flags & CNTL_SENSE_DENY)
			retval = !retval;
		if (retval) {
			_pam_log(LOG_NOTICE, "rejecting %s", name);
			retval = PAM_AUTH_ERR;
		} else {
			_pam_log(LOG_NOTICE, "allowing %s", name);
			if (user_name) {
				retval = pam_set_item(pamh, PAM_USER,
						      strdup(user_name));
				DEBUG(100,("user name=%s, status=%d",
					   user_name,retval));
			}
			retval = PAM_SUCCESS;
		}
		break;
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

