/* This file is part of pam-modules.
 * Copyright (C) 2001 Sergey Poznyakoff
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301 USA  
 */

#if defined(HAVE_CONFIG_H)
# include <config.h>
#endif
#ifdef HAVE__PAM_ACONF_H
#include <security/_pam_aconf.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <varargs.h>
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

#ifndef PAM_CONV_AGAIN
# define PAM_CONV_AGAIN PAM_TRY_AGAIN
#endif
#ifndef PAM_AUTHTOK_RECOVER_ERR
# define PAM_AUTHTOK_RECOVER_ERR PAM_AUTHTOK_RECOVERY_ERR
#endif
#ifndef PAM_EXTERN
# define PAM_EXTERN
#endif

#define PAM_OVERWRITE(s)        \
  do {                           \
	register char *p;        \
        if  ((p = s) != NULL)    \
	    while (*p) *p++ = 0; \
  } while (0) 

#define PAM_DROP_REPLY(reply, nrepl)                 \
  do {                                                \
	int i;                                        \
	for (i=0; i<nrepl; i++) {                     \
            PAM_OVERWRITE(reply[i].resp);             \
            free(reply[i].resp);                      \
	}                                             \
	if (reply)                                    \
	    free(reply);                              \
  } while (0)
	
static void
_pam_delete(char *x)
{
	PAM_OVERWRITE(x);
	free(x);
}

static void
_cleanup_string(pam_handle_t *pamh, void *x, int error_status)
{
	_pam_delete(x);
}

/* logging */
static void
_pam_vlog(int err, const char *format, va_list args)
{
	openlog("pam_regex", LOG_CONS|LOG_PID, LOG_AUTH);
	vsyslog(err, format, args);
	closelog();
}

static void
_pam_log(err, format, va_alist)
	int err;
	const char *format;
	va_dcl
{
	va_list args;

	va_start(args);
	_pam_vlog(err, format, args);
	va_end(args);
}

static void
_pam_debug(format, va_alist)
	char *format;
	va_dcl
{
	va_list args;

	va_start(args);
	_pam_vlog(LOG_DEBUG, format, args);
	va_end(args);
}

#define CNTL_DEBUG        0x0001
#define CNTL_AUDIT        0x0002
#define CNTL_AUTHTOK      0x0004
#define CNTL_WAITDEBUG    0x0008
#define CNTL_SENSE_DENY   0x0010
#define CNTL_REGEX_FLAGS  0x0020

#define CNTL_DEBUG_LEV() (cntl_flags>>16)
#define CNTL_SET_DEBUG_LEV(cntl,n) (cntl |= ((n)<<16))

static int cntl_flags;
static char *regex = NULL;
static int regex_flags = REG_NOSUB;

#define DEBUG(m,c) if (CNTL_DEBUG_LEV()>=(m)) _pam_debug c
#define AUDIT(c) if (cntl_flags&CNTL_AUDIT) _pam_debug c

#define XSTRDUP(s) (s) ? strdup(s) : NULL

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
	int ctrl=0;

	/* step through arguments */
	for (ctrl=0; argc-- > 0; ++argv) {

		/* generic options */

		if (!strncmp(*argv,"debug",5)) {
			ctrl |= CNTL_DEBUG;
			if ((*argv)[5] == '=') 
				CNTL_SET_DEBUG_LEV(ctrl,atoi(*argv+6));
			else
				CNTL_SET_DEBUG_LEV(ctrl,1);
		} else if (!strcmp(*argv,"audit"))
			ctrl |= CNTL_AUDIT;
		else if (!strcmp(*argv,"waitdebug"))
			ctrl |= CNTL_WAITDEBUG;
		else if (!strcmp(*argv,"use_authtok"))
			ctrl |= CNTL_AUTHTOK;
		else if (!strncmp(*argv,"sense=",6)) {
			if (strcmp(*argv+6,"deny") == 0)
				ctrl |= CNTL_SENSE_DENY;
			else if (strcmp(*argv+6,"allow"))
				_pam_log(LOG_ERR,"unknown sense value: %s",
					 *argv+6);
		} else if (!strncmp(*argv,"regex=",6))
			regex = *argv + 6;
		else if (!strcmp(*argv,"extended")) {
			regex_flags |= REG_EXTENDED;
			ctrl |= CNTL_REGEX_FLAGS;
		} else if (!strcmp(*argv,"basic")) {
			regex_flags &= ~REG_EXTENDED;
			ctrl |= CNTL_REGEX_FLAGS;
		} else if (!strcmp(*argv,"icase")) {
			regex_flags |= REG_ICASE;
			ctrl |= CNTL_REGEX_FLAGS;
		} else if (!strcmp(*argv,"case")) {
			regex_flags &= ~REG_ICASE;
			ctrl |= CNTL_REGEX_FLAGS;
		} else {
			_pam_log(LOG_ERR,"pam_parse: unknown option; %s",*argv);
		}
	}
	if (!regex)
		_pam_log(LOG_ERR,"pam_parse: regex not sepcified");
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
	
#ifdef DEBUG_MODE
	if (cntl_flags & CNTL_WAITDEBUG) {
		_pam_log(LOG_CRIT, "WAITING FOR DEBUG AT %s:%d",
			 __FILE__, __LINE__);
		retval = 0;
		while (!retval)
			retval=retval;
	}
#endif	
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
		} else
			retval = PAM_SUCCESS;
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
	"pam_radius",                      /* name of the module */
	pam_sm_authenticate,                 
	pam_sm_setcred,
	NULL,
	NULL,
	NULL,
	NULL
};

#endif

