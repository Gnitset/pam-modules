/* This file is part of pam-modules.
   Copyright (C) 2006, 2007, 2008 Sergey Poznyakoff
 
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

#include <graypam.h>


/* Command line parsing */
static int cntl_flags;
static long debug_level;

static int xargc;
static const char **xargv;
static int priority = LOG_INFO;
static int facility = LOG_AUTHPRIV;
static const char *syslog_tag = MODULE_NAME;
static int do_open = 1;

static struct keyword syslog_facility[] = {
        DCL("user",       LOG_USER),
	DCL("daemon",     LOG_DAEMON),
	DCL("auth",       LOG_AUTH),
	DCL("authpriv",   LOG_AUTHPRIV),
	DCL("local0",     LOG_LOCAL0),
	DCL("local1",     LOG_LOCAL1),
	DCL("local2",     LOG_LOCAL2),
	DCL("local3",     LOG_LOCAL3),
	DCL("local4",     LOG_LOCAL4),
	DCL("local5",     LOG_LOCAL5),
	DCL("local6",     LOG_LOCAL6),
	DCL("local7",     LOG_LOCAL7),
	{ NULL }
};

static struct keyword syslog_priority[] = {
        DCL("emerg",      LOG_EMERG ),
	DCL("alert",      LOG_ALERT ),
	DCL("crit",       LOG_CRIT ),
	DCL("err",        LOG_ERR ),
	DCL("warning",    LOG_WARNING ),
	DCL("notice",     LOG_NOTICE ),
	DCL("info",       LOG_INFO ),
	DCL("debug",      LOG_DEBUG ),
	{ NULL }
};

static int
parse_priority(struct pam_opt *opt, const char *str)
{
	int len;
	struct keyword *kw;

	for (len = 0; str[len]; len++)
		if (ispunct(str[len]))
			break;

	if (len) {
		kw = gray_find_keyword(syslog_facility, str, len);
		if (!kw) {
			_pam_log(LOG_ERR,
				 "unknown syslog facility: %*.*s",
				 len, len, str);
			return 1;
		}
		facility = kw->code;
	}
	
	if (str[len]) {
		str += len + 1;
		kw = gray_find_keyword(syslog_priority, str, strlen(str));
		if (!kw) {
			_pam_log(LOG_ERR,
				 "unknown syslog priority: %s", str);
			return 1;
		}
		priority = kw->code;
	}
	return 0;
}

struct pam_opt pam_opt[] = {
	{ PAM_OPTSTR(debug), pam_opt_long, &debug_level },
	{ PAM_OPTSTR(debug), pam_opt_const, &debug_level, { 1 } },
	{ PAM_OPTSTR(audit), pam_opt_bitmask, &cntl_flags, { CNTL_AUDIT } },
	{ PAM_OPTSTR(waitdebug), pam_opt_null, NULL, { 0 },
	  gray_wait_debug_fun },
	{ PAM_OPTSTR(tag), pam_opt_string, &syslog_tag },
	{ PAM_OPTSTR(pri), pam_opt_null, NULL, 0, parse_priority },
	{ PAM_OPTSTR(open), pam_opt_bool, &do_open },
	{ NULL }
};


static void
_pam_parse(pam_handle_t *pamh, int argc, const char **argv)
{
	int i;
	const char **targv;

	gray_log_init(0, MODULE_NAME, LOG_AUTHPRIV);

	targv = gray_malloc(argc * sizeof (targv[0]));
	for (i = 0; i < argc; i++) {
		if (argv[i][0] == '-') {
			if (argv[i][1] == '-' && argv[i][2] == 0)
				break;
			targv[i] = argv[i] + 1;
		} else
			break;
	}

	gray_parseopt(pam_opt, i, targv);
	free(targv);
	
	xargc = argc - i;
	xargv = argv + i;

	closelog();
	gray_log_init(!do_open, syslog_tag, facility);
}

static int
echo(pam_handle_t *pamh, const char *prefix, int argc, const char **argv)
{
	char *str;
	gray_slist_t slist;

	_pam_parse(pamh, argc, argv);
	slist = gray_slist_create();
	if (prefix) {
		gray_slist_append(slist, prefix, strlen(prefix));
		gray_slist_append(slist, ": ", 2);
	}
	gray_expand_argv(pamh, xargc, xargv, slist);
	gray_slist_append_char(slist, 0);
	str = gray_slist_finish(slist);
	_pam_log(priority, "%s", str);
	gray_slist_free(&slist);
	return PAM_IGNORE;
}



PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	gray_pam_init(PAM_IGNORE);
	return echo(pamh, __FUNCTION__, argc, argv);
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	gray_pam_init(PAM_IGNORE);
	return echo(pamh, __FUNCTION__, argc, argv);
}

PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh,int flags,int argc,const char **argv)
{
	gray_pam_init(PAM_IGNORE);
	return echo(pamh, __FUNCTION__, argc, argv);
}

PAM_EXTERN int
pam_sm_acct_mgmt (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	gray_pam_init(PAM_IGNORE);
	return echo(pamh, __FUNCTION__, argc, argv);
}

PAM_EXTERN int
pam_sm_open_session (pam_handle_t *pamh, int flags, int argc,
                     const char **argv)
{
	gray_pam_init(PAM_IGNORE);
	return echo(pamh, __FUNCTION__, argc, argv);
}

PAM_EXTERN int
pam_sm_close_session (pam_handle_t *pamh, int flags, int argc,
		      const char **argv)
{
	gray_pam_init(PAM_IGNORE);
	return echo(pamh, __FUNCTION__, argc, argv);
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
