/* This file is part of pam-modules.
   Copyright (C) 2006 Sergey Poznyakoff
 
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

#if defined(HAVE_CONFIG_H)
# include <config.h>
#endif
#ifdef HAVE__PAM_ACONF_H
#include <security/_pam_aconf.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <stdarg.h>
#define obstack_chunk_alloc malloc
#define obstack_chunk_free free
#include <obstack.h>

#define PAM_SM_AUTH
#define PAM_SM_PASSWORD
#include <security/pam_modules.h>

#include <common.c>


/* Command line parsing */
#define CNTL_DEBUG        0x0001
#define CNTL_AUDIT        0x0002
#define CNTL_WAITDEBUG    0x0004

#define CNTL_DEBUG_LEV() (cntl_flags>>16)
#define CNTL_SET_DEBUG_LEV(cntl,n) (cntl |= ((n)<<16))

static int cntl_flags;

static int xargc;
static const char **xargv;
static int priority = LOG_INFO;

#define DEBUG(m,c) if (CNTL_DEBUG_LEV()>=(m)) _pam_debug c
#define AUDIT(c) if (cntl_flags&CNTL_AUDIT) _pam_debug c

struct keyword {
	char *name;
	int len;
	int code;
};
#define DCL(n,c) { n, sizeof n - 1, c }

static struct keyword *
find_keyword(struct keyword *kwtab, const char *str, size_t len)
{
	for (; kwtab->name; kwtab++)
		if (kwtab->len == len
		    && strncmp(kwtab->name, str, kwtab->len) == 0)
			return kwtab;
	return NULL;
}

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

static char *
parse_priority(const char *str)
{
	int len;
	struct keyword *kw;

	for (len = 0; str[len]; len++)
		if (ispunct(str[len]))
			break;

	if (len) {
		kw = find_keyword(syslog_facility, str, len);
		if (!kw) {
			_pam_log(LOG_ERR,
				 "unknown syslog facility: %*.*s",
				 len, len, str);
			return;
		}
		facility = kw->code;
	}
	
	if (str[len]) {
		str += len + 1;
		kw = find_keyword(syslog_priority, str, strlen(str));
		if (!kw) {
			_pam_log(LOG_ERR,
				 "unknown syslog priority: %s", str);
			return;
		}
		priority = kw->code;
	}
}

static void
_pam_parse(pam_handle_t *pamh, int argc, const char **argv)
{
	int ctrl = 0;

	/* Collect generic arguments */
	for (; argc > 0; argv++, argc--) {
		if (!strncmp(*argv, "-debug", 6)) {
			ctrl |= CNTL_DEBUG;
			if ((*argv)[6] == '=') 
				CNTL_SET_DEBUG_LEV(ctrl, atoi(*argv + 7));
			else
				CNTL_SET_DEBUG_LEV(ctrl, 1);
		} else if (!strcmp(*argv, "-audit"))
			ctrl |= CNTL_AUDIT;
		else if (!strncmp(*argv, "-waitdebug", 10))
			WAITDEBUG(*argv + 10);
		else if (!strncmp(*argv, "-tag=", 5))
			syslog_tag = *argv + 5;
		else if (!strncmp(*argv, "-pri=", 5))
			parse_priority(*argv + 5);
		else if (!strcmp(*argv, "-no-open"))
			syslog_dont_open = 1;
		else if (!strcmp(*argv, "--"))
			break;
		else if (**argv == '-')
			_pam_log(LOG_ERR,
				 "unknown option: %s", *argv);
		else
			break;
	}
	
	/* Save the format variables */
	xargc = argc;
	xargv = argv;

	cntl_flags = ctrl;
}

static struct keyword vartab[] = {
	DCL("service", PAM_SERVICE),
	DCL("user", PAM_USER),
	DCL("tty", PAM_TTY),
	DCL("rhost", PAM_RHOST),
	DCL("ruser", PAM_RUSER),
	DCL("prompt", PAM_USER_PROMPT),
	DCL("password", PAM_AUTHTOK),
	{ NULL }
};

static int
var_tok(const char *str, const char ** pvar, size_t *plen)
{
	size_t len;

	for (len = 0; str[len]; len++) {
		if (str[len] == '}' || str[len] == ':') {
			*pvar = str;
			*plen = len;
			return 0;
		}
	}
	return 1;
}

static int
repl_tok(const char *str, const char ** pret, size_t *plen)
{
	size_t len;

	for (len = 0; str[len]; len++) {
		if (str[len] == '}') {
			*pret = str;
			*plen = len;
			return 0;
		}
	}
	return 1;
}

static int
get_variable(pam_handle_t *pamh, const char *str, struct obstack *stk,
	     const char **endp)
{
	const char *name;
	size_t namelen;
	const char *repl = NULL;
	size_t repllen = 0;
	const char *val;
	size_t vallen;
	struct keyword *kw;
	const char *end;
	int rc;
	
	str++; /* Get past the initial $ */
	if (*str == '{') {
		str++;

		if (var_tok(str, &name, &namelen))
			return 1;

		end = str + namelen;
		if (*end == ':') {
			end++;
			if (*end == '-')
				end++;
			if (repl_tok(end, &repl, &repllen))
				return 1;
			end += repllen;
		}
		end++;
	} else {
		name = str;
		namelen = strlen(str);
		end = str + namelen;
	}

	kw = find_keyword(vartab, name, namelen);
	if (!kw) {
		_pam_log(LOG_ERR,
			 "unknown PAM variable: %*.*s",
			 namelen, namelen, name);
		return 1;
	}

	rc = pam_get_item(pamh, kw->code, (const void**) &val);
	if (rc) {
		_pam_log(LOG_ERR,
			 "cannot obtain variable %s: %s",
			 kw->name, pam_strerror(pamh, rc));
		return 1;
	}

	if (!val) {
		if (repl) {
			val = repl;
			vallen = repllen;
		} else {
			val = "";
			vallen = 0;
		}
	} else
		vallen = strlen(val);

	obstack_grow(stk, val, vallen);
	*endp = end;
	return 0;
}

static void
expand_string(pam_handle_t *pamh, struct obstack *stk)
{
	int i;

	for (i = 0; i < xargc; i++) {
		DEBUG(2,("%s: %d %s", __FUNCTION__, i, xargv[i]));
		if (i > 0)
			obstack_1grow(stk, ' ');
		if (strchr(xargv[i], '$') == 0)
			obstack_grow(stk, xargv[i], strlen(xargv[i]));
		else {
			const char *p;
			
			for (p = xargv[i]; *p; p++) {
				if (*p == '\\') {
					p++;
					obstack_1grow(stk, *p);
				} else if (*p == '$') {
					if (get_variable(pamh, p, stk, &p))
						obstack_1grow(stk, *p);
					else
						p--;
				} else
					obstack_1grow(stk, *p);
			}
		}
	}
}

static int
echo(pam_handle_t *pamh, const char *prefix, int argc, const char **argv)
{
	char *str;
	struct obstack stk;

	_pam_parse(pamh, argc, argv);
	obstack_init(&stk);
	if (prefix) {
		obstack_grow(&stk, prefix, strlen(prefix));
		obstack_grow(&stk, ": ", 2);
	}
	expand_string(pamh, &stk);
	obstack_1grow(&stk, 0);
	str = obstack_finish(&stk);
	_pam_log(priority, "%s", str);
	obstack_free(&stk, NULL);
	return PAM_IGNORE;
}



PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return echo(pamh, __FUNCTION__, argc, argv);
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return echo(pamh, __FUNCTION__, argc, argv);
}

PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh,int flags,int argc,const char **argv)
{
	return echo(pamh, __FUNCTION__, argc, argv);
}

PAM_EXTERN int
pam_sm_acct_mgmt (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return echo(pamh, __FUNCTION__, argc, argv);
}

PAM_EXTERN int
pam_sm_open_session (pam_handle_t *pamh, int flags, int argc,
                     const char **argv)
{
	return echo(pamh, __FUNCTION__, argc, argv);
}

PAM_EXTERN int
pam_sm_close_session (pam_handle_t *pamh, int flags, int argc,
		      const char **argv)
{
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
