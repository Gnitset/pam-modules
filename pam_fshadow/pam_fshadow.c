/* This file is part of pam-modules.
 * Copyright (C) 2001, 2005, 2007-2008, 2010-2012, 2014-2015 Sergey
 * Poznyakoff
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 3 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/* pam_fshadow */
 
#include <graypam.h>
#include <time.h>
#include <pwd.h>
#ifdef HAVE_SHADOW_H
#include <shadow.h>
#endif
  
#if defined(HAVE_CRYPT_H)
# include <crypt.h>
#else
extern char *crypt(const char *, const char *);
#endif

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT

#include <security/pam_modules.h>

#if !HAVE_FGETPWENT
static struct passwd *
fgetpwent(FILE *fp)
{
	static char *buffer;
	static size_t buflen;
	static struct passwd pwbuf;
	size_t pos = 0;
	int c;
	size_t off[6];
	int i = 0;
	
	while ((c = fgetc(fp)) != EOF) {
		if (pos == buflen) {
			char *nb;
			size_t ns;
			
			if (buflen == 0)
				ns = 128;
			else {
				ns = ns * 2;
				if (ns < buflen) {
					errno = ENOMEM;
					return NULL;
				}
			}
			nb = realloc(buffer, ns);
			if (!nb)
				return NULL;
			buffer = nb;
			buflen = ns;
		}
		if (c == '\n') {
			buffer[pos++] = 0;
			if (i != sizeof(off)/sizeof(off[0]))
			  continue;
			break;
		}
		if (c == ':') {
			buffer[pos++] = 0;
			if (i < sizeof(off)/sizeof(off[0]))
				off[i++] = pos;
		} else
			buffer[pos++] = c;
	}

	if (pos == 0)
		return NULL;
	
	pwbuf.pw_name   = buffer;
	pwbuf.pw_passwd = buffer + off[0];
	pwbuf.pw_uid    = strtoul(buffer + off[1], NULL, 10);
	pwbuf.pw_gid    = strtoul(buffer + off[2], NULL, 10);
	pwbuf.pw_gecos  = buffer + off[3];
	pwbuf.pw_dir    = buffer + off[4];
	pwbuf.pw_shell  = buffer + off[5];

	return &pwbuf;
}
#endif

#define CNTL_AUTHTOK       0x0010 
#define CNTL_PASSWD        0x0020
#define CNTL_SHADOW        0x0040
#define CNTL_REGEX         0x0080
#define CNTL_REVERT_INDEX  0x0100

char *sysconfdir = SYSCONFDIR;
static int cntl_flags = CNTL_PASSWD|CNTL_SHADOW;
static long debug_level = 0;

static regex_t rexp;
static const char *regex_str = NULL;
static int regex_flags = REG_EXTENDED;
static int username_index = 1;
static int domain_index = 2;

struct pam_opt pam_opt[] = {
	{ PAM_OPTSTR(debug), pam_opt_long, &debug_level },
	{ PAM_OPTSTR(debug), pam_opt_const, &debug_level, { 1 } },
	{ PAM_OPTSTR(audit), pam_opt_const, &debug_level, { 100 } },
	{ PAM_OPTSTR(waitdebug), pam_opt_null, NULL, { 0 },
	  gray_wait_debug_fun },
	{ PAM_OPTSTR(use_authtok), pam_opt_bitmask, &cntl_flags,
	  { CNTL_AUTHTOK } },
	{ PAM_OPTSTR(sysconfdir), pam_opt_string, &sysconfdir },
	{ PAM_OPTSTR(regex), pam_opt_string, &regex_str },
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
	{ PAM_OPTSTR(passwd), pam_opt_bool, &cntl_flags, CNTL_PASSWD },
	{ PAM_OPTSTR(shadow), pam_opt_bool, &cntl_flags, CNTL_SHADOW },
	{ PAM_OPTSTR(revert-index), pam_opt_bool, &cntl_flags,
	  CNTL_REVERT_INDEX },
 	{ NULL }
};

static int
_pam_parse(pam_handle_t *pamh, int argc, const char **argv)
{
	int retval = PAM_SUCCESS;
	
	memset(&rexp, 0, sizeof(rexp));
	regex_str = NULL;
	regex_flags = REG_EXTENDED;
	username_index = 1;
	domain_index = 2;

	gray_log_init(0, MODULE_NAME, LOG_AUTHPRIV);
	if (gray_parseopt(pam_opt, argc, argv))
		return PAM_AUTHINFO_UNAVAIL;

	if ((cntl_flags & (CNTL_PASSWD|CNTL_SHADOW)) == 0) {
		_pam_log(LOG_CRIT,
			 "either passwd or shadow must be true");
		return PAM_AUTHINFO_UNAVAIL;
	}
	if (cntl_flags & CNTL_REVERT_INDEX) {
		username_index = 2;
		domain_index = 1;
	}
	if (regex_str) {
		int rc;
		if (rc = regcomp(&rexp, regex_str, regex_flags)) {
			size_t s = regerror(rc, &rexp, NULL, 0);
			char *buf = malloc (s);
			if (buf) {
				regerror(rc, &rexp, buf, s);
				_pam_log(LOG_NOTICE,
					 "cannot compile regex `%s': %s",
					 regex_str, buf);
				free (buf);
			} else
				_pam_log(LOG_NOTICE,
					 "cannot compile regex `%s'",
					 regex_str);
			retval = PAM_AUTHINFO_UNAVAIL;
		} else if (rexp.re_nsub != 2) {
			_pam_log(LOG_NOTICE,
				 "invalid regular expression `%s': "
				 "must contain two reference groups",
				 regex_str);
			regfree(&rexp);
			retval = PAM_AUTHINFO_UNAVAIL;
		} else
			cntl_flags |= CNTL_REGEX;
	}
       
	return retval;
}

static int
_pam_get_password(pam_handle_t *pamh, char **password, const char *prompt)
{
	char *item, *token;
	int retval;
	struct pam_message msg[3], *pmsg[3];
	struct pam_response *resp;
	int i, replies;

	DEBUG(90,("enter _pam_get_password"));
	
	if (cntl_flags & CNTL_AUTHTOK) {
		/*
		 * get the password from the PAM item
		 */
		retval = pam_get_item(pamh, PAM_AUTHTOK,
				      (const void **) &item);
		if (retval != PAM_SUCCESS) {
			/* very strange. */
			_pam_log(LOG_ALERT,
				 "can't retrieve password item: %s",
				 pam_strerror(pamh, retval));
			return retval;
		} else if (item != NULL) {
			*password = item;
			item = NULL;
			return PAM_SUCCESS;
		} else
			return PAM_AUTHTOK_RECOVER_ERR;
	}

	/*
	 * ask user for the password
	 */
	/* prepare to converse */

	i = 0;
	pmsg[i] = &msg[i];
	msg[i].msg_style = PAM_PROMPT_ECHO_OFF;
	msg[i++].msg = (const void*)prompt;
	replies = 1;

	/* run conversation */
	resp = NULL;
	token = NULL;
	retval = gray_converse(pamh, i, pmsg, &resp);

	if (resp != NULL) {
		if (retval == PAM_SUCCESS) { 	/* a good conversation */
 			token = XSTRDUP(resp[i - replies].resp);
			pam_set_item(pamh, PAM_AUTHTOK, token);
			DEBUG(100,("app returned [%s]", token));
			PAM_DROP_REPLY(resp, 1);
		} else {
			_pam_log(LOG_ERR, "conversation error: %s",
				 pam_strerror(pamh, retval));
		}
		
	} else {
		retval = (retval == PAM_SUCCESS)
			? PAM_AUTHTOK_RECOVER_ERR : retval;
	}

	if (retval == PAM_SUCCESS) {
		/*
		 * keep password as data specific to this module. pam_end()
		 * will arrange to clean it up.
		 */
		retval = pam_set_data(pamh, "password",
				      (void *)token,
				      gray_cleanup_string);
		if (retval != PAM_SUCCESS) {
			_pam_log(LOG_CRIT, 
			         "can't keep password: %s",
				 pam_strerror(pamh, retval));
			gray_pam_delete(token);
		} else {
			*password = token;
			token = NULL;	/* break link to password */
		}
	} else {
		_pam_log(LOG_ERR,
			 "unable to obtain a password: %s",
			 pam_strerror(pamh, retval));
	} 
	
	DEBUG(90,("exit _pam_get_password: %d", retval));
	return retval;
}

char *
mkfilename(const char *dir, const char *name)
{
        int len = strlen(dir) + strlen(name);
        char *p = malloc(len+2);
	if (!p) {
		_pam_log(LOG_EMERG, "not enough memory");
		abort ();
	}
        sprintf(p, "%s/%s", dir, name);
        return p;
}

int
verify_user_acct(const char *confdir, const char *username, char **pwd)
{
	char *filename = mkfilename(confdir, "passwd");
	FILE *fp;
	int retval;

	DEBUG(10,("Looking up user `%s' in `%s'",
		  username, filename));
	
	*pwd = NULL;
	fp = fopen (filename, "r");
	if (fp) {
		struct passwd *pw;
		
		while ((pw = fgetpwent(fp)) != NULL) {
			if (strcmp (pw->pw_name, username) == 0)
				break;
		}
		if (!pw) {
			_pam_log(LOG_ERR, "user %s not found in %s",
				 username, filename);
			retval = PAM_USER_UNKNOWN;
		} else {
			if (pw->pw_passwd && strlen(pw->pw_passwd) > 1)
				*pwd = strdup(pw->pw_passwd);
			retval = PAM_SUCCESS;
		}
	} else {
		_pam_log(LOG_ERR, "can't open %s: %s",
			 filename, strerror(errno));
		retval = PAM_SERVICE_ERR;
	}
	free(filename);
	return retval;
}

int
verify_user_pass(const char *confdir, const char *username,
		 const char *password)
{
#if defined(HAVE_FGETSPENT) && defined(HAVE_STRUCT_SPWD)
	struct spwd *sp = NULL;
	time_t curdays;
	FILE *fp;
	int retval = PAM_AUTH_ERR;
	char *shadow = mkfilename(confdir, "shadow");

	if (debug_level == 100)
		_pam_debug("Verifying user `%s' with password `%s' in `%s'",
			   username, password, shadow);
	else if (debug_level >= 10)
		_pam_debug("Verifying user `%s' in `%s'",
			   username, password, shadow);

	fp = fopen(shadow, "r");
	if (!fp) {
		_pam_log(LOG_ERR,
			 "can't open %s: %s", shadow, strerror(errno));
		free(shadow);
		return PAM_SERVICE_ERR;
	}

	while ((sp = fgetspent(fp)) != NULL
	       && strcmp(sp->sp_namp, username))
		;
	fclose(fp);
	
	if (!sp) {
		_pam_log(LOG_ERR,
			 "entry for %s not found in %s",
			 username, shadow);
		free(shadow);
		return PAM_USER_UNKNOWN;
	}

	/* We have the user's information, now let's check if his account
	   has expired */
	curdays = time(NULL) / (60 * 60 * 24);
	if (sp->sp_min != -1 && curdays < sp->sp_lstchg + sp->sp_min)
		retval = PAM_AUTHTOK_ERR;
	else if (sp->sp_max != -1 && sp->sp_inact != -1 && sp->sp_lstchg != 0
		 && curdays > sp->sp_lstchg + sp->sp_max + sp->sp_inact)
		/* Password is too old */
		retval = PAM_ACCT_EXPIRED;
#if defined(HAVE_STRUCT_SPWD_SP_EXPIRE)
	else if (sp->sp_expire != -1 && sp->sp_lstchg != 0
		 && curdays > sp->sp_expire)
		/* Account has expired */
		retval = PAM_ACCT_EXPIRED;
#endif
	else if (strcmp(sp->sp_pwdp, crypt(password, sp->sp_pwdp)) == 0)
		retval = PAM_SUCCESS;
	else
		retval = PAM_AUTH_ERR;

	free(shadow);
	return retval;
#else
	return PAM_AUTH_ERR;
#endif
}

static int
copy_backref (pam_handle_t *pamh, const char *name,
	      const char *buf, regmatch_t rmatch[3], int index, char **pstr)
{
	char *str;
	size_t size;
	int rc;
	
	if (rmatch[index].rm_so == -1)
		size = 0;
	else
		size = rmatch[index].rm_eo - rmatch[index].rm_so;

	str = malloc (size + 1);
	if (!str) {
		_pam_log(LOG_CRIT, "not enough memory");
		return PAM_SYSTEM_ERR;
	}
	rc = pam_set_data(pamh, name, (void *)str, gray_cleanup_string);
	if (rc != PAM_SUCCESS) {
		_pam_log(LOG_CRIT, 
			 "can't keep data [%s]: %s",
			 name,
			 pam_strerror(pamh, rc));
		gray_pam_delete(str);
	} else {
		if (size != 0)
			memcpy(str, buf + rmatch[index].rm_so, size);
		str[size] = 0;
		*pstr = str;
	}
	return rc;
}

/* --- authentication management functions (only) --- */

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags,
		    int argc, const char **argv)
{
	const char *username;
	char *password;
	int retval = PAM_AUTH_ERR;
	int rc;
	char *confdir;
	char *pwstr = NULL;
	
	/* parse arguments */
	if ((rc = _pam_parse(pamh, argc, argv)) != PAM_SUCCESS)
		return rc;
	confdir = sysconfdir;
	
	/* Get the username */
	retval = pam_get_user(pamh, &username, NULL);
	if (retval != PAM_SUCCESS || !username) {
		DEBUG(1,("can not get the username"));
		if (cntl_flags & CNTL_REGEX)
			regfree(&rexp);
		return PAM_SERVICE_ERR;
	}

	if (cntl_flags & CNTL_REGEX) {
		regmatch_t rmatch[3];
		if (regexec(&rexp, username, 3, rmatch, 0) == 0) {
			char *domain;
			
			rc = copy_backref(pamh, "DOMAIN", username, rmatch,
					  domain_index, &domain);
			if (rc != PAM_SUCCESS)
				return rc;
			rc = copy_backref(pamh, "USERNAME", username, rmatch,
					  username_index, (char **) &username);
			if (rc != PAM_SUCCESS)
				return rc;
			confdir = mkfilename(sysconfdir, domain);
			pam_set_data(pamh, "CONFDIR",
				     (void *)confdir, gray_cleanup_string);
		} else {
			DEBUG(1,("user name `%s' does not match regular "
				 "expression `%s'",
				 username,
				 regex_str));
		}
		regfree(&rexp);
	}
	
	/* Get the password */
	if (_pam_get_password(pamh, &password, "Password:"))
		return PAM_SERVICE_ERR;

	if (retval != PAM_SUCCESS) {
		_pam_log(LOG_ERR, "Could not retrive user's password");
		return -2;
	}

	if (cntl_flags & CNTL_PASSWD)
		retval = verify_user_acct(confdir, username, &pwstr);
	else
		retval = PAM_SUCCESS;
	if (retval == PAM_SUCCESS) {
		if (pwstr) {
			if (strcmp(pwstr, crypt(password, pwstr)) == 0)
				retval = PAM_SUCCESS;
			else
				retval = PAM_AUTH_ERR;
			free(pwstr);
		} else if (cntl_flags & CNTL_SHADOW)
			retval = verify_user_pass(confdir, username, password);
	}
	
	switch (retval) {
	case PAM_ACCT_EXPIRED:
		_pam_log(LOG_NOTICE, "user '%s': account expired", username);
		break;
	case PAM_SUCCESS:
		_pam_log(LOG_NOTICE, "user '%s' granted access", username);
		break;
	default:
		_pam_log(LOG_NOTICE, "user '%s' failed to authenticate",
			 username);
	}

	return retval;
}

PAM_EXTERN
int pam_sm_setcred(pam_handle_t *pamh, int flags,
		   int argc, const char **argv)
{
    return PAM_SUCCESS;
}

PAM_EXTERN
int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
		   int argc, const char **argv)
{
    return PAM_SUCCESS;
}


#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_fshadow_modstruct = {
     "pam_fshadow",
     pam_sm_authenticate,
     pam_sm_setcred,
     NULL,
     NULL,
     NULL,
     NULL,
};

#endif

