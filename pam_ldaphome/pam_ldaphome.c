/* This file is part of pam-modules.
   Copyright (C) 2005-2008, 2010-2011 Sergey Poznyakoff

   This program is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by the
   Free Software Foundation; either version 3 of the License, or (at your
   option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License along
   with this program.  If not, see <http://www.gnu.org/licenses/>. */

#ifdef HAVE__PAM_ACONF_H
# include <security/_pam_aconf.h>
#endif
#ifndef LINUX_PAM
# include <security/pam_appl.h>
#endif				/* LINUX_PAM */
#include <security/pam_modules.h>

#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <ldap.h>
#include <pwd.h>
#include <grp.h>

#include "graypam.h"

/* indicate the following groups are defined */
#define PAM_SM_AUTH

static long debug_level;
static int cntl_flags;
static char *config_file_name;
static int ldap_debug_level;
/* FIXME: This should be read from sshd_config */
static char *authorized_keys_file=".ssh/authorized_keys";
	
struct pam_opt pam_opt[] = {
	{ PAM_OPTSTR(debug),  pam_opt_long, &debug_level },
	{ PAM_OPTSTR(debug),  pam_opt_const, &debug_level, { 1 } },
	{ PAM_OPTSTR(audit),  pam_opt_bitmask, &cntl_flags, { CNTL_AUDIT } },
	{ PAM_OPTSTR(waitdebug), pam_opt_null, NULL, { 0 },
	  gray_wait_debug_fun },
	{ PAM_OPTSTR(config), pam_opt_string, &config_file_name },
	{ NULL }
};

static void
_pam_parse(pam_handle_t *pamh, int argc, const char **argv)
{
	cntl_flags = 0;
	debug_level = 0;
	config_file_name = SYSCONFDIR "/" MODULE_NAME ".conf";
	gray_log_init(0, MODULE_NAME, LOG_AUTHPRIV);
	gray_parseopt(pam_opt, argc, argv);
}

static void
argcv_free(int wc, char **wv)
{
	int i;

	for (i = 0; i < wc; i++) {
		free(wv[i]);
		free(wv);
	}
}

static int
argcv_split(const char *str, int *pargc, char ***pargv)
{
	int argc, i;
	char **argv;
	const char *p;
	int rc = 0;
	
	argc = 1;
	for (p = str; *p; p++) {
		if (*p == ' ')
			argc++;
	}
	argv = calloc(argc + 1, sizeof(argv[0]));
	if (!argv)
		return 1;
	for (i = 0, p = str;;) {
		size_t len = strcspn(p, " ");
		char *q = malloc(len + 1);

		if (!q) {
			rc = errno;
			break;
		}
		memcpy(q, p, len);
		q[len] = 0;
		argv[i++] = q;
		p += len;
		if (p)
			p += strspn(p, " ");
		if (!*p)
			break;
	}

	if (rc) {
		argcv_free(argc, argv);
		errno = rc;
		return 1;
	}

	argv[i] = NULL;
	*pargc = argc;
	*pargv = argv;
	return 0;
}

static char *
argcv_concat(int wc, char **wv)
{
	char *res, *p;
	size_t size = 0;
	int i;
	
	for (i = 0; i < wc; i++)
		size += strlen(wv[i]) + 1;
	size++;
	res = malloc(size);
	if (!res)
		return 0;
	for (p = res, i = 0; ; i++) {
		strcpy(p, wv[i]);
		p += strlen(wv[i]);
		if (i < wc)
			*p++ = ' ';
		else
			break;
	}
	*p = 0;
	return res;
}

char *
parse_ldap_uri(const char *uri)
{
	int wc;
	char **wv;
	LDAPURLDesc *ludlist, **ludp;
	char **urls = NULL;
	int nurls = 0;
	char *ldapuri = NULL;
	int rc;
	
	rc = ldap_url_parse(uri, &ludlist);
	if (rc != LDAP_URL_SUCCESS) {
		_pam_log(LOG_ERR, "cannot parse LDAP URL(s)=%s (%d)",
			 uri, rc);
		return NULL;
	}
      
	for (ludp = &ludlist; *ludp; ) {
		LDAPURLDesc *lud = *ludp;
		char **tmp;
	  
		if (lud->lud_dn && lud->lud_dn[0]
		    && (lud->lud_host == NULL || lud->lud_host[0] == '\0'))  {
			/* if no host but a DN is provided, try
			   DNS SRV to gather the host list */
			char *domain = NULL, *hostlist = NULL;
			size_t i;
	      
			if (ldap_dn2domain (lud->lud_dn, &domain) ||
			    !domain) {
				_pam_log(LOG_ERR,
					 "DNS SRV: cannot convert "
					 "DN=\"%s\" into a domain",
					 lud->lud_dn);
				goto dnssrv_free;
			}
	      
			rc = ldap_domain2hostlist(domain, &hostlist);
			if (rc) {
				_pam_log(LOG_ERR,
					 "DNS SRV: cannot convert "
					 "domain=%s into a hostlist",
					 domain);
				goto dnssrv_free;
			}

			if (argcv_split(hostlist, &wc, &wv)) {
				_pam_log(LOG_ERR,
					 "DNS SRV: could not parse "
					 "hostlist=\"%s\": %s",
					 hostlist, strerror(errno));
				goto dnssrv_free;
			}
			
			tmp = realloc(urls, sizeof(char *) * (nurls + wc + 1));
			if (!tmp) {
				_pam_log(LOG_ERR,
					 "DNS SRV %s", strerror(errno));
				goto dnssrv_free;
			}
			
			urls = tmp;
			urls[nurls] = NULL;
		
			for (i = 0; i < wc; i++) {
				char *p = malloc(strlen(lud->lud_scheme) +
						 strlen(wv[i]) +
						 3);
				if (!p) {
					_pam_log(LOG_ERR, "DNS SRV %s",
						 strerror(errno));
					goto dnssrv_free;
				}
			
				strcpy(p, lud->lud_scheme);
				strcat(p, "//");
				strcat(p, wv[i]);
				
				urls[nurls + i + 1] = NULL;
				urls[nurls + i] = p;
			}
			
			nurls += i;
	      
		  dnssrv_free:
			argcv_free(wc, wv);
			ber_memfree(hostlist);
			ber_memfree(domain);
		} else {
			tmp = realloc(urls, sizeof(char *) * (nurls + 2));
			if (!tmp) {
				_pam_log(LOG_ERR,
					 "DNS SRV %s", strerror(errno));
				break;
			}
			urls = tmp;
			urls[nurls + 1] = NULL;
			
			urls[nurls] = ldap_url_desc2str(lud);
			if (!urls[nurls]) {
				_pam_log(LOG_ERR, "DNS SRV %s",
					 strerror(errno));
				break;
			}
			nurls++;
		}
	
		*ludp = lud->lud_next;
		
		lud->lud_next = NULL;
		ldap_free_urldesc(lud);
	}

	if (ludlist) {
		ldap_free_urldesc (ludlist);
		return NULL;
	} else if (!urls)
		return NULL;
	ldapuri = argcv_concat(wc, wv);
	if (!ldapuri)
		_pam_log(LOG_ERR, "%s", strerror(errno));
	ber_memvfree ((void **)urls);
	return ldapuri;
}

static LDAP *
ldap_connect(struct gray_env *env)
{
	int rc;
	char *ldapuri = NULL;
	LDAP *ld = NULL;
	int protocol = LDAP_VERSION3; /* FIXME: must be configurable */
	char *val;
	
	if (ldap_debug_level) {
		if (ber_set_option (NULL, LBER_OPT_DEBUG_LEVEL,
				    &ldap_debug_level)
		    != LBER_OPT_SUCCESS )
			_pam_log(LOG_ERR,
				 "cannot set LBER_OPT_DEBUG_LEVEL %d",
				 ldap_debug_level);

		if (ldap_set_option (NULL, LDAP_OPT_DEBUG_LEVEL,
				     &ldap_debug_level)
		    != LDAP_OPT_SUCCESS )
			_pam_log(LOG_ERR,
				 "could not set LDAP_OPT_DEBUG_LEVEL %d",
				 ldap_debug_level);
	}

	val = gray_env_get(env, "uri");
	if (val) {
		ldapuri = parse_ldap_uri(val);
		if (!ldapuri)
			return NULL;
	}
	DEBUG(2, ("constructed LDAP URI: %s",
		  ldapuri ? ldapuri : "<DEFAULT>"));

	rc = ldap_initialize(&ld, ldapuri);
	if (rc != LDAP_SUCCESS) {
		_pam_log(LOG_ERR,
			 "cannot create LDAP session handle for "
			 "URI=%s (%d): %s",
			 ldapuri, rc, ldap_err2string(rc));
		free(ldapuri);
		return NULL;
	}
	free(ldapuri);

	val = gray_env_get(env, "tls");
		
	if (val && gray_boolean_true_p(val)) {
		rc = ldap_start_tls_s(ld, NULL, NULL);
		if (rc != LDAP_SUCCESS) {
			_pam_log(LOG_ERR,
				 "ldap_start_tls failed: %s",
				 ldap_err2string(rc));
			/* try to continue anyway, to avoid memory
			   leek (ld not being freed) */
		}
	}

	ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &protocol);

	/* FIXME: Timeouts, SASL, etc. */
	return ld;
}

static int
ldap_bind (LDAP *ld, struct gray_env *env)
{
	int msgid, err, rc;
	LDAPMessage *result;
	LDAPControl **ctrls;
	char msgbuf[256];
	char *matched = NULL;
	char *info = NULL;
	char **refs = NULL;
	static struct berval passwd;
	char *binddn;
	
	binddn = gray_env_get(env, "binddn");
	passwd.bv_val = gray_env_get(env, "bindpw");
	passwd.bv_len = passwd.bv_val ? strlen(passwd.bv_val) : 0;

	msgbuf[0] = 0;

	rc = ldap_sasl_bind(ld, binddn, LDAP_SASL_SIMPLE, &passwd,
			    NULL, NULL, &msgid);
	if (msgid == -1) {
		_pam_log(LOG_ERR,
			 "ldap_sasl_bind(SIMPLE) failed: %s",
			 ldap_err2string(rc));
		return 1;
	}

	if (ldap_result(ld, msgid, LDAP_MSG_ALL, NULL, &result ) == -1) {
		_pam_log(LOG_ERR, "ldap_result failed");
		return 1;
	}

	rc = ldap_parse_result(ld, result, &err, &matched, &info, &refs,
			       &ctrls, 1);
	if (rc != LDAP_SUCCESS) {
		_pam_log(LOG_ERR, "ldap_parse_result failed: %s",
			 ldap_err2string (rc));
		return 1;
	}

	if (ctrls)
		ldap_controls_free(ctrls);
	
	if (err != LDAP_SUCCESS
	    || msgbuf[0]
	    || (matched && matched[0])
	    || (info && info[0])
	    || refs) {
		/* FIXME: Use debug output for that */
		DEBUG(2,("ldap_bind: %s (%d)%s",
			 ldap_err2string(err), err, msgbuf));

		if (matched && *matched) 
			DEBUG(2,("matched DN: %s", matched));

		if (info && *info)
			DEBUG(2,("additional info: %s", info));
		
		if (refs && *refs) {
			int i;
			DEBUG(3,("referrals:"));
			for (i = 0; refs[i]; i++) 
				DEBUG(3,("%s", refs[i]));
		}
	}

	if (matched)
		ber_memfree(matched);
	if (info)
		ber_memfree(info);
	if (refs)
		ber_memvfree((void **)refs);

	return !(err == LDAP_SUCCESS);
}

static void
ldap_unbind(LDAP *ld)
{
	if (ld) {
		ldap_set_option(ld, LDAP_OPT_SERVER_CONTROLS, NULL);
		ldap_unbind_ext(ld, NULL, NULL);
	}
}

static char *
get_ldap_attr(LDAP *ld, LDAPMessage *msg, const char *attr)
{
	int rc;
	BerElement *ber = NULL;
	struct berval bv;
	char *ufn = NULL;
	char *val;
	struct berval **values;
	
	rc = ldap_get_dn_ber(ld, msg, &ber, &bv);
	ufn = ldap_dn2ufn(bv.bv_val);
	DEBUG(2, ("INFO: %s", ufn));
	ldap_memfree(ufn);

	values = ldap_get_values_len(ld, msg, attr);
	if (!values || !values[0]) {
		_pam_log(LOG_ERR,
			 "LDAP attribute `%s' has NULL value",
			 attr);
		return NULL;
	}
	val = strdup(values[0]->bv_val);
	if (!val)
		_pam_log(LOG_ERR, "%s", strerror(errno));
	else
		DEBUG(1, ("pubkey: %s", val));
	ldap_value_free_len(values);
	return val;
}

static char *
ldap_search(LDAP *ld, const char *base, const char *filter, const char *attr)
{
	int rc;
	LDAPMessage *res, *msg;
	ber_int_t msgid;
	char *attrs[2];
	char *ret;
	
	attrs[0] = (char*) attr;
	attrs[1] = NULL;
	rc = ldap_search_ext(ld, base, LDAP_SCOPE_SUBTREE,
			     filter, attrs, 0,
			     NULL, NULL, NULL, -1, &msgid);

	if (rc != LDAP_SUCCESS) {
		_pam_log(LOG_ERR, "ldap_search_ext: %s", ldap_err2string(rc));
		return NULL;
	}

	rc = ldap_result(ld, msgid, LDAP_MSG_ALL, NULL, &res);
	if (rc < 0) {
		_pam_log(LOG_ERR, "ldap_result failed");
		return NULL;
	}

	rc = ldap_count_entries(ld, res);
	if (rc == 0) {
		_pam_log(LOG_ERR, "not enough entires");
		return NULL;
	}
	if (rc > 1)
		_pam_log(LOG_NOTICE, "LDAP: too many entries for filter %s",
			 filter);
      
	msg = ldap_first_entry(ld, res);
	ret = get_ldap_attr(ld, msg, attr);
	ldap_msgfree(res);
  
	return ret;
}

static int
get_intval(struct gray_env *env, const char *name, unsigned long *pv)
{
	char *p;
	char *v = gray_env_get(env, name);
	
	if (!v)
		return 1;
	*pv = strtoul(v, &p, 10);
	if (*p) {
		_pam_log(LOG_ERR, "configuration variable %s is not integer",
			 name);
		return 1;
	}
	return 0;
}	

static int
check_groups(int gc, char **gv, const char *username)
{
	int i;
	
	for (i = 0; i < gc; i++) {
		struct group *gp = getgrnam(gv[i]);
		if (gp) {
			char **p;
			for (p = gp->gr_mem; *p; p++)
				if (strcmp(username, *p) == 0)
					return 0;
		}
	}
	return 1;
}

static int
check_user_groups(pam_handle_t *pamh, struct gray_env *env,
		  struct passwd **ppw, int *retval)
{
	int rc;
	const char *username;
	struct passwd *pw;
	unsigned long ival;
	char *sval;
	
	rc = pam_get_user(pamh, &username, NULL);
	if (rc != PAM_SUCCESS || !username) {
		DEBUG(1,("can not get the username"));
		*retval = rc;
		return 1;
	}
	pw = getpwnam(username);
	if (!pw) {
		*retval = PAM_USER_UNKNOWN;
		return 1;
	}
	*ppw = pw;
	if (get_intval(env, "min-uid", &ival) == 0) {
		if (pw->pw_uid < ival) {
			DEBUG(10, ("ignoring user %s: has UID < %lu",
				   username, ival));
			*retval = PAM_SUCCESS;
			return 1;
		}
	}
	if (get_intval(env, "min-gid", &ival) == 0) {
		if (pw->pw_gid < ival) {
			DEBUG(10, ("ignoring user %s: has GID < %lu",
				   username, ival));
			*retval = PAM_SUCCESS;
			return 1;
		}
	}
	sval = gray_env_get(env, "allow-groups");
	if (sval) {
		int gc;
		char **gv;
		int rc;
		
		if (argcv_split(sval, &gc, &gv)) {
			_pam_log(LOG_ERR, "cannot split allow-groups: %s",
				 strerror(errno));
			*retval = PAM_AUTH_ERR;
			return 1;
		}
		rc = check_groups(gc, gv, username);
		argcv_free(gc, gv);
		if (rc) {
			DEBUG(10, ("ignoring user %s: not in allowed group list",
				   username, ival));
			*retval = PAM_SUCCESS;
			return 1;
		}
	}
	return 0;
}

static int
populate_homedir(struct passwd *pw, const char *skel)
{
	// FIXME!!!
	_pam_log(LOG_ERR, "populate_homedir is not yet implemented!");
	return 1;
}

/* Create the directory DIR, eventually creating all intermediate directories
   starting from DIR + BASELEN. */
int
create_hierarchy(char *dir, size_t baselen)
{
	int rc;
	struct stat st;
	char *p;

	if (stat(dir, &st) == 0) {
		if (!S_ISDIR(st.st_mode)) {
			_pam_log(LOG_ERR, "component %s is not a directory",
				 dir);
			return 1;
		}
		return 0;
	} else if (errno != ENOENT) {
		_pam_log(LOG_ERR, "cannot stat file %s: %s",
		       dir, strerror(errno));
		return 1;
	}

	p = strrchr(dir, '/');
	if (p) {
		if (p - dir + 1 < baselen) {
			_pam_log(LOG_ERR, "base directory %s does not exist",
				 dir);
			return 1;
		}
		*p = 0;
	}

	rc = create_hierarchy(dir, baselen);
	if (rc == 0) {
		if (p)
			*p = '/';
		if (mkdir(dir, 0755)) {
			_pam_log(LOG_ERR, "cannot create directory %s: %s",
				 dir, strerror(errno));
			rc = 1;
		}
	}
	return rc;
}

int
create_interdir(const char *path, struct passwd *pw)
{
	char *dir, *p;
	size_t len;
	int rc;

	p = strrchr(path, '/');
	if (!p)
		return 1;
	len = p - path;
	dir = gray_malloc(len + 1);
	memcpy(dir, path, len);
	dir[len] = 0;
	rc = create_hierarchy(dir, strlen(pw->pw_dir));
	if (rc == 0)
		chown(dir, pw->pw_uid, pw->pw_gid);
	free(dir);
	return rc;
}

static void
store_pubkey(const char *key, struct passwd *pw)
{
	FILE *fp;
	const char *kp;
	int c;
	int found = 0;
	char *file_name;
	size_t homelen, pathlen, len;
	
	homelen = strlen(pw->pw_dir);
	pathlen = strlen(authorized_keys_file);
	len = homelen + pathlen;
	if (pw->pw_dir[homelen - 1] != '/')
		len++;
	file_name = gray_malloc(len + 1);
	memcpy(file_name, pw->pw_dir, homelen);
	if (pw->pw_dir[homelen - 1] != '/')
		file_name[homelen++] = '/';
	strcpy(file_name + homelen, authorized_keys_file);
	
	fp = fopen(file_name, "a+");
	if (!fp && create_interdir(file_name, pw) == 0)
		fp = fopen(file_name, "a+");
	if (!fp) {
		_pam_log(LOG_EMERG, "cannot open file %s: %s",
			 file_name, strerror(errno));
		free(file_name);
		return;
	}
	free(file_name);
	fchown(fileno(fp), pw->pw_uid, pw->pw_gid);
	
	kp = key;
	while (!feof(fp)) {
		while (*kp && (c = getc(fp)) != EOF && c == *kp)
			kp++;
		if (*kp == 0) {
			DEBUG(2, ("key found"));
			found = 1;
			break;
		}
		kp = key;
		if (c != '\n') {
			if (c != EOF) {
				while ((c = getc(fp)) != EOF && c != '\n')
					;
			}
			if (c == EOF) {
				if (ftell(fp))
					fputc('\n', fp);
				break;
			}
		}
	}

	if (!found) {
		fwrite(key, strlen(key), 1, fp);
		fputc('\n', fp);
	}
	fclose(fp);
}

static int
import_public_key(pam_handle_t *pamh, struct passwd *pw, struct gray_env *env)
{
	LDAP *ld;
	int retval;
	const char *base = gray_env_get(env, "base");
	const char *filter_pat = gray_env_get(env, "filter");
	const char *attr = gray_env_get(env, "pubkey-attr");

	if (!filter_pat) {
		_pam_log(LOG_ERR, "configuration variable `filter' not set");
		return PAM_SERVICE_ERR;
	}
	if (!attr) {
		_pam_log(LOG_ERR, "configuration variable `attr' not set");
		return PAM_SERVICE_ERR;
	}
	
	ld = ldap_connect(env);
	if (!ld)
		return PAM_SERVICE_ERR;
	if (ldap_bind(ld, env))
		retval = PAM_SERVICE_ERR;
	else {
		char *filter;
		gray_slist_t slist;
		char *pubkey;
			
		slist = gray_slist_create();
		gray_expand_string(pamh, filter_pat, slist);
		gray_slist_append_char(slist, 0);
		filter = gray_slist_finish(slist);

		pubkey = ldap_search(ld, base, filter, attr);
		gray_slist_free(&slist);
		store_pubkey(pubkey, pw);
		free(pubkey);
		retval = PAM_SUCCESS;
	}
	ldap_unbind(ld);
	return retval;
}

static int
create_home_dir(pam_handle_t *pamh, struct passwd *pw, struct gray_env *env)
{
	struct stat st;
	char *s;
	
	if (stat(pw->pw_dir, &st)) {
		if (errno != ENOENT) {
			_pam_log(LOG_ERR, "cannot stat home directory %s: %s",
				 pw->pw_dir, strerror(errno));
			return 1;
		}
		/* FIXME: mode must be configurable */
		if (mkdir(pw->pw_dir, 0775)) {
			_pam_log(LOG_ERR, "cannot create %s: %s",
				 pw->pw_dir, strerror(errno));
			return 1;
		}
		chown(pw->pw_dir, pw->pw_uid, pw->pw_gid);
	} else if (!S_ISDIR(st.st_mode)) {
		_pam_log(LOG_ERR, "%s exists, but is not a directory",
			 pw->pw_dir);
		return 1;
	}

	s = gray_env_get(env, "skel");
	if (s) {
		if (stat(s, &st)) {
			_pam_log(LOG_ERR, "cannot stat skeleton directory %s: %s",
				 pw->pw_dir, strerror(errno));
			return 1;
		} else if (!S_ISDIR(st.st_mode)) {
			_pam_log(LOG_ERR, "%s exists, but is not a directory",
				 pw->pw_dir);
			return 1;
		}
		populate_homedir(pw, s);
	}
		
	return 0;
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh,
		    int flags,
		    int argc,
		    const char **argv)
{
	int retval = PAM_AUTH_ERR;
	struct gray_env *env;
	
	_pam_parse(pamh, argc, argv);
	
	DEBUG(90,("enter pam_sm_authenticate"));
	gray_pam_init(PAM_AUTHINFO_UNAVAIL);
	if (gray_env_read(config_file_name, &env) == 0) {
		struct passwd *pw;

		if (check_user_groups(pamh, env, &pw, &retval) == 0) {
			if (create_home_dir(pamh, pw, env) == 0 && 
			    import_public_key(pamh, pw, env) == 0)
				retval = PAM_TRY_AGAIN;
		}
		gray_env_free(env);
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

struct pam_module _pam_ldaphome_modstruct = {
	"pam_ldaphome",                      /* name of the module */
	pam_sm_authenticate,                 
	pam_sm_setcred,
	NULL,
	NULL,
	NULL,
	NULL
};

#endif




