/* This file is part of pam-modules.
   Copyright (C) 2005-2008, 2010-2012 Sergey Poznyakoff

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
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
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

	for (i = 0; i < wc; i++)
		free(wv[i]);
	free(wv);
}

static void
argcvz_free(char **wv)
{
	int i;

	for (i = 0; wv[i]; i++)
		free(wv[i]);
	free(wv);
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
	res = malloc(size);
	if (!res)
		return 0;
	for (p = res, i = 0;;) {
		strcpy(p, wv[i]);
		p += strlen(wv[i]);
		if (++i < wc)
			*p++ = ' ';
		else
			break;
	}
	*p = 0;
	return res;
}

static int
get_intval(struct gray_env *env, const char *name, int base, unsigned long *pv)
{
	char *p;
	char *v = gray_env_get(env, name);
	
	if (!v)
		return 1;
	*pv = strtoul(v, &p, base);
	if (*p) {
		_pam_log(LOG_ERR, "configuration variable %s is not integer",
			 name);
		return -1;
	}
	return 0;
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
	      
			if (ldap_dn2domain(lud->lud_dn, &domain) ||
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
		ldap_free_urldesc(ludlist);
		return NULL;
	} else if (!urls)
		return NULL;
	ldapuri = argcv_concat(nurls, urls);
	if (!ldapuri)
		_pam_log(LOG_ERR, "%s", strerror(errno));
	ber_memvfree((void **)urls);
	return ldapuri;
}

static void ldap_unbind(LDAP *ld);

static LDAP *
ldap_connect(struct gray_env *env)
{
	int rc;
	char *ldapuri = NULL;
	LDAP *ld = NULL;
	int protocol = LDAP_VERSION3;
	char *val;
	unsigned long lval;
	
	if (ldap_debug_level) {
		if (ber_set_option(NULL, LBER_OPT_DEBUG_LEVEL,
				    &ldap_debug_level)
		    != LBER_OPT_SUCCESS )
			_pam_log(LOG_ERR,
				 "cannot set LBER_OPT_DEBUG_LEVEL %d",
				 ldap_debug_level);

		if (ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL,
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

	if (get_intval(env, "ldap-version", 10, &lval) == 0) {
		switch (lval) {
		case 2:
			protocol = LDAP_VERSION2;
			break;
		case 3:
			protocol = LDAP_VERSION3;
			break;
		default:
			_pam_log(LOG_ERR,
				 "%s: invalid variable value, "
				 "defaulting to 3",
				 "ldap-version");
		}
	}
		
	ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &protocol);

	val = gray_env_get(env, "tls");
		
	if (val) {
		enum { tls_no, tls_yes,	tls_only } tls;
		
		if (strcmp(val, "yes") == 0)
			tls = tls_yes;
		else if (strcmp(val, "no") == 0)
			tls = tls_no;
		else if (strcmp(val, "only") == 0)
			tls = tls_only;
		else {
			_pam_log(LOG_ERR,
				 "wrong value for tls statement, "
				 "assuming \"no\"");
			tls = tls_no;
		}

		if (tls != tls_no) {
			rc = ldap_start_tls_s(ld, NULL, NULL);
			if (rc != LDAP_SUCCESS) {
				char *msg = NULL;
				ldap_get_option(ld,
						LDAP_OPT_DIAGNOSTIC_MESSAGE,
						(void*)&msg);
				_pam_log(LOG_ERR,
					 "ldap_start_tls failed: %s",
					 ldap_err2string(rc));
				_pam_log(LOG_ERR,
					 "TLS diagnostics: %s", msg);
				ldap_memfree(msg);

				if (tls == tls_only) {
					ldap_unbind(ld);
					return NULL;
				}
				/* try to continue anyway */
			}
		}
	}
	
	/* FIXME: Timeouts, SASL, etc. */
	return ld;
}

static int
full_read(int fd, char *file, char *buf, size_t size)
{
	while (size) {
		ssize_t n;
			
		n = read(fd, buf, size);
		if (n == -1) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			_pam_log(LOG_ERR, "error reading from %s: %s",
				 file, strerror(errno));
			return -1;
		} else if (n == 0) {
			_pam_log(LOG_ERR, "short read from %s", file);
			return -1;
		}

		buf += n;
		size -= n;
	}
	return 0;
}

static int
get_passwd(struct gray_env *env, struct berval *pwd, char **palloc)
{
	char *file;

	file = gray_env_get(env, "bindpwfile");
	if (file) {
		struct stat st;
		int fd, rc;
		char *mem, *p;
		
		fd = open(file, O_RDONLY);
		if (fd == -1) {
			_pam_log(LOG_ERR, "can't open password file %s: %s",
				 file, strerror(errno));
			return -1;
		}
		if (fstat(fd, &st)) {
			_pam_log(LOG_ERR, "can't stat password file %s: %s",
				 file, strerror(errno));
			close(fd);
			return -1;
		}
		mem = malloc(st.st_size + 1);
		if (!mem) {
			_pam_log(LOG_ERR, "can't allocate memory (%lu bytes)",
				 (unsigned long) st.st_size+1);
			close(fd);
			return -1;
		}
		rc = full_read(fd, file, mem, st.st_size);
		close(fd);
		if (rc)
			return rc;
		mem[st.st_size] = 0;
		p = strchr(mem, '\n');
		if (p)
			*p = 0;
		*palloc = mem;
		pwd->bv_val = mem;
	} else
		pwd->bv_val = gray_env_get(env, "bindpw");
	pwd->bv_len = pwd->bv_val ? strlen(pwd->bv_val) : 0;
	return 0;
}

static int
ldap_bind(LDAP *ld, struct gray_env *env)
{
	int msgid, err, rc;
	LDAPMessage *result;
	LDAPControl **ctrls;
	char msgbuf[256];
	char *matched = NULL;
	char *info = NULL;
	char **refs = NULL;
	struct berval passwd;
	char *binddn;
	char *alloc_ptr = NULL;
	
	binddn = gray_env_get(env, "binddn");

	if (get_passwd(env, &passwd, &alloc_ptr))
		return 1;

	msgbuf[0] = 0;

	rc = ldap_sasl_bind(ld, binddn, LDAP_SASL_SIMPLE, &passwd,
			    NULL, NULL, &msgid);
	if (msgid == -1) {
		_pam_log(LOG_ERR,
			 "ldap_sasl_bind(SIMPLE) failed: %s",
			 ldap_err2string(rc));
		free(alloc_ptr);
		return 1;
	}

	if (ldap_result(ld, msgid, LDAP_MSG_ALL, NULL, &result ) == -1) {
		_pam_log(LOG_ERR, "ldap_result failed");
		free(alloc_ptr);
		return 1;
	}

	rc = ldap_parse_result(ld, result, &err, &matched, &info, &refs,
			       &ctrls, 1);
	if (rc != LDAP_SUCCESS) {
		_pam_log(LOG_ERR, "ldap_parse_result failed: %s",
			 ldap_err2string(rc));
		free(alloc_ptr);
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

	free(alloc_ptr);

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

static void
trimnl(char *s)
{
	size_t len = strlen(s);
	while (len > 0 && s[len-1] == '\n')
		--len;
	s[len] = 0;
}

static int
keycmp(const void *a, const void *b)
{
	return strcmp(*(char**)a, *(char**)b);
}

static char **
get_ldap_attrs(LDAP *ld, LDAPMessage *msg, const char *attr)
{
	int rc, i, count;
	BerElement *ber = NULL;
	struct berval bv;
	char *ufn = NULL;
	char **ret;
	struct berval **values;
	
	rc = ldap_get_dn_ber(ld, msg, &ber, &bv);
	ufn = ldap_dn2ufn(bv.bv_val);
	DEBUG(2, ("INFO: %s", ufn));
	ldap_memfree(ufn);

	values = ldap_get_values_len(ld, msg, attr);
	if (!values) {
		_pam_log(LOG_ERR,
			 "LDAP attribute `%s' has NULL value",
			 attr);
		return NULL;
	}

	for (count = 0; values[count]; count++)
		;

	ret = calloc(count + 1, sizeof(ret[0]));
	if (!ret)
		_pam_log(LOG_ERR, "%s", strerror(errno));
	else {
		for (i = 0; values[i]; i++) {
			char *p = malloc(values[i]->bv_len + 1);
			if (!p) {
				_pam_log(LOG_ERR, "%s", strerror(errno));
				break;
			}
			memcpy(p, values[i]->bv_val, values[i]->bv_len);
			p[values[i]->bv_len] = 0;
			trimnl(p);
			ret[i] = p;
			DEBUG(10,("pubkey: %s", p));
		}

		if (i < count) {
			argcv_free(i, ret);
			ret = NULL;
		} else {
			ret[i] = NULL;
			qsort(ret, i, sizeof(ret[0]), keycmp);
		}
	}
	
	ldap_value_free_len(values);
	return ret;
}

static char **
get_pubkeys(LDAP *ld, const char *base, const char *filter, const char *attr)
{
	int rc;
	LDAPMessage *res, *msg;
	ber_int_t msgid;
	char *attrs[2];
	char **ret;
	
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

	msg = ldap_first_entry(ld, res);
	if (!msg) {
		ldap_msgfree(res);
		return NULL;
	}

	ret = get_ldap_attrs(ld, msg, attr);
	
	ldap_msgfree(res);
  
	return ret;
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
	if (get_intval(env, "min-uid", 10, &ival) == 0) {
		if (pw->pw_uid < ival) {
			DEBUG(10, ("ignoring user %s: has UID < %lu",
				   username, ival));
			*retval = PAM_SUCCESS;
			return 1;
		}
	}
	if (get_intval(env, "min-gid", 10, &ival) == 0) {
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
copy(int src_fd, int dst_fd, char *buffer, size_t bufsize)
{
	ssize_t n;
	
	while ((n = read(src_fd, buffer, bufsize)) > 0) {
		n = write(dst_fd, buffer, n);
		if (n < 0)
			break;
	}
	return n;
}

static int
copy_file(pam_handle_t *pamh, const char *src, const char *dst,
	  char *buffer, size_t bufsize, struct stat *st)
{
	int sfd, dfd, rc;

	sfd = open(src, O_RDONLY);
	if (sfd == -1) {
		_pam_log(LOG_ERR, "cannot open %s: %s",
			 src, strerror(errno));
		return 1;
	}

	dfd = open(dst, O_CREAT|O_TRUNC|O_RDWR, 0600);
	if (dfd == -1) {
		close(sfd);
		_pam_log(LOG_ERR, "cannot create %s: %s",
			 dst, strerror(errno));
		return 1;
	}
	if (fchown(dfd, st->st_uid, st->st_gid) ||
	    fchmod(dfd, st->st_mode & 07777)) {
		_pam_log(LOG_ERR, "cannot set privileges of %s: %s",
			 dst, strerror(errno));
		/* try to continue anyway */
	}
	
	rc = copy(sfd, dfd, buffer, bufsize);
	if (rc)
		_pam_log(LOG_ERR, "I/O error copying %s to %s: %s",
			 src, dst, strerror(errno));
	
	close(sfd);
	close(dfd);

	return rc;
}

#define INITIAL_READLINK_SIZE 128

int
read_link_name(const char *name, char **pbuf, size_t *psize, size_t *plen)
{
	int rc = 0;
	char *buf = *pbuf;
	size_t size = *psize;
	ssize_t linklen;

	while (1) {
		if (!buf) {
			size = INITIAL_READLINK_SIZE;
			buf = malloc(size);
		} else {
			char *p;
			size_t newsize = size << 1;
			if (newsize < size) {
				rc = ENAMETOOLONG;
				break;
			}
			size = newsize;
			p = realloc(buf, size);
			if (!p)
				free(buf);
			buf = p;
		}
		if (!buf) {
			rc = 1;
			break;
		}

		linklen = readlink(name, buf, size);
		if (linklen < 0 && errno != ERANGE) {
			rc = 1;
			break;
		}

		if ((size_t) linklen < size) {
			buf[linklen++] = '\0';
			rc = 0;
			break;
		}
	}

	if (rc) {
		if (buf) {
			free(buf);
			buf = NULL;
		}
		size = 0;
	}
	*pbuf = buf;
	*psize = size;
	if (plen)
		*plen = linklen;
	return rc;
}


static int
copy_link(pam_handle_t *pamh, const char *src, const char *dst,
	  char *buffer, size_t bufsize, struct stat *st)
{
	char *lnkname = NULL;
	size_t lnklen = 0;
	int rc;
	
	if (read_link_name(src, &lnkname, &lnklen, NULL)) {
		_pam_log(LOG_ERR, "error reading link %s: %s",
			 src, strerror(errno));
		return 1;
	}
	rc = symlink(lnkname, dst);
	if (rc)
		_pam_log(LOG_ERR, "can't link %s to %s: %s",
			 src, dst, strerror(errno));
	else if (lchown(dst, st->st_uid, st->st_gid)) {
		_pam_log(LOG_ERR, "cannot set privileges of %s: %s",
			 dst, strerror(errno));
		/* try to continue anyway */
	}

	free(lnkname);
	return rc;
}

/* Create the directory DIR, eventually creating all intermediate directories
   starting from DIR + BASELEN. */
static int
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

static int
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
		rc = chown(dir, pw->pw_uid, pw->pw_gid);
	free(dir);
	return rc;
}

struct namebuf {
	char *name;
	size_t size;
	size_t prefix_len;
};

static void
namebuf_trimslash(struct namebuf *buf)
{
	size_t len = strlen(buf->name);
	while (len > 0 && buf->name[len-1] == '/')
		--len;
	buf->name[len] = 0;
}

static int
namebuf_init(struct namebuf *buf, const char *name)
{
	buf->name = strdup(name);
	if (!buf->name)
		return 1;
	buf->prefix_len = strlen(name);
	buf->size = buf->prefix_len + 1;
	namebuf_trimslash(buf);
	return 0;
}

static int
namebuf_set(struct namebuf *buf, const char *name)
{
	size_t len;

	if (!buf->name)
		return namebuf_init(buf, name);
	len = strlen(name);
	if (buf->prefix_len + len + 1 > buf->size) {
		size_t ns;
		char *np;

		for (ns = buf->size; buf->prefix_len + len + 1 > ns;
		     ns += ns)
			;

		np = realloc(buf->name, ns);
		if (!np)
			return 1;
		buf->size = ns;
		buf->name = np;
	}

	strcpy(buf->name + buf->prefix_len, name);
	//namebuf_trimslash(buf);

	return 0;
}

static size_t
namebuf_set_prefix(struct namebuf *buf)
{
	size_t ret;
	ret = buf->prefix_len;
	buf->prefix_len = strlen(buf->name);
	if (namebuf_set(buf, "/"))
		return 1;
	++buf->prefix_len;
	return ret;
}

static void
namebuf_set_prefix_len(struct namebuf *buf, size_t len)
{
	buf->prefix_len = len;
	buf->name[len] = 0;
}

static int recursive_copy(pam_handle_t *pamh, DIR *dir,
			  struct namebuf *srcbuf, struct namebuf *dstbuf,
			  char *buffer, size_t bufsize, struct passwd *pw,
			  struct stat *st);

static int
dir_copy_loop(pam_handle_t *pamh, DIR *dir,
	      struct namebuf *srcbuf, struct namebuf *dstbuf,
	      char *buffer, size_t bufsize, struct passwd *pw)
{
	struct dirent *ent;

	while ((ent = readdir(dir))) {
		char const *ename = ent->d_name;
		struct stat st;
		int rc;
		
		if (ename[ename[0] != '.' ? 0 : ename[1] != '.' ? 1 : 2] == 0)
			continue;
		if (namebuf_set(srcbuf, ename)) {
			_pam_log(LOG_ERR, "copy error: %s", strerror(errno));
			return 1;
		}
		if (namebuf_set(dstbuf, ename)) {
			_pam_log(LOG_ERR, "copy error: %s", strerror(errno));
			return 1;
		}
		if (lstat(srcbuf->name, &st)) {
			_pam_log(LOG_ERR, "cannot stat %s: %s",
				 srcbuf->name, strerror(errno));
			return 1;
		}
		st.st_uid = pw->pw_uid;
		st.st_gid = pw->pw_gid;
		if (S_ISREG(st.st_mode))
			rc = copy_file(pamh, srcbuf->name, dstbuf->name,
				       buffer, bufsize, &st);
		else if (S_ISDIR(st.st_mode)) {
			DIR *nd = opendir(srcbuf->name);
			if (!nd) {
				_pam_log(LOG_ERR,
					 "cannot open directory %s: %s",
					 srcbuf->name, strerror(errno));
				rc = 1;
			} else {
				size_t srclen = namebuf_set_prefix(srcbuf);
				size_t dstlen = namebuf_set_prefix(dstbuf);
				rc = recursive_copy(pamh, nd, srcbuf, dstbuf,
						    buffer, bufsize, pw,
						    &st);
				closedir(nd);
				namebuf_set_prefix_len(dstbuf, dstlen);
				namebuf_set_prefix_len(srcbuf, srclen);
			}
		} else if (S_ISLNK(st.st_mode))
			rc = copy_link(pamh, srcbuf->name, dstbuf->name,
				       buffer, bufsize, &st);
		else {
			_pam_log(LOG_NOTICE,
				 "ignoring file %s: unsupported file type",
				 srcbuf->name);
			rc = 0;
		}

		if (rc)
			return 1;
	}
	return 0;
}

static int
recursive_copy(pam_handle_t *pamh, DIR *dir,
	       struct namebuf *srcbuf, struct namebuf *dstbuf,
	       char *buffer, size_t bufsize, struct passwd *pw,
	       struct stat *st)
{
	int rc;
	struct stat dst_st;
		
	if (stat(dstbuf->name, &dst_st)) {
		if (errno == ENOENT) {
			if (mkdir(dstbuf->name, 0700)) {
				_pam_log(LOG_ERR, "cannot create %s: %s",
					 dstbuf->name, strerror(errno));
				return 1;
			}
		} else {
			_pam_log(LOG_ERR, "cannot stat %s: %s",
				 dstbuf->name, strerror(errno));
			return 1;
		}
	}

	rc = dir_copy_loop(pamh, dir, srcbuf, dstbuf, buffer, bufsize, pw);
	dstbuf->name[dstbuf->prefix_len-1] = 0;
	if (chown(dstbuf->name, pw->pw_uid, pw->pw_gid) ||
	    (st && chmod(dstbuf->name, st->st_mode & 07777))) {
		_pam_log(LOG_ERR,
			 "cannot set privileges for %s:"
			 "%s",
			 dstbuf->name,
			 strerror(errno));
	}
	
	return rc;
}

#define MIN_BUF_SIZE 2
#define MAX_BUF_SIZE 16384

static int
populate_homedir(pam_handle_t *pamh, struct passwd *pw, struct gray_env *env)
{
	const char *skel;
	char *buffer;
	size_t bufsize;
	struct stat st;
	unsigned long n;
	DIR *dir;
	int rc;
	
	skel = gray_env_get(env, "skel");
	if (!skel)
		return 0;
	
	if (stat(skel, &st)) {
		_pam_log(LOG_ERR, "cannot stat skeleton directory %s: %s",
			 pw->pw_dir, strerror(errno));
		return 1;
	} else if (!S_ISDIR(st.st_mode)) {
		_pam_log(LOG_ERR, "%s exists, but is not a directory",
			 pw->pw_dir);
		return 1;
	}

	if (get_intval(env, "copy-buf-size", 10, &n) == 0)
		bufsize = n;
	else
		bufsize = MAX_BUF_SIZE;
	
	for (; (buffer = malloc(bufsize)) == NULL; bufsize >>= 1)
		if (bufsize < MIN_BUF_SIZE)
			return ENOMEM;

	dir = opendir(skel);
	if (!dir) {
		_pam_log(LOG_ERR, "cannot open skeleton directory %s: %s",
			 skel, strerror(errno));
		rc = 1;
	} else {
		struct namebuf srcbuf, dstbuf;

		if (namebuf_init(&srcbuf, skel) == 0) {
			namebuf_set_prefix(&srcbuf);
			if (namebuf_init(&dstbuf, pw->pw_dir) == 0) {
				namebuf_set_prefix(&dstbuf);
				rc = recursive_copy(pamh, dir,
						    &srcbuf, &dstbuf,
						    buffer, bufsize, pw,
						    NULL);
				free(dstbuf.name);
			} else
				rc = 1;
			free(srcbuf.name);
		} else
			rc = 1;
		closedir(dir);
	}
	free(buffer);
	return rc;
}

static int
store_pubkeys(char **keys, struct passwd *pw, struct gray_env *env)
{
	FILE *fp;
	int c;
	char *file_name;
	size_t homelen, pathlen, len;
	int retval, i;
	int update = 0;
	int oldmask;
	unsigned long mode;
	
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

	switch (get_intval(env, "keyfile-mode", 8, &mode)) {
	case -1:
		return PAM_SERVICE_ERR;
	case 1:
		oldmask = -1;
		break;
	case 0:
		oldmask = umask(0666 ^ (mode & 0777));
	}
	
	fp = fopen(file_name, "r+");
	if (!fp && create_interdir(file_name, pw) == 0) {
		fp = fopen(file_name, "w");
		update = 1; 
	}

	if (oldmask != -1)
		umask(oldmask);
	
	if (!fp) {
		_pam_log(LOG_EMERG, "cannot open file %s: %s",
			 file_name, strerror(errno));
		free(file_name);
		return PAM_SERVICE_ERR;
	}
	if (fchown(fileno(fp), pw->pw_uid, pw->pw_gid))
		_pam_log(LOG_ERR, "chown %s: %s",
			 file_name, strerror(errno));

	if (!update) {
		i = 0;
		do {
			const char *kp = keys[i++];
			if (!kp) {
				if (getc(fp) != EOF) {
					DEBUG(2, ("some keys deleted"));
					update = 1;
				}
				break;
			}
			while (*kp && (c = getc(fp)) != EOF && c == *kp)
				kp++;
			if (*kp) {
				DEBUG(2, ("key %d mismatch", i));
				update = 1;
				break;
			}
		} while (c != EOF && (c = getc(fp)) == '\n');

		if (update) {
			rewind(fp);
			if (ftruncate(fileno(fp), 0)) {
				_pam_log(LOG_ERR, "truncate %s: %s",
					 file_name, strerror(errno));
				free(file_name);
				return PAM_SERVICE_ERR;
			}
		}
		free(file_name);
	}
	
	if (update) {
		for (i = 0; keys[i]; i++) {
			fwrite(keys[i], strlen(keys[i]), 1, fp);
			fputc('\n', fp);
		}
		retval = PAM_TRY_AGAIN;
	} else
		retval = PAM_SUCCESS;
	fclose(fp);
	return retval;
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
		char **keys;
			
		slist = gray_slist_create();
		gray_expand_string(pamh, filter_pat, slist);
		gray_slist_append_char(slist, 0);
		filter = gray_slist_finish(slist);

		keys = get_pubkeys(ld, base, filter, attr);
		gray_slist_free(&slist);
		if (keys) {
			retval = store_pubkeys(keys, pw, env);
			argcvz_free(keys);
		} else
			retval = PAM_SUCCESS;
	}
	ldap_unbind(ld);
	return retval;
}

static int
dir_in_path(const char *dir, const char *path)
{
	char *p;
	size_t dirlen;

	p = strrchr(dir, '/');
	if (p)
		dirlen = p - dir;
	else
		return 0;
	
	while (*path) {
		size_t len = strcspn(path, ":");
		while (len > 0 && path[len-1] == '/')
			--len;
		if (len == dirlen && memcmp(path, dir, len) == 0)
			return 1;
		path += len;
		if (*path == ':')
			++path;
	}
	return 0;
}

enum create_status {
	create_ok,
	create_failure,
	create_skip
};

static enum create_status
create_home_dir(pam_handle_t *pamh, struct passwd *pw, struct gray_env *env)
{
	struct stat st;
	
	if (stat(pw->pw_dir, &st)) {
		unsigned long mode = 0755;
		char *val;
		
		if (errno != ENOENT) {
			_pam_log(LOG_ERR, "cannot stat home directory %s: %s",
				 pw->pw_dir, strerror(errno));
			return create_failure;
		}
		
		val = gray_env_get(env, "allow-home-dir");
		if (val && !dir_in_path(pw->pw_dir, val))
			return create_skip;

		if (get_intval(env, "home-dir-mode", 8, &mode) == -1)
			return create_failure;
		mode &= 07777;
		if (mkdir(pw->pw_dir, 0700)) {
			_pam_log(LOG_ERR, "cannot create %s: %s",
				 pw->pw_dir, strerror(errno));
			return create_failure;
		}
		populate_homedir(pamh, pw, env);
		if (chown(pw->pw_dir, pw->pw_uid, pw->pw_gid) ||
		    chmod(pw->pw_dir, mode)) {
			_pam_log(LOG_ERR,
				 "cannot change mode or ownership of %s: %s",
				 pw->pw_dir, strerror(errno));
			return create_failure;
		}
	} else if (!S_ISDIR(st.st_mode)) {
		_pam_log(LOG_ERR, "%s exists, but is not a directory",
			 pw->pw_dir);
		return create_failure;
	}
		
	return create_ok;
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	int retval = PAM_AUTH_ERR;
	struct gray_env *env;
	
	_pam_parse(pamh, argc, argv);
	
	DEBUG(90,("enter pam_sm_authenticate"));
	gray_pam_init(PAM_AUTHINFO_UNAVAIL);
	if (gray_env_read(config_file_name, &env) == 0) {
		char *val;
		struct passwd *pw;

		if (val = gray_env_get(env, "authorized_keys"))
			authorized_keys_file = val;
		
		if (check_user_groups(pamh, env, &pw, &retval) == 0) {
			switch (create_home_dir(pamh, pw, env)) {
			case create_ok:
				retval = import_public_key(pamh, pw, env);
				break;
			case create_failure:
				retval = PAM_SERVICE_ERR;
				break;
			case create_skip:
				retval = PAM_SUCCESS;
			}
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




