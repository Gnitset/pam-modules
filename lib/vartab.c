/* This file is part of pam-modules.
   Copyright (C) 2009-2011 Sergey Poznyakoff
 
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

struct keyword *
gray_find_keyword(struct keyword *kwtab, const char *str, size_t len)
{
	for (; kwtab->name; kwtab++)
		if (kwtab->len == len
		    && strncmp(kwtab->name, str, kwtab->len) == 0)
			return kwtab;
	return NULL;
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

#define ISKW(c) ((c) && (isalnum(c) || (c) == '_'))

static int
get_variable(pam_handle_t *pamh, const char *str, gray_slist_t slist,
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
		name = end = str;
		for (namelen = 0; ISKW(*end); namelen++, end++)
			;
	}

	kw = gray_find_keyword(vartab, name, namelen);
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

	gray_escape_string(slist, val, vallen);
	*endp = end;
	return 0;
}

void
gray_expand_argv(pam_handle_t *pamh, int argc, const char **argv,
		 gray_slist_t slist)
{
	int i;

	for (i = 0; i < argc; i++) {
		if (i > 0)
			gray_slist_append_char(slist, ' ');
		if (strchr(argv[i], '$') == 0)
			gray_slist_append(slist, argv[i], strlen(argv[i]));
		else {
			const char *p;
			
			for (p = argv[i]; *p; p++) {
				if (*p == '\\') {
					p++;
					gray_slist_append_char(slist, *p);
				} else if (*p == '$') {
					if (get_variable(pamh, p, slist, &p))
						gray_slist_append_char(slist,
								       *p);
					else
						p--;
				} else
					gray_slist_append_char(slist, *p);
			}
		}
	}
}

void
gray_expand_string(pam_handle_t *pamh, const char *str, gray_slist_t slist)
{
	const char *p;
#define FLUSH() gray_slist_append(slist, str, p - str); str = p
	
	for (p = str; *p; ) {
		if (*p == '\\') {
			FLUSH();
			p++;
			if (*p) {
				gray_slist_append_char(slist, *p);
				p++;
			} else {
				gray_slist_append_char(slist, '\\');
				break;
			}
			str = p;
		} else if (*p == '$') {
			FLUSH();
			if (get_variable(pamh, p, slist, &p)) {
				gray_slist_append_char(slist, *p);
				p++;
			}
			str = p;
		} else
			p++;
	}
	FLUSH();
}
