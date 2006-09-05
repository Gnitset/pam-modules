/* This file is part of pam-modules.
   Copyright (C) 2005, 2006 Sergey Poznyakoff

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
   MA 02110-1301 USA */

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
#include <libpq-fe.h>

#include "pam_sql.c"

static char *
sql_escape_string (const char *ustr)
{
	char *str, *q;
	const unsigned char *p;
	size_t len = strlen (ustr);
#define ESCAPABLE_CHAR "\\'\""
  
	for (p = (const unsigned char *) ustr; *p; p++) {
		if (strchr (ESCAPABLE_CHAR, *p))
			len++;
	}

	str = malloc (len + 1);
	if (!str)
		return NULL;

	for (p = (const unsigned char *) ustr, q = str; *p; p++) {
		if (strchr (ESCAPABLE_CHAR, *p))
			*q++ = '\\';
		*q++ = *p;
	}
	*q = 0;
	return str;
}

char *
sql_expand_query (const char *query, const char *user, const char *pass)
{
	char *p, *q, *res;
	int len;
	char *esc_user = NULL;
	char *esc_pass = NULL;
	
	if (!query)
		return NULL;
	
	/* Compute resulting query length */
	for (len = 0, p = (char *) query; *p; ) {
		if (*p == '%') {
			if (p[1] == 'u') {
				esc_user = sql_escape_string(user);
				len += strlen (esc_user);
				p += 2;
			} if (p[1] == 'u') {
				esc_pass = sql_escape_string(pass);
				len += strlen (esc_pass);
				p += 2;
			} else if (p[1] == '%') {
				len++;
				p += 2;
			} else {
				len++;
				p++;
			}
		} else {
			len++;
			p++;
		}
	}

	res = malloc (len + 1);
	if (!res) {
		free (esc_user);
		free (esc_pass);
		return res;
	}

	for (p = (char *) query, q = res; *p; ) {
		if (*p == '%') {
			switch (*++p) {
			case 'u':
				strcpy (q, esc_user);
				q += strlen (q);
				p++;
				break;

			case 'p':
				strcpy (q, esc_pass);
				q += strlen (q);
				p++;
				break;
				
			case '%':
				*q++ = *p++;
				break;
				
			default:
				*q++ = *p++;
			}
		} else
			*q++ = *p++;
	}
	*q = 0;
	
	free (esc_user);
	free (esc_pass);
	return res;
}

int
verify_user_pass(const char *username, const char *password)
{
	PGconn  *pgconn;
	PGresult *res;
	char *hostname;
	char *login;
	char *pass;
	char *db;
	char *port;
	char *query, *exquery;
	char *p;
	int rc;
	
	hostname = find_config("host");
	CHKVAR(hostname);
	
	port = find_config("port");
	CHKVAR(port);
	
	login = find_config("login");
	CHKVAR(login);

	pass = find_config("pass");
	CHKVAR(pass);

	db = find_config("db");
	CHKVAR(db);

	query = find_config("query");
	CHKVAR(query);
	
	exquery = sql_expand_query (query, username, password);
	if (!exquery) {
		_pam_err(LOG_ERR, "cannot expand query");
		return PAM_SERVICE_ERR;
	}

	pgconn = PQsetdbLogin (hostname, port, NULL, NULL,
			       db, login, password);
	if (PQstatus (pgconn) == CONNECTION_BAD) {
		_pam_err(LOG_ERR, "cannot connect to database");
		return PAM_SERVICE_ERR;
	}

	DEBUG(10,("Executing %s", exquery));
	res = PQexec (pgconn, exquery);
	if (res == NULL) {
		_pam_err(LOG_ERR, "PQexec: %s", PQerrorMessage(pgconn));
		rc = PAM_SERVICE_ERR;
	} else if (PQresultStatus(res) != PGRES_TUPLES_OK) {
		_pam_err(LOG_ERR, "PQexec: query did not return tuples");
		rc = PAM_SERVICE_ERR;
	} else {
		char *p;
		int n;

		n = PQntuples(res);
		DEBUG(20,("Returned %d tuples", n));
		if (n != 1) {
			_pam_err(LOG_WARNING,
				 "PQexec: query returned %d tuples", n);
			if (n == 0) {
				PQclear(res);
				PQfinish(pgconn);
				return PAM_SERVICE_ERR;
			}
		}

		n = PQnfields(res);
		DEBUG(20,("Returned %d fields", n));
		if (n != 1) {
			_pam_err(LOG_WARNING,
				 "PQexec: query returned %d fields", n);
		}

		p = PQgetvalue(res, 0, 0);
		chop(p);
		DEBUG(100,("Obtained password value: %s", p));
		
		if (strcmp(p, crypt(password, p)) == 0)
			rc = PAM_SUCCESS;
		else if (rc != PAM_SUCCESS
			 && check_boolean_config ("allow-plaintext-pass", 0)) {
			if (strcmp (p, pass) == 0)
				rc = PAM_SUCCESS;
		} else
			rc = PAM_AUTH_ERR;
	}

	PQclear(res);
	PQfinish(pgconn);
	
	return rc;
}

