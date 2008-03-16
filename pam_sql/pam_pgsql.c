/* This file is part of pam-modules.
   Copyright (C) 2005, 2006, 2007, 2008 Sergey Poznyakoff

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

#include <graypam.h>
#include <libpq-fe.h>

#include "pam_sql.c"

static int
verify_user_pass(pam_handle_t *pamh, const char *password, const char *query)
{
	PGconn  *pgconn;
	PGresult *res;
	char *hostname;
	char *login;
	char *pass;
	char *db;
	char *port;
	int rc;
	gray_slist_t slist;
	
	hostname = find_config("host");
	
	port = find_config("port");

	login = find_config("login");
	CHKVAR(login);

	pass = find_config("pass");

	db = find_config("db");
	CHKVAR(db);

	pgconn = PQsetdbLogin (hostname, port, NULL, NULL,
			       db, login, pass);
	if (PQstatus (pgconn) == CONNECTION_BAD) {
		_pam_log(LOG_ERR, "cannot connect to database: %s",
			 PQerrorMessage(pgconn));
		PQfinish(pgconn);
		return PAM_SERVICE_ERR;
	}
	
	DEBUG(10,("Executing %s", query));
	res = PQexec (pgconn, query);
	if (res == NULL) {
		_pam_log(LOG_ERR, "PQexec: %s", PQerrorMessage(pgconn));
		rc = PAM_SERVICE_ERR;
	} else if (PQresultStatus(res) != PGRES_TUPLES_OK) {
		_pam_log(LOG_ERR, "PQexec: query did not return tuples");
		rc = PAM_SERVICE_ERR;
	} else {
		char *p;
		int n;

		n = PQntuples(res);
		DEBUG(20,("Returned %d tuples", n));
		if (n != 1) {
			_pam_log(LOG_WARNING,
				 "PQexec: query returned %d tuples", n);
			if (n == 0) {
				PQclear(res);
				PQfinish(pgconn);
				return PAM_USER_UNKNOWN;
			}
		}

		n = PQnfields(res);
		DEBUG(20,("Returned %d fields", n));
		if (n != 1) {
			_pam_log(LOG_WARNING,
				 "PQexec: query returned %d fields", n);
		}

		p = PQgetvalue(res, 0, 0);
		chop(p);
		DEBUG(100,("Obtained password value: %s", p));

		rc = PAM_AUTH_ERR;
		if (strcmp(p, crypt(password, p)) == 0)
			rc = PAM_SUCCESS;
		if (rc != PAM_SUCCESS
		    && check_boolean_config ("allow-ldap-pass", 1))
			rc = gray_check_ldap_pass (p, password);
		if (rc != PAM_SUCCESS
		    && check_boolean_config ("allow-plaintext-pass", 0)
		    && strcmp (p, pass) == 0)
			rc = PAM_SUCCESS;
	}

	PQclear(res);
	PQfinish(pgconn);
	
	return rc;
}

static int
sql_acct(pam_handle_t *pamh, const char *query)
{
	PGconn  *pgconn;
	PGresult *res;
	char *hostname;
	char *login;
	char *pass;
	char *db;
	char *port;
	int rc;
	gray_slist_t slist;
	
	hostname = find_config("host");
	
	port = find_config("port");

	login = find_config("login");
	CHKVAR(login);

	pass = find_config("pass");

	db = find_config("db");
	CHKVAR(db);

	pgconn = PQsetdbLogin (hostname, port, NULL, NULL,
			       db, login, pass);
	if (PQstatus (pgconn) == CONNECTION_BAD) {
		_pam_log(LOG_ERR, "cannot connect to database: %s",
			 PQerrorMessage(pgconn));
		PQfinish(pgconn);
		return PAM_SERVICE_ERR;
	}
	
	DEBUG(10,("Executing %s", query));
	res = PQexec (pgconn, query);
	if (res == NULL) {
                _pam_log(LOG_ERR, "PQexec: %s", PQerrorMessage(pgconn));
		rc = PAM_SERVICE_ERR;
        } else {
		ExecStatusType stat;
		stat = PQresultStatus(res);
		
		DEBUG(10, ("status: %s", PQresStatus(stat)));
		if (stat != PGRES_TUPLES_OK && stat != PGRES_COMMAND_OK) {
			PQclear(res);
			_pam_log(LOG_ERR, "PQexec returned %s",
			         PQresStatus(stat));
			rc = PAM_SERVICE_ERR;
		}
		DEBUG(10, ("query affected %d tuples", PQntuples(res)));
		rc = PAM_SUCCESS;
        }

	PQclear(res);
	PQfinish(pgconn);
	
	return rc;
}
