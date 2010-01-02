/* This file is part of pam-modules.
   Copyright (C) 2005, 2006, 2007, 2008, 2010 Sergey Poznyakoff

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

#include "pam_sql.h"
#include <libpq-fe.h>

char *gpam_sql_module_name = "pam_pgsql";

static int
pgsql_do_query(PGconn **ppgconn, PGresult **pres, const char *query)
{
	PGconn  *pgconn;
	char *hostname;
	char *login;
	char *db;
	char *port;
	char *pass;
	
	hostname = gpam_sql_find_config("host");
	
	port = gpam_sql_find_config("port");

	login = gpam_sql_find_config("login");
	CHKVAR(login);

	pass = gpam_sql_find_config("pass");

	db = gpam_sql_find_config("db");
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
	*pres = PQexec (pgconn, query);
	*ppgconn = pgconn;
	return PAM_SUCCESS;
}

static int
pgsql_setenv(pam_handle_t *pamh, PGconn *pgconn, const char *query)
{
#ifdef HAVE_PAM_MISC_SETENV	
	int rc;
	PGresult *res;
	
	DEBUG(10,("Executing %s", query));
	res = PQexec(pgconn, query);
	if (res == NULL) {
		_pam_log(LOG_ERR, "PQexec: %s", PQerrorMessage(pgconn));
		rc = PAM_SERVICE_ERR;
	} else if (PQresultStatus(res) != PGRES_TUPLES_OK) {
		_pam_log(LOG_ERR, "PQexec: query did not return tuples");
		rc = PAM_SERVICE_ERR;
	} else if (PQntuples(res) > 0) {
		char *p;
		int i, nf;

		nf = PQnfields(res);
		for (i = 0; i < nf; i++) {
			p = PQgetvalue(res, 0, i);
			if (p) {
				gray_trim_ws(p);
				pam_misc_setenv(pamh, PQfname(res, i), p, 0);
			}
		}
		rc = PAM_SUCCESS;
	}
	PQclear(res);
	return rc;
#else
	_pam_log(LOG_ERR, "MySQL: PAM setenv is not available.");
	return PAM_SERVICE_ERR;
#endif
}


int
gpam_sql_verify_user_pass(pam_handle_t *pamh, const char *password,
			  const char *query)
{
	int rc;
	PGconn *pgconn;
	PGresult *res;

	rc = pgsql_do_query(&pgconn, &res, query);
	if (rc != PAM_SUCCESS)
		return rc;
	if (res == NULL) {
		_pam_log(LOG_ERR, "PQexec: %s", PQerrorMessage(pgconn));
		rc = PAM_SERVICE_ERR;
	} else if (PQresultStatus(res) != PGRES_TUPLES_OK) {
		_pam_log(LOG_ERR, "PQexec: query did not return tuples");
		rc = PAM_SERVICE_ERR;
	} else {
		char *p;
		int n;
		gray_slist_t slist;

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
		gray_trim_ws(p);
		DEBUG(100,("Obtained password value: %s", p));

		rc = PAM_AUTH_ERR;
		if (strcmp(p, crypt(password, p)) == 0)
			rc = PAM_SUCCESS;
		if (rc != PAM_SUCCESS
		    && gpam_sql_check_boolean_config ("allow-ldap-pass", 1))
			rc = gray_check_ldap_pass (p, password);
		if (rc != PAM_SUCCESS
		    && gpam_sql_check_boolean_config ("allow-plaintext-pass", 0)
		    && strcmp (p, password) == 0)
			rc = PAM_SUCCESS;

		/* FIXME: This comment is needed to pacify
		   `make check-sql-config' in doc:
		   gpam_sql_find_config("setenv-query") */
		if (rc == PAM_SUCCESS
		    && (query = gpam_sql_get_query(pamh,
						   "setenv-query",
						   &slist, 0))) {
			pgsql_setenv(pamh, pgconn, query);
			gray_slist_free(&slist);
		}
	}

	PQclear(res);
	PQfinish(pgconn);
	
	return rc;
}

int
gpam_sql_acct(pam_handle_t *pamh, const char *query)
{
	int rc;
	PGconn *pgconn;
	PGresult *res;

	rc = pgsql_do_query(&pgconn, &res, query);
	if (rc != PAM_SUCCESS)
		return rc;
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

	
#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_fshadow_modstruct = {
	"pam_pgsql",
	pam_sm_authenticate,
	pam_sm_setcred,
	NULL,
	pam_sm_open_session,
	pam_sm_close_session,
	NULL,
};

#endif
