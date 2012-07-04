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

#include <graypam.h>
#include <string.h>
#include <mysql/mysql.h>
#include "pam_sql.h"

char *gpam_sql_module_name = "pam_mysql";


/* MySQL scrambled password support */


/* Convert a single hex digit to corresponding number */
static unsigned 
digit_to_number (char c)
{
	return (unsigned) (c >= '0' && c <= '9' ? c-'0' :
			   c >= 'A' && c <= 'Z' ? c-'A'+10 :
			   c-'a'+10);
}

/* Extract salt value from MySQL scrambled password.
   
   WARNING: The code assumes that
       1. strlen (password) % 8 == 0
       2. number_of_entries (RES) = strlen (password) / 8

   For MySQL >= 3.21, strlen(password) == 16 */
static void
get_salt_from_scrambled (unsigned long *res, const char *password)
{
	res[0] = res[1] = 0;
	while (*password) {
		unsigned long val = 0;
		unsigned i;
		
		for (i = 0; i < 8 ; i++)
			val = (val << 4) + digit_to_number (*password++);
		*res++ = val;
	}
}

/* Scramble a plaintext password */
static void
scramble_password (unsigned long *result, const char *password)
{
	unsigned long nr = 1345345333L, add = 7, nr2 = 0x12345671L;
	unsigned long tmp;

	for (; *password ; password++) {
		if (*password == ' ' || *password == '\t')
			continue;                   
		tmp = (unsigned long) (unsigned char) *password;
		nr ^= (((nr & 63) + add) * tmp)+ (nr << 8);
		nr2 += (nr2 << 8) ^ nr;
		add += tmp;
	}

	result[0] = nr & (((unsigned long) 1L << 31) -1L);
	result[1] = nr2 & (((unsigned long) 1L << 31) -1L);
}

static void
mu_octet_to_hex (char *to, const unsigned char *str, unsigned len)
{
	const unsigned char *str_end= str + len;
	static char d[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

	for ( ; str != str_end; ++str) {
		*to++ = d[(*str & 0xF0) >> 4];
		*to++ = d[*str & 0x0F];
	}
	*to= '\0';
}

#define SHA1_HASH_SIZE 20
static int
mu_check_mysql_4x_password (const char *scrambled, const char *message)
{
	struct sha1_ctx sha1_context;
	unsigned char hash_stage2[SHA1_HASH_SIZE];
	char to[2*SHA1_HASH_SIZE + 2];

	/* stage 1: hash password */
	gpam_sha1_init_ctx (&sha1_context);
	gpam_sha1_process_bytes (message, strlen (message), &sha1_context);
	gpam_sha1_finish_ctx (&sha1_context, to);
	
	/* stage 2: hash stage1 output */
	gpam_sha1_init_ctx (&sha1_context);
	gpam_sha1_process_bytes (to, SHA1_HASH_SIZE, &sha1_context);
	gpam_sha1_finish_ctx (&sha1_context, hash_stage2);
	
	/* convert hash_stage2 to hex string */
	to[0] = '*';
	mu_octet_to_hex (to + 1, hash_stage2, SHA1_HASH_SIZE);
	
	/* Compare both strings */
	return memcmp (to, scrambled, strlen (scrambled));
}

static int
mu_check_mysql_3x_password (const char *scrambled, const char *message)
{
	unsigned long hash_pass[2], hash_message[2];
	char buf[17];
	
	memcpy (buf, scrambled, 16);
	buf[16] = 0;
	scrambled = buf;
	
	get_salt_from_scrambled (hash_pass, scrambled);
	scramble_password (hash_message, message);
	return !(hash_message[0] == hash_pass[0]
		 && hash_message[1] == hash_pass[1]);
}

/* Check whether a plaintext password MESSAGE matches MySQL scrambled password
   PASSWORD */
static int
mu_check_mysql_scrambled_password (const char *scrambled, const char *message)
{
	const char *p;

	/* Try to normalize it by cutting off trailing whitespace */
	for (p = scrambled + strlen (scrambled) - 1;
	     p > scrambled && isspace (*p); p--)
		;
	switch (p - scrambled) {
	case 15:
		return mu_check_mysql_3x_password (scrambled, message);
	case 40:
		return mu_check_mysql_4x_password (scrambled, message);
	}
  return 1;
}

static int
check_mysql_pass(const char *sqlpass, const char *userpass)
{
	if (mu_check_mysql_scrambled_password (sqlpass, userpass) == 0)
		return PAM_SUCCESS;
	else
		return PAM_AUTH_ERR;
}


static void
make_digest (char *md5str, unsigned char *digest)
{
	int i;
	
	for (i = 0; i < 16; i++) {
		sprintf(md5str, "%02x", digest[i]);
		md5str += 2;
	}

	*md5str = 0;
}

static int
check_md5_pass(const char *sqlpass, const char *userpass)
{
	char md5str[33];
	struct gpam_md5_ctx ctx;
	unsigned char digest[16];

	md5str[0] = 0;
	gpam_md5_init_ctx (&ctx);
	gpam_md5_process_bytes (userpass, strlen (userpass), &ctx);
	gpam_md5_finish_ctx (&ctx, digest);
	make_digest (md5str, digest);
	if (strcmp (sqlpass, md5str) == 0)
		return PAM_SUCCESS;
	else
		return PAM_AUTH_ERR;
}
		
static void
flush_result(MYSQL *mysql)
{
        while (mysql_next_result(mysql) == 0) {
                MYSQL_RES *result = mysql_store_result(mysql);
                if (!result)
                        break;
                if (mysql_field_count(mysql))
                        while (mysql_fetch_row(result))
                                ;
                mysql_free_result(result);
        }
}

static int
check_query_result(MYSQL *mysql, const char *pass)
{
	MYSQL_RES *result;
	int rc = PAM_AUTH_ERR;
	
	result = mysql_store_result(mysql);
	if (!result) {
		_pam_log(LOG_ERR, "MySQL: query returned 0 tuples");
		rc = PAM_AUTH_ERR;
	} else {
		MYSQL_ROW row;
		long n = mysql_num_rows(result);
		if (n != 1) {
			_pam_log(LOG_WARNING,
				 "MySQL: query returned %d tuples", n);
			if (n == 0) {
				mysql_free_result(result);
				flush_result(mysql);
				return PAM_AUTH_ERR;
			}
		}
		n = mysql_num_fields(result);
		if (n != 1) {
			_pam_log(LOG_WARNING,
				 "MySQL: query returned %d fields", n);
		}
		
		row = mysql_fetch_row(result);
		gray_trim_ws(row[0]);
		DEBUG(100,("Obtained password value: %s", row[0]));
		if (strcmp(row[0], crypt(pass, row[0])) == 0)
			rc = PAM_SUCCESS;
		if (rc != PAM_SUCCESS
		    && gpam_sql_check_boolean_config ("allow-mysql-pass", 1))
			rc = check_mysql_pass (row[0], pass);
		if (rc != PAM_SUCCESS
		    && gpam_sql_check_boolean_config ("allow-md5-pass", 1))
			rc = check_md5_pass (row[0], pass);
		if (rc != PAM_SUCCESS
		    && gpam_sql_check_boolean_config ("allow-ldap-pass", 1))
			rc = gray_check_ldap_pass (row[0], pass);
		if (rc != PAM_SUCCESS
		    && gpam_sql_check_boolean_config ("allow-plaintext-pass", 0)) {
			if (strcmp (row[0], pass) == 0)
				rc = PAM_SUCCESS;
		}
	}
	mysql_free_result(result);
	flush_result(mysql);
	return rc;
}

static int
mysql_do_query(MYSQL *mysql, const char *query)
{
	char *socket_path = NULL;
	char *hostname;
	char *login;
	char *pass;
	char *db;
	char *port;
	int portno;
	char *p;
	
	hostname = gpam_sql_find_config("host");
	CHKVAR(hostname);
	if (hostname[0] == '/') {
		socket_path = hostname;
		hostname = "localhost";
	}
	
	port = gpam_sql_find_config("port");
	if (!port)
		portno = 3306;
	else {
		portno = strtoul (port, &p, 0);
		if (*p) {
			_pam_log(LOG_ERR, "Invalid port number: %s", port);
			return PAM_SERVICE_ERR;                       
		}
	}
	
	login = gpam_sql_find_config("login");
	CHKVAR(login);

	pass = gpam_sql_find_config("pass");
	CHKVAR(pass);

	db = gpam_sql_find_config("db");
	CHKVAR(db);

	mysql_init(mysql);

	if (!mysql_real_connect(mysql, hostname,
				login, pass, db,
				portno, socket_path, CLIENT_MULTI_RESULTS)) {
		_pam_log(LOG_ERR, "cannot connect to MySQL");
		return PAM_SERVICE_ERR;
	}
	
	DEBUG(10,("Executing %s", query));
	if (mysql_query(mysql, query)) {
		_pam_log(LOG_ERR, "MySQL: %s", mysql_error(mysql));
		mysql_close(mysql);
		return PAM_SERVICE_ERR;
	}
	return PAM_SUCCESS;
}

static int
mysql_setenv(pam_handle_t *pamh, MYSQL *mysql, const char *query)
{
#ifdef HAVE_PAM_MISC_SETENV
	MYSQL_RES *result;

	DEBUG(10,("Executing %s", query));
	if (mysql_query(mysql, query)) {
		_pam_log(LOG_ERR, "MySQL: %s", mysql_error(mysql));
		return PAM_SERVICE_ERR;
	}
	if (!(result = mysql_store_result(mysql))) {
		_pam_log(LOG_ERR, "MySQL: cannot get result: %s",
			 mysql_error(mysql));
		return PAM_SERVICE_ERR;
	}
	if (mysql_num_rows(result)) {
		MYSQL_ROW row = mysql_fetch_row(result);
		MYSQL_FIELD *fields = mysql_fetch_fields(result);
		size_t i, nf = mysql_num_fields(result);
		for (i = 0; i < nf; i++)
			if (row[i])
				pam_misc_setenv(pamh, fields[i].name,
						row[i], 0);
	}
	mysql_free_result(result);
	flush_result(mysql);
	return PAM_SUCCESS;
#else
	_pam_log(LOG_ERR, "MySQL: PAM setenv is not available.");
	return PAM_SERVICE_ERR;
#endif
}

int
gpam_sql_verify_user_pass(pam_handle_t *pamh, const char *password,
			  const char *query)
{
	MYSQL mysql;
	int rc;

	rc = mysql_do_query(&mysql, query);
	if (rc == PAM_SUCCESS) {
		const char *q;
		gray_slist_t slist;
		
		rc = check_query_result(&mysql, password);
		/* FIXME: This comment is needed to pacify
		   `make check-sql-config' in doc:
		   gpam_sql_find_config("setenv-query") */
		if (rc == PAM_SUCCESS
		    && (q = gpam_sql_get_query(pamh, "setenv-query", 
                                               &slist, 0))) {
			mysql_setenv(pamh, &mysql, q);
			gray_slist_free(&slist);
		}
		mysql_close(&mysql);
	}
	
	return rc;
}

int
gpam_sql_acct(pam_handle_t *pamh, const char *query)
{
	MYSQL mysql;
	int rc;

	rc = mysql_do_query(&mysql, query);
	if (rc == PAM_SUCCESS) {
		if (debug_level >= 10) {
			MYSQL_RES      *result;
			if (!(result = mysql_store_result(&mysql))) {
				_pam_log(LOG_ERR, "MySQL: cannot get result: %s",
					 mysql_error(&mysql));
			} else {
				size_t n = mysql_num_rows(result);
				mysql_free_result(result);
				flush_result(&mysql);
				_pam_debug("query affected %lu tuples", n);
			}
		}
		mysql_close(&mysql);
	}
	return rc;
}

	
#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_fshadow_modstruct = {
	"pam_mysql",
	pam_sm_authenticate,
	pam_sm_setcred,
	NULL,
	pam_sm_open_session,
	pam_sm_close_session,
	NULL,
};

#endif
