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
#include <mysql/mysql.h>

#include "pam_sql.c"
#include "sha1.h"
#include "md5.h"

static char *
sql_expand_query (MYSQL *mysql,
		  const char *query, const char *user, const char *pass)
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
				int input_len = strlen(user);
				int size = 2 * input_len +1;
				esc_user = malloc(size);
				if (!esc_user)
					return NULL;
				mysql_real_escape_string(mysql,
							 esc_user,
							 user, input_len);
				
				len += strlen (esc_user);
				p += 2;
			} if (p[1] == 'p') {
				int input_len = strlen(pass);
				int size = 2 * input_len + 1;
				esc_pass = malloc(size);
				if (!esc_pass)
					return NULL;
				mysql_real_escape_string(mysql,
							 esc_pass,
							 pass, input_len);
				
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
	struct md5_ctx ctx;
	unsigned char digest[16];

	md5str[0] = 0;
	md5_init_ctx (&ctx);
	md5_process_bytes (userpass, strlen (userpass), &ctx);
	md5_finish_ctx (&ctx, digest);
	make_digest (md5str, digest);
	if (strcmp (sqlpass, md5str) == 0)
		return PAM_SUCCESS;
	else
		return PAM_AUTH_ERR;
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
				return PAM_AUTH_ERR;
			}
		}
		n = mysql_num_fields(result);
		if (n != 1) {
			_pam_log(LOG_WARNING,
				 "MySQL: query returned %d fields", n);
		}
		
		row = mysql_fetch_row(result);
		chop(row[0]);
		DEBUG(100,("Obtained password value: %s", row[0]));
		if (strcmp(row[0], crypt(pass, row[0])) == 0)
			rc = PAM_SUCCESS;
		if (rc != PAM_SUCCESS
		    && check_boolean_config ("allow-mysql-pass", 1))
			rc = check_mysql_pass (row[0], pass);
		if (rc != PAM_SUCCESS
		    && check_boolean_config ("allow-md5-pass", 1))
			rc = check_md5_pass (row[0], pass);
		if (rc != PAM_SUCCESS
		    && check_boolean_config ("allow-ldap-pass", 1))
			rc = gray_check_ldap_pass (row[0], pass);
		if (rc != PAM_SUCCESS
		    && check_boolean_config ("allow-plaintext-pass", 0)) {
			if (strcmp (row[0], pass) == 0)
				rc = PAM_SUCCESS;
		}
	}
	mysql_free_result(result);
	
	return rc;
}

static int
verify_user_pass(const char *username, const char *password)
{
	MYSQL mysql;
	char *socket_path = NULL;
	char *hostname;
	char *login;
	char *pass;
	char *db;
	char *port;
	int portno;
	char *query, *exquery;
	char *p;
	int rc;
	
	hostname = find_config("host");
	CHKVAR(hostname);
	if (hostname[0] == '/') {
		socket_path = hostname;
		hostname = "localhost";
	}
	
	port = find_config("port");
	if (!port)
		portno = 3306;
	else {
		portno = strtoul (port, &p, 0);
		if (*p) {
			_pam_log(LOG_ERR, "Invalid port number: %s", port);
			return PAM_SERVICE_ERR;                       
		}
	}
	
	login = find_config("login");
	CHKVAR(login);

	pass = find_config("pass");
	CHKVAR(pass);

	db = find_config("db");
	CHKVAR(db);

	query = find_config("query");
	CHKVAR(query);

	mysql_init(&mysql);

	if (!mysql_real_connect(&mysql, hostname,
				login, pass, db,
				portno, socket_path, 0)) {
		_pam_log(LOG_ERR, "cannot connect to MySQL");
		return PAM_SERVICE_ERR;
	}

	exquery = sql_expand_query (&mysql, query, username, password);
	if (!exquery) {
		mysql_close(&mysql);
		_pam_log(LOG_ERR, "cannot expand query");
		return PAM_SERVICE_ERR;
	}
		
	if (mysql_query(&mysql, exquery)) {
		_pam_log(LOG_ERR, "MySQL: %s", mysql_error(&mysql));
		mysql_close(&mysql);
		free(exquery);
		return PAM_SERVICE_ERR;
	}
	free(exquery);
	
	rc = check_query_result(&mysql, password);
	
	mysql_close(&mysql);

	return rc;
}

