/* This file is part of pam-modules.
   Copyright (C) 2005, 2006 Sergey Poznyakoff

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
#include <mysql/mysql.h>

#include "pam_sql.c"
#include "sha1.h"
#include "sha1.c"

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
				int size = 2*strlen(user)+1;
				esc_user = malloc(size);
				if (!esc_user)
					return NULL;
				mysql_real_escape_string(mysql,
							 esc_user,
							 user, size);
				
				len += strlen (esc_user);
				p += 2;
			} if (p[1] == 'p') {
				int size = 2*strlen(pass)+1;
				esc_pass = malloc(len);
				if (!esc_pass)
					return NULL;
				mysql_real_escape_string(mysql,
							 esc_pass,
							 pass, size);
				
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
octet2hex (char *to, const unsigned char *str, unsigned len)
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
make_mysql_4x_password (char *to, const char *message)
{
	SHA1_CTX sha1_context;
	unsigned char hash_stage2[SHA1_HASH_SIZE];
	
	/* stage 1: hash password */
	SHA1Init(&sha1_context);
	SHA1Update(&sha1_context, message, strlen (message));
	SHA1Final(to, &sha1_context);
	
	/* stage 2: hash stage1 output */
	SHA1Init(&sha1_context);
	SHA1Update(&sha1_context, to, SHA1_HASH_SIZE);
	SHA1Final(hash_stage2, &sha1_context);
	
	/* convert hash_stage2 to hex string */
	*to++ =  '*';
	octet2hex (to, hash_stage2, SHA1_HASH_SIZE);
}

static int
mu_check_mysql_4x_password (const char *scrambled, const char *message)
{
	char to[2*SHA1_HASH_SIZE + 2];
	
	make_mysql_4x_password (to, message);
	/* Compare both strings */
	return memcmp (to, scrambled, strlen (scrambled));
}

/* Check whether a plaintext password MESSAGE matches MySQL scrambled password
   PASSWORD */
static int
mu_check_mysql_scrambled_password (const char *scrambled, const char *message)
{
	unsigned long hash_pass[2], hash_message[2];
	char buf[17];
	
	if (strlen (scrambled) < 16)
		return 1;
	if (strlen (scrambled) > 16) {
		const char *p;
		/* Try to normalize it by cutting off trailing whitespace */
		for (p = scrambled + strlen (scrambled) - 1;
		     p > scrambled && isspace (*p); p--)
			;
		if (p - scrambled != 15)
			return 1;
		memcpy (buf, scrambled, 16);
		buf[17] = 0;
		scrambled = buf;
	}
  
	get_salt_from_password (hash_pass, scrambled);
	scramble_password (hash_message, message);
	return !(hash_message[0] == hash_pass[0]
		 && hash_message[1] == hash_pass[1]);
}

static int
check_mysql_pass(const char *sqlpass, const char *userpass)
{
	if (mu_check_mysql_4x_password(sqlpass, userpass) == 0
	    || mu_check_mysql_scrambled_password (sqlpass, userpass) == 0)
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
		_pam_err(LOG_ERR, "MySQL: query returned 0 tuples");
		rc = PAM_AUTH_ERR;
	} else {
		MYSQL_ROW row;
		long n = mysql_num_rows(result);
		if (n != 1) {
			_pam_err(LOG_WARNING,
				 "MySQL: query returned %d tuples", n);
			if (n == 0) {
				mysql_free_result(result);
				return PAM_AUTH_ERR;
			}
		}
		n = mysql_num_fields(result);
		if (n != 1) {
			_pam_err(LOG_WARNING,
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
	MYSQL_RES *result;
	int rc;
	
	hostname = find_config("host");
	CHKVAR(hostname);
	if (hostname[0] == '/') {
		socket_path = hostname;
		hostname = "localhost";
	}
	
	port = find_config("port");
	CHKVAR(port);
	portno = strtoul (port, &p, 0);
	if (*p) {
	        _pam_err(LOG_ERR, "Invalid port number: %s", port);
		return PAM_SERVICE_ERR;                       
	}
	
	login = find_config("login");
	CHKVAR(login);

	pass = find_config("pass");
	CHKVAR(pass);

	db = find_config("db");
	CHKVAR(db);

	query = find_config("query");
	CHKVAR(query);

	exquery = sql_expand_query (&mysql, query, username, password);
	if (!exquery) {
		_pam_err(LOG_ERR, "cannot expand query");
		return PAM_SERVICE_ERR;
	}
		
	mysql_init(&mysql);

	if (!mysql_real_connect(&mysql, hostname,
				login, pass, db,
				portno, socket_path, 0)) {
		_pam_err(LOG_ERR, "cannot connect to MySQL");
		mysql_close(&mysql);
		free(exquery);
		return PAM_SERVICE_ERR;
	}

	if (mysql_query(&mysql, exquery)) {
		_pam_err(LOG_ERR, "MySQL: %s", mysql_error(&mysql));
		mysql_close(&mysql);
		free(exquery);
		return PAM_SERVICE_ERR;
	}
	free(exquery);
	
	rc = check_query_result(&mysql, password);
	
	mysql_close(&mysql);

	return rc;
}

