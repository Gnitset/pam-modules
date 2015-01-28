/* This file is part of pam-modules.
   Copyright (C) 2008, 2010-2012, 2014-2015 Sergey Poznyakoff
 
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
#if defined(HAVE_CRYPT_H)
# include <crypt.h>
#else
extern char *crypt(const char *, const char *);
#endif
#include "md5.h"
#include "sha1.h"

static int
my_strncasecmp (const char *p, const char *q, size_t len)
{
  for ( ;len; len--, p++, q++)
    {
      if (*p != toupper (*q))
	return 1;
    }
  return 0;
}

typedef int (*pwcheck_fp) (const char *, const char *);

static int
chk_crypt (const char *db_pass, const char *pass)
{
  return strcmp (db_pass, crypt (pass, db_pass)) == 0 ?
      PAM_SUCCESS : PAM_AUTH_ERR;
}

static int
chk_md5 (const char *db_pass, const char *pass)
{
  unsigned char md5digest[16];
  struct gpam_md5_ctx md5context;
  gray_slist_t slist = gray_slist_create ();
  ssize_t size;
  char *p;
  int rc;
  
  gpam_md5_init_ctx (&md5context);
  gpam_md5_process_bytes (pass, strlen (pass), &md5context);
  gpam_md5_finish_ctx (&md5context, md5digest);

  size = gray_base64_decode(slist, db_pass, strlen (db_pass));
  if (size != 16)
    {
      gray_slist_free(&slist);
      return PAM_AUTH_ERR;
    }
  p = gray_slist_finish(slist);
  rc = memcmp (md5digest, p, sizeof md5digest) == 0 ?
         PAM_SUCCESS : PAM_AUTH_ERR;
  gray_slist_free(&slist);
  return rc;
}

static int
chk_smd5 (const char *db_pass, const char *pass)
{
  int rc;
  unsigned char md5digest[16];
  unsigned char *d1;
  struct gpam_md5_ctx md5context;
  gray_slist_t slist = gray_slist_create();
  ssize_t size;

  size = gray_base64_decode(slist, db_pass, strlen (db_pass));
  if (size <= 16)
    {
      _pam_log(LOG_ERR, "malformed SMD5 password: %s", db_pass);
      gray_slist_free(&slist);
      return PAM_AUTH_ERR;
    }
  
  d1 = gray_slist_finish(slist);
  
  gpam_md5_init_ctx (&md5context);
  gpam_md5_process_bytes (pass, strlen (pass), &md5context);
  gpam_md5_process_bytes (d1 + 16, size - 16, &md5context);
  gpam_md5_finish_ctx (&md5context, md5digest);

  rc = memcmp (md5digest, d1, sizeof md5digest) == 0 ?
        PAM_SUCCESS : PAM_AUTH_ERR;    
  gray_slist_free(&slist);
  return rc;
}

static int
chk_sha (const char *db_pass, const char *pass)
{
  int rc;
  unsigned char sha1digest[20];
  unsigned char *d1;
  struct gpam_sha1_ctx sha1context;
  gray_slist_t slist = gray_slist_create();
  ssize_t size;
   
  gpam_sha1_init_ctx (&sha1context);
  gpam_sha1_process_bytes (pass, strlen (pass), &sha1context);
  gpam_sha1_finish_ctx (&sha1context, sha1digest);

  size = gray_base64_decode(slist, db_pass, strlen (db_pass));
  if (size != 20)
    {
      gray_slist_free(&slist);
      return 1;
    }
  
  d1 = gray_slist_finish(slist);
  rc = memcmp (sha1digest, d1, sizeof sha1digest) == 0 ?
           PAM_SUCCESS : PAM_AUTH_ERR;
  gray_slist_free(&slist);
  return rc;
}

static int
chk_ssha (const char *db_pass, const char *pass)
{
  int rc;
  unsigned char sha1digest[20];
  unsigned char *d1;
  struct gpam_sha1_ctx sha1context;
  gray_slist_t slist = gray_slist_create();
  ssize_t size;

  size = gray_base64_decode(slist, db_pass, strlen (db_pass));
  if (size <= 16)
    {
      _pam_log (LOG_ERR, "malformed SSHA1 password: %s", db_pass);
      gray_slist_free(&slist);
      return 1;
    }
  d1 = gray_slist_finish(slist);
  
  gpam_sha1_init_ctx (&sha1context);
  gpam_sha1_process_bytes (pass, strlen (pass), &sha1context);
  gpam_sha1_process_bytes (d1 + 20, size - 20, &sha1context);
  gpam_sha1_finish_ctx (&sha1context, sha1digest);

  rc = memcmp (sha1digest, d1, sizeof sha1digest) == 0 ?
        PAM_SUCCESS : PAM_AUTH_ERR;
  gray_slist_free(&slist);
  return rc;
}

static struct passwd_algo
{
  char *algo;
  size_t len;
  pwcheck_fp pwcheck;
} pwtab[] = {
#define DP(s, f) { #s, sizeof (#s) - 1, f }
  DP (CRYPT, chk_crypt),
  DP (MD5, chk_md5),
  DP (SMD5, chk_smd5),
  DP (SHA, chk_sha),
  DP (SSHA, chk_ssha),
  { NULL }
#undef DP
};

static pwcheck_fp
find_pwcheck (const char *algo, int len)
{
  struct passwd_algo *p;
  for (p = pwtab; p->algo; p++)
    if (len == p->len && my_strncasecmp (p->algo, algo, len) == 0)
      return p->pwcheck;
  return NULL;
}

int
gray_check_ldap_pass (const char *db_pass, const char *pass)
{
  if (db_pass[0] == '{')
    {
      int len;
      const char *algo;
      pwcheck_fp pwcheck;

      algo = db_pass + 1;
      for (len = 0; algo[len] != '}'; len++)
	if (algo[len] == 0)
	  {
	    /* Possibly malformed password */
	    return PAM_AUTH_ERR;
	  }
      db_pass = algo + len + 1;
      pwcheck = find_pwcheck (algo, len);
      if (pwcheck)
	return pwcheck (db_pass, pass);
      else
	{
	  _pam_log (LOG_ERR, "Unsupported password algorithm scheme: %.*s",
		    len, algo);
	  return PAM_AUTH_ERR;
	}
    }
  
  return PAM_AUTH_ERR;
}

