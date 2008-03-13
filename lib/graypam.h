/* This file is part of pam-modules.
   Copyright (C) 2008 Sergey Poznyakoff
 
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

#ifndef _graypam_h_
#define _graypam_h_

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
#include <ctype.h>
#include <syslog.h>
#include <errno.h>
#include <regex.h>
#include <setjmp.h>

#ifndef LINUX_PAM
#include <security/pam_appl.h>
#endif				/* LINUX_PAM */
#include <security/pam_modules.h>

#ifndef PAM_CONV_AGAIN
# define PAM_CONV_AGAIN PAM_TRY_AGAIN
#endif
#ifndef PAM_AUTHTOK_RECOVER_ERR
# define PAM_AUTHTOK_RECOVER_ERR PAM_AUTHTOK_RECOVERY_ERR
#endif
#ifndef PAM_EXTERN
# define PAM_EXTERN
#endif

#define XSTRDUP(s) ((s) ? strdup(s) : NULL)

#define PAM_OVERWRITE(s)                              \
  do {                                                \
	register char *p;                             \
        if  ((p = s) != NULL)                         \
	    while (*p) *p++ = 0;                      \
  } while (0) 

#define PAM_DROP_REPLY(reply, nrepl)                  \
  do {                                                \
	int i;                                        \
	for (i=0; i<nrepl; i++) {                     \
            PAM_OVERWRITE(reply[i].resp);             \
            free(reply[i].resp);                      \
	}                                             \
	if (reply)                                    \
	    free(reply);                              \
  } while (0)


#define MAKE_STR(pamh, str, var) \
 gray_make_str(pamh,str,#var,&var)

#define WAITDEBUG(arg) do { size_t line = __LINE__;       \
  if ((arg)[0] == '=')                                    \
     gray_wait_debug(atoi((arg)+1), __FILE__, line);           \
  else                                                    \
     gray_wait_debug(0, __FILE__, line);		          \
} while (0)

extern jmp_buf gray_pam_jmp;

#define gray_pam_init(retval)            \
	if (setjmp(gray_pam_jmp))        \
		return retval;           \

void gray_raise(const char *fmt, ...);

void *gray_malloc(size_t size);
void *gray_zalloc(size_t size);
void *gray_realloc(void *ptr, size_t size);

void gray_pam_delete(char *x);
void gray_cleanup_string(pam_handle_t *pamh, void *x, int error_status);
void gray_cleanup_regex(pam_handle_t *pamh, void *x, int error_status);
void gray_make_str(pam_handle_t *pamh, const char *str, const char *name,
		   char **ret);


typedef struct gray_slist *gray_slist_t;

gray_slist_t gray_slist_create();
void gray_slist_clear(gray_slist_t slist);
void gray_slist_free(gray_slist_t *slist);
void gray_slist_append(gray_slist_t slist, const char *str, size_t n);
void gray_slist_append_char(gray_slist_t slist, char c);
size_t gray_slist_size(gray_slist_t slist);
size_t gray_slist_coalesce(gray_slist_t slist);
void *gray_slist_head(gray_slist_t slist, size_t *psize);
void *gray_slist_finish(gray_slist_t slist);
void gray_slist_grow_backslash_num(gray_slist_t slist, char *text, char **pend,
				   int len, int base);
void gray_slist_grow_backslash(gray_slist_t slist, char *text, char **endp);


void gray_log_init(int dont_open, const char *tag, int f);
void gray_pam_vlog(int err, const char *format, va_list args);
void gray_pam_log(int err, const char *format, ...);
void gray_pam_debug(const char *format, ...);
void gray_wait_debug(size_t interval, const char *file, size_t line);

#define _pam_vlog gray_pam_vlog
#define _pam_log gray_pam_log
#define _pam_debug gray_pam_debug


int gray_transform_name_to_slist (gray_slist_t slist, char *input, char **output);
void gray_set_transform_expr (const char *expr);


int gray_converse(pam_handle_t *pamh, int nargs,
		  struct pam_message **message,
		  struct pam_response **response);

/* Command line parsing */
#define CNTL_DEBUG        0x0001
#define CNTL_AUDIT        0x0002
#define CNTL_WAITDEBUG    0x0004

#define CNTL_DEBUG_LEV() (cntl_flags>>16)
#define CNTL_SET_DEBUG_LEV(cntl,n) (cntl |= ((n)<<16))

#define DEBUG(m,c) if (CNTL_DEBUG_LEV()>=(m)) _pam_debug c
#define AUDIT(c) if (cntl_flags&CNTL_AUDIT) _pam_debug c

#endif