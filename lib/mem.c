/* This file is part of pam-modules.
   Copyright (C) 2008, 2010-2012, 2014 Sergey Poznyakoff
 
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

jmp_buf gray_pam_jmp;

void
gray_raise(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	_pam_vlog(LOG_ERR, fmt, ap);
	va_end(ap);
	longjmp(gray_pam_jmp, 1);
}

void *
gray_malloc(size_t size)
{
	void *p = malloc(size);
	if (!p)
		gray_raise("Not enough memory");
	return p;
}

void *
gray_zalloc(size_t size)
{
	void *p = malloc(size);
	if (!p)
		gray_raise("Not enough memory");
	memset(p, 0, size);
	return p;
}

void *
gray_calloc(size_t count, size_t size)
{
	return gray_zalloc(count * size);
}

void *
gray_realloc(void *ptr, size_t size)
{
	ptr = realloc(ptr, size);
	if (!ptr)
		gray_raise("Not enough memory");
	return ptr;
}

char *
gray_strdup(const char *str)
{
	char *p;
	
	if (!str)
		return NULL;
	p = gray_malloc(strlen(str) + 1);
	return strcpy(p, str);
}


void
gray_pam_delete(char *x)
{
	PAM_OVERWRITE(x);
	free(x);
}

void
gray_cleanup_string(pam_handle_t *pamh, void *x, int error_status)
{
	gray_pam_delete(x);
}

void
gray_cleanup_regex(pam_handle_t *pamh, void *x, int error_status)
{
	regfree((regex_t*)x);
}

void
gray_make_str(pam_handle_t *pamh, const char *str, const char *name,
	      char **ret)
{
	int retval;
	char *newstr = XSTRDUP(str);

	retval = pam_set_data(pamh, name, (void *)newstr, gray_cleanup_string);
	if (retval != PAM_SUCCESS) {
		_pam_log(LOG_CRIT, 
			 "can't keep data [%s]: %s",
			 name,
			 pam_strerror(pamh, retval));
		gray_pam_delete(newstr);
	} else {
		*ret = newstr;
		newstr = NULL;
	}
}


