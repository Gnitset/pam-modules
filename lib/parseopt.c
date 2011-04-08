/* This file is part of pam-modules.
   Copyright (C) 2008, 2010-2011 Sergey Poznyakoff
 
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

static struct pam_opt *
find_opt(struct pam_opt *opt, const char *str, const char **value)
{
	size_t len = strlen(str);
	int isbool;
	
	if (len > 2 && memcmp(str, "no", 2) == 0) {
		*value = NULL;
		str += 2;
		isbool = 1;
	} else {
		isbool = 0;
		*value = str;
	}
	
	for (; opt->name; opt++) {
		if (len >= opt->len
		    && memcmp(opt->name, str, opt->len) == 0
		    && (!isbool || opt->type == pam_opt_bool)) {
			int eq = str[opt->len] == '=';
			
			switch (opt->type) {
			case pam_opt_long:
			case pam_opt_string:
			case pam_opt_enum:
				if (!eq)
					continue;
				*value = str + opt->len + 1;
				break;

			case pam_opt_null:
				if (eq)
					*value = str + opt->len + 1;
				else
					*value = NULL;
				break;					
				
			default:
				if (eq)
					continue;
				break;
			}
			return opt;
		}
	}
	return NULL;
}

int
find_value(const char **enumstr, const char *value)
{
	int i;
	for (i = 0; *enumstr; enumstr++, i++)
		if (strcmp(*enumstr, value) == 0)
			return i;
	return -1;
}

int
gray_parseopt(struct pam_opt *opt, int argc, const char **argv)
{
	long n;
	char *s;
	int rc = 0;
	
	for (; argc-- > 0; ++argv) {
		const char *value;
		struct pam_opt *p = find_opt(opt, *argv, &value);

		if (!p) {
			_pam_log(LOG_ERR,
				 "%s: unknown option", *argv);
			rc = 1;
			continue;
		}
				
		switch (p->type) {
		case pam_opt_long:
			n = strtol(value, &s, 0);
			if (*s) {
				_pam_log(LOG_ERR,
					 "%s: %s is not a valid number",
					 p->name, value);
				rc = 1;
				continue;
			}
			*(long*)p->data = n;
			break;

		case pam_opt_const:
			*(long*)p->data = p->v.value;
			break;
						 
		case pam_opt_string:
			*(const char**)p->data = value;
			break;

		case pam_opt_bool:
			if (p->v.value) {
				if (value)
					*(int*)p->data |= p->v.value;
				else
					*(int*)p->data &= ~p->v.value;
			} else
				*(int*)p->data = value != NULL;
			break;
			
		case pam_opt_bitmask:
			*(int*)p->data |= p->v.value;
			break;
				
		case pam_opt_bitmask_rev:
			*(int*)p->data &= ~p->v.value;
			break;
				
		case pam_opt_enum:
			n = find_value(p->v.enumstr, value);
			if (n == -1) {
				_pam_log(LOG_ERR,
					 "%s: invalid value %s",
					 p->name, value);
				rc = 1;
				continue;
			}
			*(int*)p->data = n;
			break;

		case pam_opt_null:
			break;
		}

		if (p->func && p->func (p, value))
			rc = 1;
	}
	return rc;
}
