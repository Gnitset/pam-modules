/* This file is part of pam-modules.
   Copyright (C) 2008, 2010-2012 Sergey Poznyakoff
 
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

char *
gray_env_get(struct gray_env *env, const char *name)
{
	for (; env; env = env->next)
		if (strcmp(env->name, name) == 0)
			return env->value;
	return NULL;
}

void
gray_env_free(struct gray_env *env)
{
	while (env) {
		struct gray_env *next = env->next;
		free(env->name);
		free(env);
		env = next;
	}
}

int
gray_env_read(const char *file_name, struct gray_env **penv)
{
	FILE *fp;
	char *p;
	int rc = 0;
	int line = 0;
	char buf[128];
	gray_slist_t slist = NULL;
	struct gray_env *config_env = NULL;
		
	fp = fopen(file_name, "r");
	if (!fp) {
		_pam_log(LOG_ERR, "cannot open configuration file `%s': %s",
			 file_name, strerror (errno));
		return 1;
	}

	config_env = NULL;
	while (p = fgets(buf, sizeof buf, fp)) {
		int len;
		struct gray_env *env;
		
		line++;
		while (*p && isspace(*p))
			p++;
		len = strlen(p);
		if (len == 0)
			continue;
		if (p[len-1] != '\n') {
			if (!slist)
				slist = gray_slist_create();
			gray_slist_append(slist, p, len);
			while (p = fgets(buf, sizeof buf, fp)) {
				len = strlen(p);
				gray_slist_append(slist, p, len);
				if (p[len - 1] == '\n')
					break;
			} 
			gray_slist_append_char(slist, 0);
			p = gray_slist_finish(slist);
			len = strlen(p);
		}

		p[len-1] = 0;
		len = gray_trim_ws(p);
			
		if (*p == 0 || *p == '#')
			continue;

		if (p[len-1] == '\\') {
			int err = 0;
			
			/* Collect continuation lines */
			if (!slist)
				slist = gray_slist_create();
			do {
				gray_slist_append(slist, p, len - 1);
				p = fgets (buf, sizeof buf, fp);
				if (!p)
					break;
				line++;
				len = strlen(p);
				if (len == 0)
					break;
				if (p[len-1] != '\n') {
					_pam_log(LOG_EMERG,
						 "%s:%d: string too long",
						 file_name, line);
					err = 1; 
					break;
				}
				p[len-1] = 0;
				len = gray_trim_ws(p);
			} while (p[len-1] == '\\');
			if (len)
				gray_slist_append(slist, p, len);
			gray_slist_append_char(slist, 0);
			p = gray_slist_finish(slist);
			if (err)
				continue;
		}
		
		env = malloc(sizeof *env);
		if (!env) {
			_pam_log(LOG_EMERG, "not enough memory");
			rc = 1;
			break;
		}

		env->name = strdup(p);
		if (!env->name) {
			_pam_log(LOG_EMERG, "not enough memory");
			free(env);
			rc = 1;
			break;
		}

		for (p = env->name; *p && !isspace(*p); p++) 
			;
		if (*p)
			*p++ = 0;
		for (; *p && isspace(*p); p++)
			;
		if (!*p) {
			_pam_log(LOG_EMERG, "%s:%d: not enough fields",
				 file_name, line);
			free(env->name);
			free(env);
			continue;
		}
		env->value = p;
		env->next = config_env;
		config_env = env;
	}

	gray_slist_free(&slist);
	fclose(fp);
	*penv = config_env;
	return rc;
}

int
gray_boolean_true_p(const char *value)
{
	return strcmp(value, "yes") == 0
		|| strcmp(value, "true") == 0
		|| strcmp(value, "t") == 0;
}
