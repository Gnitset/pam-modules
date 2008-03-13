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
#if defined(HAVE_CRYPT_H)
# include <crypt.h>
#else
extern char *crypt(const char *, const char *);
#endif

/* indicate the following groups are defined */
#define PAM_SM_AUTH

#define CHKVAR(v) \
 	if (!(v)) {                                                        \
	        _pam_log(LOG_ERR, "%s: %s not defined", config_file, #v);  \
		return PAM_SERVICE_ERR;                                    \
	}                                                                  \
       	DEBUG(100,("Config: %s=%s", #v, v));

static int verify_user_pass(const char *username, const char *password);

#define CNTL_AUTHTOK      0x0010

static int cntl_flags;
char *config_file = SYSCONFDIR "/pam_sql.conf";

static void
_pam_parse(int argc, const char **argv)
{
	int ctrl=0;

	gray_log_init(0, MODULE_NAME, LOG_AUTHPRIV);

	/* step through arguments */
	for (ctrl=0; argc-- > 0; ++argv) {

		/* generic options */

		if (!strncmp(*argv,"debug",5)) {
			ctrl |= CNTL_DEBUG;
			if ((*argv)[5] == '=') 
				CNTL_SET_DEBUG_LEV(ctrl,atoi(*argv+6));
			else
				CNTL_SET_DEBUG_LEV(ctrl,1);
		} else if (!strcmp(*argv, "audit"))
			ctrl |= CNTL_AUDIT;
		else if (!strncmp(*argv, "waitdebug", 9))
			WAITDEBUG(*argv + 9);
		else if (!strcmp(*argv,"use_authtok"))
			ctrl |= CNTL_AUTHTOK;
		else if (!strncmp(*argv, "config=", 7)) 
			config_file = (char*) (*argv + 7);
		else {
			_pam_log(LOG_ERR,"unknown option: %s",
				 *argv);
		}
	}
	cntl_flags = ctrl;
}


static int
_pam_get_password(pam_handle_t *pamh, char **password, const char *prompt)
{
	char *item, *token;
	int retval;
	struct pam_message msg[3], *pmsg[3];
	struct pam_response *resp;
	int i, replies;

	DEBUG(100,("enter _pam_get_password"));
	
	if (cntl_flags & CNTL_AUTHTOK) {
		/*
		 * get the password from the PAM item
		 */
		retval = pam_get_item(pamh, PAM_AUTHTOK,
				      (const void **) &item);
		if (retval != PAM_SUCCESS) {
			/* very strange. */
			_pam_log(LOG_ALERT,
				 "can't retrieve password item: %s",
				 pam_strerror(pamh, retval));
			return retval;
		} else if (item != NULL) {
			*password = item;
			item = NULL;
			return PAM_SUCCESS;
		} else
			return PAM_AUTHTOK_RECOVER_ERR;
	}

	/*
	 * ask user for the password
	 */
	/* prepare to converse */

	i = 0;
	pmsg[i] = &msg[i];
	msg[i].msg_style = PAM_PROMPT_ECHO_OFF;
	msg[i++].msg = (const void*)prompt;
	replies = 1;

	/* run conversation */
	resp = NULL;
	token = NULL;
	retval = gray_converse(pamh, i, pmsg, &resp);

	if (resp != NULL) {
		if (retval == PAM_SUCCESS) { 	/* a good conversation */
			token = XSTRDUP(resp[i - replies].resp);
			DEBUG(10,("app returned [%s]", token));
			PAM_DROP_REPLY(resp, 1);
		} else {
			_pam_log(LOG_ERR, "conversation error: %s",
				 pam_strerror(pamh, retval));
		}
		
	} else {
		retval = (retval == PAM_SUCCESS)
			? PAM_AUTHTOK_RECOVER_ERR : retval;
	}

	if (retval == PAM_SUCCESS) {
		/*
		 * keep password as data specific to this module. pam_end()
		 * will arrange to clean it up.
		 */
		retval = pam_set_data(pamh, "password",
				      (void *)token,
				      gray_cleanup_string);
		if (retval != PAM_SUCCESS) {
			_pam_log(LOG_CRIT, 
			         "can't keep password: %s",
				 pam_strerror(pamh, retval));
			gray_pam_delete(token);
		} else {
			*password = token;
			token = NULL;	/* break link to password */
		}
	} else {
		_pam_log(LOG_ERR,
			 "unable to obtain a password: %s",
			 pam_strerror(pamh, retval));
	} 
	
	DEBUG(100,("exit _pam_get_password: %d", retval));
	return retval;
}


/* Configuration */
typedef struct config_env env_t;
struct config_env {
	env_t *next;
	char *name;
	char *value;
};
static env_t *config_env;	

/*
 * Chop off trailing whitespace. Return length of the resulting string
 */
static int
chop(char *str)
{
	int len;

	for (len = strlen(str); len > 0 && isspace(str[len-1]); len--)
		;
	str[len] = 0;
	return len;
}

char *
find_config(const char *name)
{
	env_t *env;

	for (env = config_env; env; env = env->next)
		if (strcmp(env->name, name) == 0)
			return env->value;
	return NULL;
}

void
free_config()
{
	env_t *env = config_env;
	while (env) {
		env_t *next = env->next;
		free(env->name);
		free(env);
		env = next;
	}
}

static int
boolean_true_p(const char *value)
{
	return strcmp(value, "yes") == 0
		|| strcmp(value, "true") == 0
		|| strcmp(value, "t") == 0;
}

static int
check_boolean_config(const char *name, int defval)
{
	const char *value = find_config(name);
	if (value)
		defval = boolean_true_p(value);
	return defval;
}

static int
read_config ()
{
	FILE *fp;
	char *p;
	int rc = 0;
	int line = 0;
	char buf[128];
	
	fp = fopen (config_file, "r");
	if (!fp) {
		_pam_log(LOG_ERR, "cannot open configuration file `%s': %s",
			 config_file, strerror (errno));
		return 1;
	}

	while (p = fgets (buf, sizeof buf, fp)) {
		int len;
		env_t *env;

		line++;
		while (*p && isspace(*p))
			p++;
		len = strlen(p);
		if (len == 0)
			continue;
		if (p[len-1] != '\n') {
			_pam_log(LOG_EMERG, "%s:%d: string too long",
				 config_file, line);
			continue;
		}

		p[len-1] = 0;
		chop(p);
			
		if (*p == 0 || *p == '#')
			continue;
			
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
				 config_file, line);
			free(env->name);
			free(env);
			continue;
		}
		env->value = p;
		env->next = config_env;
		config_env = env;
	}
	
	fclose(fp);
	return rc;
}
		



/* --- authentication management functions (only) --- */

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	const char *username;
	char *password;
	int retval = PAM_AUTH_ERR;

	/* parse arguments */
	_pam_parse(argc, argv);

	/* Get the username */
	retval = pam_get_user(pamh, &username, NULL);
	if (retval != PAM_SUCCESS || !username) {
		_pam_log(LOG_DEBUG, "can not get the username");
		return PAM_SERVICE_ERR;
	}

	/* Get the password */
	if (_pam_get_password(pamh, &password, "Password:"))
		return PAM_SERVICE_ERR;

	if (retval != PAM_SUCCESS) {
		_pam_log(LOG_ERR, "Could not retrive user's password");
		return PAM_SERVICE_ERR;
	}

	if (read_config()) 
		retval = PAM_SERVICE_ERR;
	else
		retval = verify_user_pass(username, password);
	free_config();
	
	switch (retval) {
	case PAM_ACCT_EXPIRED:
		_pam_log(LOG_NOTICE, "user '%s': account expired", username);
		break;
	case PAM_SUCCESS:
		_pam_log(LOG_NOTICE, "user '%s' granted access", username);
		break;
	default:
		_pam_log(LOG_NOTICE, "user '%s' failed to authenticate",
			 username);
	}

	return retval;
}

PAM_EXTERN
int pam_sm_setcred(pam_handle_t *pamh, int flags,
		   int argc, const char **argv)
{
    return PAM_SUCCESS;
}

PAM_EXTERN
int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
		   int argc, const char **argv)
{
    return PAM_SUCCESS;
}

#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_fshadow_modstruct = {
	MODULE_NAME,
	pam_sm_authenticate,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
};

#endif
