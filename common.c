#ifndef PAM_CONV_AGAIN
# define PAM_CONV_AGAIN PAM_TRY_AGAIN
#endif
#ifndef PAM_AUTHTOK_RECOVER_ERR
# define PAM_AUTHTOK_RECOVER_ERR PAM_AUTHTOK_RECOVERY_ERR
#endif
#ifndef PAM_EXTERN
# define PAM_EXTERN
#endif

#define XSTRDUP(s) (s) ? strdup(s) : NULL

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
	
static void
_pam_delete(char *x)
{
	PAM_OVERWRITE(x);
	free(x);
}

static void
_cleanup_string(pam_handle_t *pamh, void *x, int error_status)
{
	_pam_delete(x);
}

