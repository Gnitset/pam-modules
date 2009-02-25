#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <security/pam_appl.h>

extern char *user;
extern char *pass;

void error(int code, const char *fmt, ...);
int pamck_conv(int, const struct pam_message **,
	       struct pam_response **, void *);
