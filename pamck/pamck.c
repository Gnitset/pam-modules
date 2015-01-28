/* This file is part of pam-modules.
   Copyright (C) 2009-2012, 2014-2015 Sergey Poznyakoff
  
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

#include "pamck.h"
char *program_name;

void
usage()
{
	printf("usage: %s [-hv] [-s service] [-g group] user [password]\n",
	       program_name);
}

void
help()
{
	printf("usage: %s [-hv] [-s service] [-g group] user [password]\n",
	       program_name);
	printf("\nReport bugs to <%s>.\n", PACKAGE_BUGREPORT);
	printf("%s home page: <http://www.gnu.org.ua/software/%s/>.\n",
	       PACKAGE_NAME, PACKAGE);
}

void
version()
{
	printf("%s (%s) %s\n", program_name, PACKAGE, PACKAGE_VERSION);
	fputs ("\
Copyright (C) 2009-2012, 2014 Sergey Poznyakoff\n\
\n\
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.\n\
This is free software: you are free to change and redistribute it.\n\
There is NO WARRANTY, to the extent permitted by law.\n\
\n\
", stdout);
}

void
error(int code, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	fprintf(stderr, "%s: ", program_name);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
	if (code)
		exit(code);
}


struct grouptab {
	char *name;
	char *funcname;
	int (*pam_fn) (pam_handle_t *pamh, int flags);
} grouptab[] = {
	{ "auth", "pam_authenticate", pam_authenticate },
	{ "acct", "pam_acct_mgmt", pam_acct_mgmt },
	{ "open", "pam_open_session", pam_open_session },
	{ "close", "pam_close_session", pam_close_session },
	{ "pass", "pam_chauthtok", pam_chauthtok },
	{ NULL }
};

struct grouptab *
find_group(char *name)
{
	struct grouptab *p;
	for (p = grouptab; p->name; p++)
		if (strcmp(p->name, name) == 0)
			return p;
	return NULL;
}

void
groupprint()
{
	struct grouptab *p;
	for (p = grouptab; p->name; p++)
		printf("%s\n", p->name);
}

char *service = "check";
struct grouptab *group;
char *user;
char *pass;

static struct pam_conv conv = {
    pamck_conv,
    NULL
};

void
check_default(pam_handle_t *pamh)
{
	int rc;
	
        rc = pam_authenticate(pamh, 0);
	if (rc)
		error(2, "%s failed: %s",
		      "pam_authenticate", pam_strerror (pamh, rc));
	rc = pam_acct_mgmt(pamh, 0);
	if (rc)
		error(2, "%s failed: %s",
		      "pam_acct_mgmt", pam_strerror (pamh, rc));
	printf("OK\n");
}

void
check_group(pam_handle_t *pamh, struct grouptab *grp)
{
	int rc = grp->pam_fn(pamh, 0);
	if (rc) 
		error(2, "%s failed: %s", grp->funcname,
		      pam_strerror (pamh, rc));
}

int
main (int argc, char **argv)
{
	int c;
	int rc;
	pam_handle_t *pamh = NULL;
	
	program_name = argv[0];
	/* A bit of sugar to fake common GNU-style long options */
	if (argc == 2) {
		if (strcmp (argv[1], "--help") == 0) {
			help();
			exit(0);
		} if (strcmp (argv[1], "--usage") == 0) {
			usage();
			exit(0);
		} else if (strcmp (argv[1], "--version") == 0) {
			version();
			exit(0);
		}
	}
	/* Normal option processing */
	while ((c = getopt (argc, argv, "hg:s:v")) != EOF) {
		switch (c) {
		case 'h':
			help();
			exit(0);

		case 'g':
			if (strcmp(optarg, "help") == 0) {
				groupprint();
				exit(0);
			} 
			group = find_group(optarg);
			if (!group) 
				error(1,
				      "no such management group, try `%s -g help' for the list",
				      program_name);
				
			break;

		case 's':
			service = optarg;
			break;

		case 'v':
			version();
			exit(0);

		default:
			exit(1);
		}
	}

	argc -= optind;
	argv += optind;

	switch (argc) {
	case 2:
		pass = argv[1];
	case 1:
		user = argv[0];
		break;
	default:
		usage();
		exit(1);
	}

	rc = pam_start(service, user, &conv, &pamh);
	if (rc) 
		error(2, "pam_start failed");
	
	if (group)
		check_group(pamh, group);
	else
		check_default(pamh);

	if (pam_end(pamh, rc) != PAM_SUCCESS) {     
		pamh = NULL;
		error(2, "failed to release authenticator");
	}

	exit (0);
}
