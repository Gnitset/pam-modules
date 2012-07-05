/* This file is part of pam-modules.
   Copyright (C) 2012 Sergey Poznyakoff

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

#ifdef HAVE__PAM_ACONF_H
# include <security/_pam_aconf.h>
#endif
#ifndef LINUX_PAM
# include <security/pam_appl.h>
#endif				/* LINUX_PAM */
#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include <sys/types.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>

#include "graypam.h"

#define PAM_SM_SESSION

static long debug_level;
static int cntl_flags;
static char *motd_file_name;
static int optindex = -1;
static long timeout_option = 10;
static const char *logfile_name;
static long max_output_size = 2000;
static char *la_str;

struct pam_opt pam_opt[] = {
	{ PAM_OPTSTR(debug),   pam_opt_long, &debug_level },
	{ PAM_OPTSTR(debug),   pam_opt_const, &debug_level, { 1 } },
	{ PAM_OPTSTR(audit),   pam_opt_bitmask, &cntl_flags, { CNTL_AUDIT } },
	{ PAM_OPTSTR(waitdebug), pam_opt_null, NULL, { 0 },
	  gray_wait_debug_fun },
	{ PAM_OPTSTR(file),    pam_opt_string, &motd_file_name },
	{ PAM_OPTSTR(log),     pam_opt_string, &logfile_name },
	{ PAM_OPTSTR(exec),    pam_opt_rest, &optindex },
	{ PAM_OPTSTR(timeout), pam_opt_long, &timeout_option },
	{ PAM_OPTSTR(max-size),pam_opt_long, &max_output_size },
	{ PAM_OPTSTR(max-la),  pam_opt_string, &la_str },
	{ NULL }
};

static int
fpread(const char *str, double *ret)
{
	char *p;
	*ret = strtod(str, &p);
	if (*p) {
		_pam_log(LOG_ERR,
			 "not a valid floating point number: %s",
			 str);
		return 1;
	}
	return 0;
}

/* FIXME: Linux-specific */
static int
get_la(double *ret)
{
	char buf[80];
	int rc = -1;
	FILE *fp = fopen("/proc/loadavg", "r");
	if (!fp)
		return -1;
	if (!fgets(buf, sizeof(buf), fp))
		_pam_log(LOG_ERR, "cannot read /proc/loadavg: %s",
			 strerror(errno));
	else {
		char *p = strchr(buf, ' ');
		if (*p) {
			*p = 0;
			rc = fpread(buf, ret);
		} else
			rc = -1;
	}
	fclose(fp);
	return rc;
}
		
	

static int
read_fd(pam_handle_t *pamh, const char *file, int fd)
{
	char buf[1024], *p;
	ssize_t rd;
	size_t total = 0;
	size_t level = 0;
	
	while (total < max_output_size) {
		size_t rdsize = sizeof(buf) - level - 1;

		if (total + rdsize >= max_output_size &&
		    (rdsize = max_output_size - total) == 0)
			break;
		rd = read(fd, buf + level, rdsize);
		if (rd <= 0)
			break;
		total += rd;
		level += rd;
		buf[level] = 0;
		p = strrchr(buf, '\n');
		if (p)
			*p++ = 0;
		pam_info(pamh, "%s", buf);
		if (p && *p) {
			level = strlen(p);
			memmove(buf, p, level);
		} else
			level = 0;
	}
	if (level) {
		buf[level] = 0;
		pam_info(pamh, "%s", buf);
	}
	if (rd < 0) {
		_pam_log(LOG_ERR, "error reading file %s: %s",
			 file, strerror(errno));
		return PAM_SYSTEM_ERR;
	}
	return PAM_SUCCESS;
}

static int
read_file(pam_handle_t *pamh, const char *file)
{
	int fd;
	int retval;
	
	fd = open(file, O_RDONLY);
	if (fd == -1) {
		_pam_log(LOG_INFO, "cannot open file %s: %s",
			 file, strerror(errno));
		return PAM_SYSTEM_ERR;
	}
	retval = read_fd(pamh, file, fd);
	close(fd);
	return retval;
}
	
static int
exec_file(pam_handle_t *pamh, char **argv, const char *logfile)
{
	pid_t pid, rc;
	int p[2];
	char buf[1024];
	long ttl;
	time_t start;
	int i, status, intr;
	fd_set rd;
	struct timeval tv;
	size_t total = 0;
	
	if (pipe(p)) {
		_pam_log(LOG_ERR, "pipe: %s", strerror(errno));
		return PAM_SYSTEM_ERR;
	}
		
	pid = fork();
	if (pid == -1) {
		close(p[0]);
		close(p[1]);
		_pam_log(LOG_ERR, "fork: %s", strerror(errno));
		return PAM_SYSTEM_ERR;
	}
	
	if (pid == 0) {		
		/* child */
		if (dup2(p[1], 1) == -1) {
			_pam_log(LOG_ERR, "dup2: %s", strerror(errno));
			_exit(127);
		}
		for (i = sysconf(_SC_OPEN_MAX); i >= 0; i--) {
			if (i != 1)
				close(i);
		}
		open("/dev/null", O_RDONLY);
		if (logfile) {
			if (open(logfile, O_CREAT|O_APPEND|O_WRONLY,
				 0644) == -1) {
				_pam_log(LOG_ERR, "open(%s): %s",
					 logfile, strerror(errno));
				_exit(127);
			}
		} else
			dup2(1, 2);
		
		execv(argv[0], argv);
		_exit(127);
	}

	/* master */
	close(p[1]);

	start = time(NULL);
	intr = 0;
	rc = 0;
	status = 0;
	for (i = 0; total < max_output_size;) {
		FD_ZERO(&rd);
		FD_SET(p[0], &rd);

		if (intr) {
			rc = waitpid(pid, &status, WNOHANG);
			if (rc == pid)
				break;
			if (rc == (pid_t)-1) {
				_pam_log(LOG_ERR, "waitpid: %s",
					 strerror(errno));
				break;
			}
			intr = 0;
		}
		ttl = timeout_option - (time(NULL) - start);
		if (ttl <= 0) {
			_pam_log(LOG_ERR, "timed out reading from %s",
				 argv[0]);
			break;
		}
		tv.tv_sec = ttl;
		tv.tv_usec = 0;
		rc = select(p[0] + 1, &rd, NULL, NULL, &tv);
		if (rc < 0) {
			if (errno == EINTR || errno == EAGAIN) {
				intr = 1;
				continue;
			}
			_pam_log(LOG_ERR, "select: %s", strerror(errno));
		}
		if (i == sizeof(buf) - 1) {
			char *p;
			buf[i] = 0;
			p = strrchr(buf, '\n');
			if (p)
				*p++ = 0;
			pam_info(pamh, "%s", buf);
			if (p && *p) {
				i = strlen(p);
				memmove(buf, p, i);
			}
		}
		if (FD_ISSET(p[0], &rd)) {
			char c;
			
			rc = read(p[0], &c, 1);
			if (rc == 1) {
				buf[i++] = c;
				total++;
			} else if (rc == 0
				   || errno == EINTR || errno == EAGAIN) {
				intr = 1;
				continue;
			} else {
				_pam_log(LOG_ERR, "read: %s", strerror(errno));
				break;
			}
		}
	}
	if (i) {
		buf[i] = 0;
		pam_info(pamh, "%s", buf);
	}
	close(p[0]);

	if (rc != pid) {
		_pam_log(LOG_NOTICE, "killing %s (pid %lu)",
			 argv[0], (unsigned long) pid);
		kill(pid, SIGKILL);
		
		while ((rc = waitpid(pid, &status, 0)) == -1 &&
		       errno == EINTR);
		if (rc == (pid_t)-1) {
			_pam_log(LOG_ERR, "waitpid: %s", strerror(errno));
			return PAM_SYSTEM_ERR;
		}
	} else if (WIFEXITED(status)) {
		status = WEXITSTATUS(status);
		if (status) {
			_pam_log(LOG_ERR, "%s exited with status %d",
				 argv[0], status);
			return PAM_SYSTEM_ERR;
		}
	} else if (WIFSIGNALED(status)) {
		status = WTERMSIG(status);
		_pam_log(LOG_ERR, "%s got signal %d", argv[0], status);
		return PAM_SYSTEM_ERR;
	} else if (status) {
		_pam_log(LOG_ERR, "%s failed: unknown status 0x%x",
			 argv[0], status);
		return PAM_SYSTEM_ERR;
	}
	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	int retval = PAM_IGNORE;
	gray_slist_t slist;
	
	cntl_flags = 0;
	debug_level = 0;
	gray_log_init(0, MODULE_NAME, LOG_AUTHPRIV);
	gray_parseopt(pam_opt, argc, argv);
	if (la_str) {
		double max_la, la;
		if (fpread(la_str, &max_la))
			return PAM_SERVICE_ERR;
		if (get_la(&la) == 0 && la >= max_la) {
			_pam_log(LOG_ERR,
				 "load average too high: %.2g >= %.2g",
				 la, max_la);
			return PAM_IGNORE;
		}
	}

	if (motd_file_name) {
		char *file;

		slist = gray_slist_create();
		gray_expand_string(pamh, motd_file_name, slist);
		gray_slist_append_char(slist, 0);
		file = gray_slist_finish(slist);
		retval = read_file(pamh, file);
		gray_slist_free(&slist);
	} else if (optindex >= 0) {
		int i;
		char **xargv;
		
		argc -= optindex;
		argv += optindex;
		if (!argc) {
			_pam_log(LOG_INFO, "empty command line");
			return retval;
		}
		xargv = gray_malloc((argc + 1) * sizeof (xargv[0]));
		slist = gray_slist_create();
		for (i = 0; i < argc; i++) {
			gray_expand_string(pamh, argv[i], slist);
			gray_slist_append_char(slist, 0);
			xargv[i] = gray_slist_finish(slist);
		}
		xargv[i] = NULL;
		retval = exec_file(pamh, xargv, logfile_name);
		free(xargv);
		gray_slist_free(&slist);
	} else
		_pam_log(LOG_ERR,
			 "invalid usage: either file or exec must be specified");
	return retval;
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return PAM_IGNORE;
}



#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_motd_modstruct = {
     "pam_motd",
     NULL,
     NULL,
     NULL,
     pam_sm_open_session,
     pam_sm_close_session,
     NULL,
};

#endif
