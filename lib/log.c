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

#include <graypam.h>

/* Syslog functions */
static int syslog_dont_open;
static const char *syslog_tag = "pam_modules";
static int facility;

void
gray_log_init(int dont_open, const char *tag, int f)
{
	syslog_dont_open = dont_open;
	syslog_tag = tag;
	facility = f;
}

void
gray_pam_vlog(int err, const char *format, va_list args)
{
	if (syslog_dont_open)
		err |= facility;
	else
		openlog(syslog_tag, LOG_CONS|LOG_PID, facility);
	vsyslog(err, format, args);
	if (!syslog_dont_open)
		closelog();
}

void
gray_pam_log(int err, const char *format, ...)
{
	va_list args;
	
	va_start(args, format);
	gray_pam_vlog(err, format, args);
	va_end(args);
}

void
gray_pam_debug(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	gray_pam_vlog(LOG_DEBUG, format, args);
	va_end(args);
}

void
gray_wait_debug(size_t interval, const char *file, size_t line)
{
#ifdef DEBUG_MODE
	if (!interval)
		interval = 3600;
	if (file)
		gray_pam_log(LOG_CRIT, "WAITING FOR DEBUG AT %s:%d",
			     file, (unsigned long)line);
	else
		gray_pam_log(LOG_CRIT, "WAITING FOR DEBUG");
	while (interval-- > 0)
		sleep(1);
#else
	gray_pam_log(LOG_NOTICE, "Debugging is not configured");
#endif	
}

int
gray_wait_debug_fun (struct pam_opt *opt, const char *value)
{
	char *s = "";
	long n = value ? strtol(value, &s, 0) : 0;
	if (*s) { 
		_pam_log(LOG_ERR,
			 "%s: %s is not a valid number",
			 opt->name, value);
		return 1;
	}
	gray_wait_debug(0, NULL, 0);
	return 0;
}




