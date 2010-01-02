/* This file is part of pam-modules.
   Copyright (C) 2009, 2010 Sergey Poznyakoff
  
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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "pamck.h"
#if HAVE_TERMIOS_H
# include <termios.h>
#endif

#ifndef TCSASOFT
# define TCSASOFT 0
#endif

#define DELTA 128

static char *
readline (FILE *in)
{
	char *buf;
	size_t bufsize = 128;
	size_t len = 0;
	int c;
	
	buf = malloc(bufsize);
	if (!buf)
		return buf;

	while ((c = fgetc(in)) != EOF) {
		if (len + 1 == bufsize) {
			char *p = realloc(buf, bufsize + DELTA);
			if (!p) {
				free(buf);
				return NULL;
			}
			bufsize += DELTA;
			buf = p;
		}
		if (c == '\n') {
			buf[len++] = 0;
			break;
		} else
			buf[len++] = c;
	}
	return buf;
}

static char *
read_string(const char *prompt, int echo)
{
	FILE *tty, *in, *out;
	struct termios s, t;
	int tty_changed = 0;
	char *str;
	
	tty = fopen ("/dev/tty", "w+");
	if (tty == NULL) {
		in = stdin;
		out = stderr;
	} else 
		out = in = tty;
	
#if HAVE_TCGETATTR
	if (!echo) {
		if (tcgetattr(fileno(in), &t) == 0) {
			/* Save the old one. */
			s = t;
			/* Tricky, tricky. */
			t.c_lflag &= ~(ECHO | ISIG);
			tty_changed = tcsetattr(fileno(in),
						TCSAFLUSH | TCSASOFT,
						&t) == 0;
		}
	}
#endif
	
	fputs(prompt, out);
	fflush(out);
	str = readline(in);
	if (!echo)
		fputc('\n', out);

	fseek(out, 0, SEEK_CUR);

#if HAVE_TCGETATTR
	if (tty_changed)
		tcsetattr(fileno(in), TCSAFLUSH | TCSASOFT, &s);
#endif
	if (tty != NULL)
		fclose(tty);
	return str;
}

int
pamck_conv(int num_msg, const struct pam_message **msg,
	   struct pam_response **resp, void *closure)
{
	int i;
	struct pam_response *reply;
	
	if (num_msg <= 0)
		return PAM_CONV_ERR;

	reply = calloc(num_msg, sizeof(struct pam_response));
	if (!reply)
		return PAM_CONV_ERR;
	for (i = 0; i < num_msg; i++) {
		char *str;
		
		switch (msg[i]->msg_style) {
		case PAM_PROMPT_ECHO_OFF:
			if (pass)
				str = strdup(pass);
			else 
				str = read_string(msg[i]->msg, 0);
			break;
			
		case PAM_PROMPT_ECHO_ON:
			if (user)
				str = strdup(user);
			else
				str = read_string(msg[i]->msg, 1);
			break;

		case PAM_ERROR_MSG:
			if (fprintf(stderr,"%s\n",msg[i]->msg) < 0) 
				break;
			continue;
			
		case PAM_TEXT_INFO:
			if (fprintf(stdout,"%s\n",msg[i]->msg) < 0) 
				break;
			continue;
			
		default:
			error(0, "erroneous conversation (%d)",
			      msg[i]->msg_style);
		}

		if (str) {
			reply[i].resp_retcode = 0;
			reply[i].resp = str;
		} else {
			free(reply);
			return PAM_CONV_ERR;
		}
	}

	*resp = reply;
	return PAM_SUCCESS;
}
			
			
			
