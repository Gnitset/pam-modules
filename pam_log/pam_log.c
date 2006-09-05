/* This file is part of pam-modules.
   Copyright (C) 2006 Sergey Poznyakoff
 
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
 
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
 
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
   MA 02110-1301 USA  */

#if defined(HAVE_CONFIG_H)
# include <config.h>
#endif
#ifdef HAVE__PAM_ACONF_H
#include <security/_pam_aconf.h>
#endif

#include <stdio.h>
#include <unistd.h>
#include <syslog.h>
#include <stdarg.h>

#define PAM_SM_AUTH
#define PAM_SM_PASSWORD
#include <security/pam_modules.h>

PAM_EXTERN
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
			const char **argv)
{
    return PAM_IGNORE;
}

PAM_EXTERN
int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_IGNORE;
}

PAM_EXTERN
int pam_sm_chauthtok(pam_handle_t *pamh,int flags,int argc,const char **argv)
{
    return PAM_IGNORE;
}

PAM_EXTERN int
pam_sm_acct_mgmt (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_IGNORE;
}

PAM_EXTERN int
pam_sm_open_session (pam_handle_t *pamh, int flags, int argc,
                     const char **argv)
{
    return PAM_IGNORE;
}

PAM_EXTERN int
pam_sm_close_session (pam_handle_t *pamh, int flags, int argc,
		      const char **argv)
{
    return PAM_IGNORE;
}

#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_warn_modstruct = {
    "pam_log",
    pam_sm_authenticate,
    pam_sm_setcred,
    pam_sm_acct_mgmt,
    pam_sm_open_session,
    pam_sm_close_session,
    pam_sm_chauthtok,
};

#endif

/* end of module definition */
