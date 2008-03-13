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

int
gray_converse(pam_handle_t *pamh,
	      int nargs,
	      struct pam_message **message,
	      struct pam_response **response)
{
	int retval;
	struct pam_conv *conv;

	retval = pam_get_item(pamh, PAM_CONV, (const void **) &conv);
	if (retval == PAM_SUCCESS) {

		retval = conv->conv(nargs,
				    (const struct pam_message **) message,
				    response,
				    conv->appdata_ptr);
		
		if (retval != PAM_SUCCESS) {
			_pam_log(LOG_ERR,
				 "conversation failure [%s]",
				 pam_strerror(pamh, retval));
		}
	} else if (retval != PAM_CONV_AGAIN) {
		_pam_log(LOG_ERR, 
		         "couldn't obtain coversation function: %s",
			 pam_strerror(pamh, retval));
	}

	return retval;		/* propagate error status */
}

