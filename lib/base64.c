/* This file is part of pam-modules.
   Copyright (C) 2008, 2010 Sergey Poznyakoff
 
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

static int
b64_input(char c)
{
	const char table[64] =
	   "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	int i;

	for (i = 0; i < 64; i++) {
		if (table[i] == c)
			return i;
	}
	return -1;
}

ssize_t
gray_base64_decode(gray_slist_t slist, const char *iptr, size_t isize)
{
	int i = 0, pad = 0;
	size_t consumed = 0;
	ssize_t nbytes;
	unsigned char data[4];

	nbytes = 0;
	while (consumed < isize) {
		while (i < 4 && consumed < isize) {
			int tmp = b64_input(*iptr++);
			consumed++;
			if (tmp != -1)
				data[i++] = tmp;
			else if (iptr[-1] == '=') {
				data[i++] = '\0';
				pad++;
			}
		}

		/* I have a entire block of data 32 bits get the output
		   data.  */
		if (i == 4) {
			gray_slist_append_char(slist,
			     (data[0] << 2) | ((data[1] & 0x30) >> 4));
			gray_slist_append_char(slist,
			     ((data[1] & 0xf) << 4) | ((data[2] & 0x3c) >> 2));
			gray_slist_append_char(slist,
			     ((data[2] & 0x3) << 6) | data[3]);
			nbytes += 3 - pad;
		} else 
			return -1;
		i = 0;
	}
	return nbytes;
}
