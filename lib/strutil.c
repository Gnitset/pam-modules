/* This file is part of pam-modules.
   Copyright (C) 2009-2012, 2014 Sergey Poznyakoff
 
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

/*
 * Chop off trailing whitespace. Return length of the resulting string
 */
int
gray_trim_ws(char *str)
{
	int len;

	for (len = strlen(str); len > 0 && isspace(str[len-1]); len--)
		;
	str[len] = 0;
	return len;
}

