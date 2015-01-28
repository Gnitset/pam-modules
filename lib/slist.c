/* This file is part of pam-modules.
   Copyright (C) 2008, 2010-2012, 2014-2015 Sergey Poznyakoff
 
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

#define GRAY_SLIST_BUCKET_SIZE 1024

struct gray_slist_bucket {
	struct gray_slist_bucket *next;
	char *buf;
	size_t level;
	size_t size;
};

struct gray_slist {
	struct gray_slist_bucket *head, *tail;
	struct gray_slist_bucket *free;
};

static struct gray_slist_bucket *
alloc_bucket(size_t size)
{
	struct gray_slist_bucket *p = gray_malloc(sizeof(*p) + size);
	p->buf = (char*)(p + 1);
	p->level = 0;
	p->size = size;
	p->next = NULL;
	return p;
}

static void
alloc_pool(gray_slist_t slist, size_t size)
{
	struct gray_slist_bucket *p = alloc_bucket(GRAY_SLIST_BUCKET_SIZE);
	if (slist->tail)
		slist->tail->next = p;
	else
		slist->head = p;
	slist->tail = p;
}

static size_t
copy_chars(gray_slist_t slist, const char *str, size_t n)
{
	size_t rest;


	if (!slist->head || slist->tail->level == slist->tail->size)
		alloc_pool(slist, GRAY_SLIST_BUCKET_SIZE);
	rest = slist->tail->size - slist->tail->level;
	if (n > rest)
		n = rest;
	memcpy(slist->tail->buf + slist->tail->level, str, n);
	slist->tail->level += n;
	return n;
}

gray_slist_t 
gray_slist_create()
{
	gray_slist_t slist = gray_malloc(sizeof(*slist));
	slist->head = slist->tail = slist->free = 0;
	return slist;
}

void
gray_slist_clear(gray_slist_t slist)
{
	if (slist->tail) {
		slist->tail->next = slist->free;
		slist->free = slist->head;
		slist->head = slist->tail = NULL;
	}
}	


void
gray_slist_free(gray_slist_t *slist)
{
	struct gray_slist_bucket *p;
	if (*slist) {
		gray_slist_clear(*slist);
		for (p = (*slist)->free; p; ) {
			struct gray_slist_bucket *next = p->next;
			free(p);
			p = next;
		}
	}
	free(*slist);
	*slist = NULL;
}

void
gray_slist_append(gray_slist_t slist, const char *str, size_t n)
{
	const char *ptr = str;
	while (n) {
		size_t s = copy_chars(slist, ptr, n);
		ptr += s;
		n -= s;
	}
}

void
gray_slist_append_char(gray_slist_t slist, char c)
{
	gray_slist_append(slist, &c, 1);
}	

size_t
gray_slist_size(gray_slist_t slist)
{
	size_t size = 0;
	struct gray_slist_bucket *p;
	for (p = slist->head; p; p = p->next)
		size += p->level;
	return size;
}

size_t
gray_slist_coalesce(gray_slist_t slist)
{
	size_t size;

	if (slist->head && slist->head->next == NULL)
		size = slist->head->level;
	else {
		size = gray_slist_size(slist);
		struct gray_slist_bucket *bucket = alloc_bucket(size);
		struct gray_slist_bucket *p;
	
		for (p = slist->head; p; ) {
			struct gray_slist_bucket *next = p->next;
			memcpy(bucket->buf + bucket->level, p->buf, p->level);
			bucket->level += p->level;
			free(p);
			p = next;
		}
		slist->head = slist->tail = bucket;
	}
	return size;
}

void *
gray_slist_head(gray_slist_t slist, size_t *psize)
{
	if (*psize) 
		*psize = slist->head ? slist->head->level : 0;
	return slist->head ? slist->head->buf : NULL;
}

void *
gray_slist_finish(gray_slist_t slist)
{
	gray_slist_coalesce(slist);
	gray_slist_clear(slist);
	return slist->free->buf;
}


#define to_num(c) \
  (isdigit(c) ? c - '0' : (isxdigit(c) ? toupper(c) - 'A' + 10 : 255 ))

void
gray_slist_grow_backslash_num(gray_slist_t slist, char *text, char **pend,
			      int len, int base)
{
	int i;
	int val = 0;
	char *start = text;
	
	if (text[0] == '\\') {
		text++;
		if (base == 16)
			text++;
	}
	
	for (i = 0; i < len; i++) {
		int n = (unsigned char)text[i];
		if (n > 127 || (n = to_num(n)) >= base)
			break;
		val = val*base + n;
	}
	
	if (i == 0) {
		gray_slist_append(slist, start, 1);
		if (pend)
			*pend = start + 1;
	} else {
		gray_slist_append_char(slist, val);
		if (pend)
			*pend = text + i;
	}
}

int
gray_decode_backslash(int c)
{
        static char transtab[] = "a\ab\bf\fn\nr\rt\t";
        char *p;

        for (p = transtab; *p; p += 2) {
                if (*p == c)
                        return p[1];
        }
        return c;
}

void
gray_slist_grow_backslash(gray_slist_t slist, char *text, char **endp)
{
	if (text[1] == '\\' || (unsigned char)text[1] > 127) {
		gray_slist_append_char(slist, text[1]);
		text += 2;
	} else if (isdigit(text[1])) 
		gray_slist_grow_backslash_num(slist, text, &text, 3, 8);
	else if (text[1] == 'x' || text[1] == 'X')
		gray_slist_grow_backslash_num(slist, text, &text, 2, 16);
	else {
		int c = gray_decode_backslash(text[1]);
		gray_slist_append_char(slist, c);
		text += 2;
	}
		
	*endp = text;
}

