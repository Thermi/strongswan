/*
 * Copyright (C) 2008-2014 Tobias Brunner
 * Copyright (C) 2005-2008 Martin Willi
 * HSR Hochschule fuer Technik Rapperswil
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include <utils/utils.h>
#include <utils/utils/memory.h>
/**
 * Described in header.
 */
char* translate(char *str, const char *from, const char *to)
{
	char *pos = str;
	if (strlen(from) != strlen(to))
	{
		return str;
	}
	while (pos && *pos)
	{
		char *match;
		if ((match = strchr(from, *pos)) != NULL)
		{
			*pos = to[match - from];
		}
		pos++;
	}
	return str;
}

/**
 * Described in header.
 */
char* strreplace(const char *str, const char *search, const char *replace)
{
	size_t len, slen, rlen, count = 0;
	char *res, *pos, *found = NULL, *dst;

	if (!str || !*str || !search || !*search || !replace)
	{
		return (char*)str;
	}
	slen = strlen(search);
	rlen = strlen(replace);
	if (slen != rlen)
	{
		for (pos = (char*)str; (pos = strstr(pos, search)); pos += slen)
		{
			found = pos;
			count++;
		}
		if (!count)
		{
			return (char*)str;
		}
		len = (found - str) + strlen(found) + count * (rlen - slen);
	}
	else
	{
		len = strlen(str);
	}
	found = strstr(str, search);
	if (!found)
	{
		return (char*)str;
	}
	dst = res = malloc(len + 1);
	pos = (char*)str;
	do
	{
		len = found - pos;
		memcpy(dst, pos, len);
		dst += len;
		memcpy(dst, replace, rlen);
		dst += rlen;
		pos = found + slen;
	}
	while ((found = strstr(pos, search)));
	strcpy(dst, pos);
	return res;
}

linked_list_t *strsplit(const char *str, const char *tokstr)
{
	linked_list_t *list = linked_list_create();
	size_t str_len = strlen(str);
	char *saveptr, *tok = NULL, *copy = alloca(str_len+1), *tok_cpy;
	memcpy(copy, str, str_len);
	tok = strtok_r(copy, tokstr, &saveptr);
	if (tok) {
	    	tok_cpy = malloc(strlen(tok)+1);
		memcpy(tok_cpy, tok, strlen(tok)+1);
		list->insert_last(list, tok_cpy);
		while (TRUE)
		{
			tok = strtok_r(NULL, tokstr, &saveptr);
			if (tok)
			{
				size_t substring_length = strlen(tok);
				char *substring_copy = malloc(substring_length+1);
				memcpy(substring_copy, tok,  substring_length+1);
				list->insert_last(list, substring_copy);
			} else {
				break;
			}
		}
	} 
	return list;
}
