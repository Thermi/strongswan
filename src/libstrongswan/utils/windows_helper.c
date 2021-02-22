/*
 * Copyright (C) 2020 Noel Kuntze
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

#include "windows_helper.h"

/**
 * See header
 */
bool guid2string(char *dst, size_t dst_len, const GUID *guid, bool braces)
{
	size_t ret = 0;
	char *with_braces = "{%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}",
		*without_braces = "%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x";
	if (braces)
	{
	    if (dst_len >= 39 )
	    {
		ret = snprintf(dst, dst_len,
			with_braces,
			guid->Data1, guid->Data2, guid->Data3,
			guid->Data4[0], guid->Data4[1], guid->Data4[2], guid->Data4[3],
			guid->Data4[4], guid->Data4[5], guid->Data4[6], guid->Data4[7]);
	    } else {
		DBG0(DBG_LIB, "Buffer too small!");
	    }
	} else {
	    if (dst_len >= 37)
	    {
		ret = snprintf(dst, dst_len,
		    without_braces,
		    guid->Data1, guid->Data2, guid->Data3,
		    guid->Data4[0], guid->Data4[1], guid->Data4[2], guid->Data4[3],
		    guid->Data4[4], guid->Data4[5], guid->Data4[6], guid->Data4[7]);
	    } else {
		DBG0(DBG_LIB, "Buffer too small!");
	    }
	}
	return ret >= 36 ? TRUE : FALSE;
}

bool guidfromstring(GUID *guid, const char *str, bool with_braces)
{
    char *format = with_braces ?
                        "{%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX}%n" :
                        "%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%n";
    size_t nchars = 0, nfields = sscanf_s(str, format,
                        &guid->Data1, &guid->Data2, &guid->Data3,
			&guid->Data4[0], &guid->Data4[1], &guid->Data4[2], &guid->Data4[3],
			&guid->Data4[4], &guid->Data4[5], &guid->Data4[6], &guid->Data4[7],
                        &nchars);
    DBG0(DBG_LIB, "Nfields: %d, nchars: %d", nfields, nchars);
    DBG0(DBG_LIB, "nfields == 11: %d", nfields == 11);
    DBG0(DBG_LIB, "nchars == 38: %d", nchars == 38);
    if (nfields == 11 && ((with_braces && nchars == 38) || (!with_braces && nchars == 36))) {
        DBG0(DBG_LIB, "Returning True");
        return TRUE;
    }
    DBG0(DBG_LIB, "Returning False");
    return FALSE;
}
/**
 * see header
 */
bool registry_wait_get_value(HKEY key, void *caller_buf, DWORD *caller_buf_len,
	char *reg_val_name, DWORD *reg_val_type, size_t timeout)
{
	/* timeout is in ms */
	timeval_t now, deadline;
	DWORD own_ret = FALSE, function_ret_query, function_ret_wait;
	char buf[512];
	HANDLE handle = CreateEventA(
		NULL,
		FALSE,
		FALSE,
		NULL
		);
	if (!handle)
	{
		char buf[512];
		dlerror_mt(buf, sizeof(buf));
		DBG1(DBG_LIB, "Failed to create handle: %s", buf);
		return FALSE;
	}
	/* Get current time, add timeout */
	time_monotonic(&deadline);
	timeval_add_ms(&deadline, timeout);

	while(TRUE)
	{
		/* Try to get value */
		function_ret_query = RegQueryValueExA(key, reg_val_name, NULL, reg_val_type, caller_buf, (LPDWORD) caller_buf_len);
		time_monotonic(&now);
		int64_t ms_to_deadline = (deadline.tv_sec - now.tv_sec) * 1000 + (deadline.tv_usec - now.tv_usec);
		switch(function_ret_query)
		{
			case ERROR_FILE_NOT_FOUND:
			case ERROR_PATH_NOT_FOUND:
				/* All vars in this calculation are signed, so no issues
				 * until the first part overflows (certainly farther in the future than this code will run)
				 */
				if (ms_to_deadline <= 0)
				{
					DBG1(DBG_LIB, "Timed out waiting for registry value %s", reg_val_name);
					goto out;
					break;
				}
				/* Set up handle for notify */
				if (RegNotifyChangeKeyValue(key, FALSE, REG_NOTIFY_CHANGE_LAST_SET, handle, true) != ERROR_SUCCESS)
				{
					dlerror_mt(buf, sizeof(buf));
					DBG1(DBG_LIB, "Failed to call RegNotifyChangeKeyValue: %s", buf);
					goto out;
					break;
				}
				function_ret_wait = WaitForSingleObjectEx(handle, ms_to_deadline, FALSE);
				if(function_ret_wait && function_ret_wait != WAIT_OBJECT_0 )
				{
					dlerror_mt(buf, sizeof(buf));
					DBG1(DBG_LIB, "Failed to wait for event (WaitForSingleObjectEx(): %ld): %s", function_ret_wait, buf);
					goto out;
					break;
				}
				break;
			case ERROR_MORE_DATA:
				caller_buf = realloc(caller_buf, *caller_buf_len);
				break;
			case ERROR_SUCCESS:
			case TRUE:
				/* succeeded */
				own_ret = TRUE;
				goto out;
				break;
			case ERROR_INVALID_HANDLE:
			        DBG1(DBG_LIB, "Invalid handle. Failed to read string.");
				goto out;
				break;
			default:
				dlerror_mt(buf, sizeof(buf));
				DBG1(DBG_LIB, "Failed to read registry value (RegQueryValueExA): %s", buf);
				goto out;
				break;
		}
	}
	out:
	CloseHandle(handle);
	return own_ret;
}

/**
 * Described in header.
 */
char *windows_expand_string(char *buf, DWORD *buf_len, size_t *new_buf_len)
{
	size_t new_length = *buf_len, required_size;
	char *intermediate_buf = NULL;

	for(size_t i=0;i<=2;i++)
	{
		intermediate_buf = realloc(intermediate_buf, new_length);
		required_size = ExpandEnvironmentStringsA(buf, intermediate_buf, new_length);
		if (required_size > new_length)
		{
			new_length = required_size;
		} else {
			break;
		}
	}
	*new_buf_len = new_length;
	return intermediate_buf;
}

/**
 * Described in header.
 */
HKEY registry_open_wait(HKEY key, char *path, DWORD access, size_t timeout)
{
	/* timeout is in ms */
	HKEY intermediate = NULL;
	size_t path_len = strlen(path) + 1, ret;
	char buf[512], *str = path, *tok, *current_path = alloca(path_len),
		*current_path_cpy = alloca(path_len), *last_part;
	bool first = TRUE;
	timeval_t now, deadline;
	DWORD function_ret_wait;
	/* Number of iterations */

	// linked_list_t *tokens = strsplit_race(path, "\\");
	linked_list_t *tokens = strsplit(path, "\\,");
	tokens->get_last(tokens, (void **) &last_part);
	enumerator_t *enumerator = tokens->create_enumerator(tokens);
	HANDLE handle = CreateEventA(
		NULL,
		FALSE,
		FALSE,
		NULL
	);

	if (!handle)
	{
		char buf[512];
		dlerror_mt(buf, sizeof(buf));
		DBG1(DBG_LIB, "Failed to create handle: %s", buf);
		return FALSE;
	}

	/* Get current time, add timeout */
	time_monotonic(&deadline);
	timeval_add_ms(&deadline, timeout);


	/* In the loop, we check if each key occuring in the path is accessible.
	 * If a key is not, it will be created by the installation routine
	 * that was called before this function.
	 * This means that we instead wait for an event in the registry in
	 * which the key was created.
	 */
	while (enumerator->enumerate(enumerator, &tok))
	{
		if (tok)
		{
			if (first)
			{
			    memcpy(current_path, tok, strlen(tok)+1);
			    first = FALSE;
			} else {
			    memcpy(current_path_cpy, current_path, path_len);
			    snprintf(current_path, path_len, "%s\\%s", current_path_cpy, tok);
			}
			/* Add the new token to the path*/
			/* Check if the current path is accessible */
			if (last_part == tok)
			{
				access = KEY_NOTIFY;
			}

			switch((ret=RegOpenKeyA(key, current_path, &intermediate)))
			{
				case true:
				case ERROR_SUCCESS:
				    break;
				case ERROR_FILE_NOT_FOUND:
				case ERROR_PATH_NOT_FOUND:
					time_monotonic(&now);
					/* All vars in this calculation are signed, so no issues
					 * until the first part overflows (certainly farther in the future than this code will run)
					 */
					int64_t ms_to_deadline = (deadline.tv_sec - now.tv_sec) * 1000 + (deadline.tv_usec - now.tv_usec);
					if (ms_to_deadline <= 0)
					{
						DBG1(DBG_LIB, "Timed out waiting for registry value %s", current_path);
						break;
						break;
					}
					/* Setup notifier */
					if ((function_ret_wait=RegNotifyChangeKeyValue(key, FALSE, REG_NOTIFY_CHANGE_NAME, handle, true)))
					{
						DBG1(DBG_LIB, "Failed to setup notify handle for REG_NOTIFY_CHANGE_NAME on %s using RegNotifyChangeKeyValue: %s", current_path, human_readable_error(buf, function_ret_wait, sizeof(buf)));
						goto cleanup;
					}
					/* Check if we can access the key */
					switch((ret=RegOpenKeyExA(key, current_path, 0, access, &intermediate)))
					{
						case true:
						case ERROR_SUCCESS:
							/* Close the notifier handle again and open a new one, just in case the kernel handles reusing of active handles badly.*/
							CloseHandle(handle);
							handle = CreateEventA(
								NULL,
								FALSE,
								FALSE,
								NULL
							);

							if (!handle)
							{
								dlerror_mt(buf, sizeof(buf));
								DBG1(DBG_LIB, "Failed to create handle: %s", buf);
							}
							break;
						case ERROR_FILE_NOT_FOUND:
						case ERROR_PATH_NOT_FOUND:
							time_monotonic(&now);
							/* All vars in this calculation are signed, so no issues
							 * until the first part overflows (certainly farther in the future than this code will run)
							 */
							int64_t ms_to_deadline = (deadline.tv_sec - now.tv_sec) * 1000 + (deadline.tv_usec - now.tv_usec);
							if (ms_to_deadline <= 0)
							{
								DBG1(DBG_LIB, "Timed out waiting for registry value %s", current_path);
								goto cleanup;
							}
							function_ret_wait = WaitForSingleObjectEx(handle, ms_to_deadline, FALSE);
							switch(function_ret_wait)
							{
								case WAIT_OBJECT_0:
									break;
								case WAIT_TIMEOUT:
									DBG1(DBG_LIB, "Failed to wait for event (WaitForSingleObjectEx() for path %s: %ld): The time limit (timeout) was reached", current_path, function_ret_wait);
									break;
								case WAIT_FAILED:
									DBG1(DBG_LIB, "Failed to wait for event (WaitForSingleObjectEx() for path %s: %ld): %s", function_ret_wait, current_path, dlerror_mt(buf, sizeof(buf)));
									break;
							}
							if(function_ret_wait != WAIT_OBJECT_0)
							{
								goto cleanup;
							}
							break;
						default:
							dlerror_mt(buf, sizeof(buf));
							DBG1(DBG_LIB, "Failed to open registry value (RegOpenKeyEx): (decimal %u) %s", ret, buf);
							goto cleanup;
							break;
					}
					break;
				default:
					dlerror_mt(buf, sizeof(buf));
					DBG1(DBG_LIB, "Failed to open registry key %s (RegOpenKeyA): (decimal %u) %s", current_path, ret, buf);
					goto cleanup;
					break;
			}
		}
	}

cleanup: ;
	tokens->reset_enumerator(tokens, enumerator);
	while(enumerator->enumerate(enumerator, &str))
	{
	    free(str);
	}
	enumerator->destroy(enumerator);
	tokens->destroy(tokens);
	CloseHandle(handle);
	return intermediate;
}

bool check_reboot(HDEVINFO dev_info_set, SP_DEVINFO_DATA *dev_info_data)
{
	SP_DEVINSTALL_PARAMS dev_install_params = {
		.cbSize = sizeof(SP_DEVINSTALL_PARAMS)
	};
	bool ret = SetupDiGetDeviceInstallParamsA(dev_info_set, dev_info_data, &dev_install_params);
	return dev_install_params.Flags & (DI_NEEDREBOOT | DI_NEEDRESTART) & ret;
}

/**
 * If dst_len is 0, the buffer is allocated on the heap using malloc()
 * @param dst
 * @param dst_len
 * @param str
 * @param str_len
 * @return
 */
int ascii2utf16(LPWSTR *dst, size_t dst_len, const char *str, const size_t str_len)
{
    int ret = dst_len;
    for(int i=0;i<2;i++)
    {
	ret = MultiByteToWideChar(
		CP_ACP,
		0,
		str,
		str_len,
		*dst,
		ret
		);
	if(!ret)
	{
	    char buf[512];
	    DBG1(DBG_LIB, "Failed to convert string (ascii2utf) with dst %p, dst_len %u, str %p and str_Len %u: %u",
		    dst, dst_len, str, str_len, dlerror_mt(buf, sizeof(buf)));
	    return 0;
	}
	*dst = malloc(ret*sizeof(WCHAR));
	if(!(*dst))
	{
	    DBG1(DBG_LIB, "Failed to convert string (ascii2utf) with dst %p, dst_len %u, str %p and str_Len %u because the required memory of %u byte could not be allocated.",
		    dst, dst_len, str, str_len, ret);
	    return 0;
	}
    }
    return ret;
}
/**
 * See header.
 */
bool handle_is_valid(HKEY handle)
{
    return (handle != NULL && (long long) handle > 1);
}
