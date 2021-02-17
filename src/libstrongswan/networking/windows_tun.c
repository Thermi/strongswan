/*
 * Copyright (C) 2020 Noel Kuntze <noel.kuntze@thermi.consulting>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <winsock2.h>
#include <windows.h>
#include <cfgmgr32.h>
#include <setupapi.h>
#include <devpkey.h>
#include <winreg.h>
#include <utils/windows_helper.h>
#include <ddk/ndisguid.h>

#include <string.h>

#include "../utils/utils/memory.h"
#include "../collections/linked_list.h"

#include "windows_tun.h"
#include "wintun_support.h"

/* Stub. */
struct private_openvpn_tun_device_t {
} typedef private_openvpn_tun_device_t;

 /*
 * Helper function to get the next HardwareID in the
 * SP_DRVINFO_DETAIL_DATA_A.HardwareID linear array.
 * (Looks like this: "abcdef\0ghijkl\0mnopqrs\0\0". Empty string (Just a NULL byte)
 * denotes the end of the array)
 *
 * @param pile			linear character array of the hardwareIDs as they are part of
 *						the SP_DRVINFO_DETAIL_DATA_A struct.
 * @param offset		pointer to a location in which the end position of the search algorithm is stored.
 *						It is used to keep the offset between multiple calls of the function and ease its use.
 *						The value is the position at which the resulting string ends (strlen() + 1, or its NULL byte)
 * @return				The next hardwareID or NULL, if the end of the array was reached.
 */
char *windows_drv_info_get_next_hardwareid(char *pile, size_t *offset)
{
	size_t len = 0, old_offset = 0;
	old_offset = *offset;
	len = strlen(pile + *offset);
	*offset += len + 1;
	if (len == 0)
	{
		/* End of the list, empty string. */
		return NULL;
	}
	return pile + old_offset;
}

/*
 * Wide string version of windows_drv_info_get_next_hardwareid 
 */
/*
wchar_t *windows_drv_info_get_next_hardwareid_wide(wchar_t *pile, size_t *offset)
{
	size_t len = 0, old_offset = 0;
	while(true)
	{
		old_offset = *offset;
		len = wcslen(pile + *offset);
		*offset += len + sizeof(wchar_t);
		if (len == 0)
		{
			End of the list, empty string. 
			return NULL;
		}
		return pile + old_offset;
	}
}
*/

/*
 * Helper function that wraps around windows_drv_info_get_next_hardwareid.
 * It returns true if needle is in the pile (pile is a linear, empty string terminated array of strings).
 * It returns false if needle is NOT in the pile.
 *
 * @param pile			A linear array of strings. Terminated by an empty string.
 * @param needle		A string to find in pile.
 *
 * @returns				Returns whether needle is in pile
 */
bool find_matching_hardwareid(char *pile, char* needle)
{
	size_t offset = 0;
	char *item;
	while(true)
	{
		item = windows_drv_info_get_next_hardwareid(pile, &offset);
		if (!item)
		{
			return false;
		}

		if(!strcmp(item, needle))
		{
			return true;
		}
	}
	return false;
}
/*
 * Wide version of find_matching_hardwareid
 */
/*
bool find_matching_hardwareid_wide(wchar_t *pile, wchar_t* needle)
{
	size_t offset = 0;
	wchar_t *item;
	while(true)
	{
		item = windows_drv_info_get_next_hardwareid_wide(pile, &offset);
		DBG0(DBG_LIB, "next hardwareID: %ls", item);
		if (!item)
		{
			return false;
		}

		if(wcscmp(item, needle) == 0)
		{
			return true;
		}
	}
}
*/

char *windows_setupapi_get_friendly_name(char *buffer, size_t buf_len, HDEVINFO dev_info_set, SP_DEVINFO_DATA *dev_info_data)
{
	memwipe(buffer, buf_len);
	size_t required_length;
        DWORD prop_type;
	char buf[512];
	if(!SetupDiGetDeviceRegistryPropertyA(
		dev_info_set, dev_info_data,
		SPDRP_FRIENDLYNAME,
		&prop_type,
		buffer,
		buf_len,
		(DWORD *)&required_length
		))
	{
		/* Try hardware path instead */
		if(SetupDiGetDeviceRegistryPropertyA(
			dev_info_set, dev_info_data,
			SPDRP_LOCATION_INFORMATION,
			&prop_type,
			buffer,
			buf_len,
			(DWORD *)&required_length))
		{
			if (strcmp(buffer, "\r\n") || strcmp(buffer, ""))
			{
			    ignore_result(snprintf(buffer, buf_len, "<unknown>"));
			}
			return buffer;
		} else {
			DBG1(DBG_LIB, "Failed to retrieve the hardware location of a device: %s", dlerror_mt(buf, sizeof(buf)));
		}
	}
	return buffer;
}
/*
bool windows_get_driver_info_data_a(
	HDEVINFO *dev_info_set,
	SP_DEVINFO_DATA *dev_info_data,
	SP_DRVINFO_DATA_A *drv_info_data,
	PSP_DRVINFO_DETAIL_DATA_A *drv_info_detail_data,
	DWORD *property_buffer_length,
	DWORD *required_length
)
{
    DWORD error, ret;
    char buf[512];
    while(TRUE)
    {
	if (!(ret=SetupDiGetDriverInfoDetailA(
	    *dev_info_set,
	    dev_info_data,
	    drv_info_data,
	    *drv_info_detail_data,
	    *property_buffer_length,
	    required_length
	)))
	{
		error = GetLastError();
		switch (error) {
			case 0:
				break;
			case ERROR_INVALID_USER_BUFFER:
				DBG1(DBG_LIB, "Error %d: Insufficient memory.", error);
				// allocate memory
				*drv_info_detail_data = realloc(
					*drv_info_detail_data,
					*required_length + sizeof(SP_DRVINFO_DETAIL_DATA_A));
				(*drv_info_detail_data)->cbSize = sizeof(SP_DRVINFO_DETAIL_DATA_A);
				*property_buffer_length = *required_length + sizeof(SP_DRVINFO_DETAIL_DATA_A);
				DBG0(DBG_LIB, "required_length: %u", *required_length);
				if (!SetupDiGetDriverInfoDetailA(
					*dev_info_set,
					dev_info_data,
					drv_info_data,
					*drv_info_detail_data,
					*property_buffer_length,
					required_length
				))
				{
					error = GetLastError();
					DBG1(DBG_LIB,
					    "Previous required length was bogus. New error is %d: %s",
					    error, dlerror_mt(buf, sizeof(buf)));
				}
				break;
			case ERROR_INSUFFICIENT_BUFFER:
				DBG1(DBG_LIB, "Invalid user buffer (for some reason) %d", error);
				return FALSE;
				break;
			default:
				DBG1(DBG_LIB, "A different error occured %d: %s",
				 error, dlerror_mt(buf, sizeof(buf)));
				return FALSE;
				break;
		}
	} else {
	    DBG1(DBG_LIB, "Received error: %s", dlerror_mt(buf, sizeof(buf)));
	}
    }
    return FALSE;
} */

bool check_hardwareids(SP_DRVINFO_DETAIL_DATA_A *drv_info_detail_data)
{
	/* Make sure CompatIDsOffset indicates more than one HardwareID is in it
	 * but also there actually is a hardware ID in the HardwareID field,
	 * instead of just a \r(\n) (Windows DOES do that!) */
	if (drv_info_detail_data->CompatIDsOffset > 1 &&
		drv_info_detail_data->HardwareID &&
		drv_info_detail_data->HardwareID[0] != '\r')
	{
		DBG2(DBG_LIB, "HardwareID: %%s",
			drv_info_detail_data->HardwareID);
		if (!strcmp(
			drv_info_detail_data->HardwareID,
			WINTUN_COMPONENT_ID)) {
			/* HardwareID matches */
		    DBG2(DBG_LIB, "HardwareID %s matches %s",
			    drv_info_detail_data->HardwareID,
			    WINTUN_COMPONENT_ID);
		    return TRUE;
		} else {
		    DBG2(DBG_LIB, "HardwareID does not match");
		    return FALSE;
		}
	}
	// Iterate over HardwareID array in drv_info_detail_data
	if(!(WINDOWS_IS_UNITIALIZED(drv_info_detail_data->CompatIDsOffset)) &&
		drv_info_detail_data->CompatIDsLength > 0)
	{	
	    DBG2(DBG_LIB, "HardwareID: %hs", drv_info_detail_data->HardwareID);
		/* compatIDs are in wide characters. Need to convert all fields into compatible */
		if(find_matching_hardwareid(
			drv_info_detail_data->HardwareID,
			(char *) WINTUN_COMPONENT_ID))
		{
		    return TRUE;		    
		} else {
		    DBG2(DBG_LIB, "ID %s is not in compatible hardware IDs", WINTUN_COMPONENT_ID);
		    return FALSE;
		}
	}
	return FALSE;
}

/* Described in header */
linked_list_t *string_array_to_linked_list(char *pile)
{
	linked_list_t *list = linked_list_create();
	size_t offset = 0;
	char *item;
	while(true)
	{
		item = windows_drv_info_get_next_hardwareid(pile, &offset);
		if (!item)
		{
			return list;
		}
		list->insert_last(list, item);
	}
	return list;
}

/* Stub */
tun_device_t *try_configure_openvpn(const char *name_tmpl)
{
	return NULL;
}
/*
 * Described in header
 */

tun_device_t *tun_device_create(const char *name_tmpl)
{
        tun_device_t *public = NULL;
#ifdef USE_WINTUN
	public = try_configure_wintun(name_tmpl);
	/* if (!public)
	{
		public = try_configure_openvpn(name_tmpl);
	} */
	if(!public)
	{
		DBG0(DBG_LIB, "failed to create TUN device.");
		return NULL;
	}
	DBG0(DBG_LIB, "created TUN device: %s", public->get_name(public));
#else
	DBG1(DBG_LIB, "TUN devices are not supported");
#endif
	return public;
}
