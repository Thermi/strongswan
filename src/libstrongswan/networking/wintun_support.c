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

#include "wintun_support.h"

typedef struct private_windows_wintun_device_t private_windows_wintun_device_t;

struct private_windows_wintun_device_t {

	/**
	 * Public interface
	 */
	tun_device_t public;

        /**
         * The TUN device's HANDLE
         */
        HANDLE tun_handle;

        /**
         * The TUN device's rings
         */
        TUN_REGISTER_RINGS *rings;

	/**
	 * Name of the TUN device
	 */
	char if_name[IFNAMSIZ];
	
	/**
	 * Index of the interface
	 */
	uint32_t ifindex;

	/**
	 * The current MTU
	 */
	int mtu;

	/**
	 * Associated address
	 */
	host_t *address;

	/**
	 * Netmask for address
	 */
	uint8_t netmask;
};

static inline bool ring_over_capacity(TUN_RING *ring)
{
    return ((ring->Head >= TUN_RING_CAPACITY) || (ring->Tail >= TUN_RING_CAPACITY));
}

/* This is likely broken (!!!) */
static bool write_to_ring(TUN_RING *ring, chunk_t packet)
{
        /* Check if packet fits */
    TUN_PACKET *tun_packet;
    /* TODO: if ring is full or over capacity, wait until wintun driver sends event */
    if (ring_over_capacity(ring))
    {
        DBG1(DBG_LIB, "RING is over capacity!");
    }
    uint64_t aligned_packet_size = TUN_PACKET_ALIGN(packet.len);
    uint64_t buffer_space = TUN_WRAP_POSITION(((ring->Head - ring->Tail) - TUN_PACKET_ALIGNMENT), TUN_RING_CAPACITY);
    if (aligned_packet_size > buffer_space)
    {
        DBG1(DBG_LIB, "RING is full!");
    }
    
    /* copy packet size and data into ring */
    tun_packet = (TUN_PACKET *)&(ring->Data[ring->Tail]);
    tun_packet->Size = packet.len;
    memcpy(tun_packet->Data, packet.ptr, packet.len);
    
    /* move ring tail */
    ring->Tail = TUN_WRAP_POSITION((ring->Tail + aligned_packet_size), TUN_RING_CAPACITY);
    return TRUE;
}

static chunk_t *pop_from_ring(TUN_RING *ring, bool *need_restart)
{
        uint32_t length;
        size_t aligned_packet_size;
        /* TODO: If ring is over capacity wait until event is sent */
        chunk_t *chunk_packet;
        TUN_PACKET *packet;
        /* Ring is empty if head == tail */
        if (ring->Head == ring->Tail)
        {
            return NULL;
        }
        if (ring_over_capacity(ring))
        {
            DBG0(DBG_LIB, "RING is over capacity!");
        }
        length = TUN_WRAP_POSITION((ring->Tail - ring->Head),
            TUN_RING_SIZE(ring, TUN_RING_CAPACITY));
            
        if (length <sizeof(uint32_t))
        {
            DBG0(DBG_LIB, "RING contains incomplete packet header!");
            *need_restart = TRUE;
	    return NULL;

        }
        packet = (TUN_PACKET *)&(ring->Data[ring->Head]);
        if (packet->Size > TUN_MAX_IP_PACKET_SIZE)
        {
            DBG0(DBG_LIB, "RING contains packet larger than TUN_MAX_IP_PACKET_SIZE!");
	    *need_restart = TRUE;
	    return NULL;
        }

        aligned_packet_size = TUN_PACKET_ALIGN(sizeof(uint32_t) + packet->Size);
        if (aligned_packet_size > length)
        {
            DBG0(DBG_LIB, "Incomplete packet in ring!");
	    *need_restart = TRUE;
	    return NULL;
        }

        chunk_packet = malloc(sizeof(chunk_t));
        chunk_packet->ptr = malloc(packet->Size);
        chunk_packet->len = packet->Size;
        memcpy(chunk_packet->ptr, packet->Data, chunk_packet->len);
        /* Do we need to memset here? */
        memwipe(packet->Data, packet->Size);
        /* move ring head */
        ring->Head = TUN_WRAP_POSITION(ring->Head, aligned_packet_size);
        return chunk_packet;
}

/* Restart the driver.
 * FIXME: Need to somehow update all the device handles in use everywhere */
void restart_driver(private_windows_wintun_device_t *this)
{
	
}

METHOD(tun_device_t, wintun_set_mtu, bool,
	private_windows_wintun_device_t *this, int mtu)
{
	return TRUE;
}

METHOD(tun_device_t, wintun_get_mtu, int,
	private_windows_wintun_device_t *this)
{
        return TUN_MAX_IP_PACKET_SIZE;
}

/* On WIN32 we return the handle of the read ring (kernel space -> user space) */
METHOD(tun_device_t, wintun_get_handle, HANDLE,
        private_windows_wintun_device_t *this)
{
        return this->rings->Send.TailMoved;
}

METHOD(tun_device_t, wintun_write_packet, bool,
        private_windows_wintun_device_t *this, chunk_t packet)
{
        write_to_ring(this->rings->Receive.Ring, packet);
        if (this->rings->Receive.Ring->Alertable)
        {
            SetEvent(this->rings->Receive.TailMoved);
        }
        return TRUE;
}

METHOD(tun_device_t, wintun_read_packet, bool, 
        private_windows_wintun_device_t *this, chunk_t *packet)
{
	bool need_restart = FALSE;
        chunk_t *next = pop_from_ring(this->rings->Send.Ring, &need_restart);
	if (need_restart) {
		restart_driver(this);
		return FALSE;
	}
        if (!next)
        {
                this->rings->Send.Ring->Alertable = TRUE;
                next = pop_from_ring(this->rings->Send.Ring, &need_restart);
		if (need_restart) {
			restart_driver(this);
			return FALSE;
		}
                if (!next)
                {
                    WaitForSingleObject(this->rings->Send.TailMoved, INFINITE);
                    this->rings->Send.Ring->Alertable = FALSE;
                }
                this->rings->Send.Ring->Alertable = FALSE,
                ResetEvent(this->rings->Send.TailMoved);
        }
        *packet = *next;
        return TRUE;
}

/* Bogus implementation because nobody should use this */
METHOD(tun_device_t, wintun_get_name, char*,
        private_windows_wintun_device_t *this)
{
	/* Use Windows IP helper functions. */
        return this->if_name;
}

/* Bogus implementation because nobody should use this */
METHOD(tun_device_t, wintun_set_address, bool,
        private_windows_wintun_device_t *this,  host_t *addr, uint8_t netmask)
{
	/* Use Windows IP helper functions. */
        return TRUE;
}

/* Bogus implementation because nobody should use this */
METHOD(tun_device_t, wintun_get_address, host_t*,
        private_windows_wintun_device_t *this, uint8_t *netmask)
{
    /* Use Windows IP helper functions. */
    return NULL;
}

METHOD(tun_device_t, wintun_up, bool,
        private_windows_wintun_device_t *this)
{
    /* Use Windows IP helper functions. The right struct is here: https://docs.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_if_row2 */
    return TRUE;
}

/**
 * Destroy the tun device
 */
METHOD(tun_device_t, wintun_destroy, void,
	private_windows_wintun_device_t *this)
{
}

/**
 * Create the tun device and configure it as stored in the registry.
 * @param guid			GUID    GUID that the new interface should use.
 *					Can be NULL to make the system choose one at random.
 * @return bool			Whether creating failed or succeeded.
 */
bool create_wintun(char *guid)
{
	/* Reimplementation of CreateInterface from wireguard */
	char className[MAX_CLASS_NAME_LEN], buf[512],
		*property_buffer = NULL, NetCfgInstanceId[512], NetLuidIndex[512],
		IfType[512], adapter_reg_key[512], ipconfig_value[512],
		ipconfig_reg_key[512], *new_buf = NULL;
	uint64_t index = 0;
	DWORD property_buffer_length = 0, required_length = 0,
		reg_value_type, error,
		NetCfgInstanceId_length = sizeof(NetCfgInstanceId),
		NetLuidIndex_length = sizeof(NetLuidIndex),
		IfType_length = sizeof(IfType),
		ipconfig_value_length = sizeof(ipconfig_value),
		drv_info_detail_data_size = 0, ret;
	FILETIME driver_date = {
	    .dwHighDateTime = 0,
	    .dwLowDateTime = 0
	};
	memset(NetCfgInstanceId, 0, sizeof(NetCfgInstanceId));
	DWORDLONG driver_version = 0;
	bool return_code = FALSE;
	HKEY drv_reg_key = NULL, ipconfig_reg_hkey = NULL, adapter_reg_hkey = NULL;
	/* Timeout of 5000 ms for registry operations */
	size_t registry_timeout = 5000, buffer_length;
	/* Create an empty device info set for network adapter device class. */
	SP_DEVINFO_DATA dev_info_data = {
		.cbSize = sizeof(SP_DEVINFO_DATA)
	};
	SP_DRVINFO_DATA_A drv_info_data = {
		.cbSize = sizeof(SP_DRVINFO_DATA_A)
	};
	SP_DEVINSTALL_PARAMS_A dev_install_params = {
		.cbSize = sizeof(SP_DEVINSTALL_PARAMS_A)
	};
	SP_DRVINFO_DETAIL_DATA_A *drv_info_detail_data = malloc(sizeof(SP_DRVINFO_DETAIL_DATA_A));
	memset(drv_info_detail_data, 0, sizeof(SP_DRVINFO_DETAIL_DATA_A));
	drv_info_detail_data->cbSize = sizeof(SP_DRVINFO_DETAIL_DATA_A);
	
	/* is this optimizable? */
	HDEVINFO dev_info_set = SetupDiCreateDeviceInfoListExA(
		&GUID_DEVCLASS_NET,
		NULL,
		NULL,
		NULL
        );
        /* wait 50 ms */
        struct timespec ts = {
            .tv_sec = 0,
            .tv_nsec = 50000000,
        };
	
	if (!dev_info_set)
	{
		DBG1(DBG_LIB,
			"Failed to create DeviceInfoList(SetupDiCreateDeviceInfoListExA): %s",
				dlerror_mt(buf, sizeof(buf)));
		goto delete_device_info_list;
	}

	if(!SetupDiClassNameFromGuidExA(
		&GUID_DEVCLASS_NET,
		className,
		sizeof(className),
		&required_length,
		NULL,
		NULL
	))
	{
		DBG1(DBG_LIB, "Failed to translate GUID to class name (SetupDiClassNameFromGuidExA): %s",
			dlerror_mt(buf, sizeof(buf)));
		goto delete_device_info_list;
	}

	if (required_length > property_buffer_length)
	{
		property_buffer = calloc(required_length, 1);
		property_buffer_length = required_length;
		if (!SetupDiClassNameFromGuidExA(
			&GUID_DEVCLASS_NET,
			property_buffer,
			property_buffer_length,
			&required_length,
			NULL,
			NULL
		))
		{
			DBG1(DBG_LIB, "Failed to translate GUID to class name (SetupDiClassNameFromGuidExA): %s",
				dlerror_mt(buf, sizeof(buf)));
			goto delete_device_info_list;
		}
	}
	DBG0(DBG_LIB, "Got class name %s", property_buffer);
	/* property_buffer now holds class name */
	if (!SetupDiCreateDeviceInfo(
		dev_info_set,
		property_buffer,
		&GUID_DEVCLASS_NET,
		STRONGSWAN_WINTUN_INTERFACE_NAME,
		NULL,
		DICD_GENERATE_ID,
		&dev_info_data))
	{
		DBG1(DBG_LIB, "Failed to get wintun interfaces.");
		goto delete_device_info_list;
	}


	// create device
	// Set quiet install setQuietInstall
	if(!SetupDiGetDeviceInstallParamsA(dev_info_set,&dev_info_data, &dev_install_params))
	{
		DBG1(DBG_LIB, "Failed to create wintun interface at (SetupDiGetDeviceInstallParamsA): %s", dlerror_mt(buf, sizeof(buf)));
		goto delete_driver_info_list;
	}

	dev_install_params.Flags |= DI_QUIETINSTALL;

	if(!SetupDiSetDeviceInstallParamsA(dev_info_set, &dev_info_data, &dev_install_params))
	{
		DBG1(DBG_LIB, "Failed to set device install parameter (SetupDiSetDeviceInstallParamsA).");
		goto delete_device_info_list;
	}

	// Set a device information element as the selected member of a device information set. SetupDiSetSelectedDevice
	if(!SetupDiSetSelectedDevice(dev_info_set, &dev_info_data))
	{
		DBG1(DBG_LIB, "Failed to select device (SetupDiSetSelectedDevice).");
		goto delete_device_info_list;
	}

	// Set Plug&Play device hardware ID property. SetupDiSetDeviceRegistryProperty

	if(!SetupDiSetDeviceRegistryPropertyA(
		dev_info_set,
		&dev_info_data,
		SPDRP_HARDWAREID,
		WINTUN_COMPONENT_ID,
		sizeof(WINTUN_COMPONENT_ID)))
	{
		DBG1(DBG_LIB, "Failed to set Plug&Play device hardware ID property.");
		goto delete_device_info_list;
	}

	if(!SetupDiBuildDriverInfoList(dev_info_set, &dev_info_data, SPDIT_COMPATDRIVER))
	{
		DBG1(DBG_LIB, "Failed to build driver info list (SetupDiBuildDriverInfoList).");
		goto delete_device_info_list;
	}
	// Following this, DestroyDriverInfoList has to be called, too

	// loop over members of dev_info_data using EnumDriverInfo and index
	// loop over devices, search for newest driver version

	for(index=0;;index++)
	{
		if(!SetupDiEnumDriverInfo(
			dev_info_set,
			&dev_info_data,
			SPDIT_COMPATDRIVER,
			index,
			&drv_info_data))
		{
			error = GetLastError();
			if (error == ERROR_NO_MORE_ITEMS)
			{
				// break and go on
				break;
			}
			// Skip broken driver records
			continue;
		}
		DBG1(DBG_LIB, "driver description: %s", drv_info_data.Description);
		DBG1(DBG_LIB, "driver MfgName: %s", drv_info_data.MfgName);
		DBG1(DBG_LIB, "driver provider name: %s", drv_info_data.ProviderName);
		if(CompareFileTime(&drv_info_data.DriverDate, &driver_date) == 1)
		{
		    /* Check if the device is compatible by checking the hardware IDs */
		    required_length = 0;
		    if(windows_get_driver_info_data_a(
			dev_info_set,
			&dev_info_data,
			&drv_info_data,
			&drv_info_detail_data,
			&drv_info_detail_data_size,
			&required_length
			))
		    {
			if(check_hardwareids(drv_info_detail_data) ||
				strcaseeq(drv_info_data.Description, "Wintun Userspace Tunnel")) {
			    if(SetupDiSetSelectedDriverA(dev_info_set, &dev_info_data, &drv_info_data))
			    {
				DBG1(DBG_LIB, "Successfully Set driver of device %s for new wintun device",
				    windows_setupapi_get_friendly_name(
				    buf,
				    sizeof(buf),
				    dev_info_set,
				    &dev_info_data)
				);
				driver_version = drv_info_data.DriverVersion;
				driver_date = drv_info_data.DriverDate;				
			    } else {
				DBG1(DBG_LIB,
				    "Failed to set driver of device %s for new wintun device: %s",
				    windows_setupapi_get_friendly_name(
				    buf,
				    sizeof(buf),
				    dev_info_set,
				    &dev_info_data),
				    dlerror_mt(
				    buf,
				    sizeof(buf))
				);
				continue;
			    }
			} else {
			    DBG1(DBG_LIB, "No HardwareID match found");
			}
		    } else {
			DBG1(DBG_LIB, "Failed to get driver info data");
		    }
		}
	}
        if(driver_version == 0)
        {
                DBG1(DBG_LIB, "No driver installed for device: %s", dlerror_mt(buf, sizeof(buf)));
                goto delete_driver_info_list;
        }

        /* Call appropriate class installer */
        if (!SetupDiCallClassInstaller(
                DIF_REGISTERDEVICE,
                dev_info_set,
                &dev_info_data
        ))
        {
                DBG1(DBG_LIB, "SetupDiCallClassInstaller(DIF_REGISTERDEVICE) failed: %s", dlerror_mt(buf, sizeof(buf)));
                goto uninstall_device;
        }
	
	if(SetupDiCallClassInstaller(
		DIF_REGISTER_COINSTALLERS,
		dev_info_set,
		&dev_info_data
	))
	{
	    DBG2(DBG_LIB, "Succeeded in calling the class coinstallers.");
	} else {
	    DBG2(DBG_LIB, "Failed to call the class coinstallers.");
	}

        for (int i=0;i<200;i++)
        {
                if ((drv_reg_key = SetupDiOpenDevRegKey(
			dev_info_set,
			&dev_info_data,
			DICS_FLAG_GLOBAL,
			0,
			DIREG_DRV,
			KEY_SET_VALUE | KEY_QUERY_VALUE | KEY_NOTIFY
			)))
                {
		    DBG1(DBG_LIB, "Successfully opened registry key");
                    /* Got registry key */
		    break;
                } else {
		    DBG1(DBG_LIB, "Failed to open registry key");
		    /* Make sure the thread sleeps at least 50 ms */
		    ts = (struct timespec) {
			.tv_sec = 0,
			.tv_nsec = 50000000,
		    };
		    while (nanosleep(&ts, &ts)){}	 
		    drv_reg_key = NULL;
		}
	}
	if(!handle_is_valid(drv_reg_key))
	{
	    DBG0(DBG_LIB, "Failed to open DevRegKey");
	    goto delete_driver_info_list;
	}
	// Need to encode this in UTF-16 first(!)
	LPWSTR temp_buf = NULL;
	
	if(!ascii2utf16(&temp_buf, 0, GUID_WINTUN_STRONGSWAN_STRING, -1))
	{
	    DBG1(DBG_LIB, "Failed to convert string, aborting.");
	    goto delete_driver_info_list;
	}
	DBG1(DBG_LIB, "Value of HKEY drv_reg_key 1: %ld", (long long) drv_reg_key);
        if ((ret=RegSetKeyValueA(drv_reg_key, NULL, "NetSetupAnticipatedInstanceId", REG_SZ, temp_buf, wcslen(temp_buf)+1)) != ERROR_SUCCESS)
        {
                DBG1(DBG_LIB,
			"Failed to set regkey NetSetupAnticipatedInstanceId (RegSetKeyValueA): (decimal %u) %s",
			ret,
			human_readable_error(buf, ret, sizeof(buf)));
        }
	DBG1(DBG_LIB, "Value of HKEY drv_reg_key 2: %ld", (long long) drv_reg_key);	
	free(temp_buf);
	
        SetupDiCallClassInstaller(
                DIF_INSTALLINTERFACES,
                dev_info_set,
                &dev_info_data
        );

        if (!SetupDiCallClassInstaller(
                DIF_INSTALLDEVICE,
                dev_info_set,
                &dev_info_data
                ))
        {
                DBG1(DBG_LIB, "Failed to install device (SetupDicallInstaller(DIF_INSTALLDEVICE)): %s", dlerror_mt(buf, sizeof(buf)));
                goto close_reg_keys;
        }

        if (!SetupDiGetDeviceInstallParamsA(
                dev_info_set,
                &dev_info_data,
                &dev_install_params
                ))
        {
                DBG1(DBG_LIB, "Failed to get install params (SetupDiGetDeviceInstallParamsA): %s", dlerror_mt(buf, sizeof(buf)));
                goto close_reg_keys;
        }

 

        if (!SetupDiSetDeviceRegistryPropertyA(
                dev_info_set,
                &dev_info_data,
                SPDRP_DEVICEDESC,
                WINTUN_COMPONENT_ID,
                sizeof(WINTUN_COMPONENT_ID
        )))
        {
                DBG1(DBG_LIB, "Failed to get device description (SetupDiSetDeviceRegistryPropertyA(SPDRP_DEVICEDESC)) failed: %s", dlerror_mt(buf, sizeof(buf)));
                goto close_reg_keys;
        }
	if(handle_is_valid(drv_reg_key))
	{
	    RegCloseKey(drv_reg_key);
	}
	
	drv_reg_key = SetupDiOpenDevRegKey(
		dev_info_set,
		&dev_info_data,
		DICS_FLAG_GLOBAL,
		0,
		DIREG_DRV, KEY_SET_VALUE | KEY_QUERY_VALUE | KEY_NOTIFY
	);

        if (!registry_wait_get_value(drv_reg_key, NetCfgInstanceId, (DWORD *) &NetCfgInstanceId_length, "NetCfgInstanceId", &reg_value_type, registry_timeout))
        {
                DBG1(DBG_LIB, "Failed to retrieve NetCfgInstanceId key. Aborting tun device installation.");
                goto close_reg_keys;
        }
	DBG2(DBG_LIB, "NetCfgInstanceId type is %d with value: %s", reg_value_type, NetCfgInstanceId);
        if (!(reg_value_type &= (REG_SZ | REG_EXPAND_SZ | REG_MULTI_SZ)))
        {
                DBG1(DBG_LIB, "Type of NetCfgInstanceId is not REG_SZ, REG_EXPAND_SZ or REG_MULTI_SZ (Meaning it is not a string). Aborting tun device install.");
                goto close_reg_keys;
        }
        /* Expand string */

        new_buf = windows_expand_string(property_buffer, &property_buffer_length, &buffer_length);

        if (!registry_wait_get_value(drv_reg_key, NetLuidIndex, (DWORD *) &NetLuidIndex_length, "NetLuidIndex", &reg_value_type, registry_timeout))
        {
                DBG1(DBG_LIB, "Failed to retrieve NetLuidIndex key. Aborting tun device installation.");
                goto close_reg_keys;
        }
        if (reg_value_type != REG_DWORD)
        {
                DBG1(DBG_LIB, "Type of NetLuidIndex is not REG_DWORD. Aborting tun device installation.");
                goto close_reg_keys;
        }

        if (!registry_wait_get_value(drv_reg_key, IfType, (DWORD *) &IfType_length, "*IfType", &reg_value_type, registry_timeout))
        {
                DBG1(DBG_LIB, "Failed to retrieve *IfType key. Aborting tun device installation.");
                goto close_reg_keys;
        }
        if (reg_value_type != REG_DWORD)
        {
                DBG1(DBG_LIB, "Type of *IfType is not REG_DWORD. Aborting tun device installation.");
                goto close_reg_keys;
        }
	/* tcpipAdapterRegKeyName */
	ignore_result(snprintf(adapter_reg_key, sizeof(adapter_reg_key),
		"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Adapters\\%s",
		NetCfgInstanceId));
	
        // Wait for TCP/IP adapter registry key to emerge and populate.
	// Wait for reg key to be populated
	if(!(adapter_reg_hkey = registry_open_wait(HKEY_LOCAL_MACHINE, adapter_reg_key, 0, registry_timeout)))
	{
		DBG1(DBG_LIB, "Timeout while waiting for %s to be accessible.", adapter_reg_key);
		goto close_reg_keys;
	}

        /* IpConfig */
	if(!registry_wait_get_value(adapter_reg_hkey, ipconfig_value, &ipconfig_value_length, "IpConfig",
		&reg_value_type, registry_timeout))
	{
		DBG1(DBG_LIB, "Timeout while waiting for key %s\\%s", adapter_reg_key, "IpConfig");
		goto close_reg_keys;
	}
	
	if (!(reg_value_type &= (REG_SZ | REG_EXPAND_SZ | REG_MULTI_SZ)))
	{
		DBG1(DBG_LIB, "Invalid type %u for key %s\\%s",
			reg_value_type,
			adapter_reg_key,
			"IpConfig");
		goto close_reg_keys;
	}
	
        /* tcpipInterfaceRegKeyName */
	ignore_result(snprintf(ipconfig_reg_key, sizeof(ipconfig_reg_key),
		"SYSTEM\\CurrentControlSet\\Services\\%s", ipconfig_value));
	
	if(!(ipconfig_reg_hkey = registry_open_wait(HKEY_LOCAL_MACHINE, ipconfig_reg_key, 0, registry_timeout)))
	{
		DBG1(DBG_LIB, "Timeout while waiting for key %s to be accessible", ipconfig_reg_key);
		goto close_reg_keys;
	}
	
	/* EnableDeadGWDetect */
	RegSetValueExA(ipconfig_reg_hkey, "EnableDeadGWDetect", 0, REG_DWORD, 0, sizeof(0));
	
	return_code = true;
close_reg_keys :
	if(handle_is_valid(drv_reg_key))
	{
	    RegCloseKey(drv_reg_key);
	}
	if(ipconfig_reg_hkey)
	{
		RegCloseKey(ipconfig_reg_hkey);
	}
	if(adapter_reg_hkey)
	{
		RegCloseKey(adapter_reg_hkey);
	}

delete_driver_info_list : ;
        if (!return_code)
        {
                /* RemoveDeviceParams yade yade yada */
uninstall_device : ;
                /* SP_CLASSINSTALL_HEADER class_install_header = {
                        .cbSize = sizeof(SP_CLASSINSTALL_HEADER),
                        .InstallFunction = DIF_REMOVE
                };
                */
                SP_REMOVEDEVICE_PARAMS remove_device_params = {
			.ClassInstallHeader = {
				.cbSize = sizeof(SP_CLASSINSTALL_HEADER),
				.InstallFunction = DIF_REMOVE
			},
                        .Scope = DI_REMOVEDEVICE_GLOBAL,
                        .HwProfile = 0
                };
		if(SetupDiSetClassInstallParams(dev_info_set, &dev_info_data, &remove_device_params.ClassInstallHeader, sizeof(remove_device_params)))
		{
			if (!SetupDiCallClassInstaller(DIF_REMOVE,
				dev_info_set,
				&dev_info_data))
			{
				DBG1(DBG_LIB, "Failed to remove device (SetupDiCallClassInstaller): %s", dlerror_mt(buf, sizeof(buf)));
			}			
		} else {
			DBG1(DBG_LIB, "Failed to set class install params (SetupDiSetClassInstallParams): %s", dlerror_mt(buf, sizeof(buf)));
		}
        }

if (!SetupDiDestroyDriverInfoList(dev_info_set, &dev_info_data, SPDIT_COMPATDRIVER))
        {
                DBG1(DBG_LIB, "Failed to destroy driver info list (SetupDiDestroyDriverInfoList): %s", dlerror_mt(buf, sizeof(buf)));
        }

delete_device_info_list :
        if (!SetupDiDestroyDeviceInfoList(dev_info_set))
        {
                DBG1(DBG_LIB, "Failed to delete device info set (SetupDiDestroyDeviceInfoList): %s", dlerror_mt(buf, sizeof(buf)));
        }
        if(new_buf)
        {
            free(new_buf);
        }
        return return_code;
}

/**
 * Implements func (pool Pool) GetInterface(ifname string) (*Interface, error)
 * Get a wintun interface handle with that ifname.
 * If it already exists, it is deleted first and a new one is created.
 * This guarantees that the device is always configured correctly.
 * @param		ifname 		desired name of the interface
 * @return 					HANDLE to the wintun device
 */
bool wireguard_get_interface()
{
        GUID guid;
        char error_buf[512];
	SP_DEVINFO_DATA dev_info_data;
	HDEVINFO dev_info_set;
	char *property_buffer = NULL, buf[512];
	DWORD error = 0;
	uint32_t ctr = 0;
	size_t property_buffer_length = 0, required_buffer_size = 0;
	/* Initialise list */
	dev_info_set = SetupDiCreateDeviceInfoListExA(
		&GUID_DEVCLASS_NET,
		NULL,
		NULL,
		NULL
		);
	if (dev_info_set == INVALID_HANDLE_VALUE)
	{
		DBG1(DBG_LIB, "Failed to create device info list (SetupDiCreateDeviceInfoListExA): %s", dlerror_mt(buf, sizeof(buf)));
		return FALSE;
	}
	/* Get all currently existing network interfaces */
	dev_info_set = SetupDiGetClassDevsExA(
		&GUID_DEVCLASS_NET,
		"",
		NULL,
		DIGCF_PRESENT,
		dev_info_set,
		"",
		NULL
		);
	
	/* Abort if getting list of existing network interfaces failed */
	if (!dev_info_set || dev_info_set == INVALID_HANDLE_VALUE)
	{
		DBG1(DBG_LIB, "SetupDiGetClassDevsExA() failed to enumerate network devices: %s", dlerror_mt(buf, sizeof(buf)));
		goto delete_device_info_list;
		return FALSE;
	}
	/* enumerate the devices in the collection*/
	/* Check if hardware ID is Wintun */
	while(TRUE)
	{
		DBG2(DBG_LIB, "Looking at %s",
                        windows_setupapi_get_friendly_name(buf, sizeof(buf), dev_info_set, &dev_info_data));
		if (!SetupDiEnumDeviceInfo(dev_info_set, ctr++, &dev_info_data))
		{
			DBG2(DBG_LIB, "Encountered error in processing of list: %s", dlerror_mt(buf, sizeof(buf)));
			if (error == ERROR_NO_MORE_ITEMS)
			{
				DBG2(DBG_LIB, "Reached end of network interface list.");
				break;
			}
			/* Translate error into text and log it. Use FormatMessage */
			/* Continue enumerating other network interfaces */
			continue;
		}
		/* Get information about this particular network interface */
		/* Get needed length to store property */
		if (!SetupDiGetDeviceRegistryPropertyA(
			dev_info_set,
			&dev_info_data,
			SPDRP_ADDRESS,
			NULL,
			NULL,
			0,
			(DWORD *)&required_buffer_size
			))
		{
			DWORD error = GetLastError();
			/* Request failed, log error and continue */
			if(error == ERROR_INVALID_DATA)
			{
                            DBG1(DBG_LIB,
                                    "Network interface %s doesn't have a hardware address. Skipping.",
                                    windows_setupapi_get_friendly_name(buf, sizeof(buf), dev_info_set, &dev_info_data));
			}
			continue;
		}
		if (property_buffer_length < required_buffer_size)
		{
			property_buffer = realloc(property_buffer, required_buffer_size);
			property_buffer_length = required_buffer_size;
		}
		if (!SetupDiGetDeviceRegistryPropertyA(
			dev_info_set,
			&dev_info_data,
			SPDRP_ADDRESS,
                        NULL,
			property_buffer,
			required_buffer_size,
			NULL
			))
		{
			/* Request failed, log error and continue */
			DBG1(DBG_LIB, "Failed to get hardwareID for device %s: %s",
                                windows_setupapi_get_friendly_name(buf, sizeof(buf), dev_info_set, &dev_info_data),
                                dlerror_mt(error_buf, sizeof(error_buf)));
			continue;
		}
		/* Check hardware id (must be wintun) */
		if (!strcaseeq(property_buffer,  "Wintun"))
		{
			/* Not a wintun type device */
			continue;
		}
		/* It's a wintun type device, check if its name (case insensitive) is the same as ifname */
		HKEY key = SetupDiOpenDevRegKey(dev_info_set, &dev_info_data, DICS_FLAG_GLOBAL, 0, DIREG_DEV, KEY_QUERY_VALUE);
		/* return nil, fmt.Errorf("Device-specific registry key open failed: %v", err) */
		error = RegQueryValueEx(key, "NetCfgInstanceId", NULL, NULL, property_buffer, (DWORD *) &property_buffer_length);
		if (error != ERROR_SUCCESS)
		{
			if (error == ERROR_MORE_DATA)
			{
				property_buffer = realloc(property_buffer, property_buffer_length);
				error = RegQueryValueEx(key, "NetCfgInstanceId", NULL, NULL, property_buffer, (DWORD *) &property_buffer_length);
				if (error)
				{
					DBG1(DBG_LIB,
                                                "Failed to get NetCfgInstanceId for interface %s: %s",
						windows_setupapi_get_friendly_name(buf, sizeof(buf), dev_info_set, &dev_info_data),
						dlerror_mt(error_buf, sizeof(error_buf)));
					continue;
				}
			} else {
				DBG1(DBG_LIB,
                                        "Failed to get NetCfgInstanceId for interface %s: %s",
					windows_setupapi_get_friendly_name(buf, sizeof(buf), dev_info_set, &dev_info_data),
					dlerror_mt(error_buf, sizeof(error_buf)));
				continue;
			}
		}
		/* Convert NetCfgInstanceId to GUID */
		if(!guidfromstring(&guid, property_buffer))
		{
			dlerror_mt(error_buf, sizeof(error_buf));
			DBG1(DBG_LIB, "Failed to convert NetCfgInstanceId %s into GUID: %s",
				property_buffer, dlerror_mt(buf, sizeof(buf)));
			continue;
		}
		/* Check if GUID is the same */
		if (!memcmp(property_buffer, &GUID_WINTUN_STRONGSWAN, min(sizeof(GUID_WINTUN_STRONGSWAN), property_buffer_length)))
		{
			/* Is not the guid */
			continue;
		}
		/* It's the strongSwan VPN adapter. We delete it and recreate it to make sure it works. */
		/* TODO: Actually integrate that */

	}

delete_device_info_list:
        if(property_buffer)
        {
            free(property_buffer);
        }
	if (!SetupDiDestroyDeviceInfoList(dev_info_set))
	{
		DBG1(DBG_LIB, "Failed to destroy device info set (SetupDiDestroyDeviceInfoList): %s", dlerror_mt(buf, sizeof(buf)));
		return FALSE;
	}
	return TRUE;
}

char *search_interfaces(GUID *GUID)
{
	char guid_string[40];
	guid2string(guid_string, sizeof(guid_string), GUID, TRUE);
        char *interfaces = NULL;
	DBG0(DBG_LIB, "Guid2string: %s", guid_string);
        ULONG required_chars = 0;
        CONFIGRET ret;
        for(int tries=0;tries<50;tries++)
        {
            if (interfaces)
            {
                free(interfaces);
                interfaces = NULL;
            }
            for(int i=0;i<2;i++) {
		if (CM_Get_Device_Interface_List_Size(&required_chars,
			(LPGUID)&GUID_DEVINTERFACE_NET,
			guid_string,
			CM_GET_DEVICE_INTERFACE_LIST_PRESENT) != CR_SUCCESS)
		{
		    return NULL;
		}
		interfaces = realloc(interfaces, required_chars*sizeof(WCHAR));
	    }
            if (!interfaces)
	    {
                return NULL;
	    }
	    /* CM_Get_Device_Interface_List writes a zero byte seperated array of strings *
	     * Because GUID is a device guid, the resulting string array should only have one member
	     * (Making it effectively a double zero byte terminated string)
	     */
            ret = CM_Get_Device_Interface_List((LPGUID)&GUID_DEVINTERFACE_NET, guid_string,
                            interfaces, required_chars, CM_GET_DEVICE_INTERFACE_LIST_PRESENT);
            if (ret == CR_SUCCESS)
	    {
                break;
	    }
            if (ret != CR_BUFFER_SMALL)
            {
                free(interfaces);
                return NULL;
            }
        }
        return interfaces;
}

bool configure_wintun(private_windows_wintun_device_t *this, const char *name_tmpl)
{
	char buf[512], *interfaces = NULL, guid_string[512];
	for(int i=0;i<2;i++) {
	    interfaces = search_interfaces((GUID *) &GUID_WINTUN_STRONGSWAN);
	    if(!interfaces)
	    {
		DBG1(DBG_LIB, "No strongSwan VPN interface found, creating one.");
		if (!create_wintun(guid_string))
		{
		    DBG0(DBG_LIB, "Failed to create new wintun device");
		    return FALSE;
		}
	    }
	}
	/* Iterate over contents */	
	linked_list_t *list = string_array_to_linked_list(interfaces);
	enumerator_t *enumerator = list->create_enumerator(list);

	char *interface;
	while(enumerator->enumerate(enumerator, (void **) &interface))
	{
	    /* wireguard uses FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE instead of 0 after 
	       GENERIC_READ | GENERIC_WRITE. The reason for that is unknown. It makes no sense though.
	     */
		this->tun_handle = CreateFile(interface, GENERIC_READ | GENERIC_WRITE,
						 0, NULL, OPEN_EXISTING, 0, NULL);
		if(this->tun_handle) {
		    /* Don't overwrite last byte */
		    strncpy(this->if_name, interface, sizeof(this->if_name)-1);
			break;
		} else {
			DBG0(DBG_LIB, "Failed to open tun file handle %s: %s",
			    interface, dlerror_mt(buf, sizeof(buf)));
		}
	}
	DBG0(DBG_LIB, "foo");
	list->get_first(list, (void **) &interface);
	free(interface);

	enumerator->destroy(enumerator);
	list->destroy(list);

        if(!this->tun_handle)
        {
		DBG0(DBG_LIB, "Failed to find an unused TUN device.");
		return FALSE;
        }
	
        /* Create structs for rings and the rings themselves */
        this->rings = malloc(sizeof(TUN_REGISTER_RINGS));
        this->rings->Send.Ring = malloc(sizeof(TUN_RING));
	memwipe(this->rings->Send.Ring, sizeof(TUN_RING));
        this->rings->Receive.Ring = malloc(sizeof(TUN_RING));
	memwipe(this->rings->Receive.Ring, sizeof(TUN_RING));

        /* Tell driver about the rings */
        if(!DeviceIoControl(this->tun_handle,
            TUN_IOCTL_REGISTER_RINGS,
            &this->rings->Receive,
            TUN_RING_SIZE(this->rings->Receive, TUN_RING_CAPACITY),
            &this->rings->Send,
            TUN_RING_SIZE(this->rings->Send, TUN_RING_CAPACITY),
            NULL,
            NULL
        )) {
	    DBG0(DBG_LIB, "failed to install rings");
	    free(this->rings->Send.Ring);
	    free(this->rings->Receive.Ring);
	    free(this->rings);
	    return FALSE;
	}
	return TRUE;
}

/* Stub. Returns an unused wintun device */
GUID *find_unused_wintun_device(const char *name_tmpl)
{
	return NULL;
}

/* Stub. Returns the public interface of a fully configured wintun device */
tun_device_t *initialize_unused_wintun_device(const char *name_tmpl)
{
	private_windows_wintun_device_t *this;
	INIT(this,
		.public = {
			.read_packet = _wintun_read_packet,
			.write_packet = _wintun_write_packet,
			.get_mtu = _wintun_get_mtu,
			.set_mtu = _wintun_set_mtu,
			.get_name = _wintun_get_name,
                        .get_handle = _wintun_get_handle,
			.set_address = _wintun_set_address,
			.get_address = _wintun_get_address,
			.up = _wintun_up,
			.destroy = _wintun_destroy,
		},
		.rings = NULL,
                .tun_handle = NULL,
		.ifindex = 0,

	);
	if(configure_wintun(this, name_tmpl))
	{
	    return &this->public;
	} else {
	    free(this);
	    return NULL;
	}
}

/* Possibly creates, and configures a wintun device */
tun_device_t *try_configure_wintun(const char *name_tmpl)
{
	tun_device_t *new_device = NULL;
	/* Be robust */
	for(int i=0;i<5;i++)
	{
		/* Try to find an unused wintun device */
		new_device = initialize_unused_wintun_device(name_tmpl);
		if (new_device)
		{
			return new_device;
		}
	}
	return NULL;
}
