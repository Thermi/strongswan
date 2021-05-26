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
#include <ifdef.h>
/* For NTSTATUS, potentially defined in bcrypt.h if it exists */
#include <winternl.h>
#include <netioapi.h>
#include <windows.h>
#include <cfgmgr32.h>
#include <setupapi.h>
#include <devpkey.h>
#include <winreg.h>
#include <utils/windows_helper.h>

#include "wintun_support.h"
#include <threading/mutex.h>

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
        
        /**
         * Size of the rings
         */
        uint64_t ring_capacity;
	
	/**
	 * Bool to indicate to a reader not using the event handles that
	 * the tun device is getting closed
	 */
	bool close;
	
	/**
	 *  Lock used for makeing sure the device is not destroyed while in use */
	mutex_t *lock;
};

static inline bool ring_over_capacity(TUN_RING *ring, uint64_t ring_capacity)
{
    return ((ring->Head >= ring_capacity) || (ring->Tail >= ring_capacity));
}

static inline ULONG get_head(TUN_RING *ring)
{
	return (ULONG) __atomic_load_n(&ring->Head, __ATOMIC_RELAXED);
}

static inline ULONG get_tail(TUN_RING *ring)
{
	return (ULONG) __atomic_load_n(&ring->Tail, __ATOMIC_RELAXED);
}
/* This is likely broken (!!!) */
static bool write_to_ring(TUN_RING *ring, chunk_t packet, uint64_t ring_capacity)
{
    /* Check if packet fits */
    TUN_PACKET *tun_packet;
    ULONG ring_tail;
    /* TODO: if ring is full or over capacity, wait until wintun driver sends event */
    if (ring_over_capacity(ring, ring_capacity))
    {
        DBG1(DBG_LIB, "RING is over capacity!");
        return FALSE;
    }
    
    uint64_t aligned_packet_size = TUN_PACKET_ALIGN(sizeof(TUN_PACKET_HEADER) + packet.len);
    uint64_t buffer_space = TUN_WRAP_POSITION((ring->Head - ring->Tail - TUN_PACKET_ALIGNMENT), ring_capacity);
    if (aligned_packet_size > buffer_space)
    {
        DBG1(DBG_LIB, "RING is full!");
        return FALSE;
    }
    
    /* copy packet size and data into ring */
    tun_packet = (TUN_PACKET *)&(ring->Data[ring->Tail]);
    tun_packet->Size = packet.len;
    memcpy(tun_packet->Data, packet.ptr, packet.len);
    
    /* move ring tail */
    ring_tail = TUN_WRAP_POSITION((ring->Tail + aligned_packet_size), ring_capacity);
    __atomic_store(&ring->Tail, &ring_tail, __ATOMIC_RELAXED);
    return TRUE;
}

static bool pop_from_ring(TUN_RING *ring, chunk_t *chunk_packet,
                            uint64_t ring_capacity, bool *need_restart)
{
        uint32_t length;
	ULONG ret;
        size_t aligned_packet_size;
        /* TODO: If ring is over capacity wait until event is sent */
        TUN_PACKET *packet;
        /* Ring is empty if head == tail */
        if (get_head(ring) == get_tail(ring))
        {
            return FALSE;
        }
        if (ring_over_capacity(ring, ring_capacity))
        {
            DBG0(DBG_LIB, "RING is over capacity!");
        }
        length = TUN_WRAP_POSITION((ring->Tail - ring->Head),
            ring_capacity);
	
        if (length < sizeof(uint32_t))
        {
            DBG0(DBG_LIB, "RING contains incomplete packet header!");
            *need_restart = TRUE;
	    return FALSE;

        }
        packet = (TUN_PACKET *)&(ring->Data[ring->Head]);
	
        if (packet->Size > TUN_MAX_IP_PACKET_SIZE)
        {
            DBG0(DBG_LIB, "RING contains packet larger than TUN_MAX_IP_PACKET_SIZE!");
	    *need_restart = TRUE;
	    return FALSE;
        }
        aligned_packet_size = TUN_PACKET_ALIGN(sizeof(TUN_PACKET_HEADER) + packet->Size);
        if (aligned_packet_size > length)
        {
            DBG0(DBG_LIB, "Incomplete packet in send ring!");
	    *need_restart = TRUE;
	    return FALSE;
        }

        chunk_packet->ptr = malloc(packet->Size);
        chunk_packet->len = packet->Size;
        memcpy(chunk_packet->ptr, packet->Data, chunk_packet->len);
        /* Do we need to memset here? */
        /* memwipe(packet->Data, packet->Size); */
        /* move ring head */
	ret = TUN_WRAP_POSITION((ring->Head + aligned_packet_size), ring_capacity);
        __atomic_store(&ring->Head, &ret, __ATOMIC_RELAXED);
        return TRUE;
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
        return 1500;
}

/* On WIN32 we return the handle of the read ring (kernel space -> user space) */
METHOD(tun_device_t, wintun_get_handle, HANDLE,
        private_windows_wintun_device_t *this)
{
	this->lock->lock(this->lock);
	HANDLE eventhandle = this->rings->Send.TailMoved;
        this->lock->unlock(this->lock);
	return eventhandle;
}

METHOD(tun_device_t, wintun_write_packet, bool,
        private_windows_wintun_device_t *this, chunk_t packet)
{
	this->lock->lock(this->lock);
	if (this->windows_close)
	{
		return FALSE;
		this->lock->unlock(this->lock);
	}
        write_to_ring(this->rings->Receive.Ring, packet, this->ring_capacity);
        if (__atomic_load_n(&this->rings->Receive.Ring->Alertable, __ATOMIC_RELAXED))
        {
            SetEvent(this->rings->Receive.TailMoved);
        }
	this->lock->unlock(this->lock);
        return TRUE;
}

METHOD(tun_device_t, wintun_read_packet, bool, 
        private_windows_wintun_device_t *this, chunk_t *packet)
{
	bool need_restart = FALSE, success;
	this->lock->lock(this->lock);
	if (this->windows_close)
	{
		this->lock->unlock(this->lock);
		return FALSE;
	}
	success = pop_from_ring(this->rings->Send.Ring,
                packet, this->ring_capacity, &need_restart);
	if (need_restart)
        {
		this->lock->unlock(this->lock);
		restart_driver(this);
		return FALSE;
	}
	this->lock->unlock(this->lock);
	return success;
	/*
	if (!success)
        {
                 __atomic_store_n(this->rings->Send.Ring->Alertable, TRUE, __ATOMIC_RELAXED); 
                success = pop_from_ring(this->rings->Send.Ring, packet,
                        this->ring_capacity, &need_restart);
		if (need_restart)
                {
			restart_driver(this);
			return FALSE;
		}
                if (!success)
                {
			return FALSE;
                    WaitForSingleObject(this->rings->Send.TailMoved, INFINITE);
                    this->rings->Send.Ring->Alertable = FALSE;
                }
                this->rings->Send.Ring->Alertable = FALSE;
                ResetEvent(this->rings->Send.TailMoved);
        }
        return TRUE; */
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
	this->lock->lock(this->lock);
	this->close = TRUE;
	SetEvent(this->rings->Send.TailMoved);
	CloseHandle(this->rings->Send.TailMoved);
	CloseHandle(this->rings->Receive.TailMoved);
	CloseHandle(this->tun_handle);
	VirtualFree(this->rings->Send.Ring, 0, MEM_RELEASE);
	VirtualFree(this->rings->Receive.Ring, 0, MEM_RELEASE);
	VirtualFree(this->rings, 0, MEM_RELEASE);
	this->lock->unlock(this->lock);
	this->lock->destroy(this->lock);
}

/**
 * Deletes existing strongSwan wintun devices
 * @return	bool indicating if the routine encountered SetupDi errors not
 *		(not if any devices were deleted)
 */
bool delete_existing_strongswan_wintun_devices()
{
    DBG1(DBG_LIB, "Deleting existing strongSwan wintun devices.");
	/* Reimplementation of CreateInterface from wireguard */
	char buf[512];
	uint64_t index = 0;
	DWORD required_length = 0, ret = 0;
	/* Create an empty device info set for network adapter device class. */
	SP_DEVINFO_DATA dev_info_data = {
		.cbSize = sizeof(SP_DEVINFO_DATA)
	};
	
	/* Get all currently existing network interfaces */
	HDEVINFO dev_info_set = SetupDiGetClassDevsExA(
		&GUID_DEVCLASS_NET,
		NULL,
		NULL,
		DIGCF_PRESENT,
		NULL,
		NULL,
		NULL
		);
	
	if (dev_info_set == INVALID_HANDLE_VALUE || (ret=GetLastError()))
        {
            if (ret)
            {
                DBG1(DBG_LIB, "Failed to create device info list (SetupDiCreate"
			"DeviceInfoListExA): %s", human_readable_error(buf, ret,
								sizeof(buf)));
            } else {
                DBG1(DBG_LIB, "Failed to create device info list (SetupDiCreate"
			"DeviceInfoListExA), dev_info_set has value"
			"INVALID_HANDLE_VALUE");
            }
	    return FALSE;
	}
	
	if (!dev_info_set)
	{
		DBG1(DBG_LIB,
			"Failed to create DeviceInfoList(SetupDiCreateDeviceInfoListExA): %s",
				dlerror_mt(buf, sizeof(buf)));
		goto delete_device_info_list;
	}
 
	
	for(index=0;;index++)
	{
		DBG3(DBG_LIB, "Running SetupDiEnumDeviceInfo.");
		if(!SetupDiEnumDeviceInfo(
			dev_info_set,
			index,
			&dev_info_data))
		{
			ret=GetLastError();
			if (ret != ERROR_NO_MORE_ITEMS)
			{
			    DBG1(DBG_LIB, "An error occured: %s", dlerror_mt(buf, sizeof(buf)));
			}
			break;
		}
		/* Check device ID */
		if(!SetupDiGetDeviceInstanceIdA(
			dev_info_set,
			&dev_info_data,
			buf,
			sizeof(buf),
			&required_length))
		{
			DBG1(DBG_LIB, "Failed to get device ID for index %d: %s",
				index, dlerror_mt(buf, sizeof(buf)));
		} else {
			DBG2(DBG_LIB, "Retrieved Device ID: %s", buf);
			if (strstr(buf, "STRONGSWAN"))
			{
				DBG1(DBG_LIB, "Removing device %s", buf);
				/* Delete device */
				SP_REMOVEDEVICE_PARAMS remove_device_params = {
					.ClassInstallHeader = {
						.cbSize = sizeof(SP_CLASSINSTALL_HEADER),
						.InstallFunction = DIF_REMOVE
					},
					.Scope = DI_REMOVEDEVICE_GLOBAL,
					.HwProfile = 0
				};
				if(SetupDiSetClassInstallParams(dev_info_set,
					&dev_info_data,
					&remove_device_params.ClassInstallHeader,
					sizeof(remove_device_params)))
				{
					if (!SetupDiCallClassInstaller(DIF_REMOVE,
						dev_info_set,
						&dev_info_data))
					{
						DBG1(DBG_LIB, "Failed to remove "
							"device (SetupDiCallClass"
							"Installer): %s",
							dlerror_mt(buf, sizeof(buf)));
					}			
				} else {
					DBG1(DBG_LIB, "Failed to set class inst"
						"all params (SetupDiSetClassIns"
						"tallParams): %s",
						dlerror_mt(buf, sizeof(buf)));
				}
			} else {
				DBG2(DBG_LIB, "Skipping device %s", buf);
			}
		}
	}
delete_device_info_list :
        if (!SetupDiDestroyDeviceInfoList(dev_info_set))
        {
                DBG1(DBG_LIB, "Failed to delete device info set (SetupDiDestroyDeviceInfoList): %s", dlerror_mt(buf, sizeof(buf)));
        }
	return TRUE;
}

/**
 * Return the file path to the interface (Can be used with CreateFile)
 */
bool get_interface_path(char *device_id, char **buf)
{
    DBG2(DBG_LIB, "Looking for device ID %s", device_id);
    uint32_t bufsize = 512;
    GUID cpy;
    *buf = calloc(bufsize, sizeof(char));
    uint64_t tries = 0;

    do {
        sleep(1);
        cpy = (GUID) GUID_INTERFACE_NET;
        CONFIGRET ret = CM_Get_Device_Interface_List(&cpy, device_id, *buf, bufsize, CM_GET_DEVICE_INTERFACE_LIST_PRESENT);

        if (ret == CR_BUFFER_SMALL)
        {
            DBG1(DBG_LIB, "Buffer too small for CM_Get_Device_Interface_List. That shouldn't happen.");
            return FALSE;
        } else if (ret) {
            DBG1(DBG_LIB, "Other return code: %d", ret);
            return FALSE;
        }
        ret = strlen(*buf);
        if (!ret)
        {
            DBG2(DBG_LIB, "Waiting for 1 second for device path to become "
                    "available; cfgmngr32 currently returns the device path as "
                    "empty string. Try number: %d.", tries++);
        } else {
            break;
        }
    } while (TRUE);
    return TRUE;
}
/**
 * Create the tun device and configure it as stored in the registry.
 *					Can be NULL to make the system choose one at random.
 * @return char				deviceID of the device that was created.
 */
char *create_wintun(char *NetCfgInstanceId, size_t *NetCfgInstanceId_length)
{
	/* Reimplementation of CreateInterface from wireguard */
	char className[MAX_CLASS_NAME_LEN], buf[512], ipconfig_value[512],
		*device_id = NULL,
		*property_buffer = NULL;
	uint64_t index = 0;

	size_t registry_timeout = 5000;
	DWORD property_buffer_length = 0, required_length = 0,
		reg_value_type,
		ipconfig_value_length = sizeof(ipconfig_value),
		ret = 0;

	DWORDLONG driver_version = 0;
	HKEY reg_hkey = NULL;
	/* Timeout of 5000 ms for registry operations */

	LPWSTR temp_buf = NULL;

	FILETIME driver_date = {
		.dwHighDateTime = 0,
		.dwLowDateTime = 0
	};
	memset(NetCfgInstanceId, 0, *NetCfgInstanceId_length);

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
	if (dev_info_set == INVALID_HANDLE_VALUE)
        {
	    DBG1(DBG_LIB, "Failed to create device info list (SetupDiCreateDeviceInfoListExA), dev_info_set is an invalid handle");
	    free(drv_info_detail_data);
	    return FALSE;
	}
        
        if ((ret=GetLastError()))
        {
	    DBG1(DBG_LIB, "Failed to create device info list (SetupDiCreateDeviceInfoListExA): %s", human_readable_error(buf, ret, sizeof(buf)));
	    free(drv_info_detail_data);
	    return FALSE;            
        }
        /* wait 50 ms */
        struct timespec ts;
	
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
		sizeof(className)-1,
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
		STRONGSWAN_WINTUN_DEVICE_ID,
		&GUID_DEVCLASS_NET,
		STRONGSWAN_WINTUN_INTERFACE_NAME,
		NULL,
		DICD_GENERATE_ID,
		&dev_info_data))
	{
		DBG1(DBG_LIB, "Failed to create device info object: %s", dlerror_mt(buf, sizeof(buf)));
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
			ret=GetLastError();
			if (ret == ERROR_NO_MORE_ITEMS)
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
			/** On my system, the underlying call to SetupDiGetDriverInfoDetailA
			 * fails, so this is disabled for now.
			*/
		    /* required_length = 0;
		    if(windows_get_driver_info_data_a(
			dev_info_set,
			&dev_info_data,
			&drv_info_data,
			&drv_info_detail_data,
			&drv_info_detail_data_size,
			&required_length
			))
		     */
		    {
			if(check_hardwareids(drv_info_detail_data) ||
				strcaseeq(drv_info_data.Description, "Wintun Userspace Tunnel"))
                        {
			    if(SetupDiSetSelectedDriverA(dev_info_set, &dev_info_data, &drv_info_data))
			    {
				DBG2(DBG_LIB, "Successfully Set driver of device %s for new wintun device",
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
		    } /* else {
			DBG1(DBG_LIB, "Failed to get driver info data");
		    } */
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
	
	if(!SetupDiCallClassInstaller(
		DIF_REGISTER_COINSTALLERS,
		dev_info_set,
		&dev_info_data
	))
	{
	    DBG2(DBG_LIB, "Failed to call the class coinstallers.");
	}

        for (int i=0;i<200;i++)
        {
                if ((reg_hkey = SetupDiOpenDevRegKey(
			dev_info_set,
			&dev_info_data,
			DICS_FLAG_GLOBAL,
			0,
			DIREG_DRV,
			KEY_SET_VALUE | KEY_QUERY_VALUE | KEY_NOTIFY
			)))
                {
		    DBG2(DBG_LIB, "Successfully opened registry key");
                    /* Got registry key */
		    break;
                } else {
		    DBG2(DBG_LIB, "Failed to open registry key");
		    /* Make sure the thread sleeps at least 50 ms */
		    ts = (struct timespec) {
			.tv_sec = 0,
			.tv_nsec = 50000000,
		    };
		    while (nanosleep(&ts, &ts)){}	 
		    reg_hkey = NULL;
		}
	}
	if(!handle_is_valid(reg_hkey))
	{
	    DBG0(DBG_LIB, "Failed to open DevRegKey, handle is invalid.");
	    goto delete_driver_info_list;
	}
	
	if(!ascii2utf16(&temp_buf, 0, GUID_WINTUN_STRONGSWAN_STRING, -1))
	{
	    DBG1(DBG_LIB, "Failed to convert string, aborting.");
	    goto delete_driver_info_list;
	}
        if ((ret=RegSetKeyValueA(reg_hkey, NULL, "NetSetupAnticipatedInstanceId", REG_SZ, temp_buf, wcslen(temp_buf)+1)) != ERROR_SUCCESS)
        {
                DBG1(DBG_LIB,
			"Failed to set regkey NetSetupAnticipatedInstanceId (RegSetKeyValueA): (decimal %u) %s",
			ret,
			human_readable_error(buf, ret, sizeof(buf)));
        }

	RegCloseKey(reg_hkey);

	if (temp_buf) {
		free(temp_buf);
	}
	
        if (!SetupDiCallClassInstaller(
                DIF_INSTALLINTERFACES,
                dev_info_set,
                &dev_info_data
        ))
	{
	    DBG1(DBG_LIB, "Failed to call class installer: %s", dlerror_mt(buf, sizeof(buf)));
	    goto close_reg_key;
	}

        if (!SetupDiCallClassInstaller(
                DIF_INSTALLDEVICE,
                dev_info_set,
                &dev_info_data
                ))
        {
                DBG1(DBG_LIB, "Failed to install device (SetupDicallInstaller(DIF_INSTALLDEVICE)): %s", dlerror_mt(buf, sizeof(buf)));
                goto close_reg_key;
        }

        if (!SetupDiGetDeviceInstallParamsA(
                dev_info_set,
                &dev_info_data,
                &dev_install_params
                ))
        {
                DBG1(DBG_LIB, "Failed to get install params (SetupDiGetDeviceInstallParamsA): %s", dlerror_mt(buf, sizeof(buf)));
                goto close_reg_key;
        }
 
        if (!SetupDiSetDeviceRegistryPropertyA(
                dev_info_set,
                &dev_info_data,
                SPDRP_DEVICEDESC,
                STRONGSWAN_WINTUN_INTERFACE_NAME,
                sizeof(STRONGSWAN_WINTUN_INTERFACE_NAME)
        ))
        {
                DBG1(DBG_LIB, "Failed to set device description (SetupDiSetDeviceRegistryPropertyA(SPDRP_DEVICEDESC)) failed: %s", dlerror_mt(buf, sizeof(buf)));
                goto close_reg_key;
        }
	
	
	reg_hkey = SetupDiOpenDevRegKey(
		dev_info_set,
		&dev_info_data,
		DICS_FLAG_GLOBAL,
		0,
		DIREG_DRV, KEY_SET_VALUE | KEY_QUERY_VALUE | KEY_NOTIFY
	);

        if (!registry_wait_get_value(reg_hkey, NetCfgInstanceId, (DWORD *) NetCfgInstanceId_length, "NetCfgInstanceId", &reg_value_type, registry_timeout))
        {
                DBG1(DBG_LIB, "Failed to retrieve NetCfgInstanceId key. Aborting tun device installation.");
                goto close_reg_key;
        }
	
	RegCloseKey(reg_hkey);
	
        if (!(reg_value_type &= (REG_SZ | REG_EXPAND_SZ | REG_MULTI_SZ)))
        {
                DBG1(DBG_LIB, "Type of NetCfgInstanceId is not REG_SZ, REG_EXPAND_SZ or REG_MULTI_SZ (Meaning it is not a string). Aborting tun device install.");
                goto close_reg_key;
        }

	/* tcpipAdapterRegKeyName */
	ignore_result(snprintf(buf, sizeof(buf),
		"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Adapters\\%s",
		NetCfgInstanceId));
	
        // Wait for TCP/IP adapter registry key to emerge and populate.
	// Wait for reg key to be populated
	if(!(reg_hkey = registry_open_wait(HKEY_LOCAL_MACHINE, buf, 0, registry_timeout)))
	{
		DBG2(DBG_LIB, "Timeout while waiting for %s to be accessible.", buf);
		goto close_reg_key;
	}

        /* IpConfig */
	if(!registry_wait_get_value(reg_hkey, ipconfig_value, &ipconfig_value_length, "IpConfig",
		&reg_value_type, registry_timeout))
	{
		DBG2(DBG_LIB, "Timeout while waiting for key %s\\%s", buf, "IpConfig");
		goto close_reg_key;
	}
	RegCloseKey(reg_hkey);
	
	if (!(reg_value_type &= (REG_SZ | REG_EXPAND_SZ | REG_MULTI_SZ)))
	{
		DBG2(DBG_LIB, "Invalid type %u for key %s\\%s",
			reg_value_type,
			buf,
			"IpConfig");
		goto close_reg_key;
	}
	
        /* tcpipInterfaceRegKeyName */
	ignore_result(snprintf(buf, sizeof(buf),
		"SYSTEM\\CurrentControlSet\\Services\\%s", ipconfig_value));
	
	if(!(reg_hkey = registry_open_wait(HKEY_LOCAL_MACHINE, buf, 0, registry_timeout)))
	{
		DBG2(DBG_LIB, "Timeout while waiting for key %s to be accessible", buf);
		goto close_reg_key;
	}
	
	/* EnableDeadGWDetect */
	ret=0;
	if((ret=RegSetValueExA(reg_hkey, "EnableDeadGWDetect", 0, REG_DWORD, (BYTE *)&ret, sizeof(ret))) != ERROR_SUCCESS)
	{
		DBG1(DBG_LIB, "Failed to set EnableDeadGWDetect to 0 (%d): %s", ret, human_readable_error(buf, ret, sizeof(buf)));
	}
	ret=sizeof(buf);
	if ((ret=RegQueryValueExA(reg_hkey, "EnableDeadGWDetect", NULL, (LPDWORD) &index, buf, &ret)) != ERROR_SUCCESS)
	{
		DBG1(DBG_LIB, "Failed to retrieve type and value of EnableDeadGWDetect. Ret is %d", ret);
	} else {
		DBG1(DBG_LIB, "EnableDeadGWDetect is type %d with value %d", index, buf);
	}

    ret=1;
    /** Set interface metric for IPv4 (Different folder for IPv6) to 1 to make sure it is preferred for DNS resolution */
    if((ret=RegSetValueExA(reg_hkey, "InterfaceMetric", 0, REG_DWORD, (BYTE *)&ret, sizeof(ret))) != ERROR_SUCCESS)
    {
            DBG1(DBG_LIB, "Failed to set InterfaceMetric to 1 (%d): %s", ret, human_readable_error(buf, ret, sizeof(buf)));
    }

	if(!SetupDiGetDeviceInstanceIdA(
	    dev_info_set,
	    &dev_info_data,
	    buf,
	    sizeof(buf),
	    &required_length))
	{
	    DBG2(DBG_LIB, "Failed to get device ID for index %d: %s", index, dlerror_mt(buf, sizeof(buf)));
	}

	device_id = malloc(strlen(buf)+1);
        memcpy(device_id, buf, strlen(buf)+1);
	
close_reg_key :
	if(handle_is_valid(reg_hkey))
	{
	    RegCloseKey(reg_hkey);
	}

delete_driver_info_list : ;
        if (!device_id)
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
				DBG2(DBG_LIB, "Failed to remove device (SetupDiCallClassInstaller): %s", dlerror_mt(buf, sizeof(buf)));
			}			
		} else {
			DBG2(DBG_LIB, "Failed to set class install params (SetupDiSetClassInstallParams): %s", dlerror_mt(buf, sizeof(buf)));
		}
        }

if (!SetupDiDestroyDriverInfoList(dev_info_set, &dev_info_data, SPDIT_COMPATDRIVER))
        {
                DBG2(DBG_LIB, "Failed to destroy driver info list (SetupDiDestroyDriverInfoList): %s", dlerror_mt(buf, sizeof(buf)));
        }

delete_device_info_list :
        if (!SetupDiDestroyDeviceInfoList(dev_info_set))
        {
                DBG2(DBG_LIB, "Failed to delete device info set (SetupDiDestroyDeviceInfoList): %s", dlerror_mt(buf, sizeof(buf)));
        }

	if(device_id)
        {
	    DBG2(DBG_LIB, "Successfully created a wintun device with NetCfgInstanceId %s", NetCfgInstanceId);
	} else {
	    DBG2(DBG_LIB, "Failed to create a wintun device");
	}
        return device_id;
}

bool
impersonate_as_system()
{
    HANDLE thread_token, process_snapshot, winlogon_process, winlogon_token, duplicated_token;
    PROCESSENTRY32 entry;
    BOOL ret;
    DWORD pid = 0;
    TOKEN_PRIVILEGES privileges;

    memset(&entry, 0 , sizeof(entry));
    memset(&privileges, 0, sizeof(privileges));

    entry.dwSize = sizeof(PROCESSENTRY32);

    privileges.PrivilegeCount = 1;
    privileges.Privileges->Attributes = SE_PRIVILEGE_ENABLED;

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &privileges.Privileges[0].Luid))
    {
        return false;
    }

    if (!ImpersonateSelf(SecurityImpersonation))
    {
        return false;
    }

    if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES, FALSE, &thread_token))
    {
        RevertToSelf();
        return false;
    }
    if (!AdjustTokenPrivileges(thread_token, FALSE, &privileges, sizeof(privileges), NULL, NULL))
    {
        CloseHandle(thread_token);
        RevertToSelf();
        return false;
    }
    CloseHandle(thread_token);

    process_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (process_snapshot == INVALID_HANDLE_VALUE)
    {
        RevertToSelf();
        return false;
    }
    for (ret = Process32First(process_snapshot, &entry); ret; ret = Process32Next(process_snapshot, &entry))
    {
        if (!_stricmp(entry.szExeFile, "winlogon.exe"))
        {
            pid = entry.th32ProcessID;
            break;
        }
    }
    CloseHandle(process_snapshot);
    if (!pid)
    {
        RevertToSelf();
        return false;
    }

    winlogon_process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!winlogon_process)
    {
        RevertToSelf();
        return false;
    }

    if (!OpenProcessToken(winlogon_process, TOKEN_IMPERSONATE | TOKEN_DUPLICATE, &winlogon_token))
    {
        CloseHandle(winlogon_process);
        RevertToSelf();
        return false;
    }
    CloseHandle(winlogon_process);

    if (!DuplicateToken(winlogon_token, SecurityImpersonation, &duplicated_token))
    {
        CloseHandle(winlogon_token);
        RevertToSelf();
        return false;
    }
    CloseHandle(winlogon_token);

    if (!SetThreadToken(NULL, duplicated_token))
    {
        CloseHandle(duplicated_token);
        RevertToSelf();
        return false;
    }
    CloseHandle(duplicated_token);

    return true;
}

bool configure_wintun(private_windows_wintun_device_t *this, const char *name_tmpl)
{
	char buf[1024], NetCfgInstanceId[255], *interface_path = NULL, *device_id = NULL;
	DWORD ret;
        size_t NetCfgInstanceId_length = sizeof(NetCfgInstanceId);
        if (!(device_id = create_wintun(NetCfgInstanceId, &NetCfgInstanceId_length)))
        {
            DBG0(DBG_LIB, "Failed to create new wintun device");
            return FALSE;
        }
        ret = get_interface_path(device_id, &interface_path);
        free(device_id);
        if (!ret)
        {
            return FALSE;
        }
        DBG2(DBG_LIB, "Device path: %s", interface_path);

        this->tun_handle = CreateFile(
                interface_path, GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                NULL, OPEN_EXISTING, 0, NULL);
        if(this->tun_handle != INVALID_HANDLE_VALUE)
        {
            strncpy(this->if_name, NetCfgInstanceId, sizeof(this->if_name)-1);
        } else {
            DBG0(DBG_LIB, "Failed to open tun file handle %s: %s",
                 interface_path, dlerror_mt(buf, sizeof(buf)));
        }

	DBG0(DBG_LIB, "foo");

        if(!this->tun_handle)
        {
		DBG0(DBG_LIB, "Failed to find an unused TUN device.");
		return FALSE;
        }
	
        /* Create structs for rings and the rings themselves */
        this->rings = VirtualAlloc(NULL, sizeof(TUN_REGISTER_RINGS), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	this->rings->Send.TailMoved = CreateEventA(NULL, FALSE, FALSE, NULL);
        this->rings->Send.Ring = VirtualAlloc(NULL, sizeof(TUN_RING) + this->ring_capacity + WINTUN_RING_TRAILING_BYTES,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	this->rings->Send.RingSize = sizeof(TUN_RING) + this->ring_capacity + WINTUN_RING_TRAILING_BYTES;
	memwipe(this->rings->Send.Ring, sizeof(TUN_RING) + this->ring_capacity + WINTUN_RING_TRAILING_BYTES);
	this->rings->Receive.TailMoved = CreateEventA(NULL, FALSE, FALSE, NULL);
        this->rings->Receive.Ring = VirtualAlloc(NULL, sizeof(TUN_RING) + this->ring_capacity + WINTUN_RING_TRAILING_BYTES,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	this->rings->Receive.RingSize = sizeof(TUN_RING) + this->ring_capacity + WINTUN_RING_TRAILING_BYTES;
	memwipe(this->rings->Receive.Ring, sizeof(TUN_RING) + this->ring_capacity + WINTUN_RING_TRAILING_BYTES);
	DBG2(DBG_LIB, "Ring capacity: %d", this->ring_capacity);
        /* Tell driver about the rings */
	if (!impersonate_as_system())
        {
            DBG0(DBG_LIB, "Failed to impersonate as SYSTEM, make sure process is running under privileged account");
        }
	
        if(!DeviceIoControl(this->tun_handle,
            TUN_IOCTL_REGISTER_RINGS,
	    this->rings,
            sizeof(*this->rings),
            NULL,
            0,
            &ret,
            NULL))
        {
	    DBG0(DBG_LIB, "failed to install rings: %s", dlerror_mt(buf, sizeof(buf)));
	    CloseHandle(this->rings->Receive.TailMoved);
	    CloseHandle(this->rings->Send.TailMoved);
	    if(this->rings->Send.Ring)
            {
		VirtualFree(this->rings->Send.Ring, 0, MEM_RELEASE);
	    }
	    if (this->rings->Receive.Ring)
            {
		VirtualFree(this->rings->Receive.Ring, 0, MEM_RELEASE);
	    }
	 
	    VirtualFree(this->rings, 0, MEM_RELEASE);
	    CloseHandle(this->tun_handle);
	    if (!RevertToSelf())
	    {
		DBG0(DBG_LIB, "RevertToSelf error: %s", dlerror_mt(buf, sizeof(buf)));
	    }
	    return FALSE;
	}
	if (!RevertToSelf())
        {
            DBG0(DBG_LIB, "RevertToSelf error: %s", dlerror_mt(buf, sizeof(buf)));
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
		.lock = mutex_create(MUTEX_TYPE_DEFAULT),
		.rings = NULL,
                .tun_handle = NULL,
		.ifindex = 0,
                .ring_capacity = lib->settings->get_int(lib->settings,
                    "%s.ring_capacity", TUN_RING_CAPACITY, lib->ns),
	);
	if(configure_wintun(this, name_tmpl))
	{
		return &this->public;
	} else {
		this->lock->destroy(this->lock);
		free(this);
		return NULL;
	}
}

/* Possibly creates, and configures a wintun device */
tun_device_t *try_configure_wintun(const char *name_tmpl)
{
	if (lib->settings->get_bool(lib->settings, "%s.use_wintun", TRUE, lib->ns)) {
		if (lib->settings->get_bool(lib->settings, "%s.delete_existing_wintun_devices", TRUE, lib->ns))
		{
			delete_existing_strongswan_wintun_devices();
		}
		tun_device_t *new_device = NULL;
		new_device = initialize_unused_wintun_device(name_tmpl);
		if (new_device)
		{
			return new_device;
		}		
	}
	return NULL;
}
