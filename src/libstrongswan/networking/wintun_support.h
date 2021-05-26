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

/* 
 * File:   wintun_support.h
 * Author: thermi
 *
 * Created on 12. Mai 2020, 23:04
 */

#ifndef WINTUN_SUPPORT_H
#        define WINTUN_SUPPORT_H

#        ifdef __cplusplus
extern "C" {
#        endif

#include "windows_tun.h"
#include "tlhelp32.h"
#include "securitybaseapi.h"
    
#define TUN_PACKET_ALIGNMENT 4
#define TUN_RING_CAPACITY (16*1024*1024)
#define TUN_MAX_IP_PACKET_SIZE 0xFFFF
#define WINTUN_RING_TRAILING_BYTES 0x10000

typedef struct _TUN_PACKET_HEADER {
	uint32_t size;
} TUN_PACKET_HEADER;

typedef struct _TUN_PACKET {
    ULONG Size;
    UCHAR Data[TUN_MAX_IP_PACKET_SIZE];
} TUN_PACKET;

#define TUN_TRAILING_SIZE (sizeof(TUN_PACKET) + ((TUN_MAX_IP_PACKET_SIZE + \
    (TUN_PACKET_ALIGNMENT - 1)) &~ (TUN_PACKET_ALIGNMENT - 1)) - \
    TUN_PACKET_ALIGNMENT)

typedef struct _TUN_RING {
    volatile ULONG Head;
    volatile ULONG Tail;
    volatile LONG Alertable;
    UCHAR Data[];
} TUN_RING;

typedef struct _TUN_REGISTER_RINGS {
    struct {
        ULONG RingSize;
        TUN_RING *Ring;
        HANDLE TailMoved;
    } Send, Receive;
    /* Send ring is for data from driver to application */
    /* Receive ring is for data from application to driver */
} TUN_REGISTER_RINGS;

#define TUN_RING_SIZE (sizeof(TUN_RING) + TUN_RING_CAPACITY + 0x10000)


/* capacity must be a power of two and between 128 kiB and 64 MiB */
#define IFNAMSIZ 256

#define PNP_INSTANCE_ID "{abcde}"
#define WINTUN_COMPONENT_ID "Wintun"
/* for use with SetDeviceRegistryPropertyString */
#define STRONGSWAN_WINTUN_INTERFACE_NAME "strongSwan VPN adapter"
#define STRONGSWAN_WINTUN_DEVICE_ID "STRONGSWAN"
/* Randomly generated, globally unique GUID for the strongSwan VPN adapter*/
const static GUID GUID_WINTUN_STRONGSWAN = { 0x1f1f4dd1L, 0xe4d8, 0x487d, { 0xb7, 0xd5, 0x24, 0x93, 0xb2, 0xce, 0x0c, 0x49 } };
const static GUID GUID_INTERFACE_NET = {0xcac88484L, 0x7515, 0x4c03, {0x82, 0xe6, 0x71, 0xa8, 0x7a, 0xba, 0xc3, 0x61}};

const static char GUID_WINTUN_STRONGSWAN_STRING[] = "1f1f4dd1-e4d8-487d-b7d5-2493b2ce0c49";
/* GUIDs from openvpn tun.c code */
const static GUID GUID_DEVCLASS_NET = { 0x4d36e972L, 0xe325, 0x11ce, { 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18 } };
#define TUN_IOCTL_REGISTER_RINGS 0xca6ce5c0
//#define TUN_IOCTL_REGISTER_RINGS ((51820 << 16) | (0x970 << 2) | 0 /*METHOD_BUFFERED*/ | (0x3 /*FILE_READ_DATA | FILE_WRITE_DATA*/ << 14))
#define TUN_PACKET_TRAILING_SIZE (sizeof(uint32_t) + ((TUN_MAX_IP_PACKET_SIZE + \
    (TUN_PACKET_ALIGNMENT - 1)) &~(TUN_PACKET_ALIGNMENT - 1)) - TUN_PACKET_ALIGNMENT)
#define TUN_WRAP_POSITION(position, size) ((position & (size - 1)))
#define TUN_PACKET_ALIGN(size) ((size + (TUN_PACKET_ALIGNMENT - 1)) &~(TUN_PACKET_ALIGNMENT - 1))


tun_device_t *try_configure_wintun(const char *name_tmpl);

bool delete_existing_strongswan_wintun_devices();

#        ifdef __cplusplus
}
#        endif

#endif /* WINTUN_SUPPORT_H */

