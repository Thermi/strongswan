/*
 * Copyright (C) 2020 Noel Kuntze for Contauro AG
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef BLOCK_DNS_FILTER_H
#define BLOCK_DNS_FILTER_H


/* Windows 7, for some fwpmu.h functionality */
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0601

//#include <winsock2.h>
#include <src/libstrongswan/utils/compat/windows.h>
#include <src/libstrongswan/utils/windows_helper.h>
#undef CALLBACK
#define CALLBACK __stdcall

#include <ipsectypes.h>

#include <ws2ipdef.h>
#include <initguid.h>
#include <fwpmu.h>
#include <fwpmtypes.h>
#include <iphlpapi.h>

#include <fwpmtypes.h>
#include <fwpmu.h>
#undef interface
#undef CALLBACK

#include <library.h>

typedef struct block_dns_filter_t block_dns_filter_t;

struct block_dns_filter_t {
    bool up;
    HANDLE engine;
    FWPM_SESSION0 session;
    NET_LUID luid;
    uint64_t filterid;
    FWP_BYTE_BLOB *strongswanblob;    
    void (*destroy)(block_dns_filter_t *this);
    bool (*change_filter)(block_dns_filter_t *this, bool up);
};

block_dns_filter_t *block_dns_filter_create();

#endif /* BLOCK_DNS_FILTER_H */

