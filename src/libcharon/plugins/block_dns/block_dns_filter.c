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

#include "block_dns_filter.h"

#include <daemon.h>
/*
 * WFP-related defines and GUIDs not in mingw32
 */

#ifndef FWPM_SESSION_FLAG_DYNAMIC
#define FWPM_SESSION_FLAG_DYNAMIC 0x00000001
#endif

/* c38d57d1-05a7-4c33-904f-7fbceee60e82 */
DEFINE_GUID(
    BLOCK_DNS_FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    0xc38d57d1,
    0x05a7,
    0x4c33,
    0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82
    );

/* 4a72393b-319f-44bc-84c3-ba54dcb3b6b4 */
DEFINE_GUID(
    BLOCK_DNS_FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    0x4a72393b,
    0x319f,
    0x44bc,
    0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4
    );

/* d78e1e87-8644-4ea5-9437-d809ecefc971 */
DEFINE_GUID(
    BLOCK_DNS_FWPM_CONDITION_ALE_APP_ID,
    0xd78e1e87,
    0x8644,
    0x4ea5,
    0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71
    );

/* c35a604d-d22b-4e1a-91b4-68f674ee674b */
DEFINE_GUID(
    BLOCK_DNS_FWPM_CONDITION_IP_REMOTE_PORT,
    0xc35a604d,
    0xd22b,
    0x4e1a,
    0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b
    );

/* 4cd62a49-59c3-4969-b7f3-bda5d32890a4 */
DEFINE_GUID(
    BLOCK_DNS_FWPM_CONDITION_IP_LOCAL_INTERFACE,
    0x4cd62a49,
    0x59c3,
    0x4969,
    0xb7, 0xf3, 0xbd, 0xa5, 0xd3, 0x28, 0x90, 0xa4
    );


/* 1247d66d-0b60-4a15-8d44-7155d0f53a0c */
DEFINE_GUID(
   BLOCK_DNS_FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4,
   0x1247d66d,
   0x0b60,
   0x4a15,
   0x8d, 0x44, 0x71, 0x55, 0xd0, 0xf5, 0x3a, 0x0c
);

/* 0b5812a2-c3ff-4eca-b88d-c79e20ac6322 */
DEFINE_GUID(
   BLOCK_DNS_FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4_DISCARD,
   0x0b5812a2,
   0xc3ff,
   0x4eca,
   0xb8, 0x8d, 0xc7, 0x9e, 0x20, 0xac, 0x63, 0x22
);

/* 55a650e1-5f0a-4eca-a653-88f53b26aa8c */
DEFINE_GUID(
   BLOCK_DNS_FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6,
   0x55a650e1,
   0x5f0a,
   0x4eca,
   0xa6, 0x53, 0x88, 0xf5, 0x3b, 0x26, 0xaa, 0x8c
);

/* cbc998bb-c51f-4c1a-bb4f-9775fcacab2f */
DEFINE_GUID(
   BLOCK_DNS_FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6_DISCARD,
   0xcbc998bb,
   0xc51f,
   0x4c1a,
   0xbb, 0x4f, 0x97, 0x75, 0xfc, 0xac, 0xab, 0x2f
);


/* c6e63c8c-b784-4562-aa7d-0a67cfcaf9a3 */
DEFINE_GUID(
   BLOCK_DNS_FWPM_LAYER_ALE_CONNECT_REDIRECT_V4,
   0xc6e63c8c,
   0xb784,
   0x4562,
   0xaa, 0x7d, 0x0a, 0x67, 0xcf, 0xca, 0xf9, 0xa3
);

/* 587e54a7-8046-42ba-a0aa-b716250fc7fd */
DEFINE_GUID(
   BLOCK_DNS_FWPM_LAYER_ALE_CONNECT_REDIRECT_V6,
   0x587e54a7,
   0x8046,
   0x42ba,
   0xa0, 0xaa, 0xb7, 0x16, 0x25, 0x0f, 0xc7, 0xfd
);


/* 3971ef2b-623e-4f9a-8cb1-6e79b806b9a7 */
DEFINE_GUID(
   BLOCK_DNS_FWPM_CONDITION_IP_PROTOCOL,
   0x3971ef2b,
   0x623e,
   0x4f9a,
   0x8c, 0xb1, 0x6e, 0x79, 0xb8, 0x06, 0xb9, 0xa7
);


/* UUID of WFP sublayer used by all instances of strongSwan
 * ce1a169a-09fe-400e-816f-c49d806c0a7c */
DEFINE_GUID(
    STRONGSWAN_BLOCK_OUTSIDE_DNS_SUBLAYER,
    0xce1a169a,
    0x09fe,
    0x400e,
    0x81, 0x6f, 0xc4, 0x9d, 0x80, 0x6c, 0x0a, 0x7c
    );

static WCHAR *FIREWALL_NAME = L"strongSwan";

/*
 * Add a persistent sublayer with specified uuid.
 */
static DWORD
add_sublayer(block_dns_filter_t *this, GUID uuid)
{
    FWPM_SUBLAYER0 sublayer;

    memset(&sublayer, 0, sizeof(sublayer));

    sublayer.subLayerKey = uuid;
    sublayer.displayData.name = FIREWALL_NAME;
    sublayer.displayData.description = FIREWALL_NAME;
    sublayer.flags = 0;
    sublayer.weight = 0x100;

    /* Add sublayer to the session */
    return FwpmSubLayerAdd0(this->engine, &sublayer, NULL);
}

/*
 * Block outgoing port 53 traffic except for
 * (i) adapter with the specified index
 * OR
 * (ii) processes with the specified executable path
 * The firewall filters added here are automatically removed when the process exits or
 * on calling delete_block_dns_filters().
 * Arguments:
 *   engine_handle : On successful return contains the handle for a newly opened fwp session
 *                   in which the filters are added.
 *                   May be closed by passing to delete_block_dns_filters to remove the filters.
 *   index         : The index of adapter for which traffic is permitted.
 *   msg_handler   : An optional callback function for error reporting.
 * Returns 0 on success, a non-zero status code of the last failed action on failure.
 */

DWORD add_block_dns_filters(block_dns_filter_t *this)
{
    FWPM_SUBLAYER0 *sublayer_ptr = NULL;
    FWPM_FILTER0 Filter = {0};
    FWPM_FILTER_CONDITION0 Condition[4] = {0};
    DWORD err = 0;

    /* Check sublayer exists and add one if it does not. */
    if (FwpmSubLayerGetByKey0(this->engine, &STRONGSWAN_BLOCK_OUTSIDE_DNS_SUBLAYER,
            &sublayer_ptr) == ERROR_SUCCESS)
    {
        DBG2(DBG_LIB, "block-dns: Using existing sublayer");
        FwpmFreeMemory0((void **)&sublayer_ptr);
    }
    else
    {  /* Add a new sublayer -- as another process may add it in the meantime,
        * do not treat "already exists" as an error */
        err = add_sublayer(this, STRONGSWAN_BLOCK_OUTSIDE_DNS_SUBLAYER);

        if (err == FWP_E_ALREADY_EXISTS || err == ERROR_SUCCESS)
        {
            DBG2(DBG_LIB, "block-dns: Added a persistent sublayer with pre-defined UUID");
        }
        else
        {
            DBG1(DBG_LIB, "block-dns: add_sublayer: failed to add persistent sublayer");
        }
    }
    
    /* Prepare filter. */
    Filter.subLayerKey = STRONGSWAN_BLOCK_OUTSIDE_DNS_SUBLAYER;
    Filter.filterCondition = Condition;
    Filter.numFilterConditions = 3;
    Filter.displayData.name = FIREWALL_NAME;
    Filter.weight.type = FWP_UINT8;
    Filter.weight.uint8 = 0xF;
    Filter.action.type = FWP_ACTION_PERMIT;

    
    /* Prepare filters for permitting DNS queries to TUN interface */
    Condition[0].fieldKey = BLOCK_DNS_FWPM_CONDITION_IP_REMOTE_PORT;
    Condition[0].matchType = FWP_MATCH_EQUAL;
    Condition[0].conditionValue.type = FWP_UINT16;
    Condition[0].conditionValue.uint16 = htons(53);

    Condition[1].fieldKey = BLOCK_DNS_FWPM_CONDITION_IP_LOCAL_INTERFACE;
    Condition[1].matchType = FWP_MATCH_EQUAL;
    Condition[1].conditionValue.type = FWP_UINT64;
    Condition[1].conditionValue.byteBlob = NULL;
    Condition[1].conditionValue.uint64 = &this->luid.Value;
    
    /* Match on UDP */
    Condition[2].fieldKey = BLOCK_DNS_FWPM_CONDITION_IP_PROTOCOL;
    Condition[2].matchType = FWP_MATCH_EQUAL;
    Condition[2].conditionValue.type = FWP_UINT8;
    Condition[2].conditionValue.uint8 = 17;
    
    /* DNS queries over TUN, IPv4, and UDP */
    Filter.layerKey = BLOCK_DNS_FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4;
    if ((err=FwpmFilterAdd0(this->engine, &Filter, NULL, &this->filterid))) {
        DBG1(DBG_LIB, "block-dns: Add filter to permit IPv4 DNS traffic through TUN failed: %s", strerror(err));
    }
    
    /* DNS queries over TUN and IPv6, and UDP */
    Filter.layerKey = BLOCK_DNS_FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6;
    if ((err=FwpmFilterAdd0(this->engine, &Filter, NULL, &this->filterid))) {
        DBG1(DBG_LIB, "block-dns: Add filter to permit IPv6 DNS traffic through TUN failed: %s", strerror(err));
    }

    Filter.weight.uint8 = 0xE;

    /* Match on TCP */
    Condition[2].conditionValue.uint8 = 6;

    /* DNS queries over TUN, IPv4, and TCP */
    Filter.layerKey = BLOCK_DNS_FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4;
    if ((err=FwpmFilterAdd0(this->engine, &Filter, NULL, &this->filterid))) {
        DBG1(DBG_LIB, "block-dns: Add filter to permit IPv4 DNS traffic through TUN failed: %s", strerror(err));
    }
    
    /* DNS queries over TUN and IPv6, and TCP */
    Filter.layerKey = BLOCK_DNS_FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6;
    if ((err=FwpmFilterAdd0(this->engine, &Filter, NULL, &this->filterid))) {
        DBG1(DBG_LIB, "block-dns: Add filter to permit IPv6 DNS traffic through TUN failed: %s", strerror(err));
    }

    
    DBG2(DBG_LIB, "block-dns: Added permit filters for TUN interface");

    Filter.weight.uint8 = 0xD;
    /* Prepare filter to permit DNS packets from strongSwan */
    Condition[1].fieldKey = BLOCK_DNS_FWPM_CONDITION_ALE_APP_ID;
    Condition[1].matchType = FWP_MATCH_EQUAL;
    Condition[1].conditionValue.type = FWP_BYTE_BLOB_TYPE;
    Condition[1].conditionValue.byteBlob = this->strongswanblob;
    
    /* Permit strongSwan DNS queries over IPv4, and TCP */
    Filter.layerKey = BLOCK_DNS_FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    if ((err=FwpmFilterAdd0(this->engine, &Filter, NULL, &this->filterid)))
    {
        DBG1(DBG_LIB, "block-dns: Add filter to permit IPv4 port 53 traffic from strongSwan failed: %s", strerror(err));
    }
    
    /* Permit strongSwan DNS queries over IPv6, and TCP */
    Filter.layerKey = BLOCK_DNS_FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    if ((err=FwpmFilterAdd0(this->engine, &Filter, NULL, &this->filterid))) {
        DBG1(DBG_LIB, "block-dns: Add filter to permit IPv6 port 53 traffic from strongSwan failed: %s", strerror(err));
    }

    Condition[2].conditionValue.uint8 = 17;
        
    /* Permit strongSwan DNS queries over IPv4, and UDP */
    Filter.layerKey = BLOCK_DNS_FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    if ((err=FwpmFilterAdd0(this->engine, &Filter, NULL, &this->filterid)))
    {
        DBG1(DBG_LIB, "block-dns: Add filter to permit IPv4 port 53 traffic from strongSwan failed: %s", strerror(err));
    }
    
    /* Permit strongSwan DNS queries over IPv6, and UDP */
    Filter.layerKey = BLOCK_DNS_FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    if ((err=FwpmFilterAdd0(this->engine, &Filter, NULL, &this->filterid))) {
        DBG1(DBG_LIB, "block-dns: Add filter to permit IPv6 port 53 traffic from strongSwan failed: %s", strerror(err));
    }

    DBG2(DBG_LIB, "block-dns: Added permit filters for exe_path");
    
    /* Prepare filter to block any DNS packets */
    Filter.weight.uint8 = 0xD;
    Filter.layerKey = BLOCK_DNS_FWPM_LAYER_ALE_CONNECT_REDIRECT_V4;
    Filter.numFilterConditions = 2;
    Filter.action.type = FWP_ACTION_BLOCK;
    Condition[0].fieldKey = BLOCK_DNS_FWPM_CONDITION_IP_REMOTE_PORT;
    Condition[0].matchType = FWP_MATCH_EQUAL;
    Condition[0].conditionValue.type = FWP_UINT16;
    Condition[0].conditionValue.uint16 = htons(53);
    Condition[1].fieldKey = BLOCK_DNS_FWPM_CONDITION_IP_LOCAL_INTERFACE;
    Condition[1].matchType = FWP_MATCH_NOT_EQUAL;
    Condition[1].conditionValue.type = FWP_UINT64;
    Condition[1].conditionValue.byteBlob = NULL;
    Condition[1].conditionValue.uint64 = &this->luid.Value;

    /* Drop DNS packets over IPv4, and UDP*/
    Filter.layerKey = BLOCK_DNS_FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    if ((err=FwpmFilterAdd0(this->engine, &Filter, NULL, &this->filterid)))
    {
        DBG1(DBG_LIB, "block-dns: Add filter to drop all IPv4 port 53 traffic failed: %s", strerror(err));
    }

    /* Drop DNS packets over IPv6, and UDP */
    Filter.layerKey = BLOCK_DNS_FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    if ((err=FwpmFilterAdd0(this->engine, &Filter, NULL, &this->filterid)))
    {
        DBG1(DBG_LIB, "block-dns: Add filter to drop all IPv6 port 53 traffic failed: %s", strerror(err));
    }


    Condition[2].conditionValue.uint8 = 6;
    /* Drop DNS packets over IPv4, and TCP */
    Filter.layerKey = BLOCK_DNS_FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    if ((err=FwpmFilterAdd0(this->engine, &Filter, NULL, &this->filterid)))
    {
        DBG1(DBG_LIB, "block-dns: Add filter to drop all IPv4 port 53 traffic failed: %s", strerror(err));
    }

    /* Drop DNS packets over IPv6, and TCP */
    Filter.layerKey = BLOCK_DNS_FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    if ((err=FwpmFilterAdd0(this->engine, &Filter, NULL, &this->filterid)))
    {
        DBG1(DBG_LIB, "block-dns: Add filter to drop all IPv6 port 53 traffic failed: %s", strerror(err));
    }

    DBG2(DBG_LIB, "block-dns: Added block filters for all interfaces");

    return err;
}

METHOD(block_dns_filter_t, change_filter, bool, block_dns_filter_t *this, bool up)
{
    if (up && !this->up)
    {
        add_block_dns_filters(this);
    } else if (!up && this->up) {
        if (!FwpmFilterDeleteById0(this->engine, this->filterid))
        {
            DBG1(DBG_LIB, "block-dns: Failed to delete filter by id %llu", this->filterid);
            return FALSE;
        }
    }
    return TRUE;
}

bool guid2luid(char *guid_str, NET_LUID *luid)
{
    GUID guid;
    if (!guidfromstring(&guid, guid_str, TRUE))
    {
        DBG1(DBG_LIB, "Failed to convert GUID %s to GUID object", guid_str);
        return FALSE;
    }
    luid = malloc(sizeof(*luid));
    if (ConvertInterfaceGuidToLuid((const GUID *)&guid, luid ))
    {
        DBG1(DBG_LIB, "Failed to convert GUID to LUID");
        free(luid);
        return FALSE;
    }
    return TRUE;
}
METHOD(block_dns_filter_t, destroy, void, block_dns_filter_t *this)
{
    FwpmFreeMemory0((void **)&this->strongswanblob);    
    if (this->engine)
    {
        FwpmEngineClose0(this->engine);
    }
    free(this);
}

block_dns_filter_t *block_dns_filter_create()
{
    block_dns_filter_t *this;
    wchar_t exe[512];
    tun_device_t *tun;
    tun = lib->get(lib, "kernel-libipsec-tun");
    char *tun_guid = tun->get_name(tun);
    
    INIT(this,
        .change_filter = _change_filter,
        .destroy = _destroy,
        .up = FALSE,
        .filterid = 0,
    );
    if (!guid2luid(tun_guid, &this->luid))
    {
        free(this);
        return NULL;
    }
    if (!GetModuleFileNameW(NULL, exe, sizeof(exe)))
    {
        DBG1(DBG_LIB, "block-dns: Failed to get path to own executable");
        free(this);
        return NULL;
    }    
    FwpmGetAppIdFromFileName0(exe, &this->strongswanblob);

    this->session.flags = FWPM_SESSION_FLAG_DYNAMIC;

    if(!FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &this->session, &this->engine))
    {
        DBG1(DBG_LIB, "block-dns: Failed to open fwp session");
    }    
    
    return this;
}