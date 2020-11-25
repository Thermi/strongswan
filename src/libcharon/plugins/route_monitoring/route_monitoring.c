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

#include <iphlpapi.h>
#include <winsock2.h>

#include <daemon.h>
#include "route_monitoring.h"

/** Callback fror NotifyRouteChange2
 * https://docs.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-notifyroutechange2
 * 
 */

bool route_over_vpn(private_route_monitoring_plugin_t *this,
        PMIB_IPFORWARD_ROW2 our_row)
{
    
}

bool covered_by_shunt(private_route_monitoring_plugin_t *this,
        PMIB_IPFORWARD_ROW2 our_row)
{
    
}

bool covered_by_child_sa(private_route_monitoring_plugin_t *this,
        PMIB_IPFORWARD_ROW2 our_row)
{
    
}

bool countermeasures(private_route_monitoring_plugin_t *this,
        PMIB_IPFORWARD_ROW2 our_row)
{
    
}

bool alert(private_route_monitoring_plugin_t *this,
        PMIB_IPFORWARD_ROW2 our_row)
{
    
}
CALLBACK(receive_route_update_cb, void, private_route_monitoring_plugin_t *this,
        PMIB_IPFORWARD_ROW2 received_row, MIB_NOTIFICATION_TYPE route_type)
{
    char buf[512];
    MIB_IPFORWARD_ROW2 our_row;
    memset(our_row, 0, sizeof(our_row));
    our_row = {
        .DestinationPrefix = received_row->DestinationPrefix,
        .NextHop = received_row->NextHop,
        .InterfaceLuid = received_row->InterfaceLuid,
        .InterfaceIndex = received_row->InterfaceIndex,
    };
    
    if (!GetIpForwardEntry2(&our_row))
    {
        DBG1(DBG_LIB, "Failed to get route using GetIpForwardEntry2: %s", dlerror_mt(buf, sizeof(buf)));
        return;
    }
    
    switch(route_type)
    {
        /** Fall through to MibAddInstance */
        case MibParameterNotification:
        /** Route added */
        /** Check if the route goes over the VPN interface or not */
        /** Check if it's covered by one of the shunts */
        case MibAddInstance:
        /** Route deleted */            
        case MibDeleteInstance:            
            if (!route_over_vpn(this, our_row))
            {
                if(covered_by_shunt(this, our_row) || covered_by_child_sa(this, our_row))
                {
                   countermeasures(this, our_row);                    
                   alert(this, our_row);
                }
            }
            break;
    }
}
