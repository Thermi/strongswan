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

#include "route_monitoring_plugin.h"
#include "route_monitoring.h"


#include <daemon.h>

/**
 * private data of route_monitoring plugin
 */
struct private_route_monitoring_plugin_t {

	/**
	 * implements plugin interface
	 */
	route_monitoring_plugin_t public;
        
        /** GUID of the TUN device */
        char *tun;
        
        /**
         * Handle for registering and deregistering the callback
         */
        
        HANDLE callback;
};

METHOD(plugin_t, get_name, char*,
	private_route_monitoring_plugin_t *this)
{
	return "route-monitoring";
}

/**
 * Register handler
 */
static bool plugin_cb(private_route_monitoring_plugin_t *this,
					  plugin_feature_t *feature, bool reg, void *cb_data)
{
	if (reg)
	{
            if (!NotifyRouteChange2(AF_UNSPEC, receive_route_update_cb, this, FALSE, &this->callback))
            {
                DBG1(DBG_LIB, "Failed to register callback for NotifyRouteChange2");
                return FALSE;
            }
	}
	else
	{
            if (!CancelMibChangeNotify2(this->callback))
            {
                DBG1(DBG_LIB, "Failed to deregister callback for NotifyRouteChange2");
                return FALSE;
            }
	}
	return TRUE;
}

METHOD(plugin_t, get_features, int,
	private_route_monitoring_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_CALLBACK((plugin_feature_callback_t)plugin_cb, NULL),
			PLUGIN_PROVIDE(CUSTOM, "route-monitoring"),
                            PLUGIN_DEPENDS(CUSTOM, "kernel-libipsec-router"),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_route_monitoring_plugin_t *this)
{
	free(this);
}

/*
 * see header file
 */
plugin_t *route_monitoring_plugin_create()
{
	private_route_monitoring_plugin_t *this;
        tun_device_t *tun;
        lib->get(lib, "kernel-libipsec-tun", &tun);

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.destroy = _destroy,
			},
		},
                tun = tun->get_name(tun),
	);

	return &this->public.plugin;
}
