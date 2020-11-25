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

/**
 * @defgroup route_monitoring route_monitoring
 * @ingroup cplugins
 *
 * @defgroup route_monitoring_plugin route_monitoring_plugin
 * @{ @ingroup route_monitoring
 */

#ifndef ROUTE_MONITORING_H_
#define ROUTE_MONITORING_H_

#include <plugins/plugin.h>

typedef struct route_monitoring_plugin_t route_monitoring_plugin_t;

/**
 * Plugin that writes received DNS servers in a resolv.conf file.
 */
struct route_monitoring_plugin_t {

	/**
	 * implements plugin interface
	 */
	plugin_t plugin;
};

#endif /** ROUTE_MONITORING_H_ @}*/
