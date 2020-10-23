/*
 * Copyright (C) 2009 Martin Willi
 * HSR Hochschule fuer Technik Rapperswil
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

/**
 * @defgroup win_dns win_dns
 * @ingroup cplugins
 *
 * @defgroup win_dns_plugin win_dns_plugin
 * @{ @ingroup win_dns
 */

#ifndef WIN_DNS_PLUGIN_H_
#define WIN_DNS_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct win_dns_plugin_t win_dns_plugin_t;

/**
 * Plugin that configures received DNS servers using netsh.
 */
struct win_dns_plugin_t {

	/**
	 * implements plugin interface
	 */
	plugin_t plugin;
};

#endif /** WIN_DNS_PLUGIN_H_ @}*/
