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
 * @defgroup block_dns block_dns
 * @ingroup cplugins
 *
 * @defgroup block_dns_plugin block_dns_plugin
 * @{ @ingroup block_dns
 */

#ifndef BLOCK_DNS_PLUGIN_H_
#define BLOCK_DNS_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct block_dns_plugin_t block_dns_plugin_t;

struct block_dns_plugin_t {

	/**
	 * implements plugin interface
	 */
	plugin_t plugin;
};

#endif /** BLOCK_DNS_PLUGIN_H_ @}*/
