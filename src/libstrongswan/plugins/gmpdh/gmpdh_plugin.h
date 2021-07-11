/*
 * Copyright (C) 2008 Martin Willi
 * Hochschule fuer Technik Rapperswil
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
 * @defgroup gmpdh_p gmpdh
 * @ingroup plugins
 *
 * @defgroup gmpdh_plugin gmpdh_plugin
 * @{ @ingroup gmpdh_p
 */

#ifndef GMPDH_PLUGIN_H_
#define GMPDH_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct gmpdh_plugin_t gmpdh_plugin_t;

/**
 * Plugin implementing asymmetric crypto algorithms using the GNU MP library.
 */
struct gmpdh_plugin_t {

	/**
	 * implements plugin interface
	 */
	plugin_t plugin;
};

#endif /** GMPDH_PLUGIN_H_ @}*/
