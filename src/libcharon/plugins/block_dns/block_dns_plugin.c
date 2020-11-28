/*/*
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
#include "block_dns_listener.h"
#include "block_dns_plugin.h"


#include <daemon.h>
#include <utils/debug.h>
#include <plugins/plugin_feature.h>

typedef struct private_block_dns_plugin_t private_block_dns_plugin_t;

/**
 * private data of attr_sql plugin
 */
struct private_block_dns_plugin_t {

	/**
	 * implements plugin interface
	 */
	block_dns_plugin_t public;
        
        /**
         * implements the listener
         */
        block_dns_listener_t *listener;

        /**
         * implements the filter 
         */
        
        block_dns_filter_t *filter;

};

METHOD(plugin_t, get_name, char*,
	private_block_dns_plugin_t *this)
{
	return "block-dns";
}


/**
 * Register listener
 */
static bool plugin_cb(private_block_dns_plugin_t *this,
					  plugin_feature_t *feature, bool reg, void *cb_data)
{
	if (reg)
	{
		charon->bus->add_listener(charon->bus, &this->listener->listener);
	}
	else
	{
		charon->bus->remove_listener(charon->bus, &this->listener->listener);
	}
	return TRUE;
}

METHOD(plugin_t, get_features, int,
	private_block_dns_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_CALLBACK((plugin_feature_callback_t)plugin_cb, NULL),
			PLUGIN_PROVIDE(CUSTOM, "block-dns")
        };
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_block_dns_plugin_t *this)
{
	free(this);
}

/*
 * see header file
 */
plugin_t *block_dns_plugin_create()
{
	private_block_dns_plugin_t *this;
        block_dns_filter_t *filter = block_dns_filter_create();
        block_dns_listener_t *listener = block_dns_listener_create(filter);
        
        if (!filter || !listener)
        {
            if (filter)
            {
                filter->destroy(filter);
            }
            if (listener)
            {
                listener->destroy(listener);
            }
            return NULL;
        }
        
	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.destroy = _destroy,
			},
		},
                .filter = filter,
                .listener = listener,

	);

	return &this->public.plugin;
}
