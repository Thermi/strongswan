/*
 * Copyright (C) 2008-2009 Martin Willi
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

#include "gmpdh_plugin.h"

#include <library.h>
#include "../gmp/gmp_diffie_hellman.h"

typedef struct private_gmpdh_plugin_t private_gmpdh_plugin_t;

/**
 * private data of gmp_plugin
 */
struct private_gmpdh_plugin_t {

	/**
	 * public functions
	 */
	gmpdh_plugin_t public;
};

METHOD(plugin_t, get_name, char*,
	private_gmpdh_plugin_t *this)
{
	return "gmpdh";
}

METHOD(plugin_t, get_features, int,
	private_gmpdh_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		/* DH groups */
		PLUGIN_REGISTER(DH, gmp_diffie_hellman_create),
			PLUGIN_PROVIDE(DH, MODP_2048_BIT),
				PLUGIN_DEPENDS(RNG, RNG_STRONG),
			PLUGIN_PROVIDE(DH, MODP_2048_224),
				PLUGIN_DEPENDS(RNG, RNG_STRONG),
			PLUGIN_PROVIDE(DH, MODP_2048_256),
				PLUGIN_DEPENDS(RNG, RNG_STRONG),
			PLUGIN_PROVIDE(DH, MODP_1536_BIT),
				PLUGIN_DEPENDS(RNG, RNG_STRONG),
			PLUGIN_PROVIDE(DH, MODP_3072_BIT),
				PLUGIN_DEPENDS(RNG, RNG_STRONG),
			PLUGIN_PROVIDE(DH, MODP_4096_BIT),
				PLUGIN_DEPENDS(RNG, RNG_STRONG),
			PLUGIN_PROVIDE(DH, MODP_6144_BIT),
				PLUGIN_DEPENDS(RNG, RNG_STRONG),
			PLUGIN_PROVIDE(DH, MODP_8192_BIT),
				PLUGIN_DEPENDS(RNG, RNG_STRONG),
			PLUGIN_PROVIDE(DH, MODP_1024_BIT),
				PLUGIN_DEPENDS(RNG, RNG_STRONG),
			PLUGIN_PROVIDE(DH, MODP_1024_160),
				PLUGIN_DEPENDS(RNG, RNG_STRONG),
			PLUGIN_PROVIDE(DH, MODP_768_BIT),
				PLUGIN_DEPENDS(RNG, RNG_STRONG),
		PLUGIN_REGISTER(DH, gmp_diffie_hellman_create_custom),
			PLUGIN_PROVIDE(DH, MODP_CUSTOM),
				PLUGIN_DEPENDS(RNG, RNG_STRONG),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_gmpdh_plugin_t *this)
{
	free(this);
}

/*
 * see header file
 */
plugin_t *gmpdh_plugin_create()
{
	private_gmpdh_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.destroy = _destroy,
			},
		},
	);

	return &this->public.plugin;
}

