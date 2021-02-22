/*
 * Copyright (C) 2012-2013 Tobias Brunner
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

#include "kernel_libipsec_plugin.h"
#include "kernel_libipsec_ipsec.h"
#include "kernel_libipsec_router.h"

#include <daemon.h>
#include <ipsec.h>
#ifdef WIN32
#include <networking/windows_tun.h>
#else
#include <networking/tun_device.h>
#endif
#define TUN_DEFAULT_MTU 1400

typedef struct private_kernel_libipsec_plugin_t private_kernel_libipsec_plugin_t;

/**
 * private data of "kernel" libipsec plugin
 */
struct private_kernel_libipsec_plugin_t {

	/**
	 * implements plugin interface
	 */
	kernel_libipsec_plugin_t public;

	/**
	 * TUN device created by this plugin
	 */
	tun_device_t *tun;

	/**
	 * Packet router
	 */
	kernel_libipsec_router_t *router;
};

METHOD(plugin_t, get_name, char*,
	private_kernel_libipsec_plugin_t *this)
{
	return "kernel-libipsec";
}

/**
 * Create the kernel_libipsec_router_t instance
 */
static bool create_router(private_kernel_libipsec_plugin_t *this,
						  plugin_feature_t *feature, bool reg, void *arg)
{
	if (reg)
	{	/* registers as packet handler etc. */
		this->router = kernel_libipsec_router_create();
	}
	else
	{
		DESTROY_IF(this->router);
	}
	return TRUE;
}

METHOD(plugin_t, get_features, int,
	private_kernel_libipsec_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_CALLBACK(kernel_ipsec_register, kernel_libipsec_ipsec_create),
			PLUGIN_PROVIDE(CUSTOM, "kernel-ipsec"),
		PLUGIN_CALLBACK((plugin_feature_callback_t)create_router, NULL),
			PLUGIN_PROVIDE(CUSTOM, "kernel-libipsec-router"),
				PLUGIN_DEPENDS(CUSTOM, "libcharon-receiver"),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_kernel_libipsec_plugin_t *this)
{
	if (this->tun)
	{
		lib->set(lib, "kernel-libipsec-tun", NULL);
		this->tun->destroy(this->tun);
	}
	libipsec_deinit();
	free(this);
}

#ifdef WIN32
METHOD(plugin_t, reload, bool,
	private_kernel_libipsec_plugin_t *this)
{
	this->router->reload(this->router);
	return TRUE;
}
#endif
/*
 * see header file
 */
plugin_t *kernel_libipsec_plugin_create()
{
	private_kernel_libipsec_plugin_t *this;
	char buf[512];
	HANDLE pseudohandle = GetCurrentProcess();

	if (!lib->caps->check(lib->caps, CAP_NET_ADMIN))
	{	/* required to create TUN devices */
		DBG1(DBG_KNL, "kernel-libipsec plugin requires CAP_NET_ADMIN "
			 "capability");
		return NULL;
	}

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.destroy = _destroy,
#ifdef WIN32
				.reload = _reload,
#endif
			},
		},
	);

	if (!libipsec_init())
	{
		DBG1(DBG_LIB, "initialization of libipsec failed");
		destroy(this);
		return NULL;
	}

	this->tun = tun_device_create("ipsec%d");
	if (!this->tun)
	{
		DBG1(DBG_KNL, "failed to create TUN device");
		if (lib->settings->get_bool(lib->settings, "%s.use_wintun", FALSE,
					 lib->ns))
		{
			/** Windows is incredibly wonky and a lot of memory allocation
			 * goes wrong is anything goes wrong in setupapi when setting up wintun
			 * so we need to bail out here and stop the whole process.
			 * It's pointless to try to continue because the event handler won't be
			 * set up properly (queue will not be allocated, lock will be a NULL pointer, ...)
			 */
			charon->bus->alert(charon->bus, ALERT_SHUTDOWN_SIGNAL);
		}
		destroy(this);
		return NULL;
	}
	if (!this->tun->set_mtu(this->tun, TUN_DEFAULT_MTU) ||
		!this->tun->up(this->tun))
	{
		DBG1(DBG_KNL, "failed to configure TUN device");
		destroy(this);
		return NULL;
	}
	lib->set(lib, "kernel-libipsec-tun", this->tun);

	/* set TUN device as default to install VIPs */
	lib->settings->set_str(lib->settings, "%s.install_virtual_ip_on",
						   this->tun->get_name(this->tun), lib->ns);

	/* Need highest priority (not realtime for now)
	 * to make sure strongSwan can always process packets */
	if(!SetPriorityClass(pseudohandle, HIGH_PRIORITY_CLASS))
	{
		DBG1(DBG_LIB, "Failed to raise process priority: %s", dlerror_mt(buf, sizeof(buf)));
	} else {
		DBG1(DBG_LIB, "Raised process priority to HIGH_PRIORITY_CLASS");
	}
	return &this->public.plugin;
}
