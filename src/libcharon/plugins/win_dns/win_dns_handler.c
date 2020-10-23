/*
 * Copyright (C) 2012-2016 Tobias Brunner
 * Copyright (C) 2009 Martin Willi
 * HSR Hochschule fuer Technik Rapperswil
 * 
 * Copyright (C) 2020 Noel Kuntze
 * Contauro AG
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

#include <winsock2.h>
#include <netioapi.h>

#include "win_dns_handler.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <daemon.h>
#include <utils/debug.h>
#include <utils/process.h>
#include <utils/windows_helper.h>

#include <collections/array.h>
#include <threading/mutex.h>


typedef struct private_win_dns_handler_t private_win_dns_handler_t;


/**
 * Private data of an win_dns_handler_t object.
 */
struct private_win_dns_handler_t {

	/**
	 * Public win_dns_handler_t interface.
	 */
	win_dns_handler_t public;

	/**
	 * Mutex to access file exclusively
	 */
	mutex_t *mutex;

	/**
	 * list to keep DNS servers in
	 */
	linked_list_t *servers;
	
	/**
	 * Counter to keep order of installation
	 */
	size_t cnt;
};


typedef struct {

	/**
	 * DNS server address
	 */
	host_t *address;

	/**
	 * The interface index the DNS server is assigned to
	 */
	NET_IFINDEX index;
	
	/**
	 * Keeps track of order of installation
	 */
	size_t priority;
	
	/**
	 * Unique ID to identify the IKE_SA this came from by
	 */
	uint32_t unique_id;

} dns_server_t;

/**
 * Generate the path to netsh
 * @return	pointer to allocated string with the path, or NULL if it failed
 */
char *generate_netsh_path()
{	
	char *path = malloc(MAX_PATH*sizeof(char)), *exe = "system32\\netsh.exe";
	int len = GetSystemWindowsDirectory(path, MAX_PATH);
	if (len == 0 || len >= sizeof(path) - strlen(exe))
	{
		DBG1(DBG_LIB, "resolving Windows directory failed: 0x%08x",
			 GetLastError());
		free(path);
		return NULL;
	}
	if (path[len + 1] != '\\')
	{
		strncat(path, "\\", sizeof(path) - len++);
	}
	strncat(path, exe, sizeof(path) - len);
	return path;
}

/**
 * Finds the newest DNS server
 */
static dns_server_t *find_newest_server(private_win_dns_handler_t *this, char *index)
{
	dns_server_t *entry, *best_candidate = NULL;
	enumerator_t *enumerator = this->servers->create_enumerator(this->servers);
	
	while(enumerator->enumerate(enumerator, &entry))
	{
		if (best_candidate)
		{
			if (entry->priority > best_candidate->priority && entry->index == best_candidate->index)
			{
				best_candidate = entry;
			}
		} else {
			best_candidate = entry;
		}
	}
	enumerator->destroy(enumerator);
	
	return best_candidate;
}

static bool compare_dns_servers_by_unique_id_and_address(void *a, void *b)
{
	dns_server_t *da = a;
	dns_server_t *db = b;
	return da->unique_id == db->unique_id && da->address == db->address;
}

/**
 * Install the DNS server on the interface specified in %s.
 */
static bool set_dns_server(private_win_dns_handler_t *this, host_t *addr, NET_IFINDEX index) {
	int ret;
	char *netsh_path = generate_netsh_path();
	process_t *process;
	
	if (!netsh_path)
	{
		DBG1(DBG_LIB, "Failed to generate netsh path");
		return FALSE;
	}
	
	if (addr->get_family(addr) == AF_INET)
	{
		process = process_start_shell(NULL, NULL, NULL, NULL,
					 "%s interface ipv4 set dns %d static 172.16.25.1 none no",
		netsh_path, index, addr);
	} else {
		process = process_start_shell(NULL, NULL, NULL, NULL,
					 "%s interface ipv6 set dns %d static %H none no",
		netsh_path, index, addr);
	}
	free(netsh_path);
	if (process) {
		process->wait(process, &ret);
		if (ret) {
			DBG1(DBG_IKE, "Failed to handle DNS server: ret=%d", ret);
			return FALSE;
		}
	} else {
		DBG1(DBG_IKE, "Failed to handle DNS server, netsh process could not"
			"be started");
		return FALSE;
	}
	return TRUE;
}

static bool clear_dns_server(host_t *addr, NET_IFINDEX index)
{
	int ret;
	char *netsh_path = generate_netsh_path();
	process_t *process;
	if (!netsh_path)
	{
		DBG1(DBG_LIB, "Failed to generate netsh path");
		return FALSE;
	}
	if (addr->get_family(addr) == AF_INET)
	{
		process = process_start_shell(NULL, NULL, NULL, NULL,
					 "%s interface ipv4 set dns %d clear",
					 netsh_path, index);
	} else {
		process = process_start_shell(NULL, NULL, NULL, NULL,
					 "%s interface ipv6 set dns %d clear",
					 netsh_path, index);
	}
	
	free(netsh_path);
	if (process) {
		process->wait(process, &ret);
		if (ret) {
			free(netsh_path);
			DBG1(DBG_IKE, "Failed to handle DNS server: ret=%d",
				ret);
			return FALSE;
		}
	} else {

			DBG1(DBG_IKE, "Failed to handle DNS server,"
				"netsh process could not be spawned");
			return FALSE;
	}
	
	return TRUE;
}
/**
 * Translates GUID to interface index so it can be used by netsh
 */
static bool guid2index(GUID guid, NET_IFINDEX *index)
{
	NET_LUID interface_luid;
	NETIO_STATUS ret;
	char buf[512];
	if((ret=ConvertInterfaceGuidToLuid(&guid, &interface_luid)) != NO_ERROR)
	{
		DBG1(DBG_NET, "Failed to convert GUID to LUID (%d): %s",
			ret, dlerror_mt(buf, sizeof(buf)));
		return FALSE;
	}
	if((ret=ConvertInterfaceLuidToIndex(&interface_luid, index)) != NO_ERROR)
	{
		switch(ret)
		{
			case ERROR_INVALID_PARAMETER:
				DBG1(DBG_NET, "Failed to convert LUID to index:"
					" Invalid Parameter");
				break;
			default:
				DBG1(DBG_NET, "Failed to convert LUID to index "
					"(%d): %s", ret, dlerror_mt(buf, 
						sizeof(buf)));
				break;
		}
		return FALSE;
	}
	return TRUE;
	
}

METHOD(attribute_handler_t, handle, bool,
	private_win_dns_handler_t *this, ike_sa_t *ike_sa,
	configuration_attribute_type_t type, chunk_t data)
{
	dns_server_t *found = NULL;
	host_t *addr;
	NET_IFINDEX index;
	char *iface;
	GUID guid;
	bool handled;

	switch (type)
	{
		case INTERNAL_IP4_DNS:
			addr = host_create_from_chunk(AF_INET, data, 0);
			break;
		case INTERNAL_IP6_DNS:
			addr = host_create_from_chunk(AF_INET6, data, 0);
			break;
		default:
			return FALSE;
	}

	if (!addr || addr->is_anyaddr(addr))
	{
		DESTROY_IF(addr);
		return FALSE;
	}
	/* Check if we use a tun device and if we do, install the DNS server there */
	if (lib->get(lib, "kernel-libipsec-tun"))
	{
		iface=lib->settings->get_str(lib->settings, "%s.install_virtual_ip_on",
						   NULL, lib->ns);
	} else {
		if (!charon->kernel->get_interface(charon->kernel,
			ike_sa->get_my_host(ike_sa), &iface))
		{
			DBG1(DBG_IKE, "Can't install DNS server, interface does not exist!");
			return FALSE;
		}
	}
	
	if (!guidfromstring(&guid, iface, TRUE))
	{
		return FALSE;
	}
	if(!guid2index(guid, &index))
	{
		return FALSE;
	}
		
	this->mutex->lock(this->mutex);
	/** Check if the interface currently has a DNS server. If so, store
	    it in the linked list */

	handled = set_dns_server(this, addr, index);
	if (handled)
	{
		INIT(found,
			.address = addr->clone(addr),
			.index = index,
			.priority = this->cnt++,
			.unique_id = ike_sa->get_unique_id(ike_sa),
		);
		this->servers->insert_last(this->servers, found);
	}
	
	this->mutex->unlock(this->mutex);
	addr->destroy(addr);

	if (!handled)
	{
		DBG1(DBG_IKE, "adding DNS server failed");
	} else {
		DBG1(DBG_IKE, "Added DNS server %H on interface %d", addr, index);
	}
	return handled;
}

METHOD(attribute_handler_t, release, void,
	private_win_dns_handler_t *this, ike_sa_t *ike_sa,
	configuration_attribute_type_t type, chunk_t data)
{
	dns_server_t *found = NULL, *entry;
	host_t *addr;
	char *iface;
	int family;
	GUID guid;
	NET_IFINDEX index;

	switch (type)
	{
		case INTERNAL_IP4_DNS:
			family = AF_INET;
			break;
		case INTERNAL_IP6_DNS:
			family = AF_INET6;
			break;
		default:
			return;
	}
	addr = host_create_from_chunk(family, data, 0);

	/* Check if we use a tun device and if we do, install the DNS server there */
	if (lib->get(lib, "kernel-libipsec-tun"))
	{
		iface=lib->settings->get_str(lib->settings, "%s.install_virtual_ip_on",
						   NULL, lib->ns);
	} else {
		if (!charon->kernel->get_interface(charon->kernel,
			ike_sa->get_my_host(ike_sa), &iface))
		{
			DBG1(DBG_IKE, "Can't remove DNS server, interface does not exist!");
			addr->destroy(addr);
			return;
		}
	}
		
	if (!guidfromstring(&guid, iface, TRUE))
	{
		return;
	}

	if (!guid2index(guid, &index))
	{
		DBG1(DBG_IKE, "Can't remove DNS server, failed to convert guid to index");
		addr->destroy(addr);
		return;
	}
	this->mutex->lock(this->mutex);

	/** Look for the DNS server installed from this unique_id and check if it is 
	 * the best one.
	 * If it is the best one, remove it from the list, look for the next best one and install that one, if it exists.
	 * Otherwise, just clear the DNS servers for that interface (because right now,
	 * this plugin can only install one DNS server on an interface (restriction caused by netsh)
	 */
	
	INIT(found,
		.address = addr,
		.index = index,
		.unique_id = ike_sa->get_unique_id(ike_sa),
	);
	if(!this->servers->remove(this->servers, found, compare_dns_servers_by_unique_id_and_address))
	{
		DBG1(DBG_IKE, "Failed to find DNS server in list.");
	} else {
		DBG1(DBG_IKE, "Removed DNS server %H from interface %d", addr, index);
	}
	
	entry = find_newest_server(this, iface);
	if (entry)
	{

		if (set_dns_server(this, entry->address, index))
		{
			DBG1(DBG_IKE, "Installed now newest DNS server %H on"
				" interface %d", addr, index);
		}
	} else {
		if (clear_dns_server(addr, index))
		{
			DBG1(DBG_IKE, "Cleared all DNS servers from interface"
				" %d", index);
		}
	}
	
	this->mutex->unlock(this->mutex);
	free(found);
	addr->destroy(addr);
}

/**
 * Attribute enumerator implementation
 */
typedef struct {
	/** implements enumerator_t interface */
	enumerator_t public;
	/** request IPv4 DNS? */
	bool v4;
	/** request IPv6 DNS? */
	bool v6;
} attribute_enumerator_t;

METHOD(enumerator_t, attribute_enumerate, bool,
	attribute_enumerator_t *this, va_list args)
{
	configuration_attribute_type_t *type;
	chunk_t *data;

	VA_ARGS_VGET(args, type, data);
	if (this->v4)
	{
		*type = INTERNAL_IP4_DNS;
		*data = chunk_empty;
		this->v4 = FALSE;
		return TRUE;
	}
	if (this->v6)
	{
		*type = INTERNAL_IP6_DNS;
		*data = chunk_empty;
		this->v6 = FALSE;
		return TRUE;
	}
	return FALSE;
}

/**
 * Check if a list has a host of given family
 */
static bool has_host_family(linked_list_t *list, int family)
{
	enumerator_t *enumerator;
	host_t *host;
	bool found = FALSE;

	enumerator = list->create_enumerator(list);
	while (enumerator->enumerate(enumerator, &host))
	{
		if (host->get_family(host) == family)
		{
			found = TRUE;
			break;
		}
	}
	enumerator->destroy(enumerator);

	return found;
}

METHOD(attribute_handler_t, create_attribute_enumerator, enumerator_t*,
	private_win_dns_handler_t *this, ike_sa_t *ike_sa,
	linked_list_t *vips)
{
	attribute_enumerator_t *enumerator;

	INIT(enumerator,
		.public = {
			.enumerate = enumerator_enumerate_default,
			.venumerate = _attribute_enumerate,
			.destroy = (void*)free,
		},
		.v4 = has_host_family(vips, AF_INET),
		.v6 = has_host_family(vips, AF_INET6),
	);
	return &enumerator->public;
}

METHOD(win_dns_handler_t, destroy, void,
	private_win_dns_handler_t *this)
{
	this->servers->destroy(this->servers);
	this->mutex->destroy(this->mutex);
	free(this);
}

/**
 * See header
 */
win_dns_handler_t *win_dns_handler_create()
{
	private_win_dns_handler_t *this;

	INIT(this,
		.public = {
			.handler = {
				.handle = _handle,
				.release = _release,
				.create_attribute_enumerator = _create_attribute_enumerator,
			},
			.destroy = _destroy,
		},
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
		.cnt = 0,
		.servers = linked_list_create(),
	);
	return &this->public;
}
