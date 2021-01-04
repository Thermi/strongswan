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
#include <iphlpapi.h>
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
 * Get the currently configured DNS servers of an interface, specified by IF_INDEX
 * @param	index
 * @return	linked_list_t containing the DNS server addresses as host_t, each allocated seperately
 */
linked_list_t *get_dns_servers(IF_INDEX index)
{
	linked_list_t *list = linked_list_create();
	host_t *dns_server_addr;
	chunk_t chk;
	char buf[512];
	DWORD dwRetVal = 0;

	uint32_t i = 0;

	// default to unspecified address family (both)
	ULONG family = AF_UNSPEC;

	PIP_ADAPTER_ADDRESSES pAddresses = NULL;
	ULONG outBufLen = 15000;
	ULONG Iterations = 0;

	PIP_ADAPTER_ADDRESSES pCurrAddresses = NULL;
	IP_ADAPTER_DNS_SERVER_ADDRESS *pDNSServer = NULL;

	SOCKADDR_IN *sin;
	SOCKADDR_IN6 *sin6;
	do {

	    pAddresses = (IP_ADAPTER_ADDRESSES *) malloc(outBufLen);
	    if (pAddresses == NULL) {
		    DBG1(DBG_LIB, "Memory allocation failed for IP_ADAPTER_ADDRESSES struct");
		return list;
	    }

	    dwRetVal =
		GetAdaptersAddresses(family, GAA_FLAG_INCLUDE_PREFIX, NULL, pAddresses, &outBufLen);

	    if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
		free(pAddresses);
		pAddresses = NULL;
	    } else {
		break;
	    }

	    Iterations++;

	} while ((dwRetVal == ERROR_BUFFER_OVERFLOW) && (Iterations < 5));

	if (dwRetVal == NO_ERROR) {
	    // If successful, output some information from the data we received
	    pCurrAddresses = pAddresses;
	    while (pCurrAddresses) {
		if (pCurrAddresses->IfIndex == index) {
		    pDNSServer = pCurrAddresses->FirstDnsServerAddress;
		    if (pDNSServer) {
			family = AF_UNSPEC;
			for (i = 0; pDNSServer != NULL; i++) {
				switch (pDNSServer->Address.iSockaddrLength)
				{
					/* Old style sockaddr */
					/*
					case sizeof(SOCKADDR):
						DBG1(DBG_LIB, "Old style sockaddr");
						family = pDNSServer->Address.lpSockaddr->sa_family;
						switch(family)
						{
							case AF_INET:
								chk.ptr = pDNSServer->Address.lpSockaddr->sa_data;
								chk.len = sizeof(pDNSServer->Address.lpSockaddr->sa_data);
								break;
							case AF_INET6:
								sin6 = (SOCKADDR_IN6 *) pDNSServer->Address.lpSockaddr;
								chk.ptr = &sin6->sin6_addr;
								chk.len = sizeof(sin6->sin6_addr);
								break;
							default:
								DBG1(DBG_LIB, "Unknown address family %u", family);
								chk.ptr = NULL;
								chk.len = 0;
								break;
						}
						break;
						*/
					/* New style sockaddr */
					case sizeof(SOCKADDR_IN):
					case sizeof(SOCKADDR_IN6):
						sin = (SOCKADDR_IN *) pDNSServer->Address.lpSockaddr;
						sin6 = (SOCKADDR_IN6 *) pDNSServer->Address.lpSockaddr;
						family = sin->sin_family;
						switch(family)
						{
							/* IPv4 struct */
							case AF_INET:
								chk.ptr = (void *) &sin->sin_addr;
								chk.len = sizeof(sin->sin_addr);
								break;
							/* IPv6 struct */
							case AF_INET6:
								chk.ptr = (void *) &sin6->sin6_addr;
								chk.len = sizeof(sin6->sin6_addr);
								break;
							/** Different socket
							 * family,
							 * can't handle that */	
							default:
								DBG1(DBG_LIB, "Unknown address family %u", family);
								chk.ptr = NULL;
								chk.len = 0;
								break;
						}
						break;
					default:
						DBG1(DBG_LIB, "Unknown struct size %d", pDNSServer->Address.iSockaddrLength);
						chk.ptr = NULL;
						chk.len = 0;
						family = AF_UNSPEC;
						break;
						/** Unknown size, abort */
				}
				if (chk.ptr)
				{
					dns_server_addr = host_create_from_chunk(family, chk, 0);
					list->insert_last(list, dns_server_addr);
				}

				pDNSServer = pDNSServer->Next;
				}
			}
		    }
		pCurrAddresses = pCurrAddresses->Next;
	    }
	} else {
		DBG1(DBG_LIB, "Call to GetAdaptersAddresses failed with error: %u",
		       dwRetVal);
		if (dwRetVal == ERROR_NO_DATA) {
		    DBG1(DBG_LIB, "No addresses were found for the requested parameters");
		} else {
			DBG1(DBG_LIB, "Detailed error message: %s", dlerror_mt(buf, sizeof(buf)));
			if (pAddresses) {
			    free(pAddresses);
			}
		}
	}

	if (pAddresses) {
	    free(pAddresses);
	}


	return list;
}
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
	return da->unique_id == db->unique_id && da->address->equals(da->address, db->address);
}

/*
static bool compare_dns_servers_by_address_and_ifindex(void *a, void *b)
{
	dns_server_t *da = a;
	dns_server_t *db = b;
	DBG1(DBG_LIB, "da: %p db: %p *db: %p", da, db, *db);
	return da->address->equals(da->address, db->address) && da->index == db->index;
}
 * linked_list_match_t
*/

CALLBACK(compare_dns_servers_by_address_and_ifindex, bool, void *item, va_list args)
{
	dns_server_t *a, *b = item;
	VA_ARGS_VGET(args, a);
	return a->address->equals(a->address, b->address) && a->index == b->index;
}

static bool compare_dns_servers_by_address_ifindex_priority(void *a, void *b)
{
	dns_server_t *da = a;
	dns_server_t *db = b;
	return da->address->equals(da->address, db->address) && da->index == db->index
		&& da->priority == db->priority;
}

/**
 * 
 * @param this
 * @param index
 */
static void store_existing_dns_server(private_win_dns_handler_t *this, NET_IFINDEX index)
{
	linked_list_t *existing_dns_servers = get_dns_servers(index), *to_store = linked_list_create();
	enumerator_t *enumerator;
	host_t *dns_server;
	dns_server_t *dns_server_test_candidate = NULL, *ret = NULL;

	if (!existing_dns_servers)
	{
		return;
	}
	enumerator = existing_dns_servers->create_enumerator(existing_dns_servers);
	bool store = FALSE;
	/* Check if any of the DNS servers is already stored */
	while(enumerator->enumerate(enumerator, &dns_server))
	{
		INIT(dns_server_test_candidate,
			.address = dns_server,
			.index = index,
			.priority = 0,
		);
		store = FALSE;
		/* Check if that particular DNS server is stored at all */
		if(!this->servers->find_first(this->servers, compare_dns_servers_by_address_and_ifindex, (void **)&ret, (void **)dns_server_test_candidate))
		{
			/* It's not stored, so it's not added by an IKE_SA, so
			 so it can only be from the original config */
			store = TRUE;
		}
		if (store)
		{
			/* Clone the settings and store them */
			dns_server_test_candidate->address = dns_server->clone(dns_server);
			dns_server_test_candidate->unique_id = 0;
			dns_server_test_candidate->priority = 0;
			to_store->insert_last(to_store, dns_server_test_candidate);
		} else {
			free(dns_server_test_candidate);
		}
		dns_server_test_candidate = NULL;		
	}
	enumerator->destroy(enumerator);	

	enumerator = to_store->create_enumerator(to_store);
	while(enumerator->enumerate(enumerator, &dns_server_test_candidate))
	{
		this->servers->insert_last(this->servers, dns_server_test_candidate);
		existing_dns_servers->remove(existing_dns_servers, dns_server_test_candidate, NULL);
	}
	enumerator->destroy(enumerator);	
	to_store->destroy(to_store);
	/* This should be fine */	
	existing_dns_servers->destroy_function(existing_dns_servers, (void (*) (void *)) dns_server->destroy);
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
	store_existing_dns_server(this, index);
	if (addr->get_family(addr) == AF_INET)
	{
		process = process_start_shell(NULL, NULL, NULL, NULL,
					 "%s interface ipv4 set dns %d static %H none no",
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
	bool handled = FALSE;

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
	if (!iface)
        {
            DBG1(DBG_LIB, "Indeterminate interface, can't install DNS server %H", addr);
        } else {
            if (!guidfromstring(&guid, iface, TRUE))
            {
                    addr->destroy(addr);
                    return FALSE;
            }
            if(!guid2index(guid, &index))
            {
                    addr->destroy(addr);
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

            if (!handled)
            {
                    DBG1(DBG_IKE, "adding DNS server failed");
            } else {
                    DBG1(DBG_IKE, "Added DNS server %H on interface %d", addr, index);
            }
        }
	addr->destroy(addr);
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
        if (!iface) {
            DBG1(DBG_LIB, "Indeterminate interface, can't install DNS server %H", addr);
        } else {
            if (!guidfromstring(&guid, iface, TRUE))
            {
                    addr->destroy(addr);
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
                    } else {
                            DBG1(DBG_IKE, "Could not find newest DNS server for interface %d.", index);
                    }
            } else {
                    if (clear_dns_server(addr, index))
                    {
                            DBG1(DBG_IKE, "Cleared all DNS servers from interface"
                                    " %d", index);
                    } else {
                            DBG1(DBG_IKE, "Could not clear DNS servers on interface %d.", index);
                    }
            }

            this->mutex->unlock(this->mutex);
            free(found);
        }
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
