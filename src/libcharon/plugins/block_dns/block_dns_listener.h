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
 * @defgroup block-dns-listener listener
 * @{ @ingroup block-dns
 */

#ifndef BLOCK_DNS_LISTENER_H_
#define BLOCK_DNS_LISTENER_H_

#include <bus/listeners/listener.h>

typedef struct block_dns_listener_t block_dns_listener_t;

/**
 * block-dns bus listener.
 */
struct block_dns_listener_t {

	/**
	 * Implements listener_t interface.
	 */
	listener_t listener;

	/**
	 * Destroy a block_dns_listener_t.
	 */
	void (*destroy)(block_dns_listener_t *this);
};

/**
 * Create a block_dns_listener instance.
 *
 * @return		listener instance
 */
block_dns_listener_t *block_dns_listener_create();

#endif /** BLOCK_DNS_LISTENER_H_ @}*/
