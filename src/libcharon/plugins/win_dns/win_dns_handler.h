/*
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

/**
 * @defgroup win_dns_handler win_dns_handler
 * @{ @ingroup win_dns
 */

#ifndef WIN_DNS_HANDLER_H_
#define WIN_DNS_HANDLER_H_

#include <attributes/attribute_handler.h>

typedef struct win_dns_handler_t win_dns_handler_t;

/**
 * Handle DNS configuration attributes by setting them via netsh
 */
struct win_dns_handler_t {

	/**
	 * Implements the attribute_handler_t interface
	 */
	attribute_handler_t handler;

	/**
	 * Destroy a win_dns_handler_t.
	 */
	void (*destroy)(win_dns_handler_t *this);
};

/**
 * Create a win_dns_handler instance.
 */
win_dns_handler_t *win_dns_handler_create();

#endif /** WIN_DNS_HANDLER_H_ @}*/
