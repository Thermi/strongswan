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

#include "block_dns_listener.h"
#include "block_dns_filter.h"

#include <threading/mutex.h>

typedef struct private_block_dns_listener_t private_block_dns_listener_t;

/**
 * Private data of a block_dns_listener_t object.
 */
struct private_block_dns_listener_t {

	/**
	 * Public block_dns_listener_t interface.
	 */
	block_dns_listener_t public;
        
        /**
         * Lock to serialize access to counters
         */
        mutex_t *lock;
        
        /**
         * count_ike_sas
         */
        uint64_t cnt_ike_sas;
        
        /**
         * count_child_sas
         */
        uint64_t cnt_child_sas;

        /**
         * If filter is already active or not
         */
        bool active;

        block_dns_filter_t *filter;

};



METHOD(block_dns_listener_t, destroy, void,
	private_block_dns_listener_t *this)
{
    this->lock->destroy(this->lock);
    free(this);
}

METHOD(listener_t, child_updown, bool,
	private_block_dns_listener_t *this, ike_sa_t *ike_sa, child_sa_t *child_sa,
	bool up)
{
    this->lock->lock(this->lock);
    
    if (up)
    {
        ++this->cnt_child_sas;
    } else {
        --this->cnt_child_sas;
    }
    
    if (this->cnt_child_sas && !this->active)
    {
        this->filter->change_filter(this->filter, TRUE);
    }
    this->lock->unlock(this->lock);
    return TRUE;
}

METHOD(listener_t, ike_updown, bool,
	private_block_dns_listener_t *this, ike_sa_t *ike_sa,
	bool up)
{
    this->lock->lock(this->lock);
    
    if (up)
    {
        ++this->cnt_ike_sas;
    } else {
        --this->cnt_ike_sas;
    }
    
    if (!this->cnt_ike_sas && this->active)
    {
        this->filter->change_filter(this->filter, FALSE);        
    }
    this->lock->unlock(this->lock);
    return TRUE;
}

/**
 * See header
 */
block_dns_listener_t *block_dns_listener_create(block_dns_filter_t *filter)
{
	private_block_dns_listener_t *this;

	INIT(this,
		.public = {
			.listener = {
				.child_updown = _child_updown,
				.ike_updown = _ike_updown,
			},
			.destroy = _destroy,
		},
                .lock = mutex_create(MUTEX_TYPE_DEFAULT),
                .filter = filter,
	);

	return &this->public;
}
