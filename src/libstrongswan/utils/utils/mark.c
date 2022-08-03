/*
 * Copyright (C) 2022 Noel Kuntze
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

#include "mark.h"

#include <threading/spinlock.h>
#include <collections/hashtable.h>

typedef struct private_mark_tracker_t private_mark_tracker_t;

struct private_mark_tracker_t {
    mark_tracker_t public;

    spinlock_t *spinlock;
    hashtable_t *hashtable;    
    uint32_t mark_counter;
};

uint32_t increment_unmasked_bits(uint32_t mark, uint32_t increment, uint32_t mask) {
    /*
     * Add increment to mark while respecting the mask
     */ 
    return (mark & ~mask) | (((mark | ~mask) + increment) & mask);
}

uint32_t get_masked_value(uint32_t mark, uint32_t mask) {
    /*
     * Get the masked value
     */
    return mark & mask;
}

uint32_t get_number_of_set_bits(uint32_t mark) {
    /*
     * Get the number of set bits in the value
     */
    return __builtin_popcount(mark);
}

uint32_t max_number(uint32_t mask) {
    /*
     * Get the highest number that can be stored in the integer when masked by mask
     */
    return mask;
}

METHOD(mark_tracker_t, release_mark, void, private_mark_tracker_t *this, uint32_t mark){
    this->spinlock->lock(this->spinlock);
    uint64_t cpy = mark;
    this->hashtable->remove(this->hashtable, (void *) cpy);
    this->spinlock->unlock(this->spinlock);
}

METHOD(mark_tracker_t, get_mark, uint32_t, private_mark_tracker_t *this, uint32_t mask) {
    /*
     * Get mark while respecting the mask
     */
    this->spinlock->lock(this->spinlock);
    uint32_t next_value = this->mark_counter;
    uint64_t cpy = next_value;
    while (true) {
        next_value = increment_unmasked_bits(next_value, 1, mask);
        cpy = next_value;
        if (!this->hashtable->get(this->hashtable, (void *) cpy)) {
            break;
        }
        if (cpy == this->mark_counter) {
            /* For some reason this loop ran so long it wrapped around. So all marks are used. What do we do now?*/
            DBG0(DBG_CFG, "we ran out of marks to give out; starting again at 0. Mark reuse occurs now!");
        }
        
    }
    this->mark_counter = next_value;
    this->hashtable->put(this->hashtable, (void *)cpy, (void *)true);
    this->spinlock->unlock(this->spinlock);
    return next_value;
}
METHOD(mark_tracker_t, destroy, void, private_mark_tracker_t *this) {
    this->spinlock->lock(this->spinlock);
    this->hashtable->destroy(this->hashtable);
    this->spinlock->unlock(this->spinlock);
    this->spinlock->destroy(this->spinlock);
    free(this);
    return;
}

u_int hash_mark(const void *key) {
    uint64_t intermediate = (uint64_t) key;
    u_int cast = intermediate;
    return cast;
}

bool cmp_mark(const void *key, const void *other_key) {
    uint64_t intermediate = (uint64_t) key, other_intermediate = (uint64_t) other_key;
    uint32_t mark_1 = intermediate, mark_2 = other_intermediate;
    if (mark_1 < mark_2) {
        return -1;
    }
    if (mark_1 == mark_2) {
        return 0;
    }
    return 1;
}

METHOD(mark_tracker_t, reset, void, private_mark_tracker_t *this) {
    this->spinlock->lock(this->spinlock);
    this->hashtable->destroy(this->hashtable);
    this->hashtable = hashtable_create(&hash_mark, &cmp_mark, 0);
    this->mark_counter = 0;
    this->spinlock->unlock(this->spinlock);
}

mark_tracker_t *mark_tracker_create() {
    private_mark_tracker_t *this;
    INIT(this,
        .public = {
            .release_mark = _release_mark,
            .get_mark = _get_mark,
            .destroy = _destroy,
            .reset = _reset,
        },
        .spinlock = spinlock_create(),
        .mark_counter = 0,
        .hashtable = hashtable_create(&hash_mark, &cmp_mark, 0),
    );
    return &this->public;
}
