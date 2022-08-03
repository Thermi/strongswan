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

/**
 * @defgroup mark mark
 * @{ @ingroup mark
 */
#ifndef MARK_H_
#define MARK_H_

#include <library.h>


typedef struct mark_tracker_t mark_tracker_t;

struct mark_tracker_t {
    void (*destroy) (mark_tracker_t *this);
    uint32_t (*get_mark) (mark_tracker_t *this, uint32_t mask);
    void (*release_mark) (mark_tracker_t *this, uint32_t mark);
    void (*reset) (mark_tracker_t *this);
};

mark_tracker_t *mark_tracker_create();

#endif /** MARK_H_ @}*/
