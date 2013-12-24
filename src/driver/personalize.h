/*
 * Copyright (C) 2013 Cryptotronix, LLC.
 *
 * This file is part of Hashlet.
 *
 * Hashlet is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version.
 *
 * Hashlet is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Hashlet.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef PERSONALIZE_H
#define PERSONALIZE_H

#include "defs.h"
#include "command.h"
#include "util.h"

#define KEY_STORE "/.hashlet"

struct key_container
{
  struct octet_buffer keys[MAX_NUM_DATA_SLOTS];
};

/**
 * Allocate a key container object
 *
 *
 * @return A malloc'd key container
 */
struct key_container* make_key_container ();

/**
 * De-allocs all the keys (after wiping) and then frees the key container.
 *
 * @param keys The key container to free.  This pointer should not be
 * used after calling
 */
void free_key_container (struct key_container *keys);

/**
 * Personalize the device by setting the configuration zone, OTP zone,
 * and loading keys.  This can't be un-done.
 *
 * @param fd The open file descriptor
 * @param goal The desired device state
 * @param keys If keys are NULL, it will create random keys.
 * Otherwise burn in the keys provided.
 *
 * @return
 */
enum DEVICE_STATE personalize (int fd, enum DEVICE_STATE goal,
                               struct key_container *keys);

bool write_keys (int fd, struct key_container *keys,
                 struct octet_buffer *data_zone);
#endif
