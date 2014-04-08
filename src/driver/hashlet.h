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

#ifndef HASHLET_H
#define HASHLET_H

#include "util.h"
#include "log.h"
#include "command.h"
#include "personalize.h"

/**
 * Sets up the device for communication.
 *
 * @param bus The I2C bus.
 * @param addr The address of the device
 *
 * @return An open file descriptor or -1 on error
 */
int hashlet_setup(const char *bus, unsigned int addr);

/**
 * Sleeps the device and closes the file descriptor.
 *
 * @param fd The open file descriptor
 *
 */
void hashlet_teardown(int fd);

void set_log_level(enum LOG_LEVEL lvl);

/* COMMANDS */
/**
 * Get 32 bytes of random data from the device
 *
 * @param fd The open file descriptor
 * @param update_seed True updates the seed.  Do this sparingly.
 *
 * @return A malloc'ed buffer with random data.
 */
struct octet_buffer get_random(int fd, bool update_seed);
/**
 * Get X bytes of random data from the device
 *
 * @param fd The open file descriptor
 * @param update_seed True updates the seed.  Do this sparingly.
 * @param bytes number of bytes to return
 *
 * @return A malloc'ed buffer with random data.
 */
struct octet_buffer get_random_bytes(int fd, bool update_seed, int bytes);
#endif

