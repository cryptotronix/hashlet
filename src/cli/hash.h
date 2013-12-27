/* -*- mode: c; c-file-style: "gnu" -*-
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

#ifndef HASH_H
#define HASH_H

#include <stdio.h>
#include "../driver/util.h"

/**
 * Perform a SHA256 Digest on a file stream
 *
 * @param fp The file pointer to hash
 *
 * @return A malloc'd buffer of 32 bytes containing the digest.
 * buf.ptr will be null on error
 */
struct octet_buffer sha256 (FILE *fp);

/**
 * Perform a SHA 256 on a fixed data block
 *
 * @param data The data to hash
 *
 * @return The digest
 */
struct octet_buffer sha256_buffer (struct octet_buffer data);

/**
 * Performs an offline verification of a MAC using the default settings.
 *
 * @param challenge The 32 Byte challenge
 * @param challenge_rsp The 32 Byte challenge response
 * @param key The 32 byte key
 * @param key_slot The key slot used
 *
 * @return True if matched, otherwise false
 */
bool verify_hash_defaults (struct octet_buffer challenge,
                           struct octet_buffer challenge_rsp,
                           struct octet_buffer key, unsigned int key_slot);
#endif /* HASH_H */
