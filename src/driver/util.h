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

#ifndef UTIL_H
#define UTIL_H

#include <stdint.h>
#include <stdint.h>

struct octet_buffer
{
    unsigned char *ptr; /* Pointer to buffer */
    unsigned int len;   /* Length of data */
};

/**
 * Converts an octet buffer into a printable hex string.
 *
 * @param buf The octet buffer
 *
 * @return A malloc'd character string
 */
const char* octet_buffer2hex_string (struct octet_buffer buf);

void print_hex_string(char *str, uint8_t *hex, unsigned int len);

/**
 * Wipes the buffer with zeroes.
 *
 * @param buf The buffer to be wiped.
 * @param len The length of the buffer
 */
void wipe(unsigned char *buf, unsigned int len);

/**
 * Mallocs a buffer of length len and then wipes the buffer with zeroes.
 *
 * @param len The length of the buffer to allocate
 *
 * @return The allocated buffer.  NULL on error.
 */
uint8_t* malloc_wipe(unsigned int len);

/* Wipes then frees the buffer */
void free_wipe(unsigned char* buf, unsigned int len);



/**
 * Created a malloc'd octet buffer.
 *
 * @param len The length of the desired buffer.
 *
 * @return A malloc'd and wiped octet buffer.
 */
struct octet_buffer make_buffer(unsigned int len);

/**
 * Frees and clears an octet_buffer
 *
 * @param buf The malloc'ed octet buffer
 */
void free_octet_buffer(struct octet_buffer buf);

uint8_t reverse_bits_in_byte(uint8_t b);


#endif /* UTIL_H */
