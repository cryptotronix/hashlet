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
#include <stdbool.h>

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

void print_hex_string(const char *str, const uint8_t *hex, unsigned int len);

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
 * Compares two octet buffers
 *
 * @param lhs The left octet buffer
 * @param rhs The right octet buffer
 *
 * @return True if the contents are the same
 */
bool memcmp_octet_buffer (struct octet_buffer lhs, struct octet_buffer rhs);

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

/**
 * Converts an ASCII encoded Hex character string into binary.
 *
 * @param hex The null terminated ASCII Hex string
 * @param max_len The expected max len of the string
 *
 * @return The malloc'd binary encoding.  Buf.ptr will be NULL on error
 */
struct octet_buffer ascii_hex_2_bin (const char* hex, unsigned int max_len);

/**
 * Returns true if the string is all hex
 *
 * @param hex The hex string to test
 * @param max_len the expected len of the string
 *
 * @return True if the string is all hex
 */
bool is_all_hex (const char* hex, unsigned int max_len);

/**
 * Copies the src octet buffer into the dst at the given offset.  This
 * will assert to make sure the buffer's don't overflow.
 *
 * @param dst The destination buffer.
 * @param offset The offset in the destination buffer.
 * @param src The source buffer.
 *
 * @return The updated offset (offset + dst.len)
 */

unsigned int copy_buffer (struct octet_buffer dst, unsigned int offset,
                          const struct octet_buffer src);

/**
 * Copies p of length len into the octet buffer.
 *
 * @param buf The destination buffer
 * @param offset The offset in the destination buffer.
 * @param p the pointer to the data
 * @param len The lengh of the data
 *
 * @return The updated offset (offset + len)
 */
unsigned int copy_to_buffer (struct octet_buffer buf, unsigned int offset,
                             const uint8_t *p, unsigned int len);

/**
 * XOR two buffers.  The buffers must not be zero and must be the same size.
 *
 * @param lhs The left buffer.
 * @param rhs The right buffer.
 *
 * @return A malloc'd buffer that is the XOR of the two.
 */
struct octet_buffer xor_buffers (const struct octet_buffer lhs,
                                 const struct octet_buffer rhs);
#endif /* UTIL_H */
