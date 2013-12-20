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

#include "util.h"
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "log.h"


void wipe(unsigned char *buf, unsigned int len)
{

  assert(NULL != buf);
  memset(buf, 0, len);
}

uint8_t* malloc_wipe(unsigned int len)
{
  uint8_t* buf = malloc(len);

  wipe(buf, len);

  return buf;

}

void free_wipe(unsigned char* buf, unsigned int len)
{
  wipe(buf, len);

  free(buf);


}

uint8_t reverse_bits_in_byte(uint8_t b)
{
  return (b * 0x0202020202ULL & 0x010884422010ULL) % 1023;

}

struct octet_buffer make_buffer(unsigned int len)
{
    struct octet_buffer b = {};
    b.len = len;
    b.ptr = malloc_wipe(len);

    return b;
}


void free_octet_buffer(struct octet_buffer buf)
{
    free_wipe(buf.ptr, buf.len);


}
