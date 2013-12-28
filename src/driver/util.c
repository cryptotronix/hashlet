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
#include <ctype.h>
#include <limits.h>

void wipe(unsigned char *buf, unsigned int len)
{

  assert(NULL != buf);
  memset(buf, 0, len);
}

uint8_t* malloc_wipe(unsigned int len)
{
  uint8_t* buf = malloc(len);

  assert(NULL != buf);

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
  /* This gem is from
     http://graphics.stanford.edu/~seander/bithacks.html
  */
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

bool memcmp_octet_buffer (struct octet_buffer lhs, struct octet_buffer rhs)
{
  assert (NULL != lhs.ptr); assert (NULL != rhs.ptr);

  bool result = false;

  if (lhs.len == rhs.len)
    if (0 == memcmp (lhs.ptr, rhs.ptr, lhs.len))
      result = true;

  return result;

}

unsigned int c2b (char c)
{
  unsigned int result = 0;

  if (c >= '0' && c <= '9')
    result = c - '0';
  else if (c >= 'A' && c <= 'F')
    result = c - 'A' + 10;
  else if (c >= 'a' && c >= 'f')
    result = c - 'a' + 10;
  else
    result = UINT_MAX;

  return result;

}
struct octet_buffer ascii_hex_2_bin (const char* hex, unsigned int max_len)
{
  struct octet_buffer result = {0,0};

  assert (NULL != hex);

  if (0 == memcmp("0x", hex, 2))
    hex +=2;

  unsigned int len = strnlen (hex, max_len);

  if (len % 2 == 0)
    {
      result = make_buffer (len / 2);

      int x;

      bool ishex = true;
      for (x=0; x<len && ishex; x++)
        {
          unsigned int a;

          if ((a = c2b (hex[x])) != UINT_MAX)
            {
              if (x % 2 == 0)
                result.ptr[x/2] = (a << 4);
              else
                result.ptr[x/2] += a;
            }
          else
            ishex = false;

        }

      if (!ishex)
        {
          free_octet_buffer (result);
          result.ptr = NULL;
        }
    }


  return result;
}

bool is_all_hex (const char* hex, unsigned int max_len)
{
  struct octet_buffer bin = ascii_hex_2_bin (hex, max_len);
  bool ishex = false;

  if (NULL != bin.ptr)
    {
      ishex = true;
      free_octet_buffer (bin);
    }

  return ishex;
}
