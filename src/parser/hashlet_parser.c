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

#include "hashlet_parser.h"
#include <assert.h>
#include <string.h>
#include "../driver/util.h"

extern FILE *yyin;

#define NUM_KEYS 16

const char* keys [NUM_KEYS] = {0};

void put_key (unsigned int slot, const char* key)
{

  if (slot < NUM_KEYS)
    keys[slot] = key;

}

const char* get_key (unsigned int slot)
{
  assert (slot < NUM_KEYS);
  return keys[slot];
}

void free_parsed_keys (void)
{
  int x;

  for (x=0; x< NUM_KEYS; x++)
    {
      if (NULL != keys[x])
        free_wipe ((uint8_t *)keys[x], strnlen (keys[x], 64));

    }

}

int parse_file (FILE *fp)
{
  assert (NULL != fp);

  yyin = fp;

  return yyparse ();


}
