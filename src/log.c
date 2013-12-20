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

#include "log.h"

#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <assert.h>

static enum LOG_LEVEL CURRENT_LOG_LEVEL = INFO;

void CTX_LOG(enum LOG_LEVEL lvl, const char *format, ...)
{
  if (lvl <= CURRENT_LOG_LEVEL)
    {
      va_list args;
      va_start(args, format);
      vfprintf(stdout, format, args);
      printf("\n");
      va_end(args);
    }
}

void set_log_level(enum LOG_LEVEL lvl)
{
  CURRENT_LOG_LEVEL = lvl;

}

void print_hex_string(char *str, uint8_t *hex, unsigned int len)
{

  if (CURRENT_LOG_LEVEL < DEBUG)
    return;

  int i;

  assert(NULL != str);
  assert(NULL != hex);

  printf("%s : ", str);

  for (i = 0; i < len; i++)
    {
      if (i > 0) printf(" ");
      printf("0x%02X", hex[i]);
    }

  printf("\n");

}
