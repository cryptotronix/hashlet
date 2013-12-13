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

const int DEFAULT_LOG_LEVEL = DEBUG;

void CTX_LOG(enum LOG_LEVEL lvl, const char *format, ...)
{
  if (lvl <= DEFAULT_LOG_LEVEL)
    {
      va_list args;
      va_start(args, format);
      vfprintf(stdout, format, args);
      printf("\n");
      va_end(args);
    }
}
