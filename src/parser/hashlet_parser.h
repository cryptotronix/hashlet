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
#ifndef HASHLET_PARSER_H
#define HASHLET_PARSER_H

#include <stdio.h>

/**
 * Store the key from the text file into a table.
 *
 * @param slot The key slot corresponding to this key
 * @param key The ASCII hex encoded string
 */
void put_key (unsigned int slot, const char* key);

/**
 * Retrieve the key from the table
 *
 * @param slot The slot (the lookup value)
 *
 * @return An ASCII encoded hex string
 */
const char* get_key (unsigned int slot);

/**
 * Free the parsed key table
 *
 */
void free_parsed_keys (void);

/**
 * Parse the given file stream
 *
 * @param fp The open file pointer
 *
 * @return 0 on success
 */
int parse_file (FILE *fp);

/**
 * Initiate the parsing
 * Included to prevent compile warnings
 *
 * @return 0 on success
 */
int yyparse(void);

#endif
