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
%{
#include <stdio.h>
#include "hashlet_parser.h"
#include "../driver/log.h"

void yyerror (const char *error);
int yylex(void);

%}

%union
{
  unsigned int num;
  char *hex;
}

%token KEYSLOT
%token KEY_NUMBER
%token HEX

%type<num> KEY_NUMBER
%type<hex> HEX

%%

hashlet_file: key_file { CTX_LOG (DEBUG, "%s", "hashlet_file -> key_file"); }
            ;

key_file: key_entry { CTX_LOG (DEBUG, "%s", "key_file -> key_entry");}
        | key_file key_entry { CTX_LOG (DEBUG, "%s", "key_file -> key_file key_entry");}
        ;

key_entry: KEYSLOT KEY_NUMBER HEX { put_key ($2, $3); }
         ;

%%


void yyerror (const char *error)
{
  CTX_LOG (DEBUG, "%s: %s", "Parser error", error);

}
