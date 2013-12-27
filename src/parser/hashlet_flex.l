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
#include "string.h"
#include "hashlet_bison.h"
%}

%option noyywrap
%option nounput
%option noinput

%%
[ \t\n] ;    /* ignore whitespace */
^[#]+.*$      {  } /* ignore comments */
"key_slot_"   { return KEYSLOT; }
[0-9]+        { yylval.num = atoi (yytext); return NUMBER; }
[A-Fa-f0-9]+  { yylval.hex = strdup (yytext); return HEX; }
.    return yytext[0];
%%
