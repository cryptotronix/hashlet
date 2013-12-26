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
#include "config.h"

#if HAVE_GCRYPT_H
#include <assert.h>
#include <gcrypt.h>
#include "hash.h"

struct octet_buffer sha256 (FILE *fp)
{

  struct octet_buffer digest;

  assert (NULL != fp);
  /* Init gcrypt */
  assert (NULL != gcry_check_version (NULL));

  struct gcry_md_handle *hd;
  struct gcry_md_handle **hd_ptr = &hd;

  assert (GPG_ERR_NO_ERROR == gcry_md_open (hd_ptr, GCRY_MD_SHA256, 0));

  int c;

  /* Perform the hash */
  while ((c = getc (fp)) != EOF)
    {
      gcry_md_putc (hd, c);
    }

  unsigned char *result;

  assert ((result = gcry_md_read (hd, GCRY_MD_SHA256)) != NULL);

  /* copy over to the digest */
  const unsigned int DLEN = gcry_md_get_algo_dlen (GCRY_MD_SHA256);
  digest = make_buffer (DLEN);
  memcpy (digest.ptr, result, DLEN);

  gcry_md_close (hd);

  return digest;
}

#endif
