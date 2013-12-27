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
#include "../driver/defs.h"

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

struct octet_buffer sha256_buffer (struct octet_buffer data)
  {
    struct octet_buffer digest;
    const unsigned int DLEN = gcry_md_get_algo_dlen (GCRY_MD_SHA256);

    assert (NULL != data.ptr);
    /* Init gcrypt */
    assert (NULL != gcry_check_version (NULL));

    digest = make_buffer (DLEN);

    gcry_md_hash_buffer (GCRY_MD_SHA256, digest.ptr, data.ptr, data.len);

    return digest;
  }

unsigned int copy_over(uint8_t *dst, const uint8_t *src, unsigned int src_len,
                       unsigned int offset)
{
  memcpy(dst + offset, src, src_len);
  return offset + src_len;
}


struct octet_buffer perform_hash(struct octet_buffer challenge,
                                 struct octet_buffer key,
                                 uint8_t mode, uint16_t param2,
                                 struct octet_buffer otp8,
                                 struct octet_buffer otp3,
                                 struct octet_buffer sn4,
                                 struct octet_buffer sn23)
{

  assert (NULL != challenge.ptr); assert (32 == challenge.len);
  assert (NULL != key.ptr); assert (32 == key.len);
  assert (NULL != otp8.ptr); assert (8 == otp8.len);
  assert (NULL != otp3.ptr); assert (3 == otp3.len);
  assert (NULL != sn4.ptr); assert (4 == sn4.len);
  assert (NULL != sn23.ptr); assert (2 == sn23.len);

  const uint8_t opcode = {0x08};
  const uint8_t sn = 0xEE;
  const uint8_t sn2[] ={0x01, 0x23};

  unsigned int len = challenge.len + key.len + sizeof(opcode) + sizeof(mode)
    + sizeof(param2) + otp8.len + otp3.len + sizeof(sn)  + sn4.len
    + sizeof(sn2) + sn23.len;

  uint8_t *buf = malloc_wipe(len);

  unsigned int offset = 0;
  offset = copy_over(buf, key.ptr, key.len, offset);
  offset = copy_over(buf, challenge.ptr, challenge.len, offset);
  offset = copy_over(buf, &opcode, sizeof(opcode), offset);
  offset = copy_over(buf, &mode, sizeof(mode), offset);
  offset = copy_over(buf, (uint8_t *)&param2, sizeof(param2), offset);
  offset = copy_over(buf, otp8.ptr, otp8.len, offset);
  offset = copy_over(buf, otp3.ptr, otp3.len, offset);
  offset = copy_over(buf, &sn, sizeof(sn), offset);
  offset = copy_over(buf, sn4.ptr, sn4.len, offset);
  offset = copy_over(buf, sn2, sizeof (sn2), offset);
  offset = copy_over(buf, sn23.ptr, sn23.len, offset);

  print_hex_string("Data to hash", buf, len);
  struct octet_buffer data_to_hash = {buf, len};
  struct octet_buffer digest;
  digest = sha256_buffer (data_to_hash);

  print_hex_string("Result hash", digest.ptr, digest.len);

  free(buf);

  return digest;
}

bool verify_hash_defaults (struct octet_buffer challenge,
                           struct octet_buffer challenge_rsp,
                           struct octet_buffer key, unsigned int key_slot)
{

  bool result = false;

  struct octet_buffer otp8 = make_buffer (8);
  struct octet_buffer otp3 = make_buffer (3);
  struct octet_buffer sn4 = make_buffer (4);
  struct octet_buffer sn23 = make_buffer (2);
  uint8_t mode = 0;
  uint16_t param2 = 0;

  uint8_t *p = (uint8_t *)&param2;
  assert (key_slot < MAX_NUM_DATA_SLOTS);
  *p = key_slot;


  struct octet_buffer digest;
  digest = perform_hash (challenge, key, mode, param2, otp8, otp3, sn4, sn23);

  free_octet_buffer (otp8);
  free_octet_buffer (otp3);
  free_octet_buffer (sn4);
  free_octet_buffer (sn23);

  result = memcmp_octet_buffer (digest, challenge_rsp);

  free_octet_buffer (digest);

  return result;

}

#endif
