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

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <linux/i2c-dev.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include "crc.h"
#include "i2c.h"
#include "util.h"
#include <time.h>
#include "command.h"
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

int fd;

void
signal_handler(int signum)
{

  assert(0 == close(fd));

  exit(signum);

}

unsigned int copy_over(uint8_t *dst, const uint8_t *src, unsigned int src_len,
                       unsigned int offset)
{
  memcpy(dst + offset, src, src_len);
  return offset + src_len;


}
struct octet_buffer perform_hash(struct octet_buffer challenge,
                                 unsigned int slot)
{
  const uint8_t key[] =
    {
      0x40, 0x83, 0x6C, 0xA7,
      0x31, 0x28, 0x45, 0x02,
      0xD1, 0x7B, 0x34, 0xA3,
      0x49, 0xB6, 0x26, 0x67,
      0x4E, 0x3B, 0x16, 0x71,
      0x4A, 0xF1, 0x2E, 0xAA,
      0xDB, 0x58, 0xDB, 0x52,
      0x79, 0xA6, 0x82, 0x55
    };

  const uint8_t opcode = {0x08};
  const uint8_t mode = 0;
  const uint8_t param2[2] = {slot, 0};
  const uint8_t otp8[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  const uint8_t otp3[] = {0x00, 0x00, 0x00};
  const uint8_t sn = 0xEE;
  const uint8_t sn4[] = {0x00, 0x00, 0x00, 0x00};
  const uint8_t sn2[] ={0x01, 0x23};
  const uint8_t sn23[] = {0x00, 0x00};

  unsigned int len = challenge.len + sizeof(key) + sizeof(opcode) + sizeof(mode)
    + sizeof(param2) + sizeof(otp8) + sizeof(otp3) + sizeof(sn) + +sizeof(sn4)
    + sizeof(sn2) + sizeof(sn23);

  uint8_t *buf = malloc_wipe(len);

  unsigned int offset = 0;
  offset = copy_over(buf, key, sizeof(key), offset);
  offset = copy_over(buf, challenge.ptr, challenge.len, offset);
  offset = copy_over(buf, &opcode, sizeof(opcode), offset);
  offset = copy_over(buf, &mode, sizeof(mode), offset);
  offset = copy_over(buf, param2, sizeof(param2), offset);
  offset = copy_over(buf, otp8, sizeof(otp8), offset);
  offset = copy_over(buf, otp3, sizeof(otp3), offset);
  offset = copy_over(buf, &sn, sizeof(sn), offset);
  offset = copy_over(buf, sn4, sizeof(sn4), offset);
  offset = copy_over(buf, sn2, sizeof(sn2), offset);
  offset = copy_over(buf, sn23, sizeof(sn23), offset);

  print_hex_string("Data to hash", buf, len);

  gnutls_hash_hd_t  dig;
  assert(0 == gnutls_hash_init(&dig, GNUTLS_DIG_SHA256));
  assert(0 == gnutls_hash(dig, buf, len));

  uint8_t *output = malloc_wipe(gnutls_hash_get_len(GNUTLS_DIG_SHA256));

  gnutls_hash_deinit(dig, output);

  print_hex_string("Result hash", output, gnutls_hash_get_len(GNUTLS_DIG_SHA256));

  struct octet_buffer result;
  result.ptr = output;
  result.len = gnutls_hash_get_len(GNUTLS_DIG_SHA256);

  free(buf);

  return result;
}


int main(){

  char *bus = "/dev/i2c-1"; /* Pins P9_19 and P9_20 */
  int addr = 0b1100100;          /* The I2C address of TMP102 */

  unsigned char* random_buf = NULL;
  unsigned int random_len = 0;
  unsigned char buf4[4] = {0};
  unsigned char nonce_in[20] = {0};
  struct octet_buffer n_in = {nonce_in, 20};
  struct octet_buffer n_out;

  struct octet_buffer config_zone;


  unsigned char challenge_data[32];
  memset(challenge_data, 0xFF, 32);

  const uint8_t random_non_person[] =
    {
      0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
      0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
      0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
      0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00
    };


  struct octet_buffer challenge = {challenge_data, sizeof(challenge_data)};

  /*struct octet_buffer challenge = {challenge_canned, sizeof(challenge_data)};*/

  struct octet_buffer challenge_response;
  struct mac_mode_encoding m = {0};
  struct octet_buffer random;
  struct octet_buffer serial;
  struct octet_buffer calc_hash;




  fd = i2c_setup(bus);


  i2c_acquire_bus(fd, addr);

  /* Register the signal handler */
  signal(SIGINT, signal_handler);




  if (wakeup(fd))
    {

      config_zone = get_config_zone(fd);
      print_hex_string("Config Zone:", config_zone.ptr, config_zone.len);

      serial = get_serial_num(fd);
      print_hex_string("Serial:", serial.ptr, serial.len);


      random = get_random(fd, false);
      print_hex_string("Random Data", random.ptr, random.len);
      if (!is_config_locked(fd))
        {
          printf("Config is not locked\n");
          assert(0 == memcmp(random_buf, random_non_person, random_len));
        }

      read4(fd, CONFIG_ZONE, 0x15, (uint32_t *)buf4);
      printf("Word %x: ", 0x15);
      print_hex_string("Data", buf4, 4);

      /* gen nonce */


      n_out = gen_nonce(fd, 1, n_in);
      print_hex_string("nonce", n_out.ptr, n_out.len);

      if (!is_config_locked(fd))
          assert(true == set_config_zone(fd));

      read4(fd, CONFIG_ZONE, 0x05, (uint32_t *)buf4);
      printf("Word %x: ", 0x05);
      print_hex_string("Data", buf4, 4);

      write_keys(fd);


      /* Perform MAC */

      unsigned int slot_key = 1;

      challenge_response = perform_mac(fd, m, slot_key, challenge);
      print_hex_string("Challenge Response", challenge_response.ptr,
                       challenge_response.len);

      calc_hash = perform_hash(challenge, slot_key);

      assert(0 == memcmp(calc_hash.ptr, challenge_response.ptr, calc_hash.len));

      //lock(fd, CONFIG_ZONE);

      assert(set_otp_zone(fd));



    }

  sleep_device(fd);
  sleep(1);

  close(fd);

  return 0;
}
