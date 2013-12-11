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



int main(){

  char *bus = "/dev/i2c-1"; /* Pins P9_19 and P9_20 */
  int addr = 0b1100100;          /* The I2C address of TMP102 */

  unsigned char* random_buf = NULL;
  unsigned int random_len = 0;
  unsigned char buf4[4] = {0};
  unsigned char nonce_in[20] = {0};
  struct octet_buffer n_in = {nonce_in, 20};
  struct octet_buffer n_out;
  struct octet_buffer challenge;

  const unsigned char challenge_data[] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
  };

  const uint8_t random_non_person[] =
    {
      0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
      0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
      0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
      0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00
    };


  struct octet_buffer challenge_response;

  struct mac_mode_encoding m = {0};

  gnutls_hash_hd_t * dig;

  int x = 0;

  fd = i2c_setup(bus);


  i2c_acquire_bus(fd, addr);

  /* Register the signal handler */
  signal(SIGINT, signal_handler);

  //assert(0 < gnutls_hash_init(dig, GNUTLS_MAC_SHA256));

  while(x < 2)
    {

      if (wakeup(fd) >= 0)
        {

          random_len = get_random(fd, 1, &random_buf);
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

          assert(true == set_slot_config(fd));

          read4(fd, CONFIG_ZONE, 0x05, (uint32_t *)buf4);
          printf("Word %x: ", 0x05);
          print_hex_string("Data", buf4, 4);

          /* Perform MAC */
          challenge.ptr = challenge_data;
          challenge.len = sizeof(challenge_data);

          challenge_response = perform_mac(fd, m, 0, challenge);
        }

      sleep_device(fd);
      sleep(1);
      x++;
    }

}
