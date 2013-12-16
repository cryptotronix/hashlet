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

#include "command_adaptation.h"
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "i2c.h"
#include "crc.h"
#include <assert.h>
#include "util.h"


bool process_command(int fd, struct Command_ATSHA204 *c,
                     uint8_t* rec_buf, unsigned int recv_len)
{
  unsigned int c_len = 0;
  uint8_t *serialized;

  assert(NULL != c);
  assert(NULL != rec_buf);

  c_len = serialize_command(c, &serialized);

  return send_and_receive(fd, serialized, c_len, rec_buf, recv_len,
                          &c->exec_time);

}

int send_and_receive(int fd, uint8_t *send_buf, unsigned int send_buf_len,
                     uint8_t *recv_buf, unsigned int recv_buf_len,
                     struct timespec *wait_time)
{
  struct timespec tim_rem;
  int result = 0;

  assert(NULL != send_buf);
  assert(NULL != recv_buf);
  assert(NULL != wait_time);

  print_hex_string("Sending", send_buf, send_buf_len);

  result = i2c_write(fd,send_buf,send_buf_len);

  if(result > 1)
    {

      nanosleep(wait_time , &tim_rem);

      read_and_validate(fd, recv_buf, recv_buf_len);

    }
  else
    {
      perror("Send failed\n");
      exit(1);
    }

  return result;
}

unsigned int serialize_command(struct Command_ATSHA204 *c, uint8_t **serialized)
{
  unsigned int total_len = 0;
  unsigned int crc_len = 0;
  unsigned int crc_offset = 0;
  uint8_t *data;
  uint16_t *crc;


  assert(NULL != c);
  assert(NULL != serialized);

  total_len = sizeof(c->command) + sizeof(c->count) +sizeof(c->opcode) +
    sizeof(c->param1) + sizeof(c->param2) + c->data_len + sizeof(c->checksum);

  crc_len = total_len - sizeof(c->command) - sizeof(c->checksum);

  crc_offset = total_len - sizeof(c->checksum);

  c->count = total_len - sizeof(c->command);

  data = (uint8_t*)malloc(total_len);

  assert(NULL != data);

  print_command(c);

  printf("Total len: %d, count: %d, CRC_LEN: %d, CRC_OFFSET: %d\n", total_len, c->count, crc_len, crc_offset);

  /* copy over the command */
  data[0] = c->command;
  data[1] = c->count;
  data[2] = c->opcode;
  data[3] = c->param1;
  data[4] = c->param2[0];
  data[5] = c->param2[1];
  if (c->data_len > 0)
    memcpy(&data[6], c->data, c->data_len);

  crc = (uint16_t *)&data[crc_offset];
  *crc = calculate_crc16(&data[1], crc_len);

  *serialized = data;

  return total_len;

}

bool read_and_validate(int fd, uint8_t *buf, unsigned int len)
{

  uint8_t* tmp = NULL;
  const int PAYLOAD_LEN_SIZE = 1;
  const int CRC_SIZE = 2;
  bool result = false;
  unsigned int recv_buf_len = 0;
  bool crc_valid;
  unsigned int crc_offset;
  int read_bytes;

  assert(NULL != buf);

  recv_buf_len = len + PAYLOAD_LEN_SIZE + CRC_SIZE;

  crc_offset = recv_buf_len - 2;

  /* The buffer that comes back has a length byte at the front and a
   * two byte crc at the end. */
  tmp = malloc_wipe(recv_buf_len);

 TRY_AGAIN:

  read_bytes = i2c_read(fd, tmp, recv_buf_len);

  if (read_bytes == recv_buf_len)
    {
      print_hex_string("Received RSP", tmp, recv_buf_len);

      crc_valid = is_crc_16_valid(tmp, tmp[0] - CRC_16_LEN, tmp + crc_offset);

      if (true == crc_valid)
        {
          wipe(buf, len);
          memcpy(buf, &tmp[1], len);
          free_wipe(tmp, recv_buf_len);

          result = true;

        }
      else
        {
          perror("CRC FAIL!\n");
        }
    }
  else
    {
      perror("Read failed");
      goto TRY_AGAIN;

    }


  return result;
}
