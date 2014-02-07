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

#include "command_adaptation.h"
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "i2c.h"
#include "crc.h"
#include <assert.h>
#include "util.h"
#include "log.h"

const char* status_to_string (enum STATUS_RESPONSE rsp)
{
  const char *rsp_string = NULL;

  switch (rsp)
    {
    case RSP_SUCCESS:
      rsp_string = "Response Success";
      break;
    case RSP_CHECKMAC_MISCOMPARE:
      rsp_string = "Response CheckMac Miscompare";
      break;
    case RSP_PARSE_ERROR:
      rsp_string = "Response Parse Error";
      break;
    case RSP_EXECUTION_ERROR:
      rsp_string = "Response Execution Error";
      break;
    case RSP_AWAKE:
      rsp_string = "Response Awake";
      break;
    case RSP_COMM_ERROR:
      rsp_string = "Response Communication Error";
      break;
    case RSP_NAK:
      rsp_string = "Response NAK";
      break;
    default:
      assert (false);

    }

  return rsp_string;
}


enum STATUS_RESPONSE process_command (int fd, struct Command_ATSHA204 *c,
                                      uint8_t* rec_buf, unsigned int recv_len)
{
  unsigned int c_len = 0;
  uint8_t *serialized;

  assert (NULL != c);
  assert (NULL != rec_buf);

  c_len = serialize_command (c, &serialized);

  return send_and_receive (fd, serialized, c_len, rec_buf, recv_len,
                           &c->exec_time);

}

enum STATUS_RESPONSE send_and_receive (int fd, uint8_t *send_buf,
                                       unsigned int send_buf_len,
                                       uint8_t *recv_buf,
                                       unsigned int recv_buf_len,
                                       struct timespec *wait_time)
{
  struct timespec tim_rem;
  enum STATUS_RESPONSE rsp = RSP_AWAKE;
  const unsigned int NUM_RETRIES = 10;
  unsigned int x = 0;
  ssize_t result = 0;

  assert (NULL != send_buf);
  assert (NULL != recv_buf);
  assert (NULL != wait_time);

  /* Send the data at first.  During a read, if the device responds
  with an "I'm Awake" flag, we've lost synchronization, so send the
  data again in that case only.  Arbitrarily retry this procedure
  NUM_RETRIES times */
  for (x=0; x < NUM_RETRIES && rsp == RSP_AWAKE; x++)
    {
      print_hex_string ("Sending", send_buf, send_buf_len);

      result = i2c_write (fd,send_buf,send_buf_len);

      if (result > 1)
        {
          do
            {
              nanosleep (wait_time , &tim_rem);
            }
          while ((rsp = read_and_validate (fd, recv_buf, recv_buf_len))
                 == RSP_NAK);
          CTX_LOG (DEBUG, "Command Response: %s", status_to_string (rsp));
        }
      else
        {
          perror ("Send failed\n");
          exit (1);
        }


    }

  return rsp;
}

unsigned int serialize_command (struct Command_ATSHA204 *c, uint8_t **serialized)
{
  unsigned int total_len = 0;
  unsigned int crc_len = 0;
  unsigned int crc_offset = 0;
  uint8_t *data;
  uint16_t *crc;


  assert (NULL != c);
  assert (NULL != serialized);

  total_len = sizeof (c->command) + sizeof (c->count) +sizeof (c->opcode) +
    sizeof (c->param1) + sizeof (c->param2) + c->data_len + sizeof (c->checksum);

  crc_len = total_len - sizeof (c->command) - sizeof (c->checksum);

  crc_offset = total_len - sizeof (c->checksum);

  c->count = total_len - sizeof (c->command);

  data = (uint8_t*)malloc (total_len);

  assert (NULL != data);

  print_command (c);

  CTX_LOG (DEBUG,
           "Total len: %d, count: %d, CRC_LEN: %d, CRC_OFFSET: %d\n",
           total_len, c->count, crc_len, crc_offset);

  /* copy over the command */
  data[0] = c->command;
  data[1] = c->count;
  data[2] = c->opcode;
  data[3] = c->param1;
  data[4] = c->param2[0];
  data[5] = c->param2[1];
  if (c->data_len > 0)
    memcpy (&data[6], c->data, c->data_len);

  crc = (uint16_t *)&data[crc_offset];
  *crc = calculate_crc16 (&data[1], crc_len);

  *serialized = data;

  return total_len;

}

enum STATUS_RESPONSE read_and_validate (int fd, uint8_t *buf, unsigned int len)
{

  uint8_t* tmp = NULL;
  const int PAYLOAD_LEN_SIZE = 1;
  const int CRC_SIZE = 2;
  enum STATUS_RESPONSE status = RSP_COMM_ERROR;
  unsigned int recv_buf_len = 0;
  bool crc_valid;
  unsigned int crc_offset;
  int read_bytes;
  const unsigned int STATUS_RSP = 4;

  assert (NULL != buf);

  recv_buf_len = len + PAYLOAD_LEN_SIZE + CRC_SIZE;

  crc_offset = recv_buf_len - 2;

  /* The buffer that comes back has a length byte at the front and a
   * two byte crc at the end. */
  tmp = malloc_wipe (recv_buf_len);

  read_bytes = i2c_read (fd, tmp, recv_buf_len);

  /* First Case: We've read the buffer and it's a status packet */

  if (read_bytes == recv_buf_len && tmp[0] == STATUS_RSP)
  {
      print_hex_string ("Status RSP", tmp, tmp[0]);
      status = get_status_response (tmp);
      CTX_LOG (DEBUG, status_to_string (status));
      CTX_LOG (DEBUG, "Copying %d into buf", tmp[1]);
      memcpy (buf, &tmp[1], 1);
  }

  /* Second case: We received the expected message length */
  else if (read_bytes == recv_buf_len && tmp[0] == recv_buf_len)
    {
      print_hex_string ("Received RSP", tmp, recv_buf_len);

      crc_valid = is_crc_16_valid (tmp, tmp[0] - CRC_16_LEN, tmp + crc_offset);

      if (true == crc_valid)
        {
          wipe (buf, len);
          memcpy (buf, &tmp[1], len);
          status = RSP_SUCCESS;

        }
      else
        {
          perror ("CRC FAIL!\n");
        }
    }
  else
    {
      CTX_LOG (DEBUG,"Read failed, retrying");
      status = RSP_NAK;

    }

  free_wipe (tmp, recv_buf_len);

  return status;
}
