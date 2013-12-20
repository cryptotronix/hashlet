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

#include "command.h"
#include <assert.h>
#include "crc.h"
#include <stdio.h>
#include "util.h"
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "i2c.h"
#include "command_adaptation.h"
#include "log.h"
#include "config.h"

struct Command_ATSHA204 make_command()
{
  struct Command_ATSHA204 c = { .command = 0x03, .count = 0, .opcode = 0,
                                .param1 = 0,
                                .data = NULL, .data_len = 0};

  return c;

}

void set_param1(struct Command_ATSHA204 *c, uint8_t param1)
{
  assert(NULL != c);

  c->param1 = param1;

}

void set_param2(struct Command_ATSHA204 *c, uint8_t *param2)
{
  assert(NULL != c);
  assert(NULL != param2);

  c->param2[0] = param2[0];
  c->param2[1] = param2[1];

}

void set_opcode(struct Command_ATSHA204 *c, uint8_t opcode)
{
  assert(NULL != c);

  c->opcode = opcode;

}

void set_data(struct Command_ATSHA204 *c, uint8_t *data, uint8_t len)
{
  assert(NULL != c);

  if (NULL == data || 0 == len)
    {
      c->data = NULL;
      c->data_len = 0;
    }
  else
    {
      c->data = malloc(len);
      assert(NULL != c->data);
      memcpy(c->data, data, len);
      c->data_len = len;
    }


}

void set_execution_time(struct Command_ATSHA204 *c, unsigned int sec,
                        unsigned long nano)
{
  assert(NULL != c);
  c->exec_time.tv_sec = sec;
  c->exec_time.tv_nsec = nano;

}

void print_command(struct Command_ATSHA204 *c)
{
  assert(NULL != c);

  const char* opcode = NULL;

  CTX_LOG(DEBUG, "*** Printing Command ***");
  CTX_LOG(DEBUG, "Command: 0x%02X", c->command);
  CTX_LOG(DEBUG, "Count: 0x%02X", c->count);
  CTX_LOG(DEBUG, "OpCode: 0x%02X", c->opcode);

  switch(c->opcode)
    {
    case COMMAND_DERIVE_KEY:
      opcode = "Command Derive Key";
      break;
    case COMMAND_DEV_REV:
      opcode = "Command Dev Rev";
      break;
    case COMMAND_GEN_DIG:
      opcode = "Command Generate Digest";
      break;
    case COMMAND_HMAC:
      opcode = "Command HMAC";
      break;
    case COMMAND_CHECK_MAC:
      opcode = "Command Check MAC";
      break;
    case COMMAND_LOCK:
      opcode = "Command Lock";
      break;
    case COMMAND_MAC:
      opcode = "Command MAC";
      break;
    case COMMAND_NONCE:
      opcode = "Command NONCE";
      break;
    case COMMAND_PAUSE:
      opcode = "Command Pause";
      break;
    case COMMAND_RANDOM:
      opcode = "Command Random";
      break;
    case COMMAND_READ:
      opcode = "Command Read";
      break;
    case COMMAND_UPDATE_EXTRA:
      opcode = "Command Update Extra";
      break;
    case COMMAND_WRITE:
      opcode = "Command Write";
      break;
    default:
      assert(false);
    }
  CTX_LOG(DEBUG,"%s", opcode);
  CTX_LOG(DEBUG,"param1: 0x%02X", c->param1);
  CTX_LOG(DEBUG,"param2: 0x%02X 0x%02X", c->param2[0], c->param2[1]);
  if (c->data_len > 0)
    print_hex_string("Data", c->data, c->data_len);
  CTX_LOG(DEBUG,"CRC: 0x%02X 0x%02X", c->checksum[0], c->checksum[1]);
  CTX_LOG(DEBUG,"Wait time: %ld seconds %lu nanoseconds",
            c->exec_time.tv_sec, c->exec_time.tv_nsec);



}

int parse_status_response(uint8_t* rsp)
{
  assert(NULL != rsp);

  if(!is_crc_16_valid(rsp, STATUS_RSP_SIZE, rsp + STATUS_RSP_CRC_OFFSET))
    return CRC_OR_COMM_ERROR;

  return *(rsp + STATUS_RSP_PKT_OFFSET);

}


struct octet_buffer get_random(int fd, bool update_seed)
{
  uint8_t *random = NULL;
  uint8_t param2[2] = {0};
  uint8_t param1 = update_seed ? 0 : 1;
  struct octet_buffer buf = {};

  random = malloc_wipe(RANDOM_RSP_LENGTH);

  struct Command_ATSHA204 c = make_command();

  set_opcode(&c, COMMAND_RANDOM);
  set_param1(&c, param1);
  set_param2(&c, param2);
  set_data(&c, NULL, 0);
  set_execution_time(&c, 0, RANDOM_AVG_EXEC);

  if (process_command(fd, &c, random, RANDOM_RSP_LENGTH))
    //if(send_and_receive(fd, serialized, len, random, RANDOM_RSP_LENGTH, tim))
    {
      buf.ptr = random;
      buf.len = RANDOM_RSP_LENGTH;
    }

  return buf;



}

uint8_t set_zone_bits(enum DATA_ZONE zone)
{
  uint8_t z;

  switch (zone)
    {
    case CONFIG_ZONE:
      z = 0b00000000;
      break;
    case OTP_ZONE:
      z = 0b00000001;
      break;
    case DATA_ZONE:
      z = 0b00000010;
      break;
    default:
      assert(false);

    }

  return z;

}

bool read4(int fd, enum DATA_ZONE zone, uint8_t addr, uint32_t *buf)
{

  bool result = false;
  uint8_t param2[2] = {0};
  uint8_t param1 = set_zone_bits(zone);

  assert(NULL != buf);

  param2[0] = addr;

  struct Command_ATSHA204 c = make_command();

  set_opcode(&c, COMMAND_READ);
  set_param1(&c, param1);
  set_param2(&c, param2);
  set_data(&c, NULL, 0);
  set_execution_time(&c, 0, 1000000);


  if (process_command(fd, &c, (uint8_t *)buf, sizeof(uint32_t)))
    {
      result = true;
    }

  return result;
}

struct octet_buffer read32(int fd, enum DATA_ZONE zone, uint8_t addr)
{


  uint8_t param2[2] = {0};
  uint8_t param1 = set_zone_bits(zone);

  uint8_t READ_32_MASK = 0b10000000;

  param1 |= READ_32_MASK;

  param2[0] = addr;

  struct Command_ATSHA204 c = make_command();

  set_opcode(&c, COMMAND_READ);
  set_param1(&c, param1);
  set_param2(&c, param2);
  set_data(&c, NULL, 0);
  set_execution_time(&c, 0, READ_AVG_EXEC);

  const unsigned int LENGTH_OF_RESPONSE = 32;
  struct octet_buffer buf = make_buffer(LENGTH_OF_RESPONSE);

  if (!process_command(fd, &c, buf.ptr, LENGTH_OF_RESPONSE))
    {
      free_wipe(buf.ptr, LENGTH_OF_RESPONSE);
      buf.ptr = NULL;
      buf.len = 0;
    }

  return buf;
}



bool write4(int fd, enum DATA_ZONE zone, uint8_t addr, uint32_t buf)
{

  bool status = false;
  uint8_t recv = 0;
  uint8_t param2[2] = {0};
  uint8_t param1 = set_zone_bits(zone);

  param2[0] = addr;

  struct Command_ATSHA204 c = make_command();

  set_opcode(&c, COMMAND_WRITE);
  set_param1(&c, param1);
  set_param2(&c, param2);
  set_data(&c, (uint8_t *)&buf, sizeof(buf));
  set_execution_time(&c, 0, 4000000);

  if (process_command(fd, &c, &recv, sizeof(recv)));
    {
      if (0 == (int) recv)
        status = true;
    }

  return status;



}

bool write32(int fd, enum DATA_ZONE zone, uint8_t addr, struct octet_buffer buf)
{

  assert(NULL != buf.ptr);
  assert(32 == buf.len);

  bool status = false;
  uint8_t recv = 0;
  uint8_t param2[2] = {0};
  uint8_t param1 = set_zone_bits(zone);

  /* If writing 32 bytes, this bit must be set in param1 */
  uint8_t WRITE_32_MASK = 0b10000000;

  param1 |= WRITE_32_MASK;

  param2[0] = addr;

  struct Command_ATSHA204 c = make_command();

  set_opcode(&c, COMMAND_WRITE);
  set_param1(&c, param1);
  set_param2(&c, param2);
  set_data(&c, buf.ptr, buf.len);
  set_execution_time(&c, 0, WRITE_AVG_EXEC);

  if (process_command(fd, &c, &recv, sizeof(recv)));
  {
    if (0 == (int) recv)
      status = true;
  }

  return status;



}

struct octet_buffer gen_nonce(int fd, int seed_update_flag,
                              struct octet_buffer input)

{

  uint8_t *recv = NULL;
  uint8_t param1 = seed_update_flag;
  uint8_t param2[2] = {0};
  unsigned int recv_len = 0;
  struct octet_buffer response = {NULL, 0};

  assert(1 == seed_update_flag || 0 == seed_update_flag);
  assert(NULL != input.ptr);
  /* If 32, the nonce is considered a pass through and will be used
     directly by the system */
  /* If 20, the nonce will be combined with a random number */
  assert(32 == input.len || 20 == input.len);

  if (32 == input.len)
    {
      recv_len = 1;
    }
  else
    {
      recv_len = 32;
    }

  recv = malloc(recv_len);
  assert(NULL != recv);


  struct Command_ATSHA204 c = make_command();

  set_opcode(&c, COMMAND_NONCE);
  set_param1(&c, param1);
  set_param2(&c, param2);
  set_data(&c, input.ptr, input.len);
  set_execution_time(&c, 0, 22000000); /* avg. 22 msec */

  if (process_command(fd, &c, recv, recv_len));
  {
    response.ptr = recv;
    response.len= recv_len;
  }

  return response;



}


struct slot_config make_slot_config(unsigned int read_key, bool check_only,
                                    bool single_use, bool encrypted_read,
                                    bool is_secret, unsigned int write_key,
                                    enum WRITE_CONFIG write_config)
{
  struct slot_config s;

  assert(read_key < MAX_SLOTS);
  assert(write_key < MAX_SLOTS);

  s.read_key = read_key;
  s.check_only = check_only;
  s.single_use = single_use;
  s.encrypted_read = encrypted_read;
  s.is_secret = is_secret;
  s.write_key = write_key;
  s.write_config = write_config;

  return s;




}

void serialize_slot_config(struct slot_config *s, uint8_t *buf)
{

  uint8_t temp;

  assert(NULL != s);
  assert(NULL != buf);

  buf[0] = 0;
  buf[1] = 0;

  /* Place read key in the first four bits */
  temp = s->read_key;
  temp = temp << 4;
  buf[0] = buf[0] | temp;

  if (s->check_only)
    {
      buf[0] = buf[0] | CHECK_ONLY_MASK;
      CTX_LOG(DEBUG, "Check only set on slot config");
    }


  if (s->single_use)
    buf[0] = buf[0] | SINGLE_USE_MASK;

  if (s->encrypted_read)
    {
      buf[0] = buf[0] | ENCRYPTED_READ_MASK;
      CTX_LOG(DEBUG, "Encrypted read set on slot conifg");
    }

  if (s->is_secret)
    {
      buf[0] = buf[0] | IS_SECRET_MASK;
      CTX_LOG(DEBUG, "Is Secret set on slot config");
    }

  /* The first byte has now been set */

  temp = s->write_key;
  temp = temp << 4;
  buf[1] = temp;

  switch(s->write_config)
    {
    case ALWAYS:
      buf[1] = buf[1] | WRITE_CONFIG_ALWAYS_MASK;
      break;
    case NEVER:
      buf[1] = buf[1] | WRITE_CONFIG_NEVER_MASK;
      break;
    case ENCRYPT:
      buf[1] = buf[1] | WRITE_CONFIG_ENCRYPT_MASK;
      break;
    default:
      assert(false);

    }

  CTX_LOG(DEBUG, "Slot Config set: 0x%02X 0x%02X", buf[0], buf[1]);

}

uint8_t get_slot_addr(enum config_slots slot)
{
  uint8_t addr;


  /* Slot configurations start at address 0x05 */

  switch (slot)
  {

  case slot0:
    addr = 0x05;
    break;

  case slot2:
    addr = 0x06;
    break;

  case slot4:
    addr = 0x07;
    break;

  case slot6:
    addr = 0x08;
    break;

  case slot8:
    addr = 0x09;
    break;

  case slot10:
    addr = 0x0A;
    break;

  case slot12:
    addr = 0x0B;
    break;

  case slot14:
    addr = 0x0C;
    break;

  default:
    assert(false);

  }

  return addr;
}

bool write_slot_configs(int fd, enum config_slots slot,
                        struct slot_config *s1, struct slot_config *s2)
{

  uint8_t addr = get_slot_addr(slot);

  const unsigned int SIZE_OF_SLOT_BYTES = 2;

  uint32_t to_send;
  uint8_t *send_ptr = (uint8_t *)&to_send;

  bool result = false;

  assert(NULL != s1);
  assert(NULL != s2);


  serialize_slot_config(s1, send_ptr);
  serialize_slot_config(s2, send_ptr + SIZE_OF_SLOT_BYTES);

  result = write4(fd, CONFIG_ZONE, addr, to_send);

  return result;


}

bool set_config_zone(int fd)
{
    if(is_config_locked(fd))
        return false;

    enum config_slots slots[CONFIG_SLOTS_NUM_SLOTS] = {slot0, slot2, slot4,
                                                       slot6, slot8, slot10,
                                                       slot12, slot14};

    struct slot_config s1 = make_slot_config(0, true, false, false, true, 0,
                                             ALWAYS);
    struct slot_config s2 = make_slot_config(0, false, false, false, true, 0,
                                             ALWAYS);

    int x = 0;

    const uint8_t I2C_ADDR_OTP_MODE_SELECTOR_MODE [] =
        { 0xC8, 0x00, 0xAA, 0x00 };
    const uint8_t I2C_ADDR_ETC_WORD = 0x04;

    uint32_t to_send = 0;
    memcpy(&to_send, &I2C_ADDR_OTP_MODE_SELECTOR_MODE, sizeof(to_send));

    assert(write4(fd, CONFIG_ZONE, I2C_ADDR_ETC_WORD,to_send));

    for(x=0; x < CONFIG_SLOTS_NUM_SLOTS; x++)
        {
            assert(write_slot_configs(fd, slots[x], &s1, &s2));
        }

    return true;

}

uint8_t serialize_mac_mode(struct mac_mode_encoding m)
{
  /* The serialized result */
  uint8_t result = 0;

  const uint8_t SERIAL_NUM_MASK = 0b01000000;
  const uint8_t OTP_0_7_MASK =    0b00100000;
  const uint8_t OTP_0_10_MASK =   0b00010000;
  const uint8_t TEMP_KEY_MASK =   0b00000100;
  const uint8_t FIRST_32_MASK =   0b00000010;
  const uint8_t LAST_32_MASK =    0b00000001;

  if (m.use_serial_num)
    result = result ^ SERIAL_NUM_MASK;
  if (m.use_otp_0_7)
    result = result ^ OTP_0_7_MASK;
  if (m.use_otp_0_10)
    result = result ^ OTP_0_10_MASK;
  if (m.temp_key_source_flag)
    result = result ^ TEMP_KEY_MASK;
  if (m.use_first_32_temp_key)
    result = result ^ FIRST_32_MASK;
  if (m.use_second_32_temp_key)
    result = result ^ LAST_32_MASK;

  return result;

}

struct octet_buffer perform_mac(int fd, struct mac_mode_encoding m,
                                unsigned int data_slot,
                                struct octet_buffer challenge)
{
  const unsigned int recv_len = 32;
  struct octet_buffer response = {NULL, recv_len};
  uint8_t param1 = serialize_mac_mode(m);
  uint8_t param2[2] = {0};


  assert(data_slot <= MAX_NUM_DATA_SLOTS);
  if (!m.use_second_32_temp_key)
    assert(NULL != challenge.ptr && recv_len == challenge.len);

  /* Param 2 is guaranteed to be less than 15 (check above) */
  param2[0] = data_slot;
  param2[1] = 0;

  response.ptr = malloc_wipe(recv_len);

  struct Command_ATSHA204 c = make_command();

  set_opcode(&c, COMMAND_MAC);
  set_param1(&c, param1);
  set_param2(&c, param2);
  /* TODO Fix for situations not sending the challlenge */
  set_data(&c, challenge.ptr, challenge.len);
  set_execution_time(&c, 0, MAC_AVG_EXEC);

  if (process_command(fd, &c, response.ptr, recv_len))
    {
      /* Everything is already set */
    }
  else
    {
      free_wipe(response.ptr, recv_len);
      response.ptr = NULL;
    }

  return response;



}

bool is_locked(int fd, enum DATA_ZONE zone)
{
  uint32_t buf = 0;
  const uint8_t config_addr = 0x15;
  uint8_t *ptr = (uint8_t *)&buf;
  const uint8_t UNLOCKED = 0x55;
  bool result = true;
  const unsigned int CONFIG_ZONE_OFFSET = 3;
  const unsigned int DATA_ZONE_OFFSET = 2;
  unsigned int offset = 0;

  switch (zone)
    {
    case CONFIG_ZONE:
      offset = CONFIG_ZONE_OFFSET;
      break;
    case DATA_ZONE:
    case OTP_ZONE:
      offset = DATA_ZONE_OFFSET;
      break;
    default:
        assert(false);

    }

  if (read4(fd, zone, config_addr, &buf))
    {
      ptr = ptr + offset;
      if (UNLOCKED == *ptr)
        result = false;
      else
        result = true;
    }

  return result;
}

bool is_config_locked(int fd)
{
  return is_locked(fd, CONFIG_ZONE);
}

bool is_data_locked(int fd)
{
  return is_locked(fd, DATA_ZONE);
}


struct octet_buffer get_config_zone(fd)
{
    const unsigned int SIZE_OF_CONFIG_ZONE = 88;
    const unsigned int NUM_OF_WORDS = SIZE_OF_CONFIG_ZONE / 4;

    struct octet_buffer buf = make_buffer(SIZE_OF_CONFIG_ZONE);
    uint8_t *write_loc = buf.ptr;

    unsigned int addr = 0;
    unsigned int word = 0;

    while(word < NUM_OF_WORDS)
        {
            addr = word * 4;
            read4(fd, CONFIG_ZONE, word, (uint32_t*)(write_loc+addr));
            word++;
        }

    return buf;
}

bool lock(int fd, enum DATA_ZONE zone)
{

    struct octet_buffer zone_data;
    uint16_t crc;
    uint8_t param1;
    uint8_t param2[2] = {0};
    uint8_t response;
    bool result = false;


    if (is_locked(fd, zone))
        return true;


    switch (zone)
    {
    case CONFIG_ZONE:
        zone_data = get_config_zone(fd);
        param1 = 0;
        break;
    case DATA_ZONE:
    case OTP_ZONE:
        param1 = 0b10000000;
        assert(false);
        break;
    default:
        assert(false);

    }

    crc = calculate_crc16(zone_data.ptr, zone_data.len);
    memcpy(param2, &crc, sizeof(param2));

    struct Command_ATSHA204 c = make_command();

    set_opcode(&c, COMMAND_LOCK);
    set_param1(&c, param1);
    set_param2(&c, param2);
    set_data(&c, NULL, 0);
    set_execution_time(&c, 0, LOCK_AVG_EXEC);

    if (process_command(fd, &c, &response, sizeof(response)))
    {
        if (0 == response)
            {
                result = true;
                CTX_LOG(DEBUG, "Lock Successful");
            }
        else
            {
                CTX_LOG(DEBUG, "Lock Failed");
            }
    }


    return result;

}

bool is_otp_read_only_mode(int fd)
{
    const uint8_t ADDR = 0x04;
    uint32_t word = 0;
    assert(read4(fd, CONFIG_ZONE, ADDR, &word));

    uint8_t * byte = (uint8_t *)&word;

    const unsigned int OFFSET_TO_OTP_MODE = 2;
    const unsigned int OTP_READ_ONLY_MODE = 0xAA;

    return OTP_READ_ONLY_MODE == byte[OFFSET_TO_OTP_MODE] ? true : false;


}
bool set_otp_zone(int fd)
{

  const unsigned int SIZE_OF_WRITE = 32;
  /* The device must be using an OTP read only mode */

  if (!is_otp_read_only_mode(fd))
    assert(false);

  /* The writes must be done in 32 bytes blocks */

  uint8_t nulls[SIZE_OF_WRITE];
  uint8_t part1[SIZE_OF_WRITE];
  uint8_t part2[SIZE_OF_WRITE];
  struct octet_buffer buf ={};
  wipe(nulls, SIZE_OF_WRITE);
  wipe(part1, SIZE_OF_WRITE);
  wipe(part2, SIZE_OF_WRITE);

  /* Simple check to make sure PACKAGE_VERSION isn't too long */
  assert(strlen(PACKAGE_VERSION) < 10);

  /* Setup the fixed OTP data zone */
  sprintf((char *)part1, "CRYPTOTRONIX HASHLET REV: A");
  sprintf((char *)part2, "SOFTWARE VERSION: %s", PACKAGE_VERSION);

  bool success = true;

  buf.ptr = nulls;
  buf.len = sizeof(nulls);

  /* Fill the OTP zone with blanks from their default FFFF */
  success = write32(fd, OTP_ZONE, 0, buf);

  if (success)
    success = write32(fd, OTP_ZONE, SIZE_OF_WRITE / sizeof(uint32_t), buf);

  /* Fill in the data */
  buf.ptr = part1;
  CTX_LOG(DEBUG, "Writing: %s", buf.ptr);
  if (success)
    success = write32(fd, OTP_ZONE, 0, buf);
  buf.ptr = part2;
  CTX_LOG(DEBUG, "Writing: %s", buf.ptr);
  if (success)
    success = write32(fd, OTP_ZONE, SIZE_OF_WRITE / sizeof(uint32_t), buf);

  return success;
}

void write_keys(int fd)
{
  struct octet_buffer key;

  uint8_t test[] =
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

  key.ptr = test;
  key.len = sizeof(test);

  assert(write32(fd, DATA_ZONE, 8, key));

  print_hex_string("Key in address 8", key.ptr, key.len);


}

struct octet_buffer get_serial_num(int fd)
{
  struct octet_buffer serial;
  const unsigned int len = sizeof(uint32_t) * 2 + 1;
  serial.ptr = malloc_wipe(len);
  serial.len = len;

  uint32_t word = 0;

  const uint8_t SERIAL_PART1_ADDR = 0x00;
  const uint8_t SERIAL_PART2_ADDR = 0x02;
  const uint8_t SERIAL_PART3_ADDR = 0x03;

  read4(fd, CONFIG_ZONE, SERIAL_PART1_ADDR, &word);
  memcpy(serial.ptr, &word, sizeof(word));

  read4(fd, CONFIG_ZONE, SERIAL_PART2_ADDR, &word);
  memcpy(serial.ptr + sizeof(word), &word, sizeof(word));

  read4(fd, CONFIG_ZONE, SERIAL_PART3_ADDR, &word);

  uint8_t * ptr = (uint8_t *)&word;

  memcpy(serial.ptr + len - 1, ptr, 1);

  return serial;

}
