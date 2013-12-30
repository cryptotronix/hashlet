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

#include "config_zone.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "log.h"
#include "command.h"

struct slot_config make_slot_config (unsigned int read_key, bool check_only,
                                     bool single_use, bool encrypted_read,
                                     bool is_secret, unsigned int write_key,
                                     enum WRITE_CONFIG write_config)
{
  struct slot_config s;

  assert (read_key < MAX_SLOTS);
  assert (write_key < MAX_SLOTS);

  s.read_key = read_key;
  s.check_only = check_only;
  s.single_use = single_use;
  s.encrypted_read = encrypted_read;
  s.is_secret = is_secret;
  s.write_key = write_key;
  s.write_config = write_config;

  return s;

}

void serialize_slot_config (struct slot_config *s, uint8_t *buf)
{

  uint8_t temp;

  assert (NULL != s);
  assert (NULL != buf);

  buf[0] = 0;
  buf[1] = 0;

  /* Place read key in the first four bits */
  temp = s->read_key;
  temp = temp << 4;
  buf[0] = buf[0] | temp;

  if (s->check_only)
    {
      buf[0] = buf[0] | CHECK_ONLY_MASK;
      CTX_LOG (DEBUG, "Check only set on slot config");
    }


  if (s->single_use)
    buf[0] = buf[0] | SINGLE_USE_MASK;

  if (s->encrypted_read)
    {
      buf[0] = buf[0] | ENCRYPTED_READ_MASK;
      CTX_LOG (DEBUG, "Encrypted read set on slot conifg");
    }

  if (s->is_secret)
    {
      buf[0] = buf[0] | IS_SECRET_MASK;
      CTX_LOG (DEBUG, "Is Secret set on slot config");
    }

  /* The first byte has now been set */

  temp = s->write_key;
  temp = temp << 4;
  buf[1] = temp;

  switch (s->write_config)
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
      assert (false);

    }

  CTX_LOG (DEBUG, "Slot Config set: 0x%02X 0x%02X", buf[0], buf[1]);

}

struct slot_config parse_slot_config (uint16_t raw)
{
  struct slot_config parsed = {};
  uint8_t * ptr = (uint8_t *)&raw;

  const uint16_t READ_KEY_MASK = ~7;

  parsed.read_key = raw & READ_KEY_MASK;
  parsed.check_only = ((*ptr & CHECK_ONLY_MASK) == CHECK_ONLY_MASK)
    ? true : false;
  parsed.single_use = ((*ptr & SINGLE_USE_MASK) == SINGLE_USE_MASK)
    ? true : false;
  parsed.encrypted_read = ((*ptr & ENCRYPTED_READ_MASK) ==
                           ENCRYPTED_READ_MASK) ? true : false;
  parsed.is_secret = ((*ptr & IS_SECRET_MASK) == IS_SECRET_MASK)
    ? true : false;

  const uint8_t WRITE_KEY_MASK = ~7;

  parsed.write_key = *(ptr+1) & WRITE_KEY_MASK;

  const uint8_t WRITE_MASK = 7;
  const uint8_t ENCRYPT_MASK = 2;

  uint8_t write_config = *(ptr+1) & WRITE_MASK;

  if (0 == write_config)
    parsed.write_config = ALWAYS;
  else if (ENCRYPT_MASK == (write_config & ENCRYPT_MASK))
    parsed.write_config = ENCRYPT;
  else
    parsed.write_config = NEVER;

  return parsed;

}

uint8_t get_slot_addr (enum config_slots slot)
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
      assert (false);

    }

  return addr;
}

bool write_slot_configs (int fd, enum config_slots slot,
                         struct slot_config *s1, struct slot_config *s2)
{

  uint8_t addr = get_slot_addr (slot);

  const unsigned int SIZE_OF_SLOT_BYTES = 2;

  uint32_t to_send;
  uint8_t *send_ptr = (uint8_t *)&to_send;

  bool result = false;

  assert (NULL != s1);
  assert (NULL != s2);


  serialize_slot_config (s1, send_ptr);
  serialize_slot_config (s2, send_ptr + SIZE_OF_SLOT_BYTES);

  result = write4 (fd, CONFIG_ZONE, addr, to_send);

  return result;


}

bool set_config_zone (int fd)
{
  if (is_config_locked (fd))
    return true;;

  enum config_slots slots[CONFIG_SLOTS_NUM_SLOTS] = {slot0, slot2, slot4,
                                                     slot6, slot8, slot10,
                                                     slot12, slot14};

  struct slot_config s1 = make_slot_config (0, true, false, false, true, 0,
                                            ALWAYS);
  struct slot_config s2 = make_slot_config (0, false, false, false, true, 0,
                                            ALWAYS);

  int x = 0;

  const uint8_t I2C_ADDR_OTP_MODE_SELECTOR_MODE [] =
    { 0xC8, 0x00, 0xAA, 0x00 };
  const uint8_t I2C_ADDR_ETC_WORD = 0x04;

  uint32_t to_send = 0;
  memcpy (&to_send, &I2C_ADDR_OTP_MODE_SELECTOR_MODE, sizeof (to_send));

  assert (write4 (fd, CONFIG_ZONE, I2C_ADDR_ETC_WORD,to_send));

  for (x=0; x < CONFIG_SLOTS_NUM_SLOTS; x++)
    {
      assert (write_slot_configs (fd, slots[x], &s1, &s2));
    }

  return true;

}

struct slot_config get_slot_config (int fd, unsigned int slot)
{
  const unsigned int NUM_SLOTS = 16;

  assert (slot < NUM_SLOTS);

  uint32_t data;
  uint16_t raw_slot_data;

  const uint32_t OFFSET_TO_SLOT_CONFIGS = 5;
  uint8_t addr = slot;

  if (slot % 2 != 0)
    addr -= 1;

  addr += OFFSET_TO_SLOT_CONFIGS;

  assert (read4 (fd, CONFIG_ZONE, addr, &data));

  printf ("Raw data %x\n", data);

  if (slot % 2 != 0)
    raw_slot_data = ~(data << 16);
  else
    raw_slot_data = data >> 16;

  return parse_slot_config (raw_slot_data);


}
