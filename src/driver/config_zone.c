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

void serialize_slot_config (struct slot_config *s, uint8_t *config)
{
  assert (NULL != s);
  assert (NULL != config);

  uint8_t *p = config;

  /* Bit 0 is the right most bit */
  p++;

  const unsigned int MAX_KEYS = 16;
  /* Place read key in the last four bits */
  assert (s->read_key < MAX_KEYS);
  assert (s->write_key < MAX_KEYS);

  *p = s->read_key;

  if (s->check_only)
    {
      *p |= CHECK_ONLY_MASK;
      CTX_LOG (DEBUG, "Check only set on slot config");
    }


  if (s->single_use)
    {
      *p |= SINGLE_USE_MASK;
      CTX_LOG (DEBUG, "Single use set on slot config");
    }

  if (s->encrypted_read)
    {
      *p |= ENCRYPTED_READ_MASK;
      CTX_LOG (DEBUG, "Encrypted read set on slot conifg");
    }

  if (s->is_secret)
    {
      *p |= IS_SECRET_MASK;
      CTX_LOG (DEBUG, "Is Secret set on slot config");
    }

  /* The first byte has now been set */
  p--;

  *p = s->write_key;

  switch (s->write_config)
    {
    case ALWAYS:
      *p |= WRITE_CONFIG_ALWAYS_MASK;
      CTX_LOG (DEBUG, "Write config always set");
      break;
    case NEVER:
      *p |= WRITE_CONFIG_NEVER_MASK;
      CTX_LOG (DEBUG, "Write config NEVER set");
      break;
    case ENCRYPT:
      *p |= WRITE_CONFIG_ENCRYPT_MASK;
      CTX_LOG (DEBUG, "Write config ENCRYPT set");
      break;
    default:
      assert (false);

    }

  CTX_LOG (DEBUG, "Slot Config set: %02x %02x", config[0], config[1] );

}

struct slot_config parse_slot_config (uint8_t *raw)
{
  assert (NULL != raw);
  struct slot_config parsed = {0};
  uint8_t * ptr = &raw[1];

  /* Start with the LSB */
  const uint16_t READ_KEY_MASK = 15;

  parsed.read_key = *ptr & READ_KEY_MASK;

  if ((*ptr & CHECK_ONLY_MASK) == CHECK_ONLY_MASK)
    {
      parsed.check_only = true;
      CTX_LOG (DEBUG, "Slot config Check only set");
    }

  if ((*ptr & SINGLE_USE_MASK) == SINGLE_USE_MASK)
    {
      parsed.single_use = true;
      CTX_LOG (DEBUG, "Single use slot config set");
    }

  if ((*ptr & ENCRYPTED_READ_MASK) == ENCRYPTED_READ_MASK)
    {
      parsed.encrypted_read = true;
      CTX_LOG (DEBUG, "Encrypted read slot config set");
    }

  if ((*ptr & IS_SECRET_MASK) == IS_SECRET_MASK)
    {
      parsed.is_secret = true;
      CTX_LOG (DEBUG, "Is Secret slot config set");
    }

  /* Now parse the MSB */
  const uint8_t WRITE_KEY_MASK = 15;
  ptr = raw;

  parsed.write_key = *ptr & WRITE_KEY_MASK;

  CTX_LOG (DEBUG, "Slot config Write Key %u", parsed.write_key);

  uint8_t write_config = *ptr & ~WRITE_KEY_MASK;

  if (0 == (~7 & write_config))
    {
      parsed.write_config = ALWAYS;
      CTX_LOG (DEBUG, "Slot Config ALWAYS set");
    }
  else if (WRITE_CONFIG_ENCRYPT_MASK == (write_config &
                                         WRITE_CONFIG_ENCRYPT_MASK))
    {
      parsed.write_config = ENCRYPT;
      CTX_LOG (DEBUG, "Slot Config ENCRYPT set");
    }
  else
    {
      parsed.write_config = NEVER;
      CTX_LOG (DEBUG, "Slot Config NEVER set");
    }

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
  uint32_t to_send;
  uint8_t *p = (uint8_t *)&to_send;
  bool result = false;

  assert (NULL != s1);
  assert (NULL != s2);


  serialize_slot_config (s1, p);
  p += 2;
  serialize_slot_config (s2, p);

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

  uint32_t data = 0;
  uint8_t *p = (uint8_t *)&data;

  const uint32_t OFFSET_TO_SLOT_CONFIGS = 5;
  uint8_t addr = slot;

  if (slot % 2 != 0)
    addr -= 1;

  addr += OFFSET_TO_SLOT_CONFIGS;

  assert (read4 (fd, CONFIG_ZONE, addr, &data));

  printf ("Raw data %x\n", data);

  if (slot % 2 != 0)
    {
      data &= 0xFFFF;
    }
  else
    data = data >> 16;

  return parse_slot_config (p);


}
