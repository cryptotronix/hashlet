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
#include <stdlib.h>

struct slot_config make_slot_config (unsigned int read_key, bool check_only,
                                     bool single_use, bool encrypted_read,
                                     bool is_secret, unsigned int write_key,
                                     bool derive_key,
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
  s.derive_key = derive_key;
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

  if (s->derive_key)
    {
      *p |= WRITE_CONFIG_DERIVEKEY_MASK;
      CTX_LOG (DEBUG, "Derive Key set on slot config");
    }

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

  CTX_LOG (DEBUG, "*** PARSING SLOT CONFIG ***");
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

  if ((*ptr & WRITE_CONFIG_DERIVEKEY_MASK) == WRITE_CONFIG_DERIVEKEY_MASK)
    {
      parsed.derive_key = true;
      CTX_LOG (DEBUG, "Derive Key slot config set");
    }

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

  CTX_LOG (DEBUG, "*** END PARSING ***");

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

struct slot_config** build_slot_configs (void)
{
  const unsigned int NUM_SLOTS = 16;

  struct slot_config **config = (struct slot_config **)
    malloc_wipe (NUM_SLOTS * sizeof(struct slot_config *));

  int x = 0;

  for (x=0; x<NUM_SLOTS; x++)
    {
      config[x] = (struct slot_config *)
        malloc_wipe (sizeof (struct slot_config));
    }

  /* Set up each slot */

  /* Slots 0 -7 should be used for keyed hashed applications */
  *config[0] =  make_slot_config (0,     /* Slot for Encrypted Reads */
                                  false, /* Check Only */
                                  false, /* Single Use */
                                  false, /* Encrypted Read */
                                  true,  /* Is secret */
                                  0,     /* Slot for encrypted writes*/
                                  false, /* Derive Key */
                                  NEVER);/* Write configuration */

  *config[1] =  make_slot_config (0, false, false, false,
                                  true, 0, true, NEVER);

  *config[2] =  make_slot_config (0, false, false, false,
                                  true, 0, false, NEVER);

  *config[3] =  make_slot_config (0, false, false, false,
                                  true, 0, true, NEVER);

  *config[4] =  make_slot_config (0, false, false, false,
                                  true, 0, false, NEVER);

  *config[5] =  make_slot_config (0, false, false, false,
                                  true, 0, true, NEVER);

  *config[6] =  make_slot_config (0, false, false, false,
                                  true, 0, false, NEVER);

  *config[7] =  make_slot_config (0, false, false, false,
                                  true, 0, true, NEVER);

  /* Slots 8 - 11 Are reserved for password checking */
  *config[8] =  make_slot_config (0, false, false, false,
                                  true, 0, false, NEVER);

  *config[9] =  make_slot_config (0, false, false, false,
                                  true, 0, false, NEVER);

  *config[10] =  make_slot_config (0, false, false, false,
                                   true, 0, false, NEVER);

  *config[11] =  make_slot_config (0, false, false, false,
                                   true, 0, false, NEVER);

  /* Slots 12 - 13 should be used for user storage */
  *config[12] =  make_slot_config (0, false, false, false,
                                   false, 0, false, ALWAYS);

  *config[13] =  make_slot_config (0, false, false, false,
                                   false, 0, false, ALWAYS);

  /* Slots 14 and 15 are fixed test keys */
  *config[14] =  make_slot_config (0, false, false, false,
                                   false, 0, false, NEVER);

  *config[15] =  make_slot_config (0, false, false, false,
                                   false, 0, false, NEVER);

  return config;


}

void free_slot_configs (struct slot_config **slots)
{
  assert (NULL != slots);

  const unsigned int NUM_SLOTS = 16;

  int x = 0;

  for (x=0; x<NUM_SLOTS; x++)
    {
      assert (NULL != slots[x]);
      free (slots[x]);
    }

  free (slots);
}

bool set_config_zone (int fd)
{
  bool result = false;

  if (is_config_locked (fd))
    return true;

  enum config_slots slots[CONFIG_SLOTS_NUM_SLOTS] = {slot0, slot2, slot4,
                                                     slot6, slot8, slot10,
                                                     slot12, slot14};

  struct slot_config ** configs = build_slot_configs();

  int x = 0;

  const uint8_t I2C_ADDR_OTP_MODE_SELECTOR_MODE [] =
    { 0xC8, 0x00, 0xAA, 0x00 };
  const uint8_t I2C_ADDR_ETC_WORD = 0x04;

  uint32_t to_send = 0;
  memcpy (&to_send, &I2C_ADDR_OTP_MODE_SELECTOR_MODE, sizeof (to_send));

  result = write4 (fd, CONFIG_ZONE, I2C_ADDR_ETC_WORD,to_send);

  for (x=0; x < CONFIG_SLOTS_NUM_SLOTS && result; x++)
    {
      int slot = 2 * x;
      result = write_slot_configs (fd, slots[x],
                                   configs[slot], configs[slot+1]);
    }

  free_slot_configs (configs);

  return result;

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

bool cmp_slot_config (struct slot_config lhs, struct slot_config rhs)
{
  bool result = false;

  if (lhs.read_key == rhs.read_key)
    if (lhs.check_only == rhs.check_only)
      if (lhs.single_use == rhs.single_use)
        if (lhs.encrypted_read == rhs.encrypted_read)
          if (lhs.is_secret == rhs.is_secret)
            if (lhs.write_key == rhs.write_key)
              if (lhs.derive_key == rhs.derive_key)
                if (lhs.write_config == rhs.write_config)
                  result = true;

  return result;

}
