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

#ifndef CONFIG_ZONE_H
#define CONFIG_ZONE_H

#include "defs.h"
#include "util.h"

/// Enumerations for the Write config options
enum WRITE_CONFIG
  {
    ALWAYS = 0,                   /**< Always allow write access */
    NEVER,                        /**< Never allow write access  */
    ENCRYPT                       /**< Only allowed encrypted write access */
  };


/* Enumerations for the Slot configuration areas.  Two slots must be
   written together (as a 4 byte word).
*/
enum config_slots
  {
    slot0 = 0,
    slot2,
    slot4,
    slot6,
    slot8,
    slot10,
    slot12,
    slot14,
    CONFIG_SLOTS_NUM_SLOTS
  };

struct slot_config
{
  unsigned int read_key; /* Slot of key to used for encrypted reads
                            If 0x0, this slot can be used as source
                            for CheckMac copy
                         */
  bool check_only;       /* false = can be used for all crypto
                            commands
                            true = can bue used for CheckMac and
                            GenDig followed by CheckMac
                         */
  bool single_use;       /* false = no limit on the usage.
                            true = limit the number of usages based on
                            the UseFlag or last key used.
                         */
  bool encrypted_read;   /* false = clear reads are permitted.
                            true = Requires the slot to secret.
                         */
  bool is_secret;        /* false = the slot is not secret and
                            requires clear read, write, no MAC check,
                            and no Derivekey command.
                            true = The slot is secret and requires
                            encrypted reads and/or writes
                         */
  unsigned int write_key; /* Slot of key to be used to validate
                             encrypted writes
                          */
  enum WRITE_CONFIG write_config;

};


/**
 * Populate the slot config structure
 *
 * @param read_key Set to true if the slot will be used for encrypted reads.
 * @param check_only Set to true to limit slot to CheckMac and GenDig
 * followed by CheckMac
 * @param single_use Set to true to limit the number of times the key
 * can be used (based on UseFlag)
 * @param encrypted_read Set to true to require encrypted reads
 * @param is_secret Set to true to require encrypted reads
 * @param write_key The key slot to be used to decrypt encrypted writes
 * @param write_config The write config options
 *
 * @return
 */
struct slot_config make_slot_config (unsigned int read_key, bool check_only,
                                     bool single_use, bool encrypted_read,
                                     bool is_secret, unsigned int write_key,
                                     enum WRITE_CONFIG write_config);

/**
 * Write the Configuration slots.  The minimum write length is four
 * bytes therefore this function must write two slot configurations at
 * one time.
 *
 * @param fd The open file descriptor.
 * @param slot The first (even) slot to which to write
 * @param s1 The configuration data for the first slot
 * @param s2 The configuration data for the second slot
 *
 * @return true if the write sucseeds, otherwise false.
 */
bool write_slot_configs (int fd, enum config_slots slot,
                         struct slot_config *s1, struct slot_config *s2);

/**
 * Retrieve the slot configuration for the given slot.  The slot
 * configuration contains details on how the key can be used.
 *
 * @param fd The open file descriptor
 * @param slot The slot (0 - 15) to retrieve.
 *
 * @return A copied structure describing the slot configuration.
 */
struct slot_config get_slot_config (int fd, unsigned int slot);

/**
 * Converts the slot ID into an address
 *
 * @param slot The slot to use
 *
 * @return The mapped address
 */
uint8_t get_slot_addr (enum config_slots slot);


#endif
