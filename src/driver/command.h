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

/**
 * @file   command.h
 * @author Joshua Datko <jbd@cryptotronix.com>
 * @date   Tue Dec  3 09:13:45 2013
 *
 * @brief Command interface for the ATSHA204
 *
 *
 */
#ifndef COMMAND_H
#define COMMAND_H

#include <time.h>
#include <stdbool.h>
#include <stdint.h>
#include "defs.h"

/**
 * Generate a Nonce from the device
 *
 * @param fd The open file descriptor
 * @param seed_update_flag Determines if the device's random seed
 * should be updated.
 * @param input Must contain a malloced buffer of 32 or 20 bytes.  If
 * 32 bytes, the nonce will act like a pass through the the value will
 * be loaded directly.  If 20, the value will be used in generating
 * the nonce value.
 *
 * @return A malloced buffer that contains 32 bytes of random data.
 */
struct octet_buffer gen_nonce (int fd, int seed_update_flag,
                              struct octet_buffer input);



enum DATA_ZONE
  {
    CONFIG_ZONE = 0,
    OTP_ZONE = 1,
    DATA_ZONE = 2

  };


struct Command_ATSHA204
{
  uint8_t command;
  uint8_t count;
  uint8_t opcode;
  uint8_t param1;
  uint8_t param2[2];
  uint8_t *data;
  unsigned int data_len;
  uint8_t checksum[2];
  struct timespec exec_time;
};

enum STATUS_RESPONSE
{
  RSP_SUCCESS = 0,
  RSP_CHECKMAC_MISCOMPARE = 0x01,
  RSP_PARSE_ERROR = 0x03,
  RSP_EXECUTION_ERROR = 0x0F,
  RSP_AWAKE = 0x11,
  RSP_COMM_ERROR = 0xFF
};

enum STATUS_RESPONSE get_status_response (uint32_t rsp);

/* Random Commands */

/**
 * Get 32 bytes of random data from the device
 *
 * @param fd The open file descriptor
 * @param update_seed True updates the seed.  Do this sparingly.
 *
 * @return A malloc'ed buffer with random data.
 */
struct octet_buffer get_random (int fd, bool update_seed);


bool read4 (int fd, enum DATA_ZONE zone, uint8_t addr, uint32_t *buf);
bool write4 (int fd, enum DATA_ZONE zone, uint8_t addr, uint32_t buf);


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

struct slot_config make_slot_config (unsigned int read_key, bool check_only,
                                    bool single_use, bool encrypted_read,
                                    bool is_secret, unsigned int write_key,
                                    enum WRITE_CONFIG write_config);

/**
 * Set the configuration zone based.  This function will setup the
 * configuration zone, and thus the device, to a fixed configuration.
 *
 * @param fd The open file descriptor.
 *
 * @return True if succesful, otherwise false
 */
bool set_config_zone (int fd);

/**
 * Programs the OTP zone with fixed data
 *
 * @param fd The open file descriptor
 *
 * @return True if the OTP zone has been written.
 */
bool set_otp_zone (int fd);
/**
 * Structure to encode options for the MAC command.
 *
 */
struct mac_mode_encoding
{
  bool use_serial_num;          /**< Use 48 bits of SN[2:3] and
                                   SN[4:7], otherwise the messages
                                   bits are zero */
  bool use_otp_0_7;             /**< Include the OTP[0] through
                                   OTP[7] otherwise set message bits
                                   to 0.  Ignored if use_otp_0_10 is set */
  bool use_otp_0_10;            /**< Use OPT[0] through OTP[10]
                                   otherwise use zeros */
  bool temp_key_source_flag;    /**< If use_first_32 or use_second is
                                   set, this value must match the
                                   value in TempKey.SourceFlag register */
  bool use_first_32_temp_key;   /**< If set, fill the values with the
                                   first 32 bytes of TempKey.
                                   Otherwise, the first 32 bytes are
                                   loaded from one of the data slots. */
  bool use_second_32_temp_key;  /**< If set, the second 32 byres are
                                   loaded from the value in TempKey.
                                   Otherwise, they are loaded from
                                   the challenge parameter */
};


struct check_mac_encoding
{
  bool use_challenge;           /**< Set to true if using the
                                   challenge in the check mac
                                   operation.  Otherwise it will use TempKey. */
  bool use_slot_id;             /**< Set to true if the first 32
                                   bytes of the message are from a
                                   slot ID, otherwise they are from
                                   temp Key */
  bool use_otp_zone;            /**< Set to true if using 8 bytes
                                   from the OTP zone, otherwise
                                   zeroes are used. */
  bool temp_key;                /**< If TempKey is used it must match
                                   TempKey.SourceFlag
                                */

};

/**
 * Encode the check mac options
 *
 * @param c The check mac options
 *
 * @return The encoded value
 */
uint8_t serialize_check_mac_mode (struct check_mac_encoding c);

/**
 * Encode the MAC commands mode options.
 *
 * @param m The mac mode encoding struct to serialize.
 *
 * @return A byte that contains the encoded MAC command mode encodings.
 */
uint8_t serialize_mac_mode (struct mac_mode_encoding m);

/**
 *
 *
 * @param fd The file descriptor to which to write.
 * @param m The MAC command mode options.
 * @param data_slot The data slot (0-15) to be used in the MAC.
 * @param challenge If use_second_32_temp_key is false, include a 32
 * byte challenge.  Otherwise, ignored
 *
 * @return 32 Bytes of a SHA-256 digest
 */
struct octet_buffer perform_mac (int fd, struct mac_mode_encoding m,
                                unsigned int data_slot,
                                struct octet_buffer challenge);

/**
 *
 *
 * @param fd The open file descriptor
 *
 * @return True if the configuration zone is locked
 */
bool is_config_locked (int fd);

/**
 * Returns the entire configuration zone.
 *
 * @param fd The open file descriptor
 *
 * @return A malloc'ed buffer containing the entire configuration
 * zone.
 */
struct octet_buffer get_config_zone (int fd);

/**
 * Returns the entire OTP zone.
 *
 * @param fd The open file descriptor.
 *
 * @return A malloc'ed buffer containing the entire OTP zone.
 */
struct octet_buffer get_otp_zone (int fd);

/**
 * Locks the specified zone.
 *
 * @param fd The open file descriptor
 * @param zone The zone to lock.  Either CONFIG_ZONE or (DATA_ZONE or
 * OTP_ZONE). The later will be locked together
 *
 * @return True if now locked.
 */
bool lock (int fd, enum DATA_ZONE zone);

/**
 * Print the command structure to the debug log source.
 *
 * @param c The command to be sent.
 */
void print_command (struct Command_ATSHA204 *c);

/**
 * Retrieve the device's serial number
 *
 * @param fd An open file descriptor
 *
 * @return a malloc'd buffer with the serial number.
 */
struct octet_buffer get_serial_num (int fd);

/**
 * Reads 32 Bytes from the address
 *
 * @param fd The open file descriptor
 * @param zone The zone to read from
 * @param addr The address to read from
 *
 * @return 32 bytes of data or buf.ptr will be null on an error
 */
struct octet_buffer read32 (int fd, enum DATA_ZONE zone, uint8_t addr);
void write_keys (int fd);

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

#endif /* COMMAND_H */
