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
#include "util.h"



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
    RSP_SUCCESS = 0,            /**< The command succeeded. */
    RSP_CHECKMAC_MISCOMPARE = 0x01, /**< The CHECKMAC Command failed */
    RSP_PARSE_ERROR = 0x03,     /**< Command was received but length,
                                   opcode or parameters are illegal
                                   regardless of device state */
    RSP_EXECUTION_ERROR = 0x0F, /**< Command was received but can't
                                   be executed in the current state */
    RSP_AWAKE = 0x11,           /**< The device is awake */
    RSP_COMM_ERROR = 0xFF,       /**< Command was not received properly
                                   */
    RSP_NAK = 0xAA,     /**< Response was NAKed and a retry should occur */
  };

enum STATUS_RESPONSE get_status_response (const uint8_t *rsp);

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

/**
 * Read four bytes from the device.
 *
 * @param fd The open file descriptor.
 * @param zone The zone from which to read.  In some configurations,
 * four byte reads are not allowed.
 * @param addr The address from which to read.  Consult the data sheet
 * for address conversions.
 * @param buf A non-null pointer to the word to fill in.
 *
 * @return True if successful other false and buf should not be investigated.
 */
bool read4 (int fd, enum DATA_ZONE zone, uint8_t addr, uint32_t *buf);

/**
 * Write four bytes to the device
 *
 * @param fd The open file descriptor
 * @param zone The zone to which to write
 * @param addr The address to write to, consult the data sheet for
 * address conversions.
 * @param buf The data to write.  Passed by value.
 *
 * @return True if successful.
 */
bool write4 (int fd, enum DATA_ZONE zone, uint8_t addr, uint32_t buf);

/**
 * Write 32 bytes to the device.
 *
 * @param fd The open file descriptor.
 * @param zone The data zone to which to write
 * @param addr The address to write to.
 * @param buf The buffer to write, passed by value.  Buf.ptr should be
 * a valid pointer to the data and buf.len must be 32.
 * @param mac An optional mac for encrypted writes.
 *
 * @return True if successful.
 */
bool write32 (int fd, enum DATA_ZONE zone, uint8_t addr,
              struct octet_buffer buf, struct octet_buffer *mac);

/**
 * Performs the nonce operation on the device.  Depending on the data
 * parameter, this command will either generate a new nonce or combine
 * an external value.
 *
 * @param fd The open file descriptor
 * @param data If 32 bytes, this command will load the 32 byte data
 * into the temp key register directly.  If 20 bytes, it will be
 * combined per the manual and 32 bytes of random data will be returned.
 *
 * @return If data is 32 bytes, it will return a buffer of size 1 with
 * a single 0 byte.  Otherwise, it returns a 32 byte random number.
 */
struct octet_buffer gen_nonce (int fd, struct octet_buffer data);

/**
 * Generates a new nonce from the device.  This will combine the OTP
 * zone with a random number to generate the nonce.
 *
 * @param fd The open file descriptor.
 *
 * @return A 32 byte malloc'd buffer if successful.
 */
struct octet_buffer get_nonce (int fd);

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
 * @param otp_zone A pointer to an octet buffer that will be malloc'd
 * and filled in with the OTP Zone contents if successful
 *
 * @return True if the OTP zone has been written.
 */
bool set_otp_zone (int fd, struct octet_buffer *otp_zone);
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

struct mac_response
{
  bool status;                  /**< The status of the mac response */
  struct octet_buffer mac;      /**< The 32 byte MAC response */
  struct octet_buffer meta;     /**< The 13 byte meta data, needed
                                   for check mac commands */
};

/**
 *
 *
 * @param fd The file descriptor to which to write.
 * @param m The MAC command mode options.
 * @param data_slot The data slot (0-15) to be used in the MAC.
 * @param challenge If use_second_32_temp_key is false, include a 32
 * byte challenge.  Otherwise, ignored
 *
 * @return If the Mac_response status is true, ti returns malloc'd
 * buffers of the mac and meta data.
 */
struct mac_response perform_mac (int fd, struct mac_mode_encoding m,
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
 * @param crc The crc16 of the respective zone(s)
 *
 * @return True if now locked.
 */
bool lock (int fd, enum DATA_ZONE zone, uint16_t crc);

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


enum DEVICE_STATE
{
  STATE_FACTORY = 0,            /**< Config zone, data and OTP zones
                                    are unlocked */
  STATE_INITIALIZED,            /**< Config zone locked, data and OTP
                                    zones are unlockded */
  STATE_PERSONALIZED            /**< Config, data, and OTP zones are locked */
};

/**
 * Returns the logical state of the device based on the config, data,
 * and OTP zones
 *
 * @param fd The open file descriptor
 *
 * @return The devie state
 */
enum DEVICE_STATE get_device_state (int fd);

/**
 * Generates the "other data" as its known in the data sheet that is
 * used in the check mac command.
 *
 * @param fd the open file descriptor
 * @param m The same mac mode encoding used to produced the mac
 * @param data_slot the same data slot (key) used in the mac
 *
 * @return the serialized, malloc'd, meta data.  Buf.ptr will be null on error.
 */
struct octet_buffer get_check_mac_meta_data (int fd, struct mac_mode_encoding m,
                                             unsigned int data_slot);

/**
 * Performs the check mac operation
 *
 * @param fd the open file descriptor
 * @param cm The encoding of the check mac options
 * @param data_slot the data slot used for the mac (key slot)
 * @param challenge the challenge sent to the mac command
 * @param challenge_response the response generated from the mac command
 * @param other_data The other meta data generated from get_check_mac_meta_data
 *
 * @return True if a match, otherwise false
 */
bool check_mac (int fd, struct check_mac_encoding cm,
                unsigned int data_slot,
                struct octet_buffer challenge,
                struct octet_buffer challenge_response,
                struct octet_buffer other_data);

/**
 * Converts the slot number to the correct address byte
 *
 * @param zone The zone enumeration
 * @param slot The slot number
 *
 * @return The formatted byte, it will assert a failure if not correct.
 */
uint8_t slot_to_addr (enum DATA_ZONE zone, uint8_t slot);

#endif /* COMMAND_H */
