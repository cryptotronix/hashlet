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

#ifndef CLI_COMMANDS_H
#define CLI_COMMANDS_H

#include <stdbool.h>
#include "../driver/hashlet.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#define NUM_ARGS 1

#define HASHLET_COMMAND_FAIL EXIT_FAILURE
#define HASHLET_COMMAND_SUCCESS EXIT_SUCCESS

/* Command list */
#define CMD_OFFLINE_VERIFY "offline-verify"
#define CMD_HASH "hash"

/* Used by main to communicate with parse_opt. */
struct arguments
{
  char *args[NUM_ARGS];
  int silent, verbose;
  bool update_seed;
  char *output_file;
  char *input_file;
  unsigned int key_slot;
  bool test;
  struct mac_mode_encoding mac_mode;
  uint8_t address;
  int bytes;
  const char *challenge;
  const char *challenge_rsp;
  const char *meta;
  const char *write_data;
  const char *bus;
};

struct command
{
  const char *cmd;
  int (*func)(int, struct arguments *);
};

void output_hex (FILE *stream, struct octet_buffer buf);

/**
 * Sets reasonable defaults for arguments
 *
 * @param args The argument structure
 */
void set_defaults (struct arguments *args);

/**
 * Dispatch the command for execution.
 *
 * @param command The command to execute
 * @param args The argument structure
 *
 * @return The exit value of the program
 */
int dispatch (const char *command, struct arguments *args);

/**
 * Initialize command line options.  This must be called.
 *
 */
void init_cli (struct arguments * args);

#define NUM_CLI_COMMANDS 15

/**
 * Gets random from the device
 *
 * @param fd The open file descriptor
 * @param args The argument structure
 *
 * @return the exit code
 */

int cli_random (int fd, struct arguments *args);
/**
 * Gets random from the device
 *
 * @param fd The open file descriptor
 * @param args The argument structure
 *
 * @return the exit code
 */
int cli_random_bytes (int fd, struct arguments *args);

/**
 * Retrieves the device's serial number
 *
 * @param fd The open file descriptor
 * @param args The argument structure
 *
 * @return the exit code
 */
int cli_get_serial_num (int fd, struct arguments *args);

/**
 * Retrieves the devices' state
 *
 * @param fd The open File descriptor
 * @param args The argument structure
 *
 * @return The exit code
 */
int cli_get_state (int fd, struct arguments *args);

/**
 * Retrieves the entire config zone from the device
 *
 * @param fd The open file descriptor
 * @param args the argument structure
 *
 * @return the exit code
 */
int cli_get_config_zone (int fd, struct arguments *args);

/**
 * Retrieves the entire OTP Zone
 *
 * @param fd the open file descriptor
 * @param args the argument structure
 *
 * @return the exit code
 */
int cli_get_otp_zone (int fd, struct arguments *args);
/**
 * Performs a straight SHA256 of data, meant for testing purposes
 *
 * @param fd The open file descriptor
 * @param args The argument structure
 *
 * @return the exit code
 */
int cli_hash (int fd, struct arguments *args);

/**
 * Perform the device personalization by setting the config zone,
 * writing the OTP zone, and loading keys.  Keys are stored in a file
 * if successful.
 *
 * @param fd The open file descriptor
 * @param args The argument structure
 *
 * @return the exit code
 */
int cli_personalize (int fd, struct arguments *args);

/**
 * Performs the MAC command.
 *
 * @param fd The open file descriptor
 * @param args The argument structure
 *
 * @return the exit code
 */
int cli_mac (int fd, struct arguments *args);

/**
 * Test function to display the keys in the stored file
 *
 * @param fd The open file descriptor
 * @param args The args
 *
 * @return the exit code
 */
int cli_print_keys (int fd, struct arguments *args);

/**
 * Verifies a MAC from a Hashlet (without needing the hardware)
 *
 * @param fd The open file descriptor
 * @param args The args
 *
 * @return the exit code
 */
int cli_verify_mac (int fd, struct arguments *args);

/**
 * Uses the hashlet to verify a mac.  Either a MAC file must be
 * provided or the options: challenge, mac, and meta-data must be set.
 *
 * @param fd The open file descriptor
 * @param args The args
 *
 * @return the exit code
 */
int cli_check_mac (int fd, struct arguments *args);

/**
 * Attempts to write to the key slot specified by the key slot option.
 *
 * @param fd The open file descriptor.
 * @param args The args
 *
 * @return the exit code.  This command has a high probability of
 * failure if a writable key slot is not chosen.
 */
int cli_write_to_key_slot (int fd, struct arguments *args);

/**
 * Returns a nonce and loads the combined nonce value into tempkey.
 *
 * @param fd The open file descriptor
 * @param args The arguments
 *
 * @return The appropriate exit code.
 */
int cli_get_nonce (int fd, struct arguments *args);

bool is_expected_len (const char* arg, unsigned int len);
bool is_hex_arg (const char* arg, unsigned int len);

/**
 * Reads a data (key) slot.  This command will error if the key slot
 * can't be read.
 *
 * @param fd The open file descriptor
 * @param args The args
 *
 * @return exit code.  If a data slot can't be read, this will return
 * an error.
 */
int cli_read_key_slot (int fd, struct arguments *args);

struct encrypted_write
{
  struct octet_buffer mac;
  struct octet_buffer encrypted;
};

/**
 * Prepares the data for an encrypted write operation.
 *
 * @param fd The open file descriptor.
 * @param data The plain text data to write.
 * @param slot The destination slot.
 * @param ascii_key The current key value in the slot.
 *
 * @return The malloc'd encrypted write structure containing both the
 * mac and the encrypted data.
 */
struct encrypted_write cli_mac_write (int fd, struct octet_buffer data,
                                      unsigned int slot, const char *ascii_key);

#endif /* CLI_COMMANDS_H */
