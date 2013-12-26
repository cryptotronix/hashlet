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

#define NUM_ARGS 2

#define HASHLET_COMMAND_FAIL EXIT_FAILURE
#define HASHLET_COMMAND_SUCCESS EXIT_SUCCESS



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
 * @param bus The i2c bus
 * @param command The command to execute
 * @param args The argument structure
 *
 * @return The exit value of the program
 */
int dispatch (const char *bus, const char *command, struct arguments *args);

/**
 * Initialize command line options.  This must be called.
 *
 */
void init_cli (struct arguments * args);

#define NUM_CLI_COMMANDS 10

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

#endif /* CLI_COMMANDS_H */
