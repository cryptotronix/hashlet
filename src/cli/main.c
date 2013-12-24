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


#include <stdlib.h>
#include <argp.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>
#include "config.h"
#include "../driver/hashlet.h"


#define COMMAND_CMP(x) 0 == strcmp (arguments.args[1], x)

const char *argp_program_version = PACKAGE_VERSION;

const char *argp_program_bug_address = PACKAGE_BUGREPORT;

/* Program documentation. */
static char doc[] =
  "Hashlet is a program to interface to the Cryptotronix Hashlet.\n\n"
  "Currently implemented Commands:\n\n"
  "personalize   --  You should run this command first upon receiving your\n"
  "                  Hashlet.  It will load your keys and save them to\n"
  "                  ~/.hashlet as a backup\n"
  "random        --  Retrieves 32 bytes of random data from the device.\n"
  "serial-num    --  Retrieves the device's serial number.\n"
  "mac           --  Calculates a SHA-256 digest of your input data and then\n"
  "                  sends that digest to the device to be mac'ed with a key\n"
  "                  other internal data\n"
  "get-config    --  Dumps the configuration zone\n"
  "state         --  Returns the device's state.\n"
  "                  Factory -- Random will produced a fixed 0xFFFF0000\n"
  "                  Initialized -- Configuration is locked, keys may be \n"
  "                                 written\n"
  "                  Personalized -- Keys are loaded.  Memory is locked\n";


/* A description of the arguments we accept. */
static char args_doc[] = "i2c_bus command";

#define OPT_UPDATE_SEED 300


/* The options we understand. */
static struct argp_option options[] = {
  { 0, 0, 0, 0, "Global Options:", -1},
  {"verbose",  'v', 0,      0,  "Produce verbose output" },
  {"quiet",    'q', 0,      0,  "Don't produce any output" },
  {"silent",   's', 0,      OPTION_ALIAS },
  { 0, 0, 0, 0, "Random Command Options:", 2},
  {"update-seed", OPT_UPDATE_SEED, 0, 0,
     "Updates the random seed.  Only applicable to certain commands"},
  { 0, 0, 0, 0, "Mac Command Options:", 3},
  {"key-slot", 'k', "SLOT",      0,  "The internal key slot to use."},
  {"output",   'o', "FILE", 0,
   "Output to FILE instead of standard output" },
  { 0 }
};


#define NUM_ARGS 2

/* Used by main to communicate with parse_opt. */
struct arguments
{
  char *args[NUM_ARGS];
  int silent, verbose;
  bool update_seed;
  char *output_file;
  unsigned int key_slot;
  bool test;
  struct mac_mode_encoding mac_mode;
};

/* Parse a single option. */
static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
  /* Get the input argument from argp_parse, which we
     know is a pointer to our arguments structure. */
  struct arguments *arguments = state->input;
  int slot;

  switch (key)
    {
    case 'q': case 's':
      arguments->silent = 1;
      break;
    case 'v':
      arguments->verbose = 1;
      set_log_level (DEBUG);
      break;
    case 'o':
      arguments->output_file = arg;
      break;
    case OPT_UPDATE_SEED:
      arguments->update_seed = true;
      break;
    case 'k':
      slot = atoi (arg);
      if (slot < 0 || slot > 15)
        argp_usage (state);

      arguments->key_slot = slot;
      break;
    case ARGP_KEY_ARG:
      if (state->arg_num > NUM_ARGS)
        /* Too many arguments. */
        argp_usage (state);

      arguments->args[state->arg_num] = arg;

      break;

    case ARGP_KEY_END:
      if (state->arg_num < NUM_ARGS)
        /* Not enough arguments. */
        argp_usage (state);
      break;

    default:
      return ARGP_ERR_UNKNOWN;
    }
  return 0;
}

/* Our argp parser. */
static struct argp argp = { options, parse_opt, args_doc, doc };

/* Default ADDR of Hashlet */

const int ADDR = 0b1100100;


void output_hex (FILE *stream, struct octet_buffer buf)
{

  assert (NULL != stream);

  if (NULL == buf.ptr)
    printf ("Command failed\n");
  else
    {
      unsigned int i = 0;

      for (i = 0; i < buf.len; i++)
        {
          fprintf (stream, "%02X", buf.ptr[i]);
        }

      fprintf (stream, "\n");
    }

}

int
main (int argc, char **argv)
{
  struct arguments arguments;
  struct octet_buffer response;

  /* Default values. */
  arguments.silent = 0;
  arguments.verbose = 0;
  arguments.output_file = "-";
  arguments.update_seed = false;
  arguments.key_slot = 0;

  /* Default MAC mode */
  arguments.mac_mode.use_serial_num = false;
  arguments.mac_mode.use_otp_0_7 = false;
  arguments.mac_mode.use_otp_0_10 = false;
  arguments.mac_mode.temp_key_source_flag = false;
  arguments.mac_mode.use_first_32_temp_key = false;
  arguments.mac_mode.use_second_32_temp_key = false;

  /* Parse our arguments; every option seen by parse_opt will
     be reflected in arguments. */
  argp_parse (&argp, argc, argv, 0, 0, &arguments);

  int fd;

  fd = hashlet_setup (arguments.args[0], ADDR);

  if (fd < 0)
    exit (fd);

  /* TEST VECTORS */
  uint8_t test_challenge[32];
  memset (test_challenge, 0xFF, 32);
  struct octet_buffer challenge = {test_challenge, 32};


  if (COMMAND_CMP ("random"))
    {

      response = get_random (fd, arguments.update_seed);
      print_hex_string ("Random:", response.ptr, response.len);
      output_hex (stdout, response);
      free_octet_buffer (response);

    }
  else if (COMMAND_CMP ("serial-num"))
  {
      response = get_serial_num (fd);
      output_hex (stdout, response);
      free_octet_buffer (response);
  }
  else if (COMMAND_CMP ("mac"))
    {
      /* For now, used a canned challenge value, which makes testing
         easier. */
      /* TODO: The MAC command can only accept 32 bytes (or 20 if used
      with a nonce, but we'll do that later).  So, in order to handle
      variable length data, something should SHA256 the data BEFORE
      sending it to hashlet.  This can be done on the command line via
      `opensl sha256 something | hashlet /dev/i2c-1 mac`.  But, none
      of that is coded :) */
      response = perform_mac (fd, arguments.mac_mode,
                             arguments.key_slot, challenge);
      output_hex (stdout, response);
      free_octet_buffer (response);
    }
  else if (COMMAND_CMP ("check-mac"))
    {
      /* How to test:
         Generate a MAC with the 'mac' command.  Use that as a
         fixed challenge-response. */
    }
  else if (COMMAND_CMP ("slot-config"))
    {
      printf ("TODO\n");

    }
  else if (COMMAND_CMP ("get-config"))
    {
      response = get_config_zone (fd);
      output_hex (stdout, response);
      free_octet_buffer (response);
    }
  else if (COMMAND_CMP ("test"))
    {
      printf ("TODO\n");

    }
  else if (COMMAND_CMP ("state"))
    {
      const char *result;
      switch (get_device_state (fd))
        {
        case STATE_FACTORY:
          result = "Factory\n";
          break;
        case STATE_INITIALIZED:
          result = "Initialized\n";
          break;
        case STATE_PERSONALIZED:
          result = "Personalized\n";
          break;
        default:
          assert (false);
        }
      printf (result);
    }
  else if (COMMAND_CMP ("personalize"))
    {
      if (STATE_PERSONALIZED != personalize (fd, STATE_PERSONALIZED, NULL))
        printf ("Failure\n");
    }
  else
    {
      printf ("Invalid command, exiting.  Try --help\n");
      hashlet_teardown (fd);
      exit (1);


    }

  /* printf ("ARG1 = %s\nARG2 = %s\nOUTPUT_FILE = %s\n" */
  /*         "VERBOSE = %s\nSILENT = %s\n", */
  /*         arguments.args[0], arguments.args[1], */
  /*         arguments.output_file, */
  /*         arguments.verbose ? "yes" : "no", */
  /*         arguments.silent ? "yes" : "no"); */

  hashlet_teardown (fd);
  exit (0);
}
