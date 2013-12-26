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
 * @file   main.c
 * @author Joshua Datko <jbd@cryptotronix.com>
 * @date   Thu Dec 26 14:48:23 2013
 *
 * @brief Entry point for the application.  Parses arguments and then
 * hands off the command to the dispatcher.
 *
 *
 */

#include <argp.h>
#include <assert.h>
#include "cli_commands.h"
#include "config.h"


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
#if HAVE_GCRYPT_H
  "mac           --  Calculates a SHA-256 digest of your input data and then\n"
  "                  sends that digest to the device to be mac'ed with a key\n"
  "                  other internal data\n"
#endif
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
  {"address",  'a', "ADDRESS",      0,  "i2c address for the device (in hex)"},
  { 0, 0, 0, 0, "Random Command Options:", 2},
  {"update-seed", OPT_UPDATE_SEED, 0, 0,
     "Updates the random seed.  Only applicable to certain commands"},
  { 0, 0, 0, 0, "Mac Command Options:", 3},
  {"key-slot", 'k', "SLOT",      0,  "The internal key slot to use."},
  {"output",   'o', "FILE", 0,
   "Output to FILE instead of standard output" },
  { 0 }
};



/* Parse a single option. */
static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
  /* Get the input argument from argp_parse, which we
     know is a pointer to our arguments structure. */
  struct arguments *arguments = state->input;
  int slot;
  long int address_arg;

  switch (key)
    {
    case 'a':

      /* TODO: Not working as expected */
      address_arg = strtol (arg,NULL,16);
      if (0 != address_arg && isxdigit (address_arg))
        arguments->address = atoi (arg);
      else
        CTX_LOG (INFO, "Address not recognized, using default");
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

int main (int argc, char **argv)
{
  struct arguments arguments;

  /* Sets arguments defaults and the command list */
  init_cli (&arguments);

  /* Parse our arguments; every option seen by parse_opt will
     be reflected in arguments. */
  argp_parse (&argp, argc, argv, 0, 0, &arguments);

  exit (dispatch (arguments.args[0], arguments.args[1], &arguments));

}
