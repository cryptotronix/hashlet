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


#include <stdlib.h>
#include <argp.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>
#include "config.h"
#include "hashlet.h"


const char *argp_program_version = PACKAGE_VERSION;

const char *argp_program_bug_address = PACKAGE_BUGREPORT;

/* Program documentation. */
static char doc[] =
  "Hashlet is a program to interface to the Cryptotronix Hashlet.\n\n"
  "Currently implemented Commands:\n\n"
  "random        --  Retrieves 32 bytes of random data from the device.\n"
  "serial-num    --  Retrieves the device's serial number.\n";

/* A description of the arguments we accept. */
static char args_doc[] = "i2c_bus command";

#define CMD_UPDATE_SEED 300
#define CMD_SERIAL_NUM 301

/* The options we understand. */
static struct argp_option options[] = {
  {"verbose",  'v', 0,      0,  "Produce verbose output" },
  {"quiet",    'q', 0,      0,  "Don't produce any output" },
  {"silent",   's', 0,      OPTION_ALIAS },
  {"update-seed", CMD_UPDATE_SEED, 0, 0,
     "Updates the random seed.  Only applicable to certain commands"},
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
};

/* Parse a single option. */
static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
  /* Get the input argument from argp_parse, which we
     know is a pointer to our arguments structure. */
  struct arguments *arguments = state->input;

  switch (key)
    {
    case 'q': case 's':
      arguments->silent = 1;
      break;
    case 'v':
      arguments->verbose = 1;
      set_log_level(DEBUG);
      break;
    case 'o':
      arguments->output_file = arg;
      break;
    case 300:
      arguments->update_seed = true;
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


void output_hex(FILE *stream, struct octet_buffer buf)
{
  assert(NULL != buf.ptr);
  assert(NULL != stream);

  unsigned int i = 0;

  for (i = 0; i < buf.len; i++)
    {
      fprintf(stream, "%02X", buf.ptr[i]);
    }

  fprintf(stream, "\n");

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

  /* Parse our arguments; every option seen by parse_opt will
     be reflected in arguments. */
  argp_parse (&argp, argc, argv, 0, 0, &arguments);

  int fd;

  fd = hashlet_setup(arguments.args[0], ADDR);

  if (fd < 0)
    exit(fd);

  if (0 == strcmp(arguments.args[1], "random"))
    {

      response = get_random(fd, arguments.update_seed);
      print_hex_string("Random:", response.ptr, response.len);
      output_hex(stdout, response);
      free_octet_buffer(response);

    }
  else if(0 == strcmp(arguments.args[1], "serial-num"))
  {
      response = get_serial_num(fd);
      output_hex(stdout, response);
      free_octet_buffer(response);
  }
  else
    {
      printf("Invalid command, exiting.  Try --help\n");
      exit(1);
    }

  /* printf ("ARG1 = %s\nARG2 = %s\nOUTPUT_FILE = %s\n" */
  /*         "VERBOSE = %s\nSILENT = %s\n", */
  /*         arguments.args[0], arguments.args[1], */
  /*         arguments.output_file, */
  /*         arguments.verbose ? "yes" : "no", */
  /*         arguments.silent ? "yes" : "no"); */

  hashlet_teardown(fd);
  exit (0);
}
