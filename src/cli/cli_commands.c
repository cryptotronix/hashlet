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


#include <assert.h>
#include <string.h>

#include "cli_commands.h"
#include "config.h"
#include "../parser/hashlet_parser.h"
#include "../driver/personalize.h"

#if HAVE_GCRYPT_H
#include "hash.h"
#else
#define NO_GCRYPT "Rebuild with libgcrypt to enable this feature"
#endif

static struct command commands[NUM_CLI_COMMANDS];

void set_defaults (struct arguments *args)
{

  assert (NULL != args);

  args->silent = 0;
  args->verbose = 0;
  args->output_file = "-";
  args->input_file = NULL;
  args->update_seed = false;
  args->key_slot = 0;

  /* Default MAC mode */
  args->mac_mode.use_serial_num = false;
  args->mac_mode.use_otp_0_7 = false;
  args->mac_mode.use_otp_0_10 = false;
  args->mac_mode.temp_key_source_flag = false;
  args->mac_mode.use_first_32_temp_key = false;
  args->mac_mode.use_second_32_temp_key = false;

  args->challenge = NULL;
  args->challenge_rsp = NULL;

  args->address = 0b1100100;


}
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

struct command * find_command (const char* cmd)
{
  int x = 0;

  for (x=0; x < NUM_CLI_COMMANDS; x++)
    {
      const char *cmd_string = commands[x].cmd;
      if (NULL != cmd_string && (0 == strcmp(cmd_string, cmd)))
        return &commands[x];
    }

  return NULL;

}
int add_command (const struct command cmd, int loc)
{
  assert (loc < NUM_CLI_COMMANDS);

  commands[loc] = cmd;

  return loc+1;
}

void init_cli (struct arguments *args)
{
  static const struct command random_cmd = {"random", cli_random };
  static const struct command serial_cmd = {"serial-num", cli_get_serial_num };
  static const struct command state_cmd = {"state", cli_get_state };
  static const struct command config_cmd = {"get-config", cli_get_config_zone };
  static const struct command otp_cmd = {"get-otp", cli_get_otp_zone };
  static const struct command hash_cmd = {"hash", cli_hash };
  static const struct command personalize_cmd = {"personalize",
                                                 cli_personalize };
  static const struct command mac_cmd = {"mac", cli_mac };
  static const struct command print_keys_cmd = {"print-keys", cli_print_keys };
  static const struct command offline_verify_cmd =
    {"offline-verify", cli_verify_mac };

  int x = 0;

  x = add_command (random_cmd, x);
  x = add_command (serial_cmd, x);
  x = add_command (state_cmd, x);
  x = add_command (config_cmd, x);
  x = add_command (otp_cmd, x);
  x = add_command (hash_cmd, x);
  x = add_command (personalize_cmd, x);
  x = add_command (mac_cmd, x);
  x = add_command (print_keys_cmd, x);
  x = add_command (offline_verify_cmd, x);

  set_defaults (args);

}

int dispatch (const char *bus, const char *command, struct arguments *args)
{

  int result = HASHLET_COMMAND_FAIL;
  struct command * cmd = NULL;

  if ((cmd = find_command (command)) == NULL)
    printf ("%s", "Command not found.  Try --help\n");
  else
    {
      assert (NULL != cmd->func);

      int fd = 0;

      if (0 == strcmp ("/dev/null", bus))
        {
          result = (*cmd->func)(fd, args);
        }
      else if ((fd = hashlet_setup (bus, args->address)) < 0)
        perror ("Failed to setup the hashlet");
      else
        {
          result = (*cmd->func)(fd, args);
          hashlet_teardown (fd);
        }


    }

  return result;

}

FILE* get_input_file (struct arguments *args)
{
  assert (NULL != args);

  FILE* f;

  if (NULL == args->input_file)
    {
      f = stdin;
    }
  else
    {
      f = fopen (args->input_file, "r");
    }

  return f;
}


void close_input_file (struct arguments *args, FILE *f)
{
  assert (NULL != args);
  assert (NULL != f);

  /* Only close the file if input file was specified */
  if (NULL != args->input_file)
    {
      if (0 != fclose (f))
        perror ("Failed to close input file");
    }
}

int cli_random (int fd, struct arguments *args)
{

  struct octet_buffer response;
  int result = HASHLET_COMMAND_FAIL;
  assert (NULL != args);

  response = get_random (fd, args->update_seed);
  if (NULL != response.ptr)
    {
      output_hex (stdout, response);
      free_octet_buffer (response);
      result = HASHLET_COMMAND_SUCCESS;
    }

  return result;
}

int cli_get_serial_num (int fd, struct arguments *args)
{
  struct octet_buffer response;
  int result = HASHLET_COMMAND_FAIL;
  assert (NULL != args);

  response = get_serial_num (fd);
  if (NULL != response.ptr)
    {
      output_hex (stdout, response);
      free_octet_buffer (response);
      result = HASHLET_COMMAND_SUCCESS;
    }

  return result;

}

int cli_get_state (int fd, struct arguments *args)
{

  int result = HASHLET_COMMAND_SUCCESS;
  const char *state = "";

  switch (get_device_state (fd))
    {
    case STATE_FACTORY:
      state = "Factory";
      break;
    case STATE_INITIALIZED:
      state = "Initialized";
      break;
    case STATE_PERSONALIZED:
      state = "Personalized";
      break;
    default:
      result = HASHLET_COMMAND_FAIL;
    }

  printf ("%s\n", state);

  return result;


}

int cli_get_config_zone (int fd, struct arguments *args)
{
  struct octet_buffer response;
  int result = HASHLET_COMMAND_FAIL;
  assert (NULL != args);

  response = get_config_zone (fd);
  if (NULL != response.ptr)
    {
      output_hex (stdout, response);
      free_octet_buffer (response);
      result = HASHLET_COMMAND_SUCCESS;
    }

  return result;


}

int cli_get_otp_zone (int fd, struct arguments *args)
{
  struct octet_buffer response;
  int result = HASHLET_COMMAND_FAIL;
  assert (NULL != args);

  if (STATE_PERSONALIZED != get_device_state (fd))
    {
      fprintf (stderr, "%s\n" ,"Can only read OTP zone when personalized");
      return result;
    }

  response = get_otp_zone (fd);

  if (NULL != response.ptr)
    {
      output_hex (stdout, response);
      free_octet_buffer (response);
      result = HASHLET_COMMAND_SUCCESS;
    }


  return result;


}

int cli_hash (int fd, struct arguments *args)
{

  struct octet_buffer response;
  int result = HASHLET_COMMAND_FAIL;
  assert (NULL != args);

#if HAVE_GCRYPT_H
  FILE *f;
  if ((f = get_input_file (args)) == NULL)
    {
      perror ("Failed to open file");
    }
  else
    {
      response = sha256 (f);
      if (NULL != response.ptr)
        {
          output_hex (stdout, response);
          free_octet_buffer (response);
          result = HASHLET_COMMAND_SUCCESS;
        }

      close_input_file (args, f);
    }
#else
  printf ("%s\n", NO_GCRYPT);
#endif

  return result;
}


int cli_personalize (int fd, struct arguments *args)
{
  int result = HASHLET_COMMAND_FAIL;
  assert (NULL != args);

  if (STATE_PERSONALIZED != personalize (fd, STATE_PERSONALIZED, NULL))
    printf ("Failure\n");
  else
    result = HASHLET_COMMAND_SUCCESS;

  return result;

}

int cli_mac (int fd, struct arguments *args)
{
  int result = HASHLET_COMMAND_FAIL;
  assert (NULL != args);

#if HAVE_GCRYPT_H
  struct mac_response rsp;
  struct octet_buffer challenge;
  FILE *f;
  if ((f = get_input_file (args)) == NULL)
    {
      perror ("Failed to open file");
    }
  else
    {
      challenge = sha256 (f);
      if (NULL != challenge.ptr)
        {
          rsp = perform_mac (fd, args->mac_mode,
                             args->key_slot, challenge);

          if (rsp.status)
            {
              output_hex (stdout, rsp.mac);
              output_hex (stdout, rsp.meta);
              free_octet_buffer (rsp.mac);
              free_octet_buffer (rsp.meta);
              result = HASHLET_COMMAND_SUCCESS;
            }

        free_octet_buffer (challenge);
      }

      close_input_file (args, f);
    }
#else
  printf ("%s\n", NO_GCRYPT);
#endif

  return result;
}

int cli_print_keys (int fd, struct arguments *args)
{
  int result = HASHLET_COMMAND_FAIL;
  assert (NULL != args);

  FILE *fp;

  if (NULL == args->input_file)
    fp = stdin;
  else
    fp = fopen (args->input_file, "r");

  if (NULL != fp && 0 == parse_file (fp))
    {
      int x = 0;

      for (x=0; x < 16; x++)
        {
          const char *key;
          if ((key = get_key (x)) != NULL)
            {
              printf ("Key %d: %s\n", x, key);
              struct octet_buffer bkey;
              bkey = ascii_hex_2_bin (key, 64);
              print_hex_string ("Binary Key", bkey.ptr, bkey.len);
              free_octet_buffer (bkey);
            }
        }

      close_input_file (args, fp);

      result = HASHLET_COMMAND_SUCCESS;
    }
  else
    {
      fprintf (stderr, "%s", "Invalid file or file failed to parse\n");
    }


  return result;

}
const char* get_key_from_store (unsigned int slot)
{
  FILE *fp;
  const char *key = NULL;
  const char *filename = get_key_store_name ();
  assert (NULL != filename);

  fp = fopen (filename, "r");

  if (NULL != fp && 0 == parse_file (fp))
    {
      key = get_key (slot);
    }

  fclose (fp);

  return key;

}
int cli_verify_mac (int fd, struct arguments *args)
{
  int result = HASHLET_COMMAND_FAIL;
  assert (NULL != args);
#if HAVE_GCRYPT_H
  const char* key;
  struct octet_buffer challenge;
  struct octet_buffer challenge_rsp;
  struct octet_buffer key_buf;
  const unsigned int SIZE_OF_256_BITS_ASCII = 64;

  if (NULL == args->challenge_rsp)
    fprintf (stderr, "%s\n", "Challenge Response is blank");
  else if (NULL == args->challenge)
    fprintf (stderr, "%s\n", "Challenge is blank");
  else if (NULL == args->challenge && NULL == args->input_file)
    fprintf (stderr, "%s\n", "No challenge specified on command line or file");
  else if ((key = get_key_from_store (args->key_slot)) == NULL)
    fprintf (stderr, "%s\n", "Invalid file or file failed to parse");
  else
    {
      challenge = ascii_hex_2_bin (args->challenge, SIZE_OF_256_BITS_ASCII);
      challenge_rsp = ascii_hex_2_bin
        (args->challenge_rsp, SIZE_OF_256_BITS_ASCII);
      key_buf = ascii_hex_2_bin (key, SIZE_OF_256_BITS_ASCII);

      if (challenge.ptr != NULL && challenge_rsp.ptr != NULL &&
          key_buf.ptr != NULL)
        {
          if (verify_hash_defaults (challenge, challenge_rsp, key_buf,
              args->key_slot))
            {
              result = HASHLET_COMMAND_SUCCESS;
            }
          else
            fprintf (stderr, "%s\n", "Verify MAC failed");
        }

      free_octet_buffer (challenge);
      free_octet_buffer (challenge_rsp);
      free_octet_buffer (key_buf);
      free_parsed_keys ();
    }
#else
  printf ("%s\n", NO_GCRYPT);
#endif
  return result;

}
