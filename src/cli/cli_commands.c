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

#include "hash.h"

static struct command commands[NUM_CLI_COMMANDS];

void set_defaults (struct arguments *args)
{

  assert (NULL != args);

  args->silent = 0;
  args->verbose = 0;
  args->output_file = "-";
  args->input_file = NULL;
  args->update_seed = true;
  args->key_slot = 0;
  args->bytes = 32; /* The number of bytes returned in each random
                       call */

  /* Default MAC mode */
  args->mac_mode.use_serial_num = false;
  args->mac_mode.use_otp_0_7 = false;
  args->mac_mode.use_otp_0_10 = false;
  args->mac_mode.temp_key_source_flag = false;
  args->mac_mode.use_first_32_temp_key = false;
  args->mac_mode.use_second_32_temp_key = false;

  args->challenge = NULL;
  args->challenge_rsp = NULL;
  args->meta = NULL;
  args->write_data = NULL;

  args->address = 0b1100100;
  args->bus = "/dev/i2c-1";


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
  static const struct command hash_cmd = {CMD_HASH, cli_hash };
  static const struct command personalize_cmd = {"personalize",
                                                 cli_personalize };
  static const struct command mac_cmd = {"mac", cli_mac };
  static const struct command print_keys_cmd = {"print-keys", cli_print_keys };
  static const struct command offline_verify_cmd =
    {CMD_OFFLINE_VERIFY, cli_verify_mac };
  static const struct command offline_hmac_verify_cmd =
    {CMD_OFFLINE_HMAC_VERIFY, cli_verify_hmac };
  static const struct command check_mac_cmd = {"check-mac", cli_check_mac };
  static const struct command write_key_cmd = {"write", cli_write_to_key_slot };
  static const struct command read_key_cmd = {"read", cli_read_key_slot };
  static const struct command nonce_cmd = {"nonce", cli_get_nonce };
  static const struct command hmac_cmd = {"hmac", cli_hmac};

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
  x = add_command (offline_hmac_verify_cmd, x);
  x = add_command (check_mac_cmd, x);
  x = add_command (write_key_cmd, x);
  x = add_command (read_key_cmd, x);
  x = add_command (nonce_cmd, x);
  x = add_command (hmac_cmd, x);

  set_defaults (args);

}

bool cmp_commands (const char *input, const char *cmd)
{
  if (0 == strncmp (cmd, input, strlen (cmd)))
    return true;
  else
    return false;
}

bool offline_cmd (const char *command)
{
  bool is_offline = false;

  if (NULL == command)
    assert (false);
  else if (cmp_commands (command, CMD_OFFLINE_VERIFY))
    is_offline = true;
  else if (cmp_commands (command, CMD_OFFLINE_HMAC_VERIFY))
    is_offline = true;
  else if (cmp_commands (command, CMD_HASH))
    is_offline = true;

  return is_offline;
}

int dispatch (const char *command, struct arguments *args)
{

  int result = HASHLET_COMMAND_FAIL;
  struct command * cmd = NULL;

  const char *bus = args->bus;

  if ((cmd = find_command (command)) == NULL)
    printf ("%s", "Command not found.  Try --help\n");
  else
    {
      assert (NULL != cmd->func);

      int fd = 0;

      if (offline_cmd (command))
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

bool is_expected_len (const char* arg, unsigned int len)
{
  assert (NULL != arg);

  bool result = false;
  if (len == strnlen (arg, len+1))
    result = true;

  return result;

}

bool is_hex_arg (const char* arg, unsigned int len)
{
  if (is_expected_len (arg, len) && is_all_hex (arg, len))
    return true;
  else
    return false;
}


int cli_random (int fd, struct arguments *args)
{

  struct octet_buffer response;
  int result = HASHLET_COMMAND_FAIL;
  assert (NULL != args);

  response = get_random_bytes (fd, args->update_seed, args->bytes);
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

  FILE *f;
  if ((f = get_input_file (args)) == NULL)
    {
      perror ("Failed to open file");
    }
  else
    {
      response = sha256_file (f);
      if (NULL != response.ptr)
        {
          output_hex (stdout, response);
          free_octet_buffer (response);
          result = HASHLET_COMMAND_SUCCESS;
        }

      close_input_file (args, f);
    }


  return result;
}


int cli_personalize (int fd, struct arguments *args)
{
  int result = HASHLET_COMMAND_FAIL;
  assert (NULL != args);

  struct key_container* keys = NULL;

  if (NULL != args->input_file)
    keys = import_keys (args->input_file);

  if (NULL != args->input_file && NULL == keys)
    fprintf (stderr, "Failed to import key file\n");
  else if (STATE_PERSONALIZED != personalize (fd, STATE_PERSONALIZED, keys))
    fprintf (stderr, "Failure\n");
  else
    result = HASHLET_COMMAND_SUCCESS;

  if (NULL != keys)
    {
      free_key_container (keys);
    }
  return result;

}

void print_mac_result (FILE *fp,
                       struct octet_buffer challenge,
                       struct octet_buffer mac,
                       struct octet_buffer meta)
{
  assert (NULL != fp);
  fprintf (fp, "%s : ", "mac      ");
  output_hex (fp, mac);

  fprintf (fp, "%s : ", "challenge");
  output_hex (fp, challenge);

  fprintf (fp, "%s : ", "meta     ");
  output_hex (fp, meta);

}

int cli_mac (int fd, struct arguments *args)
{
  int result = HASHLET_COMMAND_FAIL;
  assert (NULL != args);

  struct mac_response rsp;
  struct octet_buffer challenge;
  FILE *f;
  if ((f = get_input_file (args)) == NULL)
    {
      perror ("Failed to open file");
    }
  else
    {
      challenge = sha256_file (f);
      if (NULL != challenge.ptr)
        {
          rsp = perform_mac (fd, args->mac_mode,
                             args->key_slot, challenge);

          if (rsp.status)
            {
              print_mac_result (stdout, challenge, rsp.mac, rsp.meta);

              free_octet_buffer (rsp.mac);
              free_octet_buffer (rsp.meta);
              result = HASHLET_COMMAND_SUCCESS;
            }

        free_octet_buffer (challenge);
      }

      close_input_file (args, f);
    }

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

  if (NULL != fp)
    {
      if (0 == parse_file (fp))
        {
          key = get_key (slot);
        }
      fclose (fp);
    }

  free ((char *)filename);

  return key;

}

int cli_verify_mac (int fd, struct arguments *args)
{
  int result = HASHLET_COMMAND_FAIL;
  assert (NULL != args);

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

  return result;

}


int cli_check_mac (int fd, struct arguments *args)
{

  int result = HASHLET_COMMAND_FAIL;
  bool mac_cmp = false;
  assert (NULL != args);

  /* TODO: parse encoding from meta data */
  struct check_mac_encoding cm = {0};

  if (NULL == args->challenge)
    fprintf (stderr, "%s\n", "Challenge can't be empty");
  if (NULL == args->challenge_rsp)
    fprintf (stderr, "%s\n", "Challenge Response can't be empty");
  if (NULL == args->meta)
    fprintf (stderr, "%s\n", "Meta data can't be empty");

  if (NULL == args->challenge || NULL == args->challenge_rsp ||
      NULL == args->meta)
    return result;

  struct octet_buffer challenge = ascii_hex_2_bin (args->challenge, 64);
  struct octet_buffer challenge_rsp = ascii_hex_2_bin (args->challenge_rsp, 64);
  struct octet_buffer meta = ascii_hex_2_bin (args->meta, 26);

  mac_cmp = check_mac (fd,  cm, args->key_slot, challenge, challenge_rsp, meta);

  free_octet_buffer (challenge);
  free_octet_buffer (challenge_rsp);
  free_octet_buffer (meta);

  if (mac_cmp)
    result = HASHLET_COMMAND_SUCCESS;
  else
    fprintf (stderr, "%s\n", "Mac miscompare");

  return result;


}

struct encrypted_write cli_mac_write (int fd, struct octet_buffer data,
                                   unsigned int slot, const char *ascii_key)
{

  struct encrypted_write result;

  struct octet_buffer key = {0,0};

  if (NULL != ascii_key)
    {
      key = ascii_hex_2_bin (ascii_key, 64);
    }
  else
    {
      CTX_LOG (DEBUG, "Previous key value not provided");
      return result;
    }


  struct octet_buffer otp = get_otp_zone (fd);

  struct octet_buffer nonce = get_nonce (fd);

  struct octet_buffer nonce_temp_key = gen_temp_key_from_nonce (fd, nonce, otp);

  assert (gen_digest (fd, DATA_ZONE, slot));

  struct octet_buffer temp_key = gen_temp_key_from_digest (fd, nonce_temp_key,
                                                           slot, key);

  result.encrypted = xor_buffers (temp_key, key);

  const uint8_t opcode = 0x12;
  const uint8_t param1 = 0b10000010;
  uint8_t param2[2] = {0};

  param2[0] = slot_to_addr (DATA_ZONE, slot);
  result.mac = mac_write (temp_key, opcode, param1, param2, data);

  print_hex_string ("OTP", otp.ptr, otp.len);

  free_octet_buffer (otp);
  free_octet_buffer (nonce);
  free_octet_buffer (nonce_temp_key);
  free_octet_buffer (temp_key);

  return result;

}

int cli_write_to_key_slot (int fd, struct arguments *args)
{

  int result = HASHLET_COMMAND_FAIL;
  assert (NULL != args);

  const unsigned int ASCII_KEY_SIZE = 64;

  struct octet_buffer key = {0,0};

  if (NULL == args->write_data)
    fprintf (stderr, "%s\n" ,"Pass the key slot data in the -w option");

  else
    {
      key = ascii_hex_2_bin (args->write_data, ASCII_KEY_SIZE);
      if (NULL != key.ptr)
        {
          struct encrypted_write write = cli_mac_write (fd, key, args->key_slot,
                                                        args->challenge);

          if (write.mac.ptr != NULL && write.encrypted.ptr != NULL &&
              write32 (fd, DATA_ZONE,
                       slot_to_addr (DATA_ZONE, args->key_slot),
                       write.encrypted,
                       &write.mac))
            {
              CTX_LOG (DEBUG, "Write success");
              result = HASHLET_COMMAND_SUCCESS;
            }
          else
            fprintf (stderr, "%s\n" ,"Key slot can not be written.");

          if (NULL != write.mac.ptr)
            free_octet_buffer (write.mac);
          if (NULL != write.encrypted.ptr)
            free_octet_buffer (write.encrypted);

          free_octet_buffer (key);
        }
      else
        {
          fprintf (stderr, "%s\n" ,"Not a valid hex string");
        }
    }

  return result;

}

int cli_read_key_slot (int fd, struct arguments *args)
{
  int result = HASHLET_COMMAND_FAIL;
  assert (NULL != args);

  struct octet_buffer buf = {0,0};
  buf = read32 (fd, DATA_ZONE, slot_to_addr (DATA_ZONE, args->key_slot));

  if (NULL != buf.ptr)
    {
      result = HASHLET_COMMAND_SUCCESS;
      output_hex (stdout, buf);
      free_octet_buffer (buf);
    }
  else
    fprintf (stderr, "%s%d\n" ,"Data can't be read from key slot: ",
             args->key_slot);

  return result;

}

int cli_get_nonce (int fd, struct arguments *args)
{
  int result = HASHLET_COMMAND_FAIL;
  assert (NULL != args);

  struct octet_buffer nonce = get_nonce (fd);

  if (nonce.len == 32 && nonce.ptr != NULL)
    {
      output_hex (stdout, nonce);
      free_octet_buffer (nonce);
      result = HASHLET_COMMAND_SUCCESS;
    }
  else
    fprintf (stderr, "%s\n", "Nonce generation failed");


  return result;

}

int cli_hmac (int fd, struct arguments *args)
{
  int result = HASHLET_COMMAND_FAIL;
  assert (NULL != args);


  FILE *f = NULL;

  /* The HMAC command requires a valid temp key.  If a file was
  specified, hash the file (to reduce it to 32 bytes), load that value
  into tempkey then proceed with the HMAC command.

  If no file was specified, load a random nonce, then proceed with
  HMAC */

  struct hmac_mode_encoding hm = {0};

  if ((f = get_input_file (args)) != NULL)
    {
      /* Digest the file then proceed */
      struct octet_buffer file_digest = {0,0};
      file_digest = sha256_file (f);
      close_input_file (args, f);

      print_hex_string ("HMAC file digest", file_digest.ptr, file_digest.len);

      if (NULL != file_digest.ptr)
        {
          if (load_nonce (fd, file_digest))
            {
              /* Set the source flag to "input" = 1 */
              hm.temp_key_source = true;

              struct octet_buffer rsp = perform_hmac (fd, hm, args->key_slot);

              if (NULL != rsp.ptr)
                {
                  output_hex (stdout, rsp);
                  free_octet_buffer (rsp);
                  result = HASHLET_COMMAND_SUCCESS;
                }
              else
                {
                  fprintf (stderr, "%s\n", "HMAC Command failed.");
                }
            }
        }
    }
  else
    {
      /* temp_key_loaded already false */
    }


  return result;
}

int cli_verify_hmac (int fd, struct arguments *args)
{
  int result = HASHLET_COMMAND_FAIL;
  assert (NULL != args);
  const char* key;
  struct octet_buffer challenge = {0,0};
  struct octet_buffer challenge_rsp = {0,0};
  struct octet_buffer key_buf = {0,0};
  const unsigned int SIZE_OF_256_BITS_ASCII = 64;

  if (NULL == args->challenge_rsp)
    fprintf (stderr, "%s\n", "Challenge Response is blank");
  else if ((key = get_key_from_store (args->key_slot)) == NULL)
    fprintf (stderr, "%s\n", "Invalid file or file failed to parse");
  else
    {
      if (NULL != args->input_file)
        {
          FILE *f = NULL;
          if ((f = get_input_file (args)) == NULL)
            {
              perror ("Failed to open file");
            }
          else
            {
              challenge = sha256_file (f);
            }
        }
      else
        {
          //read the challenge from stdin
          challenge = sha256_file (stdin);
        }

      if (NULL == challenge.ptr)
        {
          perror ("Failed to get sha256 of input data\n");
        }
      else
        {
          challenge_rsp = ascii_hex_2_bin
            (args->challenge_rsp, SIZE_OF_256_BITS_ASCII);
          key_buf = ascii_hex_2_bin (key, SIZE_OF_256_BITS_ASCII);

          if (challenge.ptr != NULL && challenge_rsp.ptr != NULL &&
              key_buf.ptr != NULL)
            {
              if (verify_hmac_defaults (challenge, challenge_rsp, key_buf,
                                        args->key_slot))
                {
                  result = HASHLET_COMMAND_SUCCESS;
                  CTX_LOG (DEBUG, "HMAC PASSED");
                }
              else
                fprintf (stderr, "%s\n", "Verify MAC failed");
            }

          free_octet_buffer (challenge);
          free_octet_buffer (challenge_rsp);
          free_octet_buffer (key_buf);
          free_parsed_keys ();
        }
    }

  return result;

}
