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

#include "command.h"
#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "log.h"
#include "config.h"
#include "personalize.h"
#include "crc.h"
#include <pwd.h>

unsigned int get_max_keys ()
{
  return MAX_NUM_DATA_SLOTS;
}


bool record_keys (struct key_container *keys)
{
  assert (NULL != keys);

  bool result = false;
  FILE *f = NULL;

  struct passwd *pw = getpwuid (getuid ());
  assert (NULL != pw);

  const char *home = pw->pw_dir;
  unsigned int filename_len = strlen (home) + strlen (KEY_STORE) + 1;
  char *filename = (char *)malloc_wipe (filename_len);
  strcpy (filename, home);
  strcat (filename, KEY_STORE);


  if ((f = fopen (filename, "w")) != NULL)
    {

      fprintf (f, "# Hashlet key store written from version: %s\n",
               PACKAGE_VERSION);

      unsigned int x = 0;
      for (x=0; x< get_max_keys (); x++)
        {
          fprintf (f, "key_slot_%02u    ",x);

          unsigned int y = 0;
          for (y=0; y < keys->keys[x].len; y++)
            {
              fprintf (f, "%02X", keys->keys[x].ptr[y]);
            }

          fprintf (f, "%s", "\n");
        }

      fclose (f);
      result = true;
    }
  else
    {
      CTX_LOG (INFO, "Failed to open %s", filename);
      perror ("Error");
    }

  free_wipe ((uint8_t *)filename, filename_len);
  return result;
}

struct key_container* make_key_container (void)
{
  return (struct key_container *)malloc_wipe ( sizeof (struct key_container));
}


void free_key_container (struct key_container *keys)
{
  assert (NULL != keys);

  unsigned int x = 0;

  for (x=0; x < get_max_keys (); x++)
    {
      if (NULL != keys->keys[x].ptr)
        free_octet_buffer (keys->keys[x]);
    }

  free (keys);

}

bool write_keys (int fd, struct key_container *keys,
                 struct octet_buffer *data_zone)
{
  assert (NULL != data_zone);
  assert (STATE_INITIALIZED == get_device_state (fd));
  bool free_keys = false;

  int x = 0;
  /* If there are no keys, which is the case when we are personalizing
     a device from scratch, create some new keys */
  if (NULL == keys)
    {
      keys = make_key_container ();
      for (x=0; x < get_max_keys (); x++)
        {
          keys->keys[x] = get_random (fd, false);
        }

      free_keys = true;
    }

  bool status = true;

  for (x=0; x < get_max_keys () && status; x++)
    {
      const unsigned int WORD_OFFSET = 8;
      unsigned int addr = WORD_OFFSET * x;
      status = write32 (fd, DATA_ZONE, addr, keys->keys[x]);
    }

  if (status)
    {
      data_zone->len = get_max_keys () * keys->keys[0].len;
      data_zone->ptr = malloc_wipe (data_zone->len);

      for (x=0; x < get_max_keys (); x++)
        {
          CTX_LOG(DEBUG, "Writing key %u", x);
          unsigned int offset = x * keys->keys[x].len;
          memcpy(data_zone->ptr + offset, keys->keys[x].ptr, keys->keys[x].len);
        }

      status = record_keys (keys);

    }


  if (free_keys)
    free_key_container (keys);

  return status;

}

uint16_t crc_data_otp_zone (struct octet_buffer data, struct octet_buffer otp)
{
  const unsigned int len = otp.len + data.len;
  uint8_t *buf = malloc_wipe (len);

  memcpy (buf, data.ptr, data.len);
  memcpy (buf + data.len, otp.ptr, otp.len);

  uint16_t crc = calculate_crc16 (buf, len);

  free_wipe (buf, len);

  return crc;

}

bool lock_config_zone (int fd, enum DEVICE_STATE state)
{

  if (STATE_FACTORY != state)
    return true;

  struct octet_buffer config = get_config_zone (fd);

  uint16_t crc = calculate_crc16 (config.ptr, config.len);

  return lock (fd, CONFIG_ZONE, crc);

}


enum DEVICE_STATE personalize (int fd, enum DEVICE_STATE goal,
                               struct key_container *keys)
{
  enum DEVICE_STATE state = get_device_state (fd);

  if (state >= goal)
    return state;

  if (set_config_zone (fd) && lock_config_zone (fd, state))
    {
      state = STATE_INITIALIZED;
      assert (get_device_state (fd) == state);

      struct octet_buffer otp_zone;
      if (set_otp_zone (fd, &otp_zone))
        {
          struct octet_buffer data_zone;
          if (write_keys (fd, keys, &data_zone))
            {
              uint16_t crc = crc_data_otp_zone (data_zone, otp_zone);

              if (lock (fd, DATA_ZONE, crc))
                {
                  state = STATE_PERSONALIZED;
                  assert (get_device_state (fd) == state);
                }

              free_octet_buffer (data_zone);
            }

          free_octet_buffer (otp_zone);
        }
    }

  return state;

}
