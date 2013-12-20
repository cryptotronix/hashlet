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

#include "i2c.h"
#include "crc.h"
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/i2c-dev.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "log.h"

int i2c_setup(char* bus)
{
  assert(NULL != bus);

  int fd;

  if ((fd = open(bus, O_RDWR)) < 0)
    {
      perror("Failed to open I2C bus\n");
      exit(1);
    }

  return fd;

}

void i2c_acquire_bus(int fd, int addr)
{
  if (ioctl(fd, I2C_SLAVE, addr) < 0)
    {
      perror("Failed to acquire bus access and/or talk to slave.\n");

      exit(1);
  }

}



bool wakeup(int fd)
{

  uint32_t wakeup = 0;
  unsigned char buf[4] = {0};
  bool awake = false;

  /* The assumption here that the fd is the i2c fd.  Of course, it may
   * not be, so this may loop for a while (read forever).  This should
   * probably try for only so often before quitting.
  */

  /* Perform a basic check to see if this fd is open.  This does not
     guarantee it is the correct fd */

  if(fcntl(fd, F_GETFD) < 0)
    perror("Invalid FD.\n");

  while (!awake)
    {
      if (write(fd,&wakeup,sizeof(wakeup)) > 1)
        {

          CTX_LOG(DEBUG, "%s", "Device is awake.");
          // Using I2C Read
          if (read(fd,buf,sizeof(buf)) <= 0)
            {
              /* ERROR HANDLING: i2c transaction failed */
              perror("Failed to read from the i2c bus.\n");
            }
          else
            {
              assert(is_crc_16_valid(buf, 2, buf+2));
              awake = true;
            }
        }
    }

  return awake;

}

int sleep_device(int fd)
{

  unsigned char sleep_byte[] = {0x01};

  return write(fd, sleep_byte, sizeof(sleep_byte));


}

ssize_t i2c_write(int fd, unsigned char *buf, unsigned int len)
{
  assert(NULL != buf);

  return write(fd, buf, len);

}

ssize_t i2c_read(int fd, unsigned char *buf, unsigned int len)
{
  assert(NULL != buf);

  return read(fd, buf, len);


}

int hashlet_setup(const char *bus, unsigned int addr)
{
    int fd = i2c_setup(bus);

    i2c_acquire_bus(fd, addr);

    wakeup(fd);

    return fd;

}

void hashlet_teardown(int fd)
{
    sleep_device(fd);

    close(fd);

}
