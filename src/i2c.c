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

int i2c_setup(char* bus)
{
  assert(NULL != bus);

  int fd;

  if ((fd = open(bus, O_RDWR)) < 0) 
    {
      perror("Failed to open I2C bus\n");
      exit(1);
    }

}

int i2c_acquire_bus(int fd, int addr)
{
  if (ioctl(fd, I2C_SLAVE, addr) < 0) 
    {
      perror("Failed to acquire bus access and/or talk to slave.\n");

      exit(1);
  }

}



int wakeup(int fd)
{
  unsigned char wakeup[4] = {0};
  unsigned char buf[32] = {0};
  int temp = 0;

  if (write(fd,wakeup,sizeof(wakeup)) > 1)
    {

      // Using I2C Read
      if (read(fd,buf,4) <= 0) 
        {
          /* ERROR HANDLING: i2c transaction failed */
          perror("Failed to read from the i2c bus.\n");

        } 
      else 
        {

          assert(is_crc_16_valid(buf, 2, buf+2));

          for(temp=0; temp<4; temp++)
            {
              printf("%x ",buf[temp]);
            }
          return 0;
        }
    }

  return -1;

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
