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

#ifndef I2C_H
#define I2C_H

#include <unistd.h>
#include <stdbool.h>

/* /\** */
/*  * Open the I2C bus */
/*  * */
/*  * @param bus The desired I2C bus. */
/*  * */
/*  * @return An open file descriptor or the program will exit. */
/*  *\/ */
/* int i2c_setup(const char* bus); */

/* void i2c_acquire_bus(int fd, int addr); */

/* bool wakeup(int fd); */

/* int sleep_device(int fd); */

/* ssize_t i2c_write(int fd, unsigned char *buf, unsigned int len); */

/* ssize_t i2c_read(int fd, unsigned char *buf, unsigned int len); */


#endif /* I2C_H */
