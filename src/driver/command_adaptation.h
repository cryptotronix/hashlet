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

#ifndef COMMAND_ADAPTATION_H
#define COMMAND_ADAPTATION_H

#include <stdbool.h>
#include <stdint.h>
#include "command.h"

bool process_command (int fd, struct Command_ATSHA204 *c,
                      uint8_t* rec_buf, unsigned int recv_len);

int send_and_receive (int fd, uint8_t *send_buf, unsigned int send_buf_len,
                      uint8_t *recv_buf, unsigned int recv_buf_len,
                      struct timespec *wait_time);

unsigned int serialize_command (struct Command_ATSHA204 *c, uint8_t **serialized);

bool read_and_validate (int fd, uint8_t *buf, unsigned int len);

#endif /* COMMAND_ADAPTATION_H */
