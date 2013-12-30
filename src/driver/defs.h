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

#ifndef DEFS_H
#define DEFS_H

/* Command OPCODES */
#define COMMAND_DERIVE_KEY      0x1C
#define COMMAND_DEV_REV         0x30
#define COMMAND_GEN_DIG         0x15
#define COMMAND_HMAC            0x11
#define COMMAND_CHECK_MAC       0x28
#define COMMAND_LOCK            0x17
#define COMMAND_MAC             0x08
#define COMMAND_NONCE           0x16
#define COMMAND_PAUSE           0x01
#define COMMAND_RANDOM          0x1B
#define COMMAND_READ            0x02
#define COMMAND_UPDATE_EXTRA    0x20
#define COMMAND_WRITE           0x12

/* Command responses */
#define SUCCESS_RESPONSE        0x00
#define CHECKMAC_MISCOMPARE     0x01
#define PARSE_ERROR             0x03
#define EXECUTION_ERROR         0x0F
#define IM_AWAKE                0x11
#define CRC_OR_COMM_ERROR       0xFF


#define MAX_NUM_DATA_SLOTS      16

/* Slot config definition */
#define MAX_SLOTS 16


/* Random Command, i.e. actual random not a random command, ha! */

#define RANDOM_UPDATE_SEED      0
#define RANDOM_NO_UPDATE_SEED   1
#define RANDOM_RSP_LENGTH       32

/* Read Command Options */

#define READ4_LENGTH            4
#define READ32_LENGTH           32

/* Execution Times (all times in nanosecs) */
#define DERIVE_KEY_AVG_EXEC 14000000
#define MAC_AVG_EXEC 12000000
#define DEV_REV_AVG_EXEC 400000
#define GEN_DIG_AVG_EXEC 11000000
#define HMAC_AVG_EXEC 27000000
#define CHECK_MAC_AVG_EXEC 12000000
#define LOCK_AVG_EXEC 5000000
#define NONCE_AVG_EXEC 22000000
#define PAUSE_AVG_EXEC 400000
#define READ_AVG_EXEC 400000
#define UPDATE_EXTRA_AVG_EXEC 8000000
#define WRITE_AVG_EXEC 4000000
#define RANDOM_AVG_EXEC 11000000

#define DERIVE_KEY_MAX_EXEC 62000000
#define DEV_REV_MAX_EXEC 2000000
#define GEN_DIG_MAX_EXEC 43000000
#define HMAC_MAX_EXEC 69000000
#define CHECK_MAC_MAX_EXEC 38000000
#define LOCK_MAX_EXEC 24000000
#define MAC_MAX_EXEC 35000000
#define NONCE_MAX_EXEC 60000000
#define PAUSE_MAX_EXEC 2000000
#define RANDOM_MAX_EXEC 50000000
#define READ_MAX_EXEC 4000000
#define UPDATE_EXTRA_MAX_EXEC 12000000
#define WRITE_MAX_EXEC 42000000



#endif /* DEFS_H */
