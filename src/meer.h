/*
** Copyright (C) 2018 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2018 Champ Clark III <cclark@quadrantsec.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#ifdef HAVE_LIBMYSQLCLIENT_R
#include <mysql/mysql.h>
#endif

#include <stdbool.h>
#include <inttypes.h>

#ifndef HAVE_STRLCAT
size_t strlcat(char *, const char *, size_t );
#endif

#ifndef HAVE_STRLCPY
size_t strlcpy(char *, const char *, size_t );
#endif

void Meer_Log (int type, const char *format,... );

/* Global Meer Configs */

typedef struct _MeerConfig _MeerConfig;
struct _MeerConfig
{

    char interface[64];
    char hostname[64];
    char runas[32];

    char classification_file[256];
    char reference_file[256];
    char genmsgmap_file[256];

    char lock_file[256];
    char waldo_file[256];
    char follow_file[256];

    int waldo_fd;

};


typedef struct _MeerOutput _MeerOutput;
struct _MeerOutput
{

#ifdef HAVE_LIBMYSQLCLIENT_R

    bool mysql_enabled;
    bool mysql_debug;
    char mysql_server[128];
    uint32_t mysql_port;
    char mysql_username[64];
    char mysql_password[64];
    char mysql_database[64];
    uint32_t mysql_sensor_id;
    MYSQL *mysql_dbh;

#endif

};

typedef struct _MeerWaldo _MeerWaldo;
struct _MeerWaldo
{
    uint64_t position;
};


