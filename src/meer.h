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

#ifdef HAVE_LIBMYSQLCLIENT
#include <mysql/mysql.h>
#endif

#ifdef HAVE_LIBPQ
#include <postgresql/libpq-fe.h>
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

    char yaml_file[256];

    char interface[64];
    char hostname[64];
    char runas[32];

    bool daemonize;
    bool quiet;

    char classification_file[256];

    char lock_file[256];
    char waldo_file[256];
    char follow_file[256];

    char meer_log[256];
    FILE *meer_log_fd;
    bool meer_log_on;


    int waldo_fd;

    bool endian;

    bool dns;
    uint32_t dns_cache;

    bool health;

    /* What ever to record */

    bool flow;
    bool http;
    bool tls;
    bool ssh;
    bool smtp;
    bool email;
    bool dns_meta;	/* NOT DONE */
    bool metadata;

};

typedef struct _MeerHealth _MeerHealth;
struct _MeerHealth
{
    uint64_t health_signature;
};

typedef struct _MeerOutput _MeerOutput;
struct _MeerOutput
{

#ifdef HAVE_LIBMYSQLCLIENT

    MYSQL *mysql_dbh;

#endif

#ifdef HAVE_LIBPQ

    PGconn   *psql;
    PGresult *result;

#endif

    bool sql_enabled;
    bool sql_debug;
    bool sql_extra_data;
    char sql_server[128];
    uint32_t sql_port;
    char sql_username[64];
    char sql_password[64];
    char sql_database[64];
    uint32_t sql_sensor_id;
    uint64_t sql_last_cid;

    bool sql_reconnect;
    uint32_t sql_reconnect_time;

    bool sql_flow;
    bool sql_http;
    bool sql_tls;
    bool sql_ssh;
    bool sql_smtp;
    bool sql_email;
    bool sql_metadata;

    char sql_driver;

    bool sql_reference_system;
    char sql_reference_file[256];
    char sql_sid_map_file[256];


};

typedef struct _MeerWaldo _MeerWaldo;
struct _MeerWaldo
{
    uint64_t position;
};

/* Counters */

typedef struct _MeerCounters _MeerCounters;
struct _MeerCounters
{

    int ClassCount;
    int ReferenceCount;			/* Legacy refererence system */
    int SIDMapCount;

#if defined(HAVE_LIBMYSQLCLIENT_R) || defined(HAVE_LIBPQ)

    uint64_t HealthCount;		/* Array count */

    uint64_t HealthCountT;
    uint64_t INSERTCount;
    uint64_t SELECTCount;
    uint64_t UPDATECount;

    uint64_t ClassCacheHitCount;
    uint64_t ClassCacheMissCount;

    uint64_t SigCacheHitCount;
    uint64_t SigCacheMissCount;

#endif

    uint64_t FlowCount;
    uint64_t HTTPCount;
    uint64_t TLSCount;
    uint64_t SMTPCount;
    uint64_t EmailCount;
    uint64_t MetadataCount;
    uint64_t SSHCount;

    uint64_t DNSCount;
    uint64_t DNSCacheCount;



};


bool Decode_JSON( char * );
