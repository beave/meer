/*
** Copyright (C) 2018-2019 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2018-2019 Champ Clark III <cclark@quadrantsec.com>
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

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>


#include "meer.h"
#include "meer-def.h"
#include "util.h"

#include "decode-json-alert.h"
#include "decode-json-dhcp.h"

#include "fingerprints.h"
#include "output-plugins/fingerprint.h"

#include "output-plugins/sql.h"

#ifdef HAVE_LIBHIREDIS


struct _MeerOutput *MeerOutput;
struct _MeerCounters *MeerCounters;
struct _MeerConfig *MeerConfig;

struct _Fingerprint_Networks *Fingerprint_Networks;

void Output_Fingerprint_IP ( struct _DecodeAlert *DecodeAlert, char *fingerprint_IP_JSON )
{

    char key[512] = { 0 };
    snprintf(key, sizeof(key), "%s:ip:%s", FINGERPRINT_REDIS_KEY, DecodeAlert->src_ip);
    Redis_Writer( "SET", key, fingerprint_IP_JSON, FINGERPRINT_IP_REDIS_EXPIRE);

}

void Output_Fingerprint_EVENT( struct _DecodeAlert *DecodeAlert, struct _FingerprintData *FingerprintData, char *fingerprint_EVENT_JSON )
{

    char key[512] = { 0 };

    snprintf(key, sizeof(key), "%s:event:%s:%" PRIu64 "", FINGERPRINT_REDIS_KEY, DecodeAlert->src_ip, DecodeAlert->alert_signature_id);
    Redis_Writer( "SET", key, fingerprint_EVENT_JSON, FingerprintData->expire );

    if ( MeerConfig->fingerprint_log[0] != '\0' )
        {
            fprintf(MeerConfig->fingerprint_log_fd, "%s\n", fingerprint_EVENT_JSON);
            fflush(MeerConfig->fingerprint_log_fd);
        }

}

void Output_Fingerprint_DHCP ( struct _DecodeDHCP *DecodeDHCP, char *fingerprint_DHCP_JSON )
{

    char key[512] = { 0 };
    snprintf(key, sizeof(key), "%s:dhcp:%s", FINGERPRINT_REDIS_KEY, DecodeDHCP->dhcp_assigned_ip);
    Redis_Writer( "SET", key, fingerprint_DHCP_JSON, FINGERPRINT_DHCP_REDIS_EXPIRE );

}


void Output_Fingerprint_Alert( struct _DecodeAlert *DecodeAlert )
{

    int i=0;
    int j=0;
    redisReply *reply;
    int key_count=0;
    char fingerprint_tmp[10240] = { 0 };
    char fingerprint_sql[10240*2] = { 0 };

    char fingerprint_dhcp_tmp[1024] = { 0 };
    char fingerprint_dhcp[1024*2] = { 0 };


    char tmp_command[ 10240 + (10240*2) ] = { 0 };

    unsigned char ip[MAXIPBIT] = { 0 };

    /* Lookup ip source from fingerprinting data */

    IP2Bit(DecodeAlert->src_ip, ip);

//            if ( Is_Inrange( ip, (unsigned char *)&Fingerprint_Networks[i].range, 1) )
//                {

                    snprintf(tmp_command, sizeof(tmp_command), "GET %s:dhcp:%s", FINGERPRINT_REDIS_KEY, DecodeAlert->src_ip);
                    Redis_Reader(tmp_command, fingerprint_dhcp_tmp, sizeof(fingerprint_dhcp_tmp));

                    if ( fingerprint_dhcp_tmp[0] != '\0' )
                        {

                            mysql_real_escape_string(MeerOutput->mysql_dbh, fingerprint_dhcp, fingerprint_dhcp_tmp, strlen(fingerprint_dhcp_tmp));

                            snprintf(tmp_command, sizeof(tmp_command), "INSERT INTO fingerprint_dhcp_src (sid, cid, json) VALUES \
(%d, %llu, '%s' )", MeerOutput->sql_sensor_id, MeerOutput->sql_last_cid, fingerprint_dhcp);
                            (void)SQL_DB_Query(tmp_command);

                        }

//		}



    for ( j=0; j < MeerCounters->fingerprint_network_count; j++ )
        {
		printf("COUNT: %d < %d\n", j, MeerCounters->fingerprint_network_count);

            if ( Is_Inrange( ip, (unsigned char *)&Fingerprint_Networks[j].range, 1) )
                {

/*
                    snprintf(tmp_command, sizeof(tmp_command), "GET %s:dhcp:%s", FINGERPRINT_REDIS_KEY, DecodeAlert->src_ip);
                    Redis_Reader(tmp_command, fingerprint_dhcp_tmp, sizeof(fingerprint_dhcp_tmp));

                    if ( fingerprint_dhcp_tmp[0] != '\0' )
                        {

                            mysql_real_escape_string(MeerOutput->mysql_dbh, fingerprint_dhcp, fingerprint_dhcp_tmp, strlen(fingerprint_dhcp_tmp));

                            snprintf(tmp_command, sizeof(tmp_command), "INSERT INTO fingerprint_dhcp_src (sid, cid, json) VALUES \
(%d, %llu, '%s' )", MeerOutput->sql_sensor_id, MeerOutput->sql_last_cid, fingerprint_dhcp);
                            (void)SQL_DB_Query(tmp_command);

                        }
*/

                    reply = redisCommand(MeerOutput->c_redis, "SCAN 0 MATCH %s:event:%s:* count 1000", FINGERPRINT_REDIS_KEY, DecodeAlert->src_ip);

                    key_count = reply->element[1]->elements;

                    for ( i = 0; i < key_count; i++)
                        {

                            redisReply *kr = reply->element[1]->element[i];
                            snprintf(tmp_command, sizeof(tmp_command), "GET %s", kr->str);
                            Redis_Reader(tmp_command, fingerprint_tmp, sizeof(fingerprint_tmp));

                            mysql_real_escape_string(MeerOutput->mysql_dbh, fingerprint_sql, fingerprint_tmp, strlen(fingerprint_tmp));

                            snprintf(tmp_command, sizeof(tmp_command), "INSERT INTO fingerprint_src (sid, cid, json) VALUES \
(%d, %llu, '%s' )", MeerOutput->sql_sensor_id, MeerOutput->sql_last_cid, fingerprint_sql);
                            (void)SQL_DB_Query(tmp_command);


                        }
                }
        }

    IP2Bit(DecodeAlert->dest_ip, ip);

//            if ( Is_Inrange( ip, (unsigned char *)&Fingerprint_Networks[i].range, 1) )
//                {

                    snprintf(tmp_command, sizeof(tmp_command), "GET %s:dhcp:%s", FINGERPRINT_REDIS_KEY, DecodeAlert->dest_ip);
                    Redis_Reader(tmp_command, fingerprint_dhcp_tmp, sizeof(fingerprint_dhcp_tmp));

                    if ( fingerprint_dhcp_tmp[0] != '\0' )
                        {

                            mysql_real_escape_string(MeerOutput->mysql_dbh, fingerprint_dhcp, fingerprint_dhcp_tmp, strlen(fingerprint_dhcp_tmp));

                            snprintf(tmp_command, sizeof(tmp_command), "INSERT INTO fingerprint_dhcp_dest (sid, cid, json) VALUES \
(%d, %llu, '%s' )", MeerOutput->sql_sensor_id, MeerOutput->sql_last_cid, fingerprint_dhcp);
                            (void)SQL_DB_Query(tmp_command);

                        }
//		}


    for ( j=0; j < MeerCounters->fingerprint_network_count; j++ )
        {

            if ( Is_Inrange( ip, (unsigned char *)&Fingerprint_Networks[j].range, 1) )
                {
/*
                    snprintf(tmp_command, sizeof(tmp_command), "GET %s:dhcp:%s", FINGERPRINT_REDIS_KEY, DecodeAlert->dest_ip);
                    Redis_Reader(tmp_command, fingerprint_dhcp_tmp, sizeof(fingerprint_dhcp_tmp));

                    if ( fingerprint_dhcp_tmp[0] != '\0' )
                        {

                            mysql_real_escape_string(MeerOutput->mysql_dbh, fingerprint_dhcp, fingerprint_dhcp_tmp, strlen(fingerprint_dhcp_tmp));

                            snprintf(tmp_command, sizeof(tmp_command), "INSERT INTO fingerprint_dhcp_dest (sid, cid, json) VALUES \
(%d, %llu, '%s' )", MeerOutput->sql_sensor_id, MeerOutput->sql_last_cid, fingerprint_dhcp);
                            (void)SQL_DB_Query(tmp_command);

                        }
*/

                    reply = redisCommand(MeerOutput->c_redis, "SCAN 0 MATCH %s:event:%s:* COUNT 1000", FINGERPRINT_REDIS_KEY,  DecodeAlert->dest_ip);

                    key_count = reply->element[1]->elements;

                    for ( i = 0; i < key_count; i++)
                        {

                            redisReply *kr = reply->element[1]->element[i];
                            snprintf(tmp_command, sizeof(tmp_command), "GET %s", kr->str);
                            Redis_Reader(tmp_command, fingerprint_tmp, sizeof(fingerprint_tmp));

                            mysql_real_escape_string(MeerOutput->mysql_dbh, fingerprint_sql, fingerprint_tmp, strlen(fingerprint_tmp));

                            snprintf(tmp_command, sizeof(tmp_command), "INSERT INTO fingerprint_dest (sid, cid, json) VALUES \
(%d, %llu, '%s' )", MeerOutput->sql_sensor_id, MeerOutput->sql_last_cid, fingerprint_sql);
                            (void)SQL_DB_Query(tmp_command);


                        }
                }
        }

}

#endif
