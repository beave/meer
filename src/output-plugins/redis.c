/*
** Copyright (C) 2018-2020 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2018-2020 Champ Clark III <cclark@quadrantsec.com>
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

/* MySQL/MariaDB specific routines */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#ifdef HAVE_LIBHIREDIS

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <hiredis/hiredis.h>

#include "meer.h"
#include "meer-def.h"
#include "lockfile.h"
#include "config-yaml.h"
#include "decode-output-json-client-stats.h"

struct _MeerOutput *MeerOutput;

uint32_t redis_batch_count = 0;

char redis_batch[MAX_REDIS_BATCH][10240 + PACKET_BUFFER_SIZE_DEFAULT];

void Redis_Connect( void )
{

    redisReply *reply;
    MeerOutput->c_redis = NULL;

    while ( MeerOutput->c_redis == NULL || MeerOutput->c_redis->err )
        {

            struct timeval timeout = { 1, 500000 }; // 5.5 seconds
            MeerOutput->c_redis = redisConnectWithTimeout(MeerOutput->redis_server, MeerOutput->redis_port, timeout);

            if (MeerOutput->c_redis == NULL || MeerOutput->c_redis->err)
                {

                    if (MeerOutput->c_redis)
                        {
                            redisFree(MeerOutput->c_redis);
                            Meer_Log(WARN, "[%s, line %d] Redis 'reader' connection error! Sleeping for 2 seconds!", __FILE__, __LINE__);

                        }
                    else
                        {
                            Meer_Log(WARN, "[%s, line %d] Redis 'reader' connection error - Can't allocate Redis context", __FILE__, __LINE__);
                        }
                    sleep(2);
                }
        }


    /* Log into Redis (if needed) */

    if ( MeerOutput->redis_password[0] != '\0' )
        {

            reply = redisCommand(MeerOutput->c_redis, "AUTH %s", MeerOutput->redis_password);

            if (!strcmp(reply->str, "OK"))
                {

                    if ( MeerOutput->redis_debug )
                        {

                            Meer_Log( DEBUG, "Authentication success for 'reader' to Redis server at %s:%d.", MeerOutput->redis_server, MeerOutput->redis_port );

                        }

                }
            else
                {

                    Remove_Lock_File();
                    Meer_Log(ERROR, "Authentication failure for 'reader' to to Redis server at %s:%d. Abort!", MeerOutput->redis_server, MeerOutput->redis_port );

                }
        }

    Meer_Log(NORMAL, "Successfully connected to Redis server at %s:%d.", MeerOutput->redis_server, MeerOutput->redis_port );

    MeerOutput->redis_error = false;

}

void Redis_Reader ( char *redis_command, char *str, size_t size )
{

    redisReply *reply;

    while ( MeerOutput->redis_error == true )
        {
            Redis_Connect();
        }

    reply = redisCommand(MeerOutput->c_redis, redis_command);

    /* Get results */

    if ( reply != NULL )
        {

            if ( MeerOutput->redis_debug )
                {
                    Meer_Log(DEBUG, "[%s, line %d] Redis Command: \"%s\"", __FILE__, __LINE__, redis_command);
                    Meer_Log(DEBUG, "[%s, line %d] Redis Reply: \"%s\"", __FILE__, __LINE__, reply->str);
                }

            /* strlcpy doesn't like to pass str as a \0.  This
               "works" around that issue (causes segfault otherwise) */

            if ( reply->str != '\0' )
                {
                    strlcpy(str, reply->str, size);
                }
            else
                {
                    str[0] = '\0';
                }
        }
    else
        {
            strlcpy(str, reply->element[0]->str, size);
        }

    /* Got good response, free here.  If we don't get a good response
       and free, we'll get a fault. */

    freeReplyObject(reply);


}

bool Redis_Writer ( char *command, char *key, char *value, int expire )
{

    redisReply *reply;

    if ( expire == 0 )
        {
            reply = redisCommand(MeerOutput->c_redis, "%s %s %s", command, key, value);
	
	    if ( MeerOutput->redis_debug )
		{
		 Meer_Log(DEBUG, "Sent to Redis: %s %s %s", command, key, value);
		}
        }
    else
        {
            reply = redisCommand(MeerOutput->c_redis, "%s %s %s EX %d", command, key, value, expire);

            if ( MeerOutput->redis_debug )
                {
                 Meer_Log(DEBUG, "Sent to Redis: %s %s %s EX %d", command, key, value, expire);
                }
        }

    if ( reply != NULL )
        {

            if ( MeerOutput->redis_debug )
                {
                    Meer_Log(DEBUG, "Write reply-str: '%s'", reply->str);
                }

            freeReplyObject(reply);
        }
    else
        {

            MeerOutput->redis_error = true;

        }

}


void JSON_To_Redis ( char *json_string )
{

    int i = 0;

    if ( redis_batch_count == MeerOutput->redis_batch )
        {

            for ( i = 0; i < MeerOutput->redis_batch; i ++ )
                {
                    Redis_Writer ( MeerOutput->redis_command, MeerOutput->redis_key, redis_batch[i], 0 );
                }

            redis_batch_count = 0;

            if ( MeerOutput->redis_debug )
                {
                    Meer_Log(WARN, "[%s, line %d] Wrote out Redis batch!", __FILE__, __LINE__);
                }

        }

    strlcpy(redis_batch[redis_batch_count], json_string, sizeof(redis_batch[redis_batch_count]));

    redis_batch_count++;

}


#endif
