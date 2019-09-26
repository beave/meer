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

/* EVE JSON decode */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#ifdef HAVE_LIBJSON_C
#include <json-c/json.h>
#endif


#ifndef HAVE_LIBJSON_C
libjson-c is required for Meer to function!
#endif

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>

#include "decode-json.h"
#include "decode-json-alert.h"
#include "decode-json-dhcp.h"

#include "decode-output-json-client-stats.h"

#include "meer.h"
#include "meer-def.h"

#include "output.h"


struct _Classifications *MeerClass;
struct _MeerOutput *MeerOutput;
struct _MeerCounters *MeerCounters;
struct _MeerConfig *MeerConfig;

bool Decode_JSON( char *json_string )
{

    struct json_object *json_obj = NULL;
    struct json_object *tmp = NULL;

    char tmp_type[32] = { 0 };
    bool bad_json = false;
    bool fingerprint_return = false;

    if ( json_string == NULL )
        {
            MeerCounters->InvalidJSONCount++;
            return 1;
        }

    json_obj = json_tokener_parse(json_string);

    if (!json_object_object_get_ex(json_obj, "event_type", &tmp))
        {
            bad_json = true;
        }

    if ( tmp == NULL )
        {
            bad_json = true;
        }

    if ( bad_json == false )
        {

            if ( MeerOutput->sql_enabled == true || MeerOutput->external_enabled == true )
                {

                    if ( !strcmp(json_object_get_string(tmp), "alert") )
                        {

                            struct _DecodeAlert *DecodeAlert;   /* event_type: alert */
                            DecodeAlert = Decode_JSON_Alert( json_obj, json_string );

                            /* DEBUG - if MeerConfig->fingerprint == true && MeerOutput->sql_fingerprint == true we NOT
                               want the event to go to Output_Alert_SQL!  */

                            if ( MeerOutput->sql_fingerprint == true )
                                {
                                    fingerprint_return = Output_Fingerprint( DecodeAlert );
                                }

                            if ( MeerOutput->sql_enabled == true && fingerprint_return == false )
                                {
                                    Output_Alert_SQL( DecodeAlert );
                                }

                            if ( MeerOutput->external_enabled == true )
                                {
                                    Output_External( DecodeAlert, json_string );
                                }

                            free(DecodeAlert);

                        }

                }

            if ( !strcmp(json_object_get_string(tmp), "dhcp") && MeerConfig->fingerprint == true )
                {
                    struct _DecodeDHCP *DecodeDHCP;   /* event_type: dhcp */
                    DecodeDHCP = Decode_JSON_DHCP( json_obj, json_string );

                    Output_Fingerprint_DHCP ( DecodeDHCP );

                }

            /* Process stats data from Sagan */

            if ( !strcmp(json_object_get_string(tmp), "client_stats") && MeerConfig->client_stats == true )
                {
                    Decode_Output_JSON_Client_Stats( json_obj, json_string );
                }


            if ( MeerOutput->pipe_enabled == true )
                {
                    strlcpy(tmp_type, json_object_get_string(tmp), sizeof(tmp_type));
                    Output_Pipe(tmp_type, json_string );
                }

#ifdef HAVE_LIBHIREDIS

            if ( MeerOutput->redis_flag == true )
                {

                    if ( !strcmp(json_object_get_string(tmp), "flow") && MeerOutput->redis_flow == true )
                        {
                            JSON_To_Redis( json_string );
                        }

                    else if ( !strcmp(json_object_get_string(tmp), "dns") && MeerOutput->redis_dns == true )
                        {
                            JSON_To_Redis( json_string );
                        }

                    else if ( !strcmp(json_object_get_string(tmp), "alert") && MeerOutput->redis_alert == true)
                        {
                            JSON_To_Redis( json_string );
                        }

                    else if ( !strcmp(json_object_get_string(tmp), "http") && MeerOutput->redis_http == true)
                        {
                            JSON_To_Redis( json_string );
                        }

                    else if ( !strcmp(json_object_get_string(tmp), "files" ) && MeerOutput->redis_files == true )
                        {
                            JSON_To_Redis( json_string );
                        }

                    else if ( !strcmp(json_object_get_string(tmp), "tls" ) && MeerOutput->redis_tls == true)
                        {
                            JSON_To_Redis( json_string );
                        }

                    else if ( !strcmp(json_object_get_string(tmp), "ssh" ) && MeerOutput->redis_ssh == true)
                        {
                            JSON_To_Redis( json_string );
                        }

                    else if ( !strcmp(json_object_get_string(tmp), "smtp" ) && MeerOutput->redis_smtp == true)
                        {
                            JSON_To_Redis( json_string );
                        }

                    else if ( !strcmp(json_object_get_string(tmp), "fileinfo" ) && MeerOutput->redis_fileinfo == true)
                        {
                            JSON_To_Redis( json_string );
                        }

                    else if ( !strcmp(json_object_get_string(tmp), "dhcp" ) && MeerOutput->redis_dhcp == true)
                        {
                            JSON_To_Redis( json_string );
                        }

                }

#endif

        }
    else
        {
            MeerCounters->InvalidJSONCount++;
        }


    /* Delete json-c _root_ objects */

    json_object_put(json_obj);

    return 0;
}
