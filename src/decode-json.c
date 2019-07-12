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

#include "decode-json-alert.h"

#include "meer.h"
#include "meer-def.h"

#include "output.h"
#include "decode-json.h"


struct _Classifications *MeerClass;
struct _MeerOutput *MeerOutput;
struct _MeerCounters *MeerCounters;

bool Decode_JSON( char *json_string )
{

    struct json_object *json_obj = NULL;
    struct json_object *tmp = NULL;

    char tmp_type[32] = { 0 };
    bool bad_json = false;

    if ( json_string == NULL )
        {
            MeerCounters->InvalidJSONCount;
            return 1;
        }

    json_obj = json_tokener_parse(json_string);

    if (!json_object_object_get_ex(json_obj, "event_type", &tmp))
        {
            bad_json == true;
        }

    if ( bad_json == false )
        {

            if ( MeerOutput->sql_enabled == true || MeerOutput->external_enabled == true)
                {

                    if ( !strcmp(json_object_get_string(tmp), "alert") )
                        {

                            struct _DecodeAlert *DecodeAlert;   /* Event_type "alert" */
                            DecodeAlert = Decode_JSON_Alert( json_obj, json_string );

                            if ( MeerOutput->sql_enabled == true )
                                {
                                    Output_Alert( DecodeAlert );
                                }

                            if ( MeerOutput->external_enabled == true )
                                {
                                    Output_External( DecodeAlert, json_string );
                                }

                            free(DecodeAlert);

                        }

                }


            /* To keep with the "barnyard2" like theme,  we only output 'alert' Suricata/
             * Sagan events. */

//            if (json_object_object_get_ex(json_obj, "event_type", &tmp))
//                {

//                    if ( !strcmp(json_object_get_string(tmp), "alert") )
//                        {

//                            struct _DecodeAlert *DecodeAlert;   /* Event_type "alert" */
//
//                            DecodeAlert = Decode_JSON_Alert( json_obj, json_string );

//                            Output_Alert( DecodeAlert );

            /* Done with decoding */

//                            free(DecodeAlert);

//                        }
//                }


            if ( MeerOutput->pipe_enabled == true )
                {

//            if (json_object_object_get_ex(json_obj, "event_type", &tmp))
//                {
                    strlcpy(tmp_type, json_object_get_string(tmp), sizeof(tmp_type));

                    Output_Pipe(tmp_type, json_string );

//                }

                }
//    else
//        {

//            MeerCounters->InvalidJSONCount++;
//        }

//    if ( MeerOutput->external_enabled == true )
//	{

//		if ( json_object_object_get_ex(json_obj, "event_type", &tmp))

//		Output_External(json_string);
//	}

        }
    else
        {
            MeerCounters->InvalidJSONCount++;
        }



    /* Delete json-c _root_ objects */

    json_object_put(json_obj);

    return 0;
}
