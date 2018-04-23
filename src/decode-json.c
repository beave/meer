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

bool Decode_JSON( char *json_string )
{

    struct json_object *json_obj;
    struct json_object *tmp;

    if ( json_string == NULL )
        {
            return 1;
        }

    json_obj = json_tokener_parse(json_string);

    if (json_object_object_get_ex(json_obj, "event_type", &tmp))
        {

            if ( !strcmp(json_object_get_string(tmp), "alert") )
                {

                    //printf("json_string: |%s|\n", json_string);

                    struct _DecodeAlert *DecodeAlert;   /* Event_type "alert" */

                    DecodeAlert = Decode_JSON_Alert( json_obj, json_string );

                    Output_Alert( DecodeAlert );

                    //printf("%s|\n", DecodeAlert->alert_signature);

                    /* Done with decoding */

                    free(DecodeAlert);

                }
        }


    /* Delete json-c objects */

    json_object_put(json_obj);
    json_object_put(tmp);

    return 0;
}
