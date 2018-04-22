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

#include "meer.h"
#include "meer-def.h"

#include "decode-json-alert.h"

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

                    Output_Alert( DecodeAlert, MeerClass );

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
