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

struct _DecodeAlert *Decode_JSON_Alert( struct json_object *json_obj )
    {

        struct _DecodeAlert *Alert_Return_Struct;
        struct json_object *tmp;
        struct json_object *tmp_alert;
        struct json_object *json_obj_alert;

        Alert_Return_Struct = malloc(sizeof(_DecodeAlert));

        if ( Alert_Return_Struct == NULL )
            {
                Meer_Log(M_ERROR, "[%s, line %d] Failed to allocate memory for _DecodeAlert. Abort!", __FILE__, __LINE__);
            }

        memset(Alert_Return_Struct, 0, sizeof(_DecodeAlert));

        Alert_Return_Struct->event_type = "alert";

        /* Base information from JSON */

        if (json_object_object_get_ex(json_obj, "timestamp", &tmp))
            {
                Alert_Return_Struct->timestamp = (char *)json_object_get_string(tmp);
            }

        if (json_object_object_get_ex(json_obj, "flowid", &tmp))
            {
                Alert_Return_Struct->flowid = (char *)json_object_get_string(tmp);
            }

        if (json_object_object_get_ex(json_obj, "in_iface", &tmp))
            {
                Alert_Return_Struct->in_iface = (char *)json_object_get_string(tmp);
            }

        if (json_object_object_get_ex(json_obj, "src_ip", &tmp))
            {
                Alert_Return_Struct->src_ip = (char *)json_object_get_string(tmp);
            }

        if (json_object_object_get_ex(json_obj, "src_port", &tmp))
            {
                Alert_Return_Struct->src_port = (char *)json_object_get_string(tmp);
            }

        if (json_object_object_get_ex(json_obj, "dest_ip", &tmp))
            {
                Alert_Return_Struct->dest_ip = (char *)json_object_get_string(tmp);
            }

        if (json_object_object_get_ex(json_obj, "dest_port", &tmp))
            {
                Alert_Return_Struct->dest_port = (char *)json_object_get_string(tmp);
            }

        if (json_object_object_get_ex(json_obj, "proto", &tmp))
            {
                Alert_Return_Struct->proto = (char *)json_object_get_string(tmp);
            }

        /* Extract "alert" information */

        if (json_object_object_get_ex(json_obj, "alert", &tmp))
            {

                json_obj_alert = json_tokener_parse(json_object_get_string(tmp));

                if (json_object_object_get_ex(json_obj_alert, "action", &tmp_alert))
                    {
                        strlcpy(Alert_Return_Struct->alert_action, (char *)json_object_get_string(tmp_alert), sizeof(Alert_Return_Struct->alert_action));
                    }

                if (json_object_object_get_ex(json_obj_alert, "gid", &tmp_alert))
                    {
                        strlcpy(Alert_Return_Struct->alert_gid, (char *)json_object_get_string(tmp_alert), sizeof(Alert_Return_Struct->alert_action));
                    }

                if (json_object_object_get_ex(json_obj_alert, "signature_id", &tmp_alert))
                    {
                        strlcpy(Alert_Return_Struct->alert_signature_id, (char *)json_object_get_string(tmp_alert), sizeof(Alert_Return_Struct->alert_signature_id));
                    }

                if (json_object_object_get_ex(json_obj_alert, "rev", &tmp_alert))
                    {
                        strlcpy(Alert_Return_Struct->alert_rev, (char *)json_object_get_string(tmp_alert), sizeof(Alert_Return_Struct->alert_rev));
                    }

                if (json_object_object_get_ex(json_obj_alert, "signature", &tmp_alert))
                    {
                        strlcpy(Alert_Return_Struct->alert_signature, (char *)json_object_get_string(tmp_alert), sizeof(Alert_Return_Struct->alert_signature));
                    }

                if (json_object_object_get_ex(json_obj_alert, "alert_catagory", &tmp_alert))
                    {
                        strlcpy(Alert_Return_Struct->alert_catagory, (char *)json_object_get_string(tmp_alert), sizeof(Alert_Return_Struct->alert_catagory));
                    }

                if (json_object_object_get_ex(json_obj_alert, "alert_severity", &tmp_alert))
                    {
                        strlcpy(Alert_Return_Struct->alert_severity, (char *)json_object_get_string(tmp_alert), sizeof(Alert_Return_Struct->alert_severity));
                    }

            }

        /* Clean up local arrays */

        json_object_put(json_obj_alert);
        json_object_put(tmp);
        json_object_put(tmp_alert);


        return(Alert_Return_Struct);
    }

