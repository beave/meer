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

#include "util.h"
#include "meer.h"
#include "meer-def.h"

#include "decode-json-alert.h"

struct _MeerConfig *MeerConfig;

struct _DecodeAlert *Decode_JSON_Alert( struct json_object *json_obj, char *json_string )
{

    struct _DecodeAlert *Alert_Return_Struct = NULL;
    struct json_object *tmp = NULL;
    struct json_object *tmp_alert = NULL;
    struct json_object *json_obj_alert = NULL;

    char src_dns[256] = { 0 };
    char dest_dns[256] = { 0 };

    bool has_alert = false;

    Alert_Return_Struct = malloc(sizeof(_DecodeAlert));

    if ( Alert_Return_Struct == NULL )
        {
            Meer_Log(ERROR, "[%s, line %d] JSON: \"%s\" Failed to allocate memory for _DecodeAlert. Abort!", __FILE__, __LINE__, json_string);
        }

    memset(Alert_Return_Struct, 0, sizeof(_DecodeAlert));

    Alert_Return_Struct->event_type = "alert";
    Alert_Return_Struct->has_extra_data = 0;

    Alert_Return_Struct->timestamp = NULL;
    Alert_Return_Struct->src_ip = NULL;
    Alert_Return_Struct->dest_ip = NULL;
    Alert_Return_Struct->flowid = NULL;
    Alert_Return_Struct->proto = NULL;

    /* Extra data */

    Alert_Return_Struct->xff = NULL;


    Alert_Return_Struct->payload[0] = '\0';
    Alert_Return_Struct->src_dns[0] = '\0';
    Alert_Return_Struct->dest_dns[0] = '\0';

    Alert_Return_Struct->alert_action[0] = '\0';
    Alert_Return_Struct->alert_gid[0] = '\0';
    Alert_Return_Struct->alert_rev = 0;
    Alert_Return_Struct->alert_signature[0] = '\0';
    Alert_Return_Struct->alert_category[0] = '\0';
    Alert_Return_Struct->alert_severity[0] = '\0';

    Alert_Return_Struct->alert_signature_id = 0;


    /* Base information from JSON */

    if (json_object_object_get_ex(json_obj, "timestamp", &tmp))
        {
            Alert_Return_Struct->timestamp = (char *)json_object_get_string(tmp);
        }

    if (json_object_object_get_ex(json_obj, "flow_id", &tmp))
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

    if (json_object_object_get_ex(json_obj, "payload", &tmp))
        {
//	        Alert_Return_Struct->payload = (char *)json_object_get_string(tmp);
            strlcpy(Alert_Return_Struct->payload, (char *)json_object_get_string(tmp), sizeof(Alert_Return_Struct->payload));
        }

    if (json_object_object_get_ex(json_obj, "icmp_type", &tmp))
        {
            Alert_Return_Struct->icmp_type = (char *)json_object_get_string(tmp);
        }

    if (json_object_object_get_ex(json_obj, "icmp_code", &tmp))
        {
            Alert_Return_Struct->icmp_code = (char *)json_object_get_string(tmp);
        }

    /* Extra Data */

    if (json_object_object_get_ex(json_obj, "xff", &tmp))
        {   
	    Alert_Return_Struct->has_extra_data = 1; 
            Alert_Return_Struct->xff = (char *)json_object_get_string(tmp);
        }

    /* Extract "alert" information */

    if (json_object_object_get_ex(json_obj, "alert", &tmp))
        {

            has_alert = true;

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
                    Alert_Return_Struct->alert_signature_id = atol((char *)json_object_get_string(tmp_alert));
                }

            if (json_object_object_get_ex(json_obj_alert, "rev", &tmp_alert))
                {
		    Alert_Return_Struct->alert_rev = atol((char *)json_object_get_string(tmp_alert));
                }

            if (json_object_object_get_ex(json_obj_alert, "signature", &tmp_alert))
                {
                    strlcpy(Alert_Return_Struct->alert_signature, (char *)json_object_get_string(tmp_alert), sizeof(Alert_Return_Struct->alert_signature));
                }

            if (json_object_object_get_ex(json_obj_alert, "category", &tmp_alert))
                {
                    strlcpy(Alert_Return_Struct->alert_category, (char *)json_object_get_string(tmp_alert), sizeof(Alert_Return_Struct->alert_category));
                }

            if (json_object_object_get_ex(json_obj_alert, "severity", &tmp_alert))
                {
                    strlcpy(Alert_Return_Struct->alert_severity, (char *)json_object_get_string(tmp_alert), sizeof(Alert_Return_Struct->alert_severity));
                }

        }


    /* Sanity Checks

    Check the basic information first */

    if ( Alert_Return_Struct->timestamp == NULL )
        {
            Meer_Log(ERROR, "JSON: \"%s\" : No timestamp found in flowid %s.", json_string, Alert_Return_Struct->flowid);
        }


    if ( Alert_Return_Struct->flowid == NULL )
        {
            Alert_Return_Struct->flowid = "0";
        }

    if ( Alert_Return_Struct->src_ip == NULL )
        {
            Meer_Log(WARN, "JSON: \"%s\" : No src_ip found in flowid %s.  Setting to NONE.", json_string, Alert_Return_Struct->flowid);
            Alert_Return_Struct->src_ip = "None";
        }

    if ( Alert_Return_Struct->dest_ip == NULL )
        {
            Meer_Log(WARN, "JSON: \"%s\" : No dest_ip found in flowid %s.  Setting to NONE.", json_string, Alert_Return_Struct->flowid);
            Alert_Return_Struct->dest_ip = "None";
        }

    if ( Alert_Return_Struct->proto == NULL )
        {
            Meer_Log(WARN, "JSON: \"%s\" : No proto found in flowid %s.  Setting to Unknown.", json_string, Alert_Return_Struct->flowid);
            Alert_Return_Struct->proto = "Unknown";
        }

    if ( Alert_Return_Struct->payload[0] == '\0' )
        {
//            Meer_Log(WARN, "JSON: \"%s\" : No payload found in flowid %s.  Setting to NONE.", json_string, Alert_Return_Struct->flowid);
            strlcpy(Alert_Return_Struct->payload, "No payload recorded by Meer", sizeof(Alert_Return_Struct->payload));
        }


    /* Do we have all the alert information we'd expect */


    if ( has_alert == false )
        {
            Meer_Log(ERROR, "JSON: \"%s\" : No alert information found in flowid %s.  Abort!", json_string, Alert_Return_Struct->flowid);
        }

    if ( Alert_Return_Struct->alert_action[0] == '\0' )
        {
            Meer_Log(WARN, "JSON: \"%s\" : No alert -> action found in flowid %s.  Setting to NONE.", json_string, Alert_Return_Struct->flowid);
            strlcpy(Alert_Return_Struct->alert_action, "None", sizeof(Alert_Return_Struct->alert_action));
        }

    if ( Alert_Return_Struct->alert_gid[0] == '\0' )
        {
            Meer_Log(WARN, "JSON: \"%s\" : No alert -> gid found in flowid %s.  Setting to 0.", json_string, Alert_Return_Struct->flowid);
            strlcpy(Alert_Return_Struct->alert_gid, "0", sizeof(Alert_Return_Struct->alert_gid));
        }

    if ( Alert_Return_Struct->alert_signature_id == 0 )
        {
            Meer_Log(ERROR, "JSON: \"%s\" : No alert -> signature_id found in flowid %s. Abort.", json_string, Alert_Return_Struct->flowid);
        }

    if ( Alert_Return_Struct->alert_rev == 0 )
        {
            Meer_Log(WARN, "JSON: \"%s\" : No alert -> rev found in flowid %s.  Setting to 0.", json_string, Alert_Return_Struct->flowid);
	    Alert_Return_Struct->alert_rev = 0; 
        }

    if ( Alert_Return_Struct->alert_signature[0] == '\0' )
        {
            Meer_Log(WARN, "JSON: \"%s\" : No alert -> rev found in flowid %s.  Setting to NONE.", json_string, Alert_Return_Struct->flowid);
            strlcpy(Alert_Return_Struct->alert_signature, "0", sizeof(Alert_Return_Struct->alert_signature));
        }

    if ( Alert_Return_Struct->alert_category[0] == '\0' )
        {
//                Meer_Log(WARN, "JSON: \"%s\" : No alert -> category found in flowid %s.  Setting to NONE.", json_string, Alert_Return_Struct->flowid);
            strlcpy(Alert_Return_Struct->alert_signature, "None", sizeof(Alert_Return_Struct->alert_signature));
        }

    if ( Alert_Return_Struct->alert_severity[0] == '\0' )
        {
            Meer_Log(WARN, "JSON: \"%s\" : No alert -> severity found in flowid %s.  Setting to 0.", json_string, Alert_Return_Struct->flowid);
            strlcpy(Alert_Return_Struct->alert_severity, "0", sizeof(Alert_Return_Struct->alert_severity));
        }

    if ( MeerConfig->dns == true )
        {

            DNS_Lookup(Alert_Return_Struct->src_ip, Alert_Return_Struct->src_dns, sizeof(Alert_Return_Struct->src_dns));
            DNS_Lookup(Alert_Return_Struct->dest_ip, Alert_Return_Struct->dest_dns, sizeof(Alert_Return_Struct->dest_dns));

        }

    /* DEBUG: Sanity check here? */

    /* Clean up local arrays */

    json_object_put(json_obj_alert);
    json_object_put(tmp);
    json_object_put(tmp_alert);


    return(Alert_Return_Struct);
}

