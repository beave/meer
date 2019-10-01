#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdbool.h>
#include <time.h>
#include <string.h>
#include <unistd.h>

#include "decode-json-alert.h"
#include "decode-json-dhcp.h"

#include "fingerprint.h"

#include "meer.h"
#include "meer-def.h"
#include "util.h"
#include "output.h"
#include "references.h"
#include "sid-map.h"
#include "config-yaml.h"

struct _FingerprintData *Parse_Fingerprint ( struct _DecodeAlert *DecodeAlert )
{

    struct _FingerprintData *FingerprintData_Return = NULL;

    struct json_object *json_obj = NULL;
    struct json_object *tmp = NULL;

    char *fingerprint_d_os = NULL;
    char *fingerprint_d_type = NULL;

    char *fingerprint_os = "unknown";
    char *fingerprint_type = "unknown";

    char *ptr1 = NULL;
    char *ptr2 = NULL;

//    bool ret = false;

    FingerprintData_Return = (struct _FingerprintData *) malloc(sizeof(_FingerprintData));

    if ( FingerprintData_Return == NULL )
        {
            Meer_Log(ERROR, "[%s, line %d] Failed to allocate memory for _FingerprintData. Abort!", __FILE__, __LINE__);
        }

    memset(FingerprintData_Return, 0, sizeof(_FingerprintData));


    //FingerprintData_Return->fingerprint_os="unknown";
    //FingerprintData_Return->fingerprint_type="unknown";

    if ( DecodeAlert->alert_metadata[0] != '\0' )
        {

            json_obj = json_tokener_parse(DecodeAlert->alert_metadata);

            if ( json_object_object_get_ex(json_obj, "fingerprint_os", &tmp))
                {

                    FingerprintData_Return->ret = true;

                    fingerprint_d_os =  (char *)json_object_get_string(tmp);

                    strtok_r(fingerprint_d_os, "\"", &ptr1);

                    if ( ptr1 == NULL )
                        {
                            Meer_Log(WARN, "[%s, line %d] Failure to decode fingerprint_os from %s", __FILE__, __LINE__, fingerprint_d_os);
                        }

                    fingerprint_os = strtok_r(NULL, "\"", &ptr1);

                    if ( fingerprint_os == NULL )
                        {
                            Meer_Log(WARN, "[%s, line %d] Failure to decode fingerprint_os from %s", __FILE__, __LINE__, fingerprint_d_os);
                        }

                    strlcpy(FingerprintData_Return->os, fingerprint_os, sizeof(FingerprintData_Return->os));
                }

            if ( json_object_object_get_ex(json_obj, "fingerprint_type", &tmp))
                {

                    FingerprintData_Return->ret = true;

                    fingerprint_d_type =  (char *)json_object_get_string(tmp);

                    if ( strcasestr( fingerprint_d_type, "client") )
                        {
			    strlcpy(FingerprintData_Return->type, fingerprint_d_type, sizeof(FingerprintData_Return->type));
                        }

                    else if ( strcasestr( fingerprint_d_type, "server") )
                        {
			    strlcpy(FingerprintData_Return->type, fingerprint_d_type, sizeof(FingerprintData_Return->type));
                        }


                }

	} 


    json_object_put(json_obj);
    return(FingerprintData_Return);

}

void Fingerprint_IP_JSON ( struct _DecodeAlert *DecodeAlert, char *str, size_t size )
{

    struct json_object *encode_json = NULL;
    encode_json = json_object_new_object();

    json_object *jtimestamp = json_object_new_string( DecodeAlert->timestamp );
    json_object_object_add(encode_json,"timestamp", jtimestamp);

    if ( DecodeAlert->src_ip != NULL )
        {
            json_object *jip = json_object_new_string( DecodeAlert->src_ip );
            json_object_object_add(encode_json,"ip", jip);
        }

    snprintf(str, size, "%s", json_object_to_json_string(encode_json));

    json_object_put(encode_json);

}


void Fingerprint_EVENT_JSON ( struct _DecodeAlert *DecodeAlert, struct _FingerprintData *FingerprintData, char *str, size_t size )
{

    struct json_object *encode_json = NULL;
    encode_json = json_object_new_object();

    struct json_object *encode_json_fp = NULL;
    encode_json_fp = json_object_new_object();

    struct json_object *encode_json_http = NULL;
    encode_json_http = json_object_new_object();

    json_object *jevent_type = json_object_new_string( "fingerprint" );
    json_object_object_add(encode_json,"event_type", jevent_type);


    if ( DecodeAlert->timestamp != NULL )
        {
            json_object *jtimestamp = json_object_new_string( DecodeAlert->timestamp );
            json_object_object_add(encode_json,"timestamp", jtimestamp);
        }

    if ( DecodeAlert->host != NULL )
        {
            json_object *jhost = json_object_new_string( DecodeAlert->host );
            json_object_object_add(encode_json,"host", jhost);
        }

    if ( DecodeAlert->flowid != NULL )
        {
            json_object *jflow_id = json_object_new_int64( atol(DecodeAlert->flowid) );
            json_object_object_add(encode_json,"flow_id", jflow_id);
        }

    if ( DecodeAlert->in_iface != NULL )
        {
            json_object *jin_iface = json_object_new_string( DecodeAlert->in_iface );
            json_object_object_add(encode_json,"in_iface", jin_iface);
        }

//    json_object *jevent_type = json_object_new_string( "fingerprint" );
//    json_object_object_add(encode_json,"event_type", jevent_type);

    if ( DecodeAlert->src_ip != NULL )
        {
            json_object *jsrc_ip = json_object_new_string( DecodeAlert->src_ip );
            json_object_object_add(encode_json,"src_ip", jsrc_ip );
        }

    if ( DecodeAlert->src_port != NULL )
        {
            json_object *jsrc_port = json_object_new_int( atoi( DecodeAlert->src_port) );
            json_object_object_add(encode_json,"src_port", jsrc_port );
        }

    if ( DecodeAlert->dest_ip != NULL )
        {
            json_object *jdest_ip = json_object_new_string( DecodeAlert->dest_ip );
            json_object_object_add(encode_json,"dest_ip", jdest_ip );
        }

    if ( DecodeAlert->dest_port != NULL )
        {
            json_object *jdest_port = json_object_new_int( atoi( DecodeAlert->dest_port) );
            json_object_object_add(encode_json,"dest_port", jdest_port );
        }

    if ( DecodeAlert->proto == NULL )
        {
            json_object *jproto = json_object_new_string( DecodeAlert->proto );
            json_object_object_add(encode_json,"proto", jproto );
        }


//    json_object *jfingerprint_type = json_object_new_string( "event" );
//    json_object_object_add(encode_json_fp,"fingerprint_type", jfingerprint_type);

    json_object *jalert_signature_id = json_object_new_int64( DecodeAlert->alert_signature_id );
    json_object_object_add(encode_json_fp,"signature_id", jalert_signature_id );

    json_object *jalert_rev = json_object_new_int64( DecodeAlert->alert_rev );
    json_object_object_add(encode_json_fp,"rev", jalert_rev );

    if ( DecodeAlert->alert_signature != NULL )
        {
            json_object *jsignature = json_object_new_string( DecodeAlert->alert_signature );
            json_object_object_add(encode_json_fp,"signature", jsignature );
        }

    if ( FingerprintData->os[0] != '\0' )
        {
            json_object *jfingerprint_os = json_object_new_string( FingerprintData->os );
            json_object_object_add(encode_json_fp,"os", jfingerprint_os );
        }

    if ( FingerprintData->type[0] != '\0' )
        {
            json_object *jfingerprint_type = json_object_new_string( FingerprintData->type );
            json_object_object_add(encode_json_fp,"client_server", jfingerprint_type );
        }

    if ( DecodeAlert->app_proto[0] != '\0' )
        {
            json_object *japp_proto = json_object_new_string( DecodeAlert->app_proto );
            json_object_object_add(encode_json_fp,"app_proto", japp_proto );
        }

    if ( DecodeAlert->payload != NULL )
        {
            json_object *jpayload = json_object_new_string( DecodeAlert->payload );
            json_object_object_add(encode_json_fp,"payload", jpayload );
        }

    if ( !strcmp(DecodeAlert->app_proto, "http") )
        {

            if ( DecodeAlert->http_user_agent[0] != '\0' )
                {
                    json_object *jhttp_user_agent = json_object_new_string( DecodeAlert->http_user_agent );
                    json_object_object_add(encode_json_http,"http_user_agent", jhttp_user_agent );
                }

            if ( DecodeAlert->http_xff[0] != '\0' )
                {
                    json_object *jhttp_xff = json_object_new_string( DecodeAlert->http_xff );
                    json_object_object_add(encode_json_http,"xff", jhttp_xff );
                }

            json_object *jfp_http = json_object_new_string( json_object_to_json_string(encode_json_http) );
            json_object_object_add(encode_json,"http", jfp_http );


        }

    json_object *jfp = json_object_new_string( json_object_to_json_string(encode_json_fp) );
    json_object_object_add(encode_json,"fingerprint", jfp );

    snprintf(str, size, "%s", json_object_to_json_string(encode_json));

    json_object_put(encode_json);
    json_object_put(encode_json_fp);
    json_object_put(encode_json_http);

}

void Fingerprint_DHCP_JSON ( struct _DecodeDHCP *DecodeDHCP, char *str, size_t size )
{

    struct json_object *encode_json = NULL;
    encode_json = json_object_new_object();

    json_object *jtimestamp = json_object_new_string( DecodeDHCP->timestamp );
    json_object_object_add(encode_json,"timestamp", jtimestamp);

    if ( DecodeDHCP->dhcp_assigned_ip[0] != '\0' )
        {
            json_object *jdhcp_assigned_ip = json_object_new_string( DecodeDHCP->dhcp_assigned_ip );
            json_object_object_add(encode_json,"assigned_ip", jdhcp_assigned_ip);
        }

    if ( DecodeDHCP->dhcp_client_mac[0] != '\0' )
        {
            json_object *jdhcp_client_mac = json_object_new_string( DecodeDHCP->dhcp_client_mac );
            json_object_object_add(encode_json,"client_mac", jdhcp_client_mac);
        }

    snprintf(str, size, "%s", json_object_to_json_string(encode_json));

    json_object_put(encode_json);

}




