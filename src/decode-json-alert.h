
#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#ifdef HAVE_LIBJSON_C
#include <json-c/json.h>
#endif

#ifndef HAVE_LIBJSON_C
libjson-c is required for Meer to function!
#endif



typedef struct _DecodeAlert _DecodeAlert;
struct _DecodeAlert
{

char *timestamp;
char *flowid;
char *in_iface;
char *event_type;

char *src_ip;
char *src_port;
char src_dns[256];

    char *dest_ip;
    char *dest_port;
    char dest_dns[256];

    char *proto;
    char app_proto[16];
    char payload[131072];
    char *stream;
    char *packet;

    bool has_extra_data;
    char *xff;

    char *icmp_type;
    char *icmp_code;


    char packet_info_link[32];

    /* Alert data */

    char alert_action[16];
    char alert_gid[5];
    uint64_t alert_signature_id;
    uint32_t alert_rev;
    char alert_signature[512];
    char alert_category[128];
    char alert_severity[5];

    /* Flow data */

    bool     has_flow;

    uint64_t flow_pkts_toserver;
    uint64_t flow_pkts_toclient;
    uint64_t flow_bytes_toserver;
    uint64_t flow_bytes_toclient;
    char flow_start_timestamp[64];

    /* HTTP data */

    bool     has_http;

    char http_hostname[1024];
    char http_url[4096];
    char http_content_type[64];
    char http_method[32];
    char http_user_agent[16384];
    char http_refer[4096];
    char http_protocol[32];
    char http_xff[128];
    int  http_status;
    uint64_t http_length;

    /* TLS */

    bool has_tls;

    char tls_session_resumed[16];
    char tls_sni[255];
    char tls_version[16];

    /* DNS */

    bool has_dns;

    /* SSH */

    bool has_ssh_server;

    char ssh_server_proto_version[8];
    char ssh_server_software_version[128];

    bool has_ssh_client;

    char ssh_client_proto_version[8];
    char ssh_client_software_version[128];



};


struct _DecodeAlert *Decode_JSON_Alert( struct json_object *json_obj, char *json_string );

