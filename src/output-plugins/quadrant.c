
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "decode-json-alert.h"

#include "meer.h"
#include "meer-def.h"
#include "config-yaml.h"
//#include "util.h"
//#include "util-base64.h"
//#include "references.h"
//#include "classifications.h"
#include "output-plugins/sql.h"
//#include "lockfile.h"
//#include "sid-map.h"


#ifdef QUADRANT
#include "output-plugins/quadrant.h"
#endif


#ifdef QUADRANT

struct _MeerOutput *MeerOutput;
struct _MeerConfig *MeerConfig;


/* These are various Quadrant specific queries.  You likely don'y want them.
   They are mostly for statistics. */

void SQL_DB_Quadrant( struct _DecodeAlert *DecodeAlert, int signature_id )
{

    char tmp[MAX_SQL_QUERY] = { 0 };

    snprintf(tmp, sizeof(tmp),
             "UPDATE sensor SET events_count = events_count+1 WHERE sid = %d",
             MeerOutput->sql_sensor_id);

    (void)SQL_DB_Query(tmp);

    snprintf(tmp, sizeof(tmp),
             "UPDATE signature SET events_count = events_count+1 WHERE sig_id = %u",
             signature_id );

    (void)SQL_DB_Query(tmp);

    snprintf(tmp, sizeof(tmp),
             "INSERT INTO tmp_events_24 (sid,cid,ip_src,ip_dst,signature,timestamp) VALUES (%u,%" PRIu64 ",'%s','%s',%d,'%s')",
             MeerOutput->sql_sensor_id, MeerOutput->sql_last_cid, DecodeAlert->src_ip, DecodeAlert->dest_ip, signature_id, DecodeAlert->timestamp );

    (void)SQL_DB_Query(tmp);

    snprintf(tmp, sizeof(tmp),
             "INSERT INTO tmp_events_today (sid,cid,ip_src,ip_dst,signature,timestamp) VALUES (%u,%" PRIu64 ",'%s','%s',%d, '%s')",
             MeerOutput->sql_sensor_id, MeerOutput->sql_last_cid, DecodeAlert->src_ip, DecodeAlert->dest_ip, signature_id, DecodeAlert->timestamp );

    (void)SQL_DB_Query(tmp);

    snprintf(tmp, sizeof(tmp),
             "INSERT INTO tmp_events_yesterday (sid,cid,ip_src,ip_dst,signature,timestamp) VALUES (%u,%" PRIu64 ",'%s','%s',%d,'%s')",
             MeerOutput->sql_sensor_id, MeerOutput->sql_last_cid, DecodeAlert->src_ip, DecodeAlert->dest_ip, signature_id, DecodeAlert->timestamp );

    (void)SQL_DB_Query(tmp);

    snprintf(tmp, sizeof(tmp),
             "INSERT INTO tmp_events_week (sid,cid,ip_src,ip_dst,signature,timestamp) VALUES (%u, %" PRIu64 ",'%s','%s',%d,'%s')",
             MeerOutput->sql_sensor_id, MeerOutput->sql_last_cid, DecodeAlert->src_ip, DecodeAlert->dest_ip, signature_id, DecodeAlert->timestamp );

    (void)SQL_DB_Query(tmp);


    snprintf(tmp, sizeof(tmp),
             "INSERT INTO tmp_events_month (sid,cid,ip_src,ip_dst,signature,timestamp) VALUES (%u, %" PRIu64 ",'%s','%s',%d,'%s')",
             MeerOutput->sql_sensor_id, MeerOutput->sql_last_cid, DecodeAlert->src_ip, DecodeAlert->dest_ip, signature_id, DecodeAlert->timestamp );

    (void)SQL_DB_Query(tmp);

    snprintf(tmp, sizeof(tmp),
             "INSERT INTO tmp_events_quarter (sid,cid,ip_src,ip_dst,signature,timestamp) VALUES (%u,%" PRIu64",'%s','%s',%d,'%s')",
             MeerOutput->sql_sensor_id, MeerOutput->sql_last_cid, DecodeAlert->src_ip, DecodeAlert->dest_ip, signature_id, DecodeAlert->timestamp );

    (void)SQL_DB_Query(tmp);

    snprintf(tmp, sizeof(tmp),
             "INSERT INTO tmp_events_year (sid,cid,ip_src,ip_dst,signature,timestamp) VALUES (%u,%" PRIu64",'%s','%s',%d,'%s')",
             MeerOutput->sql_sensor_id, MeerOutput->sql_last_cid, DecodeAlert->src_ip, DecodeAlert->dest_ip, signature_id, DecodeAlert->timestamp );

    (void)SQL_DB_Query(tmp);

}

void Redis_Quadrant( struct _DecodeAlert *DecodeAlert, int signature_id )
{

    struct json_object *jobj;

    char key[128] = { 0 };

    /* Insert "alert" to be picked up by runner */

    snprintf(key, sizeof(key), "alert:%d:%" PRIu64 "", MeerOutput->sql_sensor_id, MeerOutput->sql_last_cid);
    Redis_Writer( "SET", key, DecodeAlert->json, 0 ); 

    /* Insert stat data */

    jobj = json_object_new_object();

    json_object *jdate = json_object_new_string(DecodeAlert->timestamp);
    json_object_object_add(jobj,"timestamp", jdate);

    json_object *jsid = json_object_new_int(MeerOutput->sql_sensor_id);
    json_object_object_add(jobj,"sid", jsid);

    json_object *jcid = json_object_new_int64(MeerOutput->sql_last_cid);
    json_object_object_add(jobj,"cid", jcid);

    json_object *jflow_id = json_object_new_int64( atol(DecodeAlert->flowid) );
    json_object_object_add(jobj,"flow_id", jflow_id);

    json_object *jsrc_ip = json_object_new_string(DecodeAlert->src_ip);
    json_object_object_add(jobj,"src_ip", jsrc_ip);

    json_object *jdest_ip = json_object_new_string(DecodeAlert->dest_ip);
    json_object_object_add(jobj,"dest_ip", jdest_ip);

    json_object *jsignature_id = json_object_new_int(signature_id);
    json_object_object_add(jobj,"signature_id", jsignature_id);

    /* Insert into Redis with times */

    snprintf(key, sizeof(key), "tmp_event_24:%s", DecodeAlert->flowid);
    Redis_Writer( "SET", key, json_object_to_json_string(jobj), ( 24 * 60 * 60 ) );

    snprintf(key, sizeof(key), "tmp_event_week:%s", DecodeAlert->flowid);
    Redis_Writer( "SET", key, json_object_to_json_string(jobj), ( 24 * 60 * 60 * 7) );

    snprintf(key, sizeof(key), "tmp_event_month:%s", DecodeAlert->flowid);
    Redis_Writer( "SET", key, json_object_to_json_string(jobj), ( 24 * 60 * 60 * 30 ) );

    snprintf(key, sizeof(key), "tmp_event_quarter:%s", DecodeAlert->flowid);
    Redis_Writer( "SET", key, json_object_to_json_string(jobj), ( 24 * 60 * 60 * 90 ) );

    snprintf(key, sizeof(key), "tmp_event_year:%s", DecodeAlert->flowid);
    Redis_Writer( "SET", key, json_object_to_json_string(jobj), ( 24 * 60 * 60 * 365 ) );

    json_object_put(jobj);

}

#endif


