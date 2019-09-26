
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

    unsigned char ip_src_bit[16] = { 0 };
    uint32_t *src_ip_u32 = (uint32_t *)&ip_src_bit[0];

    IP2Bit(DecodeAlert->src_ip, ip_src_bit);

    snprintf(tmp, sizeof(tmp),
             "UPDATE sensor SET events_count = events_count+1 WHERE sid = %d",
             MeerOutput->sql_sensor_id);

    (void)SQL_DB_Query(tmp);

    snprintf(tmp, sizeof(tmp),
             "UPDATE signature SET events_count = events_count+1 WHERE sig_id = %u",
             signature_id );

    (void)SQL_DB_Query(tmp);


    /*   

         snprintf(tmp, sizeof(tmp),
         "INSERT INTO events_ip6src_sig_year (ip_src,ip_src_char,sid,cid,sig_id,timestamp) VALUES (%lu,'%s',%d,%" PRIu64 ", %" PRIu64 ", '%s')",
         src_ip_u32, DecodeAlert->src_ip, MeerOutput->sql_sensor_id, MeerOutput->sql_last_cid, signature_id, DecodeAlert->timestamp );

         (void)SQL_DB_Query(tmp);

    */
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

#endif
   

