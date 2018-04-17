#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>


#include "meer.h"
#include "meer-def.h"
#include "mysql.h"
#include "util.h"
#include "decode-json-alert.h"
#include "util-base64.h"
#include "references.h"
#include "classifications.h"



#ifdef HAVE_LIBMYSQLCLIENT
#include <mysql/mysql.h>

struct _MeerConfig *MeerConfig;
struct _MeerOutput *MeerOutput;
struct _Classifications *MeerClass;


void MySQL_Connect( void )
{

    MeerOutput->mysql_dbh = mysql_init(NULL);

    if ( MeerOutput->mysql_dbh == NULL )
        {
            Remove_Lock_File();
            Meer_Log(ERROR, "[%s, line %d] Error initializing MySQL", __FILE__, __LINE__);
        }

    my_bool reconnect = true;
    mysql_options(MeerOutput->mysql_dbh,MYSQL_READ_DEFAULT_GROUP,MeerOutput->mysql_database);
    mysql_options(MeerOutput->mysql_dbh,MYSQL_OPT_RECONNECT, &reconnect);

    if (!mysql_real_connect(MeerOutput->mysql_dbh, MeerOutput->mysql_server,
                            MeerOutput->mysql_username, MeerOutput->mysql_password, MeerOutput->mysql_database,
                            MeerOutput->mysql_port, NULL, 0 ))
        {

            Meer_Log(ERROR, "[%s, line %d] MySQL Error %u: \"%s\"", __FILE__,  __LINE__,
                     mysql_errno(MeerOutput->mysql_dbh), mysql_error(MeerOutput->mysql_dbh));

        }

    Meer_Log(NORMAL, "Successfully connected to MySQL/MariaDB database.");
}

uint32_t MySQL_Get_Sensor_ID( void )
{

    char tmp[MAX_MYSQL_QUERY];
    char *results;

    snprintf(tmp, sizeof(tmp),
             "SELECT sid FROM sensor WHERE hostname='%s' AND interface='%s' AND detail=1 AND encoding='0'",
             MeerConfig->hostname, MeerConfig->interface);

    results=MySQL_DB_Query(tmp);

    /* If we get results,  go ahead and return the value */

    if ( results != NULL )
        {

            Meer_Log(NORMAL, "Using Database Sensor ID: %d", atoi(results) );
            return( atoi(results) );
        }

    snprintf(tmp, sizeof(tmp),
             "INSERT INTO sensor (hostname, interface, filter, detail, encoding, last_cid) VALUES ('%s', '%s', NULL, '1', '0', '0')",
             MeerConfig->hostname, MeerConfig->interface);

    MySQL_DB_Query(tmp);

    results = MySQL_DB_Query("SELECT LAST_INSERT_ID()");

    Meer_Log(NORMAL, "Using New Database Sensor ID: %d", atoi(results));

    return( atoi(results) );

}

uint64_t MySQL_Get_Last_CID( void )
{

    char tmp[MAX_MYSQL_QUERY] = { 0 };
    char *results = NULL;

    snprintf(tmp, sizeof(tmp), "SELECT last_cid FROM sensor WHERE sid=%d ", MeerOutput->mysql_sensor_id);

    results=MySQL_DB_Query(tmp);

    if ( results != NULL )
        {

            Meer_Log(NORMAL, "Last CID: %d", atoi(results) );
            return( atol(results) );
        }


    return(0);
}



char *MySQL_DB_Query( char *sql )
{

    char tmp[MAX_MYSQL_QUERY];
    char *re = NULL;

    MYSQL_RES *res;
    MYSQL_ROW row;

    if ( MeerOutput->mysql_debug )
        {
            Meer_Log(DEBUG, "SQL Debug: \"%s\"", sql);
        }

    if ( mysql_real_query(MeerOutput->mysql_dbh, sql, strlen(sql) ) )
        {
            Remove_Lock_File();
            Meer_Log(ERROR, "[%s, line %d] MySQL/MariaDB Error [%u:] \"%s\"\nOffending SQL statement: %s\n", __FILE__,  __LINE__, mysql_errno(MeerOutput->mysql_dbh), mysql_error(MeerOutput->mysql_dbh), sql);

        }

    res = mysql_use_result(MeerOutput->mysql_dbh);

    if ( res != NULL )
        {
            while(row = mysql_fetch_row(res))
                {
                    snprintf(tmp, sizeof(tmp), "%s", row[0]);
                    re=tmp;
                }
        }

    mysql_free_result(res);
    return(re);


}

void MySQL_Record_Last_CID ( void )
{

    char tmp[MAX_MYSQL_QUERY];

    snprintf(tmp, sizeof(tmp),
             "UPDATE sensor SET last_cid='%" PRIu64 "' WHERE sid=%d AND hostname='%s' AND interface='%s' AND detail=1",
             MeerOutput->mysql_last_cid, MeerOutput->mysql_sensor_id, MeerConfig->hostname, MeerConfig->interface);

    (void)MySQL_DB_Query(tmp);

}

int MySQL_Get_Signature_ID ( struct _DecodeAlert *DecodeAlert )
{

    char tmp[MAX_MYSQL_QUERY];
    char *results;
    char class[64];

    int class_id = 0;
    int signature_id = 0;

    /* Lookup classtype based off the description */

    Class_Lookup( DecodeAlert->alert_category, class, sizeof(class) );

    snprintf(tmp, sizeof(tmp), "SELECT sig_class_id from sig_class where sig_class_name='%s'", class);
    results = MySQL_DB_Query(tmp);

    /* No classtype found.  Insert it */

    if ( results == NULL )
        {

            snprintf(tmp, sizeof(tmp),  "INSERT INTO sig_class(sig_class_id, sig_class_name) VALUES (DEFAULT, '%s')", class);

            (void)MySQL_DB_Query(tmp);

            results = MySQL_DB_Query("SELECT LAST_INSERT_ID()");

        }

    class_id = atoi(results);

    snprintf(tmp, sizeof(tmp), "SELECT sig_id FROM signature WHERE sig_name='%s' AND sig_rev=%s AND sig_sid=%" PRIu64 "",
             DecodeAlert->alert_signature, DecodeAlert->alert_rev, DecodeAlert->alert_signature_id);

    results = MySQL_DB_Query(tmp);

    if ( results == NULL )
        {

            snprintf(tmp, sizeof(tmp), "INSERT INTO signature(sig_name, sig_class_id, sig_priority, sig_rev, sig_sid) "
                     "VALUES ('%s', '%d', '%d', '%s', '%" PRIu64 "' )", DecodeAlert->alert_signature, class_id, DecodeAlert->alert_severity,
                     DecodeAlert->alert_rev, DecodeAlert->alert_signature_id);

            (void)MySQL_DB_Query(tmp);

            results = MySQL_DB_Query("SELECT LAST_INSERT_ID()");

        }

    signature_id = atoi(results);

    return(signature_id);

}


void MySQL_Insert_Event ( struct _DecodeAlert *DecodeAlert, int signature_id )
{

    char tmp[MAX_MYSQL_QUERY];

    snprintf(tmp, sizeof(tmp), "INSERT INTO event(sid, cid, signature, timestamp) VALUES ('%d', '%" PRIu64 "', '%d', '%s')", MeerOutput->mysql_sensor_id, MeerOutput->mysql_last_cid, signature_id, DecodeAlert->timestamp );

    (void)MySQL_DB_Query(tmp);


}

void MySQL_Insert_Header ( struct _DecodeAlert *DecodeAlert )
{

    char tmp[MAX_MYSQL_QUERY];
    char *results;
    unsigned char proto = 0;

    unsigned char ip_src_bit[16];
    uint32_t *src_ip_u32 = (uint32_t *)&ip_src_bit[0];

    unsigned char ip_dst_bit[16];
    uint32_t *dst_ip_u32 = (uint32_t *)&ip_dst_bit[0];

    IP2Bit(DecodeAlert->src_ip, ip_src_bit);
    IP2Bit(DecodeAlert->dest_ip, ip_dst_bit);

    if (!strcmp(DecodeAlert->proto, "TCP" ))
        {
            proto = TCP;
        }

    else if (!strcmp(DecodeAlert->proto, "UDP" ))
        {
            proto = UDP;
        }

    else if (!strcmp(DecodeAlert->proto, "ICMP" ))
        {
            proto = ICMP;
        }

    /* DEBUG NEEDS IPv6 */

    snprintf(tmp, sizeof(tmp),
             "INSERT INTO iphdr VALUES ( '%d', '%" PRIu64 "', '%" PRIu64 "', '%" PRIu64 "', '4', '0', '0', '0', '0', '0', '0', '0', '%d', '0' )",
             MeerOutput->mysql_sensor_id, MeerOutput->mysql_last_cid, htonl(*src_ip_u32), htonl(*dst_ip_u32), proto );

    (void)MySQL_DB_Query(tmp);

    if ( proto == TCP )
        {

            snprintf(tmp, sizeof(tmp),
                     "INSERT INTO tcphdr VALUES ( '%d', '%" PRIu64 "', '%s', '%s', '0', '0', '0', '0', '0', '0', '0', '0'  )",
                     MeerOutput->mysql_sensor_id, MeerOutput->mysql_last_cid, DecodeAlert->src_port, DecodeAlert->dest_port  );

            (void)MySQL_DB_Query(tmp);

        }

    else if ( proto == UDP )
        {

            snprintf(tmp, sizeof(tmp),
                     "INSERT INTO udphdr VALUES ( '%d', '%" PRIu64 "', '%s', '%s', '0', '0' )",
                     MeerOutput->mysql_sensor_id, MeerOutput->mysql_last_cid, DecodeAlert->src_port, DecodeAlert->dest_port );

            (void)MySQL_DB_Query(tmp);

        }

    else if ( proto == ICMP )
        {

            snprintf(tmp, sizeof(tmp), "INSERT INTO icmphdr VALUES ( '%d', '%" PRIu64 "', '%s', '%s', '0', '0', '0' )",
                     MeerOutput->mysql_sensor_id, MeerOutput->mysql_last_cid, DecodeAlert->icmp_type, DecodeAlert->icmp_code );

            (void)MySQL_DB_Query(tmp);

        }

}

void MySQL_Insert_Payload ( struct _DecodeAlert *DecodeAlert )
{

    char tmp[MAX_MYSQL_QUERY];

    int ret;

    char *hex_encode;
    uint8_t *base64_decode = malloc(strlen(DecodeAlert->payload) * 2);

    ret = DecodeBase64(base64_decode, (const uint8_t *)DecodeAlert->payload, strlen(DecodeAlert->payload), 1);
    hex_encode = Hexify( base64_decode, ret );

    snprintf(tmp, sizeof(tmp),
             "INSERT INTO data(sid, cid, data_payload) VALUES ('%d', '%" PRIu64 "', '%s')",
             MeerOutput->mysql_sensor_id, MeerOutput->mysql_last_cid, hex_encode );

    (void)MySQL_DB_Query(tmp);

    free(base64_decode);
    free(hex_encode);

}

void MySQL_Insert_DNS ( struct _DecodeAlert *DecodeAlert )
{

    char tmp[MAX_MYSQL_QUERY];

    /* Both DNS entries are empty,  no reason to insert */

    if ( !strcmp(DecodeAlert->src_dns, "")  && !strcmp(DecodeAlert->dest_dns, "" ) )
        {
            return;
        }

    snprintf(tmp, sizeof(tmp),
             "INSERT INTO dns(sid, cid, src_host, dst_host) VALUES ('%d', '%" PRIu64 "', '%s', '%s')",
             MeerOutput->mysql_sensor_id, MeerOutput->mysql_last_cid, DecodeAlert->src_dns, DecodeAlert->dest_dns);

    (void)MySQL_DB_Query(tmp);


}

void MySQL_Insert_Extra_Data ( struct _DecodeAlert *DecodeAlert )
{

char tmp[MAX_MYSQL_QUERY] = { 0 };

	if ( DecodeAlert->xff != NULL ) 
		{

		snprintf(tmp, sizeof(tmp), 
		"INSERT INTO extra (sid,cid,type,datatype,len,data) values (%d, %" PRIu64 ", %d, 1, %d, '%s')", 
		MeerOutput->mysql_sensor_id, MeerOutput->mysql_last_cid, EXTRA_ORIGNAL_CLIENT_IPV4,
		strlen( DecodeAlert->xff ), DecodeAlert->xff);

		(void)MySQL_DB_Query(tmp);

		}



}
/*
MySQL_Reference_Handler ( struct _DecodeAlert *DecodeAlert,
			  struct _References *MeerReferences )
{

        char tmp[MAX_MYSQL_QUERY];
        char *results;

	// signature id, reftype, reference
//	snprintf(tmp, sizeof(tmp), "SELECT ref_system_id from reference_system where ref_system_name='%s'", tmptoken1);


}
*/

#endif


