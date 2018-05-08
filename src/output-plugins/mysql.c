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

/* Write EVE data to MySQL databases */


#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#ifdef HAVE_LIBMYSQLCLIENT

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <mysql/mysql.h>

#include "decode-json-alert.h"

#include "meer.h"
#include "meer-def.h"
#include "util.h"
#include "util-base64.h"
#include "references.h"
#include "classifications.h"
#include "output-plugins/mysql.h"
#include "lockfile.h"
#include "sid-map.h"

struct _MeerConfig *MeerConfig;
struct _MeerOutput *MeerOutput;
struct _MeerCounters *MeerCounters;
struct _Classifications *MeerClass;

struct _SID_Map *SID_Map;

struct _SignatureCache *SignatureCache;
uint32_t SignatureCacheCount = 0;

struct _ClassificationCache *ClassificationCache;
uint32_t ClassificationCacheCount = 0;

void MySQL_Connect( void )
{

    MeerOutput->mysql_dbh = mysql_init(NULL);

    if ( MeerOutput->mysql_dbh == NULL )
        {
            Remove_Lock_File();
            Meer_Log(ERROR, "[%s, line %d] Error initializing MySQL", __FILE__, __LINE__);
        }

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

    uint32_t sensor_id = 0;

    /* For some reason Barnyar2 liked the hostname to be "hostname:interface".  We're simply mirroring
       that functionality here */

    snprintf(tmp, sizeof(tmp),
             "SELECT sid FROM sensor WHERE hostname='%s:%s' AND interface='%s' AND detail=1 AND encoding='0'",
             MeerConfig->hostname, MeerConfig->interface, MeerConfig->interface);

    results=MySQL_DB_Query(tmp);
    MeerCounters->SELECTCount++;

    /* If we get results,  go ahead and return the value */

    if ( results != NULL )
        {

            sensor_id = atoi(results);
            Meer_Log(NORMAL, "Using Database Sensor ID: %d", sensor_id );
            return( sensor_id );
        }

    snprintf(tmp, sizeof(tmp),
             "INSERT INTO sensor (hostname, interface, filter, detail, encoding, last_cid) VALUES ('%s:%s', '%s', NULL, '1', '0', '0')",
             MeerConfig->hostname, MeerConfig->interface, MeerConfig->interface);

    MySQL_DB_Query(tmp);
    MeerCounters->INSERTCount++;

    results = MySQL_DB_Query("SELECT LAST_INSERT_ID()");

    sensor_id = atoi(results);

    Meer_Log(NORMAL, "Using New Database Sensor ID: %d", sensor_id);

    return( sensor_id );

}

uint64_t MySQL_Get_Last_CID( void )
{

    char tmp[MAX_MYSQL_QUERY] = { 0 };
    char *results = NULL;
    int  last_cid = 0;

    snprintf(tmp, sizeof(tmp), "SELECT last_cid FROM sensor WHERE sid=%d ", MeerOutput->mysql_sensor_id);

    results=MySQL_DB_Query(tmp);
    MeerCounters->SELECTCount++;

    if ( results != NULL )
        {

            last_cid = atoi(results);
            Meer_Log(NORMAL, "Last CID: %d", last_cid );
            return( last_cid );
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
            MySQL_Error_Handling( sql );
        }

    res = mysql_use_result(MeerOutput->mysql_dbh);

    if ( res != NULL )
        {
            while( ( row = mysql_fetch_row(res) ) )
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
             "UPDATE sensor SET last_cid='%" PRIu64 "' WHERE sid=%d AND hostname='%s:%s' AND interface='%s' AND detail=1",
             MeerOutput->mysql_last_cid, MeerOutput->mysql_sensor_id, MeerConfig->hostname, MeerConfig->interface, MeerConfig->interface);

    (void)MySQL_DB_Query(tmp);
    MeerCounters->UPDATECount++;

}

int MySQL_Get_Class_ID ( struct _DecodeAlert *DecodeAlert )
{

    char tmp[MAX_MYSQL_QUERY] = { 0 };
    char *results;
    char class[64] = { 0 };

    int class_id = 0;

    int i = 0;

    /* Check cache */

    for (i = 0; i<ClassificationCacheCount; i++)
        {

            if ( !strcmp(DecodeAlert->alert_category, ClassificationCache[i].class_name))
                {
                    MeerCounters->ClassCacheHitCount++;
                    return(ClassificationCache[i].sig_class_id);
                }

        }

    /* Lookup classtype based off the description */

    Class_Lookup( DecodeAlert->alert_category, class, sizeof(class) );

    snprintf(tmp, sizeof(tmp), "SELECT sig_class_id from sig_class where sig_class_name='%s'", class);
    results = MySQL_DB_Query(tmp);
    MeerCounters->SELECTCount++;

    /* No classtype found.  Insert it */

    if ( results == NULL )
        {

            snprintf(tmp, sizeof(tmp),  "INSERT INTO sig_class(sig_class_id, sig_class_name) VALUES (DEFAULT, '%s')", class);
            (void)MySQL_DB_Query(tmp);
            MeerCounters->INSERTCount++;

            results = MySQL_DB_Query("SELECT LAST_INSERT_ID()");

        }

    class_id = atoi(results);

    /* Insert into cache */

    ClassificationCache = (_ClassificationCache *) realloc(ClassificationCache, (ClassificationCacheCount+1) * sizeof(_ClassificationCache));

    ClassificationCache[ClassificationCacheCount].sig_class_id = class_id;
    strlcpy(ClassificationCache[ClassificationCacheCount].class_name, DecodeAlert->alert_category, sizeof(ClassificationCache[ClassificationCacheCount].class_name));

    ClassificationCacheCount++;
    MeerCounters->ClassCacheMissCount++;

    return(class_id);
}


int MySQL_Get_Signature_ID ( struct _DecodeAlert *DecodeAlert, int class_id )
{

    char tmp[MAX_MYSQL_QUERY];
    char *results;
    int i = 0;
    unsigned sig_priority = 0;

    int signature_id = 0;

    /* Search cache */

    for (i = 0; i<SignatureCacheCount; i++)
        {

            if (!strcmp(SignatureCache[i].sig_name, DecodeAlert->alert_signature) &&
                    SignatureCache[i].sig_rev == DecodeAlert->alert_rev &&
                    SignatureCache[i].sig_sid == DecodeAlert->alert_signature_id )
                {
                    MeerCounters->SigCacheHitCount++;
                    return(SignatureCache[i].sig_id);
                }

        }

    sig_priority = Class_Lookup_Priority( DecodeAlert->alert_category);

    snprintf(tmp, sizeof(tmp), "SELECT sig_id FROM signature WHERE sig_name='%s' AND sig_rev=%d AND sig_sid=%" PRIu64 "",
             DecodeAlert->alert_signature, DecodeAlert->alert_rev, DecodeAlert->alert_signature_id);

    results = MySQL_DB_Query(tmp);
    MeerCounters->SELECTCount++;

    if ( results == NULL )
        {

            snprintf(tmp, sizeof(tmp), "INSERT INTO signature (sig_name,sig_class_id,sig_priority,sig_rev,sig_sid,sig_gid) "
                     "VALUES ('%s',%d,%d,%d,%" PRIu64 ",1)", DecodeAlert->alert_signature, class_id, sig_priority,
                     DecodeAlert->alert_rev, DecodeAlert->alert_signature_id);

            (void)MySQL_DB_Query(tmp);
            MeerCounters->INSERTCount++;

            results = MySQL_DB_Query("SELECT LAST_INSERT_ID()");

        }

    signature_id = atoi(results);

    /* Add signature to cache */

    SignatureCache = (_SignatureCache *) realloc(SignatureCache, (SignatureCacheCount+1) * sizeof(_SignatureCache));

    SignatureCache[SignatureCacheCount].sig_id = signature_id;
    SignatureCache[SignatureCacheCount].sig_rev = DecodeAlert->alert_rev;
    SignatureCache[SignatureCacheCount].sig_sid = DecodeAlert->alert_signature_id;

    strlcpy(SignatureCache[SignatureCacheCount].sig_name, DecodeAlert->alert_signature, sizeof(SignatureCache[SignatureCacheCount].sig_name));

    SignatureCacheCount++;
    MeerCounters->SigCacheMissCount++;

    return(signature_id);

}


void MySQL_Insert_Event ( struct _DecodeAlert *DecodeAlert, int signature_id )
{

    char tmp[MAX_MYSQL_QUERY];

    snprintf(tmp, sizeof(tmp), "INSERT INTO event(sid,cid,signature,timestamp,app_proto,flow_id) VALUES ('%d','%" PRIu64 "',%d,'%s','%s',%s)", MeerOutput->mysql_sensor_id, MeerOutput->mysql_last_cid, signature_id, DecodeAlert->timestamp, DecodeAlert->app_proto, DecodeAlert->flowid );


    (void)MySQL_DB_Query(tmp);
    MeerCounters->INSERTCount++;


}

void MySQL_Insert_Header ( struct _DecodeAlert *DecodeAlert )
{

    char tmp[MAX_MYSQL_QUERY];
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

    /* Legacy database allow things like ip_len to be set to NULL.  This may break
       functionality on some consoles.  We set it to 0,  even though we shouldn't
       have too :( */

    snprintf(tmp, sizeof(tmp),
             "INSERT INTO iphdr ( sid, cid,ip_src,ip_dst,ip_src_t,ip_dst_t,ip_ver,ip_proto,ip_hlen,ip_tos,ip_len,ip_id,ip_flags,ip_off,ip_ttl,ip_csum) VALUES (%d,%" PRIu64 ",%" PRIu32 ",%" PRIu32 ",'%s','%s',%u,%u,0,0,0,0,0,0,0,0)",
             MeerOutput->mysql_sensor_id, MeerOutput->mysql_last_cid, htonl(*src_ip_u32), htonl(*dst_ip_u32), DecodeAlert->src_ip, DecodeAlert->dest_ip, DecodeAlert->ip_version, proto );

    (void)MySQL_DB_Query(tmp);
    MeerCounters->INSERTCount++;

    if ( proto == TCP )
        {

            snprintf(tmp, sizeof(tmp),
                     "INSERT INTO tcphdr (sid,cid,tcp_sport,tcp_dport,tcp_seq,tcp_ack,tcp_off,tcp_res,tcp_flags,tcp_win,tcp_csum,tcp_urp) VALUES (%d,%" PRIu64 ",%s,%s,0,0,0,0,0,0,0,0)",
                     MeerOutput->mysql_sensor_id, MeerOutput->mysql_last_cid, DecodeAlert->src_port, DecodeAlert->dest_port  );

            (void)MySQL_DB_Query(tmp);
            MeerCounters->INSERTCount++;

        }

    else if ( proto == UDP )
        {

            snprintf(tmp, sizeof(tmp),
                     "INSERT INTO udphdr (sid,cid,udp_sport,udp_dport,udp_len,udp_csum) VALUES (%d,%" PRIu64 ",%s,%s,0,0)",
                     MeerOutput->mysql_sensor_id, MeerOutput->mysql_last_cid, DecodeAlert->src_port, DecodeAlert->dest_port );

            (void)MySQL_DB_Query(tmp);
            MeerCounters->INSERTCount++;

        }

    else if ( proto == ICMP )
        {

            snprintf(tmp, sizeof(tmp), "INSERT INTO icmphdr (sid,cid,icmp_type,icmp_code,icmp_csum,icmp_id,icmp_seq) VALUES (%d,%" PRIu64 ",%s,%s,0,0,0)",
                     MeerOutput->mysql_sensor_id, MeerOutput->mysql_last_cid, DecodeAlert->icmp_type, DecodeAlert->icmp_code );

            (void)MySQL_DB_Query(tmp);
            MeerCounters->INSERTCount++;

        }

}

void MySQL_Insert_Payload ( struct _DecodeAlert *DecodeAlert )
{

    char tmp[MAX_MYSQL_QUERY];

    uint32_t ret;

    char *hex_encode;
    uint8_t *base64_decode = malloc(strlen(DecodeAlert->payload) * 2);

    ret = DecodeBase64( base64_decode, (const uint8_t *)DecodeAlert->payload, strlen(DecodeAlert->payload), 1);
    hex_encode = Hexify( (char*)base64_decode, (int)ret );

    snprintf(tmp, sizeof(tmp),
             "INSERT INTO data(sid, cid, data_payload) VALUES (%d,%" PRIu64 ",'%s')",
             MeerOutput->mysql_sensor_id, MeerOutput->mysql_last_cid, hex_encode );

    (void)MySQL_DB_Query(tmp);
    MeerCounters->INSERTCount++;

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
             "INSERT INTO dns(sid, cid, src_host, dst_host) VALUES (%d,%" PRIu64 ",'%s','%s')",
             MeerOutput->mysql_sensor_id, MeerOutput->mysql_last_cid,
             DecodeAlert->src_dns,
             DecodeAlert->dest_dns );

    (void)MySQL_DB_Query(tmp);
    MeerCounters->INSERTCount++;


}

void MySQL_Insert_Extra_Data ( struct _DecodeAlert *DecodeAlert )
{

    char tmp[MAX_MYSQL_QUERY] = { 0 };

    char e_http_hostname[512] = { 0 };
    char e_http_url[3200] = { 0 };

    char e_email_attachment[10240] = { 0 };
    char e_smtp_rcpt_to[10240] = { 0 };
    char e_smtp_mail_from[10240] = { 0 };

    if ( DecodeAlert->xff != NULL )
        {

            snprintf(tmp, sizeof(tmp),
                     "INSERT INTO extra (sid,cid,type,datatype,len,data) VALUES (%d,%" PRIu64 ",%d,1,%d,'%s')",
                     MeerOutput->mysql_sensor_id, MeerOutput->mysql_last_cid, EXTRA_ORIGNAL_CLIENT_IPV4,
                     (int)strlen( DecodeAlert->xff ), DecodeAlert->xff);

            (void)MySQL_DB_Query(tmp);
            MeerCounters->INSERTCount++;

        }

    if ( DecodeAlert->ip_version == 6 )
        {

            snprintf(tmp, sizeof(tmp),
                     "INSERT INTO extra (sid,cid,type,datatype,len,data) VALUES (%d,%" PRIu64 ",%d,1,%d,'%s')",
                     MeerOutput->mysql_sensor_id, MeerOutput->mysql_last_cid, EXTRA_IPV6_SOURCE_ADDRESS,
                     (int)strlen( DecodeAlert->src_ip ), DecodeAlert->src_ip);

            (void)MySQL_DB_Query(tmp);
            MeerCounters->INSERTCount++;

            snprintf(tmp, sizeof(tmp),
                     "INSERT INTO extra (sid,cid,type,datatype,len,data) VALUES (%d,%" PRIu64 ",%d,1,%d,'%s')",
                     MeerOutput->mysql_sensor_id, MeerOutput->mysql_last_cid, EXTRA_IPV6_DESTINATION_ADDRESS,
                     (int)strlen( DecodeAlert->dest_ip ), DecodeAlert->dest_ip);

            (void)MySQL_DB_Query(tmp);
            MeerCounters->INSERTCount++;

        }

    if ( DecodeAlert->has_http == true )
        {

            if ( DecodeAlert->http_hostname[0] != '\0' )
                {

                    MySQL_Escape_String( DecodeAlert->http_hostname, e_http_hostname, sizeof(e_http_hostname));

                    snprintf(tmp, sizeof(tmp),
                             "INSERT INTO extra (sid,cid,type,datatype,len,data) VALUES (%d,%" PRIu64 ",%d,1,%d,'%s')",
                             MeerOutput->mysql_sensor_id, MeerOutput->mysql_last_cid, EXTRA_HTTP_HOSTNAME,
                             (int)strlen( e_http_hostname ), e_http_hostname );

                    (void)MySQL_DB_Query(tmp);
                    MeerCounters->INSERTCount++;

                }

            if ( DecodeAlert->http_url[0] != '\0' )
                {

                    MySQL_Escape_String( DecodeAlert->http_url, e_http_url, sizeof(e_http_url));

                    snprintf(tmp, sizeof(tmp),
                             "INSERT INTO extra (sid,cid,type,datatype,len,data) VALUES (%d,%" PRIu64 ",%d,1,%d,'%s')",
                             MeerOutput->mysql_sensor_id, MeerOutput->mysql_last_cid, EXTRA_HTTP_URI,
                             (int)strlen( e_http_url ), e_http_url);

                    (void)MySQL_DB_Query(tmp);
                    MeerCounters->INSERTCount++;

                }

        }

    if ( DecodeAlert->has_smtp == true )
        {

            if ( DecodeAlert->email_attachment[0] != '\0' )
                {

                    MySQL_Escape_String( DecodeAlert->email_attachment, e_email_attachment, sizeof(e_email_attachment));

                    snprintf(tmp, sizeof(tmp),
                             "INSERT INTO extra (sid,cid,type,datatype,len,data) VALUES (%d,%" PRIu64 ",%d,1,%d,'%s')",
                             MeerOutput->mysql_sensor_id, MeerOutput->mysql_last_cid, EXTRA_SMTP_FILENAME,
                             (int)strlen( e_http_hostname ), e_email_attachment );

                    (void)MySQL_DB_Query(tmp);
                    MeerCounters->INSERTCount++;

                }

            if ( DecodeAlert->smtp_rcpt_to[0] != '\0' )
                {

                    MySQL_Escape_String( DecodeAlert->smtp_rcpt_to, e_smtp_rcpt_to, sizeof(e_smtp_rcpt_to));

                    snprintf(tmp, sizeof(tmp),
                             "INSERT INTO extra (sid,cid,type,datatype,len,data) VALUES (%d,%" PRIu64 ",%d,1,%d,'%s')",
                             MeerOutput->mysql_sensor_id, MeerOutput->mysql_last_cid, EXTRA_SMTP_RCPT_TO,
                             (int)strlen( e_smtp_rcpt_to ), e_smtp_rcpt_to );

                    (void)MySQL_DB_Query(tmp);
                    MeerCounters->INSERTCount++;

                }

            if ( DecodeAlert->smtp_mail_from[0] != '\0' )
                {

                    MySQL_Escape_String( DecodeAlert->smtp_mail_from, e_smtp_mail_from, sizeof(e_smtp_mail_from));

                    snprintf(tmp, sizeof(tmp),
                             "INSERT INTO extra (sid,cid,type,datatype,len,data) VALUES (%d,%" PRIu64 ",%d,1,%d,'%s')",                             MeerOutput->mysql_sensor_id, MeerOutput->mysql_last_cid, EXTRA_SMTP_MAIL_FROM,
                             (int)strlen( e_smtp_mail_from ), e_smtp_mail_from );

                    (void)MySQL_DB_Query(tmp);
                    MeerCounters->INSERTCount++;

                }

        }

}

void MySQL_Insert_Flow ( struct _DecodeAlert *DecodeAlert )
{

    char tmp[MAX_MYSQL_QUERY] = { 0 };

    snprintf(tmp, sizeof(tmp),
             "INSERT INTO flow (sid,cid,pkts_toserver,pkts_toclient,bytes_toserver,bytes_toclient,start_timestamp) "
             "VALUES (%d,%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",'%s')",
             MeerOutput->mysql_sensor_id, MeerOutput->mysql_last_cid,
             DecodeAlert->flow_pkts_toserver,
             DecodeAlert->flow_pkts_toclient,
             DecodeAlert->flow_bytes_toserver,
             DecodeAlert->flow_bytes_toclient,
             DecodeAlert->flow_start_timestamp );

    (void)MySQL_DB_Query(tmp);
    MeerCounters->INSERTCount++;
}

void MySQL_Insert_HTTP ( struct _DecodeAlert *DecodeAlert )
{

    char tmp[MAX_MYSQL_QUERY] = { 0 };

    char e_http_hostname[512] = { 0 };
    char e_http_url[4100] = { 0 };
    char e_http_user_agent[16384] = { 0 };
    char e_http_refer[4100] = { 0 };

    MySQL_Escape_String( DecodeAlert->http_hostname, e_http_hostname, sizeof(e_http_hostname));
    MySQL_Escape_String( DecodeAlert->http_url, e_http_url, sizeof(e_http_url));
    MySQL_Escape_String( DecodeAlert->http_user_agent, e_http_user_agent, sizeof(e_http_user_agent));
    MySQL_Escape_String( DecodeAlert->http_refer, e_http_refer, sizeof(e_http_refer));

    snprintf(tmp, sizeof(tmp),
             "INSERT INTO http (sid,cid,hostname,url,xff,http_content_type,http_method,http_user_agent,http_refer,protocol,status,length) "
             "VALUES (%d,%" PRIu64 ",'%s','%s','%s','%s','%s','%s','%s','%s',%d,%" PRIu64 ")",
             MeerOutput->mysql_sensor_id, MeerOutput->mysql_last_cid,
             e_http_hostname,
             e_http_url,
             DecodeAlert->http_xff,
             DecodeAlert->http_content_type,
             DecodeAlert->http_method,
             e_http_user_agent,
             e_http_refer,
             DecodeAlert->http_protocol,
             DecodeAlert->http_status,
             DecodeAlert->http_length);

    (void)MySQL_DB_Query(tmp);
    MeerCounters->INSERTCount++;

}

void MySQL_Insert_TLS ( struct _DecodeAlert *DecodeAlert )
{

    char tmp[MAX_MYSQL_QUERY] = { 0 };

    char e_tls_issuerdn[256] = { 0 };
    char e_tls_subject[256] = { 0 };

    MySQL_Escape_String( DecodeAlert->tls_issuerdn, e_tls_issuerdn, sizeof(e_tls_issuerdn));
    MySQL_Escape_String( DecodeAlert->tls_subject, e_tls_subject, sizeof(e_tls_subject));

    snprintf(tmp, sizeof(tmp),
             "INSERT INTO tls (sid,cid,subject,issuerdn,serial,fingerprint,session_resumed,sni,version,notbefore,notafter) "
             "VALUES (%d,%" PRIu64 ",'%s','%s',%d,'%s','%s','%s','%s','%s','%s')",
             MeerOutput->mysql_sensor_id, MeerOutput->mysql_last_cid,
             e_tls_subject,
             e_tls_issuerdn,
             DecodeAlert->tls_serial,
             DecodeAlert->tls_fingerprint,
             DecodeAlert->tls_session_resumed,
             DecodeAlert->tls_sni,
             DecodeAlert->tls_version,
             DecodeAlert->tls_notbefore,
             DecodeAlert->tls_notafter );

    (void)MySQL_DB_Query(tmp);
    MeerCounters->INSERTCount++;

}


void MySQL_Insert_SSH ( struct _DecodeAlert *DecodeAlert, unsigned char type )
{

    char tmp[MAX_MYSQL_QUERY] = { 0 };

    char *table = NULL;
    char *proto = NULL;
    char e_software[128] = { 0 };

    if ( type == SSH_CLIENT )
        {

            table = "ssh_client";
            proto = DecodeAlert->ssh_client_proto_version;

            MySQL_Escape_String( DecodeAlert->ssh_client_software_version,
                                 e_software, sizeof(e_software));

        }
    else
        {

            table = "ssh_server";
            proto = DecodeAlert->ssh_server_proto_version;

            MySQL_Escape_String( DecodeAlert->ssh_server_software_version,
                                 e_software, sizeof(e_software));

        }

    snprintf(tmp, sizeof(tmp),
             "INSERT INTO %s (sid,cid,proto_version,sofware_version) "
             "VALUES (%d,%" PRIu64 ",'%s','%s')",
             table,MeerOutput->mysql_sensor_id, MeerOutput->mysql_last_cid,
             proto, e_software );

    (void)MySQL_DB_Query(tmp);
    MeerCounters->INSERTCount++;

}

void MySQL_Insert_Metadata ( struct _DecodeAlert *DecodeAlert )
{

    char tmp[MAX_MYSQL_QUERY] = { 0 };
    char e_alert_metadata[1024] = { 0 };

    MySQL_Escape_String( DecodeAlert->alert_metadata, e_alert_metadata, sizeof(e_alert_metadata));

    snprintf(tmp, sizeof(tmp),
             "INSERT INTO metadata (sid,cid,metadata) "
             "VALUES (%d,%" PRIu64 ",'%s')",
             MeerOutput->mysql_sensor_id, MeerOutput->mysql_last_cid,
             e_alert_metadata);

    (void)MySQL_DB_Query(tmp);
    MeerCounters->INSERTCount++;

}

void MySQL_Insert_SMTP ( struct _DecodeAlert *DecodeAlert )
{

    char tmp[MAX_MYSQL_QUERY] = { 0 };
    char e_helo[255] = { 0 };
    char e_mail_from[255] = { 0 };
    char e_rcpt_to[131072] = { 0 };

    MySQL_Escape_String( DecodeAlert->smtp_helo, e_helo, sizeof(e_helo));
    MySQL_Escape_String( DecodeAlert->smtp_mail_from, e_mail_from, sizeof(e_mail_from));
    MySQL_Escape_String( DecodeAlert->smtp_rcpt_to, e_rcpt_to, sizeof(e_rcpt_to));

    snprintf(tmp, sizeof(tmp),
             "INSERT INTO smtp (sid,cid,helo,mail_from,rcpt_to) "
             "VALUES ( %d,%" PRIu64 ",'%s','%s','%s')",
             MeerOutput->mysql_sensor_id, MeerOutput->mysql_last_cid,
             e_helo,
             e_mail_from,
             e_rcpt_to);

    (void)MySQL_DB_Query(tmp);
    MeerCounters->INSERTCount++;

}

void MySQL_Insert_Email ( struct _DecodeAlert *DecodeAlert )
{

    char tmp[MAX_MYSQL_QUERY] = { 0 };

    char e_from[1024] = { 0 };
    char e_to[10240] = { 0 };
    char e_cc[10240] = { 0 };
    char e_attachment[10240] = { 0 };

    MySQL_Escape_String( DecodeAlert->email_from, e_from, sizeof(e_from));
    MySQL_Escape_String( DecodeAlert->email_to, e_to, sizeof(e_to));
    MySQL_Escape_String( DecodeAlert->email_cc, e_cc, sizeof(e_cc));
    MySQL_Escape_String( DecodeAlert->email_attachment, e_attachment, sizeof(e_attachment));

    snprintf(tmp, sizeof(tmp),
             "INSERT INTO email (sid,cid,status,email_from,email_to,email_cc,attachment) "
             "VALUES (%d,%" PRIu64 ",'%s','%s','%s','%s','%s')",
             MeerOutput->mysql_sensor_id, MeerOutput->mysql_last_cid,
             DecodeAlert->email_status,
             e_from,
             e_to,
             e_cc,
             e_attachment);

    (void)MySQL_DB_Query(tmp);
    MeerCounters->INSERTCount++;

}


void MySQL_Escape_String( char *sql, char *str, size_t size )
{

    char tmp[MAX_MYSQL_QUERY] = { 0 };

    int len = 0;

    len = mysql_real_escape_string(MeerOutput->mysql_dbh, tmp, sql, strlen(sql));
    tmp[len] = '\0';

    snprintf(str, size, "%s", tmp);
    return;

}

int MySQL_Legacy_Reference_Handler ( struct _DecodeAlert *DecodeAlert )
{

    char tmp[MAX_MYSQL_QUERY];
    char *results = NULL;

    int ref_system_id = 0;
    int ref_id = 0;
    int sig_id = 0;

    int i = 0;

    for (i = 0; i <  MeerCounters->SIDMapCount; i++ )
        {

            if ( DecodeAlert->alert_signature_id == SID_Map[i].sid )
                {

                    snprintf(tmp, sizeof(tmp),
                             "SELECT ref_system_id FROM reference_system WHERE ref_system_name='%s'",
                             SID_Map[i].type);

                    results=MySQL_DB_Query(tmp);
                    MeerCounters->SELECTCount++;

                    if ( results == NULL )
                        {

                            snprintf(tmp, sizeof(tmp),
                                     "INSERT INTO reference_system (ref_system_name) VALUES ('%s')",
                                     SID_Map[i].type);

                            (void)MySQL_DB_Query(tmp);
                            MeerCounters->INSERTCount++;

                            results = MySQL_DB_Query("SELECT LAST_INSERT_ID()");

                        }

                    ref_system_id = atoi(results);

                    snprintf(tmp, sizeof(tmp),
                             "SELECT ref_id FROM reference WHERE ref_system_id=%d AND ref_tag='%s'",
                             ref_system_id, SID_Map[i].location);

                    results=MySQL_DB_Query(tmp);
                    MeerCounters->SELECTCount++;

                    if ( results == NULL )
                        {

                            snprintf(tmp, sizeof(tmp),
                                     "INSERT INTO reference (ref_system_id,ref_tag) VALUES (%d, '%s')",
                                     ref_system_id, SID_Map[i].location);

                            (void)MySQL_DB_Query(tmp);
                            MeerCounters->INSERTCount++;

                            results = MySQL_DB_Query("SELECT LAST_INSERT_ID()");

                        }

                    ref_id = atoi(results);

                    sig_id = MySQL_Get_Sig_ID( DecodeAlert );

                    snprintf(tmp, sizeof(tmp),
                             "SELECT sig_id FROM sig_reference WHERE sig_id=%d AND ref_id=%d",
                             sig_id, ref_id);

                    results=MySQL_DB_Query(tmp);
                    MeerCounters->SELECTCount++;

                    if ( results == NULL )
                        {

                            snprintf(tmp, sizeof(tmp),
                                     "INSERT INTO sig_reference (sig_id,ref_seq,ref_id) VALUES (%d,%d,%d)",
                                     sig_id, i, ref_id);

                            (void)MySQL_DB_Query(tmp);
                            MeerCounters->INSERTCount++;

                            results = MySQL_DB_Query("SELECT LAST_INSERT_ID()");

                        }

                }

        }

    return(sig_id);	/* DEBUG: Is this return right? */

}


int MySQL_Get_Sig_ID( struct _DecodeAlert *DecodeAlert )
{

    char tmp[MAX_MYSQL_QUERY];
    char *results = NULL;
    char class[64] = { 0 };

    int sig_class_id = 0;
    int sig_id = 0;

    Class_Lookup( DecodeAlert->alert_category, class, sizeof(class) );

    /* DEBUG: cache here */

    snprintf(tmp, sizeof(tmp),
             "SELECT sig_class_id FROM sig_class WHERE sig_class_name='%s'",
             class);

    results=MySQL_DB_Query(tmp);
    MeerCounters->SELECTCount++;

    if ( results == NULL )
        {

            snprintf(tmp, sizeof(tmp),
                     "INSERT INTO sig_class (sig_class_name) VALUES ('%s')",
                     class);

            results=MySQL_DB_Query(tmp);
            MeerCounters->INSERTCount++;

            results = MySQL_DB_Query("SELECT LAST_INSERT_ID()");

        }

    sig_class_id = atoi(results);
    sig_id = MySQL_Get_Signature_ID( DecodeAlert, sig_class_id );

    return(sig_id);

}


void MySQL_Error_Handling ( char *sql )
{

    /* Reconnect on network event */

    if ( MeerOutput->mysql_reconnect == true &&
            ( mysql_errno(MeerOutput->mysql_dbh) == 2003 ||
              mysql_errno(MeerOutput->mysql_dbh) == 2006 ) )
        {

            while ( mysql_errno(MeerOutput->mysql_dbh) == 2003 || mysql_errno(MeerOutput->mysql_dbh) == 2006 )
                {

                    Meer_Log(WARN, "MySQL/MariaDB has gone away.  Sleeping for %d seconds before attempting to reconnect.", MeerOutput->mysql_reconnect_time);

                    sleep(MeerOutput->mysql_reconnect_time);

                    if (!mysql_real_connect(MeerOutput->mysql_dbh, MeerOutput->mysql_server,
                                            MeerOutput->mysql_username, MeerOutput->mysql_password, MeerOutput->mysql_database,
                                            MeerOutput->mysql_port, NULL, 0 ))
                        {

                            Meer_Log(WARN, "[%s, line %d] MySQL Error %u: \"%s\"", __FILE__,  __LINE__,
                                     mysql_errno(MeerOutput->mysql_dbh), mysql_error(MeerOutput->mysql_dbh));

                        }

                }

            Meer_Log(NORMAL, "Successfully reconnected to MySQL/MariaDB database.");

            return;
        }

    /* All other errors */

    Remove_Lock_File();
    Meer_Log(ERROR, "[%s, line %d] MySQL/MariaDB Error [%u:] \"%s\"\nOffending SQL statement: %s\n", __FILE__,  __LINE__, mysql_errno(MeerOutput->mysql_dbh), mysql_error(MeerOutput->mysql_dbh), sql);

}

#endif

#ifdef QUADRANT

/* These are various Quadrant specific queries.  You likely don'y want them.
   They are mostly for statistics. */

void MySQL_DB_Quadrant( struct _DecodeAlert *DecodeAlert, int signature_id )
{

    char tmp[MAX_MYSQL_QUERY] = { 0 };

    unsigned char ip_src_bit[16] = { 0 };
    uint32_t *src_ip_u32 = (uint32_t *)&ip_src_bit[0];

    IP2Bit(DecodeAlert->src_ip, ip_src_bit);

    snprintf(tmp, sizeof(tmp),
             "UPDATE sensor SET events_count = events_count+1 WHERE sid = %d",
             MeerOutput->mysql_sensor_id);

    (void)MySQL_DB_Query(tmp);

    snprintf(tmp, sizeof(tmp),
             "UPDATE signature SET events_count = events_count+1 WHERE sig_id = %u",
             signature_id );

    (void)MySQL_DB_Query(tmp);

    snprintf(tmp, sizeof(tmp),
             "INSERT INTO events_ip6src_sig_48hr (ip_src,ip_src_char,sid,cid,sig_id,timestamp) VALUES (%lu,'%s',%d,%" PRIu64 ", %" PRIu64 ", '%s')",
             src_ip_u32, DecodeAlert->src_ip, MeerOutput->mysql_sensor_id, MeerOutput->mysql_last_cid, signature_id, DecodeAlert->timestamp );

    (void)MySQL_DB_Query(tmp);

    /*

         snprintf(tmp, sizeof(tmp),
         "INSERT INTO events_ip6src_sig_year (ip_src,ip_src_char,sid,cid,sig_id,timestamp) VALUES (%lu,'%s',%d,%" PRIu64 ", %" PRIu64 ", '%s')",
         src_ip_u32, DecodeAlert->src_ip, MeerOutput->mysql_sensor_id, MeerOutput->mysql_last_cid, signature_id, DecodeAlert->timestamp );

         (void)MySQL_DB_Query(tmp);

    */


    snprintf(tmp, sizeof(tmp),
             "INSERT INTO tmp_events_24 (sid,cid,signature,timestamp) VALUES (%u,%" PRIu64 ",%d,'%s')",
             MeerOutput->mysql_sensor_id, MeerOutput->mysql_last_cid, signature_id, DecodeAlert->timestamp );

    (void)MySQL_DB_Query(tmp);

    snprintf(tmp, sizeof(tmp),
             "INSERT INTO tmp_events_today (sid,cid,signature,timestamp) VALUES (%u,%" PRIu64 ",%d, '%s')",
             MeerOutput->mysql_sensor_id, MeerOutput->mysql_last_cid, signature_id, DecodeAlert->timestamp );

    (void)MySQL_DB_Query(tmp);

    snprintf(tmp, sizeof(tmp),
             "INSERT INTO tmp_events_yesterday (sid,cid,signature,timestamp) VALUES (%u,%" PRIu64 ",%d,'%s')",
             MeerOutput->mysql_sensor_id, MeerOutput->mysql_last_cid, signature_id, DecodeAlert->timestamp );

    (void)MySQL_DB_Query(tmp);

    snprintf(tmp, sizeof(tmp),
             "INSERT INTO tmp_events_week (sid,cid,signature,timestamp) VALUES (%u,% " PRIu64 ",%d,'%s')",
             MeerOutput->mysql_sensor_id, MeerOutput->mysql_last_cid, signature_id, DecodeAlert->timestamp );

    (void)MySQL_DB_Query(tmp);

    snprintf(tmp, sizeof(tmp),
             "INSERT INTO tmp_events_month (sid,cid,signature,timestamp) VALUES (%u, %" PRIu64 ",%d,'%s')",
             MeerOutput->mysql_sensor_id, MeerOutput->mysql_last_cid, signature_id, DecodeAlert->timestamp );

    (void)MySQL_DB_Query(tmp);

    snprintf(tmp, sizeof(tmp),
             "INSERT INTO tmp_events_quarter (sid,cid,signature,timestamp) VALUES (%u,%" PRIu64",%d,'%s')",
             MeerOutput->mysql_sensor_id, MeerOutput->mysql_last_cid, signature_id, DecodeAlert->timestamp );

    (void)MySQL_DB_Query(tmp);

    snprintf(tmp, sizeof(tmp),
             "INSERT INTO tmp_events_year (sid,cid,signature,timestamp) VALUES (%u,%" PRIu64",%d,'%s')",
             MeerOutput->mysql_sensor_id, MeerOutput->mysql_last_cid, signature_id, DecodeAlert->timestamp );

    (void)MySQL_DB_Query(tmp);

}

#endif



