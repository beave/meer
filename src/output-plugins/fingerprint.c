/*
** Copyright (C) 2018-2019 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2018-2019 Champ Clark III <cclark@quadrantsec.com>
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

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>


#include "decode-json-alert.h"

#include "meer.h"
#include "meer-def.h"
#include "fingerprint.h"
#include "output-plugins/sql.h"


struct _MeerOutput *MeerOutput;
struct _MeerCounters *MeerCounters;


void Fingerprint_Write( struct _DecodeAlert *DecodeAlert, char *fingerprint_os, char *fingerprint_type )
{


    char tmp[MAX_SQL_QUERY];

    uint64_t last_id;
    uint64_t ip_id;
    char *results = NULL;

    unsigned char fingerprint_os_id = 0;
    unsigned char fingerprint_type_id = 0;

    /* IF SQL IS ENABLED */

    SQL_DB_Query("BEGIN");

    snprintf(tmp, sizeof(tmp), "SELECT id FROM fp_ip WHERE ip_src = '%s'", DecodeAlert->src_ip );
    results=SQL_DB_Query(tmp);
    MeerCounters->SELECTCount++;  

    if ( results == NULL ) 
	{
	snprintf(tmp, sizeof(tmp), "INSERT INTO fp_ip (ip_src) VALUES ('%s')", DecodeAlert->src_ip);
	SQL_DB_Query(tmp);
        ip_id = atol(SQL_Get_Last_ID());
        MeerCounters->SELECTCount++;
	} else { 
	ip_id = atol(results);
	}

    if ( !strcmp(fingerprint_type, "unknown" ))
        {
            fingerprint_type_id = 0;
        }
    else
        {
            snprintf(tmp, sizeof(tmp), "SELECT id FROM fp_link_details_server_client WHERE server_client = '%s'", \
                     fingerprint_type);
            fingerprint_type_id = atoi( SQL_DB_Query(tmp) );
	    MeerCounters->SELECTCount++;
        }


    if ( !strcmp(fingerprint_os, "unknown" ))
        {
            fingerprint_os_id = 0;
        }
    else
        {
            snprintf(tmp, sizeof(tmp), "SELECT id FROM fp_link_details_os WHERE os = '%s'", \
                     fingerprint_os);
            fingerprint_os_id = atoi ( SQL_DB_Query(tmp) );
            MeerCounters->SELECTCount++;
        }


//    printf("%s [%d]|Type: %s [%d]\n", fingerprint_os, fingerprint_os_id,  fingerprint_type, fingerprint_type_id);

    snprintf(tmp, sizeof(tmp), "INSERT INTO fp_event (ip_src, ip_src_id, timestamp, flow_id, proto, app_proto, sig_name ) VALUES ( '%s', %llu, '%s', %s, '%s', '%s', '%s')", \
    DecodeAlert->src_ip, ip_id, DecodeAlert->timestamp, DecodeAlert->flowid, DecodeAlert->proto, DecodeAlert->app_proto, DecodeAlert->alert_signature ); 
    SQL_DB_Query(tmp);
    MeerCounters->INSERTCount++;

    last_id = atol(SQL_Get_Last_ID());

    snprintf(tmp, sizeof(tmp), "INSERT INTO fp_payload ( id, payload ) VALUES ( %llu, '%s')", last_id, DecodeAlert->payload);
                                                                                                    
    SQL_DB_Query(tmp);                                                            
    MeerCounters->INSERTCount++;  

    snprintf(tmp, sizeof(tmp), "INSERT INTO fp_details (id, server_client, os) VALUES ( %llu, %d, %d)", last_id, fingerprint_type_id, fingerprint_os_id );
    SQL_DB_Query(tmp);
    MeerCounters->INSERTCount++;
 
    if ( !strcmp(DecodeAlert->app_proto, "http" ))
        {

	      snprintf(tmp, sizeof(tmp), \
              "INSERT INTO fp_http ( id, http_user_agent, hostname, xff ) VALUES ( %llu, '%s', '%s', '%s' )", \
	      last_id, DecodeAlert->http_user_agent, DecodeAlert->http_hostname, DecodeAlert->xff );

            SQL_DB_Query(tmp);
            MeerCounters->INSERTCount++;

        }
    
    SQL_DB_Query("COMMIT");

}
