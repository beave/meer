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

    char *src_port; 
    char *dest_port; 

    uint64_t last_id;
    char *results = NULL;
//    char *last_id_char = NULL;

    unsigned char fingerprint_os_id = 0;
    unsigned char fingerprint_type_id = 0;


    src_port = DecodeAlert->src_port;
    dest_port = DecodeAlert->src_port;

    if ( src_port == NULL )
	{
	src_port = "0";
	}

    if ( dest_port == NULL )
	{
	dest_port = "0";
	}

    /* IF SQL IS ENABLED */

    SQL_DB_Query("BEGIN");

	if ( !strcmp(fingerprint_type, "unknown" ))
		{
		fingerprint_type_id = 0;
		} else { 
		snprintf(tmp, sizeof(tmp), "SELECT id FROM fp_link_details_server_client WHERE server_client = '%s'", \
		fingerprint_type);
		//printf("%s\n", tmp);
		fingerprint_type_id = atoi( SQL_DB_Query(tmp) );
		}
		
		
        if ( !strcmp(fingerprint_os, "unknown" ))
                {
                fingerprint_os_id = 0;
                } else { 
		snprintf(tmp, sizeof(tmp), "SELECT id FROM fp_link_details_os WHERE os = '%s'", \
		fingerprint_os);
		//printf("%s\n", tmp);
		fingerprint_os_id = atoi ( SQL_DB_Query(tmp) );
		}


	printf("%s [%d]|Type: %s [%d]\n", fingerprint_os, fingerprint_os_id,  fingerprint_type, fingerprint_type_id);

    snprintf(tmp, sizeof(tmp),
	"INSERT INTO fp_event ( timestamp, os, client_server, src_ip, dst_ip, src_port, dst_port, proto, app_proto, sig_name ) VALUES \
         ('%s', %d, %d, '%s', '%s', %s, %s, '%s', '%s', '%s')", 
         DecodeAlert->timestamp, fingerprint_os_id, fingerprint_type_id, DecodeAlert->src_ip, DecodeAlert->dest_ip, src_port, dest_port, DecodeAlert->proto,  DecodeAlert->app_proto, DecodeAlert->alert_signature); 

	SQL_DB_Query(tmp);
	MeerCounters->INSERTCount++;

	last_id = atol(SQL_Get_Last_ID());

        snprintf(tmp, sizeof(tmp), "INSERT INTO fp_payload ( id, payload ) VALUES ( '%llu', '%s')", \
	last_id, DecodeAlert->payload), 

        SQL_DB_Query(tmp);
        MeerCounters->INSERTCount++;

	if ( !strcmp(DecodeAlert->app_proto, "http" ))
		{

		snprintf(tmp, sizeof(tmp), "INSERT INTO fp_http ( id, http_user_agent, hostname, url, xff, http_content_type, \
		http_method, http_refer, protocol, status, length) VALUES \
		( %llu, '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', %d, %llu )", \
		last_id, DecodeAlert->http_user_agent, DecodeAlert->http_hostname, DecodeAlert->http_url, DecodeAlert->xff, \
		DecodeAlert->http_content_type, DecodeAlert->http_method, DecodeAlert->http_refer, \
	        DecodeAlert->http_protocol, DecodeAlert->http_status, DecodeAlert->http_length);

	        SQL_DB_Query(tmp);
        	 MeerCounters->INSERTCount++;

		}
/*

	if ( !strcmp(fingerprint_type, "unknown" ))
		{
		fingerprint_type_id = 0;
		} else { 
		snprintf(tmp, sizeof(tmp), "SELECT id FROM fp_link_details_server_client WHERE server_client = '%s'", \
		fingerprint_type);
		//printf("%s\n", tmp);
		fingerprint_type_id = atoi( SQL_DB_Query(tmp) );
		}
		
		
        if ( !strcmp(fingerprint_os, "unknown" ))
                {
                fingerprint_os_id = 0;
                } else { 
		snprintf(tmp, sizeof(tmp), "SELECT id FROM fp_link_details_type WHERE type = '%s'", \
		fingerprint_os);
		//printf("%s\n", tmp);
		fingerprint_os_id = atoi ( SQL_DB_Query(tmp) );
		}


	printf("%s [%d]|%s [%d]\n", fingerprint_os, fingerprint_os_id,  fingerprint_type, fingerprint_type_id);
*/		

	SQL_DB_Query("COMMIT");



}
