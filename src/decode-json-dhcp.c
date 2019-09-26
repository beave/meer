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

/* Decode Suricata "dhcp" */

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

#include "decode-json-dhcp.h"

struct _MeerCounters *MeerCounters;
struct _MeerConfig *MeerConfig;

struct _DecodeDHCP *Decode_JSON_DHCP( struct json_object *json_obj, char *json_string )
{

    struct _DecodeDHCP *DHCP_Return_Struct = NULL;

    struct json_object *tmp = NULL;

    struct json_object *json_obj_dhcp = NULL;

    struct json_object *tmp_dhcp = NULL;



    char *dhcp = NULL;

    DHCP_Return_Struct = (struct _DecodeDHCP *) malloc(sizeof(_DecodeDHCP));

    if ( DHCP_Return_Struct == NULL )
        {
            Meer_Log(ERROR, "[%s, line %d] JSON: \"%s\" Failed to allocate memory for _DecodeDHCP.  Abort!", __FILE__, __LINE__, json_string);
        }
        
    memset(DHCP_Return_Struct, 0, sizeof(_DecodeDHCP));

    DHCP_Return_Struct->timestamp = NULL;
    DHCP_Return_Struct->flowid = NULL;
    DHCP_Return_Struct->in_iface = NULL;
    DHCP_Return_Struct->src_ip = NULL;
    DHCP_Return_Struct->src_port = NULL;
    DHCP_Return_Struct->dest_ip = NULL;
    DHCP_Return_Struct->dest_port = NULL;
    DHCP_Return_Struct->proto = NULL;

    if (json_object_object_get_ex(json_obj, "timestamp", &tmp))
        {
            DHCP_Return_Struct->timestamp = (char *)json_object_get_string(tmp);
        } 

    if (json_object_object_get_ex(json_obj, "flow_id", &tmp))
        {
            DHCP_Return_Struct->flowid = (char *)json_object_get_string(tmp);
        } 

    if (json_object_object_get_ex(json_obj, "in_iface", &tmp))
        {
            DHCP_Return_Struct->in_iface = (char *)json_object_get_string(tmp);
        } 

    if (json_object_object_get_ex(json_obj, "src_ip", &tmp))
        {
            DHCP_Return_Struct->src_ip = (char *)json_object_get_string(tmp);
        } 

    if (json_object_object_get_ex(json_obj, "src_port", &tmp))
        {
            DHCP_Return_Struct->src_port = (char *)json_object_get_string(tmp);
        } 

    if (json_object_object_get_ex(json_obj, "dest_ip", &tmp))
        {
            DHCP_Return_Struct->dest_ip = (char *)json_object_get_string(tmp);
        } 

    if (json_object_object_get_ex(json_obj, "dest_port", &tmp))
        {
            DHCP_Return_Struct->dest_port = (char *)json_object_get_string(tmp);
        } 

    if (json_object_object_get_ex(json_obj, "proto", &tmp))
        {
            DHCP_Return_Struct->proto = (char *)json_object_get_string(tmp);
        } 

    if (json_object_object_get_ex(json_obj, "dhcp", &tmp))
	{

		dhcp = (char *)json_object_get_string(tmp);

                    if ( Validate_JSON_String( dhcp ) == 0 )
                        {   

                            json_obj_dhcp = json_tokener_parse(dhcp);
    
                            if (json_object_object_get_ex(json_obj_dhcp, "type", &tmp_dhcp))
                                {   
                                    strlcpy(DHCP_Return_Struct->dhcp_type, (char *)json_object_get_string(tmp_dhcp), sizeof(DHCP_Return_Struct->dhcp_type));
                                }

                            if (json_object_object_get_ex(json_obj_dhcp, "id", &tmp_dhcp))
                                {   
                                    strlcpy(DHCP_Return_Struct->dhcp_id, (char *)json_object_get_string(tmp_dhcp), sizeof(DHCP_Return_Struct->dhcp_id));
                                }

                            if (json_object_object_get_ex(json_obj_dhcp, "client_mac", &tmp_dhcp))
                                {   
                                    strlcpy(DHCP_Return_Struct->dhcp_client_mac, (char *)json_object_get_string(tmp_dhcp), sizeof(DHCP_Return_Struct->dhcp_client_mac));
                                }

                            if (json_object_object_get_ex(json_obj_dhcp, "assigned_ip", &tmp_dhcp))
                                {   
                                    strlcpy(DHCP_Return_Struct->dhcp_assigned_ip, (char *)json_object_get_string(tmp_dhcp), sizeof(DHCP_Return_Struct->dhcp_assigned_ip));
                                }

			}


	}

   if ( dhcp == NULL ) 
	{
	Meer_Log(WARN, "[%s, line %d] Got event_type: dhcp log without dhcp json: %s", __FILE__, __LINE__, json_string);
	}

    json_object_put(tmp);

    return(DHCP_Return_Struct);
}
