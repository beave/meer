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

/* Output routines for decoded EVE/JSON */

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

#include "meer.h"
#include "meer-def.h"
#include "util.h"
#include "output.h"
#include "references.h"
#include "sid-map.h"
#include "config-yaml.h"

#include "output-plugins/sql.h"
#include "output-plugins/pipe.h"
#include "output-plugins/external.h"

#ifdef HAVE_LIBMYSQLCLIENT
#include <mysql/mysql.h>
MYSQL    *mysql;
#endif

struct _MeerOutput *MeerOutput;
struct _MeerConfig *MeerConfig;
struct _MeerCounters *MeerCounters;
struct _MeerHealth *MeerHealth;
struct _Classifications *MeerClass;

/****************************************************************************
 * Init_Output - Init output pluggins (if needed)
 ****************************************************************************/

void Init_Output( void )
{

    if ( MeerOutput->external_enabled )
        {

            Meer_Log(NORMAL, "--[ External information ]-----------------------------------------");
            Meer_Log(NORMAL, "");
            Meer_Log(NORMAL, "Default external program: %s", MeerOutput->external_program);
            Meer_Log(NORMAL, "Execute on 'security-ips' policy: %s", MeerOutput->external_metadata_security_ips ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Execute on 'balanced-ips' policy: %s", MeerOutput->external_metadata_balanced_ips ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Execute on 'connectivity-ips' policy: %s", MeerOutput->external_metadata_connectivity_ips ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Execute on 'max-detect-ips' policy: %s", MeerOutput->external_metadata_max_detect_ips ? "enabled" : "disabled" );

            Meer_Log(NORMAL, "");
        }

    if ( MeerOutput->pipe_enabled )
        {
            uint32_t current_pipe_size = 0;
            uint32_t fd_results = 0;

            Meer_Log(NORMAL, "--[ PIPE information ]--------------------------------------------");
            Meer_Log(NORMAL, "");
            Meer_Log(NORMAL, "Pipe Location: %s", MeerOutput->pipe_location);
            Meer_Log(NORMAL, "Pipe Size: %d bytes", MeerOutput->pipe_size);
            Meer_Log(NORMAL, "");
            Meer_Log(NORMAL, "Write 'dns'    : %s", MeerOutput->pipe_dns ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'flow'    : %s", MeerOutput->pipe_flow ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'http'    : %s", MeerOutput->pipe_http ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'tls'     : %s", MeerOutput->pipe_tls ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'ssh'     : %s", MeerOutput->pipe_ssh ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'smtp'    : %s", MeerOutput->pipe_smtp ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'files'   : %s", MeerOutput->pipe_files ? "enabled" : "disabled" );

#ifdef QUADRANT

            Meer_Log(NORMAL, "Write 'bluedot' : %s", MeerOutput->pipe_bluedot ? "enabled" : "disabled" );

#endif

            Meer_Log(NORMAL, "");

            MeerOutput->pipe_fd = open(MeerOutput->pipe_location, O_RDWR);

            if ( MeerOutput->pipe_fd < 0 )
                {
                    Meer_Log(ERROR, "Cannot open %s. Abort!", MeerOutput->pipe_location);
                }

            current_pipe_size = fcntl(MeerOutput->pipe_fd, F_GETPIPE_SZ);
            fd_results = fcntl(MeerOutput->pipe_fd, F_SETPIPE_SZ, MeerOutput->pipe_size);
            fcntl(MeerOutput->pipe_fd, F_SETFL, O_NONBLOCK);

            Meer_Log(NORMAL, "The %s pipe (FIFO) was %d bytes. It is now set to %d bytes.", MeerOutput->pipe_location, current_pipe_size, MeerOutput->pipe_size);

            Meer_Log(NORMAL, "");

        }

#if defined(HAVE_LIBMYSQLCLIENT) || defined(HAVE_LIBPQ)

    if ( MeerOutput->sql_enabled )
        {


            Meer_Log(NORMAL, "--[ SQL information ]--------------------------------------------");
            Meer_Log(NORMAL, "");

            if ( MeerOutput->sql_driver == DB_MYSQL )
                {
                    Meer_Log(NORMAL, "SQL Driver: MySQL/MariaDB");
                }

            else if ( MeerOutput->sql_driver == DB_POSTGRESQL )
                {
                    Meer_Log(NORMAL, "SQL Driver: PostgreSQL");
                }

            Meer_Log(NORMAL, "Extra data: %s", MeerOutput->sql_extra_data ? "enabled" : "disabled" );

            /* Legacy reference system */

            Meer_Log(NORMAL, "Legacy Reference System': %s", MeerOutput->sql_reference_system ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "");

            if ( MeerOutput->sql_reference_system )
                {
                    Load_References();
                    Load_SID_Map();
                    Meer_Log(NORMAL, "");
                }

            SQL_Connect();

            MeerOutput->sql_sensor_id = SQL_Get_Sensor_ID();
            MeerOutput->sql_last_cid = SQL_Get_Last_CID() + 1;

            Meer_Log(NORMAL, "");
            Meer_Log(NORMAL, "Record 'json'    : %s", MeerOutput->sql_json ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Record 'metadata': %s", MeerOutput->sql_metadata ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Record 'flow'    : %s", MeerOutput->sql_flow ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Record 'http'    : %s", MeerOutput->sql_http ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Record 'tls'     : %s", MeerOutput->sql_tls ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Record 'ssh'     : %s", MeerOutput->sql_ssh ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Record 'smtp'    : %s", MeerOutput->sql_smtp ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Record 'email'   : %s", MeerOutput->sql_email ? "enabled" : "disabled" );

#ifdef QUADRANT

            Meer_Log(NORMAL, "Record 'bluedot' : %s", MeerOutput->sql_bluedot ? "enabled" : "disabled" );

#endif

            Meer_Log(NORMAL, "");
            Meer_Log(NORMAL, "---------------------------------------------------------------------------");


        }

#endif


}

/****************************************************************************
 * Output_Pipe - Determines what data/JSON should be sent to the named pipe
 ****************************************************************************/

bool Output_Pipe ( char *type, char *json_string )
{

    if ( !strcmp(type, "flow" ) && MeerOutput->pipe_flow == true )
        {
            Pipe_Write( json_string );
            return 0;
        }

    else if ( !strcmp(type, "http" ) && MeerOutput->pipe_http == true )
        {
            Pipe_Write( json_string );
            return 0;
        }

    else if ( !strcmp(type, "smtp" ) && MeerOutput->pipe_smtp == true )
        {
            Pipe_Write( json_string );
            return 0;
        }

    else if ( !strcmp(type, "ssh" ) && MeerOutput->pipe_ssh == true )
        {
            Pipe_Write( json_string );
            return 0;
        }

    else if ( !strcmp(type, "tls" ) && MeerOutput->pipe_tls == true )
        {
            Pipe_Write( json_string );
            return 0;
        }

    else if ( !strcmp(type, "dns" ) && MeerOutput->pipe_dns == true )
        {
            Pipe_Write( json_string );
            return 0;
        }

    else if ( !strcmp(type, "alert" ) && MeerOutput->pipe_alert == true )
        {
            Pipe_Write( json_string );
            return 0;
        }

    Meer_Log(WARN, "Unknown JSON type '%s'. JSON String: %s", type, json_string);
    MeerCounters->JSONPipeMisses++;
    return 1;

}

/****************************************************************************
 * Output_Alert_SQL - Sends decoded data to a MySQL/PostgreSQL database using
 * a similar format to Barnyard2 (with some extra data added in!)
 ****************************************************************************/

bool Output_Alert_SQL ( struct _DecodeAlert *DecodeAlert )
{

#if defined(HAVE_LIBMYSQLCLIENT) || defined(HAVE_LIBPQ)

    char tmp[MAX_SQL_QUERY] = { 0 };
    char convert_time[16] = { 0 };
    struct tm tm_;

    bool health_flag = 0;
    int i = 0;

    if ( MeerOutput->sql_enabled )
        {

            int signature_id = 0;
            int class_id = 0;

            if ( MeerConfig->health == true )
                {

                    for (i = 0 ; i < MeerCounters->HealthCount; i++ )
                        {

                            if ( MeerHealth[i].health_signature == DecodeAlert->alert_signature_id )
                                {
                                    health_flag = 1;
                                    break;
                                }
                        }

                }


            if ( health_flag == 0 )
                {

                    class_id = SQL_Get_Class_ID( DecodeAlert );

                    SQL_DB_Query("BEGIN");

                    if ( MeerOutput->sql_reference_system == true )
                        {

                            signature_id = SQL_Legacy_Reference_Handler ( DecodeAlert );

                            /* The SID doesn't have any reference data.  We just get it into the
                                       signature table */

                            if ( signature_id == 0 )
                                {
                                    signature_id = SQL_Get_Signature_ID( DecodeAlert, class_id );
                                }

                        }
                    else
                        {

                            signature_id = SQL_Get_Signature_ID( DecodeAlert, class_id );

                        }

                    SQL_Insert_Event( DecodeAlert, signature_id );

                    SQL_Insert_Header( DecodeAlert );

                    SQL_Insert_Payload ( DecodeAlert );

                    if ( MeerConfig->json == true )
                        {
                            SQL_Insert_JSON ( DecodeAlert );
                        }

                    if ( MeerConfig->dns == true )
                        {
                            SQL_Insert_DNS ( DecodeAlert );
                        }

                    /* We can have multiple "xff" fields in extra data */

                    if ( MeerOutput->sql_extra_data == true )
                        {
                            SQL_Insert_Extra_Data ( DecodeAlert );
                        }

                    if ( DecodeAlert->has_flow == true && MeerOutput->sql_flow == true )
                        {
                            SQL_Insert_Flow ( DecodeAlert );
                        }

                    if ( DecodeAlert->has_http == true && MeerOutput->sql_http == true )
                        {
                            SQL_Insert_HTTP ( DecodeAlert );
                        }

                    if ( DecodeAlert->has_tls == true && MeerOutput->sql_tls == true )
                        {
                            SQL_Insert_TLS ( DecodeAlert );
                        }

                    if ( DecodeAlert->has_ssh_server == true && MeerOutput->sql_ssh == true )
                        {
                            SQL_Insert_SSH ( DecodeAlert, SSH_SERVER );
                        }

                    if ( DecodeAlert->has_ssh_client == true && MeerOutput->sql_ssh == true )
                        {
                            SQL_Insert_SSH ( DecodeAlert, SSH_CLIENT );
                        }

                    if ( DecodeAlert->alert_has_metadata == true && MeerOutput->sql_metadata == true )
                        {
                            SQL_Insert_Metadata ( DecodeAlert );
                        }

                    if ( DecodeAlert->has_smtp == true && MeerOutput->sql_smtp == true )
                        {
                            SQL_Insert_SMTP ( DecodeAlert );
                        }

                    if ( DecodeAlert->has_email == true && MeerOutput->sql_email == true )
                        {
                            SQL_Insert_Email ( DecodeAlert );
                        }

#ifdef QUADRANT

                    if ( DecodeAlert->has_bluedot == true && MeerConfig->bluedot == true )
                        {
                            SQL_Insert_Bluedot ( DecodeAlert );
                        }

#endif



                    /* Record CID in case of crash/disconnections */

                    SQL_Record_Last_CID();

                    /* These are very Quadrant specific queries.  You likely don't want them. */

#ifdef QUADRANT

                    SQL_DB_Quadrant( DecodeAlert, signature_id );

#endif
                    /* Convert timestamp from event to epoch */

                    strptime(DecodeAlert->timestamp,"%FT%T",&tm_);
                    strftime(convert_time, sizeof(convert_time),"%F %T",&tm_);

                    snprintf(tmp, sizeof(tmp), "UPDATE sensor SET last_event=%d WHERE sid=%d", (int)mktime(&tm_), MeerOutput->sql_sensor_id);

                    SQL_DB_Query( (char*)tmp );

                    MeerCounters->UPDATECount++;

                    SQL_DB_Query("COMMIT");

                    MeerOutput->sql_last_cid++;

                }
            else
                {

                    /* Convert timestamp from event to epoch */

                    strptime(DecodeAlert->timestamp,"%FT%T",&tm_);
                    strftime(convert_time, sizeof(convert_time),"%F %T",&tm_);

                    snprintf(tmp, sizeof(tmp), "UPDATE sensor SET health=%d WHERE sid=%d", (int)mktime(&tm_), MeerOutput->sql_sensor_id);

                    SQL_DB_Query( (char*)tmp );

                    MeerCounters->HealthCountT++;
                    MeerCounters->UPDATECount++;

                }


        }

#endif

    return 0;
}


/****************************************************************************
 * Output_External - Sends certain data to an external program based on
 * the signature triggered.
 ****************************************************************************/

bool Output_External ( struct _DecodeAlert *DecodeAlert, char *json_string )
{

    struct json_object *json_obj = NULL;
    struct json_object *tmp = NULL;

    char *policy = NULL;

    if ( MeerOutput->external_metadata_security_ips == true ||
            MeerOutput->external_metadata_max_detect_ips == true )

        {

            if ( DecodeAlert->alert_metadata[0] != '\0' )
                {
                    json_obj = json_tokener_parse(DecodeAlert->alert_metadata);

                    if (json_object_object_get_ex(json_obj, "policy", &tmp))
                        {

                            policy = (char *)json_object_get_string(tmp);

                            if ( ( strstr( policy, "security-ips drop" ) && MeerOutput->external_metadata_security_ips == true ) ||
                                    ( strstr( policy, "max-detect-ips drop" ) && MeerOutput->external_metadata_max_detect_ips == true ) ||
                                    ( strstr( policy, "balanced-ips drop" ) && MeerOutput->external_metadata_balanced_ips == true ) ||
                                    ( strstr( policy, "connectivity-ips" ) && MeerOutput->external_metadata_connectivity_ips == true ) )
                                {
                                    External( DecodeAlert, json_string );
                                }

                        }

                }
        }
}

