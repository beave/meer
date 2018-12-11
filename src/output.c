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

#include "decode-json-alert.h"

#include "meer.h"
#include "meer-def.h"
#include "util.h"
#include "output.h"
#include "references.h"
#include "sid-map.h"
#include "config-yaml.h"

#include "output-plugins/sql.h"

#ifdef HAVE_LIBMYSQLCLIENT
#include <mysql/mysql.h>
MYSQL    *mysql;
#endif

struct _MeerOutput *MeerOutput;
struct _MeerConfig *MeerConfig;
struct _MeerCounters *MeerCounters;
struct _MeerHealth *MeerHealth;
struct _Classifications *MeerClass;

void Init_Output( void )
{

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
            Meer_Log(NORMAL, "");
            Meer_Log(NORMAL, "---------------------------------------------------------------------------");


        }

#endif


}

bool Output_Alert ( struct _DecodeAlert *DecodeAlert )
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

            class_id = SQL_Get_Class_ID( DecodeAlert );

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

#ifdef QUADRANT

                    if ( MeerConfig->bluedot == true )
                        {
                            SQL_Insert_Bluedot ( DecodeAlert );
                        }

#endif

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


                    /* Record CID in case of crash/disconnections */

                    SQL_Record_Last_CID();

                    /* These are very Quadrant specific queries.  You likely don't want them. */

#ifdef QUADRANT

                    SQL_DB_Quadrant( DecodeAlert, signature_id );

#endif


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
