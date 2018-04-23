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

#include "decode-json-alert.h"

#include "meer.h"
#include "meer-def.h"
#include "util.h"
#include "output.h"

#ifdef HAVE_LIBMYSQLCLIENT
#include <mysql/mysql.h>
#include "output-plugins/mysql.h"
MYSQL    *mysql;
#endif

struct _MeerOutput *MeerOutput;
struct _MeerConfig *MeerConfig;
struct _MeerCounters *MeerCounters;
struct _MeerHealth *MeerHealth;
struct _Classifications *MeerClass;

void Init_Output( void )
{

#ifdef HAVE_LIBMYSQLCLIENT

    if ( MeerOutput->mysql_enabled )
        {

            Meer_Log(NORMAL, "--[ MySQL/MariaDB information ]--------------------------------------------");
            MySQL_Connect();

            MeerOutput->mysql_sensor_id = MySQL_Get_Sensor_ID();
            MeerOutput->mysql_last_cid = MySQL_Get_Last_CID();

            Meer_Log(NORMAL, "");
            Meer_Log(NORMAL, "Record 'metadata': %s", MeerOutput->mysql_metadata ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Record 'flow'    : %s", MeerOutput->mysql_flow ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Record 'http'    : %s", MeerOutput->mysql_http ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Record 'tls'     : %s", MeerOutput->mysql_tls ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Record 'ssh'     : %s", MeerOutput->mysql_ssh ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Record 'smtp'    : %s", MeerOutput->mysql_smtp ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Record 'email'   : %s", MeerOutput->mysql_email ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "");

            Meer_Log(NORMAL, "---------------------------------------------------------------------------");


        }

#endif


}

bool Output_Alert ( struct _DecodeAlert *DecodeAlert )
{

    char tmp[MAX_MYSQL_QUERY] = { 0 };

#ifdef HAVE_LIBMYSQLCLIENT

    bool health_flag = 0;
    int i = 0;

    if ( MeerOutput->mysql_enabled )
        {

            int signature_id = 0;
            int class_id = 0;

            class_id = MySQL_Get_Class_ID( DecodeAlert);
            signature_id = MySQL_Get_Signature_ID( DecodeAlert, class_id );

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

                    MySQL_DB_Query("BEGIN");

                    MySQL_Insert_Event( DecodeAlert, signature_id );

                    MySQL_Insert_Header( DecodeAlert );

                    MySQL_Insert_Payload ( DecodeAlert );

//	    MySQL_Reference_Handler ( DecodeAlert );


                    if ( MeerConfig->dns == true )
                        {
                            MySQL_Insert_DNS ( DecodeAlert );
                        }

                    if ( DecodeAlert->has_extra_data == 1 )
                        {
                            MySQL_Insert_Extra_Data ( DecodeAlert );
                        }

                    if ( DecodeAlert->has_flow == true && MeerOutput->mysql_flow == true )
                        {
                            MySQL_Insert_Flow ( DecodeAlert );
                        }

                    if ( DecodeAlert->has_http == true && MeerOutput->mysql_http == true )
                        {
                            MySQL_Insert_HTTP ( DecodeAlert );
                        }

                    if ( DecodeAlert->has_tls == true && MeerOutput->mysql_tls == true )
                        {
                            MySQL_Insert_TLS ( DecodeAlert );
                        }

                    if ( DecodeAlert->has_ssh_server == true && MeerOutput->mysql_ssh == true )
                        {
                            MySQL_Insert_SSH ( DecodeAlert, SSH_SERVER );
                        }

                    if ( DecodeAlert->has_ssh_client == true && MeerOutput->mysql_ssh == true )
                        {
                            MySQL_Insert_SSH ( DecodeAlert, SSH_CLIENT );
                        }

                    if ( DecodeAlert->alert_has_metadata == true && MeerOutput->mysql_metadata == true )
                        {
                            MySQL_Insert_Metadata ( DecodeAlert );
                        }

                    if ( DecodeAlert->has_smtp == true && MeerOutput->mysql_smtp == true )
                        {
                            MySQL_Insert_SMTP ( DecodeAlert );
                        }

                    if ( DecodeAlert->has_email == true && MeerOutput->mysql_email == true )
                        {
                            MySQL_Insert_Email ( DecodeAlert );
                        }


                    MySQL_DB_Query("COMMIT");

                    MeerOutput->mysql_last_cid++;

                }
            else
                {

                    snprintf(tmp, sizeof(tmp), "UPDATE sensor SET health=%" PRIu64 " WHERE sid=%d", Epoch_Lookup(), MeerOutput->mysql_sensor_id);

                    MySQL_DB_Query( (char*)tmp );

                    MeerCounters->HealthCountT++;
                    MeerCounters->UPDATECount++;

                }


        }

#endif

    return 0;
}
