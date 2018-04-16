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

#ifdef HAVE_LIBMYSQLCLIENT
#include <mysql/mysql.h>
#include "output-plugins/mysql.h"
MYSQL    *connection, *mysql;
#endif

#include "meer.h"
#include "meer-def.h"
#include "decode-json-alert.h"

struct _MeerOutput *MeerOutput;
struct _MeerConfig *MeerConfig;
struct _MeerCounters *MeerCounters;
struct _MeerHealth *MeerHealth;


void Init_Output( void )
{

#ifdef HAVE_LIBMYSQLCLIENT

    if ( MeerOutput->mysql_enabled )
        {

            Meer_Log(NORMAL, "--[ MySQL/MariaDB information ]--------------------------------------------");
            MySQL_Connect();

            MeerOutput->mysql_sensor_id = MySQL_Get_Sensor_ID();
            MeerOutput->mysql_last_cid = MySQL_Get_Last_CID();


            Meer_Log(NORMAL, "---------------------------------------------------------------------------");


        }

#endif


}

bool Output_Alert ( struct _DecodeAlert *DecodeAlert,
                    struct _Classifications *MeerClass )
{

    char tmp[MAX_MYSQL_QUERY] = { 0 };

#ifdef HAVE_LIBMYSQLCLIENT

    bool health_flag = 0;
    int i = 0;

    if ( MeerOutput->mysql_enabled )
        {

            int signature_id = 0;

            signature_id = MySQL_Get_Signature_ID( DecodeAlert, MeerClass );

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


                    MySQL_DB_Query("COMMIT");

                    MeerOutput->mysql_last_cid++;


                }
            else
                {

                    snprintf(tmp, sizeof(tmp), "UPDATE sensor SET health=%" PRIu64 " WHERE sid=%d", Epoch_Lookup(), MeerOutput->mysql_sensor_id);
                    MySQL_DB_Query( (char*)tmp );

                }


        }

#endif


}
