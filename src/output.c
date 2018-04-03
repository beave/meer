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

#ifdef HAVE_LIBMYSQLCLIENT_R
#include <mysql/mysql.h>
MYSQL    *connection, *mysql;
#endif

#include "meer.h"
#include "meer-def.h"

struct _MeerOutput *MeerOutput;


void Init_Output( void )
{

#ifdef HAVE_LIBMYSQLCLIENT_R

    if ( MeerOutput->mysql_enabled )
        {

            Meer_Log(M_NORMAL, "--[ MySQL/MariaDB information ]----------------------------------------------");
            MySQL_Connect();

            MeerOutput->mysql_sensor_id = MySQL_Get_Sensor_ID();
            Meer_Log(M_NORMAL, "-----------------------------------------------------------------------------");


        }

#endif


}
