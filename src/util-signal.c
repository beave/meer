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

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>    /* standard unix functions, like getpid()         */
#include <signal.h>    /* signal name macros, and the signal() prototype */

#include "meer.h"
#include "meer-def.h"
#include "decode-json-alert.h"
#include "lockfile.h"

#ifdef HAVE_LIBMYSQLCLIENT
#include "output-plugins/mysql.h"
#endif


struct _MeerWaldo *MeerWaldo;
struct _MeerConfig *MeerConfig;
struct _MeerOutput *MeerOutput;


void Signal_Handler(int sig_num)
{

#ifdef HAVE_LIBMYSQLCLIENT

    if ( MeerOutput->mysql_enabled == true ) 
	{
    close(MeerConfig->waldo_fd);

    MySQL_DB_Query("ROLLBACK");

    MeerOutput->mysql_last_cid++;

    MySQL_Record_Last_CID();

    sleep(1);

    mysql_close(MeerOutput->mysql_dbh);

    Remove_Lock_File();

    Meer_Log(NORMAL, "Last CID is : %" PRIu64 ". Shutdown Complete!", MeerOutput->mysql_last_cid);
	}

#endif 

    exit(0);

}


