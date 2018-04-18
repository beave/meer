#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>    /* standard unix functions, like getpid()         */
#include <signal.h>    /* signal name macros, and the signal() prototype */

#include "meer.h"
#include "meer-def.h"

struct _MeerWaldo *MeerWaldo;
struct _MeerConfig *MeerConfig;
struct _MeerOutput *MeerOutput;


void Signal_Handler(int sig_num)
{

    close(MeerConfig->waldo_fd);

    MeerOutput->mysql_last_cid++;

    MySQL_DB_Query("ROLLBACK");

    MeerOutput->mysql_last_cid++;

    MySQL_Record_Last_CID();

    sleep(1);
    mysql_close(MeerOutput->mysql_dbh);


    Remove_Lock_File();

    Meer_Log(NORMAL, "Last CID is : %" PRIu64 ". Shutdown Complete!", MeerOutput->mysql_last_cid);

    exit(0);

}


