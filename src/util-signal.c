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


void Signal_Handler(int sig_num)
{

    close(MeerConfig->waldo_fd);
    Remove_Lock_File();

    Meer_Log(M_NORMAL, "Shutdown Complete!");
    exit(0);

}


