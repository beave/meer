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
#include <string.h>

#include "meer.h"
#include "meer-def.h"

struct _MeerWaldo *MeerWaldo;
struct _MeerConfig *MeerConfig;

void Init_Waldo( void )
{

    bool new_waldo = false;


    if (( MeerConfig->waldo_fd = open(MeerConfig->waldo_file, (O_CREAT | O_EXCL | O_RDWR), (S_IREAD | S_IWRITE))) > 0 )
        {
            Meer_Log(NORMAL,"New waldo file created.");
            new_waldo = true;
        }


    else if ((MeerConfig->waldo_fd = open(MeerConfig->waldo_file, (O_CREAT | O_RDWR), (S_IREAD | S_IWRITE))) < 0 )
        {
            Meer_Log(ERROR, "[%s, line %d] Cannot open() for waldo '%s' [%s]", __FILE__, __LINE__, MeerConfig->waldo_file, strerror(errno));
        }

    if ( ftruncate(MeerConfig->waldo_fd, sizeof(_MeerWaldo)) != 0 )
        {
            Meer_Log(ERROR, "[%s, line %d] Failed to ftruncate for _MeerWaldo. [%s]", __FILE__, __LINE__, strerror(errno));
        }

    if (( MeerWaldo = mmap(0, sizeof(_MeerWaldo), (PROT_READ | PROT_WRITE), MAP_SHARED, MeerConfig->waldo_fd, 0)) == MAP_FAILED )
        {
            Meer_Log(ERROR,"[%s, line %d] Error allocating memory for counters object! [%s]", __FILE__, __LINE__, strerror(errno));
        }

    if ( new_waldo == false )
        {
            Meer_Log(NORMAL, "Waldo loaded. Current position: %" PRIu64 "", MeerWaldo->position);
        }

}
