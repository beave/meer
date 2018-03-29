
#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>

#include "meer.h"
#include "lockfile.h"

struct _MeerConfig *MeerConfig;

void CheckLockFile ( void )
{

    char buf[10];
    FILE *lck;
    int pid;
    struct stat lckcheck;

    /* Check for lockfile first */

    if (stat(MeerConfig->lock_file, &lckcheck) == 0 )
        {

            /* Lock file is present,  open for read */

            if (( lck = fopen(MeerConfig->lock_file, "r" )) == NULL )
                {
                    fprintf(stderr, "[%s, line %d] Lock file '%s' is present but can't be read [%s]\n", __FILE__, __LINE__, MeerConfig->lock_file, strerror(errno));
                    exit(-1);
                }
            else
                {
                    if (!fgets(buf, sizeof(buf), lck))
                        {
                            fprintf(stderr, "[%s, line %d] Lock file (%s) is open for reading,  but can't read contents.\n", __FILE__, __LINE__, MeerConfig->lock_file);
                            exit(-1);
                        }

                    fclose(lck);
                    pid = atoi(buf);

                    if ( pid == 0 )
                        {
                            fprintf(stderr, "[%s, line %d] Lock file read but pid value is zero.  Aborting.....\n", __FILE__, __LINE__);
                            exit(-1);
                        }

                    /* Check to see if process is running.  We use kill with 0 signal
                     * to determine this.  We check this return value.  Signal 0
                     * won't affect running processes */

                    if ( kill(pid, 0) != -1 )
                        {
                            fprintf(stderr, "[%s, line %d] It appears that Meer is already running (pid: %d).\n", __FILE__, __LINE__, pid);
                            exit(-1);
                        }
                    else
                        {

                            printf("[%s, line %d] Lock file is present,  but Meer isn't at pid %d (Removing stale %s file)\n", __FILE__, __LINE__, pid, MeerConfig->lock_file);

                            if (unlink(MeerConfig->lock_file))
                                {
                                    fprintf(stderr, "Unable to unlink %s.\n", MeerConfig->lock_file);
                                    exit(-1);
                                }
                        }
                }
        }
    else
        {

            /* No lock file present, so create it */

            if (( lck = fopen(MeerConfig->lock_file, "w" )) == NULL )
                {
                    fprintf(stderr, "[%s, line %d] Cannot create lock file (%s - %s)", __FILE__, __LINE__, MeerConfig->lock_file, strerror(errno));
                    exit(-1);
                }
            else
                {
                    fprintf(lck, "%d", getpid() );
                    fflush(lck);
                    fclose(lck);
                }
        }
}

void Remove_Lock_File ( void )
{

    struct stat lckcheck;

    if ( (stat(MeerConfig->lock_file, &lckcheck) == 0) && unlink(MeerConfig->lock_file) != 0 )
        {
            fprintf(stderr, "[%s, line %d] Cannot remove lock file (%s - %s)\n", __FILE__, __LINE__, MeerConfig->lock_file, strerror(errno));
        }
}

