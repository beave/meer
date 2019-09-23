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

/* Main Meer function */

/*
 * Notes:  Fix validation in yaml (make sure the module is enabled)
 *         Sanity checks (external_match == NULL, dont run, etc)
 *	   port the "stat" code to Sagan for external calls.
 *	   documentation!
 */


#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <getopt.h>
#include <fcntl.h>
#include <sys/wait.h>


#include "meer.h"
#include "meer-def.h"
#include "decode-json-alert.h"

#include "util.h"
#include "util-signal.h"
#include "config-yaml.h"
#include "lockfile.h"
#include "references.h"
#include "classifications.h"
#include "waldo.h"
#include "output.h"
#include "sid-map.h"
#include "usage.h"

struct _MeerConfig *MeerConfig;
struct _MeerOutput *MeerOutput;
struct _MeerWaldo *MeerWaldo;
struct _MeerCounters *MeerCounters;
struct _Classifications *MeerClass;
struct _References *MeerReferences;

int main (int argc, char *argv[])
{

    signal(SIGINT,  &Signal_Handler);
    signal(SIGQUIT,  &Signal_Handler);
    signal(SIGTERM,  &Signal_Handler);
//    signal(SIGSEGV,  &Signal_Handler);
    signal(SIGABRT,  &Signal_Handler);
//    signal(SIGHUP,  &Signal_Handler);		/* DEBUG: Need SIGHUP handler */
    signal(SIGUSR1,  &Signal_Handler);

    /* MOST configuration options should happen in the meer.yaml.  Barnyard2's
       "command line" verses "barnyard2.conf" gets really annoying.  Meer is
       trying to avoid that.  Hence,  very few command line options! */

    const struct option long_options[] =
    {
        { "help",         no_argument,          NULL,   'h' },
        { "quiet",        no_argument,          NULL,   'q' },
        { "daemon",       no_argument,          NULL,   'D' },
//        { "credits",      no_argument,          NULL,   'C' },
        { "config",       required_argument,    NULL,   'c' },
        {0, 0, 0, 0}
    };

    static const char *short_options =
        "c:hDq";

    signed char c;
    int option_index = 0;

    int fd_int;
    FILE *fd_file;

    struct stat st;

    bool skip_flag = 0;

    char buf[BUFFER_SIZE + PACKET_BUFFER_SIZE_DEFAULT];

    uint64_t linecount = 0;
    uint64_t old_size = 0;

    MeerConfig = (struct _MeerConfig *) malloc(sizeof(_MeerConfig));

    if ( MeerConfig == NULL )
        {
            Meer_Log(ERROR, "[%s, line %d] Failed to allocate memory for _MeerConfig. Abort!", __FILE__, __LINE__);
        }

    memset(MeerConfig, 0, sizeof(_MeerConfig));

    strlcpy(MeerConfig->yaml_file, DEFAULT_CONFIG, sizeof(MeerConfig->yaml_file));
    MeerConfig->daemonize = false;
    MeerConfig->quiet = false;

    while ((c = getopt_long(argc, argv, short_options, long_options, &option_index)) != -1)
        {

            switch(c)
                {

                    if (c == -1) break;

                case 'c':
                    strlcpy(MeerConfig->yaml_file,optarg,sizeof(MeerConfig->yaml_file) - 1);
                    break;

                case 'h':
                    Usage();
                    exit(0);
                    break;

                case 'D':
                    MeerConfig->daemonize = true;
                    break;

                case 'q':
                    MeerConfig->quiet = true;
                    break;

                default:
                    fprintf(stderr, "\nInvalid argument! See below for command line switches.\n");
                    Usage();
                    exit(0);
                    break;

                }

        }

    MeerCounters = (struct _MeerCounters *) malloc(sizeof(_MeerCounters));

    if ( MeerCounters == NULL )
        {
            Meer_Log(ERROR, "[%s, line %d] Failed to allocate memory for _MeerCounters. Abort!", __FILE__, __LINE__);
        }

    memset(MeerCounters, 0, sizeof(_MeerCounters));

    Load_YAML_Config(MeerConfig->yaml_file);

    if (( MeerConfig->meer_log_fd = fopen(MeerConfig->meer_log, "a" )) == NULL )
        {
            Meer_Log(ERROR, "Cannot open Meer log file %s! [%s]. Abort!", MeerConfig->meer_log, strerror(errno));
        }

    MeerConfig->meer_log_on = true;

    Meer_Log(NORMAL, "");
    Meer_Log(NORMAL, " @@@@@@@@@@  @@@@@@@@ @@@@@@@@ @@@@@@@    Meer version %s", VERSION);
    Meer_Log(NORMAL, " @@! @@! @@! @@!      @@!      @@!  @@@   Quadrant Information Security");
    Meer_Log(NORMAL, " @!! !!@ @!@ @!!!:!   @!!!:!   @!@!!@a    https://quadrantsec.com");
    Meer_Log(NORMAL, " !!:     !!: !!:      !!:      !!: :!a    Copyright (C) 2018-2019");
    Meer_Log(NORMAL, "  :      :   : :: ::  : :: ::   :   : :");
    Meer_Log(NORMAL, "");

    Drop_Priv();

    CheckLockFile();

    MeerConfig->endian = Check_Endian();

    Load_Classifications();

    Meer_Log(NORMAL, "");
    Meer_Log(NORMAL, "Decode 'json'          : %s", MeerConfig->json ? "enabled" : "disabled" );
    Meer_Log(NORMAL, "Decode 'metadata'      : %s", MeerConfig->metadata ? "enabled" : "disabled" );
    Meer_Log(NORMAL, "Decode 'flow'          : %s", MeerConfig->flow ? "enabled" : "disabled" );
    Meer_Log(NORMAL, "Decode 'http'          : %s", MeerConfig->http ? "enabled" : "disabled" );
    Meer_Log(NORMAL, "Decode 'tls'           : %s", MeerConfig->tls ? "enabled" : "disabled" );
    Meer_Log(NORMAL, "Decode 'ssh'           : %s", MeerConfig->ssh ? "enabled" : "disabled" );
    Meer_Log(NORMAL, "Decode 'smtp'          : %s", MeerConfig->smtp ? "enabled" : "disabled" );
    Meer_Log(NORMAL, "Decode 'email'         : %s", MeerConfig->email ? "enabled" : "disabled" );
    Meer_Log(NORMAL, ""); 
    Meer_Log(NORMAL, "Fingerprint support    : %s", MeerConfig->fingerprint ? "enabled" : "disabled" );
    Meer_Log(NORMAL, "Health updates         : %s", MeerConfig->health ? "enabled" : "disabled" );


#ifdef QUADRANT
    Meer_Log(NORMAL, "Decode 'bluedot'       : %s", MeerConfig->bluedot ? "enabled" : "disabled" );
#endif

    Meer_Log(NORMAL, "");

    Init_Waldo();

    Init_Output();

    if (( fd_file = fopen(MeerConfig->follow_file, "r" )) == NULL )
        {
            Meer_Log(ERROR, "Cannot open file %s! Abort.", MeerConfig->follow_file);
        }

    fd_int = fileno(fd_file);

    /* Become a daemon if requested */

    if ( MeerConfig->daemonize == true )
        {

            Meer_Log(NORMAL, "Becoming a daemon!");

            pid_t pid = 0;
            pid = fork();

            if ( pid == 0 )
                {

                    /* Child */

                    if ( setsid() == -1 )
                        {
                            Meer_Log(ERROR, "[%s, line %d] Failed creating new session while daemonizing", __FILE__, __LINE__);
                            exit(1);
                        }

                    pid = fork();

                    if ( pid == 0 )
                        {

                            /* Grandchild, the actual daemon */

                            if ( chdir("/") == -1 )
                                {
                                    Meer_Log(ERROR, "[%s, line %d] Failed changing directory to / after daemonizing [errno %d]", __FILE__, __LINE__, errno);
                                    exit(1);
                                }

                            /* Close and re-open stdin, stdout, and stderr, so as to
                               to release anyone waiting on them. */

                            close(0);
                            close(1);
                            close(2);

                            if ( open("/dev/null", O_RDONLY) == -1 )
                                {
                                    Meer_Log(ERROR, "[%s, line %d] Failed reopening stdin after daemonizing [errno %d]", __FILE__, __LINE__, errno);
                                }

                            if ( open("/dev/null", O_WRONLY) == -1 )
                                {
                                    Meer_Log(ERROR, "[%s, line %d] Failed reopening stdout after daemonizing [errno %d]", __FILE__, __LINE__, errno);
                                }

                            if ( open("/dev/null", O_RDWR) == -1 )
                                {
                                    Meer_Log(ERROR, "[%s, line %d] Failed reopening stderr after daemonizing [errno %d]", __FILE__, __LINE__, errno);
                                }

                        }
                    else if ( pid < 0 )
                        {

                            Meer_Log(ERROR, "[%s, line %d] Failed second fork while daemonizing", __FILE__, __LINE__);
                            exit(1);

                        }
                    else
                        {

                            exit(0);
                        }

                }
            else if ( pid < 0 )
                {

                    Meer_Log(ERROR, "[%s, line %d] Failed first fork while daemonizing", __FILE__, __LINE__);
                    exit(1);

                }
            else
                {

                    /* Wait for child to exit */
                    waitpid(pid, NULL, 0);
                    exit(0);
                }
        }



    if ( MeerWaldo->position != 0 )
        {

            Meer_Log(NORMAL, "Skipping to record %" PRIu64 " in %s" , MeerWaldo->position, MeerConfig->follow_file);

            while( (fgets(buf, sizeof(buf), fd_file) != NULL ) && linecount < MeerWaldo->position )
                {

                    linecount++;
                }

            Meer_Log(NORMAL, "Reached target record of %" PRIu64 ".  Processing new records.", MeerWaldo->position);

        }
    else
        {

            Meer_Log(NORMAL, "Ingesting data. Working........");

        }

    while(fgets(buf, sizeof(buf), fd_file) != NULL)
        {

            if ( Validate_JSON_String( (char*)buf ) == 0 )
                {
                    Decode_JSON( (char*)buf );
                }

            MeerWaldo->position++;

        }

    Meer_Log(NORMAL, "Read in %" PRIu64 " lines",MeerWaldo->position);

    if (fstat(fd_int, &st))
        {
            Meer_Log(ERROR, "Cannot 'stat' spool file '%s' [%s]  Abort!", MeerConfig->follow_file, strerror(errno));
        }

    old_size = (uint64_t) st.st_size;

    Meer_Log(NORMAL, "Waiting for new data......");

    while(1)
        {

            /* If the spool file disappears, then we wait to see if a new one
                   shows up.  Suricata might be rotating the alert.json file */

            if (fstat(fd_int, &st))
                {

                    fclose(fd_file);

                    old_size = 0;
                    linecount = 0;

                    MeerWaldo->position = 0;

                    Meer_Log(ERROR, "Follow JSON File '%s' disappeared [%s].", MeerConfig->follow_file, strerror(errno) );
                    Meer_Log(ERROR, "Waiting for new spool file....");

                    while ( fstat(fd_int, &st) != 0 )
                        {

                            sleep(1);

                        }

                    if (( fd_file = fopen(MeerConfig->follow_file, "r" )) == NULL )
                        {
                            Meer_Log(ERROR, "Cannot re-open %s. [%s]", MeerConfig->follow_file, strerror(errno) );
                        }

                }

            /* Check spool file.  If it's grown,  read in the new data */

            if ( (uint64_t) st.st_size > old_size )
                {

                    while(fgets(buf, sizeof(buf), fd_file) != NULL)
                        {

                            skip_flag = Validate_JSON_String( (char*)buf );

                            if ( skip_flag == 0 )
                                {
                                    Decode_JSON( (char*)buf);
                                }

                            MeerWaldo->position++;

                        }

                    old_size = (uint64_t) st.st_size;

                }

            /* If the spool file has _shunk_,  it's been truncated.  We need to
                   re-open it! */

            else if ( (uint64_t) st.st_size < old_size )
                {
                    Meer_Log(WARN, "Spool file Truncated! Re-opening '%s'!", MeerConfig->follow_file );

                    fclose(fd_file);

                    if (( fd_file = fopen(MeerConfig->follow_file, "r" )) == NULL )
                        {
                            Meer_Log(ERROR, "Cannot re-open %s. [%s]", MeerConfig->follow_file, strerror(errno) );
                        }

                    fd_int = fileno(fd_file);
                    old_size = 0;
                    linecount = 0;

                    MeerWaldo->position = 0;

                }

            sleep(1);
        }


    return(0);

}
