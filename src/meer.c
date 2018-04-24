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

/* Main Meer function */

/* DEBUG:  Needs:
	   SIGHUP handler
	   Cache for legacy reference crap
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
    signal(SIGSEGV,  &Signal_Handler);
    signal(SIGABRT,  &Signal_Handler);

    /*
        signal(SIGHUP,  &Signal_Handler);
        signal(SIGINT,  &Signal_Handler);
        signal(SIGQUIT, &Signal_Handler);
        signal(SIGTERM, &Signal_Handler);
        signal(SIGABRT, &Signal_Handler);
        signal(SIGSEGV, &Signal_Handler );
    */

    char *yaml_file = DEFAULT_CONFIG;

    int fd_int;
    FILE *fd_file;

    struct stat st;

    bool skip_flag = 0;

    char buf[BUFFER_SIZE + PACKET_BUFFER_SIZE_DEFAULT];

    uint64_t linecount = 0;
    uint64_t old_size = 0;

    MeerCounters = malloc(sizeof(_MeerCounters));

    if ( MeerCounters == NULL )
        {
            Meer_Log(ERROR, "[%s, line %d] Failed to allocate memory for _MeerCounters. Abort!", __FILE__, __LINE__);
        }

    memset(MeerCounters, 0, sizeof(_MeerCounters));

    /* The only command line option is to specify a non-default configuration
       file */

    if ( argc > 2 )
        {
            Meer_Log(ERROR, "Too many arguments.  Only one YAML file can be specified.\n");
        }

    if ( argc == 2 )
        {
            yaml_file = argv[1];
        }

    Meer_Log(NORMAL, "");
    Meer_Log(NORMAL, " @@@@@@@@@@  @@@@@@@@ @@@@@@@@ @@@@@@@    Meer version %s", VERSION);
    Meer_Log(NORMAL, " @@! @@! @@! @@!      @@!      @@!  @@@   Quadrant Information Security");
    Meer_Log(NORMAL, " @!! !!@ @!@ @!!!:!   @!!!:!   @!@!!@a    https://quadrantsec.com");
    Meer_Log(NORMAL, " !!:     !!: !!:      !!:      !!: :!a    Copyright (C) 2018");
    Meer_Log(NORMAL, "  :      :   : :: ::  : :: ::   :   : :");
    Meer_Log(NORMAL, "");

    Load_YAML_Config(yaml_file);

    Drop_Priv();

    MeerConfig->endian = Check_Endian();

    Load_Classifications();

    /* Legacy reference system */

    if ( MeerConfig->reference_system )
        {
            Meer_Log(NORMAL, "Legacy reference system enabled");
            Load_References();
            Load_SID_Map();
        }

    Meer_Log(NORMAL, "");
    Meer_Log(NORMAL, "Decode 'metadata': %s", MeerConfig->metadata ? "enabled" : "disabled" );
    Meer_Log(NORMAL, "Decode 'flow'    : %s", MeerConfig->flow ? "enabled" : "disabled" );
    Meer_Log(NORMAL, "Decode 'http'    : %s", MeerConfig->http ? "enabled" : "disabled" );
    Meer_Log(NORMAL, "Decode 'tls'     : %s", MeerConfig->tls ? "enabled" : "disabled" );
    Meer_Log(NORMAL, "Decode 'ssh'     : %s", MeerConfig->ssh ? "enabled" : "disabled" );
    Meer_Log(NORMAL, "Decode 'smtp'    : %s", MeerConfig->smtp ? "enabled" : "disabled" );
    Meer_Log(NORMAL, "Decode 'email'   : %s", MeerConfig->email ? "enabled" : "disabled" );
    Meer_Log(NORMAL, "");

    CheckLockFile();

    Init_Waldo();

    Init_Output();

    if (( fd_file = fopen(MeerConfig->follow_file, "r" )) == NULL )
        {
            Meer_Log(ERROR, "Cannot open file %s! Abort.", MeerConfig->follow_file);
        }

    fd_int = fileno(fd_file);


    if ( MeerWaldo->position != 0 )
        {

            Meer_Log(NORMAL, "Skipping to record %" PRIu64 " in %s" , MeerWaldo->position, MeerConfig->follow_file);

            while( (fgets(buf, sizeof(buf), fd_file) != NULL ) && linecount < MeerWaldo->position )
                {

                    linecount++;
                }

            Meer_Log(NORMAL, "Reached target record of %" PRIu64 ".  Processing new records.", MeerWaldo->position);

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
            Meer_Log(ERROR, "Cannot state follow file %s.  Abort", MeerConfig->follow_file);
        }

    old_size = (uint64_t) st.st_size;

    Meer_Log(NORMAL, "Waiting for new data......");

    while(1)
        {

            if (fstat(fd_int, &st))
                {
                    Meer_Log(ERROR, "Cannot state follow file %s.  Abort", MeerConfig->follow_file);
                }

            if ( (uint64_t) st.st_size > old_size )
                {

                    while(fgets(buf, sizeof(buf), fd_file) != NULL)
                        {

                            skip_flag = Validate_JSON_String( (char*)buf );

                            if ( skip_flag == true )
                                {
                                    Decode_JSON( (char*)buf);
                                }

                            MeerWaldo->position++;
                        }

                    old_size = (uint64_t) st.st_size;

                }


            else if ( (uint64_t) st.st_size < old_size )
                {
                    Meer_Log(WARN, "File Truncated! Re-opening %s!", MeerConfig->follow_file );

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
