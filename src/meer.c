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

/*
#ifdef HAVE_LIBJSON_C
#include <json-c/json.h>
#endif


#ifndef HAVE_LIBJSON_C
libjson-c is required for Meer to function!
#endif
*/

#include "meer.h"
#include "meer-def.h"

#include "util-signal.h"
#include "lockfile.h"
#include "util.h"


struct _MeerConfig *MeerConfig;
struct _MeerOutput *MeerOutput;
struct _MeerWaldo *MeerWaldo;

// signal
// open waldo / write waldo

int main (int argc, char *argv[])
{

    signal(SIGINT,  &Signal_Handler);
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

    char buf[BUFFER_SIZE];

    uint64_t linecount = 0;
    uint64_t old_size = 0;
    uint64_t new_size = 0;

    struct json_object *json_obj;
    struct json_object *tmp;

    /* The only command line option is to specify a non-default configuration
       file */

    if ( argc > 2 )
        {
            Meer_Log(M_ERROR, "Too many arguments.  Only one YAML file can be specified.\n");
        }

    if ( argc == 2 )
        {
            yaml_file = argv[1];
        }

    Meer_Log(M_NORMAL, "Firing up Meer version %s", VERSION);

    Load_YAML_Config(yaml_file);

    Drop_Priv();

    CheckLockFile();

    Init_Waldo();

    Init_Output();

    if (( fd_file = fopen(MeerConfig->follow_file, "r" )) == NULL )
        {
            Meer_Log(M_ERROR, "Cannot open file %s! Abort.", MeerConfig->follow_file);
        }

    fd_int = fileno(fd_file);


    if ( MeerWaldo->position != 0 )
        {

            Meer_Log(M_NORMAL, "Skipping to record %" PRIu64 " in %s" , MeerWaldo->position, MeerConfig->follow_file);

            while( (fgets(buf, sizeof(buf), fd_file) != NULL ) && linecount < MeerWaldo->position )
                {

                    linecount++;
                }
        }

    while(fgets(buf, sizeof(buf), fd_file) != NULL)
        {

            Decode_JSON( (char*)buf);

//	    json_obj = json_tokener_parse(buf);

            /*
            	    if (json_object_object_get_ex(json_obj, "event_type", &tmp))
            			{
            			printf("Type: |%s|\n", json_object_get_string(tmp));
            			}
            */


            /* Do something with json/buf */

            MeerWaldo->position++;
        }

    Meer_Log(M_NORMAL, "Read in %" PRIu64 " lines",MeerWaldo->position);


    if (fstat(fd_int, &st))
        {
            Meer_Log(M_ERROR, "Cannot state follow file %s.  Abort", MeerConfig->follow_file);
        }

    old_size = (uint64_t) st.st_size;
//    printf("Size: %llu\n", old_size);

    Meer_Log(M_NORMAL, "Waiting for new data......");

    while(1)
        {

            if (fstat(fd_int, &st))
                {
                    Meer_Log(M_ERROR, "Cannot state follow file %s.  Abort", MeerConfig->follow_file);
                }

            if ( (uint64_t) st.st_size > old_size )
                {
                    printf("File grew. Reading!");

                    while(fgets(buf, sizeof(buf), fd_file) != NULL)
                        {

                            /* Do something */
                            //linecount++;
                            MeerWaldo->position++;
                            //printf("FOLLOW: [%d] buf: %s\n", linecount, buf);
                        }

                    old_size = (uint64_t) st.st_size;

                }


            else if ( (uint64_t) st.st_size < old_size )
                {
                    printf("File Truncated! Re-Opening!\n");

                    fclose(fd_file);

                    if (( fd_file = fopen(MeerConfig->follow_file, "r" )) == NULL )
                        {
                            printf("error!\n");
                            exit(-1);
                        }
                    fd_int = fileno(fd_file);
                    old_size = 0;
                    linecount = 0;
                    MeerWaldo->position = 0;
                }

//            printf("loop\n");
            sleep(1);
        }


    return(0);

}
