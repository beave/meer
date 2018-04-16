
#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "meer.h"
#include "meer-def.h"
#include "classifications.h"

struct _MeerCounters *MeerCounters;
struct _MeerConfig *MeerConfig;
struct _Classifications *MeerClass;

struct _Classifications *Load_Classifications( void )
{

    int linecount = 0;

    char buf[1024];

    char *ptr1 = NULL;
    char *ptr2 = NULL;
    char *ptr3 = NULL;
    char *ptr4 = NULL;

    FILE *class_fd;

    MeerCounters->ClassCount = 0;

    if (( class_fd = fopen(MeerConfig->classification_file, "r" )) == NULL )
        {
            Meer_Log(ERROR, "[%s, line %d] Cannot open '%s'", __FILE__,  __LINE__, MeerConfig->classification_file);
        }

    while(fgets(buf, sizeof(buf), class_fd) != NULL)
        {

            linecount++;

            if (buf[0] == '#' || buf[0] == 10 || buf[0] == ';' || buf[0] == 32)
                {
                    continue;
                }
            else
                {

                    MeerClass = (_Classifications *) realloc(MeerClass, (MeerCounters->ClassCount+1) * sizeof(_Classifications));

                    if ( MeerClass == NULL )
                        {
                            Meer_Log(ERROR, "[%s, line %d] Failed to reallocate memory for _Classifications. Abort!", __FILE__, __LINE__);


                        }
                }

            Remove_Return(buf);

            strtok_r(buf, ":", &ptr1);

            ptr2 = strtok_r(NULL, ",", &ptr1);	/* web-application-attack */
            ptr3 = strtok_r(NULL, ",", &ptr1);	/* "Web Application Attack" */
            ptr4 = strtok_r(NULL, ",", &ptr1);	/* 1 */

            if ( ptr2 == NULL || ptr3 == NULL || ptr4 == NULL )
                {
                    Meer_Log(ERROR, "[%s, line %d] Classifications file appears to be incomplete. Abort!", __FILE__, __LINE__);
                }

            Remove_Spaces(ptr2);

            strlcpy(MeerClass[MeerCounters->ClassCount].classtype, ptr2, sizeof(MeerClass[MeerCounters->ClassCount].classtype));
            strlcpy(MeerClass[MeerCounters->ClassCount].description, ptr3, sizeof(MeerClass[MeerCounters->ClassCount].description));
            MeerClass[MeerCounters->ClassCount].priority = atoi(ptr4);

            if ( MeerClass[MeerCounters->ClassCount].priority == 0 )
                {
                    Meer_Log(ERROR, "[%s, line %d] Classification has a priority of 0 at line %d in %s.", linecount, MeerConfig->classification_file);
                }

            MeerCounters->ClassCount++;

        }

    Meer_Log(NORMAL, "Classifications file loaded [%s].", MeerConfig->classification_file);
    fclose(class_fd);

    return(MeerClass);
}


/* Lookup the long description and return the classtype */

int Class_Lookup( const char *class, char *str, size_t size )
{

    int i;

    for (i = 0; i < MeerCounters->ClassCount; i++)
        {

            if (!strcmp(class, MeerClass[i].description))
                {
                    snprintf(str, size, "%s", MeerClass[i].classtype);
                    return 0;
                }
        }


    snprintf(str, sizeof("UNKNOWN"), "UNKNOWN");
    return -1;

}

