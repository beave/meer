
#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "meer.h"
#include "meer-def.h"
#include "references.h"

//struct _References *MeerReferences;
struct _MeerCounters *MeerCounters;
struct _MeerConfig *MeerConfig;

struct _References *Load_References( void )
{


    struct _References *MeerReferences = NULL;

    int linecount = 0;

    char buf[1024];

    char *ptr1 = NULL;
    char *ptr2 = NULL;
    char *ptr3 = NULL;
    char *ptr4 = NULL;

    FILE *reference_fd;

    MeerCounters->ReferenceCount = 0;

    if (( reference_fd = fopen(MeerConfig->reference_file, "r" )) == NULL )
        {
            Meer_Log(ERROR, "[%s, line %d] Cannot open '%s'", __FILE__,  __LINE__, MeerConfig->reference_file);
        }

    while(fgets(buf, sizeof(buf), reference_fd) != NULL)
        {

            linecount++;

            if (buf[0] == '#' || buf[0] == 10 || buf[0] == ';' || buf[0] == 32)
                {
                    continue;
                }
            else
                {

                    MeerReferences = (_References *) realloc(MeerReferences, (MeerCounters->ReferenceCount+1) * sizeof(_References));

                    if ( MeerReferences == NULL )
                        {
                            Meer_Log(ERROR, "[%s, line %d] Failed to reallocate memory for _References. Abort!", __FILE__, __LINE__);


                        }
                }

            Remove_Return(buf);

            strtok_r(buf, ":", &ptr1);

            ptr2 = strtok_r(NULL, ",", &ptr1);
            ptr3 = strtok_r(NULL, ",", &ptr1);

            if ( ptr2 == NULL || ptr3 == NULL )
                {
                    Meer_Log(ERROR, "[%s, line %d] Reference file appears to be incomplete. Abort!", __FILE__, __LINE__);
                }

            Remove_Spaces(ptr2);


            strlcpy(MeerReferences[MeerCounters->ReferenceCount].refid, ptr2, sizeof(MeerReferences[MeerCounters->ReferenceCount].refid));
            strlcpy(MeerReferences[MeerCounters->ReferenceCount].refurl, ptr2, sizeof(MeerReferences[MeerCounters->ReferenceCount].refurl));

            MeerCounters->ClassCount++;

        }

    Meer_Log(NORMAL, "References file loaded [%s].", MeerConfig->reference_file);
    fclose(reference_fd);

    return(MeerReferences);

}

