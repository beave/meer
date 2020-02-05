
#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "meer.h"
#include "meer-def.h"
#include "util.h"
#include "oui.h"

struct _MeerCounters *MeerCounters;
struct _MeerConfig *MeerConfig;
struct _Manfact_Struct *MF_Struct;

void Load_OUI( void )
{

    char buf[1024] = { 0 };
    char *saveptr = NULL;

    char *mac = NULL;
    char *short_manfact = NULL;
    char *long_manfact = NULL;

    int linecount = 0;

    FILE *mf;

    if (( mf = fopen(MeerConfig->oui_filename, "r" )) == NULL )
        {
            Meer_Log(ERROR, "[%s, line %d] Cannot open rule file %s. [%s]", __FILE__,  __LINE__, MeerConfig->oui_filename, strerror(errno) );
        }

    while(fgets(buf, sizeof(buf), mf) != NULL)
        {

            linecount++;

            if (buf[0] == '#' || buf[0] == 10 || buf[0] == ';' || buf[0] == 32)
                {
                    continue;
                }

            buf[ strlen(buf) - 1 ] = '\0';		/* Remove return */

            mac  = strtok_r(buf, "\t", &saveptr);
            short_manfact = strtok_r(NULL, "\t", &saveptr);
            long_manfact = strtok_r(NULL, "\t", &saveptr);

            if ( mac == NULL || short_manfact == NULL )
                {
                    Meer_Log(ERROR, "[%s, line %d] %s incorrectly formated at line %d", __FILE__,  __LINE__, MeerConfig->oui_filename, linecount );
                }

            if ( long_manfact == NULL )
                {
                    long_manfact = "0";
                }

            /* Allocate memory for classifications,  but not comments */

            MF_Struct = (_Manfact_Struct *) realloc(MF_Struct, (MeerCounters->OUICount+1) * sizeof(_Manfact_Struct));

            if ( MF_Struct == NULL )
                {
                    Meer_Log(ERROR, "[%s, line %d] Failed to reallocate memory for _Manfact_Struct. Abort!", __FILE__, __LINE__);
                }

            memset(&MF_Struct[MeerCounters->OUICount], 0, sizeof(struct _Manfact_Struct));

            strlcpy(MF_Struct[MeerCounters->OUICount].mac, mac, sizeof(MeerCounters->OUICount));
            strlcpy(MF_Struct[MeerCounters->OUICount].short_manfact, short_manfact, sizeof(MeerCounters->OUICount));
            strlcpy(MF_Struct[MeerCounters->OUICount].long_manfact, long_manfact, sizeof(MeerCounters->OUICount));

            MeerCounters->OUICount++;

        }

    Meer_Log(NORMAL, "Loaded %d entries from OUI database [%s].",  MeerCounters->OUICount,  MeerConfig->oui_filename);

}


void OUI_Lookup ( char *mac, char *str, size_t size )
{

    char *s1 = NULL;
    char *s2 = NULL;
    char *s3 = NULL;
    char *saveptr = NULL;

    int i = 0;

    char new_mac[32] = { 0 };
    char search_string[9] = { 0 };

    /* Convert the MAC to upper case */

    strlcpy(new_mac, mac, sizeof(new_mac));
    To_UpperC(new_mac);

    /* Break up the MAC */

    s1 = strtok_r(new_mac, ":", &saveptr);
    s2 = strtok_r(NULL, ":", &saveptr);
    s3 = strtok_r(NULL, ":", &saveptr);

    /* Shouldn't ever see this, but just in case */

    if ( s1 == NULL || s2 == NULL || s3 == NULL )
        {
            Meer_Log(ERROR, "[%s, line %d] Invalid entry found in _Manfact_Struct. Abort!", __FILE__, __LINE__);
        }

    /* Our new search string */

    snprintf(search_string, sizeof(search_string), "%s:%s:%s", s1, s2, s3);

    /* See if we can find the MAC address */

    for ( i = 0; i < MeerCounters->OUICount; i++ )
        {

            if ( !strncmp(search_string,  MF_Struct[i].mac, 8) )
                {

                    if ( MF_Struct[i].long_manfact[0] != '0' )
                        {
                            snprintf(str, size, "%s", MF_Struct[i].long_manfact);
                            return;
                        }
                    else
                        {
                            snprintf(str, size, "%s", MF_Struct[i].short_manfact);
                            return;
                        }

                }

        }

    /* Unknown / not found */

    snprintf(str, size, "");

}

