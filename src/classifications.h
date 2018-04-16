

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

/* Classification structure */

typedef struct _Classifications _Classifications;
struct _Classifications
{
    char classtype[64];
    char description[128];
    unsigned char priority;
};

struct _Classifications *Load_Classifications( void );
