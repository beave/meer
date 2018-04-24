

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

typedef struct _References _References;
struct _References
{
    char refid[128];
    char refurl[2100];
};

void Load_References( void );
