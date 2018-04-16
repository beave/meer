

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

typedef struct _References _References;
struct _References
{
    char refid[128];
    char refurl[2048];
};

struct _References *Load_References( void );
