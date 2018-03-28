
#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdbool.h>

#ifndef HAVE_STRLCAT
size_t strlcat(char *, const char *, size_t );
#endif

#ifndef HAVE_STRLCPY
size_t strlcpy(char *, const char *, size_t );
#endif

/* Global Meer Configs */

typedef struct _MeerConfig _MeerConfig;
struct _MeerConfig
{

    char interface[64];
    char hostname[64];
    char uid[32];
    char gid[32];

    char classification_file[256];
    char reference_file[256];
    char genmsgmap_file[256];

    char waldo_file[256];

    char follow_file[256];

};


typedef struct _MeerOutput _MeerOutput;
struct _MeerOutput
{

#ifdef HAVE_LIBMYSQLCLIENT_R

    bool mysql_enabled;
    char mysql_server[128];
    int mysql_port;
    char mysql_username[64];
    char mysql_password[64];
    char mysql_database[64];

#endif

};



