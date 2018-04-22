
#include <inttypes.h>

typedef struct _SignatureCache _SignatureCache;
struct _SignatureCache
{

    uint32_t sig_id;
    char sig_name[256];
    uint32_t sig_rev;
    uint64_t sig_sid;
};

typedef struct _ClassificationCache _ClassificationCache;
struct _ClassificationCache
{

    uint32_t sig_class_id;
    char class_name[128];
};



char *MySQL_DB_Query( char *sql );
void MySQL_Escape_String( char *sql, char *str, size_t size );
