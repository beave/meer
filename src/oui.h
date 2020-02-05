
typedef struct _Manfact_Struct _Manfact_Struct;
struct _Manfact_Struct
{
    char mac[22];
    char short_manfact[9];
    char long_manfact[128];
};


void Load_OUI( void );
void OUI_Lookup ( char *mac, char *str, size_t size );


