
#include <stdbool.h>

typedef struct _DnsCache _DnsCache;
struct _DnsCache
{
    char ipaddress[48];
    char reverse[256];
    uint64_t lookup_time;

};


void Drop_Priv(void);
bool Check_Endian(void);
char *Hexify(char *xdata, int length);
void DNS_Lookup( char *host, char *str, size_t size );
bool Validate_JSON_String( char *buf );
bool IP2Bit(char *ipaddr, unsigned char *out);
void Remove_Spaces(char *s);
void Remove_Return(char *s);
uint64_t Epoch_Lookup( void );
bool Is_IPv6 (char *ipaddr);
double CalcPct(uint64_t cnt, uint64_t total);
