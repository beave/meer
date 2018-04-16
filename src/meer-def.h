

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#define DEFAULT_CONFIG "/tmp/meer.yaml"
#define BUFFER_SIZE 10240

#define NORMAL		0
#define ERROR		1
#define WARN 	        2
#define DEBUG           3

#define	TCP		6
#define	UDP		17
#define ICMP		1

#define DNS_CACHE_DEFAULT	900
#define PACKET_BUFFER_SIZE_DEFAULT 131072


#ifdef HAVE_LIBMYSQLCLIENT

#define MAX_MYSQL_QUERY	10240

#endif
