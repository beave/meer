

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

#define SSH_SERVER	0
#define SSH_CLIENT	1

#define DNS_CACHE_DEFAULT	900
#define PACKET_BUFFER_SIZE_DEFAULT 131072

#ifdef HAVE_LIBMYSQLCLIENT

#define MAX_MYSQL_QUERY	10240 + PACKET_BUFFER_SIZE_DEFAULT

#define		EXTRA_ORIGNAL_CLIENT_IPV4		1
#define         EXTRA_ORIGNAL_CLIENT_IPV6               2
#define 	EXTRA_UNUSED				3
#define		EXTRA_GZIP_DECOMPRESSED_DATA		4
#define		EXTRA_SMTP_FILENAME			5
#define		EXTRA_SMTP_MAIL_FROM			6
#define		EXTRA_SMTP_RCPT_TO			7
#define		EXTRA_SMTP_EMAIL_HEADERS		8
#define		EXTRA_HTTP_URI				9
#define		EXTRA_HTTP_HOSTNAME			10
#define		EXTRA_IPV6_SOURCE_ADDRESS		11
#define		EXTRA_IPV6_DESTINATION_ADDRESS		12
#define		EXTRA_NORMALIZED_JAVASCRIPT		13


#endif
