

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#define DEFAULT_CONFIG "/tmp/meer.yaml"
#define BUFFER_SIZE 10240


#define M_NORMAL	0
#define M_ERROR		1
#define M_WARN		2
#define M_DEBUG		3




#ifdef HAVE_LIBMYSQLCLIENT_R

#define MAX_MYSQL_QUERY	10240

#endif
