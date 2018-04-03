#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "meer.h"
#include "meer-def.h"
#include "mysql.h"


#ifdef HAVE_LIBMYSQLCLIENT_R
#include <mysql/mysql.h>
#endif

struct _MeerConfig *MeerConfig;
struct _MeerOutput *MeerOutput;

#ifdef HAVE_LIBMYSQLCLIENT_R


void MySQL_Connect( void ) 
{

	MeerOutput->mysql_dbh = mysql_init(NULL);

	if ( MeerOutput->mysql_dbh == NULL )
		{
		Remove_Lock_File();
		Meer_Log(M_ERROR, "[%s, line %d] Error initializing MySQL", __FILE__, __LINE__);
		}

	my_bool reconnect = true;
	mysql_options(MeerOutput->mysql_dbh,MYSQL_READ_DEFAULT_GROUP,MeerOutput->mysql_database);
	mysql_options(MeerOutput->mysql_dbh,MYSQL_OPT_RECONNECT, &reconnect);

	if (!mysql_real_connect(MeerOutput->mysql_dbh, MeerOutput->mysql_server, 
	     MeerOutput->mysql_username, MeerOutput->mysql_password, MeerOutput->mysql_database, 
	     MeerOutput->mysql_port, NULL, 0 ))
	{

		Meer_Log(M_ERROR, "[%s, line %d] MySQL Error %u: \"%s\"", __FILE__,  __LINE__, 
		mysql_errno(MeerOutput->mysql_dbh), mysql_error(MeerOutput->mysql_dbh));

	}
	

	Meer_Log(M_NORMAL, "Successfully connected to MySQL/MariaDB database.");
}

uint32_t MySQL_Get_Sensor_ID( void )
{

	char tmp[MAX_MYSQL_QUERY]; 
	int sensor_id = 0;
	char *results;

	snprintf(tmp, sizeof(tmp), 
	"SELECT sid FROM sensor WHERE hostname='%s' AND interface='%s' AND detail=1 AND encoding='0'", 
	MeerConfig->hostname, MeerConfig->interface);

	results=MySQL_DB_Query(tmp); 

	/* If we get results,  go ahead and return the value */

	if ( results != NULL ) { 

		Meer_Log(M_NORMAL, "Using Database Sensor ID: %d", atoi(results) );
		return( atoi(results) ); 
	}

	snprintf(tmp, sizeof(tmp), 
	"INSERT INTO sensor (hostname, interface, filter, detail, encoding, last_cid) VALUES ('%s', '%s', NULL, '1', '0', '0')", 
	MeerConfig->hostname, MeerConfig->interface);
	MySQL_DB_Query(tmp);

	results = MySQL_DB_Query("SELECT LAST_INSERT_ID()");

	Meer_Log(M_NORMAL, "Using New Database Sensor ID: %d", atoi(results));

	return( atoi(results) ); 

}


char *MySQL_DB_Query( char *sql )
{

	char tmp[MAX_MYSQL_QUERY]; 
	char *re = NULL;

	MYSQL_RES *res;
	MYSQL_ROW row;

	if ( mysql_real_query(MeerOutput->mysql_dbh, sql, strlen(sql) ) ) 
	   {
	   Remove_Lock_File();
	   Meer_Log(M_ERROR, "MySQL/MariaDB Error [%u:] \"%s\"\nOffending SQL statement: %s\n", __FILE__,  __LINE__, mysql_errno(MeerOutput->mysql_dbh), mysql_error(MeerOutput->mysql_dbh), sql);

   	   }

        res = mysql_use_result(MeerOutput->mysql_dbh);

	if ( res != NULL ) 
	   {
	   while(row = mysql_fetch_row(res)) 
		{
		snprintf(tmp, sizeof(tmp), "%s", row[0]);
		re=tmp;
		}
	   }

	mysql_free_result(res);
	return(re);


}


#endif

