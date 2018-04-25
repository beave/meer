/*
** Copyright (C) 2018 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2018 Champ Clark III <cclark@quadrantsec.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#include <inttypes.h>
//#include "decode-json-alert.h"

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

void MySQL_Insert_Payload ( struct _DecodeAlert *DecodeAlert );
void MySQL_Insert_DNS ( struct _DecodeAlert *DecodeAlert );
void MySQL_Insert_Extra_Data ( struct _DecodeAlert *DecodeAlert );
void MySQL_Insert_Flow ( struct _DecodeAlert *DecodeAlert );
void MySQL_Insert_HTTP ( struct _DecodeAlert *DecodeAlert );
void MySQL_Insert_TLS ( struct _DecodeAlert *DecodeAlert );
void MySQL_Insert_SSH ( struct _DecodeAlert *DecodeAlert, unsigned char type );
void MySQL_Insert_Metadata ( struct _DecodeAlert *DecodeAlert );
void MySQL_Insert_SMTP ( struct _DecodeAlert *DecodeAlert );
void MySQL_Insert_Email ( struct _DecodeAlert *DecodeAlert );
void MySQL_Escape_String( char *sql, char *str, size_t size );
void MySQL_Record_Last_CID ( void );
void MySQL_Connect( void );
int MySQL_Get_Class_ID ( struct _DecodeAlert *DecodeAlert );
int MySQL_Get_Signature_ID ( struct _DecodeAlert *DecodeAlert, int class_id );
void MySQL_Insert_Event ( struct _DecodeAlert *DecodeAlert, int signature_id );
uint64_t MySQL_Get_Last_CID( void );
uint32_t MySQL_Get_Sensor_ID( void );
void MySQL_Insert_Header ( struct _DecodeAlert *DecodeAlert );
int MySQL_Legacy_Reference_Handler ( struct _DecodeAlert *DecodeAlert );
int MySQL_Get_Sig_ID( struct _DecodeAlert *DecodeAlert );
