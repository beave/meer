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

/* Display statistics */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>

#include "meer.h"
#include "meer-def.h"
#include "stats.h"


struct _MeerCounters *MeerCounters;
struct _MeerWaldo *MeerWaldo;
struct _MeerConfig *MeerConfig;

void Statistics( void )
{

    Meer_Log(NORMAL, "");
    Meer_Log(NORMAL, "--[ Meer Statistics ]---------------------------------------");
    Meer_Log(NORMAL, "");
    Meer_Log(NORMAL, " - Decoded Statistics:");
    Meer_Log(NORMAL, "");
    Meer_Log(NORMAL, " Waldo Postion : %"PRIu64 "", MeerWaldo->position);
    Meer_Log(NORMAL, " Flow          : %" PRIu64 "", MeerCounters->FlowCount);
    Meer_Log(NORMAL, " HTTP          : %" PRIu64 "", MeerCounters->HTTPCount);
    Meer_Log(NORMAL, " TLS           : %" PRIu64 "", MeerCounters->TLSCount);
    Meer_Log(NORMAL, " SSH           : %" PRIu64 "", MeerCounters->SSHCount);
    Meer_Log(NORMAL, " SMTP          : %" PRIu64 "", MeerCounters->SMTPCount);
    Meer_Log(NORMAL, " Email         : %" PRIu64 "", MeerCounters->EmailCount);
    Meer_Log(NORMAL, " Metadata      : %" PRIu64 "", MeerCounters->MetadataCount);
    Meer_Log(NORMAL, "");

    if ( MeerConfig->dns == true )
        {

            Meer_Log(NORMAL, " - DNS Statistics:");
            Meer_Log(NORMAL, "");
            Meer_Log(NORMAL, " DNS Lookups   : %"PRIu64 "", MeerCounters->DNSCount);
            Meer_Log(NORMAL, " DNS Cache Hits: %"PRIu64 "", MeerCounters->DNSCacheCount);
            Meer_Log(NORMAL, "");

        }

#ifdef HAVE_LIBMYSQLCLIENT

    Meer_Log(NORMAL, " - MySQL/MariaDB Statistics:");
    Meer_Log(NORMAL, "");
    Meer_Log(NORMAL, " Health Checks          : %"PRIu64 "", MeerCounters->HealthCountT);
    Meer_Log(NORMAL, " INSERT                 : %"PRIu64 "", MeerCounters->INSERTCount);
    Meer_Log(NORMAL, " SELECT                 : %"PRIu64 "", MeerCounters->SELECTCount);
    Meer_Log(NORMAL, " UPDATE                 : %"PRIu64 "", MeerCounters->UPDATECount);
    Meer_Log(NORMAL, " Class Cache Misses     : %"PRIu64 "", MeerCounters->ClassCacheMissCount);
    Meer_Log(NORMAL, " Class Cache Hits       : %"PRIu64 "", MeerCounters->ClassCacheHitCount);
    Meer_Log(NORMAL, " Signature Cache Misses : %"PRIu64 "", MeerCounters->ClassCacheMissCount);
    Meer_Log(NORMAL, " Signature Cache Hits   : %"PRIu64 "", MeerCounters->ClassCacheHitCount);

    Meer_Log(NORMAL, "");

#endif




}
