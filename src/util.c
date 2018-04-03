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

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>
#include <stdarg.h>


#include "meer.h"
#include "meer-def.h"

struct _MeerConfig *MeerConfig;

void Drop_Priv(void)
{

    struct passwd *pw = NULL;
    int ret;

    pw = getpwnam(MeerConfig->runas);

    if (!pw)
        {
            Meer_Log(M_ERROR, "Couldn't locate user '%s'. Aborting...\n", MeerConfig->runas);
        }

    if ( getuid() == 0 )
        {
            Meer_Log(M_NORMAL, "[*] Dropping privileges! [UID: %lu GID: %lu]\n", (unsigned long)pw->pw_uid, (unsigned long)pw->pw_gid);

            if (initgroups(pw->pw_name, pw->pw_gid) != 0 ||
                    setgid(pw->pw_gid) != 0 || setuid(pw->pw_uid) != 0)
                {
                    Meer_Log(M_ERROR, "[%s, line %d] Could not drop privileges to uid: %lu gid: %lu - %s!", __FILE__, __LINE__, (unsigned long)pw->pw_uid, (unsigned long)pw->pw_gid, strerror(errno));
                }

        }
    else
        {
            Meer_Log(M_NORMAL,"Not dropping privileges.  Already running as a non-privileged user");
        }
}


void Meer_Log (int type, const char *format,... )
{

    char buf[5128] = { 0 };
    va_list ap;

    va_start(ap, format);

    char *chr="*";
    char curtime[64];
    time_t t;
    struct tm *now;
    t = time(NULL);
    now=localtime(&t);
    strftime(curtime, sizeof(curtime), "%m/%d/%Y %H:%M:%S",  now);

    if ( type == M_ERROR )
        {
            chr="E";
        }

    if ( type == M_WARN )
        {
            chr="W";
        }

    if ( type == M_DEBUG )
        {
            chr="D";
        }

    vsnprintf(buf, sizeof(buf), format, ap);
//    fprintf(config->sagan_log_stream, "[%s] [%s] - %s\n", chr, curtime, buf);
//    fflush(config->sagan_log_stream);

//    if ( config->daemonize == 0 && config->quiet == 0 )
//        {
    printf("[%s] [%s] %s\n", chr, curtime, buf);
//        }

    if ( type == 1 )
        {
            exit(-11);
        }

}


