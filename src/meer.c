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

/* Main Meer function */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <stdlib.h>

#include "meer.h"
#include "meer-def.h"

#include "lockfile.h"
#include "util.h"


struct _MeerConfig *MeerConfig;
struct _MeerOutput *MeerOutput;

// signal
// open waldo / write waldo

int main (int argc, char *argv[])
{

    char *yaml_file = DEFAULT_CONFIG;

    /* The only command line option is to specify a non-default configuration
       file */

    if ( argc > 2 )
        {
            fprintf(stderr, "Too many arguments.  Only one YAML file can be specified.\n");
            exit(-1);
        }

    if ( argc == 2 )
        {
            yaml_file = argv[1];
        }

    Load_YAML_Config(yaml_file);

    Drop_Priv();

    CheckLockFile();


}
