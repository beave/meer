
<pre>
@@@@@@@@@@  @@@@@@@@ @@@@@@@@ @@@@@@@    
@@! @@! @@! @@!      @@!      @@!  @@@   Quadrant Information Security
@!! !!@ @!@ @!!!:!   @!!!:!   @!@!!@a    https://quadrantsec.com
!!:     !!: !!:      !!:      !!: :!a    Copyright (C) 2018
:      :   : :: ::  : :: ::   :   : :
</pre>

<i>Note: Meer is consider very beta!</i>

"Meer" (GNU/GPLv2) is a dedicated "spooler" for the Suricata & Sagan EVE output formats.  It 
functions like Banryard2 (https://github.com/firnsy/barnyard2) but rather than reading Snort's 
"unified2" format, Meer reads Suricata (https://suricata-ids.org) and Sagan (https://sagan.io) 
"EVE" JSON output. 

# Meer with MySQL/MariaDB output:

Meer stores to a database similar to Barnyard2 to remain backward compatible.  This means that
it should be functional with software like Snorby, Sguil, BASE, etc. 

While Meer uses a similar database as Barnyard2,  we've extended the tables to collect data that
Barnyard2 does not.  Meer can record metadata information around an alert.  For example,  Meer
can records "flow", "http", "smtp", "tls", "ssh" and other information.  This data can be extremely 
useful to security analysts.

Meer also has support for features that I've done with my own fork of Barnyard2-Extra (https://github.com/beave/barnyard2-extra).  For example,  Meer can do DNS lookups at the time of an alert and 
record that information.  Meer also supports recording XFF headers and "health checks" similar 
to my Barnyard2-extra.  "Health" checks are a method to insure your sensors are up and running. 

Meer is meant to be modular and simple.  We find that the EVE JSON is not only more simple to
work with but usually contains valuable information that unifed2 does not.  This project does 
not aim to replicate all features of Barnyard2.  The idea is to replicate the more useful features
and abandon the "cruft". 

# Future support:

Right now,  MySQL is the only "output" supported.  I would like to add Syslog and Elasticsearch
in the future.  If you have an idea or request,  feel free to make a pull request!  If you're 
not a programmer,  via our issues page and put in a request. 

# Dependancies:

Meer needs libjson-c,  libyaml and libmysqlclient (if you want to write to a MySQL database). 

# Support:

General questions should be sent to the Meer "google groups" at https://groups.google.com/forum/#!forum/meer-users. 

If you have an issue or a but,  please report to the Github "issues" page at https://github.com/beave/meer/issues.



