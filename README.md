
<pre>
@@@@@@@@@@  @@@@@@@@ @@@@@@@@ @@@@@@@    
@@! @@! @@! @@!      @@!      @@!  @@@   Quadrant Information Security
@!! !!@ @!@ @!!!:!   @!!!:!   @!@!!@a    https://quadrantsec.com
!!:     !!: !!:      !!:      !!: :!a    Copyright (C) 2018
:      :   : :: ::  : :: ::   :   : :
</pre>


# What is “Meer”. 

<i>Note: Meer is consider beta!</i>

<b>The quick explanation: </b> Have you ever worked with Barnyard2?  The idea behind Meer is very similar,  but rather than reading Snort’s “Unified2” files,  Meer reads Suricata and Sagan EVE JSON files. 

<b>The longer explanation: <b> “Meer” is a dedicated “spooler” for the Suricata IDS/IPS and Sagan log analysis engine.  This means that as Suricata or Sagan write alerts out of a file,  Meer can ‘follow’ that file and store alert information in a database.  You can think of the “spool” file as a “queue” system for alerts from Suricata or Sagan.   Using “spooling” system ensures the delivery of alerts to a back end database.  

Meer is meant to be modular and simple.  We find that the EVE JSON is not only more simple to
work with but usually contains valuable information that unified does not.  This project does   
not aim to replicate all features of Barnyard2.  The idea is to replicate the more useful features
and abandon the "cruft".

# Output Plugins:

MySQL/Maria DB output - This output plugin stores data to a database similar to Snort/Barnyard2.  This makes is backward compatible with Snorby,  Sguil, BASE, etc. The database schema has been extended to record other alert metadata like ‘flow’, ‘http’, ‘smtp’, ‘tls’, ‘ssh’ and other information.  This extra data can be extremely useful for security analysts.   This output also supports features I’ve done my port of Barnyard2 (https://github.com/beave/barnyard2-extra) like reverse DNS/PTR lookups,  “health” checks and “extra data” (for example XFF HTTP headers).   Meer uses internal SQL “caching” to make it more efficient when interacting with databases. 


# Current Features:


* Meer is written in C and has a very small memory footprint (only several meg of RAM).  It also CPU efficient. 
* Fast startup times (under one second).  
* Simple command line and configuration syntax.  Uses a YAML configurations similar to Suricata and Sagan. 
* Meer can do reverse DNS/PTR record lookups.   Meer has an internal DNS cache system to not overburden DNS servers with repeated queries. 
* MySQL/MariaDB output is backward compatible with legacy Snort/Barnyard2 database.
* MySQL/MariaDB internal SQL “caching” makes Meer interactions with databases more efficients. 


