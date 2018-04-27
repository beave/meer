
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

<b>The longer explanation: </b> “Meer” is a dedicated “spooler” for the Suricata IDS/IPS and Sagan log analysis engines.  This means that as Suricata or Sagan write alerts out to a file,  Meer can ‘follow’ that file and store the alert information into a database.  You can think of the “spool” file as a 'queuing' system for alerts from Suricata or Sagan.   Using a “spooling” system ensures the delivery of alerts to a back end database.  This task was traditionally accomplished by using a file format called "unified2" which was developed by the SourceFire/Snort team and a program called Barnyard2.  While unified2 has been useful,  its binary nature makes it difficult to work with and has not been extended in quite sometime.  Meer uses Suricata and Sagan's "EVE" output formats instead of unified2.  EVE is a text file that contains JSON which makes it more easy to work with.  The EVE output also contains valuable information that does not exist in unified2.

Meer is meant to be modular and simple. This project does not aim to replicate all features of Barnyard2.  The idea is to replicate the more useful features and abandon the "cruft".

# Output Plugins:

* MySQL/Maria DB output - This output plugin stores data to a database similar to Snort/Barnyard2.  This makes is backward compatible with Snorby,  Sguil, BASE, etc. The database schema has been extended to record other alert metadata like ‘flow’, ‘http’, ‘smtp’, ‘tls’, ‘ssh’ and other information.  This extra data can be extremely useful for security analysts.   This output plug in supports features I’ve done in my fork of Barnyard2 known as Barnyard2-Extra (https://github.com/beave/barnyard2-extra). For example; reverse DNS/PTR lookups,  “health” checks and “extra data” (for example XFF HTTP headers).   Meer uses internal SQL “caching” to make it more efficient when interacting with databases. 

# Current Features:


* Meer is written in C and has a very small memory footprint (only several meg of RAM).  It also CPU efficient. 
* Fast startup times (under one second).  
* Simple command line and configuration syntax.  Meer uses a YAML configurations similar to Suricata and Sagan. 
* Out of the box IPv6 support. 
* Meer can do reverse DNS/PTR record lookups.   Meer has an internal DNS cache system so to not overburden DNS servers with repeated queries. 
* MySQL/MariaDB output is backward compatible with legacy Snort/Barnyard2 database.
* MySQL/MariaDB internal SQL “caching” makes Meer interactions with databases more efficients. 

# Future "output" support: 

Meer is under development.  This is our brief "roadmap" of what we would like to see Meer do.  If
you have any ideas or requests,  please let us know via our "issues" page (https://github.com/beave/meer/issues).

* Syslog support (JSON, decoded, etc). 
* Elasticsearch
* Snortsam (??)
* Generic MySQL/MariaDB template driven writer (for building block lists, etc)
* Unified2 <b> ** THIS IS A JOKE. ** </b>

