Database/File Configuration & Rights
=====================================

Directories and rights
----------------------

Meer keeps track of its actions in the ``meer.log`` and its position in the Sagan or Suricata EVE output file
through a "waldo" file.  This means that Meer will need an area to record data to.  The default location of these
files are in the ``/var/log/meer`` directory.  You will need to create and assign this directory the proper rights.  

Making directories & assigning rights::

    sudo mkdir /var/log/meer
    sudo chown suricata /var/log/meer # Chown to 'sagan' if using with Sagan!

You will need to adjust your ``meer.yaml`` rights in the ``runas`` option to match your permissions.

Setting up a new database.
--------------------------

If you do not have a database already configured to receive alerts,  the instructions below will help
you get started.  First, you will need to create a database.   For the purpose of this document
the target database will be known as ``example_database``.  Database schemas are stored in the ``meer/sql`` directory.

Creating the ``example_database`` with MySQL/MariaDB::

    mysqladmin -u root -p create example_database
    mysql -u root -p example_database < sql/create_mysql

When using PostgreSQL, use the ``meer/sql/create_postgresql`` schema file.
    
Using a old database
--------------------

If you have a legacy database that you wish to convert, do the following with MySQL/MariaDB::

    mysql -u root -p example_database < sql/extend_mysql

This will create new tables (https, flows, dns, etc).


Setting database rights
-----------------------

It is important to setup the proper rights when using Meer.  Meer needs only INSERT and SELECT on all tables.  
It will need INSERT, SELECT and UPDATE on the ``example_database.sensor`` table.

With MySQL/MariaDB::

    GRANT INSERT,SELECT ON example_database.* to myusername@127.0.0.1 identified by 'mypassword`;
    GRANT INSERT,SELECT,UPDATE,INSERT ON example_database.sensor to myusername@127.0.0.1 identified by 'mypassword';



Meer 'core' configuration:
==========================

Meers operations are mainly controlled by the ``meer.yaml`` file.  The configuration file is split into two sections.  The ``meer-core`` controls how Meer processes incoming data from EVE files.  The ``output-plugins`` controls how data extracted from the EVE files is transported to a database back end.

'meer-core' example
-------------------

::

  meer-core:

     core:

       hostname: "mysensor"  # Unique name for this sensor (no spaces)
       interface: "eth0"     # Can be anything.  Sagan "syslog", suricata "eth0".

       runas: "suricata"     # User to "drop privileges" too.
       #runas: "sagan"

       classification: "/etc/suricata/classification.config"
       #classification: "/usr/local/etc/sagan-rules/classification.config"

       meer_log: "/var/log/meer/meer.log"   # Meer log file

       # Meer can decode various types of data from within an "alert".  This
       # section enabled/disabled various JSON decoders.

       metadata: enabled
       flow: enabled
       http: enabled
       tls: enabled
       ssh: enabled
       smtp: enabled
       email: enabled
       json: enabled       # Orignal JSON from event

       # If "dns" is enabled, Meer will do reverse DNS (PTR) lookups of an IP.
       # The "dns_cache" is the amount of time Meer should "cache" a PTR record
       # for.  The DNS cache prevents Meer from doing repeated lookups of an
       # already looked up PTR record.  This reduces overloading DNS servers.

       dns: enabled
       dns_cache: 900      # Time in seconds.


       # "health" checks are a set of signatures that are triggered every so 
       # often to ensure a sensor is up and operational.  When these events
       # are triggered,  they are not stored into the database as normal alert
       # data.  For example,  with MySQL/MariaDB output enabled, they update the 
       # "sensor.health" table with the current epoch time.  Think of these
       # events like a "ping" for your sensor.  This can be useful for detecting
       # when Meer, Suricata or Sagan have "died" unexpectedly.

       health: enabled
       health_signatures: 20000001,20000002,20000003,20000004

       waldo_file: "/var/log/meer/meer.waldo"      # Where to store the last 
                                                   # position in the 
                                                   # "follow-eve" file. 

       lock_file: "/var/log/meer/meer.lck"         # To prevent dueling processes.

       follow_eve: "/var/log/suricata/alert.json"  # The Suricata/Sagan file to monitor
       #follow_eve: "/var/log/sagan/alert.json


'meer-core' options
-------------------

Below describes the option in the `meer-core` section of the ``meer.yaml``.

hostname
~~~~~~~~

This is stored in the database in the ``sensor`` table under the ``hostname`` column. 
 The ``interface`` is appended to the ``hostname``.  This option is required.

interface
~~~~~~~~~

The ``interface`` is stored in the ``sensor`` table appended to the ``hostname`` and 
``interface`` columns.  This describes what interface the data was collected.  This can 
be any descriptive string.  For example, "eth0", "syslog", etc.   This option is required.

runas
~~~~~

This is the user name the Meer process should "drop privileges" to.  You will likely 
want to run Meer as the same user name that is collecting information.  For example, 
"sagan" or "suricata".  The ``runas`` can protect your system from security flaws in
Meer.  **Do not run as "root"**.  This option is required.

classification
~~~~~~~~~~~~~~

The ``classification`` option tells Meer where to find classification types.  This file
typically ships with Sagan, Suricata and Snort rules.  It defines a 'classtype' (for 
example, "attempt-recon") and assigns a numeric priority to the event.  This option is
required.

meer_log
~~~~~~~~

The ``meer_log`` is the location of the file for Meer to record errors and statistics 
to.  The file will need to be writable by the same user specified in the ``runas`` 
option.

metadata
~~~~~~~~

The ``metadata`` option tells Meer to decode "metadata" from Suricata or Sagan.  If 
the "metadata" is present in the alert,  Meer will decode it and store its contents
in memory for later use.

flow
~~~~

The ``flow`` option tells Meer to decode "flow" data from Suricata or Sagan.  If
the "flow" JSON is present in the alert,  Meer will decode it and store its contents
in memory for later use.

http
~~~~

The ``http`` option tells Meer to decode "http" data from Suricata or Sagan.  If
the "http" JSON is present in the alert,  Meer will decode it and store its contents
in memory for later use.


tls
~~~

The ``tls`` option tells Meer to decode "tls" data from Suricata or Sagan.  If
the "tls" JSON is present in the alert,  Meer will decode it and store its contents
in memory for later use.
ssh
~~~

The ``ssh`` option tells Meer to decode "ssh" data from Suricata or Sagan.  If
the "ssh" JSON is present in the alert,  Meer will decode it and store its contents
in memory for later use.

smtp
~~~~

The ``smtp`` option tells Meer to decode "smtp" data from Suricata or Sagan.  If
the "smtp" JSON is present in the alert,  Meer will decode it and store its contents
in memory for later use.

email
~~~~~

The ``email`` option tells Meer to decode "email" data from Suricata or Sagan.  If
the "email" JSON is present in the alert,  Meer will decode it and store its contents
in memory for later use.  This is not to be confused with ``smtp``.  The data from
``email`` will contain information like e-mail file attachments, carbon copies, etc.

json
~~~~

The ``json`` option tells Meer to store the orignal JSON/EVE event.  This is the 
raw event that Meer has read in.

dns
~~~

The ``dns`` option tells Meer to perform a DNS PTR (reverse) record lookup of the 
IP addresses involved in an alert.  This option is useful because records the
DNS record at the time the event occured. 

dns_cache
~~~~~~~~~

When ``dns`` is enabled,  Meer will internally cache records to avoid repetitive
lookups.  For example, if a 1000 alerts come in from a single IP address,  Meer
will look the DNS PTR record one time and use the cache entire the other 999
times.   This saves on lookup time and extra stress on internal DNS server.  If you
do not want Meer to cache DNS data,  simply set this option to 0.

health
~~~~~~

The ``health`` option is a set of signatures used to monitor the health of Meer and 
your Sagan or Suricata instances.  When enabled,  Meer will treat certain Sagan and
Suricata signatures as "health" indicators rather than normal alerts.   When a 
"health" signature occurs,  Meer updates the ``sensor`` table ``health`` column 
with the epoch time the health signature triggered.  This can be useful in quickly
determining if a sensor is down or behind (back logged) on alerts. 

health_signatures
~~~~~~~~~~~~~~~~~

When ``health`` is enabled,  this option supplies a list of signature IDs (sid) to 
Meer of Suricata or Sagan "health" signatures. 

waldo_file
~~~~~~~~~~

The ``waldo_file`` is a file that Meer uses to keep track of its last location within
a EVE/JSON file.  This keep Meer from re-reading data inbetween stop/starts.  This
option is required.

lock_file
~~~~~~~~~

The ``lock_file`` is used to help avoid multiple Meer processes from processing the
same data.  The lock_file should be unique per Meer instance.   The lock file contains
the process ID (PID) of instance of Meer.  This option is required.

follow_eve
~~~~~~~~~~

The ``follow_eve`` option informs Meer what file to "follow" or "monitor" for new 
alerts.  You'll want to point this to your Sagan or Suricata "alert" EVE output file. 
You can think of Meer "monitoring" this file similar to how "tail -f" operates. 
This option is requried.

Output Plugins
==============

Below is an example of the "output-plugins" from the ``meer.yaml``.

::

   output-plugins:

     # MySQL/MariaDB output - Stores data from Suricata or Sagan into a semi-
     # traditional "Barnyard2/Snort" like database.

     sql:

       enabled: yes
       driver: mysql        # "mysql" or "postgresql"
       port: 3306           # Change to 5432 for PostgreSQL
       debug: no
       server: 127.0.0.1
       port: 3306
       username: "XXXX"
       password: "XXXXXX"
       database: "snort_test"

       # Automatically reconnect to the database when disconnected.

       reconnect: enabled
       reconnect_time: 10

       # Store decoded JSON data that is similar to Unified2 "extra" data to the
       # "extra" table.

       extra_data: enabled

       # Store extra decoded JSON metadata from Suricata or Sagan.  This requires
       # your database to have the metadata, flow, http, etc. tables.  If all are
       # disabled,  Meer will stored data in strictly a Barnyard2/Snort method.
       # If you want to store this decoded information,  and you likely do,  make
       # sure you have the decoders enabled in the "core" section of this Meer
       # configuration file!

       metadata: enabled
       flow: enabled
       http: enabled
       tls: enabled
       ssh: enabled
       smtp: enabled
       email: enabled
       json: enabled

       # If you would like Meer to mimic the legacy "reference" tables from
       # Snort/Barnyard2, enable it here.  If your using more than one database
       # to store Suricata or Sagan data, you'll likely want to leave this
       # disabled. The legacy reference system isn't very efficient and there's
       # better ways to keep track of this data.  This is also a memory hog and
       # performance killer.  See tools/reference_handler/reference_handler.pl to
       # build a centralized reference table.

       reference_system: disabled
       sid_file: "/etc/suricata/rules/sid-msg.map"   # Created with "create-sidmap"
       reference: "/etc/suricata/reference.config"

       #sid_file: "/usr/local/etc/sagan-rules/sagan-sid-msg.map"
       #reference: "/usr/local/etc/sagan-rules/reference.config"


MariaDB/MySQL/PostgreSQL
------------------------

