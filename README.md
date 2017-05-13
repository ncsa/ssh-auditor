# SSH Auditor

## Usage

### Build

    $ go build

### Build a static binary including sqlite

    $ make static

### Ensure you can use enough file descriptors

    $ ulimit -n 4096

### Create initial database and discover ssh servers

    $ ./ssh-auditor discover -p 22 -p 2222 192.168.1.0/24 10.0.0.1/24

### Add credential pairs to check

    $ ./ssh-auditor addcredential root root
    $ ./ssh-auditor addcredential admin admin
    $ ./ssh-auditor addcredential guest guest --scan-interval 1 #check this once per day

### Try credentials against discovered hosts in a batch of 5000

    $ ./ssh-auditor scan

### Output a report on what credentials worked

    $ sqlite3 -header -column ssh_db.sqlite "select * from host_creds where result != ''"

### RE-Check credentials that worked

    $ ./ssh-auditor rescan

### Output a report on duplicate key usage

    $ ./ssh-auditor dupes

## Features

* SSH auditor will automatically re-check existing hosts as new credentials are added.  It will only try logging in with the new credentials.
* SSH auditor will do a full credential scan on any new host discovered.
* SSH auditor will do a full credential scan on any host whose ssh version or key fingerprint changes.
* SSH auditor will check if it can authenticate and run a command.
* SSH auditor will ALSO check to see if it can authenticate and tunnel a TCP connection.  Many appliances screw this up.
* SSH auditor will re-check each credential using a per credential scan_interval - default 14 days.


It's designed so that you can run `discover` from cron every hour, and `scan`
every few minutes to perform a constant audit.

## TODO

 - [x] update the 'host changes' table
 - [x] handle false positives from devices that don't use ssh password authentication but instead use the shell to do it.
 - [x] variable re-check times - each credential has a scan_interval in days
 - [x] better support non-standard ports - discover is the only thing that needs to be updated, the rest doesn't care.
 - [ ] possibly daemonize and add an api that bro could hook into to kick off a discover as soon as a new SSH server is detected.
 - [ ] make the store pluggable (mysql, postgresql).
 - [x] differentiate between a failed password attempt and a failed connection or timeout.  Mostly done.  Things like fail2ban complicate this.
 - [ ] add go implementations for the report sqlite3 command.

### Report query.

This seems to be the best report query:

    select
            hc.hostport, hc.user, hc.password, hc.result, hc.last_tested, h.version
     from
            host_creds hc, hosts h
     where
            h.hostport = hc.hostport
     and    result!='' order by last_tested asc
