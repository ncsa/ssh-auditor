# SSH Auditor

## Usage

### Build

    $ go build

### Build a static binary including sqlite

    $ make static

### Ensure you can use enough file descriptors

    $ ulimit -n 4096

### Create initial database and discover ssh servers

    $ ./ssh-auditor discover 192.168.1.0/24

### Add credential pairs to check

    $ sqlite3 ssh_db.sqlite "insert into credentials values ('root', 'root', 1);"
    $ sqlite3 ssh_db.sqlite "insert into credentials values ('admin', 'admin', 1);"

### try credentials against discovered hosts in a batch of 5000

    $ ./ssh-auditor scan

### Output a report on what credentials worked

    $ sqlite3 -header -column ssh_db.sqlite 'select * from host_creds where result=1

### re-check credentials that worked

    $ ./ssh-auditor rescan

### Output a report on duplicate key usage

    $ ./ssh-auditor dupes

## Features

* SSH auditor will automatically re-check existing hosts as new credentials are added.  It will only try logging in with the new credentials.
* SSH auditor will do a full credential scan on any new host discovered.
* SSH auditor will do a full credential scan on any host whose ssh version or key fingerprint changes.

It's designed so that you can run `discover` from cron every hour, and `scan`
every few minutes to perform a constant audit.

## TODO

 - [ ] update the 'host changes' table
 - [ ] handle false positives from devices that don't use ssh password authentication but instead use the shell to do it.
 - [ ] variable re-check times - right now it's hardcoded as a full re-scan every 14 days.
 - [ ] better support non-standard ports - discover is the only thing that needs to be updated, the rest doesn't care.
 - [ ] possibly daemonize and add an api that bro could hook into to kick off a discover as soon as a new server is detected.
 - [ ] make the store pluggable (mysql, postgresql).
 - [ ] add go implementations for the above sqlite3 commands.
