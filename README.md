[![Build Status](https://travis-ci.org/ncsa/ssh-auditor.svg?branch=master)](https://travis-ci.org/ncsa/ssh-auditor)

# SSH Auditor


## Features

ssh-auditor will automatically:

* Re-check all known hosts as new credentials are added.  It will only check the new credentials.
* Queue a full credential scan on any new host discovered.
* Queue a full credential scan on any known host whose ssh version or key fingerprint changes.
* Attempt command execution as well as attempt to tunnel a TCP connection.
* Re-check each credential using a per credential `scan_interval` - default 14 days.


It's designed so that you can run `ssh-auditor discover` + `ssh-auditor scan`
from cron every hour to to perform a constant audit.

## Demos

# Earlier demo showing all of the features
[![demo](https://asciinema.org/a/5rb3wv8oyoqzd80jfl03grrcv.png)](https://asciinema.org/a/5rb3wv8oyoqzd80jfl03grrcv?autoplay=1)

# Demo showing improved log output

[![demo](https://asciinema.org/a/F3fQYyJcieCS9Kfna6xWferjK.png)](https://asciinema.org/a/F3fQYyJcieCS9Kfna6xWferjK?autoplay=1)


## Usage

### Install

    $ brew install go # or however you want to install the go compiler
    $ go get github.com/ncsa/ssh-auditor

### or Build from a git clone

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

### Try credentials against discovered hosts

    $ ./ssh-auditor scan

### Output a report on what credentials worked

    $ ./ssh-auditor vuln

### RE-Check credentials that worked

    $ ./ssh-auditor rescan

### Output a report on duplicate key usage

    $ ./ssh-auditor dupes

## TODO

 - [x] update the 'host changes' table
 - [x] handle false positives from devices that don't use ssh password authentication but instead use the shell to do it.
 - [x] variable re-check times - each credential has a scan_interval in days
 - [x] better support non-standard ports - discover is the only thing that needs to be updated, the rest doesn't care.
 - [ ] possibly daemonize and add an api that bro could hook into to kick off a discover as soon as a new SSH server is detected.
 - [ ] make the store pluggable (mysql, postgresql).
 - [x] differentiate between a failed password attempt and a failed connection or timeout.  Mostly done.  Things like fail2ban complicate this.
 - [x] add go implementations for the report sqlite3 command.

## Report query.

This query that `ssh-auditor vuln` runs is

    select
            hc.hostport, hc.user, hc.password, hc.result, hc.last_tested, h.version
     from
            host_creds hc, hosts h
     where
            h.hostport = hc.hostport
     and    result!='' order by last_tested asc
