#!/bin/sh

root=`pwd`

# program=`which bash`
program=`which weston-flower`

($root/waypipe client /tmp/socket-client 2>&1 | sed 's/.*/\x1b[33m&\x1b[0m/') &
# ssh-to-self; should have a local keypair set up
(ssh -R/tmp/socket-server:/tmp/socket-client localhost $root/waypipe server /tmp/socket-server -- $program) 2>&1 | sed 's/.*/\x1b[34m&\x1b[0m/'
kill %1
rm -f /tmp/socket-client
rm -f /tmp/socket-server
