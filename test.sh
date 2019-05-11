#!/bin/sh

root=`pwd`

$root/waypipe client /tmp/socket-client &
# ssh-to-self; should have a local keypair set up
ssh -R/tmp/socket-server:/tmp/socket-client localhost $root/waypipe server /tmp/socket-server -- weston-flower
kill %1
rm -f /tmp/socket-client
rm -f /tmp/socket-server
