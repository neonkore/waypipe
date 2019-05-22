#!/bin/sh

root=`pwd`

waypipe=`which waypipe`

program=`which ${1:-weston-terminal}`

debug=
#debug=-d

# Orange=client, purple=server

($waypipe -o $debug client 2>&1 | sed 's/.*/\x1b[33m&\x1b[0m/') &
# ssh-to-self; should have a local keypair set up
(ssh -R /tmp/waypipe-server.sock:/tmp/waypipe-client.sock localhost $waypipe -o $debug server -- $program) 2>&1 | sed 's/.*/\x1b[35m&\x1b[0m/'
kill %1
rm -f /tmp/waypipe-server.sock
rm -f /tmp/waypipe-client.sock
