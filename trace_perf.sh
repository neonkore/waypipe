#!/bin/sh

prog=`which waypipe`
perf buildid-cache -a $prog
perf probe sdt_waypipe:*
perf record -e sdt_waypipe:* -aR sleep 10
perf script > scriptfile
chmod 644 scriptfile
