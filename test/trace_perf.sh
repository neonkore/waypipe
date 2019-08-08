#!/bin/sh

set -x

# This probably requires root to set up the probes, and
# a low sys/kernel/perf_event_paranoid to record them.

# Also, perf record can create huge (>1 GB) files on busy machines,
# so it's recommended to run this on a tmpfs

prog=$(which waypipe)
capture_time=${1:-120}

setup="perf buildid-cache -a `which waypipe` ; perf probe -d sdt_waypipe:* ; perf probe sdt_waypipe:* ;"
sudo -- sh -c "$setup"
sudo perf record -e sdt_waypipe:*,sched:sched_switch -aR sleep $capture_time
sudo chmod 644 perf.data

perf script --ns | gzip -9 >scriptfile.gz
