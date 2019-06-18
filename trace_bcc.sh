#!/bin/sh
set -e

# With bcc 'tplist -l `which waypipe`', can list all probes
# With bcc 'trace', can print events, arguments, and timestamps

sudo /usr/share/bcc/tools/trace -t \
    'u:/usr/bin/waypipe:construct_diff_exit "diffsize %d", arg1' \
    'u:/usr/bin/waypipe:construct_diff_enter "rects %d", arg1' \
    'u:/usr/bin/waypipe:apply_diff_enter "size %d diffsize %d", arg1, arg2' \
    'u:/usr/bin/waypipe:apply_diff_exit' \
    'u:/usr/bin/waypipe:channel_write_end' \
    'u:/usr/bin/waypipe:channel_write_start "size %d", arg1' \
    'u:/usr/bin/waypipe:worker_comp_enter "index %d", arg1' \
    'u:/usr/bin/waypipe:worker_comp_exit "index %d", arg1' \
    'u:/usr/bin/waypipe:worker_compdiff_enter "index %d", arg1' \
    'u:/usr/bin/waypipe:worker_compdiff_exit "index %d", arg1'
