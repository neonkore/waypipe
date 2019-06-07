#!/bin/sh
set -e

# With bcc 'tplist -l `which waypipe`', can list all probes
# With bcc 'trace', can print events, arguments, and timestamps

sudo /usr/share/bcc/tools/trace -t \
    'u:/home/msto/bin/waypipe:construct_diff_exit "diffsize %d", arg1' \
    'u:/home/msto/bin/waypipe:construct_diff_enter "range %d %d", arg1, arg2' \
    'u:/home/msto/bin/waypipe:apply_diff_enter "size %d diffsize %d", arg1, arg2' \
    'u:/home/msto/bin/waypipe:apply_diff_exit' \
    'u:/home/msto/bin/waypipe:channel_write_end' \
    'u:/home/msto/bin/waypipe:channel_write_start "size %d", arg1'

