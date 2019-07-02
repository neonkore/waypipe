#!/bin/sh
clang-format -style=file --assume-filename=C -i \
	util.h \
	waypipe.c server.c handlers.c client.c util.c parsing.c dmabuf.c shadow.c mainloop.c interval.c video.c \
	test/diff_roundtrip.c test/damage_merge.c test/fd_mirror.c test/wire_parse.c
black -q test/headless.py test/startup_failure.py
