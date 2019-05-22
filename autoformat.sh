#!/bin/sh
clang-format -style=file --assume-filename=C -i waypipe.c server.c client.c util.h util.c parsing.c
