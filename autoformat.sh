#!/bin/sh
set -e
black -q test/*.py protocols/*.py
clang-format -style=file --assume-filename=C -i src/*.h src/*.c  test/*.c test/*.h
