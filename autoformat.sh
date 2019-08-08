#!/bin/sh
clang-format -style=file --assume-filename=C -i src/*.h src/*.c  test/*.c
black -q test/*.py protocols/*.py
