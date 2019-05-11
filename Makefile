# todo, replace with meson

all: waypipe

waypipe: waypipe.c Makefile
	gcc -ggdb3 -o waypipe waypipe.c

clean:
	rm -f waypipe

.phony: all clean
