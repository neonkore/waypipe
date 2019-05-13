# todo, replace with meson

way_libs := $(shell pkg-config --libs wayland-client wayland-server)
way_cflags := $(shell pkg-config --cflags wayland-client wayland-server)

all: waypipe

waypipe: waypipe.c server.c client.c util.c util.h Makefile
	gcc -std=c11 -ggdb3 $(way_libs) $(way_cflags) -o waypipe waypipe.c server.c client.c util.h util.c

clean:
	rm -f waypipe

.phony: all clean
