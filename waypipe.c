/*
 * Copyright © 2019 Manuel Stoeckl
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice (including the
 * next paragraph) shall be included in all copies or substantial
 * portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#define _POSIX_C_SOURCE 200112L

#include <getopt.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>

static int run_client(const char *socket_path)
{
	struct sockaddr_un saddr;
	int fd;

	if (strlen(socket_path) >= sizeof(saddr.sun_path)) {
		fprintf(stderr, "Socket path is too long and would be truncated: %s\n",
				socket_path);
		return EXIT_FAILURE;
	}

	saddr.sun_family = AF_UNIX;
	strncpy(saddr.sun_path, socket_path, sizeof(saddr.sun_path) - 1);
	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd == -1) {
		fprintf(stderr, "Error creating socket: %s\n", strerror(errno));
		return EXIT_FAILURE;
	}
	if (bind(fd, (struct sockaddr *)&saddr, sizeof(saddr)) == -1) {
		fprintf(stderr, "Error binding socket: %s\n", strerror(errno));
		close(fd);
		return EXIT_FAILURE;
	}

	if (listen(fd, 1) == -1) {
		fprintf(stderr, "Error listening to socket: %s\n",
				strerror(errno));
		close(fd);
		unlink(socket_path);
		return EXIT_FAILURE;
	}

	fprintf(stderr, "I'm a client on %s!\n", socket_path);
	for (int i = 0; i < 1; i++) {
		// Q: multiple parallel client support?

		int client = accept(fd, NULL, NULL);
		if (client == -1) {
			fprintf(stderr, "Skipping connection\n");
			continue;
		}

		int bufsize = 4096;
		char *buf = calloc(bufsize + 1, 1);
		while (1) {
			int nb = read(client, buf, bufsize);
			if (nb <= 0) {
				fprintf(stderr, "Read failed, stopping\n");
				break;
			} else {
				fprintf(stderr, "Read with %d bytes of data |%s|\n",
						nb, buf);
			}
		}
		fprintf(stderr, "...\n");
	}

	close(fd);
	unlink(socket_path);

	return EXIT_SUCCESS;
}

static int run_server(
		const char *socket_path, int app_argc, const char **app_argv)
{
	fprintf(stderr, "I'm a server on %s!\n", socket_path);
	fprintf(stderr, "Trying to run %d:", app_argc);
	for (int i = 0; i < app_argc; i++) {
		fprintf(stderr, " %s", app_argv[i]);
	}
	fprintf(stderr, "\n");

	unsetenv("WAYLAND_DISPLAY");
	setenv("WAYLAND_SOCKET", "xyzzy", 0);
	pid_t pid = fork();
	if (!pid) {
		fprintf(stderr, "EEK\n");
		execv(app_argv[0], app_argv + 1);
		exit(EXIT_SUCCESS);
	}
	wait(pid);
	fprintf(stderr, "Program ended\n");

	struct sockaddr_un saddr;
	int fd;

	if (strlen(socket_path) >= sizeof(saddr.sun_path)) {
		fprintf(stderr, "Socket path is too long and would be truncated: %s\n",
				socket_path);
		return EXIT_FAILURE;
	}

	saddr.sun_family = AF_UNIX;
	strncpy(saddr.sun_path, socket_path, sizeof(saddr.sun_path) - 1);
	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd == -1) {
		fprintf(stderr, "Error creating socket: %s\n", strerror(errno));
		return EXIT_FAILURE;
	}
	if (connect(fd, (struct sockaddr *)&saddr, sizeof(saddr)) == -1) {
		fprintf(stderr, "Error connecting socket: %s\n",
				strerror(errno));
		close(fd);
		return EXIT_FAILURE;
	}

	for (int i = 0; i < 10; i++) {
		sleep(1);
		char msg[256];
		sprintf(msg, "Message #%d", i);
		write(fd, msg, strlen(msg) + 1);
	}
	close(fd);

	return EXIT_SUCCESS;
}

static int usage(int retcode)
{
	FILE *ostream = retcode == EXIT_SUCCESS ? stderr : stdout;
	fprintf(ostream, "usage: waypipe [OPTION] [client|server] "
			 "socket_path "
			 "[-- application ...]\n\n");
	fprintf(ostream,
			"A proxy for wayland applications. Run as client on the side with the\n"
			"wayland compositor, run as server on the side with the wayland client\n"
			"and link the sockets with ssh or some other transport.\n\n");
	fprintf(ostream, "options:\n");
	fprintf(stderr, "    -h,  --help                  Display this help and exit.\n");
	fprintf(stderr, "    -v,  --version               Print waypipe version.\n");
	return retcode;
}

static const int default_server_argc = 1;
static const char *default_server_argv[] = {"/bin/sh", NULL};
int main(int argc, char **argv)
{
	bool help = false;
	bool version = false;
	bool fail = false;
	bool is_client;
	const char *socketpath;
	int opt;
	static const struct option options[] = {
			{"help", no_argument, NULL, 'h'},
			{"version", no_argument, NULL, 'v'}, {0, 0, NULL, 0}};

	while (1) {
		opt = getopt_long(argc, argv, "hvcs", options, NULL);

		if (opt == -1)
			break;

		switch (opt) {
		case 'h':
			help = true;
			break;
		case 'v':
			version = true;
			break;
		default:
			fail = true;
			break;
		}
	}

	argv += optind;
	argc -= optind;

	if (fail || argc < 2) {
		return usage(EXIT_FAILURE);
	} else if (help) {
		return usage(EXIT_SUCCESS);
	} else if (version) {
		fprintf(stdout, "waypipe unversioned\n");
		return EXIT_SUCCESS;
	} else if (!strcmp(argv[0], "client")) {
		is_client = true;
	} else if (!strcmp(argv[0], "server")) {
		is_client = false;
	} else {
		return usage(EXIT_FAILURE);
	}
	socketpath = argv[1];
	if (is_client && argc > 2) {
		// In client mode, we do not start an application
		return usage(EXIT_FAILURE);
	}
	argv += 2;
	argc -= 2;
	if (argc > 0 && !strcmp(argv[0], "--")) {
		argv++;
		argc--;
	}
	if (is_client) {
		return run_client(socketpath);
	} else {
		const char **app_argv = (const char **)argv;
		int app_argc = argc;
		if (argc == 0) {
			app_argc = default_server_argc;
			app_argv = default_server_argv;
		}
		return run_server(socketpath, app_argc, app_argv);
	}
}
