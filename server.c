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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#include <wayland-server-core.h>

int run_server(const char *socket_path, int app_argc, char *const app_argv[])
{
	fprintf(stderr, "I'm a server on %s!\n", socket_path);
	fprintf(stderr, "Trying to run %d:", app_argc);
	for (int i = 0; i < app_argc; i++) {
		fprintf(stderr, " %s", app_argv[i]);
	}
	fprintf(stderr, "\n");

	struct wl_display *display = wl_display_create();
	// create another socketpair; one goes to display; one goes to child
	int csockpair[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, csockpair);
	if (wl_display_add_socket_fd(display, csockpair[0]) == -1) {
		fprintf(stderr, "Failed to add socket to display object\n");
		wl_display_destroy(display);
		return EXIT_FAILURE;
	}

	pid_t pid = fork();
	if (pid == -1) {
		fprintf(stderr, "Fork failed\n");
		wl_display_destroy(display);
		return EXIT_FAILURE;
	} else if (pid == 0) {
		char bufs2[16];
		sprintf(bufs2, "%d", csockpair[1]);

		// Provide the other socket in the pair to child application
		unsetenv("WAYLAND_DISPLAY");
		setenv("WAYLAND_SOCKET", bufs2, 0);

		execv(app_argv[0], app_argv);
		fprintf(stderr, "Failed to execv: %s\n", strerror(errno));
		return EXIT_FAILURE;
	}
	int status;

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

	// todo: scope manipulation, to ensure all cleanups are done
	waitpid(pid, &status, 0);
	fprintf(stderr, "Program ended\n");
	return EXIT_SUCCESS;
}
