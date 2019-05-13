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

#define _XOPEN_SOURCE 700

#include "util.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#include <wayland-client-core.h>

int run_client(const char *socket_path)
{
	struct wl_display *display = wl_display_connect(NULL);
	if (!display) {
		fprintf(stderr, "Failed to connect to a wayland server.\n");
		return EXIT_FAILURE;
	}
	int displayfd = wl_display_get_fd(display);

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

	int maxmsg = 4096;
	char *buffer = calloc(1, maxmsg + 1);

	fprintf(stderr, "I'm a client on %s!\n", socket_path);
	for (int i = 0; i < 1; i++) {
		// Q: multiple parallel remote client support? then multiplex
		// over all accepted clients?

		int client = accept(fd, NULL, NULL);
		if (client == -1) {
			fprintf(stderr, "Skipping connection\n");
			continue;
		}

		int bufsize = 4096;
		char *buf = calloc(bufsize + 1, 1);
		while (1) {
			// pselect multiple.
			fd_set readfds;
			FD_ZERO(&readfds);
			FD_SET(client, &readfds);
			FD_SET(displayfd, &readfds);
			struct timespec timeout = {
					.tv_sec = 0, .tv_nsec = 700000000L};
			int maxfd = client > displayfd ? client : displayfd;
			int r = pselect(maxfd + 1, &readfds, NULL, NULL,
					&timeout, NULL);
			if (r == -1) {
				fprintf(stderr, "Select failed, stopping\n");
				break;
			}
			fprintf(stderr, "Post select %d %d %d\n", r,
					FD_ISSET(client, &readfds),
					FD_ISSET(displayfd, &readfds));
			if (r == 0) {
				const char *msg = "magic";
				ssize_t nb = write(
						client, msg, strlen(msg) + 1);
				if (nb == -1) {
					fprintf(stderr, "Write failed, retrying anyway\n");
				}

				continue;
			}
			if (FD_ISSET(client, &readfds)) {
				fprintf(stderr, "client isset\n");
				int rc = iovec_read(client, buffer, maxmsg,
						NULL, NULL);
				if (rc == -1) {
					fprintf(stderr, "FD Read failure %ld: %s\n",
							rc, strerror(errno));
					break;
				}
				fprintf(stderr, "read bytes: %d\n", rc);
				if (rc > 0) {
					int wc = iovec_write(displayfd, buffer,
							rc, NULL, NULL);
					if (wc == -1) {
						fprintf(stderr, "FD Write  failure %ld: %s\n",
								wc,
								strerror(errno));
						break;
					}
				} else {
					fprintf(stderr, "the other side shut down\n");
					break;
				}
			}
			if (FD_ISSET(displayfd, &readfds)) {
				fprintf(stderr, "displayfd isset\n");
				int rc = iovec_read(displayfd, buffer, maxmsg,
						NULL, NULL);
				if (rc == -1) {
					fprintf(stderr, "CS Read failure %ld: %s\n",
							rc, strerror(errno));
					break;
				}
				if (rc > 0) {
					int wc = iovec_write(client, buffer, rc,
							NULL, NULL);
					if (wc == -1) {
						fprintf(stderr, "CS Write  failure %ld: %s\n",
								wc,
								strerror(errno));
						break;
					}
				} else {
					fprintf(stderr, "the display shut down\n");
					break;
				}
			}
		}
		fprintf(stderr, "...\n");
	}

	fprintf(stderr, "Closing\n");
	close(displayfd);
	close(fd);
	unlink(socket_path);

	return EXIT_SUCCESS;
}
