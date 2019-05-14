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
		wp_log(WP_ERROR, "Failed to connect to a wayland server.\n");
		return EXIT_FAILURE;
	}
	int displayfd = wl_display_get_fd(display);

	struct sockaddr_un saddr;
	int channelsock;

	if (strlen(socket_path) >= sizeof(saddr.sun_path)) {
		wp_log(WP_ERROR,
				"Socket path is too long and would be truncated: %s\n",
				socket_path);
		return EXIT_FAILURE;
	}

	saddr.sun_family = AF_UNIX;
	strncpy(saddr.sun_path, socket_path, sizeof(saddr.sun_path) - 1);
	channelsock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (channelsock == -1) {
		wp_log(WP_ERROR, "Error creating socket: %s\n",
				strerror(errno));
		return EXIT_FAILURE;
	}
	if (bind(channelsock, (struct sockaddr *)&saddr, sizeof(saddr)) == -1) {
		wp_log(WP_ERROR, "Error binding socket: %s\n", strerror(errno));
		close(channelsock);
		return EXIT_FAILURE;
	}

	if (listen(channelsock, 1) == -1) {
		wp_log(WP_ERROR, "Error listening to socket: %s\n",
				strerror(errno));
		close(channelsock);
		unlink(socket_path);
		return EXIT_FAILURE;
	}

	int maxmsg = 4096;
	char *buffer = calloc(1, maxmsg + 1);

	wp_log(WP_DEBUG, "I'm a client on %s!\n", socket_path);
	for (int i = 0; i < 1; i++) {
		// Q: multiple parallel remote client support? then multiplex
		// over all accepted clients?

		int chanclient = accept(channelsock, NULL, NULL);
		if (chanclient == -1) {
			wp_log(WP_DEBUG, "Skipping connection\n");
			continue;
		}

		int bufsize = 4096;
		char *buf = calloc(bufsize + 1, 1);
		while (1) {
			// pselect multiple.
			fd_set readfds;
			FD_ZERO(&readfds);
			FD_SET(chanclient, &readfds);
			FD_SET(displayfd, &readfds);
			struct timespec timeout = {
					.tv_sec = 0, .tv_nsec = 700000000L};
			int maxfd = chanclient > displayfd ? chanclient
							   : displayfd;
			int r = pselect(maxfd + 1, &readfds, NULL, NULL,
					&timeout, NULL);
			if (r == -1) {
				wp_log(WP_ERROR, "Select failed, stopping\n");
				break;
			}
			wp_log(WP_DEBUG, "Post select %d %d %d\n", r,
					FD_ISSET(chanclient, &readfds),
					FD_ISSET(displayfd, &readfds));

			if (FD_ISSET(chanclient, &readfds)) {
				wp_log(WP_DEBUG, "client isset\n");
				struct muxheader header;
				if (read(chanclient, &header,
						    sizeof(struct muxheader)) <
						sizeof(struct muxheader)) {
					wp_log(WP_ERROR,
							"FD header read failure: %s\n",
							strerror(errno));
					break;
				}
				char *tmpbuf = calloc(header.length, 1);
				int nread = 0;
				while (nread < header.length) {
					int nr = read(chanclient,
							tmpbuf + nread,
							header.length - nread);
					if (nr <= 0) {
						break;
					}
					nread += nr;
				}
				if (nread < header.length) {
					wp_log(WP_ERROR,
							"FD body read failure %ld/%ld: %s\n",
							nread, header.length,
							strerror(errno));
					break;
				}

				wp_log(WP_DEBUG, "read bytes: %d = %d\n", nread,
						header.length);
				int wc = iovec_write(displayfd, tmpbuf, nread,
						NULL, NULL);
				if (wc == -1) {
					wp_log(WP_ERROR,
							"FD Write  failure %ld: %s\n",
							wc, strerror(errno));
					break;
				}
				free(tmpbuf);
				wp_log(WP_DEBUG, "client done\n");
			}
			if (FD_ISSET(displayfd, &readfds)) {
				wp_log(WP_DEBUG, "displayfd isset\n");
				int fdbuf[28];
				int nfds = 28;
				int rc = iovec_read(displayfd, buffer, maxmsg,
						fdbuf, &nfds);
				if (rc == -1) {
					wp_log(WP_ERROR,
							"CS Read failure %ld: %s\n",
							rc, strerror(errno));
					break;
				}
				if (rc > 0) {
					if (nfds > 0) {
						for (int i = 0; i < nfds; i++) {
							wp_log(WP_DEBUG,
									"Got FD = %d\n",
									fdbuf[i]);
							identify_fd(fdbuf[i]);
						}
					}

					struct muxheader header = {
							.metadata = 0,
							.length = rc};
					if (write(chanclient, &header,
							    sizeof(header)) ==
							-1) {
						wp_log(WP_ERROR,
								"CS write header failure: %s\n",
								strerror(errno));
						break;
					}
					if (write(chanclient, buffer, rc) ==
							-1) {
						wp_log(WP_ERROR,
								"CS write body failure: %s\n",
								strerror(errno));
						break;
					}
				} else {
					wp_log(WP_DEBUG,
							"the display shut down\n");
					break;
				}
			}
		}
		close(chanclient);
		wp_log(WP_DEBUG, "...\n");
	}

	wp_log(WP_DEBUG, "Closing client\n");
	close(displayfd);
	close(channelsock);
	unlink(socket_path);

	return EXIT_SUCCESS;
}
