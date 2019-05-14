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

	wp_log(WP_DEBUG, "I'm a client on %s!\n", socket_path);
	// Q: multiple parallel remote client support? then multiplex
	// over all accepted clients?

	// TODO: fork the client on each acceptance, and have each forked
	// version connect separately to the Wayland server. (At the very least,
	// this will be necessary to ensure distinct pids for each client)
	int chanclient = accept(channelsock, NULL, NULL);
	if (chanclient == -1) {
		wp_log(WP_DEBUG, "First connection failed\n");
		return EXIT_FAILURE;
	}

	struct fd_translation_map fdtransmap = {
			.local_sign = 1, .list = NULL, .max_local_id = 1};

	const int maxmsg = 4096;
	char *buffer = calloc(1, maxmsg + 1);
	while (1) {
		// pselect multiple.
		fd_set readfds;
		FD_ZERO(&readfds);
		FD_SET(chanclient, &readfds);
		FD_SET(displayfd, &readfds);
		struct timespec timeout = {.tv_sec = 0, .tv_nsec = 700000000L};
		int maxfd = chanclient > displayfd ? chanclient : displayfd;
		int r = pselect(maxfd + 1, &readfds, NULL, NULL, &timeout,
				NULL);
		if (r == -1) {
			wp_log(WP_ERROR, "Select failed, stopping\n");
			break;
		}
		wp_log(WP_DEBUG, "Post select %d %d %d\n", r,
				FD_ISSET(chanclient, &readfds),
				FD_ISSET(displayfd, &readfds));

		if (FD_ISSET(chanclient, &readfds)) {
			wp_log(WP_DEBUG, "chanclient isset\n");
			char *tmpbuf;
			ssize_t nbytes =
					read_size_then_buf(chanclient, &tmpbuf);
			if (nbytes == 0) {
				wp_log(WP_ERROR,
						"channel read connection closed\n");
				break;
			}
			if (nbytes == -1) {
				wp_log(WP_ERROR, "channel read failure: %s\n",
						strerror(errno));
				break;
			}

			char *waymsg;
			int waylen;
			int nids;
			int ids[28];
			int ntransfers;
			struct transfer transfers[50];
			unpack_pipe_message((size_t)nbytes, tmpbuf, &waylen,
					&waymsg, &nids, ids, &ntransfers,
					transfers);

			apply_updates(&fdtransmap, ntransfers, transfers);

			int fds[28];
			memset(fds, 0, sizeof(fds));
			untranslate_ids(&fdtransmap, nids, ids, fds);

			wp_log(WP_DEBUG, "Read from conn %d = %d bytes\n",
					nbytes, nbytes);
			int wc = iovec_write(
					displayfd, waymsg, waylen, fds, nids);
			free(tmpbuf);
			if (wc == -1) {
				wp_log(WP_ERROR, "FD Write  failure %d: %s\n",
						wc, strerror(errno));
				break;
			}
			wp_log(WP_DEBUG, "client done\n");
		}
		if (FD_ISSET(displayfd, &readfds)) {
			wp_log(WP_DEBUG, "displayfd isset\n");
			int fdbuf[28];
			int nfds = 28;

			int rc = iovec_read(displayfd, buffer, maxmsg, fdbuf,
					&nfds);
			if (rc == -1) {
				wp_log(WP_ERROR, "CS Read failure %ld: %s\n",
						rc, strerror(errno));
				break;
			}
			if (rc > 0) {
				int ids[28];
				translate_fds(&fdtransmap, nfds, fdbuf, ids);
				int ntransfers;
				struct transfer transfers[50];
				collect_updates(&fdtransmap, &ntransfers,
						transfers);

				char *msg = NULL;
				size_t msglen;
				pack_pipe_message(&msglen, &msg, rc, buffer,
						nfds, ids, ntransfers,
						transfers);
				wp_log(WP_DEBUG,
						"Packed message size (%d fds): %ld\n",
						nfds, msglen);

				if (write(chanclient, msg, msglen) == -1) {
					free(msg);
					wp_log(WP_ERROR,
							"CC msg write failure: %s\n",
							strerror(errno));
					break;
				}
				free(msg);
			} else {
				wp_log(WP_DEBUG, "the display shut down\n");
				break;
			}
		}
	}

	cleanup_translation_map(&fdtransmap);

	free(buffer);
	close(chanclient);
	wp_log(WP_DEBUG, "...\n");

	wp_log(WP_DEBUG, "Closing client\n");
	close(displayfd);
	close(channelsock);
	unlink(socket_path);

	wl_display_disconnect(display);

	return EXIT_SUCCESS;
}
