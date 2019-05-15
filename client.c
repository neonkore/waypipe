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

/*
 * Connect-disconnect cycle, to verify that the client can connect to a display.
 */
static int verify_connection()
{
	struct wl_display *display = wl_display_connect(NULL);
	if (!display) {
		return -1;
	}
	wl_display_disconnect(display);
	return 0;
}

struct pidstack {
	struct pidstack *next;
	pid_t proc;
};

static int run_client_child(int chanfd, const char *socket_path)
{
	wp_log(WP_DEBUG, "I'm a client on %s!\n", socket_path);
	struct wl_display *display = wl_display_connect(NULL);
	if (!display) {
		wp_log(WP_ERROR, "Failed to connect to a wayland server.\n");
		return EXIT_FAILURE;
	}
	int displayfd = wl_display_get_fd(display);

	struct fd_translation_map fdtransmap = {
			.local_sign = 1, .list = NULL, .max_local_id = 1};

	const int maxmsg = 4096;
	char *buffer = calloc(1, maxmsg + 1);
	while (1) {
		// pselect multiple.
		fd_set readfds;
		FD_ZERO(&readfds);
		FD_SET(chanfd, &readfds);
		FD_SET(displayfd, &readfds);
		struct timespec timeout = {.tv_sec = 0, .tv_nsec = 700000000L};
		int maxfd = chanfd > displayfd ? chanfd : displayfd;
		int r = pselect(maxfd + 1, &readfds, NULL, NULL, &timeout,
				NULL);
		if (r == -1) {
			wp_log(WP_ERROR, "Select failed, stopping\n");
			break;
		}
		wp_log(WP_DEBUG, "Post select %d %d %d\n", r,
				FD_ISSET(chanfd, &readfds),
				FD_ISSET(displayfd, &readfds));

		if (FD_ISSET(chanfd, &readfds)) {
			wp_log(WP_DEBUG, "chanclient isset\n");
			char *tmpbuf;
			ssize_t nbytes = read_size_then_buf(chanfd, &tmpbuf);
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

				if (write(chanfd, msg, msglen) == -1) {
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
	close(chanfd);
	wp_log(WP_DEBUG, "...\n");

	wp_log(WP_DEBUG, "Closing client\n");
	close(displayfd);

	wl_display_disconnect(display);

	return EXIT_SUCCESS;
}

int run_client(const char *socket_path)
{
	if (verify_connection() == -1) {
		wp_log(WP_ERROR,
				"Failed to connect to a wayland compositor.\n");
		return EXIT_FAILURE;
	}
	wp_log(WP_DEBUG, "A wayland compositor is available. Proceeding.\n");

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
	channelsock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
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
	if (listen(channelsock, 3) == -1) {
		wp_log(WP_ERROR, "Error listening to socket: %s\n",
				strerror(errno));
		close(channelsock);
		unlink(socket_path);
		return EXIT_FAILURE;
	}

	int retcode = EXIT_SUCCESS;
	while (true) {
		int chanclient = accept(channelsock, NULL, NULL);
		if (chanclient == -1) {
			wp_log(WP_DEBUG,
					"Connection failure -- too many clients\n");
			continue;
		}

		pid_t npid = fork();
		if (npid == 0) {
			// Run forked process, with the only shared state being
			// the new channel socket
			close(channelsock);
			return run_client_child(chanclient, socket_path);
		} else if (npid == -1) {
			wp_log(WP_DEBUG, "Fork failure\n");
			retcode = EXIT_FAILURE;
			break;
		} else {
			// todo: make an option in which only one client is
			// permitted
		}
	}
	close(channelsock);
	unlink(socket_path);
	return retcode;
}
