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
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <wayland-server-core.h>

int run_server(const char *socket_path, int app_argc, char *const app_argv[])
{
	wp_log(WP_DEBUG, "I'm a server on %s!\n", socket_path);
	wp_log(WP_DEBUG, "Trying to run %d:", app_argc);
	for (int i = 0; i < app_argc; i++) {
		fprintf(stderr, " %s", app_argv[i]);
	}
	fprintf(stderr, "\n");

	// create another socketpair; one goes to display; one goes to child
	int csockpair[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, csockpair);
	int flags = fcntl(csockpair[0], F_GETFD);
	fcntl(csockpair[0], F_SETFD, flags | FD_CLOEXEC);

	pid_t pid = fork();
	if (pid == -1) {
		wp_log(WP_ERROR, "Fork failed\n");
		return EXIT_FAILURE;
	} else if (pid == 0) {
		char bufs2[16];
		sprintf(bufs2, "%d", csockpair[1]);

		// Provide the other socket in the pair to child application
		unsetenv("WAYLAND_DISPLAY");
		setenv("WAYLAND_SOCKET", bufs2, 0);

		execv(app_argv[0], app_argv);
		wp_log(WP_ERROR, "Failed to execv: %s\n", strerror(errno));
		return EXIT_FAILURE;
	}

	//	struct wl_display *display = wl_display_create();
	//	if (wl_display_add_socket_fd(display, csockpair[0]) == -1) {
	//		wp_log(WP_ERROR, "Failed to add socket to display
	// object\n"); 		wl_display_destroy(display); 		return
	// EXIT_FAILURE;
	//	}

	int status;

	struct sockaddr_un saddr;
	int chanfd;

	if (strlen(socket_path) >= sizeof(saddr.sun_path)) {
		wp_log(WP_ERROR,
				"Socket path is too long and would be truncated: %s\n",
				socket_path);
		return EXIT_FAILURE;
	}

	saddr.sun_family = AF_UNIX;
	strncpy(saddr.sun_path, socket_path, sizeof(saddr.sun_path) - 1);
	chanfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (chanfd == -1) {
		wp_log(WP_ERROR, "Error creating socket: %s\n",
				strerror(errno));
		return EXIT_FAILURE;
	}
	if (connect(chanfd, (struct sockaddr *)&saddr, sizeof(saddr)) == -1) {
		wp_log(WP_ERROR, "Error connecting socket: %s\n",
				strerror(errno));
		close(chanfd);
		return EXIT_FAILURE;
	}

	// A connection has already been established
	int appfd = csockpair[0];

	/** Main select loop:
	 * fd -> csockpair[0]
	 * csockpair[0] -> fd
	 * 1 second timer (poll waitpid) */
	struct timespec timeout = {.tv_sec = 0, .tv_nsec = 500000000L};

	int iter = 0;

	int maxmsg = 4096;
	char *buffer = calloc(1, maxmsg + 1);
	struct fd_translation_map fdtransmap = {
			.local_sign = -1, .list = NULL, .max_local_id = 1};
	while (true) {
		iter++;
		fd_set readfds;
		FD_ZERO(&readfds);
		FD_SET(chanfd, &readfds);
		FD_SET(appfd, &readfds);
		int maxfd = chanfd > appfd ? chanfd : appfd;
		int r = pselect(maxfd + 1, &readfds, NULL, NULL, &timeout,
				NULL);
		if (r < 0) {
			wp_log(WP_ERROR, "Error selecting fds: %s\n",
					strerror(errno));
			return EXIT_FAILURE;
		}

		if (FD_ISSET(chanfd, &readfds)) {
			wp_log(WP_DEBUG, "Channel read begun\n");
			char *tmpbuf;
			ssize_t nbytes = read_size_then_buf(chanfd, &tmpbuf);
			if (nbytes == 0) {
				wp_log(WP_ERROR,
						"Channel read connection closed\n");
				break;
			}
			if (nbytes == -1) {
				wp_log(WP_ERROR, "Channel read failure: %s\n",
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

			wp_log(WP_DEBUG,
					"Read %ld byte msg, %d fds, %d transfers\n",
					nbytes, nids, ntransfers);

			apply_updates(&fdtransmap, ntransfers, transfers);

			int fds[28];
			memset(fds, 0, sizeof(fds));
			untranslate_ids(&fdtransmap, nids, ids, fds);

			wp_log(WP_DEBUG, "Read from conn %d = %d bytes\n",
					nbytes, nbytes);
			ssize_t wc = iovec_write(
					appfd, waymsg, waylen, fds, nids);
			free(tmpbuf);
			if (wc == -1) {
				wp_log(WP_ERROR, "FD Write  failure %d: %s\n",
						wc, strerror(errno));
				break;
			}
		}
		if (FD_ISSET(appfd, &readfds)) {
			wp_log(WP_DEBUG, "client socket isset\n");
			int fdbuf[28];
			int nfds = 28;

			ssize_t rc = iovec_read(
					appfd, buffer, maxmsg, fdbuf, &nfds);
			if (rc == -1) {
				wp_log(WP_ERROR, "appfd read failure %ld: %s\n",
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
							"chanfd write failure: %s\n",
							strerror(errno));
					break;
				}
				free(msg);

				wp_log(WP_DEBUG, "Channel write complete\n");
			} else {
				wp_log(WP_DEBUG, "the client shut down\n");
				break;
			}
		}

		if (waitpid(pid, &status, WNOHANG) > 0) {
			break;
		}
	}
	cleanup_translation_map(&fdtransmap);
	close(chanfd);
	free(buffer);

	// todo: scope manipulation, to ensure all cleanups are done
	wp_log(WP_DEBUG, "Waiting for child process\n");
	waitpid(pid, &status, 0);
	wp_log(WP_DEBUG, "Program ended\n");
	return EXIT_SUCCESS;
}
