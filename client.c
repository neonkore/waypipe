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
#include <sys/poll.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
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
	int dispfd = wl_display_get_fd(display);

	struct fd_translation_map fdtransmap = {
			.local_sign = 1, .list = NULL, .max_local_id = 1};

	const int maxmsg = 4096;
	char *buffer = calloc(1, maxmsg + 1);
	while (1) {
		// pselect multiple.
		fd_set readfds;
		FD_ZERO(&readfds);
		FD_SET(chanfd, &readfds);
		FD_SET(dispfd, &readfds);
		struct timespec timeout = {.tv_sec = 0, .tv_nsec = 700000000L};
		int maxfd = chanfd > dispfd ? chanfd : dispfd;
		int r = pselect(maxfd + 1, &readfds, NULL, NULL, &timeout,
				NULL);
		if (r == -1) {
			wp_log(WP_ERROR, "Select failed, stopping\n");
			break;
		}

		if (FD_ISSET(chanfd, &readfds)) {
			char *tmpbuf;
			wp_log(WP_DEBUG, "Channel read begun\n");
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

			ssize_t wc = iovec_write(
					dispfd, waymsg, waylen, fds, nids);
			free(tmpbuf);
			if (wc == -1) {
				wp_log(WP_ERROR,
						"dispfd write failure %ld: %s\n",
						wc, strerror(errno));
				break;
			}
		}
		if (FD_ISSET(dispfd, &readfds)) {
			int fdbuf[28];
			int nfds = 28;

			ssize_t rc = iovec_read(
					dispfd, buffer, maxmsg, fdbuf, &nfds);
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
						"Packed message size (%d fds, %d transfers): %ld\n",
						nfds, ntransfers, msglen);

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
				wp_log(WP_DEBUG, "The display shut down\n");
				break;
			}
		}
	}

	cleanup_translation_map(&fdtransmap);

	free(buffer);
	close(chanfd);
	wp_log(WP_DEBUG, "...\n");

	wp_log(WP_DEBUG, "Closing client\n");
	close(dispfd);

	wl_display_disconnect(display);

	return EXIT_SUCCESS;
}

int run_client(const char *socket_path, bool oneshot, pid_t eol_pid)
{
	if (verify_connection() == -1) {
		wp_log(WP_ERROR,
				"Failed to connect to a wayland compositor.\n");
		if (eol_pid) {
			waitpid(eol_pid, NULL, 0);
		}
		return EXIT_FAILURE;
	}
	wp_log(WP_DEBUG, "A wayland compositor is available. Proceeding.\n");

	int nmaxclients = oneshot ? 1 : 3; // << todo, increase
	int channelsock = setup_nb_socket(socket_path, nmaxclients);
	if (channelsock == -1) {
		// Error messages already made
		if (eol_pid) {
			waitpid(eol_pid, NULL, 0);
		}
		return EXIT_FAILURE;
	}

	int retcode = EXIT_SUCCESS;
	struct kstack *children = NULL;

	/* A large fraction of the logic here is needed if we run in
	 * 'ssh' mode, but the ssh invocation itself fails while we
	 * are waiting for a socket accept */
	struct pollfd cs;
	cs.fd = channelsock;
	cs.events = POLL_IN;
	cs.revents = 0;
	while (1) {
		// TODO: figure out a safe, non-polling solution
		int r = poll(&cs, 1, 1000);
		if (r == -1) {
			if (errno == EINTR) {
				continue;
			}
			retcode = EXIT_FAILURE;
			break;
		}
		if (eol_pid) {
			int stat;
			int wp = waitpid(eol_pid, &stat, WNOHANG);
			if (wp > 0) {
				wp_log(WP_ERROR, "Child (ssh) died early\n");
				eol_pid = 0; // < recycled
				retcode = EXIT_FAILURE;
				break;
			}
		}
		// scan stack for children, and clean them up!
		wait_on_children(&children, WNOHANG);

		if (r == 0) {
			// Nothing to read
			continue;
		}

		int chanclient = accept(channelsock, NULL, NULL);
		if (chanclient == -1) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				// The wakeup may have been spurious
				continue;
			}
			wp_log(WP_ERROR, "Connection failure: %s\n",
					strerror(errno));
			retcode = EXIT_FAILURE;
			break;
		} else {
			if (oneshot) {
				retcode = run_client_child(
						chanclient, socket_path);
				break;
			} else {
				pid_t npid = fork();
				if (npid == 0) {
					// Run forked process, with the only
					// shared state being the new channel
					// socket
					while (children) {
						struct kstack *nxt =
								children->nxt;
						free(children);
						children = nxt;
					}

					close(channelsock);
					run_client_child(chanclient,
							socket_path);
					// exit path?
					return EXIT_SUCCESS;
				} else if (npid == -1) {
					wp_log(WP_DEBUG, "Fork failure\n");
					retcode = EXIT_FAILURE;
					break;
				} else {
					struct kstack *kd = calloc(1,
							sizeof(struct kstack));
					kd->pid = npid;
					kd->nxt = children;
					children = kd;
				}
				continue;
			}
		}
	}

	close(channelsock);
	unlink(socket_path);
	if (eol_pid) {
		// Don't return until the child process completes
		int status;
		waitpid(eol_pid, &status, 0);
	}
	wait_on_children(&children, 0);
	return retcode;
}
