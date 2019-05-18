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
	struct pollfd *pfds = NULL;
	while (1) {
		int npoll = 2 + count_npipes(&fdtransmap);
		free(pfds);
		// todo: resizing logic
		pfds = calloc(npoll, sizeof(struct pollfd));
		pfds[0].fd = chanfd;
		pfds[0].events = POLL_IN;
		pfds[1].fd = dispfd;
		pfds[1].events = POLL_IN;
		fill_with_pipes(&fdtransmap, pfds + 2);

		int r = poll(pfds, (nfds_t)npoll, 700);
		if (r == -1) {
			wp_log(WP_ERROR, "poll failed, stopping\n");
			break;
		}

		mark_pipe_object_statuses(&fdtransmap, npoll - 2, pfds + 2);

		if (pfds[0].revents & POLLIN) {
			// chanfd
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

			char *waymsg = NULL;
			int waylen = 0;
			int nids = 0;
			int ids[28];
			int ntransfers = 0;
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

			if (waymsg) {
				ssize_t wc = iovec_write(dispfd, waymsg, waylen,
						fds, nids);
				free(tmpbuf);
				if (wc == -1) {
					wp_log(WP_ERROR,
							"dispfd write failure %ld: %s\n",
							wc, strerror(errno));
					break;
				}
				close_local_pipe_ends(&fdtransmap);
			} else {
				free(tmpbuf);
			}

			flush_writable_pipes(&fdtransmap);
			close_rclosed_pipes(&fdtransmap);
		}

		int ntransfers = 0;
		// the wayland message is a zeroth transfer
		struct transfer transfers[50];
		int nfds = 0;
		int ids[28];
		if (pfds[1].revents & POLLIN) {
			int fdbuf[28];
			ssize_t rc = iovec_read(dispfd, buffer, maxmsg, fdbuf,
					&nfds, 28);
			if (rc == -1) {
				wp_log(WP_ERROR,
						"dispfd read failure %ld: %s\n",
						rc, strerror(errno));
				break;
			}
			if (rc > 0) {
				transfers[0].obj_id = 0;
				transfers[0].size = (size_t)rc;
				transfers[0].data = buffer;
				transfers[0].type = FDC_UNKNOWN;
				ntransfers = 1;

				translate_fds(&fdtransmap, nfds, fdbuf, ids);
			} else {
				wp_log(WP_DEBUG, "The display shut down\n");
				break;
			}
		}
		read_readable_pipes(&fdtransmap);
		collect_updates(&fdtransmap, &ntransfers, transfers);
		if (ntransfers > 0) {
			char *msg = NULL;
			size_t msglen;
			pack_pipe_message(&msglen, &msg, nfds, ids, ntransfers,
					transfers);
			wp_log(WP_DEBUG,
					"Packed message size (%d fds, %d blobs): %ld\n",
					nfds, ntransfers, msglen);

			if (write(chanfd, msg, msglen) == -1) {
				free(msg);
				wp_log(WP_ERROR, "chanfd write failure: %s\n",
						strerror(errno));
				break;
			}
			free(msg);

			wp_log(WP_DEBUG, "Channel write complete\n");
		}
	}
	free(pfds);
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
