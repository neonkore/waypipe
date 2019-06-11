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
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/wait.h>
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

int run_client(const char *socket_path, const struct main_config *config,
		bool oneshot, pid_t eol_pid)
{
	struct wl_display *display = NULL;
	if (oneshot) {
		display = wl_display_connect(NULL);
		if (!display) {
			wp_log(WP_ERROR,
					"Failed to connect to a wayland server.");
			return EXIT_FAILURE;
		}
	} else {
		if (verify_connection() == -1) {
			wp_log(WP_ERROR,
					"Failed to connect to a wayland compositor.");
			if (eol_pid) {
				waitpid(eol_pid, NULL, 0);
			}
			return EXIT_FAILURE;
		}
	}
	wp_log(WP_DEBUG, "A wayland compositor is available. Proceeding.");

	int nmaxclients = oneshot ? 1 : 128;
	int channelsock = setup_nb_socket(socket_path, nmaxclients);
	if (channelsock == -1) {
		// Error messages already made
		if (eol_pid) {
			waitpid(eol_pid, NULL, 0);
		}
		if (display) {
			wl_display_disconnect(display);
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
	cs.events = POLLIN;
	cs.revents = 0;
	while (!shutdown_flag) {
		if (eol_pid) {
			int wp = waitpid(eol_pid, NULL, WNOHANG);
			if (wp > 0) {
				wp_log(WP_DEBUG, "Child (ssh) died, exiting");
				eol_pid = 0; // < recycled
				retcode = EXIT_SUCCESS;
				break;
			}
		}

		// scan stack for children, and clean them up!
		wait_on_children(&children, WNOHANG);

		int r = poll(&cs, 1, -1);
		if (r == -1) {
			if (errno == EINTR) {
				// If SIGCHLD, we will check the child.
				// If SIGINT, the loop ends
				continue;
			}
			retcode = EXIT_FAILURE;
			break;
		} else if (r == 0) {
			// Nothing to read
			continue;
		}

		int chanclient = accept(channelsock, NULL, NULL);
		if (chanclient == -1) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				// The wakeup may have been spurious
				continue;
			}
			wp_log(WP_ERROR, "Connection failure: %s",
					strerror(errno));
			retcode = EXIT_FAILURE;
			break;
		} else {
			if (oneshot) {
				retcode = main_interface_loop(chanclient,
						wl_display_get_fd(display),
						config, true);
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

					struct wl_display *local_display =
							wl_display_connect(
									NULL);
					if (!local_display) {
						wp_log(WP_ERROR,
								"Failed to connect to a wayland server.");
						return EXIT_FAILURE;
					}
					int dispfd = wl_display_get_fd(
							local_display);
					// ignore retcode ?
					main_interface_loop(chanclient, dispfd,
							config, true);
					wl_display_disconnect(local_display);

					// exit path?
					return EXIT_SUCCESS;
				} else if (npid == -1) {
					wp_log(WP_DEBUG, "Fork failure");
					retcode = EXIT_FAILURE;
					break;
				} else {
					// Remove connection from this process
					close(chanclient);

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

	if (display) {
		wl_display_disconnect(display);
	}
	close(channelsock);
	unlink(socket_path);
	int cleanup_type = shutdown_flag ? WNOHANG : 0;
	if (eol_pid) {
		// Don't return until the child process completes
		waitpid(eol_pid, NULL, cleanup_type);
	}
	wait_on_children(&children, cleanup_type);
	// Free stack, in case we suddenly shutdown and fail to clean up
	// children
	while (children) {
		struct kstack *nxt = children->nxt;
		free(children);
		children = nxt;
	}
	return retcode;
}
