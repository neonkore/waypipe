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
#include <unistd.h>

static int get_inherited_socket()
{
	const char *fd_no = getenv("WAYLAND_SOCKET");
	char *endptr = NULL;
	errno = 0;
	int fd = (int)strtol(fd_no, &endptr, 10);
	if (*endptr || errno) {
		wp_log(WP_ERROR,
				"Failed to parse WAYLAND_SOCKET env variable with value \"%s\", exiting",
				fd_no);
		return -1;
	}
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1 && errno == EBADF) {
		wp_log(WP_ERROR,
				"The file descriptor WAYLAND_SOCKET=%d was invalid, exiting",
				fd);
		return -1;
	}
	return fd;
}

#define MAX_SOCKETPATH_LEN (int)sizeof(((struct sockaddr_un *)NULL)->sun_path)

static int get_display_path(char path[static MAX_SOCKETPATH_LEN])
{
	const char *display = getenv("WAYLAND_DISPLAY");
	if (!display) {
		wp_log(WP_ERROR, "WAYLAND_DISPLAY is not set, exiting");
		return -1;
	}
	int len = 0;
	if (display[0] != '/') {
		const char *xdg_runtime_dir = getenv("XDG_RUNTIME_DIR");
		if (!xdg_runtime_dir) {
			wp_log(WP_ERROR, "XDG_RUNTIME_DIR is not set, exiting");
			return -1;
		}
		len = snprintf(path, MAX_SOCKETPATH_LEN, "%s/%s",
				xdg_runtime_dir, display);
	} else {
		len = snprintf(path, MAX_SOCKETPATH_LEN, "%s", display);
	}
	if (len >= MAX_SOCKETPATH_LEN) {
		wp_log(WP_ERROR,
				"Wayland display socket path is longer that %d bytes, truncated to \"%s\", exiting",
				MAX_SOCKETPATH_LEN, path);
		return -1;
	}
	return 0;
}

int run_client(const char *socket_path, const struct main_config *config,
		bool oneshot, bool via_socket, pid_t eol_pid)
{
	/* Connect to Wayland display. We don't use the wayland-client
	 * function here, because its errors aren't immediately useful,
	 * and older Wayland versions have edge cases */
	int dispfd = -1;
	char disp_path[MAX_SOCKETPATH_LEN];
	if (via_socket) {
		dispfd = get_inherited_socket();
		if (dispfd == -1) {
			if (eol_pid) {
				waitpid(eol_pid, NULL, 0);
			}
			return EXIT_FAILURE;
		}
	} else {
		if (get_display_path(disp_path) == -1) {
			if (eol_pid) {
				waitpid(eol_pid, NULL, 0);
			}
			return EXIT_FAILURE;
		}
	}

	if (oneshot) {
		if (!via_socket) {
			dispfd = connect_to_socket(disp_path);
		}
	} else {
		int test_conn = connect_to_socket(disp_path);
		if (test_conn == -1) {
			wp_log(WP_ERROR,
					"Failed to connect to a wayland compositor.");
			if (eol_pid) {
				waitpid(eol_pid, NULL, 0);
			}
			return EXIT_FAILURE;
		}
		close(test_conn);
	}
	wp_log(WP_DEBUG, "A wayland compositor is available. Proceeding.");

	int nmaxclients = oneshot ? 1 : 128;
	int channelsock = setup_nb_socket(socket_path, nmaxclients);
	if (channelsock == -1) {
		// Error messages already made
		if (eol_pid) {
			waitpid(eol_pid, NULL, 0);
		}
		if (dispfd != -1) {
			close(dispfd);
		}
		return EXIT_FAILURE;
	}

	int retcode = EXIT_SUCCESS;

	/* A large fraction of the logic here is needed if we run in
	 * 'ssh' mode, but the ssh invocation itself fails while we
	 * are waiting for a socket accept */
	struct pollfd cs;
	cs.fd = channelsock;
	cs.events = POLLIN;
	cs.revents = 0;
	while (!shutdown_flag) {
		int status = -1;
		if (wait_for_pid_and_clean(eol_pid, &status, WNOHANG)) {
			eol_pid = 0; // < in case eol_pid is recycled

			wp_log(WP_DEBUG, "Child (ssh) died, exiting");
			// Copy the exit code
			retcode = WEXITSTATUS(status);
			break;
		}

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
						dispfd, config, true);
				break;
			} else {
				pid_t npid = fork();
				if (npid == 0) {
					// Run forked process, with the only
					// shared state being the new channel
					// socket
					close(channelsock);

					int dfd = connect_to_socket(disp_path);
					if (dfd == -1) {
						return EXIT_FAILURE;
					}
					// ignore retcode ?
					main_interface_loop(chanclient, dfd,
							config, true);
					close(dfd);

					// exit path?
					return EXIT_SUCCESS;
				} else if (npid == -1) {
					wp_log(WP_DEBUG, "Fork failure");
					retcode = EXIT_FAILURE;
					break;
				} else {
					// Remove connection from this process
					close(chanclient);
				}
				continue;
			}
		}
	}

	if (dispfd != -1) {
		close(dispfd);
	}
	close(channelsock);
	unlink(socket_path);
	int cleanup_type = shutdown_flag ? WNOHANG : 0;

	int status = -1;
	// Don't return until all child processes complete
	if (wait_for_pid_and_clean(eol_pid, &status, cleanup_type)) {
		retcode = WEXITSTATUS(status);
	}
	return retcode;
}
