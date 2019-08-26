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

#include "main.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static int get_inherited_socket(void)
{
	const char *fd_no = getenv("WAYLAND_SOCKET");
	char *endptr = NULL;
	errno = 0;
	int fd = (int)strtol(fd_no, &endptr, 10);
	if (*endptr || errno) {
		wp_error("Failed to parse WAYLAND_SOCKET env variable with value \"%s\", exiting",
				fd_no);
		return -1;
	}
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1 && errno == EBADF) {
		wp_error("The file descriptor WAYLAND_SOCKET=%d was invalid, exiting",
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
		wp_error("WAYLAND_DISPLAY is not set, exiting");
		return -1;
	}
	int len = 0;
	if (display[0] != '/') {
		const char *xdg_runtime_dir = getenv("XDG_RUNTIME_DIR");
		if (!xdg_runtime_dir) {
			wp_error("XDG_RUNTIME_DIR is not set, exiting");
			return -1;
		}
		len = snprintf(path, MAX_SOCKETPATH_LEN, "%s/%s",
				xdg_runtime_dir, display);
	} else {
		len = snprintf(path, MAX_SOCKETPATH_LEN, "%s", display);
	}
	if (len >= MAX_SOCKETPATH_LEN) {
		wp_error("Wayland display socket path is >=%d bytes, truncated to \"%s\", exiting",
				MAX_SOCKETPATH_LEN, path);
		return -1;
	}
	return 0;
}

static int run_single_client_reconnector(
		int channelsock, int linkfd, uint64_t conn_id)
{
	int retcode = EXIT_SUCCESS;
	while (!shutdown_flag) {
		struct pollfd pf[2];
		pf[0].fd = channelsock;
		pf[0].events = POLLIN;
		pf[0].revents = 0;
		pf[1].fd = linkfd;
		pf[1].events = 0;
		pf[1].revents = 0;

		int r = poll(pf, 2, -1);
		if (r == -1 && errno == EINTR) {
			continue;
		} else if (r == -1) {
			retcode = EXIT_FAILURE;
			break;
		} else if (r == 0) {
			// Nothing to read
			continue;
		}

		if (pf[1].revents & POLLHUP) {
			/* Hang up, main thread has closed its link */
			break;
		}
		if (pf[0].revents & POLLIN) {
			int newclient = accept(channelsock, NULL, NULL);
			if (newclient == -1) {
				if (errno == EAGAIN || errno == EWOULDBLOCK) {
					// The wakeup may have been spurious
					continue;
				}
				wp_error("Connection failure: %s",
						strerror(errno));
				retcode = EXIT_FAILURE;
				break;
			} else {
				uint64_t new_conn = 0;
				if (read(newclient, &new_conn,
						    sizeof(new_conn)) !=
						sizeof(new_conn)) {
					wp_error("Failed to get connection id");
					retcode = EXIT_FAILURE;
					close(newclient);
					break;
				}
				bool update = (new_conn & CONN_UPDATE_BIT) != 0;
				new_conn = new_conn & ~CONN_UPDATE_BIT;
				if (new_conn != conn_id) {
					close(newclient);
					continue;
				}
				if (!update) {
					wp_error("Connection token is missing update flag");
					close(newclient);
					continue;
				}
				if (send_one_fd(linkfd, newclient) == -1) {
					wp_error("Failed to get connection id");
					retcode = EXIT_FAILURE;
					close(newclient);
					break;
				}
				close(newclient);
			}
		}
	}
	close(channelsock);
	close(linkfd);
	return retcode;
}

static int run_single_client(int channelsock, pid_t *eol_pid,
		const struct main_config *config, int disp_fd)
{
	/* To support reconnection attempts, this mode creates a child
	 * reconnection watcher process, linked via socketpair */
	int retcode = EXIT_SUCCESS;
	int chanclient = -1;
	uint64_t conn_id = (uint64_t)-1;
	while (!shutdown_flag) {
		int status = -1;
		if (wait_for_pid_and_clean(eol_pid, &status, WNOHANG, NULL)) {
			eol_pid = 0; // < in case eol_pid is recycled

			wp_debug("Child (ssh) died, exiting");
			// Copy the exit code
			retcode = WEXITSTATUS(status);
			break;
		}

		struct pollfd cs;
		cs.fd = channelsock;
		cs.events = POLLIN;
		cs.revents = 0;
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

		chanclient = accept(channelsock, NULL, NULL);
		if (chanclient == -1) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				// The wakeup may have been spurious
				continue;
			}
			wp_error("Connection failure: %s", strerror(errno));
			retcode = EXIT_FAILURE;
			break;
		} else {
			if (read(chanclient, &conn_id, sizeof(conn_id)) !=
					sizeof(conn_id)) {
				wp_error("Failed to get connection id");
				retcode = EXIT_FAILURE;
				close(chanclient);
				chanclient = -1;
			}
			break;
		}
	}
	if (retcode == EXIT_FAILURE || shutdown_flag || chanclient == -1) {
		return retcode;
	}
	if (conn_id & CONN_UPDATE_BIT) {
		wp_error("Initial connection token had update flag set");
		return retcode;
	}

	/* Fork a reconnection handler, only if the connection is
	 * reconnectable/has a nonzero id */
	int linkfds[2] = {-1, -1};
	if (conn_id != 0) {
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, linkfds) == -1) {
			wp_error("Failed to create socketpair: %s",
					strerror(errno));
			close(chanclient);
			return EXIT_FAILURE;
		}

		pid_t reco_pid = fork();
		if (reco_pid == -1) {
			wp_debug("Fork failure");
			close(chanclient);
			return EXIT_FAILURE;
		} else if (reco_pid == 0) {
			if (linkfds[0] != -1) {
				close(linkfds[0]);
			}
			close(chanclient);
			close(disp_fd);
			int rc = run_single_client_reconnector(
					channelsock, linkfds[1], conn_id);
			exit(rc);
		}
		close(linkfds[1]);
	}
	close(channelsock);

	return main_interface_loop(
			chanclient, disp_fd, linkfds[0], config, true);
}

static int handle_new_client_connection(int channelsock, int chanclient,
		struct conn_map *connmap, const struct main_config *config,
		const char disp_path[static MAX_SOCKETPATH_LEN])
{

	uint64_t conn_id;
	if (read(chanclient, &conn_id, sizeof(conn_id)) != sizeof(conn_id)) {
		wp_error("Failed to get connection id");
		goto fail_cc;
	}
	if (conn_id & CONN_UPDATE_BIT) {
		conn_id = conn_id & ~CONN_UPDATE_BIT;
		for (int i = 0; i < connmap->count; i++) {
			if (connmap->data[i].token == conn_id) {
				if (send_one_fd(connmap->data[i].linkfd,
						    chanclient) == -1) {
					wp_error("Failed to send new connection fd to subprocess: %s",
							strerror(errno));
					goto fail_cc;
				}
				break;
			}
		}
		close(chanclient);
		return 0;
	}
	bool reconnectable = conn_id != 0;

	if (reconnectable && buf_ensure_size(connmap->count + 1,
					     sizeof(struct conn_addr),
					     &connmap->size,
					     (void **)&connmap->data) == -1) {
		wp_error("Failed to allocate space to track connection");
		goto fail_cc;
	}
	int linkfds[2] = {-1, -1};
	if (reconnectable) {
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, linkfds) == -1) {
			wp_error("Failed to create socketpair: %s",
					strerror(errno));
			goto fail_cc;
		}
	}
	pid_t npid = fork();
	if (npid == 0) {
		// Run forked process, with the only
		// shared state being the new channel
		// socket
		close(channelsock);
		if (reconnectable) {
			close(linkfds[0]);
		}
		for (int i = 0; i < connmap->count; i++) {
			close(connmap->data[i].linkfd);
		}

		int dfd = connect_to_socket(disp_path);
		if (dfd == -1) {
			exit(EXIT_FAILURE);
		}
		// ignore retcode ?
		main_interface_loop(chanclient, dfd, linkfds[1], config, true);
		close(dfd);

		exit(EXIT_SUCCESS);
	} else if (npid == -1) {
		wp_debug("Fork failure");
		goto fail_ps;
	}
	// Remove connection from this process

	close(chanclient);
	if (reconnectable) {
		close(linkfds[1]);
		connmap->data[connmap->count++] =
				(struct conn_addr){.linkfd = linkfds[0],
						.token = conn_id,
						.pid = npid};
	}

	return 0;
fail_ps:
	close(linkfds[0]);
fail_cc:
	close(chanclient);
	return -1;
}

static int run_multi_client(int channelsock, pid_t *eol_pid,
		const struct main_config *config,
		const char disp_path[static MAX_SOCKETPATH_LEN])
{
	struct conn_map connmap = {.data = NULL, .count = 0, .size = 0};

	struct pollfd cs;
	cs.fd = channelsock;
	cs.events = POLLIN;
	cs.revents = 0;
	int retcode = EXIT_SUCCESS;
	while (!shutdown_flag) {
		int status = -1;
		if (wait_for_pid_and_clean(
				    eol_pid, &status, WNOHANG, &connmap)) {
			wp_debug("Child (ssh) died, exiting");
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
			wp_error("Connection failure: %s", strerror(errno));
			retcode = EXIT_FAILURE;
			break;
		} else {
			if (handle_new_client_connection(channelsock,
					    chanclient, &connmap, config,
					    disp_path) == -1) {
				retcode = EXIT_FAILURE;
				break;
			}
		}
	}

	for (int i = 0; i < connmap.count; i++) {
		close(connmap.data[i].linkfd);
	}
	free(connmap.data);
	close(channelsock);
	return retcode;
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
			if (eol_pid) {
				waitpid(eol_pid, NULL, 0);
			}
			return EXIT_FAILURE;
		}
		close(test_conn);
	}
	wp_debug("A wayland compositor is available. Proceeding.");

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

	/* These handlers close the channelsock and dispfd */
	int retcode;
	if (oneshot) {
		retcode = run_single_client(
				channelsock, &eol_pid, config, dispfd);
	} else {
		retcode = run_multi_client(
				channelsock, &eol_pid, config, disp_path);
	}
	unlink(socket_path);
	int cleanup_type = shutdown_flag ? WNOHANG : 0;

	int status = -1;
	// Don't return until all child processes complete
	if (wait_for_pid_and_clean(&eol_pid, &status, cleanup_type, NULL)) {
		retcode = WEXITSTATUS(status);
	}
	return retcode;
}
