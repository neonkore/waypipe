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
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <wayland-server-core.h>

static int connect_to_channel(const char *socket_path)
{
	struct sockaddr_un saddr;
	int chanfd;
	saddr.sun_family = AF_UNIX;
	strncpy(saddr.sun_path, socket_path, sizeof(saddr.sun_path) - 1);
	chanfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (chanfd == -1) {
		wp_log(WP_ERROR, "Error creating socket: %s", strerror(errno));
		return -1;
	}

	if (connect(chanfd, (struct sockaddr *)&saddr, sizeof(saddr)) == -1) {
		wp_log(WP_ERROR, "Error connecting to socket (%s): %s",
				socket_path, strerror(errno));
		close(chanfd);
		return -1;
	}
	return chanfd;
}

int run_server(const char *socket_path, const char *drm_node, bool oneshot,
		bool unlink_at_end, const char *application,
		char *const app_argv[])
{
	wp_log(WP_DEBUG, "I'm a server on %s, running: %s", socket_path,
			app_argv[0]);

	if (strlen(socket_path) >=
			sizeof(((struct sockaddr_un *)NULL)->sun_path)) {
		wp_log(WP_ERROR,
				"Socket path is too long and would be truncated: %s",
				socket_path);
		return EXIT_FAILURE;
	}

	// Setup connection to program
	char displaypath[256];
	sprintf(displaypath, "%s.disp.sock", socket_path);
	int wayland_socket = -1, server_link = -1, wdisplay_socket = -1;
	if (oneshot) {
		int csockpair[2];
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, csockpair) == -1) {
			wp_log(WP_ERROR, "Socketpair failed: %s",
					strerror(errno));
			return EXIT_FAILURE;
		}
		if (set_fnctl_flag(csockpair[0], FD_CLOEXEC) == -1) {
			wp_log(WP_ERROR, "Fnctl failed: %s", strerror(errno));
			return EXIT_FAILURE;
		}
		wayland_socket = csockpair[1];
		server_link = csockpair[0];
	} else {
		// Bind a socket for WAYLAND_DISPLAY, and listen
		int nmaxclients = 128;
		wdisplay_socket = setup_nb_socket(displaypath, nmaxclients);
		if (wdisplay_socket == -1) {
			// Error messages already made
			return EXIT_FAILURE;
		}
	}

	// Launch program
	pid_t pid = fork();
	if (pid == -1) {
		wp_log(WP_ERROR, "Fork failed");
		if (!oneshot) {
			unlink(displaypath);
		}
		return EXIT_FAILURE;
	} else if (pid == 0) {
		if (oneshot) {
			char bufs2[16];
			sprintf(bufs2, "%d", wayland_socket);

			// Provide the other socket in the pair to child
			// application
			unsetenv("WAYLAND_DISPLAY");
			setenv("WAYLAND_SOCKET", bufs2, 1);
		} else {
			// Since Wayland 1.15, absolute paths are supported in
			// WAYLAND_DISPLAY
			unsetenv("WAYLAND_SOCKET");
			setenv("WAYLAND_DISPLAY", displaypath, 1);
			close(wdisplay_socket);
		}

		execvp(application, app_argv);
		wp_log(WP_ERROR, "Failed to execvp \'%s\': %s", application,
				strerror(errno));
		return EXIT_FAILURE;
	}
	if (oneshot) {
		// We no longer need to see this side
		close(wayland_socket);
	}

	wp_log(WP_DEBUG, "Server main!");

	int retval = EXIT_SUCCESS;
	if (oneshot) {
		int chanfd = connect_to_channel(socket_path);
		if (unlink_at_end) {
			unlink(socket_path);
		}

		wp_log(WP_DEBUG, "Oneshot connected");
		if (chanfd != -1) {
			retval = main_interface_loop(chanfd, server_link,
					drm_node, false, false);
		} else {
			retval = EXIT_FAILURE;
		}
		close(server_link);
	} else {
		struct kstack *children = NULL;

		// Poll loop - 1s poll, either child dies, or we have a
		// connection
		struct pollfd pf;
		pf.fd = wdisplay_socket;
		pf.events = POLL_IN;
		pf.revents = 0;
		while (!shutdown_flag) {
			int wp = waitpid(pid, NULL, WNOHANG);
			if (wp > 0) {
				wp_log(WP_DEBUG,
						"Child program has died, exiting");
				retval = EXIT_SUCCESS;
				break;
			} else if (wp == -1) {
				wp_log(WP_ERROR, "Failed in waitpid: %s",
						strerror(errno));
				retval = EXIT_FAILURE;
				break;
			}
			// scan stack for children, and clean them up!
			wait_on_children(&children, WNOHANG);

			int r = poll(&pf, 1, -1);
			if (r == -1) {
				if (errno == EINTR) {
					// If SIGCHLD, we will check the child.
					// If SIGINT, the loop ends
					continue;
				}
				fprintf(stderr, "Poll failed: %s",
						strerror(errno));
				retval = EXIT_FAILURE;
				break;
			} else if (r == 0) {
				continue;
			}

			int appfd = accept(wdisplay_socket, NULL, NULL);
			if (appfd == -1) {
				if (errno == EAGAIN || errno == EWOULDBLOCK) {
					// The wakeup may have been spurious
					continue;
				}
				wp_log(WP_ERROR, "Connection failure: %s",
						strerror(errno));
				retval = EXIT_FAILURE;
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

					close(wdisplay_socket);
					int chanfd = connect_to_channel(
							socket_path);

					return main_interface_loop(chanfd,
							appfd, drm_node, false,
							false);
				} else if (npid == -1) {
					wp_log(WP_DEBUG, "Fork failure");
					retval = EXIT_FAILURE;
					break;
				} else {
					// This process no longer needs the
					// application connection
					close(appfd);

					struct kstack *kd = calloc(1,
							sizeof(struct kstack));
					kd->pid = npid;
					kd->nxt = children;
					children = kd;
				}
				continue;
			}
		}
		if (unlink_at_end) {
			unlink(socket_path);
		}
		close(wdisplay_socket);
		// Wait for child processes to exit
		wp_log(WP_DEBUG, "Waiting for child handlers");
		wait_on_children(&children, shutdown_flag ? WNOHANG : 0);
		// Free stack, in case we suddenly shutdown and fail to clean up
		// children
		while (children) {
			struct kstack *nxt = children->nxt;
			free(children);
			children = nxt;
		}
	}

	if (!oneshot) {
		unlink(displaypath);
	}
	wp_log(WP_DEBUG, "Waiting for child process");
	waitpid(pid, NULL, shutdown_flag ? WNOHANG : 0);
	wp_log(WP_DEBUG, "Program ended");
	return retval;
}
