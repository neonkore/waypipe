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
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

/** Generate a token with a very low accidental collision probability */
static uint64_t get_random_token(uint64_t last_token)
{
	struct timespec tp;
	clock_gettime(CLOCK_REALTIME, &tp);
	uint64_t pid = (uint64_t)getpid();
	uint64_t base = last_token + 1;
	base += ((uint64_t)tp.tv_sec * 1000000000uL + (uint64_t)tp.tv_nsec) *
		0x1000uL;
	base += pid;
	/* /dev/urandom isn't always available, e.g., when using chroot */
	int devrand = open("/dev/urandom", O_RDONLY);
	if (devrand != -1) {
		errno = 0;
		uint64_t offset = 0;
		(void)read(devrand, &offset, sizeof(offset));
		close(devrand);
		base += offset;
	}
	return base;
}

static int run_single_server_reconnector(
		int control_pipe, int linkfd, uint64_t token)
{
	int retcode = EXIT_SUCCESS;
	while (!shutdown_flag) {
		struct pollfd pf[2];
		pf[0].fd = control_pipe;
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
			/* It is extremely unlikely that a signal would
			 * interrupt a read of properly sized socketpath */
			char path[4096];
			ssize_t amt = read(
					control_pipe, path, sizeof(path) - 1);
			if (amt == -1) {
				wp_error("Failed to read from control pipe: %s",
						strerror(errno));
				retcode = EXIT_FAILURE;
				break;
			}
			path[amt] = '\0';
			if (strlen(path) < 108) {
				int new_conn = connect_to_socket(path);
				if (new_conn == -1) {
					wp_error("Socket path \"%s\" was invalid: %s",
							path, strerror(errno));
					/* Socket path was invalid */
					continue;
				}
				uint64_t flagged_token = token | CONN_UPDATE;
				if (write(new_conn, &flagged_token,
						    sizeof(flagged_token)) !=
						sizeof(flagged_token)) {
					wp_error("Failed to write to new connection: %s",
							strerror(errno));
					close(new_conn);
					continue;
				}

				if (send_one_fd(linkfd, new_conn) == -1) {
					wp_error("Failed to send new connection to subprocess: %s",
							strerror(errno));
				}
				close(new_conn);
			}
		}
	}
	close(control_pipe);
	close(linkfd);
	return retcode;
}

static int run_single_server(int control_pipe, const char *socket_path,
		bool unlink_at_end, int server_link,
		const struct main_config *config)
{
	int chanfd = connect_to_socket(socket_path);
	if (chanfd == -1) {
		goto fail_srv;
	}
	/* Only unlink the socket if it actually was a socket */
	if (unlink_at_end) {
		unlink(socket_path);
	}

	uint64_t token = get_random_token(0);
	uint64_t unflagged_token = token & ~CONN_UPDATE;
	if (write(chanfd, &unflagged_token, sizeof(uint64_t)) !=
			sizeof(uint64_t)) {
		wp_error("Failed to write connection token to socket");
		goto fail_cfd;
	}

	int linkfds[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, linkfds) == -1) {
		wp_error("Failed to create socketpair: %s", strerror(errno));
		goto fail_cfd;
	}

	if (control_pipe != -1) {
		pid_t reco_pid = fork();
		if (reco_pid == -1) {
			wp_debug("Fork failure");
			close(linkfds[0]);
			close(linkfds[1]);
			goto fail_cfd;
		} else if (reco_pid == 0) {
			close(chanfd);
			close(linkfds[0]);
			close(server_link);
			int rc = run_single_server_reconnector(
					control_pipe, linkfds[1], token);
			exit(rc);
		}
		close(control_pipe);
		close(linkfds[1]);
	}

	/* If there is no reconnection process, the file descriptor linkfds[1]
	 * is kept alive in this process to avoid hangup spam */
	int ret = main_interface_loop(
			chanfd, server_link, linkfds[0], config, false);
	if (control_pipe == -1) {
		close(linkfds[1]);
	}
	return ret;

fail_cfd:
	close(chanfd);
fail_srv:
	close(server_link);
	return EXIT_FAILURE;
}

static int handle_new_server_connection(const char *current_sockpath,
		int control_pipe, int wdisplay_socket, int appfd,
		struct conn_map *connmap, const struct main_config *config,
		uint64_t new_token)
{
	if (buf_ensure_size(connmap->count + 1, sizeof(struct conn_addr),
			    &connmap->size, (void **)&connmap->data) == -1) {
		wp_error("Failed to allocate memory to track new connection");
		goto fail_appfd;
	}

	int chanfd = connect_to_socket(current_sockpath);
	if (chanfd == -1) {
		goto fail_appfd;
	}
	uint64_t unflagged_token = new_token & ~CONN_UPDATE;
	if (write(chanfd, &unflagged_token, sizeof(uint64_t)) !=
			sizeof(uint64_t)) {
		wp_error("Failed to write connection token: %s",
				strerror(errno));
		goto fail_chanfd;
	}

	int linksocks[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, linksocks) == -1) {
		wp_error("Socketpair for process link failed: %s",
				strerror(errno));
		goto fail_chanfd;
	}

	pid_t npid = fork();
	if (npid == 0) {
		// Run forked process, with the only shared state being the
		// new channel socket
		close(wdisplay_socket);
		close(control_pipe);
		close(linksocks[0]);
		for (int i = 0; i < connmap->count; i++) {
			close(connmap->data[i].linkfd);
		}
		int rc = main_interface_loop(
				chanfd, appfd, linksocks[1], config, false);
		exit(rc);
	} else if (npid == -1) {
		wp_debug("Fork failure");
		close(linksocks[0]);
		close(linksocks[1]);
		goto fail_chanfd;
	}

	// This process no longer needs the application connection
	close(chanfd);
	close(appfd);
	close(linksocks[1]);

	connmap->data[connmap->count++] = (struct conn_addr){
			.token = new_token,
			.pid = npid,
			.linkfd = linksocks[0],
	};

	return 0;
fail_chanfd:
	close(chanfd);
fail_appfd:
	close(appfd);
	return -1;
}

static int update_connections(char current_sockpath[static 110],
		const char *path, struct conn_map *connmap, bool unlink_at_end)
{
	/* TODO: what happens if there's a partial failure? */
	for (int i = 0; i < connmap->count; i++) {
		int chanfd = connect_to_socket(path);
		if (chanfd == -1) {
			wp_error("Failed to connect to socket at \"%s\": %s",
					path, strerror(errno));
			return -1;
		}
		uint64_t flagged_token = connmap->data[i].token | CONN_UPDATE;
		if (write(chanfd, &flagged_token, sizeof(uint64_t)) !=
				sizeof(uint64_t)) {
			wp_error("Failed to write token to replacement connection: %s",
					strerror(errno));
			close(chanfd);
			return -1;
		}

		if (send_one_fd(connmap->data[i].linkfd, chanfd) == -1) {
			// TODO: what happens if data has changed?
			close(chanfd);
			return -1;
		}
	}
	/* If switching connections succeeded, adopt the new socket */
	if (unlink_at_end && strcmp(current_sockpath, path)) {
		unlink(current_sockpath);
	}
	/* Length already checked */
	strcpy(current_sockpath, path);
	return 0;
}

static int run_multi_server(int control_pipe, const char *socket_path,
		bool unlink_at_end, int wdisplay_socket,
		const struct main_config *config, pid_t *child_pid)
{
	struct conn_map connmap = {.data = NULL, .count = 0, .size = 0};
	char current_sockpath[110];
	current_sockpath[sizeof(current_sockpath) - 1] = 0;
	strncpy(current_sockpath, socket_path, sizeof(current_sockpath) - 1);

	struct pollfd pfs[2];
	pfs[0].fd = wdisplay_socket;
	pfs[0].events = POLLIN;
	pfs[0].revents = 0;
	pfs[1].fd = control_pipe;
	pfs[1].events = POLLIN;
	pfs[1].revents = 0;
	int retcode = EXIT_SUCCESS;
	uint64_t last_token = 0;
	while (!shutdown_flag) {
		int status = -1;
		if (wait_for_pid_and_clean(
				    child_pid, &status, WNOHANG, &connmap)) {
			wp_debug("Child program has died, exiting");
			retcode = WEXITSTATUS(status);
			break;
		}

		int r = poll(pfs, 1 + (control_pipe != -1), -1);
		if (r == -1) {
			if (errno == EINTR) {
				// If SIGCHLD, we will check the child.
				// If SIGINT, the loop ends
				continue;
			}
			fprintf(stderr, "Poll failed: %s", strerror(errno));
			retcode = EXIT_FAILURE;
			break;
		} else if (r == 0) {
			continue;
		}
		if (pfs[1].revents & POLLIN) {
			char path[4096];
			ssize_t amt = read(
					control_pipe, path, sizeof(path) - 1);
			if (amt == -1) {
				wp_error("Failed to read from control pipe: %s",
						strerror(errno));
			} else {
				path[amt] = '\0';
				if (strlen(path) <= 108) {
					update_connections(current_sockpath,
							path, &connmap,
							unlink_at_end);
				}
			}
		}

		if (pfs[0].revents & POLLIN) {
			int appfd = accept(wdisplay_socket, NULL, NULL);
			if (appfd == -1) {
				if (errno == EAGAIN || errno == EWOULDBLOCK) {
					// The wakeup may have been
					// spurious
					continue;
				}
				wp_error("Connection failure: %s",
						strerror(errno));
				retcode = EXIT_FAILURE;
				break;
			} else {
				last_token = get_random_token(last_token);
				if (handle_new_server_connection(
						    current_sockpath,
						    control_pipe,
						    wdisplay_socket, appfd,
						    &connmap, config,
						    last_token) == -1) {
					retcode = EXIT_FAILURE;
					break;
				}
			}
		}
	}
	if (unlink_at_end) {
		unlink(current_sockpath);
	}
	close(wdisplay_socket);

	for (int i = 0; i < connmap.count; i++) {
		close(connmap.data[i].linkfd);
	}
	free(connmap.data);
	return retcode;
}

int run_server(const char *socket_path, const char *wayland_display,
		const char *control_path, const struct main_config *config,
		bool oneshot, bool unlink_at_end, const char *application,
		char *const app_argv[])
{
	wp_debug("I'm a server on %s, running: %s", socket_path, app_argv[0]);

	if (strlen(socket_path) >=
			sizeof(((struct sockaddr_un *)NULL)->sun_path)) {
		wp_error("Socket path is too long and would be truncated: %s",
				socket_path);
		return EXIT_FAILURE;
	}
	char display_path[256];
	if (!oneshot) {
		if (wayland_display[0] == '/') {
			snprintf(display_path, 256, "%s", wayland_display);
		} else {
			const char *xdg_dir = getenv("XDG_RUNTIME_DIR");
			if (!xdg_dir) {
				wp_error("Env. var XDG_RUNTIME_DIR not available, cannot place display socket for WAYLAND_DISPLAY=\"%s\"",
						wayland_display);
				return EXIT_FAILURE;
			}
			snprintf(display_path, 256, "%s/%s", xdg_dir,
					wayland_display);
		}
	}

	// Setup connection to program
	int wayland_socket = -1, server_link = -1, wdisplay_socket = -1;
	if (oneshot) {
		int csockpair[2];
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, csockpair) == -1) {
			wp_error("Socketpair failed: %s", strerror(errno));
			return EXIT_FAILURE;
		}
		wayland_socket = csockpair[1];
		server_link = csockpair[0];
	} else {
		// Bind a socket for WAYLAND_DISPLAY, and listen
		int nmaxclients = 128;
		wdisplay_socket = setup_nb_socket(display_path, nmaxclients);
		if (wdisplay_socket == -1) {
			// Error messages already made
			return EXIT_FAILURE;
		}
	}

	// Launch program
	pid_t pid = fork();
	if (pid == -1) {
		wp_error("Fork failed");
		if (!oneshot) {
			unlink(display_path);
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
			close(server_link);
		} else {
			// Since Wayland 1.15, absolute paths are supported in
			// WAYLAND_DISPLAY
			unsetenv("WAYLAND_SOCKET");
			setenv("WAYLAND_DISPLAY", wayland_display, 1);
			close(wdisplay_socket);
		}

		execvp(application, app_argv);
		wp_error("Failed to execvp \'%s\': %s", application,
				strerror(errno));
		return EXIT_FAILURE;
	}
	if (oneshot) {
		// We no longer need to see this side
		close(wayland_socket);
	}

	int control_pipe = -1;
	if (control_path) {
		if (mkfifo(control_path, 0644) == -1) {
			wp_error("Failed to make a control FIFO at %s: %s",
					control_path, strerror(errno));
		} else {
			/* To prevent getting POLLHUP spam after the first user
			 * closes this pipe, open both read and write ends of
			 * the named pipe */
			control_pipe = open(control_path, O_RDWR | O_NONBLOCK);
			if (control_pipe == -1) {
				wp_error("Failed to open created FIFO for reading: %s",
						control_path, strerror(errno));
			}
		}
	}

	int retcode = EXIT_SUCCESS;
	/* These functions will close server_link, wdisplay_socket, and
	 * control_pipe */
	if (oneshot) {
		retcode = run_single_server(control_pipe, socket_path,
				unlink_at_end, server_link, config);
	} else {
		retcode = run_multi_server(control_pipe, socket_path,
				unlink_at_end, wdisplay_socket, config, &pid);
	}
	if (control_pipe != -1) {
		unlink(control_path);
	}

	// Wait for child processes to exit
	wp_debug("Waiting for child handlers and program");

	int status = -1;
	if (wait_for_pid_and_clean(
			    &pid, &status, shutdown_flag ? WNOHANG : 0, NULL)) {
		wp_debug("Child program has died, exiting");
		retcode = WEXITSTATUS(status);
	}
	wp_debug("Program ended");
	return retcode;
}
