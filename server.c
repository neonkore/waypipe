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

/* Closes both provided file descriptors */
static int run_server_child(int chanfd, int appfd)
{
	int maxmsg = 4096;
	char *buffer = calloc(1, maxmsg + 1);
	struct fd_translation_map fdtransmap = {
			.local_sign = -1, .list = NULL, .max_local_id = 1};
	struct message_tracker mtracker;
	init_message_tracker(&mtracker);
	struct pollfd *pfds = NULL;
	while (!shutdown_flag) {
		int npoll = 2 + count_npipes(&fdtransmap);
		free(pfds);
		// todo: resizing logic
		pfds = calloc(npoll, sizeof(struct pollfd));
		pfds[0].fd = chanfd;
		pfds[0].events = POLL_IN;
		pfds[1].fd = appfd;
		pfds[1].events = POLL_IN;
		fill_with_pipes(&fdtransmap, pfds + 2);

		int r = poll(pfds, (nfds_t)npoll, -1);
		if (r == -1) {
			if (errno == EINTR) {
				wp_log(WP_ERROR,
						"poll interrupted: shutdown=%c\n",
						shutdown_flag ? 'Y' : 'n');
			} else {
				wp_log(WP_ERROR,
						"poll failed due to, stopping: %s\n",
						strerror(errno));
				break;
			}
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
				parse_and_prune_messages(&mtracker, &fdtransmap,
						false, false, waymsg, &waylen,
						fds, &nids);
			}

			if (waymsg) {
				ssize_t wc = iovec_write(appfd, waymsg, waylen,
						fds, nids);
				decref_transferred_fds(&fdtransmap, nids, fds);
				free(tmpbuf);
				if (wc == -1) {
					wp_log(WP_ERROR,
							"appfd write failure %ld: %s\n",
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
			ssize_t rc = iovec_read(appfd, buffer, maxmsg, fdbuf,
					&nfds, 28);
			if (rc == -1) {
				wp_log(WP_ERROR, "appfd read failure %ld: %s\n",
						rc, strerror(errno));
				break;
			}
			if (rc > 0) {
				translate_fds(&fdtransmap, nfds, fdbuf, ids);

				int nrc = (int)rc;
				parse_and_prune_messages(&mtracker, &fdtransmap,
						false, true, buffer, &nrc,
						fdbuf, &nfds);
				rc = nrc;
			}
			if (rc > 0) {
				wp_log(WP_DEBUG,
						"appfd: read %ld byte waymsg, %d fds\n",
						rc, nfds);

				transfers[0].obj_id = 0;
				transfers[0].size = (size_t)rc;
				transfers[0].data = buffer;
				transfers[0].type = FDC_UNKNOWN;
				ntransfers = 1;
			} else {
				wp_log(WP_DEBUG, "The client shut down\n");
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
			decref_transferred_rids(&fdtransmap, nfds, ids);
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
	cleanup_message_tracker(&mtracker);
	close(chanfd);
	close(appfd);
	free(buffer);
	return EXIT_SUCCESS;
}

static int connect_to_channel(const char *socket_path)
{
	struct sockaddr_un saddr;
	int chanfd;
	saddr.sun_family = AF_UNIX;
	strncpy(saddr.sun_path, socket_path, sizeof(saddr.sun_path) - 1);
	chanfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (chanfd == -1) {
		wp_log(WP_ERROR, "Error creating socket: %s\n",
				strerror(errno));
		return -1;
	}

	if (connect(chanfd, (struct sockaddr *)&saddr, sizeof(saddr)) == -1) {
		wp_log(WP_ERROR, "Error connecting to socket (%s): %s\n",
				socket_path, strerror(errno));
		close(chanfd);
		return -1;
	}
	return chanfd;
}

int run_server(const char *socket_path, bool oneshot, bool unlink_at_end,
		char *const app_argv[])
{
	wp_log(WP_DEBUG, "I'm a server on %s, running: %s\n", socket_path,
			app_argv[0]);

	if (strlen(socket_path) >=
			sizeof(((struct sockaddr_un *)NULL)->sun_path)) {
		wp_log(WP_ERROR,
				"Socket path is too long and would be truncated: %s\n",
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
			wp_log(WP_ERROR, "Socketpair failed: %s\n",
					strerror(errno));
			return EXIT_FAILURE;
		}
		if (set_fnctl_flag(csockpair[0], FD_CLOEXEC) == -1) {
			wp_log(WP_ERROR, "Fnctl failed: %s\n", strerror(errno));
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
		wp_log(WP_ERROR, "Fork failed\n");
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

		execvp(app_argv[0], app_argv);
		wp_log(WP_ERROR, "Failed to execvp \'%s\': %s\n", app_argv[0],
				strerror(errno));
		return EXIT_FAILURE;
	}
	if (oneshot) {
		// We no longer need to see this side
		close(wayland_socket);
	}

	wp_log(WP_DEBUG, "Server main!\n");

	int retval = EXIT_SUCCESS;
	if (oneshot) {
		int chanfd = connect_to_channel(socket_path);
		if (unlink_at_end) {
			unlink(socket_path);
		}

		wp_log(WP_DEBUG, "Oneshot connected\n");
		if (chanfd != -1) {
			retval = run_server_child(chanfd, server_link);
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
						"Child program has died, exiting\n");
				retval = EXIT_SUCCESS;
				break;
			} else if (wp == -1) {
				wp_log(WP_ERROR, "Failed in waitpid: %s\n",
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
				fprintf(stderr, "Poll failed: %s\n",
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
				wp_log(WP_ERROR, "Connection failure: %s\n",
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
					run_server_child(chanfd, appfd);
					return EXIT_SUCCESS;
				} else if (npid == -1) {
					wp_log(WP_DEBUG, "Fork failure\n");
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
		wp_log(WP_DEBUG, "Waiting for child handlers\n");
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
	// todo: scope manipulation, to ensure all cleanups are done
	wp_log(WP_DEBUG, "Waiting for child process\n");
	waitpid(pid, NULL, shutdown_flag ? WNOHANG : 0);
	wp_log(WP_DEBUG, "Program ended\n");
	return retval;
}
