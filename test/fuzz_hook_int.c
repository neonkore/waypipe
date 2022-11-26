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

#include "common.h"
#include "main.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <pthread.h>

struct copy_setup {
	int conn;
	int wayl;
	bool is_display_side;
	struct main_config *mc;
};

static void *start_looper(void *data)
{
	struct copy_setup *setup = (struct copy_setup *)data;
	main_interface_loop(setup->conn, setup->wayl, -1, setup->mc,
			setup->is_display_side);
	return NULL;
}

log_handler_func_t log_funcs[2] = {NULL, NULL};
int main(int argc, char **argv)
{
	if (argc == 1 || !strcmp(argv[1], "--help")) {
		printf("Usage: ./fuzz_hook_int [--server] [--log] {input_file}\n");
		printf("A program to run and control Wayland and channel inputs for a waypipe main loop\n");
		return EXIT_FAILURE;
	}
	bool display_side = true;
	if (argc > 1 && !strcmp(argv[1], "--server")) {
		display_side = false;
		argc--;
		argv++;
	}
	if (argc > 1 && !strcmp(argv[1], "--log")) {
		log_funcs[0] = test_atomic_log_handler;
		log_funcs[1] = test_atomic_log_handler;
		argc--;
		argv++;
	}
	setup_video_logging();

	size_t len;
	char *buf = read_file_into_mem(argv[1], &len);
	if (!buf) {
		return EXIT_FAILURE;
	}
	printf("Loaded %zu bytes\n", len);

	int way_fds[2], conn_fds[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, way_fds) == -1 ||
			socketpair(AF_UNIX, SOCK_STREAM, 0, conn_fds) == -1) {
		printf("Socketpair failed\n");
		return EXIT_FAILURE;
	}

	struct main_config config = {
			.drm_node = NULL,
			.n_worker_threads = 1,
			.compression = COMP_NONE,
			.compression_level = 0,
			.no_gpu = true, /* until we can construct dmabufs here
					 */
			.only_linear_dmabuf = false,
			.video_if_possible = true,
			.prefer_hwvideo = false,
	};

	pthread_t thread;
	struct copy_setup conf = {.conn = conn_fds[1],
			.wayl = way_fds[1],
			.is_display_side = display_side,
			.mc = &config};
	if (pthread_create(&thread, NULL, start_looper, &conf) == -1) {
		printf("Thread failed\n");
		return EXIT_FAILURE;
	}

	char *ignore_buf = malloc(65536);

	/* Main loop: RW from socketpairs with sendmsg, with short wait */
	int64_t file_nwords = (int64_t)len / 4;
	int64_t cursor = 0;
	uint32_t *data = (uint32_t *)buf;
	while (cursor < file_nwords) {
		uint32_t header = data[cursor++];
		bool wayland_side = header & 0x1;
		bool add_file = header & 0x2;
		int new_fileno = -1;

		if (add_file && wayland_side && cursor < file_nwords) {
			uint32_t fsize = data[cursor++];
			if (fsize == 0) {
				/* 'copy' sink */
				new_fileno = open("/dev/null",
						O_WRONLY | O_NOCTTY);
				if (new_fileno == -1) {
					wp_error("Failed to open /dev/null");
				}
			} else {
				/* avoid buffer overflow */
				fsize = fsize > 1000000 ? 1000000 : fsize;
				new_fileno = create_anon_file();
				if (ftruncate(new_fileno, (off_t)fsize) == -1) {
					wp_error("Failed to resize tempfile");
					checked_close(new_fileno);
					break;
				}
			}
		}

		uint32_t packet_size = header >> 2;
		int64_t words_left = file_nwords - cursor;
		if (packet_size > 2048) {
			packet_size = 2048;
		}
		if (packet_size > (uint32_t)words_left) {
			packet_size = (uint32_t)words_left;
		}
		/* 2 msec max delay for 8KB of data, assuming no system
		 * interference, should be easily attainable */
		int max_write_delay_ms = 1;
		int max_read_delay_ms = 2;

		int send_fd = wayland_side ? way_fds[0] : conn_fds[0];
		/* Write packet to stream */
		struct pollfd write_pfd;
		write_pfd.fd = send_fd;
		write_pfd.events = POLLOUT;
		int nw;
	retry_poll:
		nw = poll(&write_pfd, 1, max_write_delay_ms);
		if (nw == -1) {
			if (new_fileno != -1) {
				checked_close(new_fileno);
			}

			if (errno == EINTR) {
				goto retry_poll;
			}
			printf("Poll error\n");
			break;
		} else if (nw == 1 && wayland_side) {
			/* Send message */
			struct iovec the_iovec;
			the_iovec.iov_len = packet_size * 4;
			the_iovec.iov_base = (char *)&data[cursor];
			struct msghdr msg;
			msg.msg_name = NULL;
			msg.msg_namelen = 0;
			msg.msg_iov = &the_iovec;
			msg.msg_iovlen = 1;
			msg.msg_control = NULL;
			msg.msg_controllen = 0;
			msg.msg_flags = 0;

			union {
				char buf[CMSG_SPACE(sizeof(int))];
				struct cmsghdr align;
			} uc;
			memset(uc.buf, 0, sizeof(uc.buf));

			if (new_fileno != -1) {
				msg.msg_control = uc.buf;
				msg.msg_controllen = sizeof(uc.buf);
				struct cmsghdr *frst = CMSG_FIRSTHDR(&msg);
				frst->cmsg_level = SOL_SOCKET;
				frst->cmsg_type = SCM_RIGHTS;
				memcpy(CMSG_DATA(frst), &new_fileno,
						sizeof(int));
				frst->cmsg_len = CMSG_LEN(sizeof(int));
				msg.msg_controllen = CMSG_SPACE(sizeof(int));
			}

			ssize_t ret = sendmsg(way_fds[0], &msg, 0);
			if (ret == -1) {
				wp_error("Error in sendmsg");
				break;
			}
		} else if (nw == 1 && !wayland_side) {
			ssize_t ret = write(conn_fds[0], (char *)&data[cursor],
					packet_size * 4);
			if (ret == -1) {
				wp_error("Error in write");
				break;
			}
		} else {
			wp_error("Failed to send message before timeout");
		}
		if (new_fileno != -1) {
			checked_close(new_fileno);
		}

		/* Wait up to max_delay for a response. Almost all packets
		 * should be passed on unmodified; a very small fraction
		 * are dropped */
		struct pollfd read_pfds[2];
		read_pfds[0].fd = way_fds[0];
		read_pfds[1].fd = conn_fds[0];
		read_pfds[0].events = POLLIN;
		read_pfds[1].events = POLLIN;
		int nr = poll(read_pfds, 2,
				packet_size > 0 ? max_read_delay_ms : 0);
		if (nr == -1) {
			if (errno == EINTR) {
				continue;
			}
			printf("Poll error\n");
			break;
		} else if (nr == 0) {
			wp_debug("No reply to sent packet %d", packet_size);
		}
		for (int i = 0; i < 2; i++) {
			if (read_pfds[i].revents & POLLIN) {
				char cmsgdata[(CMSG_LEN(28 * sizeof(int32_t)))];
				struct iovec the_iovec;
				the_iovec.iov_len = 65536;
				the_iovec.iov_base = ignore_buf;
				struct msghdr msg;
				msg.msg_name = NULL;
				msg.msg_namelen = 0;
				msg.msg_iov = &the_iovec;
				msg.msg_iovlen = 1;
				msg.msg_control = &cmsgdata;
				msg.msg_controllen = sizeof(cmsgdata);
				msg.msg_flags = 0;
				ssize_t ret = recvmsg(read_pfds[i].fd, &msg, 0);
				if (ret == -1) {
					wp_error("Error in recvmsg");
				}
			}
		}

		cursor += packet_size;
	}
	checked_close(conn_fds[0]);
	checked_close(way_fds[0]);

	pthread_join(thread, NULL);

	free(buf);
	free(ignore_buf);
	return EXIT_SUCCESS;
}
