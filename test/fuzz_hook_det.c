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

log_handler_func_t log_funcs[2] = {NULL, NULL};
int main(int argc, char **argv)
{
	if (argc == 1 || !strcmp(argv[1], "--help")) {
		printf("Usage: ./fuzz_hook_det [--server] [--log] {input_file}\n");
		printf("A program to run and control Wayland and channel inputs for core Waypipe operations\n");
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

	size_t len;
	char *buf = read_file_into_mem(argv[1], &len);
	if (!buf) {
		return EXIT_FAILURE;
	}
	printf("Loaded %zu bytes\n", len);

	struct test_state ts;
	if (setup_state(&ts, display_side, true) == -1) {
		return -1;
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

		struct transfer_queue transfers;
		memset(&transfers, 0, sizeof(transfers));
		pthread_mutex_init(&transfers.async_recv_queue.lock, NULL);

		if (wayland_side) {
			/* Send a message (incl fds) */
			struct msg m;
			m.data = &data[cursor];
			m.len = (int)packet_size;
			if (new_fileno != -1) {
				m.fds = &new_fileno;
				m.nfds = 1;
			} else {
				m.fds = NULL;
				m.nfds = 0;
			}
			send_wayland_msg(&ts, m, &transfers);
			/* ignore any created transfers, since this is only
			 * a test of one side */
		} else {
			/* Send a transfer */
			void *msg_copy = calloc(packet_size, 4);
			memcpy(msg_copy, &data[cursor], packet_size * 4);
			transfer_add(&transfers, packet_size * 4, msg_copy);
			receive_wire(&ts, &transfers);
		}
		cleanup_transfer_queue(&transfers);

		cursor += packet_size;
	}

	cleanup_state(&ts);

	free(buf);
	free(ignore_buf);
	return EXIT_SUCCESS;
}
