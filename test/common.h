/*
 * Copyright © 2021 Manuel Stoeckl
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
#ifndef WAYPIPE_TESTCOMMON_H
#define WAYPIPE_TESTCOMMON_H

#include "main.h"
#include "parsing.h"
#include "util.h"

/** a simple log handler to STDOUT for use by test programs */
void test_log_handler(const char *file, int line, enum log_level level,
		const char *fmt, ...);
void test_atomic_log_handler(const char *file, int line, enum log_level level,
		const char *fmt, ...);

extern uint64_t time_value;
extern uint64_t local_time_offset;

void *read_file_into_mem(const char *path, size_t *len);
struct msg {
	uint32_t *data;
	int len;
	int *fds;
	int nfds;
};
struct test_state {
	struct main_config config;
	struct globals glob;
	bool display_side;
	bool failed;
	/* messages received from the other side */
	int nrcvd;
	struct msg *rcvd;
	uint64_t local_time_offset;
};

void send_wayland_msg(struct test_state *src, const struct msg msg,
		struct transfer_queue *queue);
void receive_wire(struct test_state *src, struct transfer_queue *queue);

void send_protocol_msg(struct test_state *src, struct test_state *dst,
		const struct msg msg);
int setup_state(struct test_state *s, bool display_side, bool has_gpu);
void cleanup_state(struct test_state *s);

#endif /* WAYPIPE_TESTCOMMON_H */
