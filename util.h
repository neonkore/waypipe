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
#ifndef WAYPIPE_UTIL_H
#define WAYPIPE_UTIL_H

#include <stddef.h>
#include <stdint.h>

int iovec_read(int socket, char *buf, size_t buflen, int *fds, int *numfds);
int iovec_write(int conn, char *buf, size_t buflen, int *fds, int *numfds);
int chan_write(int conn, char *buf, size_t buflen);

void identify_fd(int fd);

typedef enum { WP_DEBUG = 1, WP_ERROR = 2 } log_cat_t;
// void wp_log(log_cat_t cat, );

extern log_cat_t wp_loglevel;

// mutates a static local, hence can only be called singlethreaded
const char *static_timestamp(void);

// no trailing ;, user must supply
#define wp_log(level, fmt, ...)                                                \
	if ((level) >= wp_loglevel)                                            \
	fprintf(stderr, "%s [%s:%3d] " fmt, static_timestamp(), __FILE__,      \
			__LINE__, ##__VA_ARGS__)

struct muxheader {
	int metadata;
	int length;
};

#endif // WAYPIPE_UTIL_H
