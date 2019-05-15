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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

ssize_t iovec_read(int socket, char *buf, size_t buflen, int *fds, int *numfds);
ssize_t iovec_write(int conn, const char *buf, size_t buflen, const int *fds,
		int numfds);

typedef enum { WP_DEBUG = 1, WP_ERROR = 2 } log_cat_t;
// void wp_log(log_cat_t cat, );

extern log_cat_t waypipe_loglevel;

// mutates a static local, hence can only be called singlethreaded
const char *static_timestamp(void);

// no trailing ;, user must supply
#ifndef WAYPIPE_SRC_DIR_LENGTH
#define WAYPIPE_SRC_DIR_LENGTH 0
#endif
#define wp_log(level, fmt, ...)                                                \
	if ((level) >= waypipe_loglevel)                                       \
	fprintf(stderr, "%s [%s:%3d] " fmt, static_timestamp(),                \
			((const char *)__FILE__) + WAYPIPE_SRC_DIR_LENGTH,     \
			__LINE__, ##__VA_ARGS__)

struct fd_translation_map {
	struct shadow_fd *list;
	int max_local_id;
	int local_sign;
};

struct shadow_fd {
	struct shadow_fd *next; // singly-linked list
	int remote_id; // + if created serverside; - if created clientside
	size_t memsize;
	int fd_local;
	char *mem_local;   // mmap'd
	char *mem_mirror;  // malloc'd
	char *diff_buffer; // malloc'd
	char shm_buf_name[256];
};

struct transfer {
	size_t size;
	char *data;
	int obj_id;
};

void cleanup_translation_map(struct fd_translation_map *map);

/** Given a list of local file descriptors, produce matching global ids, and
 * register them into the translation map if not already done. */
void translate_fds(struct fd_translation_map *map, int nfds, const int fds[],
		int ids[]);
/** Produce a list of file updates to transfer. All pointers will be to existing
 * memory. */
void collect_updates(struct fd_translation_map *map, int *ntransfers,
		struct transfer transfers[]);
/** Allocate a large new buffer to contain message data, the id list, and file
 * updates. The buffer includes the size_t at the beginning, which indicates
 * the tail size */
void pack_pipe_message(size_t *msglen, char **msg, int waylen,
		const char *waymsg, int nids, const int ids[], int ntransfers,
		const struct transfer transfers[]);
/** Unpack the buffer containing message data, the id list, and file updates.
 * All returned pointers refer to positions in the source buffer. */
void unpack_pipe_message(size_t msglen, const char *msg, int *waylen,
		char **waymsg, int *nids, int ids[], int *ntransfers,
		struct transfer transfers[]);
/** Given a list of global ids, and an up-to-date translation map, produce local
 * file descriptors */
void untranslate_ids(struct fd_translation_map *map, int nids, const int ids[],
		int fds[]);
/** Apply file updates to the translation map, creating entries when there are
 * none */
void apply_updates(struct fd_translation_map *map, int ntransfers,
		const struct transfer transfers[]);

/** Read the contents of a packed message into a newly allocated buffer */
ssize_t read_size_then_buf(int fd, char **msg);

#endif // WAYPIPE_UTIL_H
