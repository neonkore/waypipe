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

// On SIGINT, this is set to true. The main program should then cleanup ASAP
extern bool shutdown_flag;

void handle_sigint(int sig);

/** Set the given flag with fcntl. Silently return -1 on failure. */
int set_fnctl_flag(int fd, int the_flag);
/** Create a nonblocking AF_UNIX/SOCK_STREAM socket, and listen with
 * nmaxclients. Prints its own error messages; returns -1 on failure. */
int setup_nb_socket(const char *socket_path, int nmaxclients);

ssize_t iovec_read(int socket, char *buf, size_t buflen, int *fds, int *numfds,
		int maxfds);
ssize_t iovec_write(int conn, const char *buf, size_t buflen, const int *fds,
		int numfds);

typedef enum { WP_DEBUG = 1, WP_ERROR = 2 } log_cat_t;

extern char waypipe_log_mode;
extern log_cat_t waypipe_loglevel;

// mutates a static local, hence can only be called singlethreaded
const char *static_timestamp(void);

#ifndef WAYPIPE_SRC_DIR_LENGTH
#define WAYPIPE_SRC_DIR_LENGTH 0
#endif
// no trailing ;, user must supply
#define wp_log(level, fmt, ...)                                                \
	if ((level) >= waypipe_loglevel)                                       \
	fprintf(stderr, "%c%d:%s [%s:%3d] " fmt, waypipe_log_mode, getpid(),   \
			static_timestamp(),                                    \
			((const char *)__FILE__) + WAYPIPE_SRC_DIR_LENGTH,     \
			__LINE__, ##__VA_ARGS__)

struct fd_translation_map {
	struct shadow_fd *list;
	int max_local_id;
	int local_sign;
};

// TODO: evtly, FDC_DMABUF and more complicated emulation types
typedef enum {
	FDC_UNKNOWN,
	FDC_FILE,
	FDC_PIPE_IR,
	FDC_PIPE_IW,
	FDC_PIPE_RW
} fdcat_t;
bool fdcat_ispipe(fdcat_t t);

struct pipe_buffer {
	void *data;
	ssize_t size;
	ssize_t used;
};

struct shadow_fd {
	struct shadow_fd *next; // singly-linked list
	fdcat_t type;
	int remote_id; // + if created serverside; - if created clientside
	int fd_local;
	// File data
	size_t file_size;
	char *file_mem_local;   // mmap'd
	char *file_mem_mirror;  // malloc'd
	char *file_diff_buffer; // malloc'd
	char file_shm_buf_name[256];
	// Pipe data
	struct pipe_buffer pipe_send;
	struct pipe_buffer pipe_recv;
	/* this is a pipe end we can read/write from. It only sometimes
	 * equals fd_local */
	int pipe_fd;
	bool pipe_readable, pipe_writable, pipe_onlyhere;
	// pipe closure (as in, POLLHUP, other end writeclose) -> statemachine?
	bool pipe_lclosed, pipe_rclosed;
};

struct transfer {
	size_t size;
	fdcat_t type;
	char *data;
	int obj_id;
	int special; // type-specific extra data
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
void pack_pipe_message(size_t *msglen, char **msg, int nids, const int ids[],
		int ntransfers, const struct transfer transfers[]);
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

/** Count the number of pipe fds being maintained by the translation map */
int count_npipes(const struct fd_translation_map *map);
/** Fill in pollfd entries, with POLL_IN | POLLOUT */
struct pollfd;
void fill_with_pipes(const struct fd_translation_map *map, struct pollfd *pfds);

/** mark pipe shadows as being ready to read or write */
void mark_pipe_object_statuses(
		struct fd_translation_map *map, int nfds, struct pollfd *pfds);
/** For pipes marked writeable, flush as much buffered data as possible */
void flush_writable_pipes(struct fd_translation_map *map);
/** For pipes marked readable, read as much data as possible without blocking */
void read_readable_pipes(struct fd_translation_map *map);
/** pipe file descriptors should never be removed, since then close-detection
 * fails. This closes the second pipe ends if we own both of them */
void close_local_pipe_ends(struct fd_translation_map *map);
/** If a pipe is remotely closed, but not locally closed, then close it too */
void close_rclosed_pipes(struct fd_translation_map *map);

struct kstack {
	struct kstack *nxt;
	pid_t pid;
};

void wait_on_children(struct kstack **children, int options);

#endif // WAYPIPE_UTIL_H
