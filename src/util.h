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

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/uio.h>

#include "config-waypipe.h"
#include "kernel.h"

#ifdef HAS_USDT
#include <sys/sdt.h>
#else
#define DTRACE_PROBE(provider, probe) (void)0
#define DTRACE_PROBE1(provider, probe, parm1) (void)0
#define DTRACE_PROBE2(provider, probe, parm1, parm2) (void)0
#define DTRACE_PROBE3(provider, probe, parm1, parm2, parm3) (void)0
#endif

// On SIGINT, this is set to true. The main program should then cleanup ASAP
extern bool shutdown_flag;

void handle_sigint(int sig);

/** Basic mathematical operations. */ // use macros?
static inline int max(int a, int b) { return a > b ? a : b; }
static inline int min(int a, int b) { return a < b ? a : b; }
static inline uint64_t maxu(uint64_t a, uint64_t b) { return a > b ? a : b; }
static inline uint64_t minu(uint64_t a, uint64_t b) { return a < b ? a : b; }
static inline int clamp(int v, int lower, int upper)
{
	return max(min(v, upper), lower);
}
static inline int align(int v, int m) { return m * ((v + m - 1) / m); }
static inline size_t alignz(size_t v, size_t m)
{
	return m * ((v + m - 1) / m);
}
/* only valid for nonegative v and positive u */
static inline int floordiv(int v, int u) { return v / u; }
static inline int ceildiv(int v, int u) { return (v + u - 1) / u; }
/* valid as long as nparts < 2**15, (hi - lo) < 2**31 */
static inline int split_interval(int lo, int hi, int nparts, int index)
{
	return lo + index * ((hi - lo) / nparts) +
	       (index * ((hi - lo) % nparts)) / nparts;
}

/** Make the file underlying this file descriptor nonblocking.
 * Silently return -1 on failure. */
int set_nonblocking(int fd);
/** Create a nonblocking AF_UNIX/SOCK_STREAM socket, and listen with
 * nmaxclients. Prints its own error messages; returns -1 on failure. */
int setup_nb_socket(const char *socket_path, int nmaxclients);
/** Connect to the socket at the given path, returning created fd if
 * successful, else -1.*/
int connect_to_socket(const char *socket_path);
/** Call close(fd), logging error when fd is invalid */
#define checked_close(fd)                                                      \
	if (close(fd) == -1) {                                                 \
		wp_error("close(%d) failed: %s", fd, strerror(errno));         \
	}
/** Verify that all file descriptors (except for stdin/out/errno) are closed */
void check_unclosed_fds(void);

#define WAYPIPE_PROTOCOL_VERSION 0x1u
/** If the byte order is wrong, the fixed set/unset bits are swapped */
#define CONN_FIXED_BIT (0x1u << 7)
#define CONN_UNSET_BIT (0x1u << 31)
#define CONN_RECONNECTABLE_BIT (0x1u << 0)
#define CONN_UPDATE_BIT (0x1u << 1)
struct connection_token {
	/** Indicate protocol version (top 16 bits), endianness, and
	 * reconnection flags. The highest bit must stay clear. */
	uint32_t header;
	uint32_t key[3]; /** Random bits used to identify the connection */
};
/** A type to help keep track of the connection handling processes */
struct conn_addr {
	struct connection_token token;
	pid_t pid;
	int linkfd;
};
struct conn_map {
	struct conn_addr *data;
	int count, size;
};
/** A useful helper routine for lists and stacks. `count` is the number of
 * objects that will be needed; `obj_size` their side; `size_t` the number
 * of objects that the malloc'd data can contain, and `data` the list buffer
 * itself. If count < space, resize the list and update space. Returns -1 on
 * allocation failure */
int buf_ensure_size(int count, size_t obj_size, int *space, void **data);
/** sendmsg a file descriptor over socket */
int send_one_fd(int socket, int fd);

enum log_level { WP_DEBUG = 0, WP_ERROR = 1 };
typedef void (*log_handler_func_t)(const char *file, int line,
		enum log_level level, const char *fmt, ...);
/** a simple log handler to STDOUT for use by test programs */
void test_log_handler(const char *file, int line, enum log_level level,
		const char *fmt, ...);
void test_atomic_log_handler(const char *file, int line, enum log_level level,
		const char *fmt, ...);
/** These log functions should be set by whichever translation units have a
 * 'main'. The first one is the debug handler, second error handler. Set them to
 * NULL to disable log messages. */
extern log_handler_func_t log_funcs[2];

#ifdef WAYPIPE_REL_SRC_DIR
#define WAYPIPE__FILE__                                                        \
	((const char *)__FILE__ + sizeof(WAYPIPE_REL_SRC_DIR) - 1)
#else
#define WAYPIPE__FILE__ __FILE__
#endif
/** No trailing ;, user must supply. The first vararg must be the format string.
 */
#define wp_error(...)                                                          \
	if (log_funcs[WP_ERROR])                                               \
	(*log_funcs[WP_ERROR])(WAYPIPE__FILE__, __LINE__, WP_ERROR, __VA_ARGS__)
#define wp_debug(...)                                                          \
	if (log_funcs[WP_DEBUG])                                               \
	(*log_funcs[WP_DEBUG])(WAYPIPE__FILE__, __LINE__, WP_DEBUG, __VA_ARGS__)

/** Run waitpid in a loop until there are no more zombies to clean up. If the
 * target_pid was one of the completed processes, set status, return true. The
 * `options` flag will be passed to waitpid. If `map` is not NULL, remove
 * entries in the connection map which were closed.
 *
 * The value *target_pid is set to 0 once the corresponding process has died,
 * as a convenience to check only the first child process with pid ==
 * *target_pid.
 */
bool wait_for_pid_and_clean(pid_t *target_pid, int *status, int options,
		struct conn_map *map);

/** An unrecoverable error-- say, running out of file descriptors */
#define ERR_FATAL -1
/** A memory allocation failed; might be fatal, might not be */
#define ERR_NOMEM -2
/** For main loop, channel disconnection */
#define ERR_DISCONN -3
/** For main loop, program disconnection */
#define ERR_STOP -4

/** A helper type, since very often buffers and their sizes are passed together
 * (or returned together) as arguments */
struct bytebuf {
	size_t size;
	char *data;
};
struct char_window {
	char *data;
	int size;
	int zone_start;
	int zone_end;
};
struct int_window {
	int *data;
	int size;
	int zone_start;
	int zone_end;
};

/**
 * @brief Wire format message types
 *
 * Each message indicates what the receiving side should do.
 */
enum wmsg_type {
	/** Send over a set of Wayland protocol messages. Preceding messages
	 * must create or update file descriptors and inject file descriptors
	 * to the queue. */
	// TODO: use extra bits to make parsing more consistent between systems;
	// i.e, to ensure that # of file descriptors consumed is the same
	WMSG_PROTOCOL, // header uint32_t, then protocol messages
	/** Inject file descriptors into the receiver's buffer, for use by the
	 * protocol parser. */
	WMSG_INJECT_RIDS, // header uint32_t, then fds
	/** Create a new shared memory file of the given size.
	 * Format: \ref wmsg_open_file */
	WMSG_OPEN_FILE,
	/** Provide a new (larger) size for the file buffer.
	 * Format: \ref wmsg_open_file */
	WMSG_EXTEND_FILE,
	/** Create a new DMABUF with the given size and \ref dmabuf_slice_data.
	 * Format: \ref wmsg_open_dmabuf */
	WMSG_OPEN_DMABUF,
	/** Fill the region of the file with the folllowing data. The data
	 * should be compressed according to the global compression option.
	 * Format: \ref wmsg_buffer_fill */
	WMSG_BUFFER_FILL,
	/** Apply a diff to the file. The diff contents may be compressed.
	 * Format: \ref wmsg_buffer_diff */
	WMSG_BUFFER_DIFF,
	/** Create a new pipe, with the given remote R/W status */
	WMSG_OPEN_IR_PIPE, // wmsg_basic
	WMSG_OPEN_IW_PIPE, // wmsg_basic
	WMSG_OPEN_RW_PIPE, // wmsg_basic
	/** Transfer data to the pipe */
	WMSG_PIPE_TRANSFER, // wmsg_basic
	/** Shutdown the read end of the pipe that waypipe uses. */
	WMSG_PIPE_SHUTDOWN_R, // wmsg_basic
	/** Shutdown the write end of the pipe that waypipe uses. */
	WMSG_PIPE_SHUTDOWN_W, // wmsg_basic
	/** Create a DMABUF (with following data parameters) that will be used
	 * to produce/consume video frames. Format: \ref wmsg_open_dmabuf */
	WMSG_OPEN_DMAVID_SRC,
	WMSG_OPEN_DMAVID_DST,
	/** Send a packet of video data to the destination */
	WMSG_SEND_DMAVID_PACKET, // wmsg_basic
	/** Acknowledge that a given number of messages has been received, so
	 * that the sender of those messages no longer needs to store them
	 * for replaying in case of reconnection. Format: \ref wmsg_ack */
	WMSG_ACK_NBLOCKS,
	/** When restarting a connection, indicate the number of the message
	 * which will be sent next. Format: \ref wmsg_restart */
	WMSG_RESTART, // wmsg_restart
	/** When the remote program is closing. Format: only the header */
	WMSG_CLOSE,
};
const char *wmsg_type_to_str(enum wmsg_type tp);
struct wmsg_open_file {
	uint32_t size_and_type;
	int32_t remote_id;
	uint32_t file_size;
};
struct wmsg_open_dmabuf {
	uint32_t size_and_type;
	int32_t remote_id;
	uint32_t file_size;
	/* following this, provide struct dmabuf_slice_data */
};
struct wmsg_buffer_fill {
	uint32_t size_and_type;
	int32_t remote_id;
	uint32_t start; /**< [start, end), in bytes of zone to be written */
	uint32_t end;
	/* following this, the possibly-compressed data */
};
struct wmsg_buffer_diff {
	uint32_t size_and_type;
	int32_t remote_id;
	uint32_t diff_size; /**< in bytes, when uncompressed */
	uint32_t ntrailing; /**< number of 'trailing' bytes, copied to tail */
	/* following this, the possibly-compressed diff  data */
};
struct wmsg_basic {
	uint32_t size_and_type;
	int32_t remote_id;
};
struct wmsg_ack {
	uint32_t size_and_type;
	uint32_t messages_received;
};
struct wmsg_restart {
	uint32_t size_and_type;
	uint32_t last_ack_received;
};
/** size: the number of bytes in the message, /excluding/ trailing padding. */
static inline uint32_t transfer_header(size_t size, enum wmsg_type type)
{
	return ((uint32_t)size << 5) | (uint32_t)type;
}
static inline size_t transfer_size(uint32_t header)
{
	return (size_t)header >> 5;
}
static inline enum wmsg_type transfer_type(uint32_t header)
{
	return (enum wmsg_type)(header & ((1u << 5) - 1));
}

/** Worker tasks write their resulting messages to this receive buffer,
 * and the main thread periodically checks the messages and appends the results
 * to the main thread. */
struct thread_msg_recv_buf {
	// TODO: make this lock free, using the fact that valid iovecs have
	// nonzero fields
	struct iovec *data;
	/** [zone_start, zone_end] contains the set of entries which might
	 * contain data */
	int zone_start, zone_end, size;
	pthread_mutex_t lock;
};

/** A queue of data blocks to be written to the channel. This should only
 * be used by the main thread; worker tasks should write to a \ref
 * thread_msg_recv_buf, from which the main thread should in turn collect data
 */
struct transfer_queue {
	/** Data to be writtenveed */
	struct iovec *vecs;
	/** Matching vector indicating to which message the corresponding data
	 * block belongs. */
	uint32_t *msgnos;
	/** start: next block to write. end: just after last block to write;
	 * size: number of iovec blocks */
	int start, end, size;
	/** How much of the block at 'start' has been written */
	size_t partial_write_amt;
	/** The most recent message number, to be incremented after almost all
	 * message types */
	uint32_t last_msgno;
	/** Messages added from a worker thread are introduced here, and should
	 * be periodically copied onto the main queue */
	struct thread_msg_recv_buf async_recv_queue;
};

/** Add transfer message to the queue, expanding the queue as necessary. */
int transfer_add(struct transfer_queue *transfers, size_t size, void *data,
		bool is_ack_msg);
/** Destroy the transfer queue, deallocating all attached buffers */
void cleanup_transfer_queue(struct transfer_queue *transfers);
/** Move any asynchronously loaded messages to the queue */
int transfer_load_async(struct transfer_queue *w);
/** Add a message to the async queue */
void transfer_async_add(struct thread_msg_recv_buf *q, void *data, size_t sz);

/* Functions that are unsually platform specific */
int create_anon_file(void);
int get_hardware_thread_count(void);
int get_iov_max(void);

#endif // WAYPIPE_UTIL_H
