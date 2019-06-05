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
#include <unistd.h>

// On SIGINT, this is set to true. The main program should then cleanup ASAP
extern bool shutdown_flag;

void handle_sigint(int sig);

/** Basic mathematical operations */
static inline int max(int a, int b) { return a > b ? a : b; }
static inline int min(int a, int b) { return a < b ? a : b; }
static inline int clamp(int v, int lower, int upper)
{
	return max(min(v, upper), lower);
}
static inline int align(int v, int m) { return m * ((v + m - 1) / m); }

/** Set the given flag with fcntl. Silently return -1 on failure. */
int set_fnctl_flag(int fd, int the_flag);
/** Create a nonblocking AF_UNIX/SOCK_STREAM socket, and listen with
 * nmaxclients. Prints its own error messages; returns -1 on failure. */
int setup_nb_socket(const char *socket_path, int nmaxclients);

ssize_t iovec_read(int socket, char *buf, size_t buflen, int *fds, int *numfds,
		int maxfds);
ssize_t iovec_write(int conn, const char *buf, size_t buflen, const int *fds,
		int numfds, int *nfds_written);

int main_interface_loop(int chanfd, int progfd, bool no_gpu, bool display_side);

typedef enum { WP_DEBUG = 1, WP_ERROR = 2 } log_cat_t;

extern char waypipe_log_mode;
extern log_cat_t waypipe_loglevel;

void wp_log_handler(const char *file, int line, log_cat_t level,
		const char *fmt, ...);

#ifndef WAYPIPE_SRC_DIR_LENGTH
#define WAYPIPE_SRC_DIR_LENGTH 0
#endif
// no trailing ;, user must supply
#define wp_log(level, fmt, ...)                                                \
	if ((level) >= waypipe_loglevel)                                       \
	wp_log_handler(((const char *)__FILE__) + WAYPIPE_SRC_DIR_LENGTH,      \
			__LINE__, (level), fmt, ##__VA_ARGS__)

struct render_data {
	bool disabled;
	int drm_fd;
	struct gbm_device *dev;
};
struct fd_translation_map {
	struct shadow_fd *list;
	int max_local_id;
	int local_sign;
	struct render_data rdata;
};

// TODO: evtly, FDC_DMABUF and more complicated emulation types
typedef enum {
	FDC_UNKNOWN,
	FDC_FILE,
	FDC_PIPE_IR,
	FDC_PIPE_IW,
	FDC_PIPE_RW,
	FDC_DMABUF
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
	// Dirty state.
	bool has_owner; // Are there protocol handlers which control the
			// is_dirty flag?
	bool is_dirty;  // If so, should this file be scanned for updates?
	/* Very simple damage tracking. This [min,max) interval contains all
	 * expected changes since the last synchronization. */
	int dirty_interval_min, dirty_interval_max;

	int refcount; // Number of references from parsing logic

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

	// DMAbuf data
	size_t dmabuf_size;
	struct gbm_bo *dmabuf_bo;
	char *dmabuf_mem_mirror;  // malloc'd
	char *dmabuf_diff_buffer; // malloc'd
};

struct transfer {
	size_t size;
	fdcat_t type;
	int obj_id;
	int special; // type-specific extra data
	// data vector must include space up to next 8-byte boundary
	char *data;
};

void cleanup_translation_map(struct fd_translation_map *map);

/** Given a file descriptor, return which type code would be applied
 * to its shadow entry. (For example, FDC_PIPE_IR for a pipe-like
 * object that can only be read.) Sets *size if non-NULL and if
 * the object is an FDC_FILE. */
fdcat_t get_fd_type(int fd, size_t *size);
/** Given a list of local file descriptors, produce matching global ids, and
 * register them into the translation map if not already done. */
struct shadow_fd *translate_fd(struct fd_translation_map *map, int fd);
void translate_fds(struct fd_translation_map *map, int nfds, const int fds[],
		int ids[]);
/** Produce a list of file updates to transfer. All pointers will be to existing
 * memory. */
void collect_updates(struct fd_translation_map *map, int *ntransfers,
		struct transfer transfers[]);
/** Set up metadata and headers for the data transfer to the channel. */
struct block_transfer;
void pack_pipe_message(struct block_transfer *bt, int nids, const int ids[],
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
/** Fill in pollfd entries, with POLL_IN | POLLOUT, for applicable pipe objects.
 * Specifically, if check_read is true, indicate all readable pipes.
 * Also, indicate all writeable pipes for which we also something to write. */
struct pollfd;
int fill_with_pipes(const struct fd_translation_map *map, struct pollfd *pfds,
		bool check_read);

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

struct shadow_fd *get_shadow_for_rid(struct fd_translation_map *map, int rid);
/** Reduce the reference count for a shadow structure which is owned. The
 * structure should not be used by the caller after this point. Returns true if
 * pointer deleted. */
bool shadow_decref(struct fd_translation_map *map, struct shadow_fd *);
/** Increase the reference count of a shadow structure, and mark it as being
 * owned. For convenience, returns the passed-in structure. */
struct shadow_fd *shadow_incref(struct shadow_fd *);
/** Decrease reference count for all objects in the given list, deleting
 * iff they are owned by protocol objects and have refcount zero */
void decref_transferred_fds(
		struct fd_translation_map *map, int nfds, int fds[]);
void decref_transferred_rids(
		struct fd_translation_map *map, int nids, int ids[]);

struct kstack {
	struct kstack *nxt;
	pid_t pid;
};

void wait_on_children(struct kstack **children, int options);

struct msg_handler {
	const struct wl_interface *interface;
	// these are structs packed densely with function pointers
	const void *event_handlers;
	const void *request_handlers;
};
struct wp_object {
	/* An object used by the wayland protocol. Specific types may extend
	 * this struct, using the following data as a header */
	const struct wl_interface *type; // Use to lookup the message handler
	uint32_t obj_id;
};

struct obj_list {
	struct wp_object **objs;
	int nobj;
	int size;
};
struct message_tracker {
	// objects all have a 'type'
	// creating a new type <-> binding it in the 'interface' list, via
	// registry. each type produces 'callbacks'
	struct obj_list objects;
};
struct context {
	struct message_tracker *const mt;
	struct fd_translation_map *const map;
	struct wp_object *obj;
	bool drop_this_msg;
	/* If true, running as waypipe client, and interfacing with compositor's
	 * buffers */
	const bool on_display_side;
	/* The transferred message can be rewritten in place, and resized, as
	 * long as there is space available. Setting 'fds_changed' will
	 * prevent the fd zone start from autoincrementing after running
	 * the function, which may be useful when injecting messages with fds */
	const int message_available_space;
	uint32_t *const message;
	int message_length;
	bool fds_changed;
	struct int_window *const fds;
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
 * Given a set of messages and fds, parse the messages, and if indicated by
 * parsing logic, compact the message buffer by removing selected messages.
 *
 * Messages with file descriptors should not be compacted.
 *
 * The amount of the message buffer read is written to `data_used`
 * The new size of the message buffer, after compaction, is `data_newsize`
 * The number of file descriptors read by the protocol is `fds_used`.
 */
void parse_and_prune_messages(struct message_tracker *mt,
		struct fd_translation_map *map, bool on_display_side,
		bool from_client, struct char_window *source_bytes,
		struct char_window *dest_bytes, struct int_window *fds);

// parsing.c

void listset_insert(struct obj_list *lst, struct wp_object *obj);
void listset_remove(struct obj_list *lst, struct wp_object *obj);
struct wp_object *listset_get(struct obj_list *lst, uint32_t id);

void init_message_tracker(struct message_tracker *mt);
void cleanup_message_tracker(
		struct fd_translation_map *map, struct message_tracker *mt);

/** Read message size from header; the 8 bytes beyond data must exist */
int peek_message_size(const void *data);
/**
 * The return value is false iff the given message should be dropped.
 * The flag `unidentified_changes` is set to true if the message does
 * not correspond to a known protocol.
 *
 * The message data payload may be modified and increased in size.
 *
 * The window `chars` should start at the message start, end
 * at its end, and indicate remaining space.
 * The window `fds` should start at the next fd in the queue, ends
 * with the last.
 *
 * The start and end of `chars` will be moved to the new end of the message.
 * The end of `fds` may be moved if any fds are inserted or discarded.
 * The start of fds will be moved, depending on how many fds were consumed.
 */
enum parse_state { PARSE_KNOWN, PARSE_UNKNOWN, PARSE_ERROR };
enum parse_state handle_message(struct message_tracker *mt,
		struct fd_translation_map *map, bool on_display_side,
		bool from_client, struct char_window *chars,
		struct int_window *fds);

// handlers.c
struct wl_interface;
struct wp_object *create_wp_object(
		uint32_t it, const struct wl_interface *type);
void destroy_wp_object(
		struct fd_translation_map *map, struct wp_object *object);
extern const struct msg_handler handlers[];
extern const struct wl_interface *the_display_interface;

// dmabuf.c
int init_render_data(struct render_data *);
void cleanup_render_data(struct render_data *);
bool is_dmabuf(int fd);
struct gbm_bo *make_dmabuf(
		struct render_data *rd, const char *data, size_t size);
int export_dmabuf(struct gbm_bo *bo);
struct gbm_bo *import_dmabuf(struct render_data *rd, int fd, size_t *size);
void destroy_dmabuf(struct gbm_bo *bo);
void *map_dmabuf(struct gbm_bo *bo, bool write, void **map_handle);
int unmap_dmabuf(struct gbm_bo *bo, void *map_handle);
/** The handle values are unique among the set of currently active buffer
 * objects. To compare a set of buffer objects, produce handles in a batch, and
 * then free the temporary buffer objects in a batch */
int get_unique_dmabuf_handle(
		struct render_data *rd, int fd, struct gbm_bo **temporary_bo);

#endif // WAYPIPE_UTIL_H
