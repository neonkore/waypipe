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
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

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
static inline uint64_t alignu(uint64_t v, uint64_t m)
{
	return m * ((v + m - 1) / m);
}
static inline int floordiv(int v, int u) { return v / u; }
static inline int ceildiv(int v, int u) { return (v + u - 1) / u; }

/** Set the given flag with fcntl. Silently return -1 on failure. */
int set_fnctl_flag(int fd, int the_flag);
/** Create a nonblocking AF_UNIX/SOCK_STREAM socket, and listen with
 * nmaxclients. Prints its own error messages; returns -1 on failure. */
int setup_nb_socket(const char *socket_path, int nmaxclients);

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

/** Run waitpid in a loop until there are no more zombies to clean up.
 * If the target_pid was one of the completed processes, set status, return
 * true. The `options` flag will be passed to waitpid */
bool wait_for_pid_and_clean(pid_t target_pid, int *status, int options);

/** A helper type, since very often buffers and their sizes are passed together
 * (or returned together) as arguments */
struct bytebuf {
	size_t size;
	char *data;
};

struct render_data {
	bool disabled;
	int drm_fd;
	const char *drm_node_path;
	struct gbm_device *dev;
};

enum thread_task {
	THREADTASK_STOP,
	THREADTASK_MAKE_COMPRESSEDDIFF,
};

typedef struct LZ4F_dctx_s LZ4F_dctx;
typedef struct ZSTD_CCtx_s ZSTD_CCtx;
typedef struct ZSTD_DCtx_s ZSTD_DCtx;
struct comp_ctx {
	LZ4F_dctx *lz4f_dcontext;
	ZSTD_CCtx *zstd_ccontext;
	ZSTD_DCtx *zstd_dcontext;
};

struct thread_data {
	pthread_t thread;
	struct fd_translation_map *map;
	/* This determines, based on the state stored in the map's linked
	 * shadow structure target, which work is performed, and where
	 * data should be read and written */
	int index;
	int last_task_id;
	/* Where to record the location and size of the compressed diff
	 * produced by this thread. The buffer data will point into an
	 * existing buffer */
	struct bytebuf cd_dst;
	size_t cd_actual_size;
	struct comp_ctx comp_ctx;
};
enum compression_mode { COMP_NONE, COMP_LZ4, COMP_ZSTD };
struct fd_translation_map {
	struct shadow_fd *list;
	int max_local_id;
	int local_sign;
	/* Compression information is globally shared, to save memory, and
	 * because most rapidly changing application buffers have similar
	 * content and use the same settings */
	enum compression_mode compression;
	struct comp_ctx comp_ctx; // threadlocal
	/* The latency of a multithreaded operation can be approximated with two
	 * main components: the context switching time to get all threads
	 * working (and then notify the original thread), and the time to
	 * perform the (fully parallel) work. If the context switching time is
	 * the same for all threads, then there is a threshold beyond which it
	 * is helpful to run multithreaded (with as many threads as possible),
	 * below which a single-threaded approach is faster. */
	int scancomp_thread_threshold;
	/* Threads. These should only be used for computational work;
	 * communication should be limited to task descriptions, with pointers
	 * to e.g. the condition variables used to notify when work is done or
	 * not */
	int nthreads;
	struct thread_data *threads;
	/* `work_state` guards `nthreads_completed`, `next_thread_task`,
	 * `task_id`, and `thread_target`. `work_needed_notify` signals when to
	 * check for an increased task counter; `work_done_notify` lets the main
	 * thread know that a task has been done.
	 */
	pthread_cond_t work_done_notify;
	pthread_cond_t work_needed_notify;
	pthread_mutex_t work_state_mutex;
	int task_id;
	int nthreads_completed;
	struct shadow_fd *thread_target;
	enum thread_task next_thread_task;
};

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

struct dmabuf_slice_data {
	/* This information partially duplicates that of a gbm_bo. However, for
	 * instance with weston, it is possible for the compositor to handle
	 * multibuffer multiplanar images, even though a driver may only support
	 * multiplanar images derived from a single underlying dmabuf. */
	uint32_t width;
	uint32_t height;
	uint32_t format;
	uint32_t num_planes;
	// to which planes is the matching dmabuf assigned?
	uint8_t using_planes[4];
	uint32_t strides[4];
	uint32_t offsets[4];
	uint64_t modifier;

	// which update type to expect
	bool using_video;
};

// Q: use uint32_t everywhere?
struct ext_interval {
	/* A slight modification of the standard 'damage' rectangle
	 * formulation, written to be agnostic of whatever buffers
	 * underlie the system.
	 *
	 * [start,start+width),[start+stride,start+stride+width),
	 * ... [start+(rep-1)*stride,start+(rep-1)*stride+width) */
	int32_t start;
	/* Subinterval width */
	int32_t width;
	/* Number of distinct subinterval start positions. For a single
	 * interval, this is one. */
	int32_t rep;
	/* Spacing between start positions, should be > width, unless
	 * the is only one subinterval, in which case the value shouldn't
	 * matter and is conventionally set to 0. */
	int32_t stride;
};
#define DAMAGE_EVERYTHING ((struct ext_interval *)-1)

struct damage {
	/* Interval-based damage tracking. If damage is NULL, there is
	 * no recorded damage. If damage is DAMAGE_EVERYTHING, the entire
	 * region should be updated. If ndamage_rects > 0, then
	 * damage points to an array of struct damage_interval objects. */
	struct ext_interval *damage;
	int ndamage_rects;

	int acc_damage_stat, acc_count;
};

/** Given an array of extended intervals, update the base damage structure
 * so that it contains a reasonably small disjoint set of extended intervals
 * which contains the old base set and the new set. */
void merge_damage_records(struct damage *base, int nintervals,
		const struct ext_interval *const new_list);
/** Return a single interval containing the entire damaged region */
void get_damage_interval(const struct damage *base, int *min, int *max,
		int *total_covered_area);
/** Set damage to empty  */
void reset_damage(struct damage *base);
/** Expand damage to cover everything */
void damage_everything(struct damage *base);

struct shadow_fd {
	struct shadow_fd *next; // singly-linked list
	fdcat_t type;
	int remote_id; // + if created serverside; - if created clientside
	int fd_local;
	// Dirty state.
	bool has_owner; // Are there protocol handlers which control the
			// is_dirty flag?
	bool is_dirty;  // If so, should this file be scanned for updates?
	struct damage damage;

	/* There are two types of reference counts for shadow_fd objects;
	 * a struct shadow_fd can only be safely deleted when both counts are
	 * zero. The protocol refcount tracks the number of protocol objects
	 * which have a reference to the shadow_fd (and which may try to
	 * mark it dirty.) The transfer refcount tracks the number of times
	 * that the object id (as either remote_id, or fd_local) must be passed
	 * on to the next program (waypipe instance, or application/compositor)
	 * so that said program can correctly parse its Wayland messages. */
	int refcount_protocol; // Number of references from protocol objects
	int refcount_transfer; // Number of references from fd transfer logic

	// common buffers for file-like types
	char *mem_mirror;      // exact mirror of the contents
	char *diff_buffer;     // target buffer for uncompressed diff
	char *compress_buffer; // target buffer for compressed diff
	size_t compress_space;

	// File data
	size_t file_size;
	char *file_mem_local; // mmap'd
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
	struct dmabuf_slice_data dmabuf_info;

	struct AVCodec *video_codec;
	struct AVCodecContext *video_context;
	struct AVFrame *video_reg_frame;
	struct AVFrame *video_yuv_frame;
	struct AVPacket *video_packet;
	struct SwsContext *video_color_context;
	char *video_buffer;
	int64_t video_frameno;
};

struct transfer {
	fdcat_t type;
	int obj_id;
	// type-specific extra data
	union {
		int pipeclose;
		int file_actual_size;
		int raw; // < for obviously type-independent cases
	} special;

	int nblocks;
	// each subtransfer must include space up to the next 8-byte boundary.
	// they will all be concatenated by the writev call
	struct bytebuf *subtransfers;
};

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
	bool is_zombie; // object deleted but not yet acknowledged remotely
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

	// Precomputed signatures for active functions. The arg table contains
	// a concatenated list of all argument type signature vectors. The
	// request/event cache elements are vectors of ffi_cif types
	void *cif_arg_table;
	void *cif_table;
	void **event_cif_cache;
	void **request_cif_cache;
};
struct context {
	struct globals *const g;
	struct obj_list *const obj_list;
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

struct main_config {
	const char *drm_node;
	enum compression_mode compression;
	bool no_gpu;
	bool linear_dmabuf;
	bool video_if_possible;
};
struct globals {
	const struct main_config *config;
	struct fd_translation_map map;
	struct render_data render;
	struct message_tracker tracker;
};

int main_interface_loop(int chanfd, int progfd,
		const struct main_config *config, bool display_side);

void setup_translation_map(struct fd_translation_map *map, bool display_side,
		enum compression_mode compression);
void cleanup_translation_map(struct fd_translation_map *map);

/** Given a file descriptor, return which type code would be applied to its
 * shadow entry. (For example, FDC_PIPE_IR for a pipe-like object that can only
 * be read.) Sets *size if non-NULL and if the object is an FDC_FILE. */
fdcat_t get_fd_type(int fd, size_t *size);
/** Given a local file descriptor, produce matching global id, and register it
 * into the translation map if not already done. The function can also be
 * provided with optional extra information.
 */
struct dmabuf_slice_data;
struct shadow_fd *translate_fd(struct fd_translation_map *map,
		struct render_data *render, int fd,
		struct dmabuf_slice_data *info);
/** Given a struct shadow_fd, produce some number of corresponding file update
 * transfer messages. All pointers will be to existing memory. */
void collect_update(struct fd_translation_map *map, struct shadow_fd *cur,
		int *ntransfers, struct transfer transfers[], int *nblocks,
		struct bytebuf blocks[]);
/** Apply a file update to the translation map, creating an entry when there is
 * none */
void apply_update(struct fd_translation_map *map, struct render_data *render,
		const struct transfer *transf);
/** Get the shadow structure associated to a remote id, or NULL if it dne */
struct shadow_fd *get_shadow_for_rid(struct fd_translation_map *map, int rid);

/** Count the number of pipe fds being maintained by the translation map */
int count_npipes(const struct fd_translation_map *map);
/** Fill in pollfd entries, with POLLIN | POLLOUT, for applicable pipe objects.
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

/** Reduce the reference count for a shadow structure which is owned. The
 * structure should not be used by the caller after this point. Returns true if
 * pointer deleted. */
bool shadow_decref_protocol(struct fd_translation_map *map, struct shadow_fd *);
bool shadow_decref_transfer(struct fd_translation_map *map, struct shadow_fd *);
/** Increase the reference count of a shadow structure, and mark it as being
 * owned. For convenience, returns the passed-in structure. */
struct shadow_fd *shadow_incref_protocol(struct shadow_fd *);
struct shadow_fd *shadow_incref_transfer(struct shadow_fd *);
/** Decrease reference count for all objects in the given list, deleting
 * iff they are owned by protocol objects and have refcount zero */
void decref_transferred_fds(
		struct fd_translation_map *map, int nfds, int fds[]);
void decref_transferred_rids(
		struct fd_translation_map *map, int nids, int ids[]);

// parsing.c

void listset_insert(struct fd_translation_map *map, struct obj_list *lst,
		struct wp_object *obj);
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
enum parse_state handle_message(struct globals *g, bool on_display_side,
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

/* Additional information to help serialize a dmabuf */
int init_render_data(struct render_data *);
void cleanup_render_data(struct render_data *);
bool is_dmabuf(int fd);
struct gbm_bo *make_dmabuf(struct render_data *rd, const char *data,
		size_t size, struct dmabuf_slice_data *info);
int export_dmabuf(struct gbm_bo *bo);
struct gbm_bo *import_dmabuf(struct render_data *rd, int fd, size_t *size,
		struct dmabuf_slice_data *info);
void destroy_dmabuf(struct gbm_bo *bo);
void *map_dmabuf(struct gbm_bo *bo, bool write, void **map_handle);
int unmap_dmabuf(struct gbm_bo *bo, void *map_handle);
/** The handle values are unique among the set of currently active buffer
 * objects. To compare a set of buffer objects, produce handles in a batch, and
 * then free the temporary buffer objects in a batch */
int get_unique_dmabuf_handle(
		struct render_data *rd, int fd, struct gbm_bo **temporary_bo);
uint32_t dmabuf_get_simple_format_for_plane(uint32_t format, int plane);

// exported for testing
void apply_diff(size_t size, char *__restrict__ base, size_t diffsize,
		const char *__restrict__ diff);
void construct_diff(size_t size, const struct damage *__restrict__ damage,
		size_t copy_domain_start, size_t copy_domain_end,
		char *__restrict__ base, const char *__restrict__ changed,
		size_t *diffsize, char *__restrict__ diff);

#endif // WAYPIPE_UTIL_H
