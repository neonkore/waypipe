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
#include <sys/uio.h>

#include "config-waypipe.h"

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
/* only valid for nonegative v and positive u */
static inline int floordiv(int v, int u) { return v / u; }
static inline int ceildiv(int v, int u) { return (v + u - 1) / u; }

/** Make the file underlying this file descriptor nonblocking.
 * Silently return -1 on failure. */
int set_nonblocking(int fd);
/** Create a nonblocking AF_UNIX/SOCK_STREAM socket, and listen with
 * nmaxclients. Prints its own error messages; returns -1 on failure. */
int setup_nb_socket(const char *socket_path, int nmaxclients);
/** Connect to the socket at the given path, returning created fd if
 * successful, else -1.*/
int connect_to_socket(const char *socket_path);
/** A type to help keep track of the connection handling processes */
#define CONN_UPDATE 0x1
struct conn_addr {
	uint64_t token;
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
/* a simple log handler to STDOUT for use by test programs */
void test_log_handler(const char *file, int line, enum log_level level,
		const char *fmt, ...);
/* These log functions should be set by whichever translation units have a
 * 'main'. The first one is the debug handler, second error handler. Set them to
 * NULL to disable log messages. */
extern log_handler_func_t log_funcs[2];

#ifdef WAYPIPE_REL_SRC_DIR
#define WAYPIPE__FILE__                                                        \
	((const char *)__FILE__ + sizeof(WAYPIPE_REL_SRC_DIR) - 1)
#else
#define WAYPIPE__FILE__ __FILE__
#endif
// No trailing ;, user must supply. The first vararg must be the format string.
#define wp_error(...)                                                          \
	if (log_funcs[WP_ERROR])                                               \
	(*log_funcs[WP_ERROR])(WAYPIPE__FILE__, __LINE__, WP_ERROR, __VA_ARGS__)
#define wp_debug(...)                                                          \
	if (log_funcs[WP_DEBUG])                                               \
	(*log_funcs[WP_DEBUG])(WAYPIPE__FILE__, __LINE__, WP_DEBUG, __VA_ARGS__)

/** Run waitpid in a loop until there are no more zombies to clean up. If the
 * target_pid was one of the completed processes, set status, return true. The
 * `options` flag will be passed to waitpid. If `map` is not NULL, remove
 * entries in the connection map which were closed */
bool wait_for_pid_and_clean(pid_t target_pid, int *status, int options,
		struct conn_map *map);

/** A helper type, since very often buffers and their sizes are passed together
 * (or returned together) as arguments */
struct bytebuf {
	size_t size;
	char *data;
};

typedef void *VADisplay;
typedef unsigned int VAGenericID;
typedef VAGenericID VAConfigID;
struct render_data {
	bool disabled;
	int drm_fd;
	const char *drm_node_path;
	struct gbm_device *dev;
	/* video hardware context */
	bool av_disabled;
	struct AVBufferRef *av_hwdevice_ref;
	struct AVBufferRef *av_drmdevice_ref;
	VADisplay av_vadisplay;
	VAConfigID av_copy_config;
};

typedef struct LZ4F_dctx_s LZ4F_dctx;
typedef struct ZSTD_CCtx_s ZSTD_CCtx;
typedef struct ZSTD_DCtx_s ZSTD_DCtx;
struct comp_ctx {
	LZ4F_dctx *lz4f_dcontext;
	ZSTD_CCtx *zstd_ccontext;
	ZSTD_DCtx *zstd_dcontext;
};

enum compression_mode {
	COMP_NONE,
#ifdef HAS_LZ4
	COMP_LZ4,
#endif
#ifdef HAS_ZSTD
	COMP_ZSTD,
#endif
};

typedef int (*interval_diff_fn_t)(const int diff_window_size, const int i_end,
		const uint64_t *__restrict__ mod, uint64_t *__restrict__ base,
		uint64_t *__restrict__ diff, int i);

struct fd_translation_map {
	struct shadow_fd *list;
	int max_local_id;
	int local_sign;
};

struct thread_pool {
	int nthreads;
	struct thread_data *threads; // including a slot for the zero thread
	/* Compression information is globally shared, to save memory, and
	 * because most rapidly changing application buffers have similar
	 * content and use the same settings */
	enum compression_mode compression;
	interval_diff_fn_t diff_func;
	int diff_func_alignment;

	// Mutable state
	pthread_mutex_t work_mutex;
	pthread_cond_t work_cond;

	int queue_start, queue_end, queue_size;
	struct task_data *queue;
	// TODO: distinct queues for wayland->channel and channel->wayland
	int queue_in_progress;

	// to wake to main loop
	int selfpipe_r, selfpipe_w;
};

struct thread_data {
	pthread_t thread;
	struct thread_pool *pool;
	/* Thread local data */
	struct comp_ctx comp_ctx;

	/* A local temporary buffer, used to e.g. store diff sections before
	 * compression */
	void *tmp_buf;
	int tmp_size;
};

enum task_type {
	TASK_STOP,
	TASK_COMPRESS_BLOCK,
	TASK_COMPRESS_DIFF,
};

struct task_data {
	enum task_type type;

	struct shadow_fd *sfd;
	struct fd_translation_map *map;
	/* For block compression option */
	int zone_start, zone_end;
	/* For diff compression option */
	struct interval *damage_intervals;
	int damage_len;
	bool damaged_end;

	struct transfer_data *transfers;
};

typedef enum {
	FDC_UNKNOWN,
	FDC_FILE,      /* Shared memory buffer */
	FDC_PIPE_IR,   /* pipe-like object, reading from program */
	FDC_PIPE_IW,   /* pipe-like object, writing to program */
	FDC_PIPE_RW,   /* pipe-like object, read+write support */
	FDC_DMABUF,    /* DMABUF buffer (will be exactly replicated) */
	FDC_DMAVID_IR, /* DMABUF-based video, reading from program */
	FDC_DMAVID_IW, /* DMABUF-based video, writing to program */
} fdcat_t;
bool fdcat_ispipe(fdcat_t t);

enum wmsg_type {
	/* Send over a set of Wayland protocol messages. Preceding messages
	 * must create or update file descriptors and inject file descriptors
	 * to the queue.
	 *
	 * TODO: use extra bits to make parsing more consistent between systems;
	 * i.e, to ensure that # of file descriptors consumed is the same */
	WMSG_PROTOCOL, // just header uint32, then protocol messages
	/* Inject file descriptors into the receiver's buffer, for use by the
	 * protocol parser */
	WMSG_INJECT_RIDS, // just header uint32, then fds
	/* Create a new shared memory file of the given size */
	WMSG_OPEN_FILE, // wmsg_open_file
	/* Provide a new (larger) size for the file buffer */
	WMSG_EXTEND_FILE, // wmsg_open_file
	/* Create a new DMABUF with the given size and dmabuf_slice_data */
	WMSG_OPEN_DMABUF, // wmsg_open_dmabuf
	/* Fill the region of the file with the folllowing data. The data should
	 * be compressed according to the selected compression option */
	WMSG_BUFFER_FILL, // wmsg_buffer_fill
	/* Apply a diff to the file. The diff contents may be compressed. */
	WMSG_BUFFER_DIFF, // wmsg_buffer_diff
	/* Create a new pipe, with the given remote R/W status */
	WMSG_OPEN_IR_PIPE, // wmsg_basic
	WMSG_OPEN_IW_PIPE, // wmsg_basic
	WMSG_OPEN_RW_PIPE, // wmsg_basic
	/* Transfer data to the pipe */
	WMSG_PIPE_TRANSFER, // wmsg_basic
	/* No more data will be transferred to this pipe. */
	WMSG_PIPE_HANGUP, // wmsg_basic
	/* Create a DMABUF (with following data parameters) that will be used
	 * to produce/consume video frames. */
	WMSG_OPEN_DMAVID_SRC, // wmsg_open_dmabuf
	WMSG_OPEN_DMAVID_DST, // wmsg_open_dmabuf
	/* Send a packet of video data to the destination */
	WMSG_SEND_DMAVID_PACKET, // wmsg_basic
	/* Acknowledge that a given number of messages has been received, so
	 * that the sender of those messages no longer needs to store them
	 * for replaying in case of reconnection */
	WMSG_ACK_NBLOCKS, // wmsg_ack
	/* When restarting a connection, indicate the number of the message
	 * which will be sent next */
	WMSG_RESTART, // wmsg_restart
	/* When the remote program is closing */
	WMSG_CLOSE, // uint32_t + padding
};
const char *wmsg_type_to_str(enum wmsg_type tp);
struct wmsg_open_file {
	uint32_t size_and_type;
	int32_t remote_id;
	uint32_t file_size;
	uint32_t pad4;
};
struct wmsg_open_dmabuf {
	uint32_t size_and_type;
	int32_t remote_id;
	uint32_t file_size;
	uint32_t pad4;
	/* following this, provide struct dmabuf_slice_data */
};
struct wmsg_buffer_fill {
	uint32_t size_and_type;
	int32_t remote_id;
	uint32_t start; // [start, end), in bytes of zone to be written
	uint32_t end;
	/* following this, the possibly-compressed data */
};
struct wmsg_buffer_diff {
	uint32_t size_and_type;
	int32_t remote_id;
	uint32_t diff_size; // in bytes, when uncompressed
	uint32_t ntrailing; // number of 'trailing' bytes, copied to tail
	/* following this, the possibly-compressed diff  data */
};
struct wmsg_basic {
	uint32_t size_and_type;
	int32_t remote_id;
	uint32_t pad3;
	uint32_t pad4;
};
struct wmsg_ack {
	uint32_t size_and_type;
	uint32_t messages_received;
	uint32_t pad3;
	uint32_t pad4;
};
struct wmsg_restart {
	uint32_t size_and_type;
	uint32_t last_ack_received;
	uint32_t pad3;
	uint32_t pad4;
};
/* size: the number of bytes in the message, /excluding/ trailing padding. */
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

struct pipe_buffer {
	char *data;
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
	int32_t num_planes;
	uint32_t offsets[4];
	uint32_t strides[4];
	uint64_t modifier;
	// to which planes is the matching dmabuf assigned?
	uint8_t using_planes[4];
};

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
struct interval {
	/* start+end is better than start+width, since the limits are used
	 * repeatedly by merge operations, while width is only needed for
	 * e.g. streaming area estimates which are very fast anyway */
	int32_t start;
	int32_t end;
};

#define DAMAGE_EVERYTHING ((struct interval *)-1)

struct damage {
	/* Interval-based damage tracking. If damage is NULL, there is
	 * no recorded damage. If damage is DAMAGE_EVERYTHING, the entire
	 * region should be updated. If ndamage_rects > 0, then
	 * damage points to an array of struct damage_interval objects. */
	struct interval *damage;
	int ndamage_intvs;

	int acc_damage_stat, acc_count;
};

/** Given an array of extended intervals, update the base damage structure
 * so that it contains a reasonably small disjoint set of extended intervals
 * which contains the old base set and the new set. */
void merge_damage_records(struct damage *base, int nintervals,
		const struct ext_interval *const new_list);
/** Return the total area covered by the damage region */
int get_damage_area(const struct damage *base);
/** Set damage to empty  */
void reset_damage(struct damage *base);
/** Expand damage to cover everything */
void damage_everything(struct damage *base);

typedef VAGenericID VAContextID;
typedef VAGenericID VASurfaceID;
typedef VAGenericID VABufferID;

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
	/* For worker threads, contains their allocated damage intervals */
	struct interval *damage_task_interval_store;

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
	bool refcount_compute; // Are the any thread tasks referring to this?

	// common buffers for file-like types
	/* total memory size of either the dmabuf or the file */
	size_t buffer_size;
	/* mmap'd long term for files, short term for dmabufs */
	char *mem_local;
	/* exact mirror of the contents, albeit allocated with overrun space */
	char *mem_mirror;

	// File data
	size_t remote_bufsize; // used to check for and send file extensions
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
	struct gbm_bo *dmabuf_bo;
	struct dmabuf_slice_data dmabuf_info;
	void *dmabuf_map_handle; /* Nonnull when DMABUF is currently mapped */

	// Video data
	struct AVCodecContext *video_context;
	struct AVFrame *video_local_frame; /* In format matching DMABUF */
	struct AVFrame *video_tmp_frame;   /* To hold intermediate copies */
	struct AVFrame *video_yuv_frame;   /* In enc/dec preferred format */
	void *video_yuv_frame_data;
	struct AVPacket *video_packet;
	struct SwsContext *video_color_context;
	int64_t video_frameno;

	VASurfaceID video_va_surface;
	VAContextID video_va_context;
	VABufferID video_va_pipeline;
};

/* A structure tracking data blocks to transfer. Users should ensure that each
 * group of consecutive messages is 16-aligned, so that the headers make sense.
 */
struct transfer_data {
	/* A short buffer filled with zeros, to provide padding when the source
	 * buffer is insufficiently large/shouldn't be modified. */
	char zeros[16];
	/* Data to be writtenveed */
	struct iovec *data;
	/* Matching vector indicating to which message the corresponding data
	 * block belongs. */
	uint32_t *msgno;
	/* start: next block to write. end: just after last block to write;
	 * size: number of iovec blocks */
	int start, end, size;
	/* How much of the block at 'start' has been written */
	int partial_write_amt;
	/* The most recent message number */
	uint32_t last_msgno;
	/* Guard for all operations */
	pthread_mutex_t lock;
};

struct wp_interface;
struct msg_handler {
	const struct wp_interface *interface;
	// these are structs packed densely with function pointers
	const void *event_handlers;
	const void *request_handlers;
	// can the type be produced via wl_registry::bind ?
	bool is_global;
};
struct wp_object {
	/* An object used by the wayland protocol. Specific types may extend
	 * this struct, using the following data as a header */
	const struct wp_interface *type; // Use to lookup the message handler
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
	int n_worker_threads;
	enum compression_mode compression;
	bool no_gpu;
	bool linear_dmabuf;
	bool video_if_possible;
	bool prefer_hwvideo;
};
struct globals {
	const struct main_config *config;
	struct fd_translation_map map;
	struct render_data render;
	struct message_tracker tracker;
	struct thread_pool threads;
};

bool transfer_add(struct transfer_data *transfers, size_t size, void *data,
		uint32_t msgno);
bool transfer_zeropad(
		struct transfer_data *transfers, size_t size, uint32_t msgno);

/* chanfd: connected socket to channel
 * progfd: connected socket to Wayland program
 * linkfd: optional connected socket providing new chanfds */
int main_interface_loop(int chanfd, int progfd, int linkfd,
		const struct main_config *config, bool display_side);

void setup_translation_map(struct fd_translation_map *map, bool display_side);
void cleanup_translation_map(struct fd_translation_map *map);

void setup_thread_pool(struct thread_pool *pool,
		enum compression_mode compression, int n_threads);
void cleanup_thread_pool(struct thread_pool *pool);

/** Given a file descriptor, return which type code would be applied to its
 * shadow entry. (For example, FDC_PIPE_IR for a pipe-like object that can only
 * be read.) Sets *size if non-NULL and if the object is an FDC_FILE. */
fdcat_t get_fd_type(int fd, size_t *size);
const char *fdcat_to_str(fdcat_t cat);
/** Given a local file descriptor, type hint, and already computed size,
 * produce matching global id, and register it into the translation map if
 * not already done. The function can also be provided with optional extra
 * information (*info).
 */
struct dmabuf_slice_data;
struct shadow_fd *translate_fd(struct fd_translation_map *map,
		struct render_data *render, int fd, fdcat_t type, size_t sz,
		const struct dmabuf_slice_data *info);
/** Given a struct shadow_fd, produce some number of corresponding file update
 * transfer messages. All pointers will be to existing memory. */
void collect_update(struct fd_translation_map *map, struct thread_pool *threads,
		struct shadow_fd *cur, struct transfer_data *transfers);
/** After all thread pool tasks have completed, reduce refcounts and clean up
 * related data */
void finish_update(struct fd_translation_map *map, struct shadow_fd *sfd);
/** Apply a data update message to an element in the translation map, creating
 * an entry when there is none */
void apply_update(struct fd_translation_map *map, struct thread_pool *threads,
		struct render_data *render, enum wmsg_type type, int remote_id,
		const struct bytebuf *msg);
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

/** If sfd->type == FDC_FILE, increase the size of the backing data to support
 * at least new_size, and mark the new part of underlying file as dirty */
void extend_shm_shadow(struct fd_translation_map *map,
		struct thread_pool *threads, struct shadow_fd *sfd,
		size_t new_size);
void run_task(struct task_data *task, struct thread_data *local);

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
struct wp_object *create_wp_object(
		uint32_t it, const struct wp_interface *type);
void destroy_wp_object(
		struct fd_translation_map *map, struct wp_object *object);
extern const struct msg_handler handlers[];
extern const struct wp_interface *the_display_interface;

// dmabuf.c

/* Additional information to help serialize a dmabuf */
int init_render_data(struct render_data *);
void cleanup_render_data(struct render_data *);
bool is_dmabuf(int fd);
struct gbm_bo *make_dmabuf(struct render_data *rd, size_t size,
		const struct dmabuf_slice_data *info);
int export_dmabuf(struct gbm_bo *bo);
struct gbm_bo *import_dmabuf(struct render_data *rd, int fd, size_t *size,
		const struct dmabuf_slice_data *info);
void destroy_dmabuf(struct gbm_bo *bo);
void *map_dmabuf(struct gbm_bo *bo, bool write, void **map_handle);
int unmap_dmabuf(struct gbm_bo *bo, void *map_handle);
/** The handle values are unique among the set of currently active buffer
 * objects. To compare a set of buffer objects, produce handles in a batch, and
 * then free the temporary buffer objects in a batch */
int get_unique_dmabuf_handle(
		struct render_data *rd, int fd, struct gbm_bo **temporary_bo);
uint32_t dmabuf_get_simple_format_for_plane(uint32_t format, int plane);

// video.c
/** set redirect for ffmpeg logging through wp_log */

void cleanup_hwcontext(struct render_data *rd);
bool video_supports_dmabuf_format(uint32_t format, uint64_t modifier);
bool video_supports_shm_format(uint32_t format);
void setup_video_logging(void);
void destroy_video_data(struct shadow_fd *sfd);
/** These need to have the dmabuf/dmabuf_info set beforehand */
void setup_video_encode(struct shadow_fd *sfd, struct render_data *rd);
void setup_video_decode(struct shadow_fd *sfd, struct render_data *rd);
/** the video frame to be transferred should already have been transferred into
 * `sfd->mem_mirror`. */
void collect_video_from_mirror(
		struct shadow_fd *sfd, struct transfer_data *transfers);
void apply_video_packet(struct shadow_fd *sfd, struct render_data *rd,
		const struct bytebuf *data);
/** All return pointers can be NULL. Determines how much extra space or
 * padded width/height is needed for a video frame */
void pad_video_mirror_size(int width, int height, int stride, int *new_width,
		int *new_height, int *new_min_size);

// kernel.c
/** Returns a function pointer to a diff construction kernel, and indicates
 * the alignment of the data which is to be passed in */
interval_diff_fn_t get_fastest_diff_function(int *alignment);
int construct_diff_core(interval_diff_fn_t idiff_fn,
		const struct interval *__restrict__ damaged_intervals,
		int n_intervals, char *__restrict__ base,
		const char *__restrict__ changed, char *__restrict__ diff);
int construct_diff_trailing(int size, int alignment, char *__restrict__ base,
		const char *__restrict__ changed, char *__restrict__ diff);
void apply_diff(size_t size, char *__restrict__ target1,
		char *__restrict__ target2, size_t diffsize, size_t ntrailing,
		const char *__restrict__ diff);

#endif // WAYPIPE_UTIL_H
