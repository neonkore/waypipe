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
#ifndef WAYPIPE_SHADOW_H
#define WAYPIPE_SHADOW_H

#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dmabuf.h"
#include "interval.h"
#include "kernel.h"
#include "util.h"

struct pollfd;
typedef VAGenericID VAContextID;
typedef VAGenericID VASurfaceID;
typedef VAGenericID VABufferID;
typedef struct ZSTD_CCtx_s ZSTD_CCtx;
typedef struct ZSTD_DCtx_s ZSTD_DCtx;

struct comp_ctx {
	void *lz4_extstate;
	ZSTD_CCtx *zstd_ccontext;
	ZSTD_DCtx *zstd_dcontext;
};

enum compression_mode {
	COMP_NONE,
	COMP_LZ4,
	COMP_ZSTD,
};

struct shadow_fd_link {
	struct shadow_fd_link *l_prev, *l_next; /* Doubly linked list */
};

struct fd_translation_map {
	struct shadow_fd_link link; /* store in first position */

	int max_local_id;
	int local_sign;
};

/** Thread pool and associated global information */
struct thread_pool {
	int nthreads;
	struct thread_data *threads; // including a slot for the zero thread
	/* Compression information is globally shared, to save memory, and
	 * because most rapidly changing application buffers have similar
	 * content and use the same settings */
	enum compression_mode compression;
	int compression_level;

	interval_diff_fn_t diff_func;
	int diff_alignment_bits;

	// Mutable state
	pthread_mutex_t work_mutex;
	pthread_cond_t work_cond;

	bool do_work;
	int stack_count, stack_size;
	struct task_data *stack;
	// TODO: distinct queues for wayland->channel and channel->wayland,
	// to make multithreaded decompression possible
	int tasks_in_progress;

	// to wake the main loop
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

/** Specification for a task to be run on another thread */
struct task_data {
	enum task_type type;

	struct shadow_fd *sfd;
	/* For block compression option */
	int zone_start, zone_end;
	/* For diff compression option */
	struct interval *damage_intervals;
	int damage_len;
	bool damaged_end;

	struct thread_msg_recv_buf *msg_queue;
};

/** Shadow object types, signifying file descriptor type and usage */
enum fdcat {
	FDC_UNKNOWN,
	FDC_FILE,      /* Shared memory buffer */
	FDC_PIPE,      /* pipe-like object */
	FDC_DMABUF,    /* DMABUF buffer (will be exactly replicated) */
	FDC_DMAVID_IR, /* DMABUF-based video, reading from program */
	FDC_DMAVID_IW, /* DMABUF-based video, writing to program */
};

struct pipe_buffer {
	char *data;
	int size;
	int used;
};

/** Reference count for a struct shadow_fd; the object can be safely deleted
 * iff all counts are zero/false. */
struct refcount {
	/** How many protocol objects refer to this shadow structure */
	int protocol;
	/** How many times must the shadow_fd still be sent to the Wayland
	 * program */
	int transfer;
	/** Do any thread tasks potentially refer to this */
	bool compute;
};

struct pipe_state {
	/** Temporary buffers to contain small chunks of data, before it is
	 * transported further */
	struct pipe_buffer send;
	struct pipe_buffer recv;
	/** Internal file descriptor through which all pipe interactions
	 * are mediated. This equals fd_local, except during the time period
	 * where the shadow_fd is created but the fd_local has not yet been
	 * sent to the remote process. */
	int fd;
	/** 4 bits are needed for the pipe state machine (once the pipe has
	 * been created. They describe the properties of `pipe_fd` locally
	 * and remotely */
	bool can_read, can_write;
	bool remote_can_read, remote_can_write;
	/** What is the state of the pipe, according to poll ?
	 * (POLLIN|POLLHUP -> readable ; POLLOUT -> writeable) */
	bool readable, writable;
	bool pending_w_shutdown;
};

enum video_coding_fmt {
	VIDEO_H264,
	VIDEO_VP9,
};

/**
 * @brief The shadow_fd struct
 *
 * This structure is created to track each file descriptor used by the
 * Wayland protocol.
 */
struct shadow_fd {
	struct shadow_fd_link link; /* part of doubly linked list */

	enum fdcat type;
	int remote_id; // + if created serverside; - if created clientside
	int fd_local;
	/** true iff the shadow structure is newly created and no message
	 * to create a copy has been sent yet */
	bool only_here;
	// Dirty state.
	bool has_owner; // Are there protocol handlers which control the
			// is_dirty flag?
	bool is_dirty;  // If so, should this file be scanned for updates?
	struct damage damage;
	/* For worker threads, contains their allocated damage intervals */
	struct interval *damage_task_interval_store;

	struct refcount refcount;

	// common buffers for file-like types
	/* total memory size of either the dmabuf or the file */
	size_t buffer_size;
	/* mmap'd long term for files, short term for dmabufs */
	char *mem_local;
	/* exact mirror of the contents, with proper alignment */
	char *mem_mirror;
	void *mem_mirror_handle;

	// File data
	size_t remote_bufsize; // used to check for and send file extensions
	bool file_readonly;

	// Pipe data
	struct pipe_state pipe;

	// DMAbuf data
	struct gbm_bo *dmabuf_bo;
	struct dmabuf_slice_data dmabuf_info;
	void *dmabuf_map_handle; /* Nonnull when DMABUF is currently mapped */
	uint32_t dmabuf_map_stride; /* stride at which mem_local is mapped */
	/* temporary cache of stride-fixed mem_local. Same dimensions as
	 * mem_mirror */
	char *dmabuf_warped;
	void *dmabuf_warped_handle;

	// Video data
	struct AVCodecContext *video_context;
	struct AVFrame *video_local_frame; /* In format matching DMABUF */
	struct AVFrame *video_tmp_frame;   /* To hold intermediate copies */
	struct AVFrame *video_yuv_frame;   /* In enc/dec preferred format */
	void *video_yuv_frame_data;
	void *video_local_frame_data;
	struct AVPacket *video_packet;
	struct SwsContext *video_color_context;
	int64_t video_frameno;
	enum video_coding_fmt video_fmt;

	VASurfaceID video_va_surface;
	VAContextID video_va_context;
	VABufferID video_va_pipeline;
};

const char *compression_mode_to_str(enum compression_mode mode);

void setup_translation_map(struct fd_translation_map *map, bool display_side);
void cleanup_translation_map(struct fd_translation_map *map);

int setup_thread_pool(struct thread_pool *pool,
		enum compression_mode compression, int compression_level,
		int n_threads);
void cleanup_thread_pool(struct thread_pool *pool);

/** Given a file descriptor, return which type code would be applied to its
 * shadow entry. (For example, FDC_PIPE_IR for a pipe-like object that can only
 * be read.) Sets *size if non-NULL and if the object is an FDC_FILE. */
enum fdcat get_fd_type(int fd, size_t *size);
const char *fdcat_to_str(enum fdcat cat);
/** Given a local file descriptor, type hint, and already computed size,
 * produce matching global id, and register it into the translation map if
 * not already done. The function can also be provided with optional extra
 * information (*info).
 *
 * This may return NULL on allocation failure; other failures will in general
 * warn and disable replication features.
 **/
struct shadow_fd *translate_fd(struct fd_translation_map *map,
		struct render_data *render, int fd, enum fdcat type, size_t sz,
		const struct dmabuf_slice_data *info, bool force_pipe_iw);
/** Given a struct shadow_fd, produce some number of corresponding file update
 * transfer messages. All pointers will be to existing memory. */
void collect_update(struct thread_pool *threads, struct shadow_fd *cur,
		struct transfer_queue *transfers, bool use_old_dmavid_req);
/** After all thread pool tasks have completed, reduce refcounts and clean up
 * related data. The caller should then invoke destroy_shadow_if_unreferenced.
 */
void finish_update(struct shadow_fd *sfd);
/** Apply a data update message to an element in the translation map, creating
 * an entry when there is none.
 *
 * Returns -1 if the error is the fault of the other waypipe instance,
 * 0 otherwise. (For example, syscall failure => 0, bad message length => -1.)
 */
int apply_update(struct fd_translation_map *map, struct thread_pool *threads,
		struct render_data *render, enum wmsg_type type, int remote_id,
		const struct bytebuf *msg);
/** Get the shadow structure associated to a remote id, or NULL if it dne */
struct shadow_fd *get_shadow_for_rid(struct fd_translation_map *map, int rid);
/** Get shadow structure for a local file descriptor, or NULL if it dne */
struct shadow_fd *get_shadow_for_local_fd(
		struct fd_translation_map *map, int lfd);

/** Count the number of pipe fds being maintained by the translation map */
int count_npipes(const struct fd_translation_map *map);
/** Fill in pollfd entries, with POLLIN | POLLOUT, for applicable pipe objects.
 * Specifically, if check_read is true, indicate all readable pipes.
 * Also, indicate all writeable pipes for which we also something to write. */
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
bool shadow_decref_protocol(struct shadow_fd *);
bool shadow_decref_transfer(struct shadow_fd *);
/** Increase the reference count of a shadow structure, and mark it as being
 * owned. For convenience, returns the passed-in structure. */
struct shadow_fd *shadow_incref_protocol(struct shadow_fd *);
struct shadow_fd *shadow_incref_transfer(struct shadow_fd *);
/** If the shadow structure has no references, destroy it and remove it from the
 * map */
bool destroy_shadow_if_unreferenced(struct shadow_fd *sfd);
/** Decrease reference count for all objects in the given list, deleting
 * iff they are owned by protocol objects and have refcount zero */
void decref_transferred_fds(
		struct fd_translation_map *map, int nfds, int fds[]);
void decref_transferred_rids(
		struct fd_translation_map *map, int nids, int ids[]);

/** If sfd->type == FDC_FILE, increase the size of the backing data to support
 * at least new_size, and mark the new part of underlying file as dirty */
void extend_shm_shadow(struct thread_pool *threads, struct shadow_fd *sfd,
		size_t new_size);

/** Notify the threads so that they can start working on the tasks in the pool,
 * and return the total number of tasks */
int start_parallel_work(struct thread_pool *pool,
		struct thread_msg_recv_buf *recv_queue);
/** Return true if there is a work task (not a stop task) remaining for the
 * main thread to work on; also set *is_done if all tasks have completed. */
bool request_work_task(struct thread_pool *pool, struct task_data *task,
		bool *is_done);
/** Run a work task */
void run_task(struct task_data *task, struct thread_data *local);

// video.c
void cleanup_hwcontext(struct render_data *rd);
bool video_supports_dmabuf_format(uint32_t format, uint64_t modifier);
bool video_supports_shm_format(uint32_t format);
/** Fast check for whether video coding format can be used */
bool video_supports_coding_format(enum video_coding_fmt fmt);
/** set redirect for ffmpeg logging through wp_log */
void setup_video_logging(void);
void destroy_video_data(struct shadow_fd *sfd);
/** These need to have the dmabuf/dmabuf_info set beforehand */
int setup_video_encode(struct shadow_fd *sfd, struct render_data *rd);
int setup_video_decode(struct shadow_fd *sfd, struct render_data *rd);
/** the video frame to be transferred should already have been transferred into
 * `sfd->mem_mirror`. */
void collect_video_from_mirror(
		struct shadow_fd *sfd, struct transfer_queue *transfers);
/** Decompress a video packet and apply the new frame onto the shadow_fd  */
void apply_video_packet(struct shadow_fd *sfd, struct render_data *rd,
		const struct bytebuf *data);

#endif // WAYPIPE_SHADOW_H
