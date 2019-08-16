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

#include "shadow.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef HAS_LZ4
#include <lz4.h>
#include <lz4hc.h>
#endif
#ifdef HAS_ZSTD
#include <zstd.h>
#endif

struct shadow_fd *get_shadow_for_local_fd(
		struct fd_translation_map *map, int lfd)
{
	for (struct shadow_fd *cur = map->list; cur; cur = cur->next) {
		if (cur->fd_local == lfd) {
			return cur;
		}
	}
	return NULL;
}
struct shadow_fd *get_shadow_for_rid(struct fd_translation_map *map, int rid)
{
	for (struct shadow_fd *cur = map->list; cur; cur = cur->next) {
		if (cur->remote_id == rid) {
			return cur;
		}
	}
	return NULL;
}
static void destroy_unlinked_sfd(
		struct fd_translation_map *map, struct shadow_fd *sfd)
{
	wp_debug("Destroying %s RID=%d", fdcat_to_str(sfd->type),
			sfd->remote_id);
	/* video must be cleaned up before any buffers that it may rely on */
	destroy_video_data(sfd);

	/* free all accumulated damage records */
	reset_damage(&sfd->damage);
	free(sfd->damage_task_interval_store);

	if (sfd->type == FDC_FILE) {
		munmap(sfd->mem_local, sfd->buffer_size);
		free(sfd->mem_mirror);
	} else if (sfd->type == FDC_DMABUF || sfd->type == FDC_DMAVID_IR ||
			sfd->type == FDC_DMAVID_IW) {
		destroy_dmabuf(sfd->dmabuf_bo);
		free(sfd->mem_mirror);
	} else if (sfd->type == FDC_PIPE) {
		if (sfd->pipe.fd != sfd->fd_local && sfd->pipe.fd != -1) {
			close(sfd->pipe.fd);
		}
		free(sfd->pipe.recv.data);
		free(sfd->pipe.send.data);
	}
	if (sfd->fd_local != -1) {
		if (close(sfd->fd_local) == -1) {
			wp_error("Incorrect close(%d): %s", sfd->fd_local,
					strerror(errno));
		}
	}
	free(sfd);
	(void)map;
}
static void cleanup_thread_local(struct thread_data *data)
{
#ifdef HAS_ZSTD
	ZSTD_freeCCtx(data->comp_ctx.zstd_ccontext);
	ZSTD_freeDCtx(data->comp_ctx.zstd_dcontext);
#endif
#ifdef HAS_LZ4
	free(data->comp_ctx.lz4_extstate);
#endif
	free(data->tmp_buf);
}

static void setup_thread_local(struct thread_data *data,
		enum compression_mode mode, int compression_level)
{
	struct comp_ctx *ctx = &data->comp_ctx;
	ctx->zstd_ccontext = NULL;
	ctx->zstd_dcontext = NULL;
	ctx->lz4_extstate = NULL;
#ifdef HAS_LZ4
	if (mode == COMP_LZ4) {
		/* Like LZ4Frame, integer codes indicate compression level.
		 * Negative numbers are acceleration, positive use the HC
		 * routines */
		if (compression_level <= 0) {
			ctx->lz4_extstate = malloc((size_t)LZ4_sizeofState());
		} else {
			ctx->lz4_extstate = malloc((size_t)LZ4_sizeofStateHC());
		}
	}
#endif
#ifdef HAS_ZSTD
	if (mode == COMP_ZSTD) {
		ctx->zstd_ccontext = ZSTD_createCCtx();
		ctx->zstd_dcontext = ZSTD_createDCtx();
	}
#endif
	(void)mode;
	(void)compression_level;

	data->tmp_buf = NULL;
	data->tmp_size = 0;
}
void cleanup_translation_map(struct fd_translation_map *map)
{
	struct shadow_fd *cur = map->list;
	map->list = NULL;
	while (cur) {
		struct shadow_fd *tmp = cur;
		cur = tmp->next;
		tmp->next = NULL;
		destroy_unlinked_sfd(map, tmp);
	}
}
bool destroy_shadow_if_unreferenced(
		struct fd_translation_map *map, struct shadow_fd *sfd)
{
	bool autodelete = sfd->has_owner;
	if (sfd->type == FDC_PIPE && !sfd->pipe.can_read &&
			!sfd->pipe.can_write && !sfd->pipe.remote_can_read &&
			!sfd->pipe.remote_can_write) {
		autodelete = true;
	}
	if (sfd->refcount.protocol == 0 && sfd->refcount.transfer == 0 &&
			sfd->refcount.compute == false && autodelete) {
		for (struct shadow_fd *cur = map->list, *prev = NULL; cur;
				prev = cur, cur = cur->next) {
			if (cur == sfd) {
				if (!prev) {
					map->list = cur->next;
				} else {
					prev->next = cur->next;
				}
				break;
			}
		}

		destroy_unlinked_sfd(map, sfd);
		return true;
	} else if (sfd->refcount.protocol < 0 || sfd->refcount.transfer < 0) {
		wp_error("Negative refcount for rid=%d: %d protocol references, %d transfer references",
				sfd->remote_id, sfd->refcount.protocol,
				sfd->refcount.transfer);
	}
	return false;
}

static void *worker_thread_main(void *arg);
void setup_translation_map(struct fd_translation_map *map, bool display_side)
{
	map->local_sign = display_side ? -1 : 1;
	map->list = NULL;
	map->max_local_id = 1;
}

static void shutdown_threads(struct thread_pool *pool)
{
	pthread_mutex_lock(&pool->work_mutex);
	free(pool->stack);
	struct task_data task;
	memset(&task, 0, sizeof(task));
	task.type = TASK_STOP;
	pool->stack = &task;
	pool->stack_count = 1;
	pool->stack_size = 1;
	pool->do_work = true;
	pthread_cond_broadcast(&pool->work_cond);
	pthread_mutex_unlock(&pool->work_mutex);

	for (int i = 1; i < pool->nthreads; i++) {
		pthread_join(pool->threads[i].thread, NULL);
	}
	pool->stack = NULL;
}

void setup_thread_pool(struct thread_pool *pool,
		enum compression_mode compression, int comp_level,
		int n_threads)
{
	pool->diff_func = get_diff_function(
			DIFF_FASTEST, &pool->diff_alignment_bits);

	pool->compression = compression;
	pool->compression_level = comp_level;
	if (n_threads <= 0) {
		// platform dependent
		int nt = get_hardware_thread_count();
		pool->nthreads = max(nt / 2, 1);
	} else {
		pool->nthreads = n_threads;
	}
	pool->stack_size = 0;
	pool->stack_count = 0;
	pool->stack = NULL;
	pool->tasks_in_progress = 0;
	pool->do_work = true;

	pthread_mutex_init(&pool->work_mutex, NULL);
	pthread_cond_init(&pool->work_cond, NULL);

	/* Thread #0 is the 'main' thread */
	pool->threads = calloc(
			(size_t)pool->nthreads, sizeof(struct thread_data));
	bool had_failures = false;
	pool->threads[0].pool = pool;
	pool->threads[0].thread = pthread_self();
	for (int i = 1; i < pool->nthreads; i++) {
		pool->threads[i].pool = pool;
		int ret = pthread_create(&pool->threads[i].thread, NULL,
				worker_thread_main, &pool->threads[i]);
		if (ret == -1) {
			wp_error("Thread creation failed");
			had_failures = true;
			break;
		}
	}

	if (had_failures) {
		shutdown_threads(pool);
		pool->threads = realloc(
				pool->threads, sizeof(struct thread_data));
		pool->nthreads = 1;
	}

	setup_thread_local(&pool->threads[0], compression, comp_level);

	int fds[2];
	if (pipe(fds) == -1) {
		wp_error("Failed to create pipe: %s", strerror(errno));
	}
	pool->selfpipe_r = fds[0];
	pool->selfpipe_w = fds[1];
	if (set_nonblocking(pool->selfpipe_r) == -1) {
		wp_error("Failed to make read end of pipe nonblocking: %s",
				strerror(errno));
	}
}
void cleanup_thread_pool(struct thread_pool *pool)
{
	shutdown_threads(pool);
	cleanup_thread_local(&pool->threads[0]);

	pthread_mutex_destroy(&pool->work_mutex);
	pthread_cond_destroy(&pool->work_cond);
	free(pool->threads);
	free(pool->stack);

	close(pool->selfpipe_r);
	close(pool->selfpipe_w);
}

const char *fdcat_to_str(enum fdcat cat)
{
	switch (cat) {
	case FDC_UNKNOWN:
		return "FDC_UNKNOWN";
	case FDC_FILE:
		return "FDC_FILE";
	case FDC_PIPE:
		return "FDC_PIPE";
	case FDC_DMABUF:
		return "FDC_DMABUF";
	case FDC_DMAVID_IR:
		return "FDC_DMAVID_IR";
	case FDC_DMAVID_IW:
		return "FDC_DMAVID_IW";
	}
	return "<invalid>";
}

enum fdcat get_fd_type(int fd, size_t *size)
{
	struct stat fsdata;
	memset(&fsdata, 0, sizeof(fsdata));
	int ret = fstat(fd, &fsdata);
	if (ret == -1) {
		wp_error("The fd %d is not file-like: %s", fd, strerror(errno));
		return FDC_UNKNOWN;
	} else if (S_ISREG(fsdata.st_mode)) {
		if (size) {
			*size = (size_t)fsdata.st_size;
		}
		return FDC_FILE;
	} else if (S_ISFIFO(fsdata.st_mode) || S_ISCHR(fsdata.st_mode) ||
			S_ISSOCK(fsdata.st_mode)) {
		if (S_ISCHR(fsdata.st_mode)) {
			wp_error("The fd %d, size %" PRId64
				 ", mode %x is a character device. Proceeding under the assumption that it is pipe-like.",
					fd, (int64_t)fsdata.st_size,
					fsdata.st_mode);
		}
		if (S_ISSOCK(fsdata.st_mode)) {
			wp_error("The fd %d, size %" PRId64
				 ", mode %x is a socket. Proceeding under the assumption that it is pipe-like.",
					fd, (int64_t)fsdata.st_size,
					fsdata.st_mode);
		}
		return FDC_PIPE;
	} else if (is_dmabuf(fd)) {
		return FDC_DMABUF;
	} else {
		wp_error("The fd %d has an unusual mode %x (type=%x): blk=%d chr=%d dir=%d lnk=%d reg=%d fifo=%d sock=%d; expect an application crash!",
				fd, fsdata.st_mode, fsdata.st_mode & S_IFMT,
				S_ISBLK(fsdata.st_mode),
				S_ISCHR(fsdata.st_mode),
				S_ISDIR(fsdata.st_mode),
				S_ISLNK(fsdata.st_mode),
				S_ISREG(fsdata.st_mode),
				S_ISFIFO(fsdata.st_mode),
				S_ISSOCK(fsdata.st_mode), strerror(errno));
		return FDC_UNKNOWN;
	}
}

static size_t compress_bufsize(struct thread_pool *pool, size_t max_input)
{
	switch (pool->compression) {
	case COMP_NONE:
		(void)max_input;
		return 0;
#ifdef HAS_LZ4
	case COMP_LZ4:
		/* This bound applies for both LZ4 and LZ4HC compressors */
		return (size_t)LZ4_compressBound((int)max_input);
#endif
#ifdef HAS_ZSTD
	case COMP_ZSTD:
		return ZSTD_compressBound(max_input);
#endif
	}
	return 0;
}

/* With the selected compression method, compress the buffer
 * {isize,ibuf}, possibly modifying {msize,mbuf}, and setting
 * {wsize,wbuf} to indicate the result */
static void compress_buffer(struct thread_pool *pool, struct comp_ctx *ctx,
		size_t isize, const char *ibuf, size_t msize, char *mbuf,
		struct bytebuf *dst)
{
	(void)ctx;
	// Ensure inputs always nontrivial
	if (isize == 0) {
		dst->size = 0;
		dst->data = (char *)ibuf;
		return;
	}

	DTRACE_PROBE1(waypipe, compress_buffer_enter, isize);
	switch (pool->compression) {
	case COMP_NONE:
		(void)msize;
		(void)mbuf;
		dst->size = isize;
		dst->data = (char *)ibuf;
		break;
#ifdef HAS_LZ4
	case COMP_LZ4: {
		int ws;
		if (pool->compression_level <= 0) {
			ws = LZ4_compress_fast_extState(ctx->lz4_extstate, ibuf,
					mbuf, (int)isize, (int)msize,
					-pool->compression_level);
		} else {
			ws = LZ4_compress_HC_extStateHC(ctx->lz4_extstate, ibuf,
					mbuf, (int)isize, (int)msize,
					pool->compression_level);
		}
		if (ws == 0) {
			wp_error("LZ4 compression failed for %zu bytes in %zu of space",
					isize, msize);
		}
		dst->size = (size_t)ws;
		dst->data = (char *)mbuf;
		break;
	}
#endif
#ifdef HAS_ZSTD
	case COMP_ZSTD: {
		size_t ws = ZSTD_compressCCtx(ctx->zstd_ccontext, mbuf, msize,
				ibuf, isize, pool->compression_level);
		if (ZSTD_isError(ws)) {
			wp_error("Zstd compression failed for %d bytes in %d of space: %s",
					(int)isize, (int)msize,
					ZSTD_getErrorName(ws));
		}
		dst->size = (size_t)ws;
		dst->data = (char *)mbuf;
		break;
	}
#endif
	}
	DTRACE_PROBE1(waypipe, compress_buffer_exit, dst->size);
}
/* With the selected compression method, uncompress the buffer {isize,ibuf},
 * to precisely msize bytes, setting {wsize,wbuf} to indicate the result.
 * If the compression mode requires it. */
static void uncompress_buffer(struct thread_pool *pool, struct comp_ctx *ctx,
		size_t isize, const char *ibuf, size_t msize, char *mbuf,
		size_t *wsize, const char **wbuf)
{
	(void)ctx;
	// Ensure inputs always nontrivial
	if (isize == 0) {
		*wsize = 0;
		*wbuf = ibuf;
		return;
	}

	DTRACE_PROBE1(waypipe, uncompress_buffer_enter, isize);
	switch (pool->compression) {
	case COMP_NONE:
		(void)mbuf;
		(void)msize;
		*wsize = isize;
		*wbuf = ibuf;
		break;
#ifdef HAS_LZ4
	case COMP_LZ4: {
		int ws = LZ4_decompress_safe(
				ibuf, mbuf, (int)isize, (int)msize);
		if (ws < 0 || (size_t)ws != msize) {
			wp_error("Lz4 decompression failed for %d bytes to %d of space, used %d",
					(int)isize, (int)msize, ws);
		}
		*wsize = (size_t)ws;
		*wbuf = mbuf;
		break;
	}
#endif
#ifdef HAS_ZSTD
	case COMP_ZSTD: {
		size_t ws = ZSTD_decompressDCtx(
				ctx->zstd_dcontext, mbuf, msize, ibuf, isize);
		if (ZSTD_isError(ws) || (size_t)ws != msize) {
			wp_error("Zstd decompression failed for %d bytes to %d of space: %s",
					(int)isize, (int)msize,
					ZSTD_getErrorName(ws));
			ws = 0;
		}
		*wsize = ws;
		*wbuf = mbuf;
		break;
	}
#endif
	}
	DTRACE_PROBE1(waypipe, uncompress_buffer_exit, *wsize);
}

struct shadow_fd *translate_fd(struct fd_translation_map *map,
		struct render_data *render, int fd, enum fdcat type,
		size_t file_sz, const struct dmabuf_slice_data *info,
		bool read_modifier, bool force_pipe_iw)
{
	struct shadow_fd *sfd = get_shadow_for_local_fd(map, fd);
	if (sfd) {
		return sfd;
	}
	if (type == FDC_DMAVID_IR || type == FDC_DMAVID_IW) {
		if (!info) {
			wp_error("No dmabuf info provided");
			return NULL;
		}
	}

	// Create a new translation map.
	sfd = calloc(1, sizeof(struct shadow_fd));
	sfd->next = map->list;
	map->list = sfd;
	sfd->fd_local = fd;
	sfd->mem_local = NULL;
	sfd->mem_mirror = NULL;
	sfd->buffer_size = 0;
	sfd->remote_id = (map->max_local_id++) * map->local_sign;
	sfd->type = type;
	// File changes must be propagated
	sfd->is_dirty = true;
	damage_everything(&sfd->damage);
	sfd->has_owner = false;
	/* Start the number of expected transfers to channel remaining
	 * at one, and number of protocol objects referencing this
	 * shadow_fd at zero.*/
	sfd->refcount.transfer = 1;
	sfd->refcount.protocol = 0;
	sfd->refcount.compute = false;

	sfd->only_here = true;

	wp_debug("Creating new %s shadow RID=%d for local fd %d",
			fdcat_to_str(sfd->type), sfd->remote_id, fd);
	if (sfd->type == FDC_FILE) {
		if (file_sz >= UINT32_MAX / 2) {
			wp_error("Failed to create shadow structure, file size %zu too large to transfer",
					file_sz);
			return sfd;
		}
		sfd->buffer_size = file_sz;
		// both r/w permissions, because the size the allocates
		// the memory does not always have to be the size that
		// modifies it
		sfd->mem_local = mmap(NULL, sfd->buffer_size,
				PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		if (!sfd->mem_local) {
			wp_error("Mmap failed!");
			return sfd;
		}
		// This will be created at the first transfer
		sfd->mem_mirror = NULL;
	} else if (sfd->type == FDC_PIPE) {
		// Make this end of the pipe nonblocking, so that we can
		// include it in our main loop.
		if (set_nonblocking(sfd->fd_local) == -1) {
			wp_error("Failed to make fd nonblocking");
		}
		sfd->pipe.fd = sfd->fd_local;

		if (force_pipe_iw) {
			sfd->pipe.can_write = true;
		} else {
			/* this classification overestimates with
			 * socketpairs that have partially been shutdown.
			 * what about platform-specific RW pipes? */
			int flags = fcntl(fd, F_GETFL, 0);
			if (flags == -1) {
				wp_error("fctnl F_GETFL failed!");
			}
			if ((flags & O_ACCMODE) == O_RDONLY) {
				sfd->pipe.can_read = true;
			} else if ((flags & O_ACCMODE) == O_WRONLY) {
				sfd->pipe.can_write = true;
			} else {
				sfd->pipe.can_read = true;
				sfd->pipe.can_write = true;
			}
		}
	} else if (sfd->type == FDC_DMAVID_IR) {
		memcpy(&sfd->dmabuf_info, info,
				sizeof(struct dmabuf_slice_data));
		init_render_data(render);
		sfd->dmabuf_bo = import_dmabuf(render, sfd->fd_local,
				&sfd->buffer_size, &sfd->dmabuf_info,
				read_modifier);
		if (!sfd->dmabuf_bo) {
			return sfd;
		}
		int mirror_size = 0;
		pad_video_mirror_size((int)sfd->dmabuf_info.width,
				(int)sfd->dmabuf_info.height,
				(int)sfd->dmabuf_info.strides[0], NULL, NULL,
				&mirror_size);
		sfd->mem_mirror = calloc(
				(size_t)max((int)sfd->buffer_size, mirror_size),
				1);
		(void)setup_video_encode(sfd, render);
	} else if (sfd->type == FDC_DMAVID_IW) {
		memcpy(&sfd->dmabuf_info, info,
				sizeof(struct dmabuf_slice_data));
		// TODO: multifd-dmabuf video surface
		init_render_data(render);
		sfd->dmabuf_bo = import_dmabuf(render, sfd->fd_local,
				&sfd->buffer_size, &sfd->dmabuf_info,
				read_modifier);
		if (!sfd->dmabuf_bo) {
			return sfd;
		}
		(void)setup_video_decode(sfd, render);
	} else if (sfd->type == FDC_DMABUF) {
		sfd->buffer_size = 0;

		init_render_data(render);
		if (info) {
			memcpy(&sfd->dmabuf_info, info,
					sizeof(struct dmabuf_slice_data));
		} else {
			// already zero initialized (no information).
		}
		sfd->dmabuf_bo = import_dmabuf(render, sfd->fd_local,
				&sfd->buffer_size, &sfd->dmabuf_info,
				read_modifier);
		if (!sfd->dmabuf_bo) {
			return sfd;
		}
		// to be created on first transfer
		sfd->mem_mirror = NULL;
	}
	return sfd;
}

static void *shrink_buffer(void *buf, size_t sz)
{
	void *nbuf = realloc(buf, sz);
	if (nbuf) {
		return nbuf;
	} else {
		wp_debug("Failed to shrink buffer with realloc, not a problem");
		return buf;
	}
}

/* Construct and optionally compress a diff between sfd->mem_mirror and
 * the actual memmap'd data */
static void worker_run_compress_diff(
		struct task_data *task, struct thread_data *local)
{
	struct shadow_fd *sfd = task->sfd;
	struct thread_pool *pool = local->pool;

	size_t damage_space = 0;
	for (int i = 0; i < task->damage_len; i++) {
		int range = task->damage_intervals[i].end -
			    task->damage_intervals[i].start;
		damage_space += (size_t)range + 8;
	}
	if (task->damaged_end) {
		damage_space += 1u << pool->diff_alignment_bits;
	}
	DTRACE_PROBE1(waypipe, worker_compdiff_enter, damage_space);

	char *diff_buffer = NULL;
	char *diff_target = NULL;
	if (pool->compression == COMP_NONE) {
		diff_buffer = malloc(
				damage_space + sizeof(struct wmsg_buffer_diff));
		if (!diff_buffer) {
			wp_error("Allocation failed, dropping diff transfer block");
			goto end;
		}
		diff_target = diff_buffer + sizeof(struct wmsg_buffer_diff);
	} else {
		if (buf_ensure_size((int)damage_space, 1, &local->tmp_size,
				    &local->tmp_buf) == -1) {
			wp_error("Allocation failed, dropping diff transfer block");
			goto end;
		}
		diff_target = local->tmp_buf;
	}

	DTRACE_PROBE1(waypipe, construct_diff_enter, task->damage_len);
	size_t diffsize = construct_diff_core(pool->diff_func,
			pool->diff_alignment_bits, task->damage_intervals,
			task->damage_len, sfd->mem_mirror, sfd->mem_local,
			diff_target);
	size_t ntrailing = 0;
	if (task->damaged_end) {
		ntrailing = construct_diff_trailing(sfd->buffer_size,
				pool->diff_alignment_bits, sfd->mem_mirror,
				sfd->mem_local, diff_target + diffsize);
	}
	DTRACE_PROBE1(waypipe, construct_diff_exit, diffsize);
	if (diffsize == 0 && ntrailing == 0) {
		free(diff_buffer);
		goto end;
	}

	uint8_t *msg;
	size_t sz;
	size_t net_diff_sz = diffsize + ntrailing;
	if (pool->compression == COMP_NONE) {
		sz = net_diff_sz + sizeof(struct wmsg_buffer_diff);
		msg = (uint8_t *)diff_buffer;
	} else {
		struct bytebuf dst;
		size_t comp_size = compress_bufsize(pool, net_diff_sz);
		char *comp_buf = malloc(alignz(comp_size, 4) +
					sizeof(struct wmsg_buffer_diff));
		if (!comp_buf) {
			wp_error("Allocation failed, dropping diff transfer block");
			goto end;
		}
		compress_buffer(pool, &local->comp_ctx, net_diff_sz,
				diff_target, comp_size,
				comp_buf + sizeof(struct wmsg_buffer_diff),
				&dst);
		sz = dst.size + sizeof(struct wmsg_buffer_diff);
		msg = (uint8_t *)comp_buf;
	}
	msg = shrink_buffer(msg, alignz(sz, 4));
	memset(msg + sz, 0, alignz(sz, 4) - sz);
	struct wmsg_buffer_diff header;
	header.size_and_type = transfer_header(sz, WMSG_BUFFER_DIFF);
	header.remote_id = sfd->remote_id;
	header.diff_size = (uint32_t)diffsize;
	header.ntrailing = (uint32_t)ntrailing;
	memcpy(msg, &header, sizeof(struct wmsg_buffer_diff));

	transfer_async_add(task->msg_queue, msg, alignz(sz, 4));

end:
	DTRACE_PROBE1(waypipe, worker_compdiff_exit, diffsize);
}

/* Compress data for sfd->mem_mirror */
static void worker_run_compress_block(
		struct task_data *task, struct thread_data *local)
{

	struct shadow_fd *sfd = task->sfd;
	struct thread_pool *pool = local->pool;
	if (task->zone_end == task->zone_start) {
		wp_error("Skipping task");
		return;
	}

	/* Allocate a disjoint target interval to each worker */
	size_t source_start = (size_t)task->zone_start;
	size_t source_end = (size_t)task->zone_end;
	DTRACE_PROBE1(waypipe, worker_comp_enter, source_end - source_start);

	size_t sz = 0;
	uint8_t *msg;
	if (pool->compression == COMP_NONE) {
		sz = sizeof(struct wmsg_buffer_fill) +
		     (source_end - source_start);

		msg = malloc(alignz(sz, 4));
		if (!msg) {
			wp_error("Allocation failed, dropping fill transfer block");
			goto end;
		}
		memcpy(msg + sizeof(struct wmsg_buffer_fill),
				sfd->mem_mirror + source_start,
				source_end - source_start);
	} else {
		size_t comp_size = compress_bufsize(
				pool, source_end - source_start);
		msg = malloc(alignz(comp_size, 4) +
				sizeof(struct wmsg_buffer_fill));
		if (!msg) {
			wp_error("Allocation failed, dropping fill transfer block");
			goto end;
		}
		struct bytebuf dst;
		compress_buffer(pool, &local->comp_ctx,
				source_end - source_start,
				&sfd->mem_mirror[source_start], comp_size,
				(char *)msg + sizeof(struct wmsg_buffer_fill),
				&dst);
		sz = dst.size + sizeof(struct wmsg_buffer_fill);
		msg = shrink_buffer(msg, alignz(sz, 4));
	}
	memset(msg + sz, 0, alignz(sz, 4) - sz);
	struct wmsg_buffer_fill header;
	header.size_and_type = transfer_header(sz, WMSG_BUFFER_FILL);
	header.remote_id = sfd->remote_id;
	header.start = (uint32_t)source_start;
	header.end = (uint32_t)source_end;
	memcpy(msg, &header, sizeof(struct wmsg_buffer_fill));

	transfer_async_add(task->msg_queue, msg, alignz(sz, 4));

end:
	DTRACE_PROBE1(waypipe, worker_comp_exit,
			sz - sizeof(struct wmsg_buffer_fill));
}

/* Optionally compress the data in mem_mirror, and set up the initial
 * transfer blocks */
static void queue_fill_transfers(struct thread_pool *threads,
		struct shadow_fd *sfd, struct transfer_queue *transfers)
{
	// new transfer, we send file contents verbatim
	const int chunksize = 262144;

	int region_start = (int)sfd->remote_bufsize;
	int region_end = (int)sfd->buffer_size;
	if (region_start == region_end) {
		return;
	}

	/* Keep sfd alive at least until write to channel is done */
	sfd->refcount.compute = true;

	int nshards = ceildiv((region_end - region_start), chunksize);

	pthread_mutex_lock(&threads->work_mutex);
	if (buf_ensure_size(threads->stack_count + nshards,
			    sizeof(struct task_data), &threads->stack_size,
			    (void **)&threads->stack) == -1) {
		wp_error("Allocation failed, dropping some fill tasks");
		pthread_mutex_unlock(&threads->work_mutex);
		return;
	}

	for (int i = 0; i < nshards; i++) {
		struct task_data task;
		memset(&task, 0, sizeof(task));
		task.type = TASK_COMPRESS_BLOCK;
		task.sfd = sfd;
		task.msg_queue = &transfers->async_recv_queue;

		int range = (region_end - region_start);
		task.zone_start = region_start + (range * i) / nshards;
		task.zone_end = region_start + (range * (i + 1)) / nshards;

		threads->stack[threads->stack_count++] = task;
	}
	pthread_mutex_unlock(&threads->work_mutex);
}

static void queue_diff_transfers(struct thread_pool *threads,
		struct shadow_fd *sfd, struct transfer_queue *transfers)
{
	const int chunksize = 262144;
	if (!sfd->damage.damage) {
		return;
	}

	/* Keep sfd alive at least until write to channel is done */
	sfd->refcount.compute = true;

	int bs = 1 << threads->diff_alignment_bits;
	int align_end = bs * ((int)sfd->buffer_size / bs);
	bool check_tail = false;

	int net_damage = 0;
	if (sfd->damage.damage == DAMAGE_EVERYTHING) {
		reset_damage(&sfd->damage);
		struct ext_interval all = {.start = 0,
				.width = align_end,
				.rep = 1,
				.stride = 0};
		merge_damage_records(&sfd->damage, 1, &all,
				threads->diff_alignment_bits);
		check_tail = true;
		net_damage = align_end;
	} else {
		for (int ir = 0, iw = 0; ir < sfd->damage.ndamage_intvs; ir++) {
			/* Extend all damage to the nearest alignment block */
			struct interval e = sfd->damage.damage[ir];
			check_tail |= e.end > align_end;
			e.end = min(e.end, align_end);
			if (e.start < e.end) {
				/* End clipping may produce empty/degenerate
				 * intervals, so filter them out now */
				sfd->damage.damage[iw++] = e;
				net_damage += e.end - e.start;
			}
			if (e.end & (bs - 1) || e.start & (bs - 1)) {
				wp_error("Interval [%d, %d) is not aligned",
						e.start, e.end);
			}
		}
	}
	int nshards = ceildiv(net_damage, chunksize);

	/* Instead of allocating individual buffers for each task, create a
	 * global damage tracking buffer into which tasks index. It will be
	 * deleted in `finish_update`. */
	struct interval *intvs = malloc(
			sizeof(struct interval) *
			(size_t)(sfd->damage.ndamage_intvs + nshards));
	int *offsets = calloc((size_t)nshards + 1, sizeof(int));
	if (!offsets) {
		// TODO: avoid making this allocation entirely
		wp_error("Failed to allocate diff region control buffer, dropping diff tasks");
		return;
	}

	sfd->damage_task_interval_store = intvs;
	int tot_blocks = net_damage / bs;
	int ir = 0, iw = 0, acc_prev_blocks = 0;
	for (int shard = 0; shard < nshards; shard++) {
		int s_lower = (int)(shard * (int64_t)tot_blocks) / nshards;
		int s_upper = (int)((shard + 1) * (int64_t)tot_blocks) /
			      nshards;

		while (acc_prev_blocks < s_upper &&
				ir < sfd->damage.ndamage_intvs) {
			struct interval e = sfd->damage.damage[ir];
			const int w = (e.end - e.start) / bs;

			int a_low = max(0, s_lower - acc_prev_blocks);
			int a_high = min(w, s_upper - acc_prev_blocks);

			struct interval r = {
					.start = e.start + bs * a_low,
					.end = e.start + bs * a_high,
			};
			intvs[iw++] = r;

			if (acc_prev_blocks + w > s_upper) {
				break;
			} else {
				acc_prev_blocks += w;
				ir++;
			}
		}

		offsets[shard + 1] = iw;
	}
	/* Reset damage, once it has been applied */
	reset_damage(&sfd->damage);

	pthread_mutex_lock(&threads->work_mutex);
	if (buf_ensure_size(threads->stack_count + nshards,
			    sizeof(struct task_data), &threads->stack_size,
			    (void **)&threads->stack) == -1) {
		wp_error("Allocation failed, dropping some diff tasks");
		pthread_mutex_unlock(&threads->work_mutex);
		free(offsets);
		return;
	}

	for (int i = 0; i < nshards; i++) {
		struct task_data task;
		memset(&task, 0, sizeof(task));
		task.type = TASK_COMPRESS_DIFF;
		task.sfd = sfd;
		task.msg_queue = &transfers->async_recv_queue;

		task.damage_len = offsets[i + 1] - offsets[i];
		task.damage_intervals =
				&sfd->damage_task_interval_store[offsets[i]];
		task.damaged_end = (i == nshards - 1) && check_tail;

		threads->stack[threads->stack_count++] = task;
	}
	pthread_mutex_unlock(&threads->work_mutex);
	free(offsets);
}

static void add_dmabuf_create_request(struct transfer_queue *transfers,
		struct shadow_fd *sfd, enum wmsg_type variant)
{
	size_t actual_len = sizeof(struct wmsg_open_dmabuf) +
			    sizeof(struct dmabuf_slice_data);
	size_t padded_len = alignz(actual_len, 4);

	uint8_t *data = calloc(1, padded_len);
	struct wmsg_open_dmabuf *header = (struct wmsg_open_dmabuf *)data;
	header->file_size = (uint32_t)sfd->buffer_size;
	header->remote_id = sfd->remote_id;
	header->size_and_type = transfer_header(actual_len, variant);
	memcpy(data + sizeof(struct wmsg_open_dmabuf), &sfd->dmabuf_info,
			sizeof(struct dmabuf_slice_data));

	transfer_add(transfers, padded_len, data, false);
}
static void add_file_create_request(
		struct transfer_queue *transfers, struct shadow_fd *sfd)
{
	struct wmsg_open_file *header =
			calloc(1, sizeof(struct wmsg_open_file));
	header->file_size = (uint32_t)sfd->buffer_size;
	header->remote_id = sfd->remote_id;
	header->size_and_type = transfer_header(
			sizeof(struct wmsg_open_file), WMSG_OPEN_FILE);

	transfer_add(transfers, sizeof(struct wmsg_open_file), header, false);
}

void finish_update(struct shadow_fd *sfd)
{
	if (!sfd->refcount.compute) {
		return;
	}
	if (sfd->type == FDC_DMABUF && sfd->dmabuf_map_handle) {
		// if this fails, unmap_dmabuf will print error
		(void)unmap_dmabuf(sfd->dmabuf_bo, sfd->dmabuf_map_handle);
		sfd->dmabuf_map_handle = NULL;
		sfd->mem_local = NULL;
	}
	if (sfd->damage_task_interval_store) {
		free(sfd->damage_task_interval_store);
		sfd->damage_task_interval_store = NULL;
	}
	sfd->refcount.compute = false;
}

void collect_update(struct thread_pool *threads, struct shadow_fd *sfd,
		struct transfer_queue *transfers)
{
	if (sfd->type == FDC_FILE) {
		if (!sfd->is_dirty) {
			// File is clean, we have no reason to believe
			// that its contents could have changed
			return;
		}
		// Clear dirty state
		sfd->is_dirty = false;
		if (sfd->only_here) {
			sfd->only_here = false;
			reset_damage(&sfd->damage);

			// increase space, to avoid overflow when
			// writing this buffer along with padding
			size_t alignment = 1u << threads->diff_alignment_bits;
			sfd->mem_mirror = aligned_alloc(alignment,
					alignz(sfd->buffer_size, alignment));
			memcpy(sfd->mem_mirror, sfd->mem_local,
					sfd->buffer_size);

			sfd->remote_bufsize = 0;

			add_file_create_request(transfers, sfd);
			queue_fill_transfers(threads, sfd, transfers);
			sfd->remote_bufsize = sfd->buffer_size;
			return;
		}

		if (sfd->remote_bufsize < sfd->buffer_size) {
			struct wmsg_open_file *header = calloc(
					1, sizeof(struct wmsg_open_file));
			header->file_size = (uint32_t)sfd->buffer_size;
			header->remote_id = sfd->remote_id;
			header->size_and_type = transfer_header(
					sizeof(struct wmsg_open_file),
					WMSG_EXTEND_FILE);

			transfer_add(transfers, sizeof(struct wmsg_open_file),
					header, false);

			memcpy(sfd->mem_mirror + sfd->remote_bufsize,
					sfd->mem_local + sfd->remote_bufsize,
					sfd->buffer_size - sfd->remote_bufsize);

			queue_fill_transfers(threads, sfd, transfers);
			sfd->remote_bufsize = sfd->buffer_size;
		}

		queue_diff_transfers(threads, sfd, transfers);
	} else if (sfd->type == FDC_DMABUF) {
		// If buffer is clean, do not check for changes
		if (!sfd->is_dirty) {
			return;
		}
		sfd->is_dirty = false;

		bool first = false;
		if (sfd->only_here) {
			sfd->only_here = false;
			first = true;

			add_dmabuf_create_request(
					transfers, sfd, WMSG_OPEN_DMABUF);
		}
		if (!sfd->dmabuf_bo) {
			// ^ was not previously able to create buffer
			return;
		}
		if (!sfd->mem_local) {
			sfd->mem_local = map_dmabuf(sfd->dmabuf_bo, false,
					&sfd->dmabuf_map_handle);
			if (!sfd->mem_local) {
				return;
			}
		}
		if (first) {
			size_t alignment = 1u << threads->diff_alignment_bits;
			sfd->mem_mirror = aligned_alloc(alignment,
					alignz(sfd->buffer_size, alignment));
			// Q: is it better to run the copy in parallel?
			memcpy(sfd->mem_mirror, sfd->mem_local,
					sfd->buffer_size);

			queue_fill_transfers(threads, sfd, transfers);
		} else {
			damage_everything(&sfd->damage);

			queue_diff_transfers(threads, sfd, transfers);
		}
		/* Unmapping will be handled by finish_update() */

	} else if (sfd->type == FDC_DMAVID_IR) {
		if (!sfd->is_dirty) {
			return;
		}
		sfd->is_dirty = false;
		if (!sfd->dmabuf_bo || !sfd->video_context) {
			// ^ was not previously able to create buffer
			return;
		}
		if (sfd->only_here) {
			sfd->only_here = false;
			add_dmabuf_create_request(
					transfers, sfd, WMSG_OPEN_DMAVID_DST);
		}
		collect_video_from_mirror(sfd, transfers);
	} else if (sfd->type == FDC_DMAVID_IW) {
		sfd->is_dirty = false;
		if (sfd->only_here) {
			sfd->only_here = false;
			add_dmabuf_create_request(
					transfers, sfd, WMSG_OPEN_DMAVID_SRC);
		}
	} else if (sfd->type == FDC_PIPE) {
		// Pipes always update, no matter what the message
		// stream indicates.
		if (sfd->only_here) {
			sfd->only_here = false;

			struct wmsg_basic *createh =
					calloc(1, sizeof(struct wmsg_basic));
			enum wmsg_type type;
			if (sfd->pipe.can_read && !sfd->pipe.can_write) {
				type = WMSG_OPEN_IW_PIPE;
				sfd->pipe.remote_can_write = true;
			} else if (sfd->pipe.can_write && !sfd->pipe.can_read) {
				type = WMSG_OPEN_IR_PIPE;
				sfd->pipe.remote_can_read = true;
			} else {
				type = WMSG_OPEN_RW_PIPE;
				sfd->pipe.remote_can_read = true;
				sfd->pipe.remote_can_write = true;
			}
			createh->size_and_type = transfer_header(
					sizeof(struct wmsg_basic), type);
			createh->remote_id = sfd->remote_id;

			transfer_add(transfers, sizeof(struct wmsg_basic),
					createh, false);
		}

		if (sfd->pipe.recv.used > 0) {
			size_t msgsz = sizeof(struct wmsg_basic) +
				       (size_t)sfd->pipe.recv.used;
			char *buf = malloc(alignz(msgsz, 4));
			struct wmsg_basic *header = (struct wmsg_basic *)buf;
			header->size_and_type = transfer_header(
					msgsz, WMSG_PIPE_TRANSFER);
			header->remote_id = sfd->remote_id;
			memcpy(buf + sizeof(struct wmsg_basic),
					sfd->pipe.recv.data,
					(size_t)sfd->pipe.recv.used);
			memset(buf + msgsz, 0, alignz(msgsz, 4) - msgsz);

			transfer_add(transfers, alignz(msgsz, 4), buf, false);

			sfd->pipe.recv.used = 0;
		}

		if (!sfd->pipe.can_read && sfd->pipe.remote_can_write) {
			struct wmsg_basic *header =
					calloc(1, sizeof(struct wmsg_basic));
			header->size_and_type = transfer_header(
					sizeof(struct wmsg_basic),
					WMSG_PIPE_SHUTDOWN_W);
			header->remote_id = sfd->remote_id;
			transfer_add(transfers, sizeof(struct wmsg_basic),
					header, false);
			sfd->pipe.remote_can_write = false;
		}
		if (!sfd->pipe.can_write && sfd->pipe.remote_can_read) {
			struct wmsg_basic *header =
					calloc(1, sizeof(struct wmsg_basic));
			header->size_and_type = transfer_header(
					sizeof(struct wmsg_basic),
					WMSG_PIPE_SHUTDOWN_R);
			header->remote_id = sfd->remote_id;
			transfer_add(transfers, sizeof(struct wmsg_basic),
					header, false);
			sfd->pipe.remote_can_read = false;
		}
	}
}

static int create_from_update(struct fd_translation_map *map,
		struct thread_pool *threads, struct render_data *render,
		enum wmsg_type type, int remote_id, const struct bytebuf *msg)
{
	if (type == WMSG_OPEN_FILE) {
		if (msg->size < sizeof(struct wmsg_open_file)) {
			wp_error("Message size to create file is too small (%zu bytes)",
					msg->size);
			return ERR_FATAL;
		}
	} else if (type == WMSG_OPEN_DMABUF || type == WMSG_OPEN_DMAVID_DST ||
			type == WMSG_OPEN_DMAVID_SRC) {
		if (msg->size < sizeof(struct wmsg_open_dmabuf) +
						sizeof(struct dmabuf_slice_data)) {
			wp_error("Message size to create dmabuf is too small (%zu bytes)",
					msg->size);
			return ERR_FATAL;
		}
	}

	wp_debug("Introducing new fd, remoteid=%d", remote_id);
	struct shadow_fd *sfd = calloc(1, sizeof(struct shadow_fd));
	sfd->next = map->list;
	map->list = sfd;
	sfd->remote_id = remote_id;
	sfd->fd_local = -1;
	sfd->is_dirty = false;
	reset_damage(&sfd->damage);
	sfd->only_here = false;
	/* Start the object reference at one, so that, if it is owned by
	 * some known protocol object, it can not be deleted until the
	 * fd has at least be transferred over the Wayland connection */
	sfd->refcount.transfer = 1;
	sfd->refcount.protocol = 0;
	sfd->refcount.compute = false;
	if (type == WMSG_OPEN_FILE) {

		const struct wmsg_open_file header =
				*(const struct wmsg_open_file *)msg->data;

		sfd->type = FDC_FILE;
		sfd->mem_local = NULL;
		sfd->buffer_size = header.file_size;
		sfd->remote_bufsize = sfd->buffer_size;
		size_t alignment = 1u << threads->diff_alignment_bits;
		sfd->mem_mirror = aligned_alloc(
				alignment, alignz(sfd->buffer_size, alignment));

		// The PID should be unique during the lifetime of the
		// program
		char file_shm_buf_name[256];
		sprintf(file_shm_buf_name, "/waypipe%d-data_%d", getpid(),
				sfd->remote_id);

		sfd->fd_local = shm_open(file_shm_buf_name,
				O_RDWR | O_CREAT | O_TRUNC, 0644);
		if (sfd->fd_local == -1) {
			wp_error("Failed to create shm file for object %d: %s",
					sfd->remote_id, strerror(errno));
			return 0;
		}
		if (shm_unlink(file_shm_buf_name) == -1) {
			wp_error("Failed to unlink new shm file for object %d: %s",
					sfd->remote_id, strerror(errno));
		}
		if (ftruncate(sfd->fd_local, (off_t)sfd->buffer_size) == -1) {
			wp_error("Failed to resize shm file %s to size %zu for reason: %s",
					file_shm_buf_name, sfd->buffer_size,
					strerror(errno));
			return 0;
		}
		sfd->mem_local = mmap(NULL, sfd->buffer_size,
				PROT_READ | PROT_WRITE, MAP_SHARED,
				sfd->fd_local, 0);
		memcpy(sfd->mem_local, sfd->mem_mirror, sfd->buffer_size);
	} else if (type == WMSG_OPEN_RW_PIPE || type == WMSG_OPEN_IW_PIPE ||
			type == WMSG_OPEN_IR_PIPE) {
		sfd->type = FDC_PIPE;

		int pipedes[2];
		if (type == WMSG_OPEN_RW_PIPE) {
			if (socketpair(AF_UNIX, SOCK_STREAM, 0, pipedes) ==
					-1) {
				wp_error("Failed to create a socketpair: %s",
						strerror(errno));
				return 0;
			}
		} else {
			if (pipe(pipedes) == -1) {
				wp_error("Failed to create a pipe: %s",
						strerror(errno));
				return 0;
			}
		}

		/* We pass 'fd_local' to the client, although we only
		 * read and write from pipe_fd if it exists. */
		if (type == WMSG_OPEN_IR_PIPE) {
			// Read end is 0; the other process writes
			sfd->fd_local = pipedes[1];
			sfd->pipe.fd = pipedes[0];
			sfd->pipe.can_read = true;
			sfd->pipe.remote_can_write = true;
		} else if (type == WMSG_OPEN_IW_PIPE) {
			// Write end is 1; the other process reads
			sfd->fd_local = pipedes[0];
			sfd->pipe.fd = pipedes[1];
			sfd->pipe.can_write = true;
			sfd->pipe.remote_can_read = true;
		} else { // FDC_PIPE_RW
			// Here, it doesn't matter which end is which
			sfd->fd_local = pipedes[0];
			sfd->pipe.fd = pipedes[1];
			sfd->pipe.can_read = true;
			sfd->pipe.can_write = true;
			sfd->pipe.remote_can_read = true;
			sfd->pipe.remote_can_write = true;
		}

		if (set_nonblocking(sfd->pipe.fd) == -1) {
			wp_error("Failed to make private pipe end nonblocking: %s",
					strerror(errno));
			return 0;
		}
	} else if (type == WMSG_OPEN_DMAVID_DST) {
		/* remote read data, this side writes data */
		sfd->type = FDC_DMAVID_IW;
		const struct wmsg_open_dmabuf header =
				*(const struct wmsg_open_dmabuf *)msg->data;

		sfd->buffer_size = header.file_size;

		if (init_render_data(render) == 1) {
			sfd->fd_local = -1;
			return 0;
		}
		memcpy(&sfd->dmabuf_info,
				msg->data + sizeof(struct wmsg_open_dmabuf),
				sizeof(struct dmabuf_slice_data));
		sfd->dmabuf_bo = make_dmabuf(
				render, sfd->buffer_size, &sfd->dmabuf_info);
		if (!sfd->dmabuf_bo) {
			wp_error("FDC_DMAVID_IW: RID=%d make_dmabuf failure, sz=%d (%d)",
					sfd->remote_id, (int)sfd->buffer_size,
					sizeof(struct dmabuf_slice_data));
			return 0;
		}
		sfd->fd_local = export_dmabuf(sfd->dmabuf_bo);

		int mirror_size = 0;
		pad_video_mirror_size((int)sfd->dmabuf_info.width,
				(int)sfd->dmabuf_info.height,
				(int)sfd->dmabuf_info.strides[0], NULL, NULL,
				&mirror_size);
		sfd->mem_mirror = calloc(
				(size_t)max((int)sfd->buffer_size, mirror_size),
				1);
		(void)setup_video_decode(sfd, render);
	} else if (type == WMSG_OPEN_DMAVID_SRC) {
		/* remote writes data, this side reads data */
		sfd->type = FDC_DMAVID_IR;
		const struct wmsg_open_dmabuf header =
				*(const struct wmsg_open_dmabuf *)msg->data;
		sfd->buffer_size = header.file_size;

		if (init_render_data(render) == 1) {
			sfd->fd_local = -1;
			return 0;
		}

		memcpy(&sfd->dmabuf_info,
				msg->data + sizeof(struct wmsg_open_dmabuf),
				sizeof(struct dmabuf_slice_data));
		sfd->dmabuf_bo = make_dmabuf(
				render, sfd->buffer_size, &sfd->dmabuf_info);
		if (!sfd->dmabuf_bo) {
			wp_error("FDC_DMAVID_IR: RID=%d make_dmabuf failure",
					sfd->remote_id);
			return 0;
		}
		sfd->fd_local = export_dmabuf(sfd->dmabuf_bo);

		int mirror_size = 0;
		pad_video_mirror_size((int)sfd->dmabuf_info.width,
				(int)sfd->dmabuf_info.height,
				(int)sfd->dmabuf_info.strides[0], NULL, NULL,
				&mirror_size);
		sfd->mem_mirror = calloc(
				(size_t)max((int)sfd->buffer_size, mirror_size),
				1);
		(void)setup_video_encode(sfd, render);
	} else if (type == WMSG_OPEN_DMABUF) {
		sfd->type = FDC_DMABUF;
		const struct wmsg_open_dmabuf header =
				*(const struct wmsg_open_dmabuf *)msg->data;
		sfd->buffer_size = header.file_size;

		memcpy(&sfd->dmabuf_info,
				msg->data + sizeof(struct wmsg_open_dmabuf),
				sizeof(struct dmabuf_slice_data));
		size_t alignment = 1u << threads->diff_alignment_bits;
		sfd->mem_mirror = aligned_alloc(
				alignment, alignz(sfd->buffer_size, alignment));

		wp_debug("Creating remote DMAbuf of %d bytes",
				(int)sfd->buffer_size);
		// Create mirror from first transfer
		// The file can only actually be created when we know
		// what type it is?
		if (init_render_data(render) == 1) {
			sfd->fd_local = -1;
			return 0;
		}

		sfd->dmabuf_bo = make_dmabuf(
				render, sfd->buffer_size, &sfd->dmabuf_info);
		if (!sfd->dmabuf_bo) {
			sfd->fd_local = -1;
			return 0;
		}
		sfd->fd_local = export_dmabuf(sfd->dmabuf_bo);
	} else {
		wp_error("Creating unknown file type updates");
		return ERR_FATAL;
	}
	return 0;
}

static void increase_buffer_sizes(struct shadow_fd *sfd,
		struct thread_pool *threads, size_t new_size)
{
	size_t old_size = sfd->buffer_size;
	munmap(sfd->mem_local, old_size);
	sfd->buffer_size = new_size;
	sfd->mem_local = mmap(NULL, sfd->buffer_size, PROT_READ | PROT_WRITE,
			MAP_SHARED, sfd->fd_local, 0);
	if (!sfd->mem_local) {
		wp_error("Mmap failed!");
		return;
	}
	// todo: handle allocation failures

	/* Reallocation here is complicated by the requirement that the mirror
	 * memory be aligned; unfortunately, there is no aligned_realloc */
	size_t al = 1u << threads->diff_alignment_bits;
	sfd->mem_mirror =
			realloc(sfd->mem_mirror, alignz(sfd->buffer_size, al));
	if ((size_t)sfd->mem_mirror % al != 0) {
		char *mem = aligned_alloc(al, alignz(sfd->buffer_size, al));
		memcpy(mem, sfd->mem_mirror, old_size);
		free(sfd->mem_mirror);
		sfd->mem_mirror = mem;
	}
}

static void pipe_close_write(struct shadow_fd *sfd)
{
	if (sfd->pipe.can_read) {
		/* if pipe.fd is both readable and writable, assume
		 * socket
		 */
		shutdown(sfd->pipe.fd, SHUT_WR);
	} else {
		close(sfd->pipe.fd);
		if (sfd->fd_local == sfd->pipe.fd) {
			sfd->fd_local = -1;
		}
		sfd->pipe.fd = -1;
	}
	sfd->pipe.can_write = false;

	/* Also free any accumulated data that was not delivered */
	free(sfd->pipe.send.data);
	memset(&sfd->pipe.send, 0, sizeof(sfd->pipe.send));
}
static void pipe_close_read(struct shadow_fd *sfd)
{
	if (sfd->pipe.can_write) {
		/* if pipe.fd is both readable and writable, assume
		 * socket
		 */
		shutdown(sfd->pipe.fd, SHUT_RD);
	} else {
		close(sfd->pipe.fd);
		if (sfd->fd_local == sfd->pipe.fd) {
			sfd->fd_local = -1;
		}
		sfd->pipe.fd = -1;
	}
	sfd->pipe.can_read = false;
}

int apply_update(struct fd_translation_map *map, struct thread_pool *threads,
		struct render_data *render, enum wmsg_type type, int remote_id,
		const struct bytebuf *msg)
{
	if (type == WMSG_OPEN_FILE || type == WMSG_OPEN_DMABUF ||
			type == WMSG_OPEN_IR_PIPE ||
			type == WMSG_OPEN_IW_PIPE ||
			type == WMSG_OPEN_RW_PIPE ||
			type == WMSG_OPEN_DMAVID_SRC ||
			type == WMSG_OPEN_DMAVID_DST) {
		struct shadow_fd *sfd = get_shadow_for_rid(map, remote_id);
		if (sfd) {
			wp_error("shadow structure for RID=%d was already created",
					remote_id);
			return ERR_FATAL;
		}
		return create_from_update(
				map, threads, render, type, remote_id, msg);
	}

	struct shadow_fd *sfd = get_shadow_for_rid(map, remote_id);
	if (!sfd) {
		wp_error("shadow structure for RID=%d was not available",
				remote_id);
		return ERR_FATAL;
	}
	if (type == WMSG_EXTEND_FILE) {
		if (sfd->type != FDC_FILE) {
			wp_error("Trying to extend RID=%d, type=%s, which is not a file",
					remote_id, fdcat_to_str(sfd->type));
			return ERR_FATAL;
		}
		if (msg->size < sizeof(struct wmsg_open_file)) {
			wp_error("File extend message size to RID=%d is too small (%zu) to contain header",
					remote_id, msg->size);
			return ERR_FATAL;
		}

		const struct wmsg_open_file *header =
				(const struct wmsg_open_file *)msg->data;
		if (header->file_size <= sfd->buffer_size) {
			wp_error("File extend message for RID=%d does not increase size %u %z",
					remote_id, header->file_size,
					sfd->buffer_size);
			return ERR_FATAL;
		}

		if (ftruncate(sfd->fd_local, (off_t)header->file_size) == -1) {
			wp_error("Failed to resize file buffer: %s",
					strerror(errno));
			return 0;
		}
		increase_buffer_sizes(sfd, threads, (size_t)header->file_size);
	} else if (type == WMSG_BUFFER_FILL) {
		if (sfd->type != FDC_FILE && sfd->type != FDC_DMABUF) {
			wp_error("Trying to fill RID=%d, type=%s, which is not a buffer-type",
					remote_id, fdcat_to_str(sfd->type));
			return ERR_FATAL;
		}
		if (msg->size < sizeof(struct wmsg_buffer_fill)) {
			wp_error("Buffer fill message size to RID=%d is too small (%zu) to contain header",
					remote_id, msg->size);
			return ERR_FATAL;
		}
		const struct wmsg_buffer_fill *header =
				(const struct wmsg_buffer_fill *)msg->data;

		size_t uncomp_size = header->end - header->start;
		struct thread_data *local = &threads->threads[0];
		if (buf_ensure_size((int)uncomp_size, 1, &local->tmp_size,
				    &local->tmp_buf) == -1) {
			wp_error("Failed to expand temporary decompression buffer, dropping update");
			return 0;
		}

		const char *act_buffer = NULL;
		size_t act_size = 0;
		uncompress_buffer(threads, &threads->threads[0].comp_ctx,
				msg->size - sizeof(struct wmsg_buffer_fill),
				msg->data + sizeof(struct wmsg_buffer_fill),
				uncomp_size, local->tmp_buf, &act_size,
				&act_buffer);

		// `memsize+8*remote_nthreads` is the worst-case diff
		// expansion
		if (header->end > sfd->buffer_size) {
			wp_error("Transfer end overflow %" PRIu32 " > %zu",
					header->end, sfd->buffer_size);
			return ERR_FATAL;
		}
		if (act_size != header->end - header->start) {
			wp_error("Transfer size mismatch %zu %" PRIu32,
					act_size, header->end - header->start);
			return ERR_FATAL;
		}
		memcpy(sfd->mem_mirror + header->start, act_buffer,
				header->end - header->start);

		void *handle = NULL;
		if (sfd->type == FDC_DMABUF) {
			sfd->mem_local = map_dmabuf(
					sfd->dmabuf_bo, true, &handle);
			if (!sfd->mem_local) {
				return 0;
			}
		}
		memcpy(sfd->mem_local + header->start,
				sfd->mem_mirror + header->start,
				header->end - header->start);

		if (sfd->type == FDC_DMABUF) {
			sfd->mem_local = NULL;
			if (unmap_dmabuf(sfd->dmabuf_bo, handle) == -1) {
				return 0;
			}
		}
	} else if (type == WMSG_BUFFER_DIFF) {
		if (sfd->type != FDC_FILE && sfd->type != FDC_DMABUF) {
			wp_error("Trying to apply diff to RID=%d, type=%s, which is not a buffer-type",
					remote_id, fdcat_to_str(sfd->type));
			return ERR_FATAL;
		}
		if (msg->size < sizeof(struct wmsg_buffer_diff)) {
			wp_error("Buffer diff message size to RID=%d is too small (%zu) to contain header",
					remote_id, msg->size);
			return ERR_FATAL;
		}
		const struct wmsg_buffer_diff *header =
				(const struct wmsg_buffer_diff *)msg->data;

		struct thread_data *local = &threads->threads[0];
		if (buf_ensure_size((int)(header->diff_size +
						    header->ntrailing),
				    1, &local->tmp_size,
				    &local->tmp_buf) == -1) {
			wp_error("Failed to expand temporary decompression buffer, dropping update");
			return 0;
		}

		const char *act_buffer = NULL;
		size_t act_size = 0;
		uncompress_buffer(threads, &threads->threads[0].comp_ctx,
				msg->size - sizeof(struct wmsg_buffer_diff),
				msg->data + sizeof(struct wmsg_buffer_diff),
				header->diff_size + header->ntrailing,
				local->tmp_buf, &act_size, &act_buffer);

		// `memsize+8*remote_nthreads` is the worst-case diff
		// expansion
		if (act_size != header->diff_size + header->ntrailing) {
			wp_error("Transfer size mismatch %zu %u", act_size,
					header->diff_size + header->ntrailing);
			return ERR_FATAL;
		}

		void *handle = NULL;
		if (sfd->type == FDC_DMABUF) {
			sfd->mem_local = map_dmabuf(
					sfd->dmabuf_bo, true, &handle);
			if (!sfd->mem_local) {
				return 0;
			}
		}

		DTRACE_PROBE2(waypipe, apply_diff_enter, sfd->buffer_size,
				header->diff_size);
		apply_diff(sfd->buffer_size, sfd->mem_mirror, sfd->mem_local,
				header->diff_size, header->ntrailing,
				act_buffer);
		DTRACE_PROBE(waypipe, apply_diff_exit);

		if (sfd->type == FDC_DMABUF) {
			sfd->mem_local = NULL;
			if (unmap_dmabuf(sfd->dmabuf_bo, handle) == -1) {
				return 0;
			}
		}
	} else if (type == WMSG_PIPE_TRANSFER) {
		if (sfd->type != FDC_PIPE) {
			wp_error("Trying to write data to RID=%d, type=%s, which is not a pipe",
					remote_id, fdcat_to_str(sfd->type));
			return ERR_FATAL;
		}
		if (!sfd->pipe.can_write || sfd->pipe.pending_w_shutdown) {
			wp_debug("Discarding transfer to pipe RID=%d, because pipe cannot be written to",
					remote_id);
			return 0;
		}

		size_t transf_data_sz = msg->size - sizeof(struct wmsg_basic);

		int netsize = sfd->pipe.send.used + (int)transf_data_sz;
		if (buf_ensure_size(netsize, 1, &sfd->pipe.send.size,
				    (void **)&sfd->pipe.send.data) == -1) {
			wp_error("Failed to expand pipe transfer buffer, dropping data");
			return 0;
		}

		memcpy(sfd->pipe.send.data + sfd->pipe.send.used,
				msg->data + sizeof(struct wmsg_basic),
				transf_data_sz);
		sfd->pipe.send.used = netsize;

		// The pipe itself will be flushed/or closed later by
		// flush_writable_pipes
		sfd->pipe.writable = true;
	} else if (type == WMSG_PIPE_SHUTDOWN_R) {
		if (sfd->type != FDC_PIPE) {
			wp_error("Trying to read shutdown the pipe RID=%d, type=%s, which is not a pipe",
					remote_id, fdcat_to_str(sfd->type));
			return ERR_FATAL;
		}
		sfd->pipe.remote_can_write = false;
		if (!sfd->pipe.can_read) {
			wp_debug("Discarding read shutdown to pipe RID=%d, which cannot read",
					remote_id);
			return 0;
		}
		pipe_close_read(sfd);
	} else if (type == WMSG_PIPE_SHUTDOWN_W) {
		if (sfd->type != FDC_PIPE) {
			wp_error("Trying to write shutdown the pipe RID=%d, type=%s, which is not a pipe",
					remote_id, fdcat_to_str(sfd->type));
			return ERR_FATAL;
		}
		sfd->pipe.remote_can_read = false;
		if (!sfd->pipe.can_write) {
			wp_debug("Discarding write shutdown to pipe RID=%d, which cannot write",
					remote_id);
			return 0;
		}
		if (sfd->pipe.send.used <= 0) {
			pipe_close_write(sfd);
		} else {
			/* Shutdown as soon as the current data has been written
			 */
			sfd->pipe.pending_w_shutdown = true;
		}
	} else if (type == WMSG_SEND_DMAVID_PACKET) {
		if (sfd->type != FDC_DMAVID_IW) {
			wp_error("Trying to send video packet to RID=%d, type=%s, which is not a video output buffer",
					remote_id, fdcat_to_str(sfd->type));
			return ERR_FATAL;
		}
		if (!sfd->dmabuf_bo) {
			wp_error("Applying update to nonexistent dma buffer object rid=%d",
					sfd->remote_id);
			return 0;
		}
		struct bytebuf data = {
				.data = msg->data + sizeof(struct wmsg_basic),
				.size = msg->size - sizeof(struct wmsg_basic)};
		apply_video_packet(sfd, render, &data);
	} else {
		wp_error("Unexpected update type: %s", wmsg_type_to_str(type));
		return ERR_FATAL;
	}
	return 0;
}

bool shadow_decref_protocol(
		struct fd_translation_map *map, struct shadow_fd *sfd)
{
	sfd->refcount.protocol--;
	return destroy_shadow_if_unreferenced(map, sfd);
}

bool shadow_decref_transfer(
		struct fd_translation_map *map, struct shadow_fd *sfd)
{
	sfd->refcount.transfer--;
	if (sfd->refcount.transfer == 0 && sfd->type == FDC_PIPE) {
		/* fd_local has been transferred for the last time, so close
		 * it and make it match pipe.fd, just as on the side where
		 * the original pipe was introduced */
		if (sfd->pipe.fd != sfd->fd_local) {
			close(sfd->fd_local);
			sfd->fd_local = sfd->pipe.fd;
		}
	}
	return destroy_shadow_if_unreferenced(map, sfd);
}
struct shadow_fd *shadow_incref_protocol(struct shadow_fd *sfd)
{
	sfd->has_owner = true;
	sfd->refcount.protocol++;
	return sfd;
}
struct shadow_fd *shadow_incref_transfer(struct shadow_fd *sfd)
{
	sfd->has_owner = true;
	if (sfd->type == FDC_PIPE && sfd->refcount.protocol == 0) {
		wp_error("The other pipe end may have been closed");
	}
	sfd->refcount.protocol++;
	return sfd;
}
void decref_transferred_fds(struct fd_translation_map *map, int nfds, int fds[])
{
	for (int i = 0; i < nfds; i++) {
		struct shadow_fd *sfd = get_shadow_for_local_fd(map, fds[i]);
		shadow_decref_transfer(map, sfd);
	}
}
void decref_transferred_rids(
		struct fd_translation_map *map, int nids, int ids[])
{
	for (int i = 0; i < nids; i++) {
		struct shadow_fd *sfd = get_shadow_for_rid(map, ids[i]);
		shadow_decref_transfer(map, sfd);
	}
}

int count_npipes(const struct fd_translation_map *map)
{
	int np = 0;
	for (struct shadow_fd *cur = map->list; cur; cur = cur->next) {
		if (cur->type == FDC_PIPE) {
			np++;
		}
	}
	return np;
}
int fill_with_pipes(const struct fd_translation_map *map, struct pollfd *pfds,
		bool check_read)
{
	int np = 0;
	for (struct shadow_fd *cur = map->list; cur; cur = cur->next) {
		if (cur->type == FDC_PIPE && cur->pipe.fd != -1) {
			pfds[np].fd = cur->pipe.fd;
			pfds[np].events = 0;
			if (check_read && cur->pipe.readable) {
				pfds[np].events |= POLLIN;
			}
			if (cur->pipe.send.used > 0) {
				pfds[np].events |= POLLOUT;
			}
			np++;
		}
	}
	return np;
}

static struct shadow_fd *get_shadow_for_pipe_fd(
		struct fd_translation_map *map, int pipefd)
{
	for (struct shadow_fd *cur = map->list; cur; cur = cur->next) {
		if (cur->type == FDC_PIPE && cur->pipe.fd == pipefd) {
			return cur;
		}
	}
	return NULL;
}

void mark_pipe_object_statuses(
		struct fd_translation_map *map, int nfds, struct pollfd *pfds)
{
	for (int i = 0; i < nfds; i++) {
		int lfd = pfds[i].fd;
		struct shadow_fd *sfd = get_shadow_for_pipe_fd(map, lfd);
		if (!sfd) {
			wp_error("Failed to find shadow struct for .pipe_fd=%d",
					lfd);
			continue;
		}
		if (pfds[i].revents & POLLIN || pfds[i].revents & POLLHUP) {
			/* In */
			sfd->pipe.readable = true;
		}
		if (pfds[i].revents & POLLOUT) {
			sfd->pipe.writable = true;
		}
	}
}

void flush_writable_pipes(struct fd_translation_map *map)
{
	for (struct shadow_fd *sfd = map->list; sfd; sfd = sfd->next) {
		if (sfd->type != FDC_PIPE || !sfd->pipe.writable ||
				sfd->pipe.send.used <= 0) {
			continue;
		}

		sfd->pipe.writable = false;
		wp_debug("Flushing %zd bytes into RID=%d", sfd->pipe.send.used,
				sfd->remote_id);
		ssize_t changed = write(sfd->pipe.fd, sfd->pipe.send.data,
				(size_t)sfd->pipe.send.used);

		if (changed == -1 &&
				(errno == EAGAIN || errno == EWOULDBLOCK)) {
			wp_debug("Writing to pipe RID=%d would block\n",
					sfd->remote_id);
			continue;
		} else if (changed == -1 &&
				(errno == EPIPE || errno == EBADF)) {
			/* No process has access to the other end of the pipe,
			 * or the file descriptor is otherwise permanently
			 * unwriteable */
			pipe_close_write(sfd);
		} else if (changed == -1) {
			wp_error("Failed to write into pipe with remote_id=%d: %s",
					sfd->remote_id, strerror(errno));
		} else {
			wp_debug("Wrote %zd more bytes into pipe RID=%d",
					changed, sfd->remote_id);
			sfd->pipe.send.used -= (int)changed;
			if (sfd->pipe.send.used > 0) {
				memmove(sfd->pipe.send.data,
						sfd->pipe.send.data + changed,
						(size_t)sfd->pipe.send.used);
			}
			if (sfd->pipe.send.used <= 0 &&
					sfd->pipe.pending_w_shutdown) {
				/* A shutdown request was made, but can only be
				 * applied now that the write buffer has been
				 * cleared */
				pipe_close_write(sfd);
				sfd->pipe.pending_w_shutdown = false;
			}
		}
	}
	/* Destroy any new unreferenced objects */
	for (struct shadow_fd *cur = map->list, *nxt = NULL; cur; cur = nxt) {
		nxt = cur->next;
		destroy_shadow_if_unreferenced(map, cur);
	}
}
void read_readable_pipes(struct fd_translation_map *map)
{
	for (struct shadow_fd *sfd = map->list; sfd; sfd = sfd->next) {
		if (sfd->type != FDC_PIPE || !sfd->pipe.readable) {
			continue;
		}

		if (sfd->pipe.recv.size == 0) {
			sfd->pipe.recv.size = 32768;
			sfd->pipe.recv.data =
					malloc((size_t)sfd->pipe.recv.size);
		}
		if (sfd->pipe.recv.size > sfd->pipe.recv.used) {
			sfd->pipe.readable = false;
			ssize_t changed = read(sfd->pipe.fd,
					sfd->pipe.recv.data +
							sfd->pipe.recv.used,
					(size_t)(sfd->pipe.recv.size -
							sfd->pipe.recv.used));
			if (changed == 0) {
				/* No process has access to the other end of the
				 * pipe */
				pipe_close_read(sfd);
			} else if (changed == -1 &&
					(errno == EAGAIN ||
							errno == EWOULDBLOCK)) {
				wp_debug("Reading from pipe RID=%d would block\n",
						sfd->remote_id);
				continue;
			} else if (changed == -1) {
				wp_error("Failed to read from pipe with remote_id=%d: %s",
						sfd->remote_id,
						strerror(errno));
			} else {
				wp_debug("Read %zd more bytes from pipe RID=%d",
						changed, sfd->remote_id);
				sfd->pipe.recv.used += (int)changed;
			}
		}
	}

	/* Destroy any new unreferenced objects */
	for (struct shadow_fd *cur = map->list, *nxt = NULL; cur; cur = nxt) {
		nxt = cur->next;
		destroy_shadow_if_unreferenced(map, cur);
	}
}

void extend_shm_shadow(struct fd_translation_map *map,
		struct thread_pool *threads, struct shadow_fd *sfd,
		size_t new_size)
{
	if (sfd->buffer_size >= new_size) {
		return;
	}

	// Verify that the file size actually increased
	struct stat st;
	int fs = fstat(sfd->fd_local, &st);
	if (fs == -1) {
		wp_error("Checking file size failed: %s", strerror(errno));
		return;
	}
	if ((size_t)st.st_size < new_size) {
		wp_error("Trying to resize file larger (%d) than the actual file size (%d), ignoring",
				(int)new_size, (int)st.st_size);
		return;
	}

	increase_buffer_sizes(sfd, threads, new_size);
	(void)map;

	// leave `sfd->remote_bufsize` unchanged, and mark dirty
	sfd->is_dirty = true;
}

void run_task(struct task_data *task, struct thread_data *local)
{
	if (task->type == TASK_COMPRESS_BLOCK) {
		worker_run_compress_block(task, local);
	} else if (task->type == TASK_COMPRESS_DIFF) {
		worker_run_compress_diff(task, local);
	} else {
		wp_error("Unidentified task type");
	}
}

int start_parallel_work(struct thread_pool *pool,
		struct thread_msg_recv_buf *recv_queue)
{
	pthread_mutex_lock(&pool->work_mutex);
	if (recv_queue->zone_start != recv_queue->zone_end) {
		wp_error("Some async messages not yet sent");
	}
	recv_queue->zone_start = 0;
	recv_queue->zone_end = 0;
	int num_mt_tasks = pool->stack_count;
	if (buf_ensure_size(num_mt_tasks, sizeof(struct iovec),
			    &recv_queue->size,
			    (void **)&recv_queue->data) == -1) {
		wp_error("Failed to provide enough space for receive queue, skipping all work tasks");
		num_mt_tasks = 0;
	}
	pool->do_work = num_mt_tasks > 0;

	/* Start the work tasks here */
	if (num_mt_tasks > 0) {
		pthread_cond_broadcast(&pool->work_cond);
	}
	pthread_mutex_unlock(&pool->work_mutex);

	return num_mt_tasks;
}

bool request_work_task(
		struct thread_pool *pool, struct task_data *task, bool *is_done)
{
	pthread_mutex_lock(&pool->work_mutex);
	*is_done = pool->stack_count == 0 && pool->tasks_in_progress == 0;
	bool has_task = false;
	if (pool->stack_count > 0 && pool->do_work) {
		int i = pool->stack_count - 1;
		if (pool->stack[i].type != TASK_STOP) {
			*task = pool->stack[i];
			has_task = true;
			pool->stack_count--;
			pool->tasks_in_progress++;
			if (pool->stack_count <= 0) {
				pool->do_work = false;
			}
		}
	}
	pthread_mutex_unlock(&pool->work_mutex);
	return has_task;
}

static void *worker_thread_main(void *arg)
{
	struct thread_data *data = arg;
	struct thread_pool *pool = data->pool;

	setup_thread_local(data, pool->compression, pool->compression_level);

	/* The loop is globally locked by default, and only unlocked in
	 * pthread_cond_wait. Yes, there are fancier and faster schemes.
	 */
	pthread_mutex_lock(&pool->work_mutex);
	while (1) {
		while (!pool->do_work) {
			pthread_cond_wait(&pool->work_cond, &pool->work_mutex);
		}
		if (pool->stack_count <= 0) {
			pool->do_work = false;
			continue;
		}
		/* Copy task, since the queue may be resized */
		int i = pool->stack_count - 1;
		struct task_data task = pool->stack[i];
		if (task.type == TASK_STOP) {
			break;
		}
		pool->tasks_in_progress++;
		pool->stack_count--;
		if (pool->stack_count <= 0) {
			pool->do_work = false;
		}
		pthread_mutex_unlock(&pool->work_mutex);
		run_task(&task, data);
		pthread_mutex_lock(&pool->work_mutex);

		uint8_t triv = 0;
		pool->tasks_in_progress--;
		if (write(pool->selfpipe_w, &triv, 1) == -1) {
			wp_error("Failed to write to self-pipe");
		}
	}
	pthread_mutex_unlock(&pool->work_mutex);

	cleanup_thread_local(data);
	return NULL;
}
