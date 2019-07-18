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

#if !defined(__DragonFly__) && !defined(__FreeBSD__) && !defined(__NetBSD__)
/* _SC_NPROCESSORS_ONLN isn't part of any X/Open version */
#define _XOPEN_SOURCE 700
#endif

#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef HAS_LZ4
#include <lz4frame.h>
#endif
#ifdef HAS_ZSTD
#include <zstd.h>
#endif

bool fdcat_ispipe(fdcat_t t)
{
	return t == FDC_PIPE_IR || t == FDC_PIPE_RW || t == FDC_PIPE_IW;
}

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
	/* video must be cleaned up before any buffers that it may rely on */
	destroy_video_data(sfd);

	/* free all accumulated damage records */
	reset_damage(&sfd->damage);
	free(sfd->damage_task_interval_store);

	if (sfd->type == FDC_FILE) {
		munmap(sfd->mem_local, sfd->buffer_size);
		free(sfd->mem_mirror);
		if (sfd->file_shm_buf_name[0]) {
			shm_unlink(sfd->file_shm_buf_name);
		}
	} else if (sfd->type == FDC_DMABUF || sfd->type == FDC_DMAVID_IR ||
			sfd->type == FDC_DMAVID_IW) {
		destroy_dmabuf(sfd->dmabuf_bo);
		free(sfd->mem_mirror);
	} else if (fdcat_ispipe(sfd->type)) {
		if (sfd->pipe_fd != sfd->fd_local && sfd->pipe_fd != -1 &&
				sfd->pipe_fd != -2) {
			close(sfd->pipe_fd);
		}
		free(sfd->pipe_recv.data);
		free(sfd->pipe_send.data);
	}
	if (sfd->fd_local != -2 && sfd->fd_local != -1) {
		if (close(sfd->fd_local) == -1) {
			wp_error("Incorrect close(%d): %s", sfd->fd_local,
					strerror(errno));
		}
	}
	free(sfd);
	(void)map;
}
static void cleanup_comp_ctx(struct comp_ctx *ctx)
{
#ifdef HAS_ZSTD
	ZSTD_freeCCtx(ctx->zstd_ccontext);
	ZSTD_freeDCtx(ctx->zstd_dcontext);
#endif
#ifdef HAS_LZ4
	LZ4F_freeDecompressionContext(ctx->lz4f_dcontext);
#endif
	(void)ctx;
}

static void setup_comp_ctx(struct comp_ctx *ctx, enum compression_mode mode)
{
	ctx->zstd_ccontext = NULL;
	ctx->zstd_dcontext = NULL;
	ctx->lz4f_dcontext = NULL;
#ifdef HAS_LZ4
	if (mode == COMP_LZ4) {
		LZ4F_errorCode_t err = LZ4F_createDecompressionContext(
				&ctx->lz4f_dcontext, LZ4F_VERSION);
		if (LZ4F_isError(err)) {
			wp_error("Failed to created LZ4F decompression context: %s",
					LZ4F_getErrorName(err));
		}
	}
#endif
#ifdef HAS_ZSTD
	if (mode == COMP_ZSTD) {
		ctx->zstd_ccontext = ZSTD_createCCtx();
		ctx->zstd_dcontext = ZSTD_createDCtx();
		ZSTD_CCtx_setParameter(
				ctx->zstd_ccontext, ZSTD_c_compressionLevel, 5);
	}
#endif
	(void)mode;
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
static bool destroy_shadow_if_unreferenced(
		struct fd_translation_map *map, struct shadow_fd *sfd)
{
	if (sfd->refcount_protocol == 0 && sfd->refcount_transfer == 0 &&
			sfd->refcount_compute == false && sfd->has_owner) {
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
	} else if (sfd->refcount_protocol < 0 || sfd->refcount_transfer < 0) {
		wp_error("Negative refcount for rid=%d: %d protocol references, %d transfer references",
				sfd->remote_id, sfd->refcount_protocol,
				sfd->refcount_transfer);
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
	buf_ensure_size(pool->queue_end + pool->nthreads - 1,
			sizeof(struct task_data), &pool->queue_size,
			(void **)&pool->queue);
	/* Discard all queue elements; this will need adjustment if tasks ever
	 * own their own memory */
	pool->queue_start = 0;
	pool->queue_end = 0;
	pool->queue_in_progress = 0;
	for (int i = 1; i < pool->nthreads; i++) {
		struct task_data task;
		memset(&task, 0, sizeof(task));
		task.type = TASK_STOP;
		pool->queue[pool->queue_end++] = task;
	}
	pthread_mutex_unlock(&pool->work_mutex);
	pthread_cond_broadcast(&pool->work_cond);

	for (int i = 1; i < pool->nthreads; i++) {
		pthread_join(pool->threads[i].thread, NULL);
	}
}

void setup_thread_pool(struct thread_pool *pool,
		enum compression_mode compression, int n_threads)
{
	pool->compression = compression;
	if (n_threads <= 0) {
		// platform dependent
		long nt = sysconf(_SC_NPROCESSORS_ONLN);
		pool->nthreads = max((int)nt / 2, 1);
	} else {
		pool->nthreads = n_threads;
	}
	pool->queue_size = 0;
	pool->queue_end = 0;
	pool->queue_start = 0;
	pool->queue_in_progress = 0;
	pool->queue = NULL;

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

	setup_comp_ctx(&pool->threads[0].comp_ctx, compression);

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
	cleanup_comp_ctx(&pool->threads[0].comp_ctx);

	pthread_mutex_destroy(&pool->work_mutex);
	pthread_cond_destroy(&pool->work_cond);
	free(pool->threads);
	free(pool->queue);

	close(pool->selfpipe_r);
	close(pool->selfpipe_w);
}

const char *fdcat_to_str(fdcat_t cat)
{
	switch (cat) {
	case FDC_UNKNOWN:
		return "FDC_UNKNOWN";
	case FDC_FILE:
		return "FDC_FILE";
	case FDC_PIPE_IR:
		return "FDC_PIPE_IR";
	case FDC_PIPE_IW:
		return "FDC_PIPE_IW";
	case FDC_PIPE_RW:
		return "FDC_PIPE_RW";
	case FDC_DMABUF:
		return "FDC_DMABUF";
	case FDC_DMAVID_IR:
		return "FDC_DMAVID_IR";
	case FDC_DMAVID_IW:
		return "FDC_DMAVID_IW";
	}
	return "<invalid>";
}

fdcat_t get_fd_type(int fd, size_t *size)
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
			wp_error("The fd %d, size %ld, mode %x is a character device. Proceeding under the assumption that it is pipe-like.",
					fd, fsdata.st_size, fsdata.st_mode);
		}
		if (S_ISSOCK(fsdata.st_mode)) {
			wp_error("The fd %d, size %ld, mode %x is a socket. Proceeding under the assumption that it is pipe-like.",
					fd, fsdata.st_size, fsdata.st_mode);
		}
		int flags = fcntl(fd, F_GETFL, 0);
		if (flags == -1) {
			wp_error("fctnl F_GETFL failed!");
		}
		if ((flags & O_ACCMODE) == O_RDONLY) {
			return FDC_PIPE_IR;
		} else if ((flags & O_ACCMODE) == O_WRONLY) {
			return FDC_PIPE_IW;
		} else {
			return FDC_PIPE_RW;
		}
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
		return (size_t)LZ4F_compressFrameBound((int)max_input, NULL);
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
		size_t ws = LZ4F_compressFrame(mbuf, msize, ibuf, isize, NULL);
		if (LZ4F_isError(ws)) {
			wp_error("Lz4 compression failed for %d bytes in %d of space: %s",
					(int)isize, (int)msize,
					LZ4F_getErrorName(ws));
		}
		dst->size = (size_t)ws;
		dst->data = (char *)mbuf;
		break;
	}
#endif
#ifdef HAS_ZSTD
	case COMP_ZSTD: {
		size_t ws = ZSTD_compress2(
				ctx->zstd_ccontext, mbuf, msize, ibuf, isize);
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
 * If the compression mode requires it. Returns a pointer to a newly allocated
 * buffer, else NULL. */
static void *uncompress_buffer(struct thread_pool *pool, struct comp_ctx *ctx,
		size_t isize, const char *ibuf, size_t msize, size_t *wsize,
		const char **wbuf)
{
	(void)ctx;
	// Ensure inputs always nontrivial
	if (isize == 0) {
		*wsize = 0;
		*wbuf = ibuf;
		return NULL;
	}

	DTRACE_PROBE1(waypipe, uncompress_buffer_enter, isize);
	void *ret = NULL;
	switch (pool->compression) {
	case COMP_NONE:
		(void)msize;
		*wsize = isize;
		*wbuf = ibuf;
		break;
#ifdef HAS_LZ4
	case COMP_LZ4: {
		char *mbuf = malloc(msize);
		size_t total = 0;
		size_t read = 0;
		while (read < isize) {
			size_t dst_remaining = msize - total;
			size_t src_remaining = isize - read;
			size_t hint = LZ4F_decompress(ctx->lz4f_dcontext,
					&mbuf[total], &dst_remaining,
					&ibuf[read], &src_remaining, NULL);
			read += src_remaining;
			total += dst_remaining;
			if (LZ4F_isError(hint)) {
				wp_error("Lz4 decomp. failed with %d bytes and %d space remaining: %s",
						isize - read, msize - total,
						LZ4F_getErrorName(hint));
				break;
			}
		}
		*wsize = total;
		*wbuf = mbuf;
		ret = mbuf;
		break;
	}
#endif
#ifdef HAS_ZSTD
	case COMP_ZSTD: {
		char *mbuf = malloc(msize);
		size_t ws = ZSTD_decompressDCtx(
				ctx->zstd_dcontext, mbuf, msize, ibuf, isize);
		if (ZSTD_isError(ws) || (size_t)ws != msize) {
			wp_error("Zstd decompression failed for %d bytes to %d of space: %s",
					(int)isize, (int)msize,
					ZSTD_getErrorName(ws));
			ws = 0;
		}
		*wsize = (size_t)ws;
		*wbuf = mbuf;
		ret = mbuf;
		break;
	}
#endif
	}
	DTRACE_PROBE1(waypipe, uncompress_buffer_exit, *wsize);
	return ret;
}

struct shadow_fd *translate_fd(struct fd_translation_map *map,
		struct render_data *render, int fd, fdcat_t type,
		size_t file_sz, const struct dmabuf_slice_data *info)
{
	struct shadow_fd *sfd = get_shadow_for_local_fd(map, fd);
	if (sfd) {
		return sfd;
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
	sfd->refcount_transfer = 1;
	sfd->refcount_protocol = 0;

	wp_debug("Creating new shadow buffer for local fd %d", fd);
	if (sfd->type == FDC_FILE) {
		if (file_sz >= UINT32_MAX / 2) {
			wp_error("Failed to create shadow structure, file size %ld too large to transfer",
					(uint64_t)file_sz);
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
	} else if (fdcat_ispipe(sfd->type)) {
		// Make this end of the pipe nonblocking, so that we can
		// include it in our main loop.
		if (set_nonblocking(sfd->fd_local) == -1) {
			wp_error("Failed to make fd nonblocking");
		}
		sfd->pipe_fd = sfd->fd_local;

		// Allocate a reasonably small read buffer
		sfd->pipe_recv.size = 16384;
		sfd->pipe_recv.data = calloc((size_t)sfd->pipe_recv.size, 1);

		sfd->pipe_onlyhere = true;
	} else if (sfd->type == FDC_DMAVID_IR) {
		if (!info) {
			wp_error("No info available");
		}
		memcpy(&sfd->dmabuf_info, info,
				sizeof(struct dmabuf_slice_data));
		init_render_data(render);
		sfd->dmabuf_bo = import_dmabuf(
				render, sfd->fd_local, &sfd->buffer_size, info);
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
		setup_video_encode(sfd, render);
	} else if (sfd->type == FDC_DMAVID_IW) {
		if (!info) {
			wp_error("No info available");
		}
		memcpy(&sfd->dmabuf_info, info,
				sizeof(struct dmabuf_slice_data));
		// TODO: multifd-dmabuf video surface
		init_render_data(render);
		sfd->dmabuf_bo = import_dmabuf(
				render, sfd->fd_local, &sfd->buffer_size, info);
		if (!sfd->dmabuf_bo) {
			return sfd;
		}
		setup_video_decode(sfd, render);
		/* notify remote side with sentinel frame */
		sfd->video_frameno = -1;
	} else if (sfd->type == FDC_DMABUF) {
		sfd->buffer_size = 0;

		init_render_data(render);
		sfd->dmabuf_bo = import_dmabuf(
				render, sfd->fd_local, &sfd->buffer_size, info);
		if (!sfd->dmabuf_bo) {
			return sfd;
		}
		if (info) {
			memcpy(&sfd->dmabuf_info, info,
					sizeof(struct dmabuf_slice_data));
		} else {
			// already zero initialized (no information).
		}
		// to be created on first transfer
		sfd->mem_mirror = NULL;
	}
	return sfd;
}

/* large window sizes (64) can be faster if everything has changed,
 * at the cost of overcopying sometimes. 0 is also a reasonable
 * choice. Differences are amplified at low optimization levels. */
#define DIFF_WINDOW_SIZE 32

static uint64_t run_interval_diff(uint64_t blockrange_min,
		uint64_t blockrange_max,
		const uint64_t *__restrict__ changed_blocks,
		uint64_t *__restrict__ base_blocks,
		uint64_t *__restrict__ diff_blocks, uint64_t cursor)
{
	/* we paper over gaps of a given window size, to avoid fine
	 * grained context switches */
	uint64_t i = blockrange_min;
	uint64_t changed_val = i < blockrange_max ? changed_blocks[i] : 0;
	uint64_t base_val = i < blockrange_max ? base_blocks[i] : 0;
	i++;
	// Alternating scanners, ending with a mispredict each.
	bool clear_exit = false;
	while (i < blockrange_max) {
		while (changed_val == base_val && i < blockrange_max) {
			changed_val = changed_blocks[i];
			base_val = base_blocks[i];
			i++;
		}
		if (i == blockrange_max) {
			/* it's possible that the last value actually;
			 * see exit block */
			clear_exit = true;
			break;
		}
		uint64_t last_header = cursor++;
		diff_blocks[last_header] = (i - 1) << 32;
		diff_blocks[cursor++] = changed_val;
		base_blocks[i - 1] = changed_val;
		// changed_val != base_val, difference occurs at early
		// index
		uint64_t nskip = 0;
		// we could only sentinel this assuming a tiny window
		// size
		while (i < blockrange_max && nskip <= DIFF_WINDOW_SIZE) {
			base_val = base_blocks[i];
			changed_val = changed_blocks[i];
			base_blocks[i] = changed_val;
			i++;
			diff_blocks[cursor++] = changed_val;
			nskip++;
			nskip *= (base_val == changed_val);
		}
		cursor -= nskip;
		diff_blocks[last_header] |= i - nskip;
		/* our sentinel, at worst, causes overcopy by one. this
		 * is fine
		 */
	}

	/* If only the last block changed */
	if ((clear_exit || blockrange_min + 1 == blockrange_max) &&
			changed_val != base_val) {
		diff_blocks[cursor++] =
				(blockrange_max - 1) << 32 | blockrange_max;
		diff_blocks[cursor++] = changed_val;
		base_blocks[blockrange_max - 1] = changed_val;
	}
	return cursor;
}

/** Construct a very simple binary diff format, designed to be fast for
 * small changes in big files, and entire-file changes in essentially
 * random files. Tries not to read beyond the end of the input buffers,
 * because they are often mmap'd. Simultaneously updates the `base`
 * buffer to match the `changed` buffer.
 *
 * `slice_no` and `nslices` are used to restrict the diff to a subset of
 * the damaged area.
 *
 * Requires that `diff` point to a memory buffer of size `size + 8`, or
 * if slices are used, `align(ceildiv(size, nslices), 8) + 16`.
 */
void construct_diff(size_t size,
		const struct interval *__restrict__ damaged_intervals,
		int n_intervals, char *__restrict__ base,
		const char *__restrict__ changed, size_t *diffsize,
		char *__restrict__ diff)
{
	DTRACE_PROBE1(waypipe, construct_diff_enter, n_intervals);

	uint64_t nblocks = (uint64_t)floordiv((int)size, 8);
	uint64_t *__restrict__ base_blocks = (uint64_t *)base;
	const uint64_t *__restrict__ changed_blocks = (const uint64_t *)changed;

	uint64_t *__restrict__ diff_blocks = (uint64_t *)diff;
	uint64_t ntrailing = size - 8 * nblocks;
	uint64_t cursor = 0;

	bool check_tail = false;
	for (int i = 0; i < n_intervals; i++) {
		struct interval e = damaged_intervals[i];
		uint64_t bstart = (uint64_t)floordiv(e.start, 8);
		uint64_t bend = (uint64_t)ceildiv(e.end, 8);
		if (bend > nblocks) {
			check_tail = true;
		}
		bend = minu(bend, nblocks);
		if (bstart >= bend) {
			continue;
		}
		cursor = run_interval_diff(bstart, bend, changed_blocks,
				base_blocks, diff_blocks, cursor);
	}

	bool tail_change = false;
	if (check_tail && ntrailing > 0) {
		for (uint64_t i = 0; i < ntrailing; i++) {
			tail_change |= base[nblocks * 8 + i] !=
				       changed[nblocks * 8 + i];
		}
	}
	if (tail_change) {
		for (uint64_t i = 0; i < ntrailing; i++) {
			diff[cursor * 8 + i] = changed[nblocks * 8 + i];
			base[nblocks * 8 + i] = changed[nblocks * 8 + i];
		}
		*diffsize = cursor * 8 + ntrailing;
	} else {
		*diffsize = cursor * 8;
	}
	DTRACE_PROBE1(waypipe, construct_diff_exit, *diffsize);
}
void apply_diff(size_t size, char *__restrict__ target1,
		char *__restrict__ target2, size_t diffsize,
		const char *__restrict__ diff)
{
	uint64_t nblocks = size / 8;
	uint64_t ndiffblocks = diffsize / 8;
	uint64_t *__restrict__ t1_blocks = (uint64_t *)target1;
	uint64_t *__restrict__ t2_blocks = (uint64_t *)target2;
	uint64_t *__restrict__ diff_blocks = (uint64_t *)diff;
	uint64_t ndifftrailing = diffsize - 8 * ndiffblocks;
	if (diffsize % 8 != 0 && ndifftrailing != (size - 8 * nblocks)) {
		wp_error("Trailing bytes mismatch for diff.");
		return;
	}
	DTRACE_PROBE2(waypipe, apply_diff_enter, size, diffsize);
	for (uint64_t i = 0; i < ndiffblocks;) {
		uint64_t block = diff_blocks[i];
		uint64_t nfrom = block >> 32;
		uint64_t nto = (block << 32) >> 32;
		if (nto > nblocks || nfrom >= nto ||
				i + (nto - nfrom) >= ndiffblocks) {
			wp_error("Invalid copy range [%ld,%ld) > %ld=nblocks or [%ld,%ld) > %ld=ndiffblocks",
					nfrom, nto, nblocks, i + 1,
					i + 1 + (nto - nfrom), ndiffblocks);
			return;
		}
		memcpy(t1_blocks + nfrom, diff_blocks + i + 1,
				8 * (nto - nfrom));
		memcpy(t2_blocks + nfrom, diff_blocks + i + 1,
				8 * (nto - nfrom));
		i += nto - nfrom + 1;
	}
	DTRACE_PROBE(waypipe, apply_diff_exit);
	if (ndifftrailing > 0) {
		for (uint64_t i = 0; i < ndifftrailing; i++) {
			target1[nblocks * 8 + i] = diff[ndiffblocks * 8 + i];
			target2[nblocks * 8 + i] = diff[ndiffblocks * 8 + i];
		}
	}
}

/* Construct and optionally compress a diff between sfd->mem_mirror and
 * the actual memmap'd data */
static void worker_run_compress_diff(
		struct task_data *task, struct thread_data *local)
{
	struct shadow_fd *sfd = task->sfd;
	struct thread_pool *pool = local->pool;

	/* Depending on the buffer format, doing a memcpy before running the
	 * diff construction routine can be significantly faster. */
	// TODO: Either autodetect when this happens, or write a
	// faster/vectorizable diff routine

	size_t damage_space = 0;
	for (int i = 0; i < task->damage_len; i++) {
		damage_space += (size_t)(task->damage_intervals[i].end -
						task->damage_intervals[i]
								.start) +
				8;
	}
	DTRACE_PROBE1(waypipe, worker_compdiff_enter, damage_space);

	char *diff_buffer = NULL;
	char *diff_target = NULL;
	if (pool->compression == COMP_NONE) {
		diff_buffer = malloc(
				damage_space + sizeof(struct wmsg_buffer_diff));
		diff_target = diff_buffer + sizeof(struct wmsg_buffer_diff);
	} else {
		diff_buffer = malloc(damage_space);
		diff_target = diff_buffer;
	}

	size_t diffsize;
	construct_diff(sfd->buffer_size, task->damage_intervals,
			task->damage_len, sfd->mem_mirror, sfd->mem_local,
			&diffsize, diff_target);
	if (diffsize == 0) {
		free(diff_buffer);
		goto end;
	}

	uint8_t *msg;
	size_t sz;
	if (pool->compression == COMP_NONE) {
		sz = diffsize + sizeof(struct wmsg_buffer_diff);
		msg = (uint8_t *)diff_buffer;
	} else {
		struct bytebuf dst;
		size_t comp_size = compress_bufsize(pool, diffsize);
		char *comp_buf = malloc(alignu(comp_size, 16) +
					sizeof(struct wmsg_buffer_diff));
		compress_buffer(pool, &local->comp_ctx, diffsize, diff_target,
				comp_size,
				comp_buf + sizeof(struct wmsg_buffer_diff),
				&dst);
		free(diff_buffer);
		sz = dst.size + sizeof(struct wmsg_buffer_diff);
		msg = (uint8_t *)comp_buf;
	}
	msg = realloc(msg, alignu(sz, 16));
	memset(msg + sz, 0, alignu(sz, 16) - sz);
	struct wmsg_buffer_diff header;
	header.size_and_type = transfer_header(sz, WMSG_BUFFER_DIFF);
	header.remote_id = sfd->remote_id;
	header.diff_size = (uint32_t)diffsize;
	header.pad4 = 0;
	memcpy(msg, &header, sizeof(struct wmsg_buffer_diff));

	struct transfer_data *transfers = task->transfers;

	pthread_mutex_lock(&transfers->lock);
	transfer_add(transfers, alignu(sz, 16), msg, transfers->last_msgno++);
	pthread_mutex_unlock(&transfers->lock);

end:
	DTRACE_PROBE1(waypipe, worker_compdiff_exit, diffsize);
}

/* Compress data for sfd->mem_mirror */
static void worker_run_compress_block(
		struct task_data *task, struct thread_data *local)
{

	struct shadow_fd *sfd = task->sfd;
	struct thread_pool *pool = local->pool;

	/* Allocate a disjoint target interval to each worker */
	size_t source_start = (size_t)task->zone_start;
	size_t source_end = (size_t)task->zone_end;
	DTRACE_PROBE1(waypipe, worker_comp_enter, source_end - source_start);

	size_t sz = sizeof(struct wmsg_buffer_fill);
	if (source_end == source_start) {
		/* Nothing to do here */

		wp_error("Skipping task");
		goto end;
	}

	uint8_t *msg;
	if (pool->compression == COMP_NONE) {
		sz = sizeof(struct wmsg_buffer_fill) +
		     (source_end - source_start);

		msg = malloc(alignu(sz, 16));
		memcpy(msg + sizeof(struct wmsg_buffer_fill),
				sfd->mem_mirror + source_start,
				source_end - source_start);
	} else {
		size_t comp_size = compress_bufsize(
				pool, source_end - source_start);
		struct bytebuf dst;
		msg = malloc(alignu(comp_size, 16) +
				sizeof(struct wmsg_buffer_fill));
		compress_buffer(pool, &local->comp_ctx,
				source_end - source_start,
				&sfd->mem_mirror[source_start], comp_size,
				(char *)msg + sizeof(struct wmsg_buffer_fill),
				&dst);
		msg = realloc(msg,
				alignu(dst.size, 16) +
						sizeof(struct wmsg_buffer_fill));
		sz = dst.size + sizeof(struct wmsg_buffer_fill);
	}
	memset(msg + sz, 0, alignu(sz, 16) - sz);
	struct wmsg_buffer_fill header;
	header.size_and_type = transfer_header(sz, WMSG_BUFFER_FILL);
	header.remote_id = sfd->remote_id;
	header.start = (uint32_t)source_start;
	header.end = (uint32_t)source_end;
	memcpy(msg, &header, sizeof(struct wmsg_buffer_fill));

	struct transfer_data *transfers = task->transfers;

	pthread_mutex_lock(&transfers->lock);
	transfer_add(transfers, alignu(sz, 16), msg, transfers->last_msgno++);
	pthread_mutex_unlock(&transfers->lock);

end:
	DTRACE_PROBE1(waypipe, worker_comp_exit,
			sz - sizeof(struct wmsg_buffer_fill));
}

/* Optionally compress the data in mem_mirror, and set up the initial
 * transfer blocks */
static void queue_fill_transfers(struct fd_translation_map *map,
		struct thread_pool *threads, struct shadow_fd *sfd,
		struct transfer_data *transfers)
{
	// new transfer, we send file contents verbatim
	const int chunksize = 262144;

	int region_start = (int)sfd->remote_bufsize;
	int region_end = (int)sfd->buffer_size;
	if (region_start == region_end) {
		return;
	}

	/* Keep sfd alive at least until write to channel is done */
	sfd->refcount_compute = true;

	int nshards = ceildiv((region_end - region_start), chunksize);

	pthread_mutex_lock(&threads->work_mutex);
	buf_ensure_size(threads->queue_end + nshards, sizeof(struct task_data),
			&threads->queue_size, (void **)&threads->queue);

	for (int i = 0; i < nshards; i++) {
		struct task_data task;
		task.type = TASK_COMPRESS_BLOCK;
		task.sfd = sfd;
		task.map = map;
		task.transfers = transfers;

		int range = (region_end - region_start);
		task.zone_start = region_start + (range * i) / nshards;
		task.zone_end = region_start + (range * (i + 1)) / nshards;

		task.damage_len = 0;
		task.damage_intervals = NULL;
		threads->queue[threads->queue_end++] = task;
	}
	pthread_mutex_unlock(&threads->work_mutex);
	pthread_cond_broadcast(&threads->work_cond);
}

static void queue_diff_transfers(struct fd_translation_map *map,
		struct thread_pool *threads, struct shadow_fd *sfd,
		struct transfer_data *transfers)
{
	const int chunksize = 262144;
	if (!sfd->damage.damage) {
		return;
	}

	/* Keep sfd alive at least until write to channel is done */
	sfd->refcount_compute = true;

	if (sfd->damage.damage == DAMAGE_EVERYTHING) {
		reset_damage(&sfd->damage);
		struct ext_interval all = {.start = 0,
				.width = (int)sfd->buffer_size,
				.rep = 1,
				.stride = 0};
		merge_damage_records(&sfd->damage, 1, &all);
	}

	int net_damage = 0;
	for (int i = 0; i < sfd->damage.ndamage_intvs; i++) {
		/* Extend all damage to the nearest 8-block */
		struct interval e = sfd->damage.damage[i];
		e.start = floordiv(e.start, 8) * 8;
		e.end = ceildiv(e.end, 8) * 8;
		sfd->damage.damage[i] = e;
		net_damage += e.end - e.start;
	}

	int nshards = ceildiv(net_damage, chunksize);

	/* Instead of allocating individual buffers for each task, create a
	 * global damage tracking buffer into which tasks index. It will be
	 * deleted in `finish_update`. */
	struct interval *intvs = malloc(
			sizeof(struct interval) *
			(size_t)(sfd->damage.ndamage_intvs + nshards));
	int *offsets = calloc((size_t)nshards + 1, sizeof(int));
	sfd->damage_task_interval_store = intvs;
	int tot_blocks = net_damage / 8;
	int ir = 0, iw = 0, acc_prev_blocks = 0;
	for (int shard = 0; shard < nshards; shard++) {
		int s_lower = (shard * tot_blocks) / nshards;
		int s_upper = ((shard + 1) * tot_blocks) / nshards;

		while (acc_prev_blocks < s_upper) {
			struct interval e = sfd->damage.damage[ir];
			const int w = (e.end - e.start) / 8;
			int e_lower = acc_prev_blocks;
			int e_upper = acc_prev_blocks + w;

			int a_low = max(e_lower, s_lower) - acc_prev_blocks;
			int a_high = min(e_upper, s_upper) - acc_prev_blocks;

			intvs[iw++] = (struct interval){
					.start = e.start + 8 * a_low,
					.end = e.start + 8 * a_high,
			};

			if (acc_prev_blocks + w > s_upper) {
				break;
			} else {
				acc_prev_blocks += w;
				ir++;
			}
		}

		offsets[shard + 1] = iw;
	}

	pthread_mutex_lock(&threads->work_mutex);
	buf_ensure_size(threads->queue_end + nshards, sizeof(struct task_data),
			&threads->queue_size, (void **)&threads->queue);

	for (int i = 0; i < nshards; i++) {
		struct task_data task;
		task.type = TASK_COMPRESS_DIFF;
		task.sfd = sfd;
		task.map = map;
		task.transfers = transfers;

		task.damage_len = offsets[i + 1] - offsets[i];
		task.damage_intervals =
				&sfd->damage_task_interval_store[offsets[i]];

		task.zone_start = 0;
		task.zone_end = 0;
		threads->queue[threads->queue_end++] = task;
	}
	pthread_mutex_unlock(&threads->work_mutex);
	free(offsets);

	pthread_cond_broadcast(&threads->work_cond);
}

static void add_dmabuf_create_request(struct transfer_data *transfers,
		struct shadow_fd *sfd, enum wmsg_type variant)
{
	size_t actual_len = sizeof(struct wmsg_open_dmabuf) +
			    sizeof(struct dmabuf_slice_data);
	size_t padded_len = alignu(actual_len, 16);

	uint8_t *data = calloc(1, padded_len);
	struct wmsg_open_dmabuf *header = (struct wmsg_open_dmabuf *)data;
	header->file_size = sfd->buffer_size;
	header->remote_id = sfd->remote_id;
	header->size_and_type = transfer_header(actual_len, variant);
	memcpy(data + sizeof(struct wmsg_open_dmabuf), &sfd->dmabuf_info,
			sizeof(struct dmabuf_slice_data));

	pthread_mutex_lock(&transfers->lock);
	transfer_add(transfers, padded_len, data, transfers->last_msgno++);
	pthread_mutex_unlock(&transfers->lock);
}
static void add_file_create_request(
		struct transfer_data *transfers, struct shadow_fd *sfd)
{
	struct wmsg_open_file *header =
			calloc(1, sizeof(struct wmsg_open_file));
	header->file_size = sfd->buffer_size;
	header->remote_id = sfd->remote_id;
	header->size_and_type = transfer_header(
			sizeof(struct wmsg_open_file), WMSG_OPEN_FILE);

	pthread_mutex_lock(&transfers->lock);
	transfer_add(transfers, sizeof(struct wmsg_open_file), header,
			transfers->last_msgno++);
	pthread_mutex_unlock(&transfers->lock);
}

void finish_update(struct fd_translation_map *map, struct shadow_fd *sfd)
{
	if (!sfd->refcount_compute) {
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
	sfd->refcount_compute = false;
	destroy_shadow_if_unreferenced(map, sfd);
}

void collect_update(struct fd_translation_map *map, struct thread_pool *threads,
		struct shadow_fd *sfd, struct transfer_data *transfers)
{
	if (sfd->type == FDC_FILE) {
		if (!sfd->is_dirty) {
			// File is clean, we have no reason to believe
			// that its contents could have changed
			return;
		}
		// Clear dirty state
		sfd->is_dirty = false;
		if (!sfd->mem_mirror) {
			reset_damage(&sfd->damage);

			// increase space, to avoid overflow when
			// writing this buffer along with padding
			sfd->mem_mirror = calloc(align(sfd->buffer_size, 8), 1);
			memcpy(sfd->mem_mirror, sfd->mem_local,
					sfd->buffer_size);

			sfd->remote_bufsize = 0;

			add_file_create_request(transfers, sfd);
			queue_fill_transfers(map, threads, sfd, transfers);
			sfd->remote_bufsize = sfd->buffer_size;
			return;
		}

		if (sfd->remote_bufsize != sfd->buffer_size) {
			struct wmsg_open_file *header = calloc(
					1, sizeof(struct wmsg_open_file));
			header->file_size = sfd->buffer_size;
			header->remote_id = sfd->remote_id;
			header->size_and_type = transfer_header(
					sizeof(struct wmsg_open_file),
					WMSG_EXTEND_FILE);

			pthread_mutex_lock(&transfers->lock);
			transfer_add(transfers, sizeof(struct wmsg_open_file),
					header, transfers->last_msgno++);
			pthread_mutex_unlock(&transfers->lock);

			memcpy(sfd->mem_mirror + sfd->remote_bufsize,
					sfd->mem_local + sfd->remote_bufsize,
					sfd->buffer_size - sfd->remote_bufsize);

			queue_fill_transfers(map, threads, sfd, transfers);
			sfd->remote_bufsize = sfd->buffer_size;
		}

		queue_diff_transfers(map, threads, sfd, transfers);
	} else if (sfd->type == FDC_DMABUF) {
		// If buffer is clean, do not check for changes
		if (!sfd->is_dirty) {
			return;
		}
		sfd->is_dirty = false;

		bool first = false;
		if (!sfd->mem_mirror) {
			sfd->mem_mirror = calloc(1, sfd->buffer_size);
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
			// Q: is it better to run the copy in parallel?
			memcpy(sfd->mem_mirror, sfd->mem_local,
					sfd->buffer_size);

			queue_fill_transfers(map, threads, sfd, transfers);
		} else {
			damage_everything(&sfd->damage);

			queue_diff_transfers(map, threads, sfd, transfers);
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
		if (sfd->video_frameno == 0) {
			add_dmabuf_create_request(
					transfers, sfd, WMSG_OPEN_DMAVID_DST);
		}
		collect_video_from_mirror(sfd, transfers);
	} else if (sfd->type == FDC_DMAVID_IW) {
		sfd->is_dirty = false;
		if (sfd->video_frameno == -1) {
			add_dmabuf_create_request(
					transfers, sfd, WMSG_OPEN_DMAVID_SRC);
			sfd->video_frameno++;
		}
	} else if (fdcat_ispipe(sfd->type)) {
		// Pipes always update, no matter what the message
		// stream indicates.
		if (sfd->pipe_onlyhere) {
			struct wmsg_basic *createh =
					calloc(1, sizeof(struct wmsg_basic));
			enum wmsg_type type;
			if (sfd->type == FDC_PIPE_IR) {
				type = WMSG_OPEN_IW_PIPE;
			} else if (sfd->type == FDC_PIPE_IW) {
				type = WMSG_OPEN_IR_PIPE;
			} else {
				type = WMSG_OPEN_RW_PIPE;
			}
			createh->size_and_type = transfer_header(
					sizeof(struct wmsg_basic), type);
			createh->remote_id = sfd->remote_id;

			pthread_mutex_lock(&transfers->lock);
			transfer_add(transfers, sizeof(struct wmsg_basic),
					createh, transfers->last_msgno++);
			pthread_mutex_unlock(&transfers->lock);

			sfd->pipe_onlyhere = false;
		}

		if (sfd->pipe_recv.used > 0) {
			struct wmsg_basic *header =
					calloc(1, sizeof(struct wmsg_basic));
			size_t msgsz = sizeof(struct wmsg_basic) +
				       sfd->pipe_recv.used;
			header->size_and_type = transfer_header(
					msgsz, WMSG_PIPE_TRANSFER);
			header->remote_id = sfd->remote_id;

			size_t psz = alignu(sfd->pipe_recv.used, 16);
			char *buf = malloc(psz);
			memcpy(buf, sfd->pipe_recv.data, sfd->pipe_recv.used);
			memset(buf + sfd->pipe_recv.used, 0,
					psz - sfd->pipe_recv.used);

			pthread_mutex_lock(&transfers->lock);
			transfer_add(transfers, sizeof(struct wmsg_basic),
					header, transfers->last_msgno);
			transfer_add(transfers, psz, buf,
					transfers->last_msgno);
			pthread_mutex_unlock(&transfers->lock);

			transfers->last_msgno++;
			sfd->pipe_recv.used = 0;
		}

		if (sfd->pipe_lclosed && !sfd->pipe_rclosed) {
			struct wmsg_basic *hanguph =
					calloc(1, sizeof(struct wmsg_basic));
			hanguph->size_and_type = transfer_header(
					sizeof(struct wmsg_basic),
					WMSG_PIPE_HANGUP);
			hanguph->remote_id = sfd->remote_id;

			pthread_mutex_lock(&transfers->lock);
			transfer_add(transfers, sizeof(struct wmsg_basic),
					hanguph, transfers->last_msgno++);
			pthread_mutex_unlock(&transfers->lock);

			sfd->pipe_rclosed = true;
			close(sfd->pipe_fd);
			sfd->pipe_fd = -2;
		}
	}
}

void create_from_update(struct fd_translation_map *map,
		struct render_data *render, enum wmsg_type type, int remote_id,
		const struct bytebuf *msg)
{

	wp_debug("Introducing new fd, remoteid=%d", remote_id);
	struct shadow_fd *sfd = calloc(1, sizeof(struct shadow_fd));
	sfd->next = map->list;
	map->list = sfd;
	sfd->remote_id = remote_id;
	sfd->fd_local = -1;
	sfd->is_dirty = false;
	reset_damage(&sfd->damage);
	/* Start the object reference at one, so that, if it is owned by
	 * some known protocol object, it can not be deleted until the
	 * fd has at least be transferred over the Wayland connection */
	sfd->refcount_transfer = 1;
	sfd->refcount_protocol = 0;
	if (type == WMSG_OPEN_FILE) {
		const struct wmsg_open_file header =
				*(const struct wmsg_open_file *)msg->data;

		sfd->type = FDC_FILE;
		sfd->mem_local = NULL;
		sfd->buffer_size = header.file_size;
		sfd->remote_bufsize = sfd->buffer_size;
		sfd->mem_mirror = calloc(
				(size_t)align((int)sfd->buffer_size, 8), 1);

		// The PID should be unique during the lifetime of the
		// program
		sprintf(sfd->file_shm_buf_name, "/waypipe%d-data_%d", getpid(),
				sfd->remote_id);

		sfd->fd_local = shm_open(sfd->file_shm_buf_name,
				O_RDWR | O_CREAT | O_TRUNC, 0644);
		if (sfd->fd_local == -1) {
			wp_error("Failed to create shm file for object %d: %s",
					sfd->remote_id, strerror(errno));
			return;
		}
		if (ftruncate(sfd->fd_local, sfd->buffer_size) == -1) {
			wp_error("Failed to resize shm file %s to size %ld for reason: %s",
					sfd->file_shm_buf_name,
					sfd->buffer_size, strerror(errno));
			return;
		}
		sfd->mem_local = mmap(NULL, sfd->buffer_size,
				PROT_READ | PROT_WRITE, MAP_SHARED,
				sfd->fd_local, 0);
		memcpy(sfd->mem_local, sfd->mem_mirror, sfd->buffer_size);
	} else if (type == WMSG_OPEN_RW_PIPE || type == WMSG_OPEN_IW_PIPE ||
			type == WMSG_OPEN_IR_PIPE) {
		int pipedes[2];
		if (type == WMSG_OPEN_RW_PIPE) {
			if (socketpair(AF_UNIX, SOCK_STREAM, 0, pipedes) ==
					-1) {
				wp_error("Failed to create a socketpair: %s",
						strerror(errno));
				return;
			}
		} else {
			if (pipe(pipedes) == -1) {
				wp_error("Failed to create a pipe: %s",
						strerror(errno));
				return;
			}
		}

		/* We pass 'fd_local' to the client, although we only
		 * read and write from pipe_fd if it exists. */
		if (type == WMSG_OPEN_IR_PIPE) {
			// Read end is 0; the other process writes
			sfd->fd_local = pipedes[1];
			sfd->pipe_fd = pipedes[0];
			sfd->type = FDC_PIPE_IR;
		} else if (type == WMSG_OPEN_IW_PIPE) {
			// Write end is 1; the other process reads
			sfd->fd_local = pipedes[0];
			sfd->pipe_fd = pipedes[1];
			sfd->type = FDC_PIPE_IW;
		} else { // FDC_PIPE_RW
			// Here, it doesn't matter which end is which
			sfd->fd_local = pipedes[0];
			sfd->pipe_fd = pipedes[1];
			sfd->type = FDC_PIPE_RW;
		}

		if (set_nonblocking(sfd->pipe_fd) == -1) {
			wp_error("Failed to make private pipe end nonblocking: %s",
					strerror(errno));
			return;
		}

		// Allocate a reasonably small read buffer
		sfd->pipe_recv.size = 16384;
		sfd->pipe_recv.data = calloc((size_t)sfd->pipe_recv.size, 1);
		sfd->pipe_onlyhere = false;
	} else if (type == WMSG_OPEN_DMAVID_DST) {
		/* remote read data, this side writes data */
		const struct wmsg_open_dmabuf header =
				*(const struct wmsg_open_dmabuf *)msg->data;

		sfd->type = FDC_DMAVID_IW;
		sfd->buffer_size = header.file_size;

		if (init_render_data(render) == 1) {
			sfd->fd_local = -1;
			return;
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
			return;
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
		setup_video_decode(sfd, render);
	} else if (type == WMSG_OPEN_DMAVID_SRC) {
		/* remote writes data, this side reads data */
		sfd->type = FDC_DMAVID_IR;
		const struct wmsg_open_dmabuf header =
				*(const struct wmsg_open_dmabuf *)msg->data;
		sfd->buffer_size = header.file_size;

		if (init_render_data(render) == 1) {
			sfd->fd_local = -1;
			return;
		}

		memcpy(&sfd->dmabuf_info,
				msg->data + sizeof(struct wmsg_open_dmabuf),
				sizeof(struct dmabuf_slice_data));
		sfd->dmabuf_bo = make_dmabuf(
				render, sfd->buffer_size, &sfd->dmabuf_info);
		if (!sfd->dmabuf_bo) {
			wp_error("FDC_DMAVID_IR: RID=%d make_dmabuf failure",
					sfd->remote_id);
			return;
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
		setup_video_encode(sfd, render);
	} else if (type == WMSG_OPEN_DMABUF) {
		sfd->type = FDC_DMABUF;
		const struct wmsg_open_dmabuf header =
				*(const struct wmsg_open_dmabuf *)msg->data;
		sfd->buffer_size = header.file_size;

		memcpy(&sfd->dmabuf_info,
				msg->data + sizeof(struct wmsg_open_dmabuf),
				sizeof(struct dmabuf_slice_data));
		sfd->mem_mirror = calloc(sfd->buffer_size, 1);

		wp_debug("Creating remote DMAbuf of %d bytes",
				(int)sfd->buffer_size);
		// Create mirror from first transfer
		// The file can only actually be created when we know
		// what type it is?
		if (init_render_data(render) == 1) {
			sfd->fd_local = -1;
			return;
		}

		sfd->dmabuf_bo = make_dmabuf(
				render, sfd->buffer_size, &sfd->dmabuf_info);
		if (!sfd->dmabuf_bo) {
			sfd->fd_local = -1;
			return;
		}
		sfd->fd_local = export_dmabuf(sfd->dmabuf_bo);
	} else {
		wp_error("Creating unknown file type updates");
	}
}

static void increase_buffer_sizes(struct shadow_fd *sfd, size_t new_size)
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
	sfd->mem_mirror = realloc(sfd->mem_mirror, align(sfd->buffer_size, 8));
	/* set extension bytes to zero so that the standard diff procedure has
	 * a known state to work against */
	memset(sfd->mem_mirror + old_size, 0,
			align(sfd->buffer_size, 8) - old_size);
}

void apply_update(struct fd_translation_map *map, struct thread_pool *threads,
		struct render_data *render, enum wmsg_type type, int remote_id,
		const struct bytebuf *msg)
{
	if (type == WMSG_OPEN_FILE || type == WMSG_OPEN_DMABUF ||
			type == WMSG_OPEN_IR_PIPE ||
			type == WMSG_OPEN_IW_PIPE ||
			type == WMSG_OPEN_RW_PIPE ||
			type == WMSG_OPEN_DMAVID_SRC ||
			type == WMSG_OPEN_DMAVID_DST) {
		create_from_update(map, render, type, remote_id, msg);
		return;
	}

	struct shadow_fd *sfd = get_shadow_for_rid(map, remote_id);
	if (!sfd) {
		wp_error("shadow structure for RID=%d was not available",
				remote_id);
		return;
	}
	if (type == WMSG_EXTEND_FILE) {
		if (sfd->type != FDC_FILE) {
			wp_error("Trying to extend RID=%d, type=%s, which is not a file",
					remote_id, fdcat_to_str(sfd->type));
			return;
		}

		const struct wmsg_open_file *header =
				(const struct wmsg_open_file *)msg->data;
		if (ftruncate(sfd->fd_local, header->file_size) == -1) {
			wp_error("Failed to resize file buffer: %s",
					strerror(errno));
		}
		increase_buffer_sizes(sfd, header->file_size);
	} else if (type == WMSG_BUFFER_FILL) {
		if (sfd->type != FDC_FILE && sfd->type != FDC_DMABUF) {
			wp_error("Trying to fill RID=%d, type=%s, which is not a buffer-type",
					remote_id, fdcat_to_str(sfd->type));
			return;
		}
		const struct wmsg_buffer_fill *header =
				(const struct wmsg_buffer_fill *)msg->data;
		size_t sz = transfer_size(header->size_and_type);

		const char *act_buffer = NULL;
		size_t act_size = 0;
		void *fptr = uncompress_buffer(threads,
				&threads->threads[0].comp_ctx,
				sz - sizeof(struct wmsg_buffer_fill),
				msg->data + sizeof(struct wmsg_buffer_fill),
				header->end - header->start, &act_size,
				&act_buffer);

		// `memsize+8*remote_nthreads` is the worst-case diff
		// expansion
		if (header->end > sfd->buffer_size) {
			wp_error("Transfer end overflow %ld > %ld",
					(uint64_t)header->end,
					(uint64_t)sfd->buffer_size);
		}
		if (act_size != header->end - header->start) {
			wp_error("Transfer size mismatch %ld %ld",
					(uint64_t)act_size,
					(uint64_t)(header->end -
							header->start));
		}
		memcpy(sfd->mem_mirror + header->start, act_buffer,
				header->end - header->start);
		free(fptr);

		void *handle = NULL;
		if (sfd->type == FDC_DMABUF) {
			sfd->mem_local = map_dmabuf(
					sfd->dmabuf_bo, true, &handle);
			if (!sfd->mem_local) {
				return;
			}
		}
		memcpy(sfd->mem_local + header->start,
				sfd->mem_mirror + header->start,
				header->end - header->start);

		if (sfd->type == FDC_DMABUF) {
			sfd->mem_local = NULL;
			if (unmap_dmabuf(sfd->dmabuf_bo, handle) == -1) {
				return;
			}
		}
	} else if (type == WMSG_BUFFER_DIFF) {
		if (sfd->type != FDC_FILE && sfd->type != FDC_DMABUF) {
			wp_error("Trying to apply diff to RID=%d, type=%s, which is not a buffer-type",
					remote_id, fdcat_to_str(sfd->type));
			return;
		}
		const struct wmsg_buffer_diff *header =
				(const struct wmsg_buffer_diff *)msg->data;
		size_t sz = transfer_size(header->size_and_type);

		const char *act_buffer = NULL;
		size_t act_size = 0;
		void *fptr = uncompress_buffer(threads,
				&threads->threads[0].comp_ctx,
				sz - sizeof(struct wmsg_buffer_diff),
				msg->data + sizeof(struct wmsg_buffer_diff),
				header->diff_size, &act_size, &act_buffer);

		// `memsize+8*remote_nthreads` is the worst-case diff
		// expansion
		if (act_size != header->diff_size) {
			wp_error("Transfer size mismatch %ld %ld", act_size,
					header->diff_size);
		}

		void *handle = NULL;
		if (sfd->type == FDC_DMABUF) {
			sfd->mem_local = map_dmabuf(
					sfd->dmabuf_bo, true, &handle);
			if (!sfd->mem_local) {
				free(fptr);
				return;
			}
		}
		apply_diff(sfd->buffer_size, sfd->mem_mirror, sfd->mem_local,
				act_size, act_buffer);
		free(fptr);
		if (sfd->type == FDC_DMABUF) {
			sfd->mem_local = NULL;
			if (unmap_dmabuf(sfd->dmabuf_bo, handle) == -1) {
				return;
			}
		}
	} else if (type == WMSG_PIPE_TRANSFER) {
		if (sfd->type != FDC_PIPE_IW && sfd->type != FDC_PIPE_RW) {
			wp_error("Trying to write data to RID=%d, type=%s, which is not a writable pipe",
					remote_id, fdcat_to_str(sfd->type));
			return;
		}

		const struct wmsg_basic *header =
				(const struct wmsg_basic *)msg->data;
		size_t sz = transfer_size(header->size_and_type);
		size_t transfer_size = sz - sizeof(struct wmsg_basic);

		ssize_t netsize = sfd->pipe_send.used + (ssize_t)transfer_size;
		if (sfd->pipe_send.size <= 1024) {
			sfd->pipe_send.size = 1024;
		}
		while (sfd->pipe_send.size < netsize) {
			sfd->pipe_send.size *= 2;
		}
		if (sfd->pipe_send.data) {
			sfd->pipe_send.data = realloc(sfd->pipe_send.data,
					sfd->pipe_send.size);
		} else {
			sfd->pipe_send.data = calloc(sfd->pipe_send.size, 1);
		}
		memcpy(sfd->pipe_send.data + sfd->pipe_send.used,
				msg->data + sizeof(struct wmsg_basic),
				transfer_size);
		sfd->pipe_send.used = netsize;

		// The pipe itself will be flushed/or closed later by
		// flush_writable_pipes
		sfd->pipe_writable = true;
	} else if (type == WMSG_PIPE_HANGUP) {
		if (sfd->type != FDC_PIPE_IW && sfd->type != FDC_PIPE_RW) {
			wp_error("Trying to hang up the pipe RID=%d, type=%s, which is not a writable pipe",
					remote_id, fdcat_to_str(sfd->type));
			return;
		}
		sfd->pipe_rclosed = true;
	} else if (type == WMSG_SEND_DMAVID_PACKET) {
		if (sfd->type != FDC_DMAVID_IW) {
			wp_error("Trying to send video packet to RID=%d, type=%s, which is not a video output buffer",
					remote_id, fdcat_to_str(sfd->type));
			return;
		}
		if (!sfd->dmabuf_bo) {
			wp_error("Applying update to nonexistent dma buffer object rid=%d",
					sfd->remote_id);
			return;
		}
		const struct wmsg_basic *header =
				(const struct wmsg_basic *)msg->data;
		size_t sz = transfer_size(header->size_and_type);
		struct bytebuf data = {
				.data = msg->data + sizeof(struct wmsg_basic),
				.size = sz - sizeof(struct wmsg_basic)};
		apply_video_packet(sfd, render, &data);
	} else {
		wp_error("Unexpected update type: %s", wmsg_type_to_str(type));
	}
}

bool shadow_decref_protocol(
		struct fd_translation_map *map, struct shadow_fd *sfd)
{
	sfd->refcount_protocol--;
	return destroy_shadow_if_unreferenced(map, sfd);
}

bool shadow_decref_transfer(
		struct fd_translation_map *map, struct shadow_fd *sfd)
{
	sfd->refcount_transfer--;
	return destroy_shadow_if_unreferenced(map, sfd);
}
struct shadow_fd *shadow_incref_protocol(struct shadow_fd *sfd)
{
	sfd->has_owner = true;
	sfd->refcount_protocol++;
	return sfd;
}
struct shadow_fd *shadow_incref_transfer(struct shadow_fd *sfd)
{
	sfd->refcount_transfer++;
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
		if (fdcat_ispipe(cur->type)) {
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
		if (fdcat_ispipe(cur->type)) {
			if (!cur->pipe_lclosed) {
				pfds[np].fd = cur->pipe_fd;
				pfds[np].events = 0;
				if (check_read &&
						(cur->type == FDC_PIPE_RW ||
								cur->type == FDC_PIPE_IR)) {
					pfds[np].events |= POLLIN;
				}
				if (cur->pipe_send.used > 0) {
					pfds[np].events |= POLLOUT;
				}
				np++;
			}
		}
	}
	return np;
}

static struct shadow_fd *get_shadow_for_pipe_fd(
		struct fd_translation_map *map, int pipefd)
{
	for (struct shadow_fd *cur = map->list; cur; cur = cur->next) {
		if (fdcat_ispipe(cur->type) && cur->pipe_fd == pipefd) {
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
		if (pfds[i].revents & POLLIN) {
			sfd->pipe_readable = true;
		}
		if (pfds[i].revents & POLLOUT) {
			sfd->pipe_writable = true;
		}
		if (pfds[i].revents & POLLHUP) {
			sfd->pipe_lclosed = true;
		}
	}
}

void flush_writable_pipes(struct fd_translation_map *map)
{
	for (struct shadow_fd *cur = map->list; cur; cur = cur->next) {
		if (fdcat_ispipe(cur->type) && cur->pipe_writable &&
				cur->pipe_send.used > 0) {
			cur->pipe_writable = false;
			wp_debug("Flushing %ld bytes into RID=%d",
					cur->pipe_send.used, cur->remote_id);
			ssize_t changed =
					write(cur->pipe_fd, cur->pipe_send.data,
							cur->pipe_send.used);

			if (changed == -1) {
				wp_error("Failed to write into pipe with remote_id=%d: %s",
						cur->remote_id,
						strerror(errno));
			} else if (changed == 0) {
				wp_debug("Zero write event");
			} else {
				cur->pipe_send.used -= changed;
				if (cur->pipe_send.used) {
					memmove(cur->pipe_send.data,
							cur->pipe_send.data +
									changed,
							cur->pipe_send.used);
				} else {
					free(cur->pipe_send.data);
					cur->pipe_send.data = NULL;
					cur->pipe_send.size = 0;
					cur->pipe_send.used = 0;
				}
			}
		}
	}
}
void read_readable_pipes(struct fd_translation_map *map)
{
	for (struct shadow_fd *cur = map->list; cur; cur = cur->next) {
		if (fdcat_ispipe(cur->type) && cur->pipe_readable &&
				cur->pipe_recv.size > cur->pipe_recv.used) {
			cur->pipe_readable = false;
			ssize_t changed = read(cur->pipe_fd,
					cur->pipe_recv.data +
							cur->pipe_recv.used,
					cur->pipe_recv.size -
							cur->pipe_recv.used);
			if (changed == -1) {
				wp_error("Failed to read from pipe with remote_id=%d: %s",
						cur->remote_id,
						strerror(errno));
			} else if (changed == 0) {
				wp_debug("Zero write event");
			} else {
				wp_debug("Read %ld more bytes from RID=%d",
						changed, cur->remote_id);
				cur->pipe_recv.used += changed;
			}
		}
	}
}

void close_local_pipe_ends(struct fd_translation_map *map)
{
	for (struct shadow_fd *cur = map->list; cur; cur = cur->next) {
		if (fdcat_ispipe(cur->type) && cur->fd_local != -2 &&
				cur->fd_local != cur->pipe_fd) {
			close(cur->fd_local);
			cur->fd_local = -2;
		}
	}
}

void close_rclosed_pipes(struct fd_translation_map *map)
{
	for (struct shadow_fd *cur = map->list; cur; cur = cur->next) {
		if (fdcat_ispipe(cur->type) && cur->pipe_rclosed &&
				!cur->pipe_lclosed) {
			close(cur->pipe_fd);
			if (cur->pipe_fd == cur->fd_local) {
				cur->fd_local = -2;
			}
			cur->pipe_fd = -2;
			cur->pipe_lclosed = true;
		}
	}
}

void extend_shm_shadow(struct fd_translation_map *map, struct shadow_fd *sfd,
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

	increase_buffer_sizes(sfd, new_size);
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
	}
}

static void *worker_thread_main(void *arg)
{
	struct thread_data *data = arg;
	struct thread_pool *pool = data->pool;

	setup_comp_ctx(&data->comp_ctx, pool->compression);

	/* The loop is globally locked by default, and only unlocked in
	 * pthread_cond_wait. Yes, there are fancier and faster schemes.
	 */
	pthread_mutex_lock(&pool->work_mutex);
	while (1) {
		while (pool->queue_start == pool->queue_end) {
			pthread_cond_wait(&pool->work_cond, &pool->work_mutex);
		}
		/* Copy task, since the queue may be resized */
		struct task_data task = pool->queue[pool->queue_start++];
		pool->queue_in_progress++;
		pthread_mutex_unlock(&pool->work_mutex);
		run_task(&task, data);
		pthread_mutex_lock(&pool->work_mutex);

		uint8_t triv = 0;
		pool->queue_in_progress--;
		if (write(pool->selfpipe_w, &triv, 1) == -1) {
			wp_error("Failed to write to self-pipe");
		}
		if (task.type == TASK_STOP) {
			break;
		}
	}
	pthread_mutex_unlock(&pool->work_mutex);

	cleanup_comp_ctx(&data->comp_ctx);
	return NULL;
}
