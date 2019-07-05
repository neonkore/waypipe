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

	if (sfd->type == FDC_FILE) {
		munmap(sfd->mem_local, sfd->buffer_size);
		free(sfd->mem_mirror);
		free(sfd->diff_buffer);
		free(sfd->compress_buffer);
		if (sfd->file_shm_buf_name[0]) {
			shm_unlink(sfd->file_shm_buf_name);
		}
	} else if (sfd->type == FDC_DMABUF) {
		destroy_dmabuf(sfd->dmabuf_bo);
		free(sfd->mem_mirror);
		free(sfd->diff_buffer);
		free(sfd->compress_buffer);
		free(sfd->video_buffer);
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
			wp_log(WP_ERROR, "Incorrect close(%d): %s",
					sfd->fd_local, strerror(errno));
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
static void cleanup_threads(struct fd_translation_map *map)
{
	pthread_mutex_lock(&map->work_state_mutex);
	map->next_thread_task = THREADTASK_STOP;
	map->task_id++;
	map->nthreads_completed = 0;
	pthread_mutex_unlock(&map->work_state_mutex);

	pthread_cond_broadcast(&map->work_needed_notify);
	for (int i = 0; i < map->nthreads - 1; i++) {
		pthread_join(map->threads[i].thread, NULL);
		cleanup_comp_ctx(&map->threads[i].comp_ctx);
	}
	pthread_mutex_destroy(&map->work_state_mutex);
	pthread_cond_destroy(&map->work_done_notify);
	pthread_cond_destroy(&map->work_needed_notify);
	free(map->threads);
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
			wp_log(WP_ERROR,
					"Failed to created LZ4F decompression context: %s",
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
	cleanup_comp_ctx(&map->comp_ctx);
	if (map->nthreads > 1) {
		cleanup_threads(map);
	}
}

static void *worker_thread_main(void *arg);
void setup_translation_map(struct fd_translation_map *map, bool display_side,
		enum compression_mode comp, int nthreads)
{
	map->local_sign = display_side ? -1 : 1;
	map->list = NULL;
	map->max_local_id = 1;
	map->compression = comp;
	setup_comp_ctx(&map->comp_ctx, comp);

	if (nthreads == 0) {
		// platform dependent
		long nt = sysconf(_SC_NPROCESSORS_ONLN);
		map->nthreads = max((int)nt / 2, 1);
	} else {
		map->nthreads = nthreads;
	}

	// 1 ms wakeup for other threads, assuming mild CPU load.
	float thread_switch_delay = 0.001f; // seconds
	float scan_proc_irate = 0.5e-9f;    // seconds/byte
	float comp_proc_irate = 0.f;        // seconds/bytes
#ifdef HAS_LZ4
	if (comp == COMP_LZ4) {
		// 0.15 seconds on uncompressable 1e8 bytes
		comp_proc_irate = 1.5e-9f;
	}
#endif
#ifdef HAS_ZSTD
	if (comp == COMP_ZSTD) {
		// 0.5 seconds on uncompressable 1e8 bytes
		comp_proc_irate = 5e-9f;
	}
#endif
	float proc_irate = scan_proc_irate + comp_proc_irate;
	if (map->nthreads > 1) {
		map->diffcomp_thread_threshold =
				(int)((thread_switch_delay * map->nthreads) /
						(proc_irate * (map->nthreads -
									      1)));
		if (comp_proc_irate > 0) {
			map->comp_thread_threshold =
					(int)((thread_switch_delay *
							      map->nthreads) /
							(proc_irate * (map->nthreads -
										      1)));
		} else {
			map->comp_thread_threshold = INT32_MAX;
		}
	} else {
		map->diffcomp_thread_threshold = INT32_MAX;
		map->comp_thread_threshold = INT32_MAX;
	}
	// stop task won't be called unless the main task id is
	// incremented
	map->next_thread_task = THREADTASK_STOP;
	map->nthreads_completed = 0;
	map->task_id = 0;
	if (map->nthreads > 1) {
		pthread_mutex_init(&map->work_state_mutex, NULL);
		pthread_cond_init(&map->work_done_notify, NULL);
		pthread_cond_init(&map->work_needed_notify, NULL);

		// The main thread has index zero, and will, since
		// computations block it anyway, share part of the
		// workload
		map->threads = calloc((size_t)(map->nthreads - 1),
				sizeof(struct thread_data));
		bool had_failures = false;
		for (int i = 0; i < map->nthreads - 1; i++) {
			// false sharing is negligible for cold data
			map->threads[i].map = map;
			map->threads[i].index = i + 1;
			map->threads[i].thread = 0;
			map->threads[i].last_task_id = 0;

			map->threads[i].cd_actual_size = 0;
			map->threads[i].cd_dst.data = NULL;
			map->threads[i].cd_dst.size = 0;
			setup_comp_ctx(&map->threads[i].comp_ctx, comp);

			int ret = pthread_create(&map->threads[i].thread, NULL,
					worker_thread_main, &map->threads[i]);
			if (ret == -1) {
				wp_log(WP_ERROR, "Thread creation failed");
				had_failures = true;
				break;
			}
		}

		if (had_failures) {
			cleanup_threads(map);
			map->nthreads = 1;
		}
	}
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
	}
	return "<invalid>";
}

fdcat_t get_fd_type(int fd, size_t *size)
{
	struct stat fsdata;
	memset(&fsdata, 0, sizeof(fsdata));
	int ret = fstat(fd, &fsdata);
	if (ret == -1) {
		wp_log(WP_ERROR, "The fd %d is not file-like: %s", fd,
				strerror(errno));
		return FDC_UNKNOWN;
	} else if (S_ISREG(fsdata.st_mode)) {
		if (size) {
			*size = (size_t)fsdata.st_size;
		}
		return FDC_FILE;
	} else if (S_ISFIFO(fsdata.st_mode) || S_ISCHR(fsdata.st_mode) ||
			S_ISSOCK(fsdata.st_mode)) {
		if (S_ISCHR(fsdata.st_mode)) {
			wp_log(WP_ERROR,
					"The fd %d, size %ld, mode %x is a character device. Proceeding under the assumption that it is pipe-like.",
					fd, fsdata.st_size, fsdata.st_mode);
		}
		if (S_ISSOCK(fsdata.st_mode)) {
			wp_log(WP_ERROR,
					"The fd %d, size %ld, mode %x is a socket. Proceeding under the assumption that it is pipe-like.",
					fd, fsdata.st_size, fsdata.st_mode);
		}
		int flags = fcntl(fd, F_GETFL, 0);
		if (flags == -1) {
			wp_log(WP_ERROR, "fctnl F_GETFL failed!");
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
		wp_log(WP_ERROR,
				"The fd %d has an unusual mode %x (type=%x): blk=%d chr=%d dir=%d lnk=%d reg=%d fifo=%d sock=%d; expect an application crash!",
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

static size_t compress_bufsize(struct fd_translation_map *map, size_t max_input)
{
	switch (map->compression) {
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
static void compress_buffer(struct fd_translation_map *map,
		struct comp_ctx *ctx, size_t isize, const char *ibuf,
		size_t msize, char *mbuf, size_t *wsize, const char **wbuf)
{
	(void)ctx;
	// Ensure inputs always nontrivial
	if (isize == 0) {
		*wsize = 0;
		*wbuf = ibuf;
		return;
	}

	DTRACE_PROBE1(waypipe, compress_buffer_enter, isize);
	switch (map->compression) {
	case COMP_NONE:
		(void)msize;
		(void)mbuf;
		*wsize = isize;
		*wbuf = ibuf;
		break;
#ifdef HAS_LZ4
	case COMP_LZ4: {
		size_t ws = LZ4F_compressFrame(mbuf, msize, ibuf, isize, NULL);
		if (LZ4F_isError(ws)) {
			wp_log(WP_ERROR,
					"Lz4 compression failed for %d bytes in %d of space: %s",
					(int)isize, (int)msize,
					LZ4F_getErrorName(ws));
		}
		*wsize = (size_t)ws;
		*wbuf = mbuf;
		break;
	}
#endif
#ifdef HAS_ZSTD
	case COMP_ZSTD: {
		size_t ws = ZSTD_compress2(
				ctx->zstd_ccontext, mbuf, msize, ibuf, isize);
		if (ZSTD_isError(ws)) {
			wp_log(WP_ERROR,
					"Zstd compression failed for %d bytes in %d of space: %s",
					(int)isize, (int)msize,
					ZSTD_getErrorName(ws));
		}
		*wsize = (size_t)ws;
		*wbuf = mbuf;
		break;
	}
#endif
	}
	DTRACE_PROBE1(waypipe, compress_buffer_exit, *wsize);
}
/* With the selected compression method, uncompress the buffer
 * {isize,ibuf}, possibly modifying {msize,mbuf}, and setting
 * {wsize,wbuf} to indicate the result. msize should be set = the
 * uncompressed buffer size, which should have been provided. */
static void uncompress_buffer(struct fd_translation_map *map, size_t isize,
		const char *ibuf, size_t msize, char *mbuf, size_t *wsize,
		const char **wbuf)
{
	// Ensure inputs always nontrivial
	if (isize == 0) {
		*wsize = 0;
		*wbuf = ibuf;
		return;
	}

	DTRACE_PROBE1(waypipe, uncompress_buffer_enter, isize);
	switch (map->compression) {
	case COMP_NONE:
		(void)msize;
		(void)mbuf;
		*wsize = isize;
		*wbuf = ibuf;
		break;
#ifdef HAS_LZ4
	case COMP_LZ4: {
		size_t total = 0;
		size_t read = 0;
		while (read < isize) {
			size_t dst_remaining = msize - total;
			size_t src_remaining = isize - read;
			size_t hint = LZ4F_decompress(
					map->comp_ctx.lz4f_dcontext,
					&mbuf[total], &dst_remaining,
					&ibuf[read], &src_remaining, NULL);
			read += src_remaining;
			total += dst_remaining;
			if (LZ4F_isError(hint)) {
				wp_log(WP_ERROR,
						"Lz4 decomp. failed with %d bytes and %d space remaining: %s",
						isize - read, msize - total,
						LZ4F_getErrorName(hint));
				break;
			}
		}
		*wsize = total;
		*wbuf = mbuf;
		break;
	}
#endif
#ifdef HAS_ZSTD
	case COMP_ZSTD: {
		size_t ws = ZSTD_decompressDCtx(map->comp_ctx.zstd_dcontext,
				mbuf, msize, ibuf, isize);
		if (ZSTD_isError(ws) || (size_t)ws != msize) {
			wp_log(WP_ERROR,
					"Zstd decompression failed for %d bytes to %d of space: %s",
					(int)isize, (int)msize,
					ZSTD_getErrorName(ws));
			ws = 0;
		}
		*wsize = (size_t)ws;
		*wbuf = mbuf;
		break;
	}
#endif
	}
	DTRACE_PROBE1(waypipe, uncompress_buffer_exit, *wsize);
}

struct shadow_fd *translate_fd(struct fd_translation_map *map,
		struct render_data *render, int fd, fdcat_t type,
		size_t file_sz, struct dmabuf_slice_data *info, bool use_video)
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
	sfd->buffer_size = (size_t)-1;
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

	wp_log(WP_DEBUG, "Creating new shadow buffer for local fd %d", fd);
	if (sfd->type == FDC_FILE) {
		// We have a file-like object
		sfd->buffer_size = file_sz;
		// both r/w permissions, because the size the allocates
		// the memory does not always have to be the size that
		// modifies it
		sfd->mem_local = mmap(NULL, sfd->buffer_size,
				PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		if (!sfd->mem_local) {
			wp_log(WP_ERROR, "Mmap failed!");
			return sfd;
		}
		// This will be created at the first transfer
		sfd->mem_mirror = NULL;
	} else if (fdcat_ispipe(sfd->type)) {
		// Make this end of the pipe nonblocking, so that we can
		// include it in our main loop.
		if (set_nonblocking(sfd->fd_local) == -1) {
			wp_log(WP_ERROR, "Failed to make fd nonblocking");
		}
		sfd->pipe_fd = sfd->fd_local;

		// Allocate a reasonably small read buffer
		sfd->pipe_recv.size = 16384;
		sfd->pipe_recv.data = calloc((size_t)sfd->pipe_recv.size, 1);

		sfd->pipe_onlyhere = true;
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
		sfd->diff_buffer = NULL;
		sfd->type = FDC_DMABUF;

		if (info && use_video) {
			setup_video_encode(sfd, (int)info->width,
					(int)info->height,
					(int)info->strides[0],
					(int)info->format);
		}
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
void construct_diff(size_t size, const struct damage *__restrict__ damage,
		uint64_t slice_no, uint64_t nslices, char *__restrict__ base,
		const char *__restrict__ changed, size_t *diffsize,
		char *__restrict__ diff)
{
	DTRACE_PROBE1(waypipe, construct_diff_enter, damage->ndamage_intvs);

	uint64_t nblocks = (uint64_t)floordiv((int)size, 8);
	uint64_t *__restrict__ base_blocks = (uint64_t *)base;
	const uint64_t *__restrict__ changed_blocks = (const uint64_t *)changed;

	uint64_t *__restrict__ diff_blocks = (uint64_t *)diff;
	uint64_t ntrailing = size - 8 * nblocks;
	uint64_t cursor = 0;

	struct interval damage_everything = {0, size};
	struct interval *damage_list;
	int damage_len;
	if (damage->damage == DAMAGE_EVERYTHING) {
		damage_list = &damage_everything;
		damage_len = 1;
	} else {
		damage_list = damage->damage;
		damage_len = damage->ndamage_intvs;
	}

	uint64_t net_blocks = 0;
	if (nslices > 1) {
		for (int d = 0; d < damage_len; d++) {
			/* realign to get true checked sizes */
			struct interval intv = damage_list[d];
			uint64_t bstart =
					minu(floordiv(intv.start, 8), nblocks);
			uint64_t bend = minu(ceildiv(intv.end, 8), nblocks);
			net_blocks += bend - bstart;
		}
	} else {
		net_blocks = UINT64_MAX;
	}
	uint64_t blockno_min = (net_blocks * slice_no) / nslices;
	uint64_t blockno_max = (net_blocks * (slice_no + 1)) / nslices;

	uint64_t acc_blocks = 0;
	for (int d = 0; d < damage_len; d++) {
		struct interval intv = damage_list[d];
		uint64_t bstart = minu(floordiv(intv.start, 8), nblocks);
		uint64_t bend = minu(ceildiv(intv.end, 8), nblocks);
		uint64_t w = bend - bstart;
		/* Adjust `bstart` and `bend` to be fall within the cumulative
		 * block count restrictions. */
		if (acc_blocks < blockno_min) {
			bstart += (blockno_min - acc_blocks);
		}
		acc_blocks += w;
		if (acc_blocks > blockno_max) {
			/* don't wrap over */
			if (bend < (acc_blocks - blockno_max)) {
				bend = 0;
			} else {
				bend -= (acc_blocks - blockno_max);
			}
		}
		if (bend <= bstart) {
			continue;
		}
		cursor = run_interval_diff(bstart, bend, changed_blocks,
				base_blocks, diff_blocks, cursor);
	}

	bool check_tail = slice_no + 1 == nslices;
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
		wp_log(WP_ERROR, "Trailing bytes mismatch for diff.");
		return;
	}
	DTRACE_PROBE2(waypipe, apply_diff_enter, size, diffsize);
	for (uint64_t i = 0; i < ndiffblocks;) {
		uint64_t block = diff_blocks[i];
		uint64_t nfrom = block >> 32;
		uint64_t nto = (block << 32) >> 32;
		if (nto > nblocks || nfrom >= nto ||
				i + (nto - nfrom) >= ndiffblocks) {
			wp_log(WP_ERROR,
					"Invalid copy range [%ld,%ld) > %ld=nblocks or [%ld,%ld) > %ld=ndiffblocks",
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

struct transfer *setup_single_block_transfer(int *ntransfers,
		struct transfer transfers[], int *nblocks,
		struct bytebuf blocks[], size_t size, const char *data)
{
	int nt = (*ntransfers)++;
	int nb = (*nblocks)++;
	transfers[nt].type = FDC_UNKNOWN;
	transfers[nt].obj_id = 0;
	transfers[nt].special.raw = 0;
	transfers[nt].nblocks = 1;
	transfers[nt].subtransfers = &blocks[nb];
	blocks[nb].size = size;
	blocks[nb].data = (char *)data;
	return &transfers[nt];
}

/* Construct and optionally compress a diff between sfd->mem_mirror and
 * the actual memmap'd data */
static void worker_run_compresseddiff(struct fd_translation_map *map,
		struct comp_ctx *ctx, int index, int nthreads,
		struct bytebuf *dst, size_t *actual_size)
{
	DTRACE_PROBE1(waypipe, worker_compdiff_enter, index);
	struct shadow_fd *sfd = map->thread_target;

	/* Allocate a disjoint target interval to each worker */
	size_t diff_step = align(ceildiv(sfd->buffer_size, nthreads) + 16, 8);
	size_t comp_step = compress_bufsize(map, diff_step);

	size_t diffsize;
	construct_diff(sfd->buffer_size, &sfd->damage, index, nthreads,
			sfd->mem_mirror, sfd->mem_local, &diffsize,
			&sfd->diff_buffer[diff_step * index]);
	*actual_size = diffsize;

	if (diffsize > diff_step) {
		wp_log(WP_ERROR, "Compression section %d overflow (%d>%d)",
				index, (int)diffsize, (int)diff_step);
	}

	dst->size = 0;
	dst->data = NULL;
	compress_buffer(map, ctx, diffsize,
			&sfd->diff_buffer[diff_step * index], comp_step,
			&sfd->compress_buffer[comp_step * index], &dst->size,
			(const char **)&dst->data);

	DTRACE_PROBE1(waypipe, worker_compdiff_exit, index);
}

/* Compress data for sfd->mem_mirror */
static void worker_run_compressblock(struct fd_translation_map *map,
		struct comp_ctx *ctx, int index, int nthreads,
		struct bytebuf *dst, size_t *actual_size)
{
	DTRACE_PROBE1(waypipe, worker_comp_enter, index);

	struct shadow_fd *sfd = map->thread_target;

	/* Allocate a disjoint target interval to each worker */
	size_t source_start =
			align(((size_t)index * sfd->buffer_size) / nthreads, 8);
	size_t source_end = align(
			(((size_t)index + 1) * sfd->buffer_size) / nthreads, 8);
	source_end = min(sfd->buffer_size, source_end);

	size_t comp_step = compress_bufsize(
			map, align(ceildiv(sfd->buffer_size, nthreads) + 8, 8));

	*actual_size = source_end - source_start;

	dst->size = 0;
	dst->data = NULL;
	compress_buffer(map, ctx, source_end - source_start,
			&sfd->mem_mirror[source_start], comp_step,
			&sfd->compress_buffer[comp_step * index], &dst->size,
			(const char **)&dst->data);

	DTRACE_PROBE1(waypipe, worker_comp_exit, index);
}

static void queue_thread_task(struct fd_translation_map *map,
		struct shadow_fd *shadow, enum thread_task task)
{
	pthread_mutex_lock(&map->work_state_mutex);
	map->task_id++;
	map->nthreads_completed = 0;
	map->next_thread_task = task;
	map->thread_target = shadow;
	pthread_mutex_unlock(&map->work_state_mutex);
	pthread_cond_broadcast(&map->work_needed_notify);
}
static void wait_thread_task(struct fd_translation_map *map)
{
	pthread_mutex_lock(&map->work_state_mutex);
	map->nthreads_completed++;
	while (map->nthreads_completed < map->nthreads) {
		pthread_cond_wait(
				&map->work_done_notify, &map->work_state_mutex);
	}
	pthread_mutex_unlock(&map->work_state_mutex);
}
/* Optionally compress the data in mem_mirror, and set up the initial
 * transfer blocks */
static void add_initial_compressed_block(struct fd_translation_map *map,
		struct shadow_fd *sfd, int *ntransfers,
		struct transfer transfers[], int *nblocks,
		struct bytebuf blocks[])
{
	// new transfer, we send file contents verbatim
	bool use_threads =
			(int32_t)sfd->buffer_size > map->comp_thread_threshold;

	size_t cd_actual_size0;
	struct bytebuf cd_dst0;
	if (use_threads) {
		queue_thread_task(map, sfd, THREADTASK_COMPRESSBLOCK);
	} else {
		map->thread_target = sfd;
	}
	worker_run_compressblock(map, &map->comp_ctx, 0,
			use_threads ? map->nthreads : 1, &cd_dst0,
			&cd_actual_size0);
	if (use_threads) {
		wait_thread_task(map);
	}

	struct transfer *tf = &transfers[(*ntransfers)++];
	tf->type = sfd->type;
	tf->obj_id = sfd->remote_id;
	tf->nblocks = 0;
	tf->subtransfers = &blocks[*nblocks];
	tf->special.block_meta = 0;
	if (sfd->type == FDC_DMABUF) {
		/* Add metadata section to ensure proper remote
		 * initialization
		 */
		struct bytebuf meta = {.data = (char *)&sfd->dmabuf_info,
				.size = sizeof(struct dmabuf_slice_data)};
		blocks[(*nblocks)++] = meta;
		tf->nblocks++;
	}
	if (cd_actual_size0) {
		tf->special.block_meta += cd_actual_size0;
		blocks[(*nblocks)++] = cd_dst0;
		tf->nblocks++;
	}
	if (use_threads) {
		for (int i = 0; i < map->nthreads - 1; i++) {
			if (map->threads[i].cd_actual_size) {
				tf->special.block_meta +=
						map->threads[i].cd_actual_size;
				blocks[(*nblocks)++] = map->threads[i].cd_dst;
				tf->nblocks++;
			}
		}
	}
}
static void add_updated_diff_block(struct fd_translation_map *map,
		struct shadow_fd *sfd, int *ntransfers,
		struct transfer transfers[], int *nblocks,
		struct bytebuf blocks[], int total_damaged_area)
{
	DTRACE_PROBE2(waypipe, diffcomp_start, total_damaged_area,
			sfd->buffer_size);
	bool use_threads = total_damaged_area > map->diffcomp_thread_threshold;

	size_t cd_actual_size0;
	struct bytebuf cd_dst0;
	if (use_threads) {
		queue_thread_task(map, sfd, THREADTASK_MAKE_COMPRESSEDDIFF);
	} else {
		map->thread_target = sfd;
	}
	worker_run_compresseddiff(map, &map->comp_ctx, 0,
			use_threads ? map->nthreads : 1, &cd_dst0,
			&cd_actual_size0);
	if (use_threads) {
		wait_thread_task(map);
	}

	size_t actual_diff_size = cd_actual_size0;
	if (use_threads) {
		for (int i = 0; i < map->nthreads - 1; i++) {
			if (map->threads[i].cd_actual_size) {
				actual_diff_size +=
						map->threads[i].cd_actual_size;
			}
		}
	}

	if (actual_diff_size > 0) {
		/* Only make the transfer if there were changes */
		struct transfer *tf = &transfers[(*ntransfers)++];
		tf->type = sfd->type;
		tf->obj_id = sfd->remote_id;
		tf->nblocks = 0;
		tf->subtransfers = &blocks[*nblocks];
		tf->special.block_meta = actual_diff_size;

		if (cd_actual_size0) {
			blocks[(*nblocks)++] = cd_dst0;
			tf->nblocks++;
		}
		if (use_threads) {
			for (int i = 0; i < map->nthreads - 1; i++) {
				if (map->threads[i].cd_actual_size) {
					blocks[(*nblocks)++] =
							map->threads[i].cd_dst;
					tf->nblocks++;
				}
			}
		}
	}
	reset_damage(&sfd->damage);
	DTRACE_PROBE1(waypipe, diffcomp_end, actual_diff_size);
	wp_log(WP_DEBUG, "Diff+comp construction end: %ld/%ld",
			(uint64_t)actual_diff_size, (uint64_t)sfd->buffer_size);
}

static void get_max_diff_space_usage(struct fd_translation_map *map,
		size_t buffer_size, size_t *diff_size, size_t *compdiff_size)
{
	size_t slice_size = align(ceildiv(buffer_size, map->nthreads) + 16, 8);
	*diff_size = slice_size * map->nthreads;

	// Using a number of distinct compressions often (but not necessarily)
	// will increase space needed
	*compdiff_size = max(compress_bufsize(map, align(buffer_size + 8, 8)),
			compress_bufsize(map, slice_size));
}

void collect_update(struct fd_translation_map *map, struct shadow_fd *sfd,
		int *ntransfers, struct transfer transfers[], int *nblocks,
		struct bytebuf blocks[])
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

			size_t diff_space = 0;
			get_max_diff_space_usage(map, sfd->buffer_size,
					&diff_space, &sfd->compress_space);
			sfd->diff_buffer = calloc(diff_space, 1);
			sfd->compress_buffer =
					sfd->compress_space
							? calloc(sfd->compress_space,
									  1)
							: NULL;

			add_initial_compressed_block(map, sfd, ntransfers,
					transfers, nblocks, blocks);
		}

		if (sfd->has_been_extended) {
			sfd->has_been_extended = false;
			struct transfer *tf = &transfers[(*ntransfers)++];
			tf->type = sfd->type;
			tf->obj_id = sfd->remote_id;
			tf->nblocks = 0;
			tf->subtransfers = NULL;
			tf->special.block_meta = FILE_SIZE_EXTEND_FLAG |
						 (uint32_t)sfd->buffer_size;
		}

		int total_area = get_damage_area(&sfd->damage);
		total_area = min(total_area, (int)sfd->buffer_size);
		if (total_area == 0) {
			reset_damage(&sfd->damage);
			return;
		}

		if (!sfd->diff_buffer) {
			/* Create diff buffer by need for remote files */
			size_t diff_space = 0;
			get_max_diff_space_usage(map, sfd->buffer_size,
					&diff_space, &sfd->compress_space);
			sfd->diff_buffer = calloc(diff_space, 1);
			if (!sfd->compress_buffer && sfd->compress_space) {
				sfd->compress_buffer =
						calloc(sfd->compress_space, 1);
			}
		}
		add_updated_diff_block(map, sfd, ntransfers, transfers, nblocks,
				blocks, total_area);

	} else if (sfd->type == FDC_DMABUF) {
		// If buffer is clean, do not check for changes
		if (!sfd->is_dirty) {
			return;
		}
		sfd->is_dirty = false;

		bool first = false;
		if (!sfd->mem_mirror && !sfd->video_codec) {
			sfd->mem_mirror = calloc(1, sfd->buffer_size);

			size_t diff_space = 0;
			get_max_diff_space_usage(map, sfd->buffer_size,
					&diff_space, &sfd->compress_space);
			sfd->diff_buffer = calloc(diff_space, 1);
			sfd->compress_buffer =
					sfd->compress_space
							? calloc(sfd->compress_space,
									  1)
							: NULL;
			first = true;
		} else if (!sfd->mem_mirror && sfd->video_codec) {
			int mirror_size = 0;
			pad_video_mirror_size((int)sfd->dmabuf_info.width,
					(int)sfd->dmabuf_info.height,
					(int)sfd->dmabuf_info.strides[0], NULL,
					NULL, &mirror_size);
			sfd->mem_mirror = calloc(
					(size_t)max((int)sfd->buffer_size,
							mirror_size),
					1);
			first = true;
		}
		void *handle = NULL;
		if (!sfd->dmabuf_bo) {
			// ^ was not previously able to create buffer
			return;
		}
		void *data = map_dmabuf(sfd->dmabuf_bo, false, &handle);
		if (!data) {
			return;
		}
		if (sfd->video_codec && sfd->video_context &&
				sfd->video_reg_frame && sfd->video_packet) {
			memcpy(sfd->mem_mirror, data, sfd->buffer_size);
			collect_video_from_mirror(sfd, ntransfers, transfers,
					nblocks, blocks, first);
			return;
		}

		if (first) {
			// Write diff with a header, and build mirror,
			// only touching data once
			memcpy(sfd->mem_mirror, data, sfd->buffer_size);

			add_initial_compressed_block(map, sfd, ntransfers,
					transfers, nblocks, blocks);
		} else {

			if (!sfd->diff_buffer) {
				// This can happen in
				// reverse-transport scenarios
				size_t diff_space = 0;
				get_max_diff_space_usage(map, sfd->buffer_size,
						&diff_space,
						&sfd->compress_space);
				sfd->diff_buffer = calloc(diff_space, 1);
				if (!sfd->compress_buffer &&
						sfd->compress_space) {
					sfd->compress_buffer = calloc(
							sfd->compress_space, 1);
				}
			}

			damage_everything(&sfd->damage);
			sfd->mem_local = data;

			/* Depending on the buffer format, doing a memcpy before
			 * running the diff construction routine can be
			 * significantly faster. */
			// TODO: Either autodetect when this happens, or write a
			// faster/vectorizable diff routine
			add_updated_diff_block(map, sfd, ntransfers, transfers,
					nblocks, blocks, (int)sfd->buffer_size);
			sfd->mem_local = NULL;
		}
		if (unmap_dmabuf(sfd->dmabuf_bo, handle) == -1) {
			// there was an issue unmapping; unmap_dmabuf
			// will log error
			return;
		}
	} else if (fdcat_ispipe(sfd->type)) {
		// Pipes always update, no matter what the message
		// stream indicates. Hence no sfd->is_dirty flag check
		if (sfd->pipe_recv.used > 0 || sfd->pipe_onlyhere ||
				(sfd->pipe_lclosed && !sfd->pipe_rclosed)) {
			sfd->pipe_onlyhere = false;
			wp_log(WP_DEBUG,
					"Adding update to pipe RID=%d, with %ld bytes, close %c",
					sfd->remote_id, sfd->pipe_recv.used,
					(sfd->pipe_lclosed &&
							!sfd->pipe_rclosed)
							? 'Y'
							: 'n');
			struct transfer *tf = setup_single_block_transfer(
					ntransfers, transfers, nblocks, blocks,
					sfd->pipe_recv.used,
					sfd->pipe_recv.data);
			tf->type = sfd->type;
			tf->obj_id = sfd->remote_id;
			if (sfd->pipe_lclosed && !sfd->pipe_rclosed) {
				tf->special.pipeclose = 1;
				sfd->pipe_rclosed = true;
				close(sfd->pipe_fd);
				sfd->pipe_fd = -2;
			} else {
				tf->special.pipeclose = 0;
			}
			// clear
			sfd->pipe_recv.used = 0;
		}
	}
}

void create_from_update(struct fd_translation_map *map,
		struct render_data *render, const struct transfer *transf)
{

	wp_log(WP_DEBUG, "Introducing new fd, remoteid=%d", transf->obj_id);
	struct shadow_fd *sfd = calloc(1, sizeof(struct shadow_fd));
	sfd->next = map->list;
	map->list = sfd;
	sfd->remote_id = transf->obj_id;
	sfd->fd_local = -1;
	sfd->type = transf->type;
	sfd->is_dirty = false;
	reset_damage(&sfd->damage);
	/* Start the object reference at one, so that, if it is owned by
	 * some known protocol object, it can not be deleted until the
	 * fd has at least be transferred over the Wayland connection */
	sfd->refcount_transfer = 1;
	sfd->refcount_protocol = 0;
	if (sfd->type == FDC_FILE) {
		sfd->mem_local = NULL;
		sfd->buffer_size = (size_t)(transf->special.block_meta &
					    FILE_SIZE_SIZE_MASK);
		sfd->mem_mirror = calloc(
				(size_t)align((int)sfd->buffer_size, 8), 1);

		size_t diff_space = 0;
		get_max_diff_space_usage(map, sfd->buffer_size, &diff_space,
				&sfd->compress_space);
		sfd->compress_buffer =
				sfd->compress_space
						? calloc(sfd->compress_space, 1)
						: NULL;

		if (transf->special.block_meta & FILE_SIZE_VIDEO_FLAG) {
			wp_log(WP_ERROR, "TODO, full video frame fill");
		} else {
			size_t act_size = 0;
			const char *act_buffer = NULL;
			uncompress_buffer(map, transf->subtransfers[0].size,
					transf->subtransfers[0].data,
					sfd->buffer_size, sfd->compress_buffer,
					&act_size, &act_buffer);

			// The first time only, the transfer data is a
			// direct copy of the source
			memcpy(sfd->mem_mirror, act_buffer, act_size);
		}
		// The PID should be unique during the lifetime of the
		// program
		sprintf(sfd->file_shm_buf_name, "/waypipe%d-data_%d", getpid(),
				sfd->remote_id);

		sfd->fd_local = shm_open(sfd->file_shm_buf_name,
				O_RDWR | O_CREAT | O_TRUNC, 0644);
		if (sfd->fd_local == -1) {
			wp_log(WP_ERROR,
					"Failed to create shm file for object %d: %s",
					sfd->remote_id, strerror(errno));
			return;
		}
		if (ftruncate(sfd->fd_local, sfd->buffer_size) == -1) {
			wp_log(WP_ERROR,
					"Failed to resize shm file %s to size %ld for reason: %s",
					sfd->file_shm_buf_name,
					sfd->buffer_size, strerror(errno));
			return;
		}
		sfd->mem_local = mmap(NULL, sfd->buffer_size,
				PROT_READ | PROT_WRITE, MAP_SHARED,
				sfd->fd_local, 0);
		memcpy(sfd->mem_local, sfd->mem_mirror, sfd->buffer_size);
	} else if (fdcat_ispipe(sfd->type)) {
		int pipedes[2];
		if (transf->type == FDC_PIPE_RW) {
			if (socketpair(AF_UNIX, SOCK_STREAM, 0, pipedes) ==
					-1) {
				wp_log(WP_ERROR,
						"Failed to create a socketpair: %s",
						strerror(errno));
				return;
			}
		} else {
			if (pipe(pipedes) == -1) {
				wp_log(WP_ERROR, "Failed to create a pipe: %s",
						strerror(errno));
				return;
			}
		}

		/* We pass 'fd_local' to the client, although we only
		 * read and write from pipe_fd if it exists. */
		if (transf->type == FDC_PIPE_IW) {
			// Read end is 0; the other process writes
			sfd->fd_local = pipedes[1];
			sfd->pipe_fd = pipedes[0];
			sfd->type = FDC_PIPE_IR;
		} else if (transf->type == FDC_PIPE_IR) {
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
			wp_log(WP_ERROR,
					"Failed to make private pipe end nonblocking: %s",
					strerror(errno));
			return;
		}

		// Allocate a reasonably small read buffer
		sfd->pipe_recv.size = 16384;
		sfd->pipe_recv.data = calloc((size_t)sfd->pipe_recv.size, 1);
		sfd->pipe_onlyhere = false;
	} else if (sfd->type == FDC_DMABUF) {
		bool use_video = transf->special.block_meta &
				 FILE_SIZE_VIDEO_FLAG;
		sfd->buffer_size = (size_t)(transf->special.block_meta &
					    FILE_SIZE_SIZE_MASK);
		size_t diff_space = 0;
		get_max_diff_space_usage(map, sfd->buffer_size, &diff_space,
				&sfd->compress_space);
		sfd->compress_buffer = calloc(sfd->compress_space, 1);

		struct bytebuf block = transf->subtransfers[0];
		struct dmabuf_slice_data *info =
				(struct dmabuf_slice_data *)block.data;
		const char *contents = NULL;
		size_t contents_size = sfd->buffer_size;
		if (use_video) {
			int mirror_size = 0;
			pad_video_mirror_size((int)info->width,
					(int)info->height,
					(int)info->strides[0], NULL, NULL,
					&mirror_size);
			sfd->mem_mirror = calloc(
					(size_t)max((int)sfd->buffer_size,
							mirror_size),
					1);
			setup_video_decode(sfd, (int)info->width,
					(int)info->height,
					(int)info->strides[0],
					(int)info->format);

			// Apply first frame, if available
			if (block.size > sizeof(struct dmabuf_slice_data)) {
				apply_video_packet_to_mirror(sfd,
						block.size - sizeof(struct dmabuf_slice_data),
						block.data + sizeof(struct dmabuf_slice_data));
			} else {
				memset(sfd->mem_mirror, 213, sfd->buffer_size);
			}
			contents = sfd->mem_mirror;
		} else {
			sfd->mem_mirror = calloc(sfd->buffer_size, 1);
			const char *compressed_contents =
					block.data +
					sizeof(struct dmabuf_slice_data);

			size_t szcheck = 0;
			uncompress_buffer(map,
					block.size - sizeof(struct dmabuf_slice_data),
					compressed_contents, sfd->buffer_size,
					sfd->compress_buffer, &szcheck,
					&contents);

			memcpy(sfd->mem_mirror, contents, sfd->buffer_size);
		}

		wp_log(WP_DEBUG, "Creating remote DMAbuf of %d bytes",
				(int)contents_size);
		// Create mirror from first transfer
		// The file can only actually be created when we know
		// what type it is?
		if (init_render_data(render) == 1) {
			sfd->fd_local = -1;
			return;
		}

		sfd->dmabuf_bo = make_dmabuf(
				render, contents, contents_size, info);
		if (!sfd->dmabuf_bo) {
			sfd->fd_local = -1;
			return;
		}
		memcpy(&sfd->dmabuf_info, info,
				sizeof(struct dmabuf_slice_data));
		sfd->fd_local = export_dmabuf(sfd->dmabuf_bo);
	} else {
		wp_log(WP_ERROR, "Creating unknown file type updates");
	}
}

static void increase_buffer_sizes(struct fd_translation_map *map,
		struct shadow_fd *sfd, size_t new_size)
{
	size_t old_size = sfd->buffer_size;
	munmap(sfd->mem_local, old_size);
	sfd->buffer_size = new_size;
	sfd->mem_local = mmap(NULL, sfd->buffer_size, PROT_READ | PROT_WRITE,
			MAP_SHARED, sfd->fd_local, 0);
	if (!sfd->mem_local) {
		wp_log(WP_ERROR, "Mmap failed!");
		return;
	}
	// todo: handle allocation failures
	sfd->mem_mirror = realloc(sfd->mem_mirror, align(sfd->buffer_size, 8));
	/* set extension bytes to zero so that the standard diff procedure has
	 * a known state to work against */
	memset(sfd->mem_mirror + old_size, 0,
			align(sfd->buffer_size, 8) - old_size);

	size_t diff_space = 0;
	get_max_diff_space_usage(map, sfd->buffer_size, &diff_space,
			&sfd->compress_space);
	if (sfd->diff_buffer) {
		sfd->diff_buffer = realloc(sfd->diff_buffer, diff_space);
	}
	if (sfd->compress_buffer && sfd->compress_space) {
		sfd->compress_buffer =
				realloc(sfd->compress_buffer, diff_space);
	}
}

void apply_update(struct fd_translation_map *map, struct render_data *render,
		const struct transfer *transf)
{
	struct shadow_fd *sfd = get_shadow_for_rid(map, transf->obj_id);
	if (!sfd) {
		create_from_update(map, render, transf);
		return;
	}

	struct bytebuf block = transf->subtransfers[0];
	if (sfd->type == FDC_FILE) {
		if (transf->type != sfd->type) {
			wp_log(WP_ERROR, "Transfer type mismatch %d %d",
					transf->type, sfd->type);
		}
		uint32_t m_size = transf->special.block_meta &
				  FILE_SIZE_SIZE_MASK;
		if (transf->special.block_meta & FILE_SIZE_EXTEND_FLAG) {
			/* Zero-extend the buffer to have the new size */
			if (ftruncate(sfd->fd_local, m_size) == -1) {
				wp_log(WP_ERROR,
						"Failed to resize file buffer: %s",
						strerror(errno));
			}
			increase_buffer_sizes(map, sfd, m_size);

			return;
		}

		const char *act_buffer = NULL;
		size_t act_size = 0;
		uncompress_buffer(map, block.size, block.data, m_size,
				sfd->compress_buffer, &act_size, &act_buffer);

		// `memsize+8*remote_nthreads` is the worst-case diff
		// expansion
		if (act_size > sfd->buffer_size + 8 * 128) {
			wp_log(WP_ERROR, "Transfer size mismatch %ld %ld",
					act_size, sfd->buffer_size);
		}
		apply_diff(sfd->buffer_size, sfd->mem_mirror, sfd->mem_local,
				act_size, act_buffer);
	} else if (fdcat_ispipe(sfd->type)) {
		bool rw_match = sfd->type == FDC_PIPE_RW &&
				transf->type == FDC_PIPE_RW;
		bool iw_match = sfd->type == FDC_PIPE_IW &&
				transf->type == FDC_PIPE_IR;
		bool ir_match = sfd->type == FDC_PIPE_IR &&
				transf->type == FDC_PIPE_IW;
		if (!rw_match && !iw_match && !ir_match) {
			wp_log(WP_ERROR, "Transfer type contramismatch %d %d",
					transf->type, sfd->type);
		}

		ssize_t netsize = sfd->pipe_send.used + (ssize_t)block.size;
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
		memcpy(sfd->pipe_send.data + sfd->pipe_send.used, block.data,
				block.size);
		sfd->pipe_send.used += (ssize_t)block.size;

		// The pipe itself will be flushed/or closed later by
		// flush_writable_pipes
		sfd->pipe_writable = true;

		if (transf->special.pipeclose) {
			sfd->pipe_rclosed = true;
		}
	} else if (sfd->type == FDC_DMABUF) {
		if (!sfd->dmabuf_bo) {
			wp_log(WP_ERROR,
					"Applying update to nonexistent dma buffer object rid=%d",
					sfd->remote_id);
			return;
		}

		if (sfd->video_codec) {
			apply_video_packet_to_mirror(
					sfd, block.size, block.data);

			// this frame is applied via memcpy

			void *handle = NULL;
			void *data = map_dmabuf(sfd->dmabuf_bo, true, &handle);
			if (!data) {
				return;
			}
			memcpy(data, sfd->mem_mirror, sfd->buffer_size);
			if (unmap_dmabuf(sfd->dmabuf_bo, handle) == -1) {
				// there was an issue unmapping;
				// unmap_dmabuf will log error
				return;
			}

		} else {

			const char *act_buffer = NULL;
			size_t act_size = 0;
			uncompress_buffer(map, block.size, block.data,
					transf->special.block_meta,
					sfd->compress_buffer, &act_size,
					&act_buffer);

			wp_log(WP_DEBUG, "Applying dmabuf damage");
			void *handle = NULL;
			void *data = map_dmabuf(sfd->dmabuf_bo, true, &handle);
			if (!data) {
				return;
			}
			apply_diff(sfd->buffer_size, sfd->mem_mirror, data,
					act_size, act_buffer);
			if (unmap_dmabuf(sfd->dmabuf_bo, handle) == -1) {
				// there was an issue unmapping;
				// unmap_dmabuf will log error
				return;
			}
		}
	}
}

static bool destroy_shadow_if_unreferenced(
		struct fd_translation_map *map, struct shadow_fd *sfd)
{
	if (sfd->refcount_protocol == 0 && sfd->refcount_transfer == 0 &&
			sfd->has_owner) {
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
		wp_log(WP_ERROR,
				"Negative refcount for rid=%d: %d protocol references, %d transfer references",
				sfd->remote_id, sfd->refcount_protocol,
				sfd->refcount_transfer);
	}
	return false;
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
			wp_log(WP_ERROR,
					"Failed to find shadow struct for .pipe_fd=%d",
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
			wp_log(WP_DEBUG, "Flushing %ld bytes into RID=%d",
					cur->pipe_send.used, cur->remote_id);
			ssize_t changed =
					write(cur->pipe_fd, cur->pipe_send.data,
							cur->pipe_send.used);

			if (changed == -1) {
				wp_log(WP_ERROR,
						"Failed to write into pipe with remote_id=%d: %s",
						cur->remote_id,
						strerror(errno));
			} else if (changed == 0) {
				wp_log(WP_DEBUG, "Zero write event");
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
				wp_log(WP_ERROR,
						"Failed to read from pipe with remote_id=%d: %s",
						cur->remote_id,
						strerror(errno));
			} else if (changed == 0) {
				wp_log(WP_DEBUG, "Zero write event");
			} else {
				wp_log(WP_DEBUG,
						"Read %ld more bytes from RID=%d",
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
		wp_log(WP_ERROR, "Checking file size failed: %s",
				strerror(errno));
		return;
	}
	if ((size_t)st.st_size > new_size) {
		wp_log(WP_ERROR,
				"Trying to resize file larger (%d) than the actual file size (%d), ignoring",
				(int)new_size, (int)st.st_size);
		return;
	}

	size_t old_size = sfd->buffer_size;
	increase_buffer_sizes(map, sfd, new_size);

	sfd->has_been_extended = true;
	sfd->is_dirty = true;
	struct ext_interval fresh = {
			.start = (int)old_size,
			.width = (int)(new_size - old_size),
			.rep = 1,
			.stride = 0,
	};
	merge_damage_records(&sfd->damage, 1, &fresh);
}

static void *worker_thread_main(void *arg)
{
	struct thread_data *data = arg;
	struct fd_translation_map *map = data->map;

	wp_log(WP_DEBUG, "Opening worker thread %d", data->index);

	/* The loop is globally locked by default, and only unlocked in
	 * pthread_cond_wait. Yes, there are fancier and faster schemes.
	 */
	pthread_mutex_lock(&map->work_state_mutex);
	while (1) {
		if (map->task_id != data->last_task_id) {
			data->last_task_id = map->task_id;
			if (map->next_thread_task == THREADTASK_STOP) {
				break;
			}
			enum thread_task task = map->next_thread_task;
			pthread_mutex_unlock(&map->work_state_mutex);
			/* The main thread should not have modified any
			 * worker-related state since releasing its
			 * mutex */
			if (task == THREADTASK_MAKE_COMPRESSEDDIFF) {
				worker_run_compresseddiff(map, &data->comp_ctx,
						data->index, map->nthreads,
						&data->cd_dst,
						&data->cd_actual_size);
			} else if (task == THREADTASK_COMPRESSBLOCK) {
				worker_run_compressblock(map, &data->comp_ctx,
						data->index, map->nthreads,
						&data->cd_dst,
						&data->cd_actual_size);
			}
			pthread_mutex_lock(&map->work_state_mutex);

			map->nthreads_completed++;
			if (map->nthreads_completed == map->nthreads) {
				pthread_cond_signal(&map->work_done_notify);
			}
		}

		pthread_cond_wait(&map->work_needed_notify,
				&map->work_state_mutex);
	}
	pthread_mutex_unlock(&map->work_state_mutex);

	wp_log(WP_DEBUG, "Closing worker thread %d", data->index);
	return NULL;
}
