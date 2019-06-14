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

#define _XOPEN_SOURCE 700

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

#include <libavformat/avformat.h>
#include <libavutil/display.h>
#include <libavutil/hwcontext_drm.h>
#include <libavutil/imgutils.h>
#include <libavutil/opt.h>
#include <libavutil/pixdesc.h>
#include <libswscale/swscale.h>
#include <lz4.h>
#include <zstd.h>

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
		struct fd_translation_map *map, struct shadow_fd *shadow)
{
	if (shadow->type == FDC_FILE) {
		munmap(shadow->file_mem_local, shadow->file_size);
		free(shadow->mem_mirror);
		free(shadow->diff_buffer);
		free(shadow->compress_buffer);
		if (shadow->file_shm_buf_name[0]) {
			shm_unlink(shadow->file_shm_buf_name);
		}
	} else if (shadow->type == FDC_DMABUF) {
		destroy_dmabuf(shadow->dmabuf_bo);
		free(shadow->mem_mirror);
		free(shadow->diff_buffer);
		free(shadow->compress_buffer);

		sws_freeContext(shadow->video_color_context);
		av_frame_free(&shadow->video_reg_frame);
		av_frame_free(&shadow->video_yuv_frame);
		avcodec_free_context(&shadow->video_context);
		av_packet_free(&shadow->video_packet);
		free(shadow->video_buffer);

	} else if (fdcat_ispipe(shadow->type)) {
		if (shadow->pipe_fd != shadow->fd_local &&
				shadow->pipe_fd != -1 &&
				shadow->pipe_fd != -2) {
			close(shadow->pipe_fd);
		}
		free(shadow->pipe_recv.data);
		free(shadow->pipe_send.data);
	}
	if (shadow->fd_local != -2 && shadow->fd_local != -1) {
		if (close(shadow->fd_local) == -1) {
			wp_log(WP_ERROR, "Incorrect close(%d): %s",
					shadow->fd_local, strerror(errno));
		}
	}
	free(shadow);
	(void)map;
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
	}
	pthread_mutex_destroy(&map->work_state_mutex);
	pthread_cond_destroy(&map->work_done_notify);
	pthread_cond_destroy(&map->work_needed_notify);
	free(map->threads);
}
void cleanup_translation_map(struct fd_translation_map *map)
{
	struct shadow_fd *cur = map->list;
	map->list = NULL;
	while (cur) {
		struct shadow_fd *shadow = cur;
		cur = shadow->next;
		shadow->next = NULL;
		destroy_unlinked_sfd(map, shadow);
	}
	ZSTD_freeCCtx(map->zstd_ccontext);
	ZSTD_freeDCtx(map->zstd_dcontext);
	free(map->lz4_state_buffer);

	if (map->nthreads > 1) {
		cleanup_threads(map);
	}
}
static void worker_run_compresseddiff(struct fd_translation_map *map, int index)
{
	(void)map;
	(void)index;
}
static void *worker_thread_main(void *arg)
{
	struct thread_data *data = arg;
	struct fd_translation_map *map = data->map;

	wp_log(WP_DEBUG, "Opening worker thread %d", data->index);

	/* The loop is globally locked by default, and only unlocked in
	 * pthread_cond_wait. Yes, there are fancier and faster schemes. */
	pthread_mutex_lock(&map->work_state_mutex);
	while (1) {
		if (map->task_id != data->last_task_id) {
			data->last_task_id = map->task_id;
			if (map->next_thread_task == THREADTASK_STOP) {
				break;
			}
			// Do work!
			if (map->next_thread_task ==
					THREADTASK_MAKE_COMPRESSEDDIFF) {
				pthread_mutex_unlock(&map->work_state_mutex);
				// The main thread should not have modified
				// any worker-related state since updating
				// its task id
				worker_run_compresseddiff(map, data->index);
				pthread_mutex_lock(&map->work_state_mutex);
			}
			map->nthreads_completed++;
			pthread_cond_signal(&map->work_done_notify);
		}

		pthread_cond_wait(&map->work_needed_notify,
				&map->work_state_mutex);
	}
	pthread_mutex_unlock(&map->work_state_mutex);

	wp_log(WP_DEBUG, "Closing worker thread %d", data->index);
	return NULL;
}

void setup_translation_map(struct fd_translation_map *map, bool display_side,
		enum compression_mode comp)
{
	map->local_sign = display_side ? -1 : 1;
	map->list = NULL;
	map->max_local_id = 1;
	map->compression = comp;
	map->zstd_ccontext = NULL;
	map->zstd_dcontext = NULL;
	map->lz4_state_buffer = NULL;
	if (comp == COMP_LZ4) {
		map->lz4_state_buffer = calloc((size_t)LZ4_sizeofState(), 1);
	} else if (comp == COMP_ZSTD) {
		map->zstd_ccontext = ZSTD_createCCtx();
		map->zstd_dcontext = ZSTD_createDCtx();
		ZSTD_CCtx_setParameter(
				map->zstd_ccontext, ZSTD_c_compressionLevel, 5);
	}

	// platform dependent
	long nt = sysconf(_SC_NPROCESSORS_ONLN);

	map->nthreads = ceildiv((int)nt, 2);
	wp_log(WP_ERROR, "Num threads: %d", map->nthreads);

	// 1 ms wakeup for other threads, assuming mild CPU load.
	float thread_switch_delay = 0.001f; // seconds
	float scan_proc_irate = 0.5e-9f;    // seconds/byte
	float comp_proc_irate = 0.f;        // seconds/bytes
	if (comp == COMP_LZ4) {
		// 0.15 seconds on uncompressable 1e8 bytes
		comp_proc_irate = 1.5e-9f;
	} else if (comp == COMP_ZSTD) {
		// 0.5 seconds on uncompressable 1e8 bytes
		comp_proc_irate = 5e-9f;
	}
	float proc_irate = scan_proc_irate + comp_proc_irate;
	if (map->nthreads > 1) {
		map->scancomp_thread_threshold =
				(int)((thread_switch_delay * map->nthreads) /
						(proc_irate * (map->nthreads -
									      1)));

	} else {
		map->scancomp_thread_threshold = INT32_MAX;
	}
	// stop task won't be called unless the main task id is incremented
	map->next_thread_task = THREADTASK_STOP;
	map->nthreads_completed = 0;
	map->task_id = 0;
	if (map->nthreads > 1) {
		pthread_mutex_init(&map->work_state_mutex, NULL);
		pthread_cond_init(&map->work_done_notify, NULL);
		pthread_cond_init(&map->work_needed_notify, NULL);

		// The main thread has index zero, and will, since computations
		// block it anyway, share part of the workload
		map->threads = calloc(
				map->nthreads - 1, sizeof(struct thread_data));
		bool had_failures = false;
		for (int i = 0; i < map->nthreads - 1; i++) {
			// false sharing is negligible for cold data
			map->threads[i].map = map;
			map->threads[i].index = i + 1;
			map->threads[i].thread = 0;
			map->threads[i].last_task_id = 0;
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
	} else if (S_ISFIFO(fsdata.st_mode) || S_ISCHR(fsdata.st_mode)) {
		if (!S_ISFIFO(fsdata.st_mode)) {
			wp_log(WP_ERROR,
					"The fd %d, size %ld, mode %x is a character device. Proceeding under the assumption that it is pipe-like.",
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
				fd, fsdata.st_mode, fsdata.st_mode & __S_IFMT,
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
	default:
	case COMP_NONE:
		return 0;
	case COMP_LZ4:
		return (size_t)max(
				LZ4_compressBound((int)max_input), max_input);
	case COMP_ZSTD:
		return ZSTD_compressBound(max_input);
	}
}
/* With the selected compression method, compress the buffer {isize,ibuf},
 * possibly modifying {msize,mbuf}, and setting {wsize,wbuf} to indicate
 * the result */
static void compress_buffer(struct fd_translation_map *map, size_t isize,
		const char *ibuf, size_t msize, char *mbuf, size_t *wsize,
		const char **wbuf)
{
	// Ensure inputs always nontrivial
	if (isize == 0) {
		*wsize = 0;
		*wbuf = ibuf;
		return;
	}

	switch (map->compression) {
	case COMP_NONE:
		*wsize = isize;
		*wbuf = ibuf;
		return;
	case COMP_LZ4: {
		int ws = LZ4_compress_fast_extState(map->lz4_state_buffer, ibuf,
				mbuf, (int)isize, (int)msize, 1);
		if (ws == 0) {
			wp_log(WP_ERROR,
					"Lz4 compression failed for %d bytes in %d of space",
					(int)isize, (int)msize);
		}
		*wsize = (size_t)ws;
		*wbuf = mbuf;
		return;
	}
	case COMP_ZSTD: {
		size_t ws = ZSTD_compress2(
				map->zstd_ccontext, mbuf, msize, ibuf, isize);
		if (ZSTD_isError(ws)) {
			wp_log(WP_ERROR,
					"Zstd compression failed for %d bytes in %d of space: %s",
					(int)isize, (int)msize,
					ZSTD_getErrorName(ws));
		}
		*wsize = (size_t)ws;
		*wbuf = mbuf;
		return;
	}
	}
}
/* With the selected compression method, uncompress the buffer {isize,ibuf},
 * possibly modifying {msize,mbuf}, and setting {wsize,wbuf} to indicate
 * the result. msize should be set = the uncompressed buffer size, which
 * should have been provided. */
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

	switch (map->compression) {
	case COMP_NONE:
		*wsize = isize;
		*wbuf = ibuf;
		return;
	case COMP_LZ4: {
		int ws = LZ4_decompress_safe(
				ibuf, mbuf, (int)isize, (int)msize);
		if (ws < 0 || (size_t)ws != msize) {
			wp_log(WP_ERROR,
					"Lz4 decompression failed for %d bytes to %d of space, used %d",
					(int)isize, (int)msize, ws);
		}
		*wsize = (size_t)ws;
		*wbuf = mbuf;
		return;
	}
	case COMP_ZSTD: {
		size_t ws = ZSTD_decompressDCtx(
				map->zstd_dcontext, mbuf, msize, ibuf, isize);
		if (ZSTD_isError(ws) || (size_t)ws != msize) {
			wp_log(WP_ERROR,
					"Zstd decompression failed for %d bytes to %d of space: %s",
					(int)isize, (int)msize,
					ZSTD_getErrorName(ws));
		}
		*wsize = (size_t)ws;
		*wbuf = mbuf;
		return;
	}
	}
}

struct shadow_fd *translate_fd(struct fd_translation_map *map,
		struct render_data *render, int fd,
		struct dmabuf_slice_data *info)
{
	struct shadow_fd *cur = map->list;
	while (cur) {
		if (cur->fd_local == fd) {
			return cur;
		}
		cur = cur->next;
	}

	// Create a new translation map.
	struct shadow_fd *shadow = calloc(1, sizeof(struct shadow_fd));
	shadow->next = map->list;
	map->list = shadow;
	shadow->fd_local = fd;
	shadow->file_mem_local = NULL;
	shadow->mem_mirror = NULL;
	shadow->file_size = (size_t)-1;
	shadow->remote_id = (map->max_local_id++) * map->local_sign;
	shadow->type = FDC_UNKNOWN;
	// File changes must be propagated
	shadow->is_dirty = true;
	damage_everything(&shadow->damage);
	shadow->has_owner = false;
	/* Start the number of expected transfers to channel remaining at one,
	 * and number of protocol objects referencing this shadow_fd at zero.*/
	shadow->refcount_transfer = 1;
	shadow->refcount_protocol = 0;

	wp_log(WP_DEBUG, "Creating new shadow buffer for local fd %d", fd);

	size_t fsize = 0;
	shadow->type = get_fd_type(fd, &fsize);
	if (shadow->type == FDC_FILE) {
		// We have a file-like object
		shadow->file_size = fsize;
		// both r/w permissions, because the size the allocates the
		// memory does not always have to be the size that modifies it
		shadow->file_mem_local = mmap(NULL, shadow->file_size,
				PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		if (!shadow->file_mem_local) {
			wp_log(WP_ERROR, "Mmap failed!");
			return shadow;
		}
		// This will be created at the first transfer
		shadow->mem_mirror = NULL;
	} else if (fdcat_ispipe(shadow->type)) {
		// Make this end of the pipe nonblocking, so that we can include
		// it in our main loop.
		set_fnctl_flag(shadow->fd_local, O_NONBLOCK);
		shadow->pipe_fd = shadow->fd_local;

		// Allocate a reasonably small read buffer
		shadow->pipe_recv.size = 16384;
		shadow->pipe_recv.data = calloc(shadow->pipe_recv.size, 1);

		shadow->pipe_onlyhere = true;
	} else if (shadow->type == FDC_DMABUF) {
		shadow->dmabuf_size = 0;

		init_render_data(render);
		shadow->dmabuf_bo = import_dmabuf(render, shadow->fd_local,
				&shadow->dmabuf_size, info);
		if (!shadow->dmabuf_bo) {
			return shadow;
		}
		if (info) {
			memcpy(&shadow->dmabuf_info, info,
					sizeof(struct dmabuf_slice_data));
		} else {
			// already zero initialized (no information).
		}
		// to be created on first transfer
		shadow->mem_mirror = NULL;
		shadow->diff_buffer = NULL;
		shadow->type = FDC_DMABUF;

		if (info && info->using_video) {
			// Try to set up a video encoding and a video decoding
			// stream with AVCodec, although transmissions in each
			// direction are relatively independent. TODO: use
			// hardware support only if available.
			struct AVCodec *codec =
					avcodec_find_encoder(AV_CODEC_ID_H264);
			if (!codec) {
				wp_log(WP_ERROR,
						"Failed to find encoder for h264");
			}

			struct AVCodecContext *ctx =
					avcodec_alloc_context3(codec);

			struct AVPacket *pkt = av_packet_alloc();

			ctx->bit_rate = 3000000;
			// non-odd resolution ?
			ctx->width = align(info->width, 8);
			ctx->height = align(info->height, 8);
			// "time" is only meaningful in terms of the frames
			// provided
			ctx->time_base = (AVRational){1, 25};
			ctx->framerate = (AVRational){25, 1};

			/* B-frames are directly tied to latency, since each one
			 * is predicted using its preceding and following
			 * frames. The gop size is chosen by the driver. */
			ctx->gop_size = -1;
			ctx->max_b_frames = 0; // Q: how to get this to zero?
			ctx->pix_fmt = AV_PIX_FMT_YUV420P;
			// low latency
			ctx->delay = 0;
			if (av_opt_set(ctx->priv_data, "preset", "ultrafast",
					    0) != 0) {
				wp_log(WP_ERROR,
						"Failed to set x264 encode ultrafast preset");
			}
			if (av_opt_set(ctx->priv_data, "tune", "zerolatency",
					    0) != 0) {
				wp_log(WP_ERROR,
						"Failed to set x264 encode zerolatency");
			}

			bool near_perfect = false;
			if (near_perfect && av_opt_set(ctx->priv_data, "crf",
							    "0", 0) != 0) {
				wp_log(WP_ERROR, "Failed to set x264 crf");
			}

			// option: crf = 0

			if (avcodec_open2(ctx, codec, NULL) < 0) {
				wp_log(WP_ERROR, "Failed to open codec");
			}

			struct AVFrame *frame = av_frame_alloc();
			if (!frame) {
				wp_log(WP_ERROR,
						"Could not allocate video frame");
			}
			frame->format = AV_PIX_FMT_BGR0;
			frame->width = ctx->width;
			frame->height = ctx->height;
			frame->linesize[0] = info->strides[0];

			struct AVFrame *yuv_frame = av_frame_alloc();
			yuv_frame->width = ctx->width;
			yuv_frame->height = ctx->height;
			yuv_frame->format = AV_PIX_FMT_YUV420P;
			if (av_image_alloc(yuv_frame->data, yuv_frame->linesize,
					    yuv_frame->width, yuv_frame->height,
					    AV_PIX_FMT_YUV420P, 64) < 0) {
				wp_log(WP_ERROR,
						"Failed to allocate temp image");
			}

			if (sws_isSupportedInput(AV_PIX_FMT_BGR0) == 0) {
				wp_log(WP_ERROR,
						"AV_PIX_FMT_BGR0 not supported");
			}
			if (sws_isSupportedInput(AV_PIX_FMT_YUV420P) == 0) {
				wp_log(WP_ERROR,
						"AV_PIX_FMT_YUV420P not supported");
			}

			struct SwsContext *sws = sws_getContext(ctx->width,
					ctx->height, AV_PIX_FMT_BGR0,
					ctx->width, ctx->height,
					AV_PIX_FMT_YUV420P, SWS_BILINEAR, NULL,
					NULL, NULL);
			if (!sws) {
				wp_log(WP_ERROR,
						"Could not create software color conversion context");
			}

			shadow->video_codec = codec;
			shadow->video_yuv_frame = yuv_frame;
			shadow->video_reg_frame = frame;
			shadow->video_packet = pkt;
			shadow->video_context = ctx;
			shadow->video_color_context = sws;
		}
	}
	return shadow;
}

#define DIFF_WINDOW_SIZE 4

static uint64_t run_interval_diff(uint64_t blockrange_min,
		uint64_t blockrange_max,
		const uint64_t *__restrict__ changed_blocks,
		uint64_t *__restrict__ base_blocks,
		uint64_t *__restrict__ diff_blocks, uint64_t cursor)
{
	/* we paper over gaps of a given window size, to avoid fine grained
	 * context switches */
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
			/* it's possible that the last value actually; see exit
			 * block */
			clear_exit = true;
			break;
		}
		uint64_t last_header = cursor++;
		diff_blocks[last_header] = (i - 1) << 32;
		diff_blocks[cursor++] = changed_val;
		base_blocks[i - 1] = changed_val;
		// changed_val != base_val, difference occurs at early index
		uint64_t nskip = 0;
		// we could only sentinel this assuming a tiny window size
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
		/* our sentinel, at worst, causes overcopy by one. this is fine
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

/** Construct a very simple binary diff format, designed to be fast for small
 * changes in big files, and entire-file changes in essentially random files.
 * Tries not to read beyond the end of the input buffers, because they are often
 * mmap'd. Simultaneously updates the `base` buffer to match the `changed`
 * buffer.
 *
 * Requires that `diff` point to a memory buffer of size `size + 8`.
 */
void construct_diff(size_t size, const struct damage *__restrict__ damage,
		char *__restrict__ base, const char *__restrict__ changed,
		size_t *diffsize, char *__restrict__ diff)
{
	DTRACE_PROBE1(waypipe, construct_diff_enter, damage->ndamage_rects);

	uint64_t nblocks = (uint64_t)floordiv((int)size, 8);
	uint64_t *__restrict__ base_blocks = (uint64_t *)base;
	const uint64_t *__restrict__ changed_blocks = (const uint64_t *)changed;

	uint64_t *__restrict__ diff_blocks = (uint64_t *)diff;
	uint64_t ntrailing = size - 8 * nblocks;
	uint64_t cursor = 0;

	if (damage->damage == DAMAGE_EVERYTHING) {
		cursor = run_interval_diff(0, nblocks, changed_blocks,
				base_blocks, diff_blocks, cursor);
	} else {
		for (int b = 0; b < damage->ndamage_rects; b++) {
			struct ext_interval ei = damage->damage[b];
			for (int r = 0; r < ei.rep; r++) {
				uint64_t minb = (uint64_t)min(
						floordiv(ei.start + r * ei.stride,
								8),
						(int)nblocks);
				uint64_t maxb = (uint64_t)min(
						ceildiv(ei.start + r * ei.stride +
										ei.width,
								8),
						(int)nblocks);
				if (minb >= maxb) {
					continue;
				}
				cursor = run_interval_diff(minb, maxb,
						changed_blocks, base_blocks,
						diff_blocks, cursor);
			}
		}
	}

	bool tail_change = false;
	if (ntrailing > 0) {
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
void apply_diff(size_t size, char *__restrict__ base, size_t diffsize,
		const char *__restrict__ diff)
{
	uint64_t nblocks = size / 8;
	uint64_t ndiffblocks = diffsize / 8;
	uint64_t *__restrict__ base_blocks = (uint64_t *)base;
	uint64_t *__restrict__ diff_blocks = (uint64_t *)diff;
	uint64_t ntrailing = size - 8 * nblocks;
	if (diffsize % 8 != 0 && ntrailing != (diffsize - 8 * ndiffblocks)) {
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
		memcpy(base_blocks + nfrom, diff_blocks + i + 1,
				8 * (nto - nfrom));
		i += nto - nfrom + 1;
	}
	DTRACE_PROBE(waypipe, apply_diff_exit);
	if (ntrailing > 0) {
		for (uint64_t i = 0; i < ntrailing; i++) {
			base[nblocks * 8 + i] = diff[ndiffblocks * 8 + i];
		}
	}
}

void collect_update(struct fd_translation_map *map, struct shadow_fd *cur,
		int *ntransfers, struct transfer transfers[])
{
	if (cur->type == FDC_FILE) {
		if (!cur->is_dirty) {
			// File is clean, we have no reason to believe
			// that its contents could have changed
			return;
		}
		// Clear dirty state
		cur->is_dirty = false;
		if (!cur->mem_mirror) {
			reset_damage(&cur->damage);

			// increase space, to avoid overflow when
			// writing this buffer along with padding
			cur->mem_mirror = calloc(align(cur->file_size, 8), 1);
			// 8 extra bytes for worst case diff expansion
			cur->diff_buffer =
					calloc(align(cur->file_size + 8, 8), 1);
			memcpy(cur->mem_mirror, cur->file_mem_local,
					cur->file_size);
			cur->compress_space = compress_bufsize(
					map, align(cur->file_size + 8, 8));
			cur->compress_buffer = calloc(cur->compress_space, 1);

			// new transfer, we send file contents verbatim
			int nt = (*ntransfers)++;
			compress_buffer(map, cur->file_size, cur->mem_mirror,
					cur->compress_space,
					cur->compress_buffer,
					&transfers[nt].size,
					&transfers[nt].data);
			transfers[nt].type = cur->type;
			transfers[nt].obj_id = cur->remote_id;
			transfers[nt].special.file_actual_size = cur->file_size;
		}

		int intv_min, intv_max;
		get_damage_interval(&cur->damage, &intv_min, &intv_max);
		intv_min = clamp(intv_min, 0, (int)cur->file_size);
		intv_max = clamp(intv_max, 0, (int)cur->file_size);
		if (intv_min >= intv_max) {
			reset_damage(&cur->damage);
			return;
		}
		// todo: make the 'memcmp' fine grained, depending on damage
		// complexity
		bool delta = memcmp(cur->file_mem_local + intv_min,
					     (cur->mem_mirror + intv_min),
					     (size_t)(intv_max - intv_min)) !=
			     0;
		if (!delta) {
			reset_damage(&cur->damage);
			return;
		}
		if (!cur->diff_buffer) {
			/* Create diff buffer by need for remote files
			 */
			cur->diff_buffer = calloc(cur->file_size + 8, 1);
		}

		size_t diffsize;
		wp_log(WP_DEBUG, "Diff construction start");
		construct_diff(cur->file_size, &cur->damage, cur->mem_mirror,
				cur->file_mem_local, &diffsize,
				cur->diff_buffer);
		reset_damage(&cur->damage);
		wp_log(WP_DEBUG, "Diff construction end: %ld/%ld", diffsize,
				cur->file_size);
		if (diffsize > 0) {
			int nt = (*ntransfers)++;
			transfers[nt].obj_id = cur->remote_id;
			compress_buffer(map, diffsize, cur->diff_buffer,
					cur->compress_space,
					cur->compress_buffer,
					&transfers[nt].size,
					&transfers[nt].data);
			transfers[nt].type = cur->type;
			transfers[nt].special.file_actual_size = (int)diffsize;
		}
	} else if (cur->type == FDC_DMABUF) {
		// If buffer is clean, do not check for changes
		if (!cur->is_dirty) {
			return;
		}
		cur->is_dirty = false;

		bool first = false;
		if (!cur->mem_mirror && !cur->dmabuf_info.using_video) {
			cur->mem_mirror = calloc(1, cur->dmabuf_size);
			// 8 extra bytes for diff messages, or
			// alternatively for type header info
			size_t diffb_size =
					(size_t)max(sizeof(struct dmabuf_slice_data),
							8) +
					(size_t)align((int)cur->dmabuf_size, 8);
			cur->diff_buffer = calloc(diffb_size, 1);
			cur->compress_space = compress_bufsize(map, diffb_size);
			cur->compress_buffer =
					cur->compress_space
							? calloc(cur->compress_space,
									  1)
							: NULL;
			first = true;
		} else if (!cur->mem_mirror && cur->dmabuf_info.using_video) {
			// required extra tail space, 16 bytes (?)
			cur->mem_mirror = calloc(1, cur->dmabuf_size + 16);
			first = true;
		}
		void *handle = NULL;
		if (!cur->dmabuf_bo) {
			// ^ was not previously able to create buffer
			return;
		}
		void *data = map_dmabuf(cur->dmabuf_bo, false, &handle);
		if (!data) {
			return;
		}
		if (cur->dmabuf_info.using_video && cur->video_context &&
				cur->video_reg_frame && cur->video_packet) {
			memcpy(cur->mem_mirror, data, cur->dmabuf_size);
			cur->video_reg_frame->data[0] =
					(uint8_t *)cur->mem_mirror;
			for (int i = 1; i < AV_NUM_DATA_POINTERS; i++) {
				cur->video_reg_frame->data[i] = NULL;
			}

			av_frame_make_writable(cur->video_yuv_frame);
			if (sws_scale(cur->video_color_context,
					    (const uint8_t *const *)cur
							    ->video_reg_frame
							    ->data,
					    cur->video_reg_frame->linesize, 0,
					    cur->video_reg_frame->height,
					    cur->video_yuv_frame->data,
					    cur->video_yuv_frame->linesize) <
					0) {
				wp_log(WP_ERROR,
						"Failed to perform color conversion");
			}

			cur->video_yuv_frame->pts = cur->video_frameno++;
			int sendstat = avcodec_send_frame(cur->video_context,
					cur->video_yuv_frame);
			char errbuf[256];
			strcpy(errbuf, "Unknown error");
			if (sendstat < 0) {
				av_strerror(sendstat, errbuf, sizeof(errbuf));
				wp_log(WP_ERROR, "Failed to create frame: %s",
						errbuf);
				return;
			}
			// assume 1-1 frames to packets, at the moment
			int recvstat = avcodec_receive_packet(
					cur->video_context, cur->video_packet);
			if (recvstat == AVERROR(EINVAL)) {
				wp_log(WP_ERROR, "Failed to receive packet");
				return;
			} else if (recvstat == AVERROR(EAGAIN)) {
				wp_log(WP_ERROR, "Packet needs more input");
				// Clearly, the solution is to resend the
				// original frame ? but _lag_
			}
			if (recvstat == 0) {
				// we can unref the packet when? after sending?
				// on the next arrival?
				struct AVPacket *pkt = cur->video_packet;

				int nt = (*ntransfers)++;
				if (first) {
					// For the first frame, we must prepend
					// the video slice data
					free(cur->video_buffer);
					cur->video_buffer = calloc(
							pkt->buf->size +
									sizeof(struct dmabuf_slice_data),
							1);
					memcpy(cur->video_buffer,
							&cur->dmabuf_info,
							sizeof(struct dmabuf_slice_data));
					memcpy(cur->video_buffer + sizeof(struct dmabuf_slice_data),
							pkt->buf->data,
							pkt->buf->size);
					transfers[nt].data = cur->video_buffer;
					transfers[nt].size =
							pkt->size +
							sizeof(struct dmabuf_slice_data);
				} else {
					free(cur->video_buffer);
					size_t sz = pkt->buf->size;
					cur->video_buffer =
							malloc(align(sz, 8));
					memcpy(cur->video_buffer,
							pkt->buf->data, sz);
					transfers[nt].data = cur->video_buffer;
					transfers[nt].size = sz;
				}
				av_packet_unref(pkt);

				transfers[nt].type = cur->type;
				transfers[nt].obj_id = cur->remote_id;
				transfers[nt].special.file_actual_size =
						cur->dmabuf_size;
			} else if (first) {
				int nt = (*ntransfers)++;
				transfers[nt].data =
						(const char *)&cur->dmabuf_info;
				transfers[nt].size = sizeof(
						struct dmabuf_slice_data);
				transfers[nt].type = cur->type;
				// Q: use a type 'FDC_VIDEODMABUF ?' -- but
				// transport could also work for shm
				transfers[nt].obj_id = cur->remote_id;
				transfers[nt].special.file_actual_size =
						cur->dmabuf_size;
			}
			return;
		}

		if (first) {
			// Write diff with a header, and build mirror,
			// only touching data once
			memcpy(cur->mem_mirror, data, cur->dmabuf_size);

			const char *datavec = NULL;
			size_t compdata_size = 0;
			compress_buffer(map, cur->dmabuf_size, cur->mem_mirror,
					cur->compress_space -
							sizeof(struct dmabuf_slice_data),
					cur->compress_buffer +
							sizeof(struct dmabuf_slice_data),
					&compdata_size, &datavec);

			memcpy(cur->diff_buffer, &cur->dmabuf_info,
					sizeof(struct dmabuf_slice_data));
			memcpy(cur->diff_buffer + sizeof(struct dmabuf_slice_data),
					datavec, compdata_size);
			// new transfer, we send file contents verbatim

			wp_log(WP_DEBUG, "Sending initial dmabuf");
			int nt = (*ntransfers)++;
			transfers[nt].data = cur->diff_buffer;
			transfers[nt].size = sizeof(struct dmabuf_slice_data) +
					     compdata_size;
			transfers[nt].type = cur->type;
			transfers[nt].obj_id = cur->remote_id;
			transfers[nt].special.file_actual_size =
					cur->dmabuf_size;
		} else {
			// Depending on the buffer format, doing a memcpy first
			// can be significantly faster.
			// TODO: autodetect when this happens
			char *tmp = data;

			bool delta = memcmp(
					cur->mem_mirror, tmp, cur->dmabuf_size);
			if (delta) {
				if (!cur->diff_buffer) {
					// This can happen in reverse-transport
					// scenarios
					cur->diff_buffer = calloc(
							align(cur->dmabuf_size,
									8),
							1);
				}

				// TODO: damage region support!
				size_t diffsize;
				wp_log(WP_DEBUG, "Diff construction start");
				struct damage everything = {
						.damage = DAMAGE_EVERYTHING,
						.ndamage_rects = 0};
				construct_diff(cur->dmabuf_size, &everything,
						cur->mem_mirror, tmp, &diffsize,
						cur->diff_buffer);
				wp_log(WP_DEBUG,
						"Diff construction end: %ld/%ld",
						diffsize, cur->dmabuf_size);

				int nt = (*ntransfers)++;
				transfers[nt].data = cur->diff_buffer;
				compress_buffer(map, diffsize, cur->diff_buffer,
						cur->compress_space,
						cur->compress_buffer,
						&transfers[nt].size,
						&transfers[nt].data);
				transfers[nt].obj_id = cur->remote_id;
				transfers[nt].type = cur->type;
				transfers[nt].special.file_actual_size =
						diffsize;
			}
		}
		if (unmap_dmabuf(cur->dmabuf_bo, handle) == -1) {
			// there was an issue unmapping; unmap_dmabuf
			// will log error
			return;
		}
	} else if (fdcat_ispipe(cur->type)) {
		// Pipes always update, no matter what the message
		// stream indicates. Hence no cur->is_dirty flag check
		if (cur->pipe_recv.used > 0 || cur->pipe_onlyhere ||
				(cur->pipe_lclosed && !cur->pipe_rclosed)) {
			cur->pipe_onlyhere = false;
			wp_log(WP_DEBUG,
					"Adding update to pipe RID=%d, with %ld bytes, close %c",
					cur->remote_id, cur->pipe_recv.used,
					(cur->pipe_lclosed &&
							!cur->pipe_rclosed)
							? 'Y'
							: 'n');
			int nt = (*ntransfers)++;
			transfers[nt].data = cur->pipe_recv.data;
			transfers[nt].size = cur->pipe_recv.used;
			transfers[nt].type = cur->type;
			transfers[nt].obj_id = cur->remote_id;
			transfers[nt].special.pipeclose = 0;
			if (cur->pipe_lclosed && !cur->pipe_rclosed) {
				transfers[nt].special.pipeclose = 1;
				cur->pipe_rclosed = true;
				close(cur->pipe_fd);
				cur->pipe_fd = -2;
			}
			// clear
			cur->pipe_recv.used = 0;
		}
	}
}

static void apply_video_packet_to_mirror(
		struct shadow_fd *sfd, size_t size, const char *data)
{
	// We unpack directly one mem_mirror
	sfd->video_reg_frame->data[0] = (uint8_t *)sfd->mem_mirror;
	for (int i = 1; i < AV_NUM_DATA_POINTERS; i++) {
		sfd->video_reg_frame->data[i] = NULL;
	}

	// padding, requires zerod overflow for read
	sfd->video_packet->data = (uint8_t *)data;
	sfd->video_packet->size = size;

	int sendstat = avcodec_send_packet(
			sfd->video_context, sfd->video_packet);
	char errbuf[256];
	strcpy(errbuf, "Unknown error");
	if (sendstat < 0) {
		av_strerror(sendstat, errbuf, sizeof(errbuf));
		wp_log(WP_ERROR, "Failed to send packet: %s", errbuf);
	}

	while (true) {
		// Apply all produced frames
		int recvstat = avcodec_receive_frame(
				sfd->video_context, sfd->video_yuv_frame);
		if (recvstat == 0) {
			if (sws_scale(sfd->video_color_context,
					    (const uint8_t *const *)sfd
							    ->video_yuv_frame
							    ->data,
					    sfd->video_yuv_frame->linesize, 0,
					    sfd->video_yuv_frame->height,
					    sfd->video_reg_frame->data,
					    sfd->video_reg_frame->linesize) <
					0) {
				wp_log(WP_ERROR,
						"Failed to perform color conversion");
			}

		} else {
			if (recvstat != AVERROR(EAGAIN)) {
				char errbuf[256];
				strcpy(errbuf, "Unknown error");
				av_strerror(sendstat, errbuf, sizeof(errbuf));
				wp_log(WP_ERROR,
						"Failed to receive frame due to error: %s",
						errbuf);
			}
			break;
		}
		// the scale/copy operation output is
		// already onto mem_mirror
	}
}

void apply_update(struct fd_translation_map *map, struct render_data *render,
		const struct transfer *transf)
{
	struct shadow_fd *cur = get_shadow_for_rid(map, transf->obj_id);
	if (cur) {
		if (cur->type == FDC_FILE) {
			if (transf->type != cur->type) {
				wp_log(WP_ERROR, "Transfer type mismatch %d %d",
						transf->type, cur->type);
			}
			const char *act_buffer = NULL;
			size_t act_size = 0;
			uncompress_buffer(map, transf->size, transf->data,
					transf->special.file_actual_size,
					cur->compress_buffer, &act_size,
					&act_buffer);

			// `memsize+8` is the worst-case diff expansion
			if (act_size > cur->file_size + 8) {
				wp_log(WP_ERROR,
						"Transfer size mismatch %ld %ld",
						act_size, cur->file_size);
			}
			apply_diff(cur->file_size, cur->mem_mirror, act_size,
					act_buffer);
			apply_diff(cur->file_size, cur->file_mem_local,
					act_size, act_buffer);
		} else if (fdcat_ispipe(cur->type)) {
			bool rw_match = cur->type == FDC_PIPE_RW &&
					transf->type == FDC_PIPE_RW;
			bool iw_match = cur->type == FDC_PIPE_IW &&
					transf->type == FDC_PIPE_IR;
			bool ir_match = cur->type == FDC_PIPE_IR &&
					transf->type == FDC_PIPE_IW;
			if (!rw_match && !iw_match && !ir_match) {
				wp_log(WP_ERROR,
						"Transfer type contramismatch %d %d",
						transf->type, cur->type);
			}

			ssize_t netsize = cur->pipe_send.used +
					  (ssize_t)transf->size;
			if (cur->pipe_send.size <= 1024) {
				cur->pipe_send.size = 1024;
			}
			while (cur->pipe_send.size < netsize) {
				cur->pipe_send.size *= 2;
			}
			if (cur->pipe_send.data) {
				cur->pipe_send.data = realloc(
						cur->pipe_send.data,
						cur->pipe_send.size);
			} else {
				cur->pipe_send.data =
						calloc(cur->pipe_send.size, 1);
			}
			memcpy(cur->pipe_send.data + cur->pipe_send.used,
					transf->data, transf->size);
			cur->pipe_send.used += (ssize_t)transf->size;

			// The pipe itself will be flushed/or closed later by
			// flush_writable_pipes
			cur->pipe_writable = true;

			if (transf->special.pipeclose) {
				cur->pipe_rclosed = true;
			}
		} else if (cur->type == FDC_DMABUF) {
			if (!cur->dmabuf_bo) {
				wp_log(WP_ERROR,
						"Applying update to nonexistent dma buffer object rid=%d",
						cur->remote_id);
				return;
			}

			if (cur->dmabuf_info.using_video) {
				apply_video_packet_to_mirror(cur, transf->size,
						transf->data);

				// this frame is applied via memcpy

				void *handle = NULL;
				void *data = map_dmabuf(
						cur->dmabuf_bo, true, &handle);
				if (!data) {
					return;
				}
				memcpy(data, cur->mem_mirror, cur->dmabuf_size);
				if (unmap_dmabuf(cur->dmabuf_bo, handle) ==
						-1) {
					// there was an issue unmapping;
					// unmap_dmabuf will log error
					return;
				}

			} else {

				const char *act_buffer = NULL;
				size_t act_size = 0;
				uncompress_buffer(map, transf->size,
						transf->data,
						transf->special.file_actual_size,
						cur->compress_buffer, &act_size,
						&act_buffer);

				wp_log(WP_DEBUG, "Applying dmabuf damage");
				apply_diff(cur->dmabuf_size, cur->mem_mirror,
						act_size, act_buffer);
				void *handle = NULL;
				void *data = map_dmabuf(
						cur->dmabuf_bo, true, &handle);
				if (!data) {
					return;
				}
				apply_diff(cur->dmabuf_size, data, act_size,
						act_buffer);
				if (unmap_dmabuf(cur->dmabuf_bo, handle) ==
						-1) {
					// there was an issue unmapping;
					// unmap_dmabuf will log error
					return;
				}
			}
		}
		return;
	}

	wp_log(WP_DEBUG, "Introducing new fd, remoteid=%d", transf->obj_id);
	struct shadow_fd *shadow = calloc(1, sizeof(struct shadow_fd));
	shadow->next = map->list;
	map->list = shadow;
	shadow->remote_id = transf->obj_id;
	shadow->fd_local = -1;
	shadow->type = transf->type;
	shadow->is_dirty = false;
	reset_damage(&shadow->damage);
	/* Start the object reference at one, so that, if it is owned by
	 * some known protocol object, it can not be deleted until the fd
	 * has at least be transferred over the Wayland connection */
	shadow->refcount_transfer = 1;
	shadow->refcount_protocol = 0;
	if (shadow->type == FDC_FILE) {
		shadow->file_mem_local = NULL;
		shadow->file_size = transf->special.file_actual_size;
		shadow->mem_mirror = calloc(
				(size_t)align((int)shadow->file_size, 8), 1);

		shadow->compress_space = compress_bufsize(
				map, align((int)shadow->file_size, 8) + 8);
		shadow->compress_buffer =
				shadow->compress_space
						? calloc(shadow->compress_space,
								  1)
						: NULL;

		size_t act_size = 0;
		const char *act_buffer = NULL;
		uncompress_buffer(map, transf->size, transf->data,
				shadow->file_size, shadow->compress_buffer,
				&act_size, &act_buffer);

		// The first time only, the transfer data is a direct copy of
		// the source
		memcpy(shadow->mem_mirror, act_buffer, act_size);
		// The PID should be unique during the lifetime of the program
		sprintf(shadow->file_shm_buf_name, "/waypipe%d-data_%d",
				getpid(), shadow->remote_id);

		shadow->fd_local = shm_open(shadow->file_shm_buf_name,
				O_RDWR | O_CREAT | O_TRUNC, 0644);
		if (shadow->fd_local == -1) {
			wp_log(WP_ERROR,
					"Failed to create shm file for object %d: %s",
					shadow->remote_id, strerror(errno));
			return;
		}
		if (ftruncate(shadow->fd_local, shadow->file_size) == -1) {
			wp_log(WP_ERROR,
					"Failed to resize shm file %s to size %ld for reason: %s",
					shadow->file_shm_buf_name,
					shadow->file_size, strerror(errno));
			return;
		}
		shadow->file_mem_local = mmap(NULL, shadow->file_size,
				PROT_READ | PROT_WRITE, MAP_SHARED,
				shadow->fd_local, 0);
		memcpy(shadow->file_mem_local, shadow->mem_mirror,
				shadow->file_size);
	} else if (fdcat_ispipe(shadow->type)) {
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

		/* We pass 'fd_local' to the client, although we only read and
		 * write from pipe_fd if it exists. */
		if (transf->type == FDC_PIPE_IW) {
			// Read end is 0; the other process writes
			shadow->fd_local = pipedes[1];
			shadow->pipe_fd = pipedes[0];
			shadow->type = FDC_PIPE_IR;
		} else if (transf->type == FDC_PIPE_IR) {
			// Write end is 1; the other process reads
			shadow->fd_local = pipedes[0];
			shadow->pipe_fd = pipedes[1];
			shadow->type = FDC_PIPE_IW;
		} else { // FDC_PIPE_RW
			// Here, it doesn't matter which end is which
			shadow->fd_local = pipedes[0];
			shadow->pipe_fd = pipedes[1];
			shadow->type = FDC_PIPE_RW;
		}

		if (set_fnctl_flag(shadow->pipe_fd, O_NONBLOCK) == -1) {
			wp_log(WP_ERROR,
					"Failed to make private pipe end nonblocking: %s",
					strerror(errno));
			return;
		}

		// Allocate a reasonably small read buffer
		shadow->pipe_recv.size = 16384;
		shadow->pipe_recv.data = calloc(shadow->pipe_recv.size, 1);
		shadow->pipe_onlyhere = false;
	} else if (shadow->type == FDC_DMABUF) {
		shadow->dmabuf_size = transf->special.file_actual_size;
		shadow->compress_space =
				compress_bufsize(map, shadow->dmabuf_size);
		shadow->compress_buffer = calloc(shadow->compress_space, 1);
		shadow->mem_mirror = calloc(shadow->dmabuf_size, 1);

		struct dmabuf_slice_data *info =
				(struct dmabuf_slice_data *)transf->data;
		const char *contents = NULL;
		size_t contents_size = shadow->dmabuf_size;
		if (info->using_video) {
			struct AVCodec *codec =
					avcodec_find_decoder(AV_CODEC_ID_H264);
			if (!codec) {
				wp_log(WP_ERROR,
						"Failed to find decoder for h264");
			}

			struct AVCodecContext *ctx =
					avcodec_alloc_context3(codec);

			struct AVPacket *pkt = av_packet_alloc();
			// non-odd resolution ?
			ctx->width = align(info->width, 8);
			ctx->height = align(info->height, 8);
			ctx->pix_fmt = AV_PIX_FMT_YUV420P;
			ctx->delay = 0;
			if (avcodec_open2(ctx, codec, NULL) < 0) {
				wp_log(WP_ERROR, "Failed to open codec");
			}

			struct AVFrame *frame = av_frame_alloc();
			if (!frame) {
				wp_log(WP_ERROR,
						"Could not allocate video frame");
			}
			frame->format = AV_PIX_FMT_BGR0;
			frame->width = ctx->width;
			frame->height = ctx->height;
			frame->linesize[0] = info->strides[0];

			if (sws_isSupportedInput(AV_PIX_FMT_BGR0) == 0) {
				wp_log(WP_ERROR,
						"AV_PIX_FMT_BGR0 not supported");
			}
			if (sws_isSupportedInput(AV_PIX_FMT_YUV420P) == 0) {
				wp_log(WP_ERROR,
						"AV_PIX_FMT_YUV420P not supported");
			}

			struct SwsContext *sws = sws_getContext(ctx->width,
					ctx->height, AV_PIX_FMT_YUV420P,
					ctx->width, ctx->height,
					AV_PIX_FMT_BGR0, SWS_BILINEAR, NULL,
					NULL, NULL);
			if (!sws) {
				wp_log(WP_ERROR,
						"Could not create software color conversion context");
			}

			struct AVFrame *yuv_frame = av_frame_alloc();
			yuv_frame->width = ctx->width;
			yuv_frame->height = ctx->height;
			yuv_frame->format = AV_PIX_FMT_YUV420P;

			shadow->video_codec = codec;
			shadow->video_reg_frame = frame;
			shadow->video_yuv_frame = yuv_frame;
			shadow->video_packet = pkt;
			shadow->video_context = ctx;
			shadow->video_color_context = sws;

			// Apply first frame, if available
			if (transf->size > sizeof(struct dmabuf_slice_data)) {
				apply_video_packet_to_mirror(shadow,
						transf->size - sizeof(struct dmabuf_slice_data),
						transf->data + sizeof(struct dmabuf_slice_data));
			} else {
				memset(shadow->mem_mirror, 213,
						shadow->dmabuf_size);
			}
			contents = shadow->mem_mirror;

		} else {
			const char *compressed_contents =
					transf->data +
					sizeof(struct dmabuf_slice_data);

			size_t szcheck = 0;
			uncompress_buffer(map,
					transf->size - sizeof(struct dmabuf_slice_data),
					compressed_contents,
					shadow->dmabuf_size,
					shadow->compress_buffer, &szcheck,
					&contents);

			memcpy(shadow->mem_mirror, contents,
					shadow->dmabuf_size);
		}

		wp_log(WP_DEBUG, "Creating remote DMAbuf of %d bytes",
				(int)contents_size);
		// Create mirror from first transfer
		// The file can only actually be created when we know what type
		// it is?
		if (init_render_data(render) == 1) {
			shadow->fd_local = -1;
			return;
		}

		shadow->dmabuf_bo = make_dmabuf(
				render, contents, contents_size, info);
		if (!shadow->dmabuf_bo) {
			shadow->fd_local = -1;
			return;
		}
		memcpy(&shadow->dmabuf_info, info,
				sizeof(struct dmabuf_slice_data));
		shadow->fd_local = export_dmabuf(shadow->dmabuf_bo);
	} else {
		wp_log(WP_ERROR, "Creating unknown file type updates");
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
