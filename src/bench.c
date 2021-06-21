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
#include "util.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

struct compression_range {
	enum compression_mode mode;
	int min_val;
	int max_val;
	const char *desc;
};

static const struct compression_range comp_ranges[] = {
		{COMP_NONE, 0, 0, "none"},
#ifdef HAS_LZ4
		{COMP_LZ4, -10, 16, "lz4"},
#endif
#ifdef HAS_ZSTD
		{COMP_ZSTD, -10, 22, "zstd"},
#endif
};

static void *create_text_like_image(size_t size)
{
	uint8_t *data = malloc(size);
	if (!data) {
		return NULL;
	}
	for (size_t i = 0; i < size; i++) {
		size_t step = i / 203 - i / 501;
		bool s = step % 2 == 0;
		data[i] = (uint8_t)(s ? ((step >> 1) & 0x2) + 0xfe : 0x00);
	}
	//	int f = open("1.rgb", O_RDONLY);
	//	read(f, data, size);
	//	close(f);
	return data;
}
static void *create_video_like_image(size_t size)
{
	uint8_t *data = malloc(size);
	if (!data) {
		return NULL;
	}
	for (size_t i = 0; i < size; i++) {
		/* primary sequence, with runs, but avoiding obvious repetition
		 * then add fine grain, a main source of complexity in real
		 * images
		 */
		uint32_t noise = (uint32_t)rand() % 2;
		data[i] = (uint8_t)(i + i / 101 + i / 33 + noise);
	}
	//	int f = open("0.rgb", O_RDONLY);
	//	read(f, data, size);
	//	close(f);
	return data;
}
/** Create a shuffled variation of the original image. */
static void perturb(void *data, size_t size)
{
	uint8_t *bytes = (uint8_t *)data;
	for (int i = 0; i < 50; i++) {
		// TODO: avoid redundant motion, and make this very fast
		size_t low = (size_t)rand() % size;
		size_t high = (size_t)rand() % size;
		if (low >= high) {
			continue;
		}
		for (size_t k = 0; k < (high - low) / 2; k++) {
			uint8_t tmp = bytes[low + k];
			bytes[low + k] = bytes[high - k];
			bytes[high - k] = tmp;
		}
	}
}

struct bench_result {
	const struct compression_range *rng;
	int level;
	float comp_time, dcomp_time;
};

static int float_compare(const void *a, const void *b)
{
	float va = *(const float *)a;
	float vb = *(const float *)b;
	if (va < vb)
		return -1;
	if (va > vb)
		return 1;
	return 0;
}
static int compare_bench_result(const void *a, const void *b)
{

	const struct bench_result *va = (const struct bench_result *)a;
	const struct bench_result *vb = (const struct bench_result *)b;
	if (va->comp_time < vb->comp_time)
		return -1;
	if (va->comp_time > vb->comp_time)
		return 1;
	return 0;
}

struct diff_comp_results {
	/* Compressed packet size, in bytes */
	float packet_size;
	/* Time to construct compressed diff, in seconds */
	float diffcomp_time;
	/* Diff size / buffer size */
	float diff_frac;
	/* Compressed size / original size */
	float comp_frac;
};

static int compare_timespec(const struct timespec *a, const struct timespec *b)
{
	if (a->tv_sec != b->tv_sec)
		return a->tv_sec < b->tv_sec ? -1 : 1;
	if (a->tv_nsec != b->tv_nsec)
		return a->tv_nsec < b->tv_nsec ? -1 : 1;
	return 0;
}

/* requires delta >= 0 */
static struct timespec timespec_add(struct timespec base, int64_t delta_ns)
{
	struct timespec ret;
	ret.tv_sec = base.tv_sec + delta_ns / 1000000000LL;
	ret.tv_nsec = base.tv_nsec + delta_ns % 1000000000LL;
	if (ret.tv_nsec > 1000000000LL) {
		ret.tv_nsec -= 1000000000LL;
		ret.tv_sec++;
	}
	return ret;
}

static int64_t timespec_sub(struct timespec a, struct timespec b)
{
	return (a.tv_sec - b.tv_sec) * 1000000000LL + (a.tv_nsec - b.tv_nsec);
}

#define NSAMPLES 5

static struct bench_result run_sub_bench(bool first,
		const struct compression_range *rng, int level,
		float bandwidth_mBps, int n_worker_threads, unsigned int seed,
		bool text_like, size_t test_size, void *image)
{
	/* Reset seed, so that all random image
	 * perturbations are consistent between runs */
	srand(seed);

	/* Setup a shadow structure */
	struct thread_pool pool;
	setup_thread_pool(&pool, rng->mode, level, n_worker_threads);
	if (first) {
		printf("Running compression level benchmarks, assuming bandwidth=%g MB/s, with %d threads\n",
				bandwidth_mBps, pool.nthreads);
	}

	struct fd_translation_map map;
	setup_translation_map(&map, false);

	struct wmsg_open_file file_msg;
	file_msg.remote_id = 0;
	file_msg.file_size = (uint32_t)test_size;
	file_msg.size_and_type = transfer_header(
			sizeof(struct wmsg_open_file), WMSG_OPEN_FILE);

	struct render_data render;
	memset(&render, 0, sizeof(render));
	render.disabled = true;
	render.drm_fd = 1;
	render.av_disabled = true;

	struct bytebuf msg = {.size = sizeof(struct wmsg_open_file),
			.data = (char *)&file_msg};
	(void)apply_update(&map, &pool, &render, WMSG_OPEN_FILE, 0, &msg);
	struct shadow_fd *sfd = get_shadow_for_rid(&map, 0);

	int iter = 0;
	float samples[NSAMPLES];
	float diff_frac[NSAMPLES], comp_frac[NSAMPLES];
	for (; !shutdown_flag && iter < NSAMPLES; iter++) {

		/* Reset image state */
		memcpy(sfd->mem_local, image, test_size);
		memcpy(sfd->mem_mirror, image, test_size);
		perturb(sfd->mem_local, test_size);
		sfd->is_dirty = true;
		damage_everything(&sfd->damage);

		/* Create transfer queue */
		struct transfer_queue transfer_data;
		memset(&transfer_data, 0, sizeof(struct transfer_queue));
		pthread_mutex_init(&transfer_data.async_recv_queue.lock, NULL);

		struct timespec t0, t1;
		clock_gettime(CLOCK_REALTIME, &t0);
		collect_update(&pool, sfd, &transfer_data, false);
		start_parallel_work(&pool, &transfer_data.async_recv_queue);

		/* A restricted main loop, in which transfer blocks are
		 * instantaneously consumed when previous blocks have been
		 * 'sent' */
		struct timespec next_write_time = {.tv_sec = 0, .tv_nsec = 0};
		size_t total_wire_size = 0;
		size_t net_diff_size = 0;
		while (1) {
			uint8_t flush[64];
			(void)read(pool.selfpipe_r, flush, sizeof(flush));

			/* Run tasks on main thread, just like the main loop */
			bool done = false;
			struct task_data task;
			bool has_task = request_work_task(&pool, &task, &done);
			if (has_task) {
				run_task(&task, &pool.threads[0]);

				pthread_mutex_lock(&pool.work_mutex);
				pool.tasks_in_progress--;
				pthread_mutex_unlock(&pool.work_mutex);
			}

			struct timespec cur_time;
			clock_gettime(CLOCK_REALTIME, &cur_time);
			if (compare_timespec(&next_write_time, &cur_time) < 0) {
				transfer_load_async(&transfer_data);
				if (transfer_data.start < transfer_data.end) {
					struct iovec v =
							transfer_data.vecs
									[transfer_data.start++];
					float delay_s = (float)v.iov_len /
							(bandwidth_mBps * 1e6f);
					total_wire_size += v.iov_len;
					/* Only one message type will be
					 * produced for diffs */
					struct wmsg_buffer_diff *header =
							v.iov_base;
					net_diff_size += (size_t)(header->diff_size +
								  header->ntrailing);

					/* Advance timer for next receipt */
					int64_t delay_ns = (int64_t)(delay_s *
								     1e9f);
					next_write_time = timespec_add(
							cur_time, delay_ns);
				}
			} else {
				/* Very short delay, for poll loop */
				bool tasks_remaining = false;
				pthread_mutex_lock(&pool.work_mutex);
				tasks_remaining = pool.stack_count > 0;
				pthread_mutex_unlock(&pool.work_mutex);

				struct timespec delay_time;
				delay_time.tv_sec = 0;
				delay_time.tv_nsec = 10000;
				if (!tasks_remaining) {
					int64_t nsecs_left = timespec_sub(
							next_write_time,
							cur_time);
					if (nsecs_left > 1000000000LL) {
						nsecs_left = 1000000000LL;
					}
					if (nsecs_left > delay_time.tv_nsec) {
						delay_time.tv_nsec = nsecs_left;
					}
				}
				nanosleep(&delay_time, NULL);
			}
			bool all_sent = false;
			all_sent = transfer_data.start == transfer_data.end;

			if (done && all_sent) {
				break;
			}
		}

		finish_update(sfd);
		cleanup_transfer_queue(&transfer_data);
		clock_gettime(CLOCK_REALTIME, &t1);

		struct diff_comp_results r;
		r.packet_size = (float)total_wire_size;
		r.diffcomp_time = 1.0f * (float)(t1.tv_sec - t0.tv_sec) +
				  1e-9f * (float)(t1.tv_nsec - t0.tv_nsec);
		r.comp_frac = r.packet_size / (float)net_diff_size;
		r.diff_frac = (float)net_diff_size / (float)test_size;

		samples[iter] = r.diffcomp_time;
		diff_frac[iter] = r.diff_frac;
		comp_frac[iter] = r.comp_frac;
	}

	/* Cleanup sfd and helper structures */
	cleanup_thread_pool(&pool);
	cleanup_translation_map(&map);

	qsort(samples, (size_t)iter, sizeof(float), float_compare);
	qsort(diff_frac, (size_t)iter, sizeof(float), float_compare);
	qsort(comp_frac, (size_t)iter, sizeof(float), float_compare);
	/* Using order statistics, because moment statistics a) require
	 * libm; b) don't work well with outliers. */
	float median = samples[iter / 2];
	float hiqr = (samples[(iter * 3) / 4] - samples[iter / 4]) / 2;
	float dmedian = diff_frac[iter / 2];
	float dhiqr = (diff_frac[(iter * 3) / 4] - diff_frac[iter / 4]) / 2;
	float cmedian = comp_frac[iter / 2];
	float chiqr = (comp_frac[(iter * 3) / 4] - comp_frac[iter / 4]) / 2;

	struct bench_result res;
	res.rng = rng;
	res.level = level;
	printf("%s, %s=%d: transfer %f+/-%f sec, diff %f+/-%f, comp %f+/-%f\n",
			text_like ? "txt" : "img", rng->desc, level, median,
			hiqr, dmedian, dhiqr, cmedian, chiqr);

	res.comp_time = median;
	res.dcomp_time = hiqr;
	return res;
}

int run_bench(float bandwidth_mBps, uint32_t test_size, int n_worker_threads)
{
	/* 4MB test image - 1024x1024x4. Any smaller, and unrealistic caching
	 * speedups may occur */
	struct timespec tp;
	clock_gettime(CLOCK_REALTIME, &tp);

	srand((unsigned int)tp.tv_nsec);
	void *text_image = create_text_like_image(test_size);
	void *vid_image = create_video_like_image(test_size);
	if (!text_image || !vid_image) {
		free(text_image);
		free(vid_image);
		wp_error("Failed to allocate test images");
		return EXIT_FAILURE;
	}

	/* Q: store an array of all the modes -> outputs */
	// Then sort that array
	int ntests = 0;
	for (size_t c = 0; c < sizeof(comp_ranges) / sizeof(comp_ranges[0]);
			c++) {
		ntests += comp_ranges[c].max_val - comp_ranges[c].min_val + 1;
	}

	/* For the content, the mode is generally consistent */

	struct bench_result *tresults =
			calloc((size_t)ntests, sizeof(struct bench_result));
	struct bench_result *iresults =
			calloc((size_t)ntests, sizeof(struct bench_result));
	int ntres = 0, nires = 0;
	for (int k = 0; k < 2; k++) {
		bool text_like = k == 0;
		int j = 0;
		for (size_t c = 0;
				!shutdown_flag &&
				c < sizeof(comp_ranges) / sizeof(comp_ranges[0]);
				c++) {
			for (int lvl = comp_ranges[c].min_val;
					!shutdown_flag &&
					lvl <= comp_ranges[c].max_val;
					lvl++) {

				struct bench_result res = run_sub_bench(j == 0,
						&comp_ranges[c], lvl,
						bandwidth_mBps,
						n_worker_threads,
						(unsigned int)tp.tv_nsec,
						text_like, test_size,
						text_like ? text_image
							  : vid_image);
				if (text_like) {
					tresults[j++] = res;
					ntres++;
				} else {
					iresults[j++] = res;
					nires++;
				}
			}
		}
	}
	for (int k = 0; k < 2; k++) {
		bool text_like = k == 0;
		struct bench_result *results = text_like ? tresults : iresults;
		int nr = text_like ? ntres : nires;
		if (nr <= 0) {
			continue;
		}

		/* Print best recommendation */
		qsort(results, (size_t)nr, sizeof(struct bench_result),
				compare_bench_result);

		struct bench_result best = results[0];
		printf("%s, best compression level: \"%s=%d\", with %f+/-%f sec for sample transfer\n",
				text_like ? "Text heavy image"
					  : "Photo-like image",
				best.rng->desc, best.level, best.comp_time,
				best.dcomp_time);
	}
	free(tresults);
	free(iresults);

	free(vid_image);
	free(text_image);
	return EXIT_SUCCESS;
}
