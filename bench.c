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

#if !defined(__DragonFly__) && !defined(__FreeBSD__) && !defined(__OpenBSD__)
/* aligned_alloc isn't part of any X/Open version */
#define _XOPEN_SOURCE 700
#endif
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

#define MAX_ALIGNMENT 64

static void *create_text_like_image(size_t size)
{
	uint8_t *data = aligned_alloc(
			MAX_ALIGNMENT, alignu(size, MAX_ALIGNMENT));
	int step = 0;
	for (size_t i = 0; i < size; i++) {
		step = i / 203 - i / 501;
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
	uint8_t *data = aligned_alloc(
			MAX_ALIGNMENT, alignu(size, MAX_ALIGNMENT));
	for (size_t i = 0; i < size; i++) {
		/* primary sequence, with runs, but avoiding obvious repetition
		 */
		data[i] = (uint8_t)(i + i / 101 + i / 33);
		/* fine grain, a main source of complexity in real images*/
		data[i] += rand() % 2;
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
		size_t low = rand() % size;
		size_t high = rand() % size;
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

#define NSAMPLES 5

int run_bench(float bandwidth_mBps, int n_worker_threads)
{
	/* 4MB test image - 1024x1024x4. Any smaller, and unrealistic caching
	 * speedups may occur */
	struct timespec tp;
	clock_gettime(CLOCK_REALTIME, &tp);

	srand((unsigned int)tp.tv_nsec);
	size_t test_size = (1u << 22) + 13;
	size_t alloc_size = alignu(test_size, MAX_ALIGNMENT);
	void *text_image = create_text_like_image(test_size);
	void *vid_image = create_video_like_image(test_size);

	/* Q: store an array of all the modes -> outputs */
	// Then sort that array
	size_t ntests = 0;
	for (size_t c = 0; c < sizeof(comp_ranges) / sizeof(comp_ranges[0]);
			c++) {
		ntests += comp_ranges[c].max_val - comp_ranges[c].min_val + 1;
	}

	void *base = aligned_alloc(MAX_ALIGNMENT, alloc_size);
	void *mod = aligned_alloc(MAX_ALIGNMENT, alloc_size);
	size_t max_diff_size = alignu(alloc_size + 8, MAX_ALIGNMENT);
	void *diff = aligned_alloc(MAX_ALIGNMENT, max_diff_size);

	/* For the content, the mode is generally consistent */

	struct bench_result *tresults =
			calloc(ntests, sizeof(struct bench_result));
	struct bench_result *iresults =
			calloc(ntests, sizeof(struct bench_result));
	int ntres = 0;
	int nires = 0;
	for (int k = 0; k < 2; k++) {
		bool text_like = k == 0;
		struct bench_result *results = text_like ? tresults : iresults;
		int *nresults = text_like ? &ntres : &nires;
		int j = 0;
		for (size_t c = 0;
				!shutdown_flag &&
				c < sizeof(comp_ranges) / sizeof(comp_ranges[0]);
				c++) {
			for (int lvl = comp_ranges[c].min_val;
					!shutdown_flag &&
					lvl <= comp_ranges[c].max_val;
					lvl++) {

				/* Reset seed, so that all random image
				 * perturbations are consistent between runs */
				srand((unsigned int)tp.tv_nsec);

				struct thread_pool pool;
				setup_thread_pool(&pool, comp_ranges[c].mode,
						lvl, n_worker_threads);
				if (j == 0) {

					printf("Running compression level benchmarks, assuming bandwidth=%g MB/s, %d hardware threads\n",
							bandwidth_mBps,
							pool.nthreads);
				}

				size_t comp_size = compress_bufsize(
						&pool, max_diff_size);
				void *comp = malloc(comp_size);

				int alignment;
				interval_diff_fn_t diff_fn =
						get_fastest_diff_function(
								DIFF_FASTEST,
								&alignment);

				struct interval damage;
				damage.start = 0;
				damage.end = test_size - test_size % alignment;

				int iter = 0;
				float samples[NSAMPLES];
				float diff_frac[NSAMPLES], comp_frac[NSAMPLES];
				for (; !shutdown_flag && iter < NSAMPLES;
						iter++) {
					memcpy(base,
							text_like ? text_image
								  : vid_image,
							test_size);
					memcpy(mod,
							text_like ? text_image
								  : vid_image,
							test_size);
					perturb(mod, test_size);

					struct timespec t0, t2;
					clock_gettime(CLOCK_MONOTONIC, &t0);
					int diffsize = 0;
					if (damage.start < damage.end) {
						diffsize = construct_diff_core(
								diff_fn,
								&damage, 1,
								base, mod,
								diff);
					}
					int ntrailing = ntrailing = construct_diff_trailing(
							test_size, alignment,
							base, mod,
							(char *)diff + diffsize);
					struct bytebuf dst;
					compress_buffer(&pool,
							&pool.threads[0].comp_ctx,
							diffsize + ntrailing,
							diff, comp_size, comp,
							&dst);
					clock_gettime(CLOCK_MONOTONIC, &t2);

					float packet_size = (float)dst.size;
					float diffcomp_time =
							1.0f * (t2.tv_sec - t0.tv_sec) +
							1e-9f * (t2.tv_nsec - t0.tv_nsec);
					float transfer_time =
							packet_size /
							(bandwidth_mBps * 1e6f);

					int nthreads = pool.nthreads;
					double net_time =
							transfer_time +
							diffcomp_time / nthreads;

					samples[iter] = net_time;
					diff_frac[iter] =
							(diffsize + ntrailing) /
							(float)test_size;
					comp_frac[iter] =
							packet_size /
							(diffsize + ntrailing);
				}
				qsort(samples, (size_t)iter, sizeof(float),
						float_compare);
				qsort(diff_frac, (size_t)iter, sizeof(float),
						float_compare);
				qsort(comp_frac, (size_t)iter, sizeof(float),
						float_compare);
				/* Using order statistics, because moment
				 * statistics a) require libm; b) don't work
				 * well with outliers.  */
				float median = samples[iter / 2];
				float hiqr = (samples[(iter * 3) / 4] -
							     samples[iter / 4]) /
					     2;
				float dmedian = diff_frac[iter / 2];
				float dhiqr = (diff_frac[(iter * 3) / 4] -
							      diff_frac[iter /
									      4]) /
					      2;
				float cmedian = comp_frac[iter / 2];
				float chiqr = (comp_frac[(iter * 3) / 4] -
							      comp_frac[iter /
									      4]) /
					      2;

				free(comp);
				cleanup_thread_pool(&pool);

				struct bench_result res;
				res.rng = &comp_ranges[c];
				res.level = lvl;
				printf("%s, %s=%d: transfer %f+/-%f sec, diff %f+/-%f, comp %f+/-%f\n",
						text_like ? "txt" : "img",
						comp_ranges[c].desc, lvl,
						median, hiqr, dmedian, dhiqr,
						cmedian, chiqr);

				res.comp_time = median;
				res.dcomp_time = hiqr;

				results[j++] = res;
				(*nresults)++;
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
		qsort(results, nr, sizeof(struct bench_result),
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

	free(mod);
	free(base);
	free(diff);
	free(vid_image);
	free(text_image);
	return EXIT_SUCCESS;
}
