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

#include "common.h"
#include "shadow.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int64_t rand_gap_fill(char *data, size_t size, int max_run)
{
	if (max_run == -1) {
		memset(data, rand(), size);
		return 1;
	} else if (max_run == -2) {
		memset(data, 0, size);
		return 0;
	}

	max_run = max(2, max_run);
	size_t pos = 0;
	int64_t nruns = 0;
	while (pos < size) {
		int gap1 = (rand() % max_run);
		gap1 = min((int)(size - pos), gap1);
		pos += (size_t)gap1;
		int gap2 = (rand() % max_run);
		gap2 = min((int)(size - pos), gap2);
		int val = rand();
		memset(&data[pos], val, (size_t)gap2);
		pos += (size_t)gap2;
		nruns++;
	}
	return nruns;
}

struct subtest {
	size_t size;
	int max_gap;
	uint32_t seed;
	int shards;
};

static const struct subtest subtests[] = {
		{256, 128, 0x11, 3},
		{333333, 128, 0x11, 3},
		{39, 2, 0x13, 17},
		{10000000, 262144, 0x21, 1},
		{4, 4, 0x41, 1},
		{65537, 177, 0x51, 1},
		{17777, 2, 0x61, 1},
		{60005, 60005, 0x71, 1},
		{1 << 16, -1, 0x71, 4},
		{1 << 16, -2, 0x71, 4},
		{1 << 24, -1, 0x71, 4},
		{1 << 24, -2, 0x71, 4},
};

static const enum diff_type diff_types[5] = {
		DIFF_AVX512F,
		DIFF_AVX2,
		DIFF_SSE3,
		DIFF_NEON,
		DIFF_C,
};
static const char *diff_names[5] = {
		"avx512",
		"avx2  ",
		"sse3  ",
		"neon  ",
		"plainC",
};

static bool run_subtest(int i, const struct subtest test, char *diff,
		char *source, char *mirror, char *target1, char *target2,
		interval_diff_fn_t diff_fn, int alignment_bits,
		const char *diff_name)
{
	uint64_t ns01 = 0, ns12 = 0;
	int64_t nruns = 0;
	size_t net_diffsize = 0;
	srand((uint32_t)test.seed);
	memset(mirror, 0, test.size);
	memset(target1, 0, test.size);
	memset(target2, 0, test.size);

	int roughtime = (int)test.size + test.shards * 500;
	int repetitions = min(100, max(1000000000 / roughtime, 1));

	bool all_success = true;
	for (int x = 0; x < repetitions; x++) {
		nruns += rand_gap_fill(source, test.size, test.max_gap);

		net_diffsize = 0;
		for (int s = 0; s < test.shards; s++) {

			struct interval damage;
			damage.start = split_interval(
					0, (int)test.size, test.shards, s);
			damage.end = split_interval(
					0, (int)test.size, test.shards, s + 1);
			int alignment = 1 << alignment_bits;
			damage.start = alignment * (damage.start / alignment);
			damage.end = alignment * (damage.end / alignment);

			struct timespec t0, t1, t2;
			clock_gettime(CLOCK_MONOTONIC, &t0);
			size_t diffsize = 0;
			if (damage.start < damage.end) {
				diffsize = construct_diff_core(diff_fn,
						alignment_bits, &damage, 1,
						mirror, source, diff);
			}
			size_t ntrailing = 0;
			if (s == test.shards - 1) {
				ntrailing = construct_diff_trailing(test.size,
						alignment_bits, mirror, source,
						diff + diffsize);
			}
			clock_gettime(CLOCK_MONOTONIC, &t1);
			apply_diff(test.size, target1, target2, diffsize,
					ntrailing, diff);
			clock_gettime(CLOCK_MONOTONIC, &t2);
			ns01 += (uint64_t)((t1.tv_sec - t0.tv_sec) *
							   1000000000LL +
					   (t1.tv_nsec - t0.tv_nsec));
			ns12 += (uint64_t)((t2.tv_sec - t1.tv_sec) *
							   1000000000LL +
					   (t2.tv_nsec - t1.tv_nsec));
			net_diffsize += diffsize + ntrailing;
		}

		if (memcmp(target1, source, test.size)) {
			printf("Failed to synchronize\n");
			int ndiff = 0;
			for (size_t k = 0; k < test.size; k++) {
				if (target1[k] != source[k] ||
						mirror[k] != source[k]) {
					if (ndiff > 300) {
						printf("and still more differences\n");
						break;
					}
					printf("i %d: target1 %02x mirror %02x source %02x\n",
							(int)k,
							(uint8_t)target1[k],
							(uint8_t)mirror[k],
							(uint8_t)source[k]);
					ndiff++;
				}
			}
			all_success = false;
			break;
		}
	}

	double scale = 1.0 / ((double)repetitions * (double)test.size);
	printf("%s #%2d, : %6.3f,%6.3f,%6.3f ns/byte create,apply,net (%d/%d@%d), %.1f bytes/run\n",
			diff_name, i, (double)ns01 * scale,
			(double)ns12 * scale, (double)(ns01 + ns12) * scale,
			(int)net_diffsize, (int)test.size, test.shards,
			(double)repetitions * (double)test.size /
					(double)nruns);
	return all_success;
}

log_handler_func_t log_funcs[2] = {test_log_handler, test_log_handler};
int main(int argc, char **argv)
{
	(void)argc;
	(void)argv;

	bool all_success = true;

	const int nsubtests = (sizeof(subtests) / sizeof(subtests[0]));
	for (int i = 0; i < nsubtests; i++) {
		struct subtest test = subtests[i];

		/* Use maximum alignment */
		const size_t bufsize = alignz(test.size + 8 + 64, 64);
		char *diff = aligned_alloc(64, bufsize);
		char *source = aligned_alloc(64, bufsize);
		char *mirror = aligned_alloc(64, bufsize);
		char *target1 = aligned_alloc(64, bufsize);
		char *target2 = aligned_alloc(64, bufsize);
		const int ntypes = sizeof(diff_types) / sizeof(diff_types[0]);
		for (int a = 0; a < ntypes; a++) {
			int alignment_bits;
			interval_diff_fn_t diff_fn = get_diff_function(
					diff_types[a], &alignment_bits);
			if (!diff_fn) {
				continue;
			}
			all_success &= run_subtest(i, test, diff, source,
					mirror, target1, target2, diff_fn,
					alignment_bits, diff_names[a]);
		}
		free(diff);
		free(source);
		free(mirror);
		free(target1);
		free(target2);
	}

	return all_success ? EXIT_SUCCESS : EXIT_FAILURE;
}
