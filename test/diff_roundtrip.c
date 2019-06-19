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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int buf_ndiff(size_t size, const char *left, const char *right,
		const char *leftname, const char *rightname)
{
	if (!memcmp(left, right, size)) {
		return 0;
	}

	int nchanged = 0;
	for (size_t i = 0; i < size; i++) {
		nchanged += (left[i] != right[i]);
		if (left[i] != right[i]) {
			printf("Disagreement at i=%d, %s=%02x, %s=%02x\n",
					(int)i, leftname,
					(uint32_t)(uint8_t)left[i], rightname,
					(uint32_t)(uint8_t)right[i]);
		}
	}

	return nchanged;
}

static const struct damage damage_all = {
		.damage = DAMAGE_EVERYTHING,
		.ndamage_rects = 0,
};

static int ideal_round(
		size_t bufsize, char *base, const char *changed, char *other)
{
	char *diff = calloc(bufsize + 8, 1);
	size_t diffsize = 0;
	construct_diff(bufsize, &damage_all, 0, SIZE_MAX, base, changed,
			&diffsize, diff);
	apply_diff(bufsize, other, diffsize, diff);
	free(diff);
	int nch = 0;
	if ((nch = buf_ndiff(bufsize, changed, base, "changed", "base"))) {
		printf("Diff failed, base and changed disagree, at %d bytes\n",
				nch);
		return EXIT_FAILURE;
	}
	if ((nch = buf_ndiff(bufsize, changed, other, "changed", "other"))) {
		printf("Diff failed, other and changed disagree, at %d bytes\n",
				nch);
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

static long rand_gap_fill(char *data, int size, int max_run)
{
	max_run = max(2, max_run);
	int pos = 0;
	long nruns = 0;
	while (pos < size) {
		int gap1 = (rand() % max_run);
		gap1 = min(size - pos, gap1);
		pos += gap1;
		int gap2 = (rand() % max_run);
		gap2 = min(size - pos, gap2);
		int val = rand();
		memset(&data[pos], val, gap2);
		pos += gap2;
		nruns++;
	}
	return nruns;
}

static const int subtests[][4] = {{333333, 128, 0x11, 1000},
		{100000000, 262144, 0x21, 10}, {4, 4, 0x41, 10000},
		{65537, 177, 0x51, 1000}, {17777, 2, 0x61, 1000},
		{60005, 60005, 0x71, 1000}};

log_handler_func_t log_funcs[2] = {test_log_handler, test_log_handler};
int main(int argc, char **argv)
{
	(void)argc;
	(void)argv;

	struct damage d = {NULL, 0, 0, 0};
	damage_everything(&d);
	int nsubtests = (sizeof(subtests) / sizeof(subtests[0]));
	for (int i = 0; i < nsubtests; i++) {
		int bufsize = subtests[i][0];
		int max_gap = subtests[i][1];
		srand((uint32_t)subtests[i][2]);
		int nreps = subtests[i][3];
		size_t diffsize = 0;
		char *diff = calloc((size_t)bufsize + 32, 1);
		char *source = calloc((size_t)bufsize + 32, 1);
		char *mirror = calloc((size_t)bufsize + 32, 1);
		char *target1 = calloc((size_t)bufsize + 32, 1);
		char *target2 = calloc((size_t)bufsize + 32, 1);
		uint64_t ns01 = 0, ns12 = 0;
		long nruns = 0;
		for (int x = 0; x < subtests[i][3]; x++) {
			nruns += rand_gap_fill(source, bufsize, max_gap);

			struct timespec t0, t1, t2;
			clock_gettime(CLOCK_MONOTONIC, &t0);
			construct_diff(bufsize, &d, 0, SIZE_MAX, mirror, source,
					&diffsize, diff);
			clock_gettime(CLOCK_MONOTONIC, &t1);
			/* note: dual apply could be much faster */
			apply_diff(bufsize, target1, diffsize, diff);
			apply_diff(bufsize, target2, diffsize, diff);
			clock_gettime(CLOCK_MONOTONIC, &t2);
			ns01 += (t1.tv_sec - t0.tv_sec) * 1000000000L +
				(t1.tv_nsec - t0.tv_nsec);
			ns12 += (t2.tv_sec - t1.tv_sec) * 1000000000L +
				(t2.tv_nsec - t1.tv_nsec);
		}
		if (memcmp(target1, source, bufsize)) {
			printf("Failed to synchronize\n");
			for (int i = 0; i < bufsize; i++) {
				if (target1[i] != source[i] ||
						mirror[i] != source[i]) {
					printf("i %d: target1 %02x mirror %02x source %02x\n",
							i, (uint8_t)target1[i],
							(uint8_t)mirror[i],
							(uint8_t)source[i]);
				}
			}
		}

		double scale = 1.0 / (nreps * bufsize);
		printf("Subtest #%d: %6.3f,%6.3f,%6.3f ns/byte create,apply,net (%d/%d), %.1f bytes/run\n",
				i, ns01 * scale, ns12 * scale,
				(ns01 + ns12) * scale, (int)diffsize, bufsize,
				bufsize * nreps / (double)nruns);
		free(diff);
		free(source);
		free(mirror);
		free(target1);
		free(target2);
	}

	bool all_success = true;
	{
		size_t bufsize = 333333;

		char *changed = calloc(bufsize, 1);
		for (size_t i = 0; i < bufsize; i++) {
			changed[i] = (i * 251) % 256;
		}
		memset(changed + bufsize / 5, 0, bufsize / 7);
		memset(changed + bufsize - bufsize / 17, 0, bufsize / 17);
		char *zerobase = calloc(bufsize, 1);
		char *zeroclone = calloc(bufsize, 1);
		all_success &= ideal_round(bufsize, zerobase, changed,
					       zeroclone) == EXIT_SUCCESS;

		for (size_t i = 0; i < bufsize; i++) {
			changed[i] = (char)(i >> 8);
		}
		memset(changed + 2 * bufsize / 3, 3, bufsize / 7);

		all_success &= ideal_round(bufsize, zerobase, changed,
					       zeroclone) == EXIT_SUCCESS;
		memset(changed, 7, 1000);
		memset(changed + bufsize - 7, 8, 7);
		all_success &= ideal_round(bufsize, zerobase, changed,
					       zeroclone) == EXIT_SUCCESS;

		free(zerobase);
		free(zeroclone);
		free(changed);
	}

	return all_success ? EXIT_SUCCESS : EXIT_FAILURE;
}
