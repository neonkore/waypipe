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

log_handler_func_t log_funcs[2] = {test_log_handler, test_log_handler};
int main(int argc, char **argv)
{
	(void)argc;
	(void)argv;

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

	{
		int size = 1000, offset = 300, subsize = 300;
		int imgsize = size * size * sizeof(uint32_t);
		char *img_changed = calloc(size * size, sizeof(uint32_t));
		char *img_base = calloc(size * size, sizeof(uint32_t));
		char *img_cloneA = calloc(size * size, sizeof(uint32_t));
		char *img_cloneB = calloc(size * size, sizeof(uint32_t));
		char *img_diff = calloc(size * size + 2, sizeof(uint32_t));
		size_t diffsize = 0;
		struct timespec t_before, t_after;
		clock_gettime(CLOCK_MONOTONIC, &t_before);
		for (int i = 0; i < 1000; i++) {
			for (int x = offset; x < offset + subsize; x += 1) {
				for (int y = offset; y < offset + subsize;
						y += 3) {
					img_changed[sizeof(uint32_t) *
							(size_t)(size * x +
									y)] =
							i + x + y;
				}
			}
			/* A data transfer for shm requires 1x construct_diff,
			 * and 2x apply_diff */
			construct_diff(imgsize, &damage_all, 0, SIZE_MAX,
					img_base, img_changed, &diffsize,
					img_diff);
			apply_diff(imgsize, img_cloneA, diffsize, img_diff);
			apply_diff(imgsize, img_cloneB, diffsize, img_diff);
		}
		clock_gettime(CLOCK_MONOTONIC, &t_after);
		int ich = 0;
		if ((ich = buf_ndiff(imgsize, img_base, img_changed, "img_base",
				     "img_changed")) > 0) {
			printf("Timing test, end result has %d discrepancies\n",
					ich);
			all_success = false;
		}
		double elapsed = (t_after.tv_sec - t_before.tv_sec) * 1.0 +
				 (t_after.tv_nsec - t_before.tv_nsec) * 1e-9;
		printf("Timing test, took %f ms\n", elapsed * 1e3);

		free(img_base);
		free(img_diff);
		free(img_changed);
		free(img_cloneA);
		free(img_cloneB);
	}

	return all_success ? EXIT_SUCCESS : EXIT_FAILURE;
}
