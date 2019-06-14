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

static void fill_overcopy_pattern(
		int Ntotal, int margin, struct ext_interval *data)
{
	int stride = 100 + margin + 1;
	for (int i = 0; i < Ntotal; i++) {
		data[i] = (struct ext_interval){
				.start = i * stride,
				.width = 100,
				.rep = 100,
				.stride = stride,
		};
	}
}

static void fill_line_crossing_pattern(
		int Ntotal, int margin, struct ext_interval *data)
{
	int step = (margin + 2);
	int boxsize = ceildiv(Ntotal, 2) * step;
	for (int i = 0; i < Ntotal; i++) {
		if (i % 2 == 0) {
			data[i] = (struct ext_interval){
					.start = (i / 2) * step,
					.width = 1,
					.rep = boxsize,
					.stride = boxsize,
			};
		} else {
			data[i] = (struct ext_interval){
					.start = (i / 2) * boxsize,
					.width = boxsize,
					.rep = 1,
					.stride = 0,
			};
		}
	}
}

static inline int eint_low(const struct ext_interval *i) { return i->start; }
static inline int eint_high(const struct ext_interval *i)
{
	return i->start + (i->rep - 1) * i->stride + i->width;
}
/** Verify that:
 * - the new set of intervals covers the old
 * - the new set of intervals is disjoint within margin
 */
static bool check_solution_properties(int nsub, const struct ext_interval *sub,
		int nsup, const struct ext_interval *sup, int margin)
{
	int minv = INT32_MAX, maxv = INT32_MIN;
	for (int i = 0; i < nsup; i++) {
		minv = min(minv, eint_low(&sup[i]));
		maxv = max(maxv, eint_high(&sup[i]));
	}
	for (int i = 0; i < nsub; i++) {
		minv = min(minv, eint_low(&sub[i]));
		maxv = max(maxv, eint_high(&sub[i]));
	}
	if (minv > maxv) {
		return true;
	}
	minv -= margin;
	maxv += margin;
	char *test = calloc(maxv - minv, 1);
	// Fast & stupid containment test
	for (int i = 0; i < nsub; i++) {
		struct ext_interval e = sub[i];
		for (int k = 0; k < e.rep; k++) {
			memset(&test[e.start + e.stride * k - minv], 1,
					e.width);
		}
	}
	for (int i = 0; i < nsup; i++) {
		struct ext_interval e = sup[i];
		for (int k = 0; k < e.rep; k++) {
			if (memchr(&test[e.start + e.stride * k - minv -
						   margin],
					    2, e.width + 2 * margin) != NULL) {
				printf("Internal overlap failure\n");
				free(test);
				return false;
			}

			memset(&test[e.start + e.stride * k - minv], 2,
					e.width);
		}
	}
	bool yes = memchr(test, 1, maxv - minv) == NULL;
	int count = 0;
	if (!yes) {
		for (int i = 0; i < maxv - minv; i++) {
			count += test[i] == 1;
		}
		printf("Fail count: %d/%d\n", count, maxv - minv);
	}
	free(test);
	return yes;
}

void merge_core(const int old_count, struct ext_interval *old_list,
		const int new_count, const struct ext_interval *const new_list,
		int *dst_count, struct ext_interval **dst_list,
		int merge_margin);

struct pattern {
	const char *name;
	void (*func)(int Ntotal, int margin, struct ext_interval *data);
};
static const struct pattern patterns[] = {{"overcopy", fill_overcopy_pattern},
		{"line-crossing", fill_line_crossing_pattern}, {NULL, NULL}};

int main(int argc, char **argv)
{
	(void)argc;
	(void)argv;
	srand(0);

	bool all_success = true;
	// no larger, because e.g. test sizes are (margins*N)^2
	int margins[] = {2, 11, 32};
	int nvec[] = {1000, 50, 10};

	for (int z = 0; z < 3; z++) {
		for (int ip = 0; patterns[ip].name; ip++) {
			/* Pattern tests: we generate a given pattern of damage
			 * rectangles, apply the merge function, and verify that
			 * all the desired result properties hold */
			struct ext_interval *data = calloc((size_t)nvec[z],
					sizeof(struct ext_interval));

			printf("\n----  pattern=%s, margin=%d, N=%d\n",
					patterns[ip].name, nvec[z], margins[z]);

			(*patterns[ip].func)(nvec[z], margins[z], data);

			// check that minv >= 0, maxv is <= 1GB
			long minv = 0, maxv = 0;
			for (int i = 0; i < nvec[z]; i++) {
				long high = data[i].start +
					    ((long)data[i].rep) *
							    data[i].stride +
					    data[i].width;
				maxv = maxv > high ? maxv : high;
				minv = minv < data[i].start ? minv
							    : data[i].start;
			}
			if (minv < 0) {
				printf("generated interval set violates lower bound, skipping\n");
				continue;
			}
			if (maxv > 0x40000000L) {
				printf("generated interval set would use too much memory to check, skipping\n");
				continue;
			}

			int dst_count;
			struct ext_interval *dst_list = NULL;
			struct timespec t0, t1;
			clock_gettime(CLOCK_MONOTONIC, &t0);
			merge_core(0, NULL, nvec[z], data, &dst_count,
					&dst_list, margins[z]);
			clock_gettime(CLOCK_MONOTONIC, &t1);

			double elapsed = 1.0 * (t1.tv_sec - t0.tv_sec) +
					 1e-9 * (t1.tv_nsec - t0.tv_nsec);

			printf("merge operation took %f ms\n", elapsed * 1e3);

			bool pass = check_solution_properties(nvec[z], data,
					dst_count, dst_list, margins[z]);
			all_success &= pass;
			printf("new size is %d\n", dst_count);

			free(dst_list);
			free(data);
		}
	}

	return all_success ? EXIT_SUCCESS : EXIT_FAILURE;
}
