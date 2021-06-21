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

static void fill_overcopy_pattern(
		int Ntotal, int margin, struct ext_interval *data)
{
	int stride = 100 + margin + 1;
	for (int i = 0; i < Ntotal; i++) {
		data[i] = (struct ext_interval){
				.start = (i) % (Ntotal / 2) * stride,
				.width = 100 - (i > Ntotal / 2),
				.rep = 100,
				.stride = stride,
		};
	}
}

static void fill_line_crossing_pattern(
		int Ntotal, int margin, struct ext_interval *data)
{
	int step = (margin + 1);
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

static void fill_vline_pattern(
		int Ntotal, int margin, struct ext_interval *data)
{
	int step = (margin + 2);
	int stride = Ntotal * step;
	for (int i = 0; i < Ntotal; i++) {
		data[i] = (struct ext_interval){
				.start = i * step,
				.width = 1,
				.rep = 2,
				.stride = stride,
		};
	}
}

static int randint(int max)
{
	int cap = RAND_MAX - RAND_MAX % max;
	while (1) {
		int x = rand();
		if (x >= cap) {
			continue;
		}
		return x % max;
	}
}

static void fill_circle_pattern(
		int Ntotal, int margin, struct ext_interval *data)
{
	srand((uint32_t)(Ntotal + 165 * margin));

	int i = 0;
	int R = (int)((2 * margin + Ntotal) * 0.3);
	int s = (2 * margin + Ntotal) / 2;
	while (i < Ntotal) {
		int x = randint(2 * R);
		int w = randint(2 * R - x) + 1;
		int y = randint(2 * R);
		int h = randint(2 * R - y) + 1;
		int64_t x2a = (x - R) * (x - R);
		int64_t x2b = (x + w - R) * (x + w - R);
		int64_t x2 = x2a < x2b ? x2b : x2a;
		int64_t y2a = (y - R) * (y - R);
		int64_t y2b = (y + w - R) * (y + w - R);
		int64_t y2 = y2a < y2b ? y2b : y2a;
		if (x2 + y2 >= R * R) {
			continue;
		}

		data[i++] = (struct ext_interval){
				.start = s * y + x,
				.width = w,
				.rep = h,
				.stride = s,
		};
	}
}

static void fill_snow_pattern(int Ntotal, int margin, struct ext_interval *data)
{
	srand((uint32_t)(Ntotal + 165 * margin));

	int size = 4;
	while (size * size < Ntotal * margin) {
		size = size + size / 4;
	}

	for (int i = 0; i < Ntotal; i++) {
		int x = randint(size);
		int y = randint(size);
		data[i] = (struct ext_interval){
				.start = size * y + x,
				.width = 1,
				.rep = 1,
				.stride = size,
		};
	}
}
struct pattern {
	const char *name;
	void (*func)(int Ntotal, int margin, struct ext_interval *data);
};
static const struct pattern patterns[] = {{"overcopy", fill_overcopy_pattern},
		{"line-crossing", fill_line_crossing_pattern},
		{"circle", fill_circle_pattern}, {"snow", fill_snow_pattern},
		{"vline", fill_vline_pattern}, {NULL, NULL}};

static inline int eint_low(const struct ext_interval i) { return i.start; }
static inline int eint_high(const struct ext_interval i)
{
	return i.start + (i.rep - 1) * i.stride + i.width;
}

static void write_eint(
		struct ext_interval e, char *buf, int minv, uint8_t value)
{
	for (int k = 0; k < e.rep; k++) {
		memset(&buf[e.start + e.stride * k - minv], value,
				(size_t)e.width);
	}
}

/** Verify that:
 * - the new set of intervals covers the old
 * - the new set of intervals is disjoint within margin
 */
static bool check_solution_properties(int nsub, const struct ext_interval *sub,
		int nsup, const struct interval *sup, int margin)
{
	int minv = INT32_MAX, maxv = INT32_MIN;
	for (int i = 0; i < nsup; i++) {
		minv = min(minv, sup[i].start);
		maxv = max(maxv, sup[i].end);
	}
	for (int i = 0; i < nsub; i++) {
		minv = min(minv, eint_low(sub[i]));
		maxv = max(maxv, eint_high(sub[i]));
	}
	if (minv > maxv) {
		return true;
	}
	minv -= margin;
	maxv += margin;
	char *test = calloc((size_t)(maxv - minv), 1);
	// Fast & stupid containment test
	for (int i = 0; i < nsub; i++) {
		write_eint(sub[i], test, minv, 1);
	}
	for (int i = 0; i < nsup; i++) {
		struct interval e = sup[i];
		if (memchr(&test[e.start - minv - margin], 2,
				    (size_t)(e.end - e.start + 2 * margin)) !=
				NULL) {
			printf("Internal overlap failure\n");
			free(test);
			return false;
		}

		memset(&test[e.start - minv], 2, (size_t)(e.end - e.start));
	}
	bool yes = memchr(test, 1, (size_t)(maxv - minv)) == NULL;
	if (!yes) {
		int count = 0;
		for (int i = 0; i < maxv - minv; i++) {
			count += test[i] == 1;
		}
		printf("Fail count: %d/%d\n", count, maxv - minv);
		if (maxv - minv < 200) {
			for (int i = 0; i < maxv - minv; i++) {
				printf("%d", test[i]);
			}
			printf("\n");
		}
	}

	free(test);
	return yes;
}

static int convert_to_simple(
		struct interval *vec, int count, const struct ext_interval *ext)
{
	int k = 0;
	for (int i = 0; i < count; i++) {
		for (int j = 0; j < ext[i].rep; j++) {
			vec[k].start = ext[i].start + j * ext[i].stride;
			vec[k].end = vec[k].start + ext[i].width;
			k++;
		}
	}
	return k;
}
static int simple_lexsort(const void *L, const void *R)
{
	const struct interval *l = L;
	const struct interval *r = R;
	if (l->start != r->start) {
		return l->start - r->start;
	}
	return l->end - r->end;
}

/** A merge operation which reduces the compound intervals to simple intervals,
 * and then merges them that way. After all, this only expands memory use and
 * runtime by a factor of screen height... */
static void __attribute__((noinline))
merge_simple(const int old_count, struct ext_interval *old_list,
		const int new_count, const struct ext_interval *const new_list,
		int *dst_count, struct interval **dst_list, int merge_margin)
{
	int nintervals = 0;
	for (int i = 0; i < old_count; i++) {
		nintervals += old_list[i].rep;
	}
	for (int i = 0; i < new_count; i++) {
		nintervals += new_list[i].rep;
	}
	struct interval *vec =
			malloc((size_t)nintervals * sizeof(struct interval));
	int base = convert_to_simple(vec, old_count, old_list);
	convert_to_simple(&vec[base], new_count, new_list);

	// divide and conquer would be faster here
	qsort(vec, (size_t)nintervals, sizeof(struct interval), simple_lexsort);

	int r = 0, w = 0;
	while (r < nintervals) {
		// inside loop.
		int end = vec[w].end;
		r++; // the interval already contains itself

		while (r < nintervals && vec[r].start < end + merge_margin) {
			end = max(end, vec[r].end);
			r++;
		}
		vec[w].end = end;
		w++;
		if (r < nintervals) {
			vec[w] = vec[r];
		}
	}

	*dst_list = vec;
	*dst_count = w;
}

static int get_coverage(const int c, const struct interval *li)
{
	int n = 0;
	for (int i = 0; i < c; i++) {
		n += li[i].end - li[i].start;
	}
	return n;
}

log_handler_func_t log_funcs[2] = {test_log_handler, test_log_handler};
int main(int argc, char **argv)
{
	(void)argc;
	(void)argv;
	bool all_success = true;

	srand(0);
	// no larger, because e.g. test sizes are (margins*N)^2
	int margins[] = {2, 11, 32, 1};
	int nvec[] = {1000, 50, 10, 30};

	for (int z = 0; z < (int)(sizeof(nvec) / sizeof(nvec[0])); z++) {
		for (int ip = 0; patterns[ip].name; ip++) {
			/* Pattern tests: we generate a given pattern of damage
			 * rectangles, apply the merge function, and verify that
			 * all the desired result properties hold */
			struct ext_interval *data = calloc((size_t)nvec[z],
					sizeof(struct ext_interval));

			printf("\n----  pattern=%s, N=%d, margin=%d\n",
					patterns[ip].name, nvec[z], margins[z]);

			(*patterns[ip].func)(nvec[z], margins[z], data);

			// check that minv >= 0, maxv is <= 1GB
			int64_t minv = 0, maxv = 0;
			for (int i = 0; i < nvec[z]; i++) {
				int64_t high = data[i].start +
					       ((int64_t)data[i].rep) *
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
			if (maxv > 0x40000000LL) {
				printf("generated interval set would use too much memory to check, skipping\n");
				continue;
			}

			const char *names[2] = {"simple", "merges"};
			for (int k = 0; k < 2; k++) {
				int dst_count = 0;
				struct interval *dst_list = NULL;

				int margin = margins[z];

				struct timespec t0, t1;
				clock_gettime(CLOCK_MONOTONIC, &t0);
				if (k == 0) {
					merge_simple(0, NULL, nvec[z], data,
							&dst_count, &dst_list,
							margin);
				} else if (k == 1) {
					merge_mergesort(0, NULL, nvec[z], data,
							&dst_count, &dst_list,
							margin, 0);
				}

				clock_gettime(CLOCK_MONOTONIC, &t1);

				double elapsed01 =
						1.0 * (double)(t1.tv_sec -
								      t0.tv_sec) +
						1e-9 * (double)(t1.tv_nsec -
								       t0.tv_nsec);

				bool pass = check_solution_properties(nvec[z],
						data, dst_count, dst_list,
						margins[z]);
				all_success &= pass;

				int coverage = get_coverage(
						dst_count, dst_list);
				printf("%s operation took %9.5f ms, %d intervals, %d bytes, %s\n",
						names[k], elapsed01 * 1e3,
						dst_count, coverage,
						pass ? "pass" : "FAIL");
				free(dst_list);
			}
			free(data);
		}
	}

	return all_success ? EXIT_SUCCESS : EXIT_FAILURE;
}
