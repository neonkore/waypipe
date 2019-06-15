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

// Test targets
void merge_core(const int old_count, struct ext_interval *old_list,
		const int new_count, const struct ext_interval *const new_list,
		int *dst_count, struct ext_interval **dst_list,
		int merge_margin);
uint32_t merge_intervals(const struct ext_interval a,
		const struct ext_interval b, struct ext_interval o[static 3],
		int merge_margin);

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
	long R = (int)((2 * margin + Ntotal) * 0.3);
	int s = (2 * margin + Ntotal) / 2;
	while (i < Ntotal) {
		int x = randint(2 * R);
		int w = randint(2 * R - x) + 1;
		int y = randint(2 * R);
		int h = randint(2 * R - y) + 1;
		long x2 = max((x - R) * (x - R), (x + w - R) * (x + w - R));
		long y2 = max((y - R) * (y - R), (y + w - R) * (y + w - R));
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
		{NULL, NULL}};

static inline int eint_low(const struct ext_interval i) { return i.start; }
static inline int eint_high(const struct ext_interval i)
{
	return i.start + (i.rep - 1) * i.stride + i.width;
}

static void write_eint(
		struct ext_interval e, char *buf, int minv, uint8_t value)
{
	for (int k = 0; k < e.rep; k++) {
		memset(&buf[e.start + e.stride * k - minv], value, e.width);
	}
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
		minv = min(minv, eint_low(sup[i]));
		maxv = max(maxv, eint_high(sup[i]));
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
	char *test = calloc(maxv - minv, 1);
	// Fast & stupid containment test
	for (int i = 0; i < nsub; i++) {
		write_eint(sub[i], test, minv, 1);
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

static void print_eint(const char *name, struct ext_interval e)
{
	printf("%s: SWRS=%d,%d,%d,%d range=[%d,%d)\n", name, e.start, e.width,
			e.rep, e.stride, eint_low(e), eint_high(e));
}

struct interval {
	int32_t start;
	int32_t width;
};

static int convert_to_simple(
		struct interval *vec, int count, const struct ext_interval *ext)
{
	int k = 0;
	for (int i = 0; i < count; i++) {
		for (int j = 0; j < ext[i].rep; j++) {
			vec[k].start = ext[i].start + j * ext[i].stride;
			vec[k].width = ext[i].width;
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
	return l->width - r->width;
}

/** A merge operation which reduces the compound intervals to simple intervals,
 * and then merges them that way. After all, this only expands memory use and
 * runtime by a factor of screen height... */
static void merge_simple(const int old_count, struct ext_interval *old_list,
		const int new_count, const struct ext_interval *const new_list,
		int *dst_count, struct ext_interval **dst_list,
		int merge_margin)
{
	int nintervals = 0;
	for (int i = 0; i < old_count; i++) {
		nintervals += old_list[i].rep;
	}
	for (int i = 0; i < new_count; i++) {
		nintervals += new_list[i].rep;
	}
	struct interval *vec = malloc((size_t)nintervals * sizeof(vec));
	int base = convert_to_simple(vec, old_count, old_list);
	base += convert_to_simple(&vec[base], new_count, new_list);

	// divide and conquer would be faster here
	qsort(vec, nintervals, sizeof(struct interval), simple_lexsort);

	int r = 0, w = 0;
	while (r < nintervals) {
		// inside loop.
		int end = vec[w].start + vec[w].width;
		r++; // the interval already contains itself

		while (r < nintervals && vec[r].start < end + merge_margin) {
			end = max(end, vec[r].start + vec[r].width);
			r++;
		}
		vec[w].width = end - vec[w].start;
		w++;
		if (r < nintervals) {
			vec[w] = vec[r];
		}
	}
	struct ext_interval *ret =
			malloc((size_t)w * sizeof(struct ext_interval));
	for (int i = 0; i < w; i++) {
		ret[i] = (struct ext_interval){.start = vec[i].start,
				.width = vec[i].width,
				.rep = 1,
				.stride = 0

		};
	}
	free(vec);

	*dst_list = ret;
	*dst_count = w;
}

static int get_coverage(const int c, const struct ext_interval *li)
{
	int n = 0;
	for (int i = 0; i < c; i++) {
		n += li[i].rep * li[i].width;
	}
	return n;
}

static bool check_merge_properties(struct ext_interval a, struct ext_interval b,
		int n, struct ext_interval *res, int margin)
{
	int minv = min(eint_low(a), eint_low(b));
	int maxv = max(eint_high(a), eint_high(b));
	int aminv = minv, amaxv = maxv;
	for (int i = 0; i < n; i++) {
		minv = min(minv, eint_low(res[i]));
		maxv = max(maxv, eint_high(res[i]));
	}
	if (minv < aminv || maxv > amaxv) {
		printf("Exterior range expansion, [%d,%d) to [%d,%d) with margin=%d\n",
				aminv, amaxv, minv, maxv, margin);
		return false;
	}

	if (n == 0) {
		return true;
	}

	// Check that we do not write new data outside the region of overlap
	// plus margin
	int avh = min(eint_high(a), eint_high(b)) + margin;
	int avl = max(eint_low(a), eint_low(b)) - margin;
	maxv = max(avh, maxv);
	minv = min(avl, minv);
	if (avh < avl) {
		return true;
	}

	char *test = calloc(maxv - minv, 1);
	for (int i = 0; i < n; i++) {
		write_eint(res[i], test, minv, 1);
	}
	write_eint(a, test, minv, 2);
	write_eint(b, test, minv, 2);
	if (memchr(test, 1, avl - minv) != NULL) {
		printf("Lower branch was modified below margin (domain of legal change [%d,%d))\n",
				avl, avh);
		for (int i = 0; i < maxv - minv; i++) {
			printf("%d", test[i]);
		}
		printf("\n");
		free(test);
		return false;
	}
	if (memchr(test + avh - minv, 1, maxv - avh) != NULL) {
		printf("Upper branch was modified above margin (domain of legal change [%d,%d))\n",
				avl, avh);
		for (int i = 0; i < maxv - minv; i++) {
			printf("%d", test[i]);
		}
		printf("\n");
		free(test);
		return false;
	}

	free(test);
	return true;
}

static bool sub_test_mergeprop(int iter, struct ext_interval t,
		struct ext_interval e, int margin)
{
	struct ext_interval o[3];
	uint32_t n = merge_intervals(e, t, o, margin);

	bool pass_form = true;
	for (uint32_t i = 0; i < n; i++) {
		if (o[i].rep <= 0 || o[i].width <= 0 || o[i].stride < 0) {
			pass_form = false;
		}
	}

	bool pass_merge = check_merge_properties(e, t, (int)n, o, margin);

	struct ext_interval inputs[2] = {e, t};
	bool pass_set = check_solution_properties(2, inputs,
			n == 0 ? 2 : (int)n, n == 0 ? inputs : o, margin);

	if (!pass_set || !pass_merge || !pass_form) {
		printf("#%d\n", iter);
		print_eint("rel", e);
		print_eint("test", t);
		const char *names[] = {"set0", "set1", "set2"};
		for (uint32_t i = 0; i < n; i++) {
			print_eint(names[i], o[i]);
		}
	}
	return pass_set && pass_merge && pass_form;
}

static bool test_mergeprop(struct ext_interval e, int margin)
{
	int maxq = eint_high(e) + margin * 5;
	bool allpass = true;
	int iter = 0;
	for (int s = 0; s < maxq; s++) {
		for (int w = 1; w <= e.stride - margin; w++) {
			for (int r = 1; r < (maxq - s) / e.stride + 1; r++) {
				struct ext_interval t = {s, w, r, e.stride};
				allpass &= sub_test_mergeprop(
						iter++, t, e, margin);
			}
		}
	}
	for (int s = 0; s < maxq; s++) {
		for (int w = 1; w <= maxq - s; w++) {
			struct ext_interval t = {s, w, 1, e.stride};
			allpass &= sub_test_mergeprop(iter++, t, e, margin);
		}
	}

	printf("%d merge configurations checked\n", iter);
	return allpass;
}

struct intv_test_set {
	struct ext_interval intv;
	int margin;
};

static const struct intv_test_set merge_tests[] = {
		{{12, 4, 7, 11}, 3},
		{{3, 33, 1, 6}, 4},
		{{20, 4, 4, 9}, 4},
		{{10, 2, 1, 5}, 2},
		{{4, 4, 4, 8}, 4},
		{{28, 10, 1, 1}, 6},
		{{0, 0, 0, 0}, 0},
};

int main(int argc, char **argv)
{
	(void)argc;
	(void)argv;
	bool all_success = true;

	printf("---- pairwise merge checks\n");
	for (int i = 0; merge_tests[i].margin; i++) {
		all_success &= test_mergeprop(
				merge_tests[i].intv, merge_tests[i].margin);
	}

	srand(0);
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

			printf("\n----  pattern=%s, N=%d, margin=%d\n",
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

			int simple_count;
			struct ext_interval *simple_list = NULL;

			struct timespec t0, t1, t2;
			clock_gettime(CLOCK_MONOTONIC, &t0);
			merge_core(0, NULL, nvec[z], data, &dst_count,
					&dst_list, margins[z]);
			clock_gettime(CLOCK_MONOTONIC, &t1);
			merge_simple(0, NULL, nvec[z], data, &simple_count,
					&simple_list, margins[z]);
			clock_gettime(CLOCK_MONOTONIC, &t2);

			double elapsed01 = 1.0 * (t1.tv_sec - t0.tv_sec) +
					   1e-9 * (t1.tv_nsec - t0.tv_nsec);
			double elapsed12 = 1.0 * (t2.tv_sec - t1.tv_sec) +
					   1e-9 * (t2.tv_nsec - t1.tv_nsec);

			printf("merge operation took %f ms\n", elapsed01 * 1e3);
			printf("simple operation took %f ms\n",
					elapsed12 * 1e3);

			bool pass = check_solution_properties(nvec[z], data,
					dst_count, dst_list, margins[z]);
			all_success &= pass;

			bool pass_simple = check_solution_properties(nvec[z],
					data, simple_count, simple_list,
					margins[z]);
			all_success &= pass_simple;

			printf("new size is %d, %s, %d bytes\n", dst_count,
					pass ? "pass" : "fail",
					get_coverage(dst_count, dst_list));
			printf("simple size is %d, %s, %d bytes\n",
					simple_count,
					pass_simple ? "pass" : "fail",
					get_coverage(simple_count,
							simple_list));

			free(simple_list);
			free(dst_list);
			free(data);
		}
	}

	return all_success ? EXIT_SUCCESS : EXIT_FAILURE;
}
