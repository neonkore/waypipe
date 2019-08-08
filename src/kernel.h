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
#ifndef WAYPIPE_KERNEL_H
#define WAYPIPE_KERNEL_H

#include <stddef.h>
#include <stdint.h>

struct interval;
typedef int (*interval_diff_fn_t)(const int diff_window_size, const int i_end,
		const uint64_t *__restrict__ mod, uint64_t *__restrict__ base,
		uint64_t *__restrict__ diff, int i);

enum diff_type {
	DIFF_FASTEST,
	DIFF_AVX512F,
	DIFF_AVX2,
	DIFF_SSE41,
	DIFF_NEON,
	DIFF_C,
};

/** Returns a function pointer to a diff construction kernel, and indicates
 * the alignment of the data which is to be passed in */
interval_diff_fn_t get_fastest_diff_function(
		enum diff_type type, int *alignment);
int construct_diff_core(interval_diff_fn_t idiff_fn,
		const struct interval *__restrict__ damaged_intervals,
		int n_intervals, char *__restrict__ base,
		const char *__restrict__ changed, char *__restrict__ diff);
int construct_diff_trailing(int size, int alignment, char *__restrict__ base,
		const char *__restrict__ changed, char *__restrict__ diff);
void apply_diff(size_t size, char *__restrict__ target1,
		char *__restrict__ target2, size_t diffsize, size_t ntrailing,
		const char *__restrict__ diff);

#endif // WAYPIPE_KERNEL_H
