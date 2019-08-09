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
typedef size_t (*interval_diff_fn_t)(const int diff_window_size,
		const void *__restrict__ imod, void *__restrict__ ibase,
		uint32_t *__restrict__ diff, size_t i, const size_t i_end);

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
interval_diff_fn_t get_diff_function(enum diff_type type, int *alignment_bits);
size_t construct_diff_core(interval_diff_fn_t idiff_fn, int alignment_bits,
		const struct interval *__restrict__ damaged_intervals,
		int n_intervals, void *__restrict__ base,
		const void *__restrict__ changed, void *__restrict__ diff);
size_t construct_diff_trailing(size_t size, int alignment_bits,
		char *__restrict__ base, const char *__restrict__ changed,
		char *__restrict__ diff);
void apply_diff(size_t size, char *__restrict__ target1,
		char *__restrict__ target2, size_t diffsize, size_t ntrailing,
		const char *__restrict__ diff);

#endif // WAYPIPE_KERNEL_H
