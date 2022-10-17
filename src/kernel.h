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
	DIFF_SSE3,
	DIFF_NEON,
	DIFF_C,
};

/** Returns a function pointer to a diff construction kernel, and indicates
 * the alignment of the data which is to be passed in */
interval_diff_fn_t get_diff_function(enum diff_type type, int *alignment_bits);
/** Given intervals aligned to 1<<alignment_bits, create a diff of changed
 * over base, and update base to match changed. */
size_t construct_diff_core(interval_diff_fn_t idiff_fn, int alignment_bits,
		const struct interval *__restrict__ damaged_intervals,
		int n_intervals, void *__restrict__ base,
		const void *__restrict__ changed, void *__restrict__ diff);
/** If the bytes after the last multiple of 1<<alignment_bits differ, copy
 * them over base and append the to the diff */
size_t construct_diff_trailing(size_t size, int alignment_bits,
		char *__restrict__ base, const char *__restrict__ changed,
		char *__restrict__ diff);
/** Apply a diff to both target buffers */
void apply_diff(size_t size, char *__restrict__ target1,
		char *__restrict__ target2, size_t diffsize, size_t ntrailing,
		const char *__restrict__ diff);
/**
 * src, dest are buffers whose meaningful content consists of a series
 * of rows; the start coordinates of each row are multiples of 'src_stride' and
 * 'dst_stride', respectively. For example, 'C' in the following diagram
 * indicates and important byte; '.' indicates a byte whose value does not
 * matter.
 *
 * CCCCCCCCCCC......
 * CCCCCCCCCCC......
 * CCCCCCCCCCC......
 *
 * This function copies the content bytes of src to the content bytes of dest.
 * Note: 'src' is the original point of the src buffer, this may be unintuitive.
 */
void stride_shifted_copy(char *dest, const char *src, size_t src_start,
		size_t copy_length, size_t row_length, size_t src_stride,
		size_t dst_stride);

#endif // WAYPIPE_KERNEL_H
