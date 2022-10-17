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

#include "kernel.h"
#include "interval.h"
#include "util.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

static size_t run_interval_diff_C(const int diff_window_size,
		const void *__restrict__ imod, void *__restrict__ ibase,
		uint32_t *__restrict__ idiff, size_t i, const size_t i_end)
{
	const uint64_t *__restrict__ mod = imod;
	uint64_t *__restrict__ base = ibase;
	uint64_t *__restrict__ diff = (uint64_t *__restrict__)idiff;

	/* we paper over gaps of a given window size, to avoid fine
	 * grained context switches */
	const size_t i_start = i;
	size_t dc = 0;
	uint64_t changed_val = i < i_end ? mod[i] : 0;
	uint64_t base_val = i < i_end ? base[i] : 0;
	i++;
	// Alternating scanners, ending with a mispredict each.
	bool clear_exit = false;
	while (i < i_end) {
		while (changed_val == base_val && i < i_end) {
			changed_val = mod[i];
			base_val = base[i];
			i++;
		}
		if (i == i_end) {
			/* it's possible that the last value actually;
			 * see exit block */
			clear_exit = true;
			break;
		}
		uint32_t *ctrl_blocks = (uint32_t *)&diff[dc++];
		ctrl_blocks[0] = (uint32_t)((i - 1) * 2);
		diff[dc++] = changed_val;
		base[i - 1] = changed_val;
		// changed_val != base_val, difference occurs at early
		// index
		size_t nskip = 0;
		// we could only sentinel this assuming a tiny window
		// size
		while (i < i_end && nskip <= (size_t)diff_window_size / 2) {
			base_val = base[i];
			changed_val = mod[i];
			base[i] = changed_val;
			i++;
			diff[dc++] = changed_val;
			nskip++;
			nskip *= (base_val == changed_val);
		}
		dc -= nskip;
		ctrl_blocks[1] = (uint32_t)((i - nskip) * 2);
		/* our sentinel, at worst, causes overcopy by one. this
		 * is fine
		 */
	}

	/* If only the last block changed */
	if ((clear_exit || i_start + 1 == i_end) && changed_val != base_val) {
		uint32_t *ctrl_blocks = (uint32_t *)&diff[dc++];
		ctrl_blocks[0] = (uint32_t)(i_end - 1) * 2;
		ctrl_blocks[1] = (uint32_t)i_end * 2;
		diff[dc++] = changed_val;
		base[i_end - 1] = changed_val;
	}
	return dc * 2;
}

#ifdef HAVE_AVX512F
static bool avx512f_available(void)
{
	return __builtin_cpu_supports("avx512f");
}
size_t run_interval_diff_avx512f(const int diff_window_size,
		const void *__restrict__ imod, void *__restrict__ ibase,
		uint32_t *__restrict__ idiff, size_t i, const size_t i_end);
#endif

#ifdef HAVE_AVX2
static bool avx2_available(void) { return __builtin_cpu_supports("avx2"); }
size_t run_interval_diff_avx2(const int diff_window_size,
		const void *__restrict__ imod, void *__restrict__ ibase,
		uint32_t *__restrict__ idiff, size_t i, const size_t i_end);
#endif

#ifdef HAVE_NEON
bool neon_available(void); // in platform.c
size_t run_interval_diff_neon(const int diff_window_size,
		const void *__restrict__ imod, void *__restrict__ ibase,
		uint32_t *__restrict__ idiff, size_t i, const size_t i_end);
#endif

#ifdef HAVE_SSE3
static bool sse3_available(void) { return __builtin_cpu_supports("sse3"); }
size_t run_interval_diff_sse3(const int diff_window_size,
		const void *__restrict__ imod, void *__restrict__ ibase,
		uint32_t *__restrict__ idiff, size_t i, const size_t i_end);
#endif

interval_diff_fn_t get_diff_function(enum diff_type type, int *alignment_bits)
{
#ifdef HAVE_AVX512F
	if ((type == DIFF_FASTEST || type == DIFF_AVX512F) &&
			avx512f_available()) {
		*alignment_bits = 6;
		return run_interval_diff_avx512f;
	}
#endif
#ifdef HAVE_AVX2
	if ((type == DIFF_FASTEST || type == DIFF_AVX2) && avx2_available()) {
		*alignment_bits = 6;
		return run_interval_diff_avx2;
	}
#endif
#ifdef HAVE_NEON
	if ((type == DIFF_FASTEST || type == DIFF_NEON) && neon_available()) {
		*alignment_bits = 4;
		return run_interval_diff_neon;
	}
#endif
#ifdef HAVE_SSE3
	if ((type == DIFF_FASTEST || type == DIFF_SSE3) && sse3_available()) {
		*alignment_bits = 5;
		return run_interval_diff_sse3;
	}
#endif
	if ((type == DIFF_FASTEST || type == DIFF_C)) {
		*alignment_bits = 3;
		return run_interval_diff_C;
	}
	*alignment_bits = 0;
	return NULL;
}

/** Construct the main portion of a diff. The provided arguments should
 * be validated beforehand. All intervals, as well as the base/changed data
 * pointers, should be aligned to the alignment size associated with the
 * interval diff function */
size_t construct_diff_core(interval_diff_fn_t idiff_fn, int alignment_bits,
		const struct interval *__restrict__ damaged_intervals,
		int n_intervals, void *__restrict__ base,
		const void *__restrict__ changed, void *__restrict__ diff)
{
	uint32_t *diff_blocks = (uint32_t *)diff;
	size_t cursor = 0;
	for (int i = 0; i < n_intervals; i++) {
		struct interval e = damaged_intervals[i];
		size_t bend = (size_t)e.end >> alignment_bits;
		size_t bstart = (size_t)e.start >> alignment_bits;
		cursor += (*idiff_fn)(24, changed, base, diff_blocks + cursor,
				bstart, bend);
	}
	return cursor * sizeof(uint32_t);
}
size_t construct_diff_trailing(size_t size, int alignment_bits,
		char *__restrict__ base, const char *__restrict__ changed,
		char *__restrict__ diff)
{
	size_t alignment = 1u << alignment_bits;
	size_t ntrailing = size % alignment;
	size_t offset = size - ntrailing;
	bool tail_change = false;
	if (ntrailing > 0) {
		for (size_t i = 0; i < ntrailing; i++) {
			tail_change |= base[offset + i] != changed[offset + i];
		}
	}
	if (tail_change) {
		for (size_t i = 0; i < ntrailing; i++) {
			diff[i] = changed[offset + i];
			base[offset + i] = changed[offset + i];
		}
		return ntrailing;
	}
	return 0;
}
void apply_diff(size_t size, char *__restrict__ target1,
		char *__restrict__ target2, size_t diffsize, size_t ntrailing,
		const char *__restrict__ diff)
{
	size_t nblocks = size / sizeof(uint32_t);
	size_t ndiffblocks = diffsize / sizeof(uint32_t);
	uint32_t *__restrict__ t1_blocks = (uint32_t *)target1;
	uint32_t *__restrict__ t2_blocks = (uint32_t *)target2;
	uint32_t *__restrict__ diff_blocks = (uint32_t *)diff;
	for (size_t i = 0; i < ndiffblocks;) {
		size_t nfrom = (size_t)diff_blocks[i];
		size_t nto = (size_t)diff_blocks[i + 1];
		size_t span = nto - nfrom;
		if (nto > nblocks || nfrom >= nto ||
				i + (nto - nfrom) >= ndiffblocks) {
			wp_error("Invalid copy range [%zu,%zu) > %zu=nblocks or [%zu,%zu) > %zu=ndiffblocks",
					nfrom, nto, nblocks, i + 1,
					i + 1 + span, ndiffblocks);
			return;
		}
		memcpy(t1_blocks + nfrom, diff_blocks + i + 2,
				sizeof(uint32_t) * span);
		memcpy(t2_blocks + nfrom, diff_blocks + i + 2,
				sizeof(uint32_t) * span);
		i += span + 2;
	}
	if (ntrailing > 0) {
		size_t offset = size - ntrailing;
		for (size_t i = 0; i < ntrailing; i++) {
			target1[offset + i] = diff[diffsize + i];
			target2[offset + i] = diff[diffsize + i];
		}
	}
}

void stride_shifted_copy(char *dest, const char *src, size_t src_start,
		size_t copy_length, size_t row_length, size_t src_stride,
		size_t dst_stride)
{
	size_t src_end = src_start + copy_length;
	size_t lrow = src_start / src_stride;
	size_t trow = src_end / src_stride;
	/* special case: inside a segment */
	if (lrow == trow) {
		size_t cstart = src_start - lrow * src_stride;
		if (cstart < row_length) {
			size_t cend = src_end - trow * src_stride;
			cend = cend > row_length ? row_length : cend;
			memcpy(dest + dst_stride * lrow + cstart,
					src + src_start, cend - cstart);
		}
		return;
	}

	/* leading segment */
	if (src_start > lrow * src_stride) {
		size_t igap = src_start - lrow * src_stride;
		if (igap < row_length) {
			memcpy(dest + dst_stride * lrow + igap, src + src_start,
					row_length - igap);
		}
	}

	/* main body */
	size_t srow = (src_start + src_stride - 1) / src_stride;
	for (size_t i = srow; i < trow; i++) {
		memcpy(dest + dst_stride * i, src + src_stride * i, row_length);
	}

	/* trailing segment */
	if (src_end > trow * src_stride) {
		size_t local = src_end - trow * src_stride;
		local = local > row_length ? row_length : local;
		memcpy(dest + dst_stride * trow, src + src_end - local, local);
	}
}
