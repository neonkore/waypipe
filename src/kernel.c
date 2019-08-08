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

#include "damage.h"
#include "util.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if defined(__linux__) && defined(__arm__)
#include <asm/hwcap.h>
#include <sys/auxv.h>
#elif defined(__FreeBSD__) && defined(__arm__)
#include <sys/auxv.h>
#endif

int run_interval_diff_C(const int diff_window_size, const int i_end,
		const uint64_t *__restrict__ mod, uint64_t *__restrict__ base,
		uint64_t *__restrict__ diff, int i)
{
	/* we paper over gaps of a given window size, to avoid fine
	 * grained context switches */
	const int i_start = i;
	int dc = 0;
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
		int last_header = dc++;
		diff[last_header] = (uint64_t)(i - 1);
		diff[dc++] = changed_val;
		base[i - 1] = changed_val;
		// changed_val != base_val, difference occurs at early
		// index
		int nskip = 0;
		// we could only sentinel this assuming a tiny window
		// size
		while (i < i_end && nskip <= diff_window_size) {
			base_val = base[i];
			changed_val = mod[i];
			base[i] = changed_val;
			i++;
			diff[dc++] = changed_val;
			nskip++;
			nskip *= (base_val == changed_val);
		}
		dc -= nskip;
		diff[last_header] |= (uint64_t)(i - nskip) << 32;
		/* our sentinel, at worst, causes overcopy by one. this
		 * is fine
		 */
	}

	/* If only the last block changed */
	if ((clear_exit || i_start + 1 == i_end) && changed_val != base_val) {
		diff[dc++] = ((uint64_t)i_end << 32) | (uint64_t)(i_end - 1);
		diff[dc++] = changed_val;
		base[i_end - 1] = changed_val;
	}
	return dc;
}

#ifdef HAVE_AVX512F
static bool avx512f_available(void)
{
	return __builtin_cpu_supports("avx512f");
}
int run_interval_diff_avx512f(const int diff_window_size, const int i_end,
		const uint64_t *__restrict__ mod, uint64_t *__restrict__ base,
		uint64_t *__restrict__ diff, int i);
#endif

#ifdef HAVE_AVX2
static bool avx2_available(void) { return __builtin_cpu_supports("avx2"); }
int run_interval_diff_avx2(const int diff_window_size, const int i_end,
		const uint64_t *__restrict__ mod, uint64_t *__restrict__ base,
		uint64_t *__restrict__ diff, int i);
#endif

#ifdef HAVE_NEON
static bool neon_available(void)
{
	/* The actual methods are platform-dependent */
#if defined(__linux__) && defined(__arm__)
	return (getauxval(AT_HWCAP) & HWCAP_NEON) != 0;
#elif defined(__FreeBSD__) && defined(__arm__)
	unsigned long hwcap = 0;
	elf_aux_info(AT_HWCAP, &hwcap, sizeof(hwcap));
	return (hwcap & HWCAP_NEON) != 0;
#endif
	return true;
}
int run_interval_diff_neon(const int diff_window_size, const int i_end,
		const uint64_t *__restrict__ mod, uint64_t *__restrict__ base,
		uint64_t *__restrict__ diff, int i);
#endif

#ifdef HAVE_SSE41
static bool sse41_available(void) { return __builtin_cpu_supports("sse4.1"); }
int run_interval_diff_sse41(const int diff_window_size, const int i_end,
		const uint64_t *__restrict__ mod, uint64_t *__restrict__ base,
		uint64_t *__restrict__ diff, int i);
#endif

interval_diff_fn_t get_fastest_diff_function(
		enum diff_type type, int *alignment)
{
#ifdef HAVE_AVX512F
	if ((type == DIFF_FASTEST || type == DIFF_AVX512F) &&
			avx512f_available()) {
		*alignment = 64;
		return run_interval_diff_avx512f;
	}
#endif
#ifdef HAVE_AVX2
	if ((type == DIFF_FASTEST || type == DIFF_AVX2) && avx2_available()) {
		*alignment = 64;
		return run_interval_diff_avx2;
	}
#endif
#ifdef HAVE_NEON
	if ((type == DIFF_FASTEST || type == DIFF_NEON) && neon_available()) {
		*alignment = 16;
		return run_interval_diff_neon;
	}
#endif
#ifdef HAVE_SSE41
	if ((type == DIFF_FASTEST || type == DIFF_SSE41) && sse41_available()) {
		*alignment = 32;
		return run_interval_diff_sse41;
	}
#endif
	if ((type == DIFF_FASTEST || type == DIFF_C)) {
		*alignment = 8;
		return run_interval_diff_C;
	}
	*alignment = 0;
	return NULL;
}

/** Construct the main portion of a diff. The provided arguments should
 * be validated beforehand. All intervals, as well as the base/changed data
 * pointers, should be aligned to the alignment size associated with the
 * interval diff function */
int construct_diff_core(interval_diff_fn_t idiff_fn,
		const struct interval *__restrict__ damaged_intervals,
		int n_intervals, char *__restrict__ base,
		const char *__restrict__ changed, char *__restrict__ diff)
{
	uint64_t *base_blocks = (uint64_t *)base;
	const uint64_t *changed_blocks = (const uint64_t *)changed;
	uint64_t *diff_blocks = (uint64_t *)diff;
	uint64_t cursor = 0;
	for (int i = 0; i < n_intervals; i++) {
		struct interval e = damaged_intervals[i];
		int bend = e.end / 8;
		int bstart = e.start / 8;
		cursor += (uint64_t)(*idiff_fn)(12, bend, changed_blocks,
				base_blocks, diff_blocks + cursor, bstart);
	}
	return cursor * 8;
}
int construct_diff_trailing(int size, int alignment, char *__restrict__ base,
		const char *__restrict__ changed, char *__restrict__ diff)
{
	int ntrailing = (int)size % alignment;
	int offset = size - ntrailing;
	bool tail_change = false;
	if (ntrailing > 0) {
		for (int i = 0; i < ntrailing; i++) {
			tail_change |= base[offset + i] != changed[offset + i];
		}
	}
	if (tail_change) {
		for (int i = 0; i < ntrailing; i++) {
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
	size_t nblocks = size / 8;
	size_t ndiffblocks = diffsize / 8;
	uint64_t *__restrict__ t1_blocks = (uint64_t *)target1;
	uint64_t *__restrict__ t2_blocks = (uint64_t *)target2;
	uint64_t *__restrict__ diff_blocks = (uint64_t *)diff;
	for (size_t i = 0; i < ndiffblocks;) {
		union {
			uint64_t u;
			uint32_t v[2];
		} block;
		block.u = diff_blocks[i];
		size_t nfrom = (size_t)block.v[0];
		size_t nto = (size_t)block.v[1];
		size_t span = nto - nfrom;
		if (nto > nblocks || nfrom >= nto ||
				i + (nto - nfrom) >= ndiffblocks) {
			wp_error("Invalid copy range [%zu,%zu) > %zu=nblocks or [%zu,%zu) > %zu=ndiffblocks",
					nfrom, nto, nblocks, i + 1,
					i + 1 + span, ndiffblocks);
			return;
		}
		memcpy(t1_blocks + nfrom, diff_blocks + i + 1, 8 * span);
		memcpy(t2_blocks + nfrom, diff_blocks + i + 1, 8 * span);
		i += span + 1;
	}
	if (ntrailing > 0) {
		size_t offset = size - ntrailing;
		for (size_t i = 0; i < ntrailing; i++) {
			target1[offset + i] = diff[diffsize + i];
			target2[offset + i] = diff[diffsize + i];
		}
	}
}
