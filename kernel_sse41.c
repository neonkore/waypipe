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

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <emmintrin.h> // sse
#include <pmmintrin.h> // sse2
#include <smmintrin.h> // sse4.1
#include <tmmintrin.h> // sse3
#include <xmmintrin.h> // ssse3

bool sse41_available(void) { return __builtin_cpu_supports("sse4.1"); }

int run_interval_diff_sse41(const int diff_window_size, const int i_end,
		const uint64_t *__restrict__ mod, uint64_t *__restrict__ base,
		uint64_t *__restrict__ diff, int i)
{
	int dc = 0;
	while (1) {
		/* Loop: no changes */
		uint32_t *ctrl_blocks = (uint32_t *)&diff[dc++];

		int trailing_unchanged = 0;
		for (; i < i_end; i += 4) {
			/* Q: does it make sense to unroll by 2, cutting branch
			 * count in half? */
			__m128i b0 = _mm_load_si128((const __m128i *)&base[i]);
			__m128i b1 = _mm_load_si128(
					(const __m128i *)&base[i + 2]);
			__m128i m0 = _mm_load_si128((const __m128i *)&mod[i]);
			__m128i m1 = _mm_load_si128(
					(const __m128i *)&mod[i + 2]);

			/* pxor + ptest + branch could be faster, depending on
			 * compiler choices */
			__m128i eq0 = _mm_cmpeq_epi64(m0, b0);
			__m128i eq1 = _mm_cmpeq_epi64(m1, b1);
			uint32_t mask = (uint32_t)_mm_movemask_epi8(eq0);
			mask |= ((uint32_t)_mm_movemask_epi8(eq1)) << 16;
			if (mask != 0xffffffff) {
				_mm_storeu_si128((__m128i *)&base[i], m0);
				_mm_storeu_si128((__m128i *)&base[i + 2], m1);

				/* Write the changed bytes, starting at the
				 * first modified term, and set the
				 * unchanged counter */
				int ncom = __builtin_ctz(~mask) >> 3;
				for (int z = ncom; z < 4; z++) {
					diff[dc++] = mod[i + z];
				}
				trailing_unchanged = __builtin_clz(~mask) >> 3;
				ctrl_blocks[0] = i + ncom;

				i += 4;
				if (i >= i_end) {
					/* Last block, hence will not enter copy
					 * loop */
					ctrl_blocks[1] = i;
					dc++;
				}

				break;
			}
		}
		if (i >= i_end) {
			dc--;
			break;
		}

		/* Loop: until no changes for DIFF_WINDOW +/- 4 spaces */
		for (; i < i_end; i += 4) {
			__m128i b0 = _mm_load_si128((const __m128i *)&base[i]);
			__m128i b1 = _mm_load_si128(
					(const __m128i *)&base[i + 2]);
			__m128i m0 = _mm_load_si128((const __m128i *)&mod[i]);
			__m128i m1 = _mm_load_si128(
					(const __m128i *)&mod[i + 2]);

			__m128i eq0 = _mm_cmpeq_epi64(m0, b0);
			__m128i eq1 = _mm_cmpeq_epi64(m1, b1);
			uint32_t mask = (uint32_t)_mm_movemask_epi8(eq0);
			mask |= ((uint32_t)_mm_movemask_epi8(eq1)) << 16;

			bool clear = mask == 0xffffffff;
			/* Because clz is undefined when mask=0, extend */
			uint64_t ext_mask = ((uint64_t)mask) << 32;
			int nleading = __builtin_clzll(~ext_mask);

			trailing_unchanged = clear * (trailing_unchanged + 4) +
					     (!clear) * (nleading >> 3);

			_mm_storeu_si128((__m128i *)&diff[dc], m0);
			_mm_storeu_si128((__m128i *)&diff[dc + 2], m1);
			dc += 4;
			if (trailing_unchanged > diff_window_size) {
				i += 4;
				break;
			}
			_mm_storeu_si128((__m128i *)&base[i], m0);
			_mm_storeu_si128((__m128i *)&base[i + 2], m1);
		}
		/* Write coda */
		dc -= trailing_unchanged;
		ctrl_blocks[1] = i - trailing_unchanged;

		if (i >= i_end) {
			break;
		}
	}

	return dc;
}
