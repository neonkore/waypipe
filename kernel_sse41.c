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
	const __m128i ident = _mm_set_epi8(
			15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
	const __m128i swap = _mm_set_epi8(
			7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8);
	const __m128i table[2] = {ident, swap};

	int dc = 0;
	while (1) {
		/* Loop: no changes */
		uint32_t *ctrl_blocks = (uint32_t *)&diff[dc++];

		int trailing_unchanged = 0;
		for (; i < i_end; i += 2) {
			/* Q: does it make sense to unroll by 2, cutting branch
			 * count in half? */
			__m128i m = _mm_load_si128((const __m128i *)&mod[i]);
			__m128i b = _mm_load_si128((const __m128i *)&base[i]);

			/* pxor + ptest + branch could be faster, depending on
			 * compiler choices */
			__m128i eq = _mm_cmpeq_epi64(m, b);
			uint32_t mask = (uint32_t)_mm_movemask_epi8(eq);
			if (mask != 0xffff) {
				_mm_storeu_si128((__m128i *)&base[i], m);

				/* Write the changed bytes, starting at the
				 * first modified term,
				 * and set the n_unchanged counter */
				int ncom = (mask & 0xff) != 0;

				__m128i left_aligned = _mm_shuffle_epi8(
						m, table[ncom > 0]);
				_mm_storeu_si128((__m128i *)&diff[dc],
						left_aligned);
				dc += 2 - ncom;
				trailing_unchanged = (mask & 0xff00) != 0;
				ctrl_blocks[0] = i + ncom;

				i += 2;
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
		for (; i < i_end; i += 2) {
			__m128i m = _mm_load_si128((const __m128i *)&mod[i]);
			__m128i b = _mm_load_si128((const __m128i *)&base[i]);
			__m128i eq = _mm_cmpeq_epi64(m, b);
			uint32_t mask = (uint32_t)_mm_movemask_epi8(eq);

			bool clear = mask == 0x0000ffff;
			bool trail_one = (mask & 0x0000ff00) != 0;
			trailing_unchanged = trail_one +
					     clear * (trailing_unchanged + 1);

			_mm_storeu_si128((__m128i *)&diff[dc], m);
			dc += 2;
			if (trailing_unchanged > diff_window_size) {
				i += 2;
				break;
			}
			_mm_storeu_si128((__m128i *)&base[i], m);
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
