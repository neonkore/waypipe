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
#include <tmmintrin.h> // sse3

size_t run_interval_diff_sse3(const int diff_window_size,
		const void *__restrict__ imod, void *__restrict__ ibase,
		uint32_t *__restrict__ diff, size_t i, const size_t i_end)
{
	const __m128i *__restrict__ mod = imod;
	__m128i *__restrict__ base = ibase;

	size_t dc = 0;
	while (1) {
		/* Loop: no changes */
		uint32_t *ctrl_blocks = (uint32_t *)&diff[dc];
		dc += 2;

		int trailing_unchanged = 0;
		for (; i < i_end; i++) {
			__m128i b0 = _mm_load_si128(&base[2 * i]);
			__m128i b1 = _mm_load_si128(&base[2 * i + 1]);
			__m128i m0 = _mm_load_si128(&mod[2 * i]);
			__m128i m1 = _mm_load_si128(&mod[2 * i + 1]);

			/* pxor + ptest + branch could be faster, depending on
			 * compiler choices */
			__m128i eq0 = _mm_cmpeq_epi32(m0, b0);
			__m128i eq1 = _mm_cmpeq_epi32(m1, b1);
			uint32_t mask = (uint32_t)_mm_movemask_epi8(eq0);
			mask |= ((uint32_t)_mm_movemask_epi8(eq1)) << 16;
			if (mask != 0xffffffff) {
				_mm_storeu_si128(&base[2 * i], m0);
				_mm_storeu_si128(&base[2 * i + 1], m1);

				/* Write the changed bytes, starting at the
				 * first modified term, and set the unchanged
				 * counter.  */
				size_t ncom = (size_t)__builtin_ctz(~mask) >> 2;
				union {
					__m128i s[2];
					uint32_t v[8];
				} tmp;
				tmp.s[0] = m0;
				tmp.s[1] = m1;
				for (size_t z = ncom; z < 8; z++) {
					diff[dc++] = tmp.v[z];
				}
				trailing_unchanged = __builtin_clz(~mask) >> 2;
				ctrl_blocks[0] = (uint32_t)(8 * i + ncom);

				i++;
				if (i >= i_end) {
					/* Last block, hence will not enter copy
					 * loop */
					ctrl_blocks[1] = (uint32_t)(8 * i);
					dc += 2;
				}

				break;
			}
		}
		if (i >= i_end) {
			dc -= 2;
			break;
		}

		/* Loop: until no changes for DIFF_WINDOW +/- 4 spaces */
		for (; i < i_end; i++) {
			__m128i b0 = _mm_load_si128(&base[2 * i]);
			__m128i b1 = _mm_load_si128(&base[2 * i + 1]);
			__m128i m0 = _mm_load_si128(&mod[2 * i]);
			__m128i m1 = _mm_load_si128(&mod[2 * i + 1]);

			__m128i eq0 = _mm_cmpeq_epi32(m0, b0);
			__m128i eq1 = _mm_cmpeq_epi32(m1, b1);
			uint32_t mask = (uint32_t)_mm_movemask_epi8(eq0);
			mask |= ((uint32_t)_mm_movemask_epi8(eq1)) << 16;

			bool clear = mask == 0xffffffff;
			/* Because clz is undefined when mask=0, extend */
			uint64_t ext_mask = ((uint64_t)mask) << 32;
			int nleading = __builtin_clzll(~ext_mask);

			trailing_unchanged = clear * (trailing_unchanged + 8) +
					     (!clear) * (nleading >> 2);

			_mm_storeu_si128((__m128i *)&diff[dc], m0);
			_mm_storeu_si128((__m128i *)&diff[dc + 4], m1);
			dc += 8;
			if (trailing_unchanged > diff_window_size) {
				i++;
				break;
			}
			_mm_storeu_si128(&base[2 * i], m0);
			_mm_storeu_si128(&base[2 * i + 1], m1);
		}
		/* Write coda */
		dc -= (size_t)trailing_unchanged;
		ctrl_blocks[1] = (uint32_t)(8 * i - (size_t)trailing_unchanged);

		if (i >= i_end) {
			break;
		}
	}
	return dc;
}
