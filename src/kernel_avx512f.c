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

#include <x86intrin.h>

size_t run_interval_diff_avx512f(const int diff_window_size,
		const void *__restrict__ imod, void *__restrict__ ibase,
		uint32_t *__restrict__ diff, size_t i, const size_t i_end)
{
	const __m512i *mod = imod;
	__m512i *base = ibase;

	size_t dc = 0;
	while (1) {
		/* Loop: no changes */
		uint32_t *ctrl_blocks = (uint32_t *)&diff[dc];
		dc += 2;

		int trailing_unchanged = 0;
		for (; i < i_end; i++) {
			__m512i m = _mm512_load_si512(&mod[i]);
			__m512i b = _mm512_load_si512(&base[i]);
			uint32_t mask = (uint32_t)_mm512_cmpeq_epi32_mask(m, b);
			if (mask != 0xffff) {
				_mm512_store_si512(&base[i], m);

				size_t ncom = (size_t)_tzcnt_u32(
						~(unsigned int)mask);
				__mmask16 storemask =
						(__mmask16)(0xffffu << ncom);
#if 0
				__m512i v = _mm512_maskz_compress_epi32(
						storemask, m);
				_mm512_storeu_si512(&diff[dc], v);
#else
				_mm512_mask_storeu_epi32(
						&diff[dc - ncom], storemask, m);
#endif
				dc += 16 - ncom;

				trailing_unchanged = (int)_lzcnt_u32(~mask &
								     0xffff) -
						     16;
				ctrl_blocks[0] = (uint32_t)(16 * i + ncom);

				i++;
				if (i >= i_end) {
					/* Last block, hence will not enter copy
					 * loop */
					ctrl_blocks[1] = (uint32_t)(16 * i);
					dc += 2;
				}

				break;
			}
		}
		if (i >= i_end) {
			dc -= 2;
			break;
		}

		/* Loop: until an entire window is clear */
		for (; i < i_end; i++) {
			__m512i m = _mm512_load_si512(&mod[i]);
			__m512i b = _mm512_load_si512(&base[i]);
			uint32_t mask = (uint32_t)_mm512_cmpeq_epi32_mask(m, b);

			/* Reset trailing counter if anything changed */
			uint32_t amask = ~(mask << 16);
			int clear = (mask == 0xffff) ? 1 : 0;
			trailing_unchanged = clear * trailing_unchanged +
					     (int)_lzcnt_u32(amask);

			_mm512_storeu_si512(&diff[dc], m);
			dc += 16;
			if (trailing_unchanged > diff_window_size) {
				i++;
				break;
			}
			_mm512_store_si512(&base[i], m);
		}
		/* Write coda */
		dc -= (size_t)trailing_unchanged;
		ctrl_blocks[1] =
				(uint32_t)(16 * i - (size_t)trailing_unchanged);

		if (i >= i_end) {
			break;
		}
	}

	return dc;
}
