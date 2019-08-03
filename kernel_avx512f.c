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

bool avx512f_available(void) { return __builtin_cpu_supports("avx512f"); }

int run_interval_diff_avx512f(const int diff_window_size, const int i_end,
		const uint64_t *__restrict__ mod, uint64_t *__restrict__ base,
		uint64_t *__restrict__ diff, int i)
{
	int dc = 0;
	while (1) {
		/* Loop: no changes */
		uint32_t *ctrl_blocks = (uint32_t *)&diff[dc++];

		int trailing_unchanged = 0;
		for (; i < i_end; i += 8) {
			__m512i m = _mm512_load_si512(&mod[i]);
			__m512i b = _mm512_load_si512(&base[i]);
			__mmask8 mask = _mm512_cmpeq_epi64_mask(m, b);
			if (mask != 0xff) {
				_mm512_store_si512(&base[i], m);

				int ncom = (int)_tzcnt_u32(~mask);
				__mmask8 storemask = (__mmask8)(0xffu << ncom);
#if 0
				__m512i v = _mm512_maskz_compress_epi64(
						storemask, m);
				_mm512_storeu_si512(&diff[dc], v);
#else
				_mm512_mask_storeu_epi64(
						&diff[dc - ncom], storemask, m);
#endif
				dc += 8 - ncom;

				trailing_unchanged =
						(int)_lzcnt_u32(~mask & 0xff) -
						24;
				ctrl_blocks[0] = i + ncom;

				i += 8;
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

		/* Loop: until an entire window is clear */
		for (; i < i_end; i += 8) {
			__m512i m = _mm512_load_si512(&mod[i]);
			__m512i b = _mm512_load_si512(&base[i]);
			__mmask8 mask = _mm512_cmpeq_epi64_mask(m, b);

			/* Reset trailing counter if anything changed */
			uint32_t amask = ~((uint32_t)mask << 24);
			bool clear = mask == 0xff;
			trailing_unchanged = clear * trailing_unchanged +
					     (_lzcnt_u32(amask));

			_mm512_storeu_si512(&diff[dc], m);
			dc += 8;
			if (trailing_unchanged > diff_window_size) {
				i += 8;
				break;
			}
			_mm512_store_si512(&base[i], m);
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
