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

#include <immintrin.h>

bool avx2_available(void) { return __builtin_cpu_supports("avx2"); }

int run_interval_diff_avx2(const int diff_window_size, const int i_end,
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
			__m256i m = _mm256_load_si256((const __m256i *)&mod[i]);
			__m256i b = _mm256_load_si256(
					(const __m256i *)&base[i]);
			__m256i eq = _mm256_cmpeq_epi64(m, b);
			uint32_t mask = (uint32_t)_mm256_movemask_epi8(eq);
			if (mask != 0xffffffff) {
				_mm256_store_si256((__m256i *)&base[i], m);

				/* Write the changed bytes, starting at the
				 * first modified term,
				 * and set the n_unchanged counter */
				int ncom = __builtin_ctz(~mask) >> 3;

				__m128i halfsize = _mm_set_epi64x(0uLL,
						0xffffffffuLL << (ncom * 8));
				__m256i storemask =
						_mm256_cvtepi8_epi64(halfsize);
				_mm256_maskstore_epi64(
						(long long *)&diff[dc - ncom],
						storemask, m);

				dc += 4 - ncom;
				trailing_unchanged =
						(~mask == 0) ? 4
							     : (__builtin_clz(~mask) >>
									       3);
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
			__m256i m = _mm256_load_si256((const __m256i *)&mod[i]);
			__m256i b = _mm256_load_si256(
					(const __m256i *)&base[i]);
			__m256i eq = _mm256_cmpeq_epi64(m, b);
			uint32_t mask = (uint32_t)_mm256_movemask_epi8(eq);

			/* Reset trailing counter if anything changed */
			trailing_unchanged = trailing_unchanged *
					     (mask == 0xffffffff);
			trailing_unchanged +=
					(~mask == 0) ? 4
						     : (__builtin_clz(~mask) >>
								       3);
			_mm256_storeu_si256((__m256i *)&diff[dc], m);
			dc += 4;
			if (trailing_unchanged > diff_window_size) {
				i += 4;
				break;
			}
			_mm256_store_si256((__m256i *)&base[i], m);
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
