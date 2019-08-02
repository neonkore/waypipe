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

bool avx2_available(void) { return __builtin_cpu_supports("avx2"); }

#ifdef __x86_64__
static inline int tzcnt(uint64_t v) { return (int)_tzcnt_u64(v); }
#else
static inline int tzcnt(uint64_t v) { return v ? __builtin_ctzll(v) : 64; }
#endif
#ifdef __x86_64__
static inline int lzcnt(uint64_t v) { return (int)_lzcnt_u64(v); }
#else
static inline int lzcnt(uint64_t v) { return v ? __builtin_clzll(v) : 64; }
#endif

int run_interval_diff_avx2(const int diff_window_size, const int i_end,
		const uint64_t *__restrict__ mod, uint64_t *__restrict__ base,
		uint64_t *__restrict__ diff, int i)
{
	int dc = 0;
	while (1) {
		/* Loop: no changes */
		uint32_t *ctrl_blocks = (uint32_t *)&diff[dc++];

		int trailing_unchanged = 0;
		for (; i < i_end; i += 8) {
			__m256i m0 = _mm256_load_si256(
					(const __m256i *)&mod[i]);
			__m256i m1 = _mm256_load_si256(
					(const __m256i *)&mod[i + 4]);
			__m256i b0 = _mm256_load_si256(
					(const __m256i *)&base[i]);
			__m256i b1 = _mm256_load_si256(
					(const __m256i *)&base[i + 4]);
			__m256i eq0 = _mm256_cmpeq_epi64(m0, b0);
			__m256i eq1 = _mm256_cmpeq_epi64(m1, b1);

			/* It's very hard to tell which loop exit method is
			 * better, since the routine is typically bandwidth
			 * limited */
#if 1
			uint32_t mask0 = (uint32_t)_mm256_movemask_epi8(eq0);
			uint32_t mask1 = (uint32_t)_mm256_movemask_epi8(eq1);
			uint64_t mask = mask0 + mask1 * 0x100000000uLL;
			if (~mask) {
#else
			__m256i andv = _mm256_and_si256(eq0, eq1);
			if (_mm256_testz_si256(andv, _mm256_set1_epi8(-1))) {
				uint32_t mask0 = (uint32_t)_mm256_movemask_epi8(
						eq0);
				uint32_t mask1 = (uint32_t)_mm256_movemask_epi8(
						eq1);
				uint64_t mask = mask0 + mask1 * 0x100000000uLL;
#endif
				_mm256_store_si256((__m256i *)&base[i], m0);
				_mm256_store_si256((__m256i *)&base[i + 4], m1);

				/* Write the changed bytes, starting at the
				 * first modified term,
				 * and set the n_unchanged counter */
				int ncom = tzcnt(~mask) >> 3;

#if 1
				int block_shift = ncom & 3;
				__m128i halfsize = _mm_set_epi64x(0uLL,
						0xffffffffuLL << (block_shift *
								  8));
				__m256i storemask =
						_mm256_cvtepi8_epi64(halfsize);
				_mm256_maskstore_epi64(
						(long long *)&diff[dc -
								   block_shift],
						storemask, ncom < 4 ? m0 : m1);
				if (ncom < 4) {
					_mm256_storeu_si256(
							(__m256i *)&diff[dc +
									 4 -
									 block_shift],
							m1);
				}
				dc += 8 - ncom;
#else
				for (unsigned int z = (unsigned int)ncom; z < 8;
						z++) {
					diff[dc++] = mod[i + z];
				}
#endif

				trailing_unchanged = lzcnt(~mask) >> 3;
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

		/* Loop: until no changes for DIFF_WINDOW +/- 4 spaces */
		for (; i < i_end; i += 8) {
			__m256i m0 = _mm256_load_si256(
					(const __m256i *)&mod[i]);
			__m256i m1 = _mm256_load_si256(
					(const __m256i *)&mod[i + 4]);
			__m256i b0 = _mm256_load_si256(
					(const __m256i *)&base[i]);
			__m256i b1 = _mm256_load_si256(
					(const __m256i *)&base[i + 4]);
			__m256i eq0 = _mm256_cmpeq_epi64(m0, b0);
			__m256i eq1 = _mm256_cmpeq_epi64(m1, b1);
			uint32_t mask0 = (uint32_t)_mm256_movemask_epi8(eq0);
			uint32_t mask1 = (uint32_t)_mm256_movemask_epi8(eq1);
			uint64_t mask = mask0 + mask1 * 0x100000000uLL;

			/* Reset trailing counter if anything changed */
			bool clear = ~mask == 0;
			trailing_unchanged = clear * trailing_unchanged +
					     (lzcnt(~mask) >> 3);

			_mm256_storeu_si256((__m256i *)&diff[dc], m0);
			_mm256_storeu_si256((__m256i *)&diff[dc + 4], m1);
			dc += 8;
			if (trailing_unchanged > diff_window_size) {
				i += 8;
				break;
			}
			_mm256_store_si256((__m256i *)&base[i], m0);
			_mm256_store_si256((__m256i *)&base[i + 4], m1);
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
