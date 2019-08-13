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

size_t run_interval_diff_avx2(const int diff_window_size,
		const void *__restrict__ imod, void *__restrict__ ibase,
		uint32_t *__restrict__ diff, size_t i, const size_t i_end)
{
	const __m256i *__restrict__ mod = imod;
	__m256i *__restrict__ base = ibase;

	size_t dc = 0;
	while (1) {
		/* Loop: no changes */
		uint32_t *ctrl_blocks = &diff[dc];
		dc += 2;

		int trailing_unchanged = 0;
		for (; i < i_end; i++) {
			__m256i m0 = _mm256_load_si256(&mod[2 * i]);
			__m256i m1 = _mm256_load_si256(&mod[2 * i + 1]);
			__m256i b0 = _mm256_load_si256(&base[2 * i]);
			__m256i b1 = _mm256_load_si256(&base[2 * i + 1]);
			__m256i eq0 = _mm256_cmpeq_epi32(m0, b0);
			__m256i eq1 = _mm256_cmpeq_epi32(m1, b1);

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
				_mm256_store_si256(&base[2 * i], m0);
				_mm256_store_si256(&base[2 * i + 1], m1);

				/* Write the changed bytes, starting at the
				 * first modified term,
				 * and set the n_unchanged counter */
				size_t ncom = (size_t)tzcnt(~mask) >> 2;

				size_t block_shift = (ncom & 7);
				uint64_t esmask = 0xffffffffuLL
						  << (block_shift * 4);
				__m128i halfsize = _mm_set_epi64x(
						0uLL, (long long)esmask);
				__m256i estoremask =
						_mm256_cvtepi8_epi64(halfsize);
				_mm256_maskstore_epi32(
						(int *)&diff[dc - block_shift],
						estoremask, ncom < 8 ? m0 : m1);
				if (ncom < 8) {
					_mm256_storeu_si256(
							(__m256i *)&diff[dc +
									 8 -
									 block_shift],
							m1);
				}
				dc += 16 - ncom;

				trailing_unchanged = lzcnt(~mask) >> 2;
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

		/* Loop: until no changes for DIFF_WINDOW +/- 4 spaces */
		for (; i < i_end; i++) {
			__m256i m0 = _mm256_load_si256(&mod[2 * i]);
			__m256i m1 = _mm256_load_si256(&mod[2 * i + 1]);
			__m256i b0 = _mm256_load_si256(&base[2 * i]);
			__m256i b1 = _mm256_load_si256(&base[2 * i + 1]);
			__m256i eq0 = _mm256_cmpeq_epi32(m0, b0);
			__m256i eq1 = _mm256_cmpeq_epi32(m1, b1);
			uint32_t mask0 = (uint32_t)_mm256_movemask_epi8(eq0);
			uint32_t mask1 = (uint32_t)_mm256_movemask_epi8(eq1);
			uint64_t mask = mask0 + mask1 * 0x100000000uLL;

			/* Reset trailing counter if anything changed */
			bool clear = ~mask == 0;
			trailing_unchanged = clear * trailing_unchanged +
					     (lzcnt(~mask) >> 2);

			_mm256_storeu_si256((__m256i *)&diff[dc], m0);
			_mm256_storeu_si256((__m256i *)&diff[dc + 8], m1);
			dc += 16;
			if (trailing_unchanged > diff_window_size) {
				i++;
				break;
			}
			_mm256_store_si256(&base[2 * i], m0);
			_mm256_store_si256(&base[2 * i + 1], m1);
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
