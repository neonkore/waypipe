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
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <arm_neon.h>

size_t run_interval_diff_neon(const int diff_window_size,
		const void *__restrict__ imod, void *__restrict__ ibase,
		uint32_t *__restrict__ diff, size_t i, const size_t i_end)
{
	const uint64_t *__restrict__ mod = imod;
	uint64_t *__restrict__ base = ibase;

	size_t dc = 0;
	while (1) {
		uint32_t *ctrl_blocks = &diff[dc];
		dc += 2;

		/* Loop: no changes */
		size_t trailing_unchanged = 0;
		for (; i < i_end; i++) {
			/* Q: does it make sense to unroll by 2, cutting branch
			 * count in half? */
			uint64x2_t b = vld1q_u64(&base[2 * i]);
			uint64x2_t m = vld1q_u64(&mod[2 * i]);
			uint64x2_t x = veorq_u64(m, b);
			uint32x2_t o = vqmovn_u64(x);
			uint64_t n = vget_lane_u64(vreinterpret_u64_u32(o), 0);
			if (n) {
				vst1q_u64(&base[2 * i], m);

				bool lead_empty = vget_lane_u32(o, 0) == 0;
				/* vtbl only works on u64 chunks, so we branch
				 * instead */
				if (lead_empty) {
					vst1_u64((uint64_t *)&diff[dc],
							vget_high_u64(m));
					trailing_unchanged = 0;
					ctrl_blocks[0] = (uint32_t)(4 * i + 2);
					dc += 2;
				} else {
					vst1q_u64((uint64_t *)&diff[dc], m);
					trailing_unchanged =
							2 *
							(vget_lane_u32(o, 1) ==
									0);
					ctrl_blocks[0] = (uint32_t)(4 * i);
					dc += 4;
				}
				trailing_unchanged = 0;

				i++;
				if (i >= i_end) {
					/* Last block, hence will not enter copy
					 * loop */
					ctrl_blocks[1] = (uint32_t)(4 * i);
					dc += 2;
				}

				break;
			}
		}
		if (i >= i_end) {
			dc -= 2;
			break;
		}

		/* Main copy loop */
		for (; i < i_end; i++) {
			uint64x2_t m = vld1q_u64(&mod[2 * i]);
			uint64x2_t b = vld1q_u64(&base[2 * i]);
			uint64x2_t x = veorq_u64(m, b);

			uint32x2_t o = vqmovn_u64(x);
			uint64_t n = vget_lane_u64(vreinterpret_u64_u32(o), 0);

			/* Reset trailing counter if anything changed */
			trailing_unchanged = trailing_unchanged * (n == 0);
			size_t nt = (size_t)((vget_lane_u32(o, 1) == 0) *
					     (1 + (vget_lane_u32(o, 0) == 0)));
			trailing_unchanged += 2 * nt;

			vst1q_u64((uint64_t *)&diff[dc], m);
			dc += 4;
			if (trailing_unchanged > (size_t)diff_window_size) {
				i++;
				break;
			}
			vst1q_u64(&base[2 * i], m);
		}
		/* Write coda */
		dc -= trailing_unchanged;
		ctrl_blocks[1] = (uint32_t)(4 * i - trailing_unchanged);
		if (i >= i_end) {
			break;
		}
	}

	return dc;
}
