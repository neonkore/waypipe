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

#include <arm_neon.h>

#if defined(__linux__) && defined(__arm__)
#include <asm/hwcap.h>
#include <sys/auxv.h>
#elif defined(__FreeBSD__) && defined(__arm__)
#include <sys/auxv.h>
#endif

bool neon_available(void)
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
		uint64_t *__restrict__ diff, int i)
{
	int dc = 0;
	while (1) {
		uint32_t *ctrl_blocks = (uint32_t *)&diff[dc++];

		/* Loop: no changes */
		int trailing_unchanged = 0;
		for (; i < i_end; i += 2) {
			/* Q: does it make sense to unroll by 2, cutting branch
			 * count in half? */
			uint64x2_t b = vld1q_u64(&base[i]);
			uint64x2_t m = vld1q_u64(&mod[i]);
			uint64x2_t x = veorq_u64(m, b);
			uint32x2_t o = vqmovn_u64(x);
			uint64_t n = vget_lane_u64(vreinterpret_u64_u32(o), 0);
			if (n) {
				vst1q_u64(&base[i], m);

				bool lead_empty = vget_lane_u32(o, 0) == 0;
				/* vtbl only works on u64 chunks, so we branch
				 * instead */
				if (lead_empty) {
					vst1_u64(&diff[dc], vget_high_u64(m));
					trailing_unchanged = 0;
					ctrl_blocks[0] = i + 1;
					dc++;
				} else {
					vst1q_u64(&diff[dc], m);
					trailing_unchanged =
							vget_lane_u32(o, 1) ==
							0;
					ctrl_blocks[0] = i;
					dc += 2;
				}

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

		/* Main copy loop */
		for (; i < i_end; i += 2) {
			uint64x2_t m = vld1q_u64(&mod[i]);
			uint64x2_t b = vld1q_u64(&base[i]);
			uint64x2_t x = veorq_u64(m, b);

			uint32x2_t o = vqmovn_u64(x);
			uint64_t n = vget_lane_u64(vreinterpret_u64_u32(o), 0);

			/* Reset trailing counter if anything changed */
			trailing_unchanged = trailing_unchanged * (n == 0);
			int nt = (vget_lane_u32(o, 1) == 0) *
				 (1 + (vget_lane_u32(o, 0) == 0));
			trailing_unchanged += nt;

			vst1q_u64(&diff[dc], m);
			dc += 2;
			if (trailing_unchanged > diff_window_size) {
				i += 2;
				break;
			}
			vst1q_u64(&base[i], m);
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
