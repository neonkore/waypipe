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
#ifndef WAYPIPE_INTERVAL_H
#define WAYPIPE_INTERVAL_H

#include <stdint.h>

/** A slight modification of the standard 'damage' rectangle
 * formulation, written to be agnostic of whatever buffers
 * underlie the system.
 *
 * [start,start+width),[start+stride,start+stride+width),
 * ... [start+(rep-1)*stride,start+(rep-1)*stride+width) */
struct ext_interval {
	int32_t start;
	/** Subinterval width */
	int32_t width;
	/** Number of distinct subinterval start positions. For a single
	 * interval, this is one. */
	int32_t rep;
	/** Spacing between start positions, should be > width, unless
	 * the is only one subinterval, in which case the value shouldn't
	 * matter and is conventionally set to 0. */
	int32_t stride;
};
/** [start, end). (This is better than {start,width}, since width computations
 * are rare and trivial, while merging code branches frequently off of
 * endpoints) */
struct interval {
	int32_t start;
	int32_t end;
};

#define DAMAGE_EVERYTHING ((struct interval *)-1)

/** Interval-based damage tracking. If damage is NULL, there is
 * no recorded damage. If damage is DAMAGE_EVERYTHING, the entire
 * region should be updated. If ndamage_intvs > 0, then
 * damage points to an array of struct interval objects. */
struct damage {
	struct interval *damage;
	int ndamage_intvs;

	int64_t acc_damage_stat;
	int acc_count;
};

/** Given an array of extended intervals, update the base damage structure
 * so that it contains a reasonably small disjoint set of extended intervals
 * which contains the old base set and the new set. Before merging, all
 * interval boundaries will be rounded to the next multiple of
 * `1 << alignment_bits`. */
void merge_damage_records(struct damage *base, int nintervals,
		const struct ext_interval *const new_list, int alignment_bits);
/** Set damage to empty  */
void reset_damage(struct damage *base);
/** Expand damage to cover everything */
void damage_everything(struct damage *base);

/* internal merge driver, made visible for testing */
void merge_mergesort(const int old_count, struct interval *old_list,
		const int new_count, const struct ext_interval *const new_list,
		int *dst_count, struct interval **dst_list, int merge_margin,
		int alignment_bits);

#endif // WAYPIPE_INTERVAL_H
