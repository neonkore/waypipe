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

#define _XOPEN_SOURCE 700
#include "util.h"

#include <stdlib.h>
#include <string.h>

/* This value must be larger than 8, or diffs will explode */
#define MERGE_MARGIN 1024

static inline int eint_low(const struct ext_interval *i) { return i->start; }
static inline int eint_high(const struct ext_interval *i)
{
	return i->start + (i->rep - 1) * i->stride + i->width;
}
static struct ext_interval containing_interval(
		const struct ext_interval *a, const struct ext_interval *b)
{
	int minv = min(eint_low(a), eint_low(b));
	int maxv = max(eint_high(a), eint_high(b));
	return (struct ext_interval){.start = minv,
			.width = maxv - minv,
			.rep = 1,
			.stride = 0};
}

/** Given two intervals A,B of matching stride, produce an interval containing
 * both, where start % stride matches A */
static struct ext_interval merge_fc_aligned(const struct ext_interval *a,
		const struct ext_interval *b, int common_stride)
{
	const int mod_a = a->start % common_stride;
	const int mod_b = b->start % common_stride;
	int width = mod_b + b->width - mod_a +
		    (mod_a > mod_b ? common_stride : 0);
	// Increase width to minimum level implied by e.g. long single intervals
	width = max(width, max(a->width, b->width));
	if (width >= common_stride - MERGE_MARGIN) {
		return containing_interval(a, b);
	}

	const int b_high = eint_high(b);
	int pre_shift = ceildiv(max(a->start - b->start, 0), common_stride);
	int post_shift = ceildiv(
			max(0, b_high - a->start - a->width), common_stride);

	int nreps = pre_shift + max(a->rep, post_shift);
	return (struct ext_interval){
			.start = a->start - common_stride * pre_shift,
			.width = width,
			.rep = nreps,
			.stride = nreps > 1 ? common_stride : 0};
}

/** Given two intervals, produce a third minimal /single/ interval which
 * contains both of them and has no internal gaps less than MERGE_MARGIN */
static struct ext_interval merge_fully_consumed(
		const struct ext_interval *a, const struct ext_interval *b)
{
	if ((a->rep > 1 && b->rep > 1 && a->stride != b->stride) ||
			(a->rep == 1 && b->rep == 1)) {
		// The logic for the first case is complicated and is unlikely
		// to happen in practice
		return containing_interval(a, b);
	}
	int stride = a->rep == 1 ? b->stride : a->stride;

	struct ext_interval a_aligned = merge_fc_aligned(a, b, stride);
	struct ext_interval b_aligned = merge_fc_aligned(b, a, stride);

	if (a_aligned.rep * a_aligned.width < b_aligned.rep * b_aligned.width) {
		return a_aligned;
	} else {
		return b_aligned;
	}
}
static struct ext_interval drop_tail(
		const struct ext_interval *a, int nreps_left)
{
	return (struct ext_interval){.start = a->start,
			.width = a->width,
			.rep = nreps_left,
			.stride = nreps_left > 1 ? a->stride : 0};
}
static struct ext_interval drop_head(
		const struct ext_interval *a, int nreps_left)
{
	return (struct ext_interval){
			.start = a->start + a->stride * (a->rep - nreps_left),
			.width = a->width,
			.rep = nreps_left,
			.stride = nreps_left > 1 ? a->stride : 0};
}

static struct ext_interval drop_ends(
		const struct ext_interval *a, int ncut_left, int ncut_right)
{
	int nreps_left = a->rep - ncut_left - ncut_right;
	return (struct ext_interval){.start = a->start + a->stride * ncut_left,
			.width = a->width,
			.rep = nreps_left,
			.stride = nreps_left > 1 ? a->stride : 0};
}

static uint32_t merge_contained(const struct ext_interval *outer,
		const struct ext_interval *inner,
		struct ext_interval o[static 3])
{
	if (outer->stride == 0 || outer->rep == 1) {
		// Fast exit, when one part is a solid interval
		o[0] = *outer;
		return 1;
	}

	/* [stride=5, start=0, width=3, rep=9]
	 * U [stride=5, start=17, width=2, rep=5]
	 *
	 * ===  ===  ===  ===  ===  ===  ===  ===  ===
	 *                  ==   ==   ==   ==   ==
	 * ===  ===  ===  ------------------------ ===
	 */
	int nlower = 0;
	int nupper = 0;
	if (outer->rep > 1) {
		int low_cutoff = eint_low(inner) - MERGE_MARGIN;
		nlower = ceildiv(low_cutoff - outer->start - outer->width,
				outer->stride);
		int high_cutoff = eint_high(inner) + MERGE_MARGIN + 1;
		nupper = outer->rep -
			 ceildiv(high_cutoff - outer->start, outer->stride);
	}

	if (nlower + nupper == outer->rep) {
		// No change: the new interval fits right in, between existing
		// ones
		return 0;
	}

	uint32_t n = 0;
	struct ext_interval couter = drop_ends(outer, nlower, nupper);
	o[n++] = merge_fully_consumed(inner, &couter);

	/* Adjust lower/upper after the fact, because merging the inner interval
	 * can expand the area covered the first/last subintervals in the
	 * central area, so that they conflict with the last/first elements in
	 * the first/last tails */
	if (outer->rep > 1) {
		int low_cutoff = eint_low(&o[0]) - MERGE_MARGIN;
		int high_cutoff = eint_high(&o[0]) + MERGE_MARGIN + 1;

		int nlower = ceildiv(low_cutoff - outer->start - outer->width,
				outer->stride);
		int nupper = outer->rep -
			     ceildiv(high_cutoff - outer->start, outer->stride);

		if (nlower > 0) {
			o[n++] = drop_tail(outer, nlower);
		}
		if (nupper > 0) {
			o[n++] = drop_head(outer, nupper);
		}
	}

	return n;
}

/** Merge assymmetric pair of intervals, assuming that neither is
 * any lower than the other */
static uint32_t merge_assym(const struct ext_interval *lower,
		const struct ext_interval *upper,
		struct ext_interval o[static 3])
{
	if (eint_high(lower) < eint_low(upper) - MERGE_MARGIN) {
		// No change, segments do not overlap
		return 0;
	}

	/* The prototypical example.
	 * ===  ===  ===  ===  ===  ===
	 *                  ==   ==   ==   ==   ==
	 * ===  ===  ===  --------------   ==   ==
	 */
	// numbers of upper and lower segments which do not participate in the
	// merge
	int nlower = 0;
	int nupper = 0;
	if (lower->rep > 1) {
		int cutoff = eint_low(upper) - MERGE_MARGIN;
		nlower = ceildiv(cutoff - lower->start - lower->width,
				lower->stride);
	}
	if (upper->rep > 1) {
		int cutoff = eint_high(lower) + MERGE_MARGIN + 1;
		nupper = upper->rep -
			 ceildiv(cutoff - upper->start, upper->stride);
	}

	uint32_t n = 0;
	struct ext_interval clower = drop_head(lower, lower->rep - nlower);
	struct ext_interval cupper = drop_tail(upper, upper->rep - nupper);
	o[n++] = merge_fully_consumed(&clower, &cupper);

	if (lower->rep > 1) {
		int low_cutoff = eint_low(&o[0]) - MERGE_MARGIN;
		int nlower = ceildiv(low_cutoff - lower->start - lower->width,
				lower->stride);
		if (nlower > 0) {
			o[n++] = drop_tail(lower, nlower);
		}
	}
	if (upper->rep > 1) {
		int high_cutoff = eint_high(&o[0]) + MERGE_MARGIN + 1;
		int nupper = upper->rep -
			     ceildiv(high_cutoff - upper->start, upper->stride);
		if (nupper > 0) {
			o[n++] = drop_head(upper, nupper);
		}
	}
	return n;
}

/** Given two intervals, merge them so that all intervals which were
 * disjoint (by more than MERGE_MARGIN) from both original intervals are
 * also disjoint from the merge result.
 *
 * If `ia` and `ib` are disjoint, then nothing is written to `o`. Otherwise,
 * this function writes between one and three disjoint intervals into `o`.
 * It returns the number of intervals written. */
static uint32_t merge_intervals(const struct ext_interval *a,
		const struct ext_interval *b, struct ext_interval o[static 3])
{
	/* Naive, but still very casework-intensive, solution: the overlapping
	 * portion of a series of intervals is replaced by a single solid
	 * interval, and the tail portions are extended. */
	int a_low = eint_low(a);
	int a_high = eint_high(a);
	int b_low = eint_low(b);
	int b_high = eint_high(b);

	if (a->stride == b->stride && (a->rep > 1 || b->rep > 1)) {
		/* Special case: merge two horizontally aligned buffers */
		int common_stride = a->rep > 1 ? a->stride : b->stride;
		int mod_a = a->start % common_stride,
		    mod_b = b->start % common_stride;
		if (a->width == b->width && mod_a == mod_b) {
			if (a->start + a->rep * a->stride == b->start) {
				o[0] = (struct ext_interval){
						.start = a->start,
						.width = a->width,
						.stride = common_stride,
						.rep = a->rep + b->rep,
				};
				return 1;
			}
			if (b->start + b->rep * b->stride == a->start) {
				o[0] = (struct ext_interval){
						.start = b->start,
						.width = b->width,
						.stride = common_stride,
						.rep = a->rep + b->rep,
				};
				return 1;
			}
		}

		/* Special case: don't merge two parallel buffers */
		if (mod_a > mod_b) {
			mod_b += common_stride;
		}
		int gap_ab = mod_b - (mod_a + a->width);
		if (mod_b > mod_a) {
			mod_a += common_stride;
		}
		int gap_ba = mod_a - (mod_b + b->width);
		if (gap_ab > MERGE_MARGIN && gap_ba > MERGE_MARGIN) {
			return 0;
		}
	}

	// TODO: combine consecutive regions with matching width (vstack)

	// Categorize by symmetry class
	if (a_low >= b_low && a_high <= b_high) {
		return merge_contained(b, a, o);
	}
	if (b_low >= a_low && b_high <= a_high) {
		return merge_contained(a, b, o);
	}
	if (a_low <= b_low) {
		return merge_assym(a, b, o);
	}
	if (b_low <= a_low) {
		return merge_assym(b, a, o);
	}
	abort();
}

/** If the internal gaps of an extended interval are too large, replace the
 * interval with a single contiguous block. Also, get rid of meaningless
 * strides */
static struct ext_interval smooth_gaps(struct ext_interval i)
{
	if (i.width > i.stride - MERGE_MARGIN) {
		i.width = i.stride * (i.rep - 1) + i.width;
		i.rep = 1;
	}
	if (i.rep == 1) {
		i.stride = 0;
	}
	return i;
}

bool check_subset_property(int nsup, const struct ext_interval *sup, int nsub,
		const struct ext_interval *sub, int nsup2,
		const struct ext_interval *sup2)
{
	// Verify that the new set of intervals covers the old.
	int minv = INT32_MAX, maxv = INT32_MIN;
	for (int i = 0; i < nsup; i++) {
		minv = min(minv, eint_low(&sup[i]));
		maxv = max(maxv, eint_high(&sup[i]));
	}
	for (int i = 0; i < nsup2; i++) {
		minv = min(minv, eint_low(&sup2[i]));
		maxv = max(maxv, eint_high(&sup2[i]));
	}
	for (int i = 0; i < nsub; i++) {
		minv = min(minv, eint_low(&sub[i]));
		maxv = max(maxv, eint_high(&sub[i]));
	}
	if (minv > maxv) {
		return true;
	}
	char *test = calloc(maxv - minv, 1);
	// Fast & stupid containment test
	for (int i = 0; i < nsub; i++) {
		struct ext_interval e = sub[i];
		for (int k = 0; k < e.rep; k++) {
			memset(&test[e.start + e.stride * k - minv], 1,
					e.width);
		}
	}
	for (int i = 0; i < nsup; i++) {
		struct ext_interval e = sup[i];
		for (int k = 0; k < e.rep; k++) {
			if (memchr(&test[e.start + e.stride * k - minv], 2,
					    e.width) != NULL) {
				wp_log(WP_ERROR, "Internal overlap fail, sup1");
				free(test);
				return false;
			}

			memset(&test[e.start + e.stride * k - minv], 2,
					e.width);
		}
	}
	for (int i = 0; i < nsup2; i++) {
		struct ext_interval e = sup2[i];
		for (int k = 0; k < e.rep; k++) {
			if (memchr(&test[e.start + e.stride * k - minv], 2,
					    e.width) != NULL) {
				wp_log(WP_ERROR, "Internal overlap fail, sup2");
				free(test);
				return false;
			}
			memset(&test[e.start + e.stride * k - minv], 2,
					e.width);
		}
	}
	bool yes = memchr(test, 1, maxv - minv) == NULL;
	int count = 0;
	if (!yes) {
		for (int i = 0; i < maxv - minv; i++) {
			count += test[i] == 1;
			if (test[i] == 1) {
				wp_log(WP_ERROR, "Fail at %d", i + minv);
			}
		}
		wp_log(WP_ERROR, "Fail count: %d/%d", count, maxv - minv);
	}
	free(test);
	return yes;
}

void merge_damage_records(struct damage *base, int nintervals,
		const struct ext_interval *const new_list)
{
	for (int i = 0; i < nintervals; i++) {
		base->acc_damage_stat += new_list[i].width * new_list[i].rep;
		base->acc_count++;
	}

	// Fast return if there is nothing to do
	if (base->damage == DAMAGE_EVERYTHING || nintervals <= 0) {
		return;
	}

	/* Naive merging. With each pass, introduce an additional interval.
	 * There will be at most a factor of 2 expansion, so we plan ahead by
	 * factor-4 expanding. */
	int space = max(base->ndamage_rects, 16) * 4;
	struct ext_interval *scratch =
			calloc(space, sizeof(struct ext_interval));
	memcpy(scratch, base->damage,
			base->ndamage_rects * sizeof(struct ext_interval));
	int used = base->ndamage_rects;

	// Standard dynamic resizing
	int queue_space = nintervals * 2;
	struct ext_interval *queue =
			calloc(nintervals * 2, sizeof(struct ext_interval));
	int z = 0;
	for (int i = 0; i < nintervals; i++) {
		queue[z++] = smooth_gaps(new_list[i]);
	}
	while (z > 0) {
		/* In each round, merge the incoming interval with every other
		 * interval in the list. When an element is absorbed (for
		 * instance, because it was entirely contained a large element),
		 * remove it from the list, and update the list as it is
		 * scanned. When an element is added, insert it into the rewrite
		 * gap, or if not possible, append it to the end of the list. */
		const struct ext_interval intv = queue[--z];

		int write_index = 0;
		bool intv_changed = false;
		int read_index = 0;
		for (; read_index < used;) {
			const struct ext_interval test = scratch[read_index++];

			struct ext_interval products[3];
			uint32_t ne = merge_intervals(&intv, &test, products);
			if (ne == 0) {
				// No change, keep inspected element unchanged
				scratch[write_index++] = test;
			} else {
				/* If a portion of the introduced interval was
				 * entirely contained by the existing interval,
				 * the existing interval is unchanged, and we
				 * keep it. */
				bool existing_unchanged = false;
				for (uint32_t s = 0; s < ne; s++) {
					if (!memcmp(&products[s], &test,
							    sizeof(struct ext_interval))) {
						existing_unchanged = true;
						memset(&products[s], 0,
								sizeof(struct ext_interval));
					}
				}
				if (existing_unchanged) {
					scratch[write_index++] = test;
				}

				/* If the introduced interval was unchanged,
				 * then we can continue with this loop, since
				 * all preceding merge operations are still
				 * correct */
				bool intv_unchanged = false;
				for (uint32_t s = 0; s < ne; s++) {
					if (!memcmp(&products[s], &intv,
							    sizeof(struct ext_interval))) {
						intv_unchanged = true;
						memset(&products[s], 0,
								sizeof(struct ext_interval));
					}
				}

				/* All new/modified elements must be
				 * reintroduced to the queue,
				 * because we cannot rule out collisions with
				 * preceding/following elements */
				if (z + (int)ne >= queue_space) {
					queue = realloc(queue,
							2 * queue_space *
									sizeof(struct ext_interval));
					memset(queue + z, 0,
							sizeof(struct ext_interval) *
									(queue_space * 2 -
											z));
					queue_space *= 2;
				}
				for (uint32_t x = 0; x < ne; x++) {
					if (products[x].width) {
						queue[z++] = products[x];
					}
				}

				if (!intv_unchanged) {
					intv_changed = true;
					break;
				}
			}
		}
		if (intv_changed) {
			/* Pass unsuccessful, fixing up any produced gaps */
			memmove(&scratch[write_index], &scratch[read_index],
					(used - read_index) *
							sizeof(struct ext_interval));
			used = write_index + used - read_index;
		} else {
			/* Pass was successful and did not modify the introduced
			 * interval */
			scratch[write_index++] = intv;
			used = write_index;
		}

		if (used + 1 >= space / 2) {
			space *= 2;
			struct ext_interval *nscratch = calloc(
					space, sizeof(struct ext_interval));
			memcpy(nscratch, scratch,
					sizeof(struct ext_interval) * used);
			free(scratch);
			scratch = nscratch;
		}
	}

	base->damage = realloc(
			base->damage, sizeof(struct ext_interval) * used);
	memcpy(base->damage, scratch, sizeof(struct ext_interval) * used);
	free(scratch);
	free(queue);
	base->ndamage_rects = used;
}
void get_damage_interval(const struct damage *base, int *minincl, int *maxexcl)
{
	if (base->damage == DAMAGE_EVERYTHING) {
		*minincl = INT32_MIN;
		*maxexcl = INT32_MAX;
	} else if (base->damage == NULL || base->ndamage_rects == 0) {
		*minincl = INT32_MAX;
		*maxexcl = INT32_MIN;
	} else {
		int low = INT32_MAX;
		int high = INT32_MIN;
		int final_set_cover = 0;
		for (int i = 0; i < base->ndamage_rects; i++) {
			struct ext_interval *v = &base->damage[i];
			low = min(low, v->start);
			high = max(high, v->start + (v->rep - 1) * v->stride +
							 v->width);

			final_set_cover += v->rep * v->width;
		}
		double cover_fraction =
				base->acc_damage_stat / (double)final_set_cover;
		wp_log(WP_DEBUG,
				"Damage interval: {%d(%d)} -> [%d, %d) [%d], %f",
				base->ndamage_rects, base->acc_count, low, high,
				final_set_cover, cover_fraction);

		*minincl = low;
		*maxexcl = high;
	}
}
void reset_damage(struct damage *base)
{
	if (base->damage != DAMAGE_EVERYTHING) {
		free(base->damage);
	}
	base->damage = NULL;
	base->ndamage_rects = 0;
	base->acc_damage_stat = 0;
	base->acc_count = 0;
}
void damage_everything(struct damage *base)
{
	if (base->damage != DAMAGE_EVERYTHING) {
		free(base->damage);
	}
	base->damage = DAMAGE_EVERYTHING;
	base->ndamage_rects = 0;
}
