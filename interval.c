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
#define MERGE_MARGIN 128

static inline int eint_low(const struct ext_interval *i) { return i->start; }
static inline int eint_high(const struct ext_interval *i)
{
	return i->start + (i->rep - 1) * i->stride + i->width;
}

static int emargin(const struct ext_interval *ia, const struct ext_interval *ib)
{
	int ia_low = eint_low(ia);
	int ia_high = eint_high(ia);
	int ib_low = eint_low(ib);
	int ib_high = eint_high(ib);

	if (ia_high < ib_low) {
		return ib_low - ia_high;
	}
	if (ia_low > ib_high) {
		return ia_low - ib_high;
	}
	return 0;
}

/** Are there no more than `margin` bytes of space between consecutive
 * subintervals? */
static bool koverlap(const struct ext_interval *ia,
		const struct ext_interval *ib, int margin)
{
	return emargin(ia, ib) <= margin;
}
int check_disjoint(int N, const struct ext_interval *intervals)
{
	int noverlapping = 0;
	for (int j = 0; j < N; j++) {
		for (int k = 0; k < j; k++) {
			noverlapping += koverlap(&intervals[k], &intervals[j],
					MERGE_MARGIN);
			if (koverlap(&intervals[k], &intervals[j],
					    MERGE_MARGIN)) {
				wp_log(WP_ERROR, "%d %d", k, j);
			}
		}
	}
	return noverlapping;
}
/** Given two intervals, produce a third minimal /single/ interval which
 * contains both of them and has no internal gaps less than MERGE_MARGIN */
static struct ext_interval merge_fully_consumed(
		const struct ext_interval *a, const struct ext_interval *b)
{
	// Interval style merge: TODO, replace with 'smallest containing
	// tororectangle'
	int minv = min(eint_low(a), eint_low(b));
	int maxv = max(eint_high(a), eint_high(b));
	return (struct ext_interval){.start = minv,
			.width = maxv - minv,
			.rep = 1,
			.stride = 0};
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

static int merge_contained(const struct ext_interval *outer,
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
		nlower = floordiv(low_cutoff - outer->width - outer->start,
				outer->stride);
		int high_cutoff = eint_high(inner) + MERGE_MARGIN + 1;
		nupper = outer->rep -
			 ceildiv(high_cutoff - outer->start, outer->stride);
	}

	int n = 0;
	if (nlower > 0) {
		o[n++] = drop_tail(outer, nlower);
	}
	struct ext_interval couter = drop_ends(outer, nlower, nupper);
	o[n++] = merge_fully_consumed(inner, &couter);
	if (nupper > 0) {
		o[n++] = drop_head(outer, nupper);
	}

	return n;
}

/** Merge assymmetric pair of intervals, assuming that neither is
 * any lower than the other */
static int merge_assym(const struct ext_interval *lower,
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
		nlower = floordiv(cutoff - lower->width - lower->start,
				lower->stride);
	}
	if (upper->rep > 1) {
		int cutoff = eint_high(lower) + MERGE_MARGIN + 1;
		nupper = upper->rep -
			 ceildiv(cutoff - upper->start, upper->stride);
	}

	int n = 0;
	if (nlower > 0) {
		o[n++] = drop_tail(lower, nlower);
	}
	struct ext_interval clower = drop_head(lower, lower->rep - nlower);
	struct ext_interval cupper = drop_tail(upper, upper->rep - nupper);
	o[n++] = merge_fully_consumed(&clower, &cupper);
	if (nupper > 0) {
		o[n++] = drop_head(upper, nupper);
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
static int merge_intervals(const struct ext_interval *ia,
		const struct ext_interval *ib, struct ext_interval o[static 3])
{
	/* Naive, but still very casework-intensive, solution: the overlapping
	 * portion of a series of intervals is replaced by a single solid
	 * interval, and the tail portions are extended. */
	int a_low = eint_low(ia);
	int a_high = eint_high(ia);
	int b_low = eint_low(ib);
	int b_high = eint_high(ib);

	// Categorize by symmetry class
	if (a_low >= b_low && a_high <= b_high) {
		return merge_contained(ib, ia, o);
	}
	if (b_low >= a_low && b_high <= a_high) {
		return merge_contained(ia, ib, o);
	}
	if (a_low <= b_low) {
		return merge_assym(ia, ib, o);
	}
	if (b_low <= a_low) {
		return merge_assym(ib, ia, o);
	}
	abort();
}

/* If the internal gaps of an extended interval are too large, replace the
 * interval with a single contiguous block. Also, get rid of meaningless
 * strides */
static void smooth_gaps(struct ext_interval *i)
{
	if (i->width > i->stride - MERGE_MARGIN) {
		i->width = i->stride * (i->rep - 1) + i->width;
		i->rep = 1;
	}
	if (i->rep == 1) {
		i->stride = 0;
	}
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
	memcpy(queue, new_list, nintervals * sizeof(struct ext_interval));

	int z = nintervals;
	while (z > 0) {
		/* In each round, merge the incoming interval with every other
		 * interval in the list. When an element is absorbed (for
		 * instance, because it was entirely contained a large element),
		 * remove it from the list, and update the list as it is
		 * scanned. When an element is added, insert it into the rewrite
		 * gap, or if not possible, append it to the end of the list. */
		struct ext_interval intv = queue[--z];
		smooth_gaps(&intv);

		int write_index = 0;
		for (int i = 0; i < used; i++) {
			if (i > write_index) {
				// If there is a gap, advance the next element
				// to be tested
				scratch[write_index] = scratch[i];
				memset(&scratch[i], 0, sizeof(scratch[i]));
			}

			struct ext_interval products[3];
			int ne = merge_intervals(
					&intv, &scratch[write_index], products);
			if (ne == 0) {
				// No change, keep inspected element unchanged
				write_index++;
			} else if (ne >= 1) {
				// Clear the field, carry the result, and write
				// nothing
				memset(&scratch[write_index], 0,
						sizeof(scratch[write_index]));
				intv = products[0];

				/* We cannot rule out that the 'shards' of the
				 * merge operation do not intersect any other
				 * elements. Consequently, we must requeue them.
				 * (Fortunately, we can continue intersecting
				 * one of the intervals, because we know by
				 * construction that it intersects no previous
				 * intervals */
				if (z + ne - 1 >= queue_space) {
					queue = realloc(queue,
							2 * queue_space *
									sizeof(struct ext_interval));
					memset(queue + z, 0,
							sizeof(struct ext_interval) *
									(queue_space * 2 -
											z));
					queue_space *= 2;
				}
				for (int x = 1; x < ne; x++) {
					queue[z++] = products[x];
				}
			}
		}
		scratch[write_index++] = intv;
		used = write_index;

		for (int i = 0; i < used; i++) {
			if (scratch[i].rep == 0) {
				wp_log(WP_ERROR,
						"Warning, empty field at %d (used=%d)",
						i, used);
			}
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

		int noverlapping = check_disjoint(
				base->ndamage_rects, base->damage);
		if (noverlapping) {
			wp_log(WP_ERROR, "Overlaps: %d", noverlapping);
		}

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
