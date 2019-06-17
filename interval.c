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

static inline int eint_low(const struct ext_interval i) { return i.start; }
static inline int eint_high(const struct ext_interval i)
{
	return i.start + (i.rep - 1) * i.stride + i.width;
}
static inline bool eint_eq(struct ext_interval a, struct ext_interval b)
{
	return !memcmp(&a, &b, sizeof(struct ext_interval));
}

static struct ext_interval containing_interval(
		const struct ext_interval a, const struct ext_interval b)
{
	int minv = min(eint_low(a), eint_low(b));
	int maxv = max(eint_high(a), eint_high(b));
	return (struct ext_interval){.start = minv,
			.width = maxv - minv,
			.rep = 1,
			/* todo: is this used anywhere ? */
			.stride = max(a.stride, b.stride)};
}

/* Given an interval `i` with rep > 1, divide it into three parts:
 * one which has no components intersecting or above low_cut, one
 * which has no components intersecting or below high cut, and one
 * remaining component. All `out` fields will be written in (low,mid,high)
 * order, but empty fields will be set to be all zero. */
static void split_interval(struct ext_interval i, int low_cut, int high_cut,
		struct ext_interval out[static 3])
{
	/* Number of subintervals below `low_cut`, excluding those overlapping
	 * with it */
	int il = floordiv(max(low_cut - i.start - i.width + i.stride, 0),
			i.stride);
	int ih = ceildiv(max(high_cut - i.start, 0), i.stride);
	/* clipping logic, in case our interval is large */
	ih = min(ih, i.rep);

	memset(out, 0, sizeof(struct ext_interval) * 3);
	if (il > 0 && il < i.rep) {
		out[0] = (struct ext_interval){.start = i.start,
				.width = i.width,
				.rep = il,
				.stride = i.stride

		};
	}

	/* for example, can split an interval with a noop injection */
	if (ih > il) {
		out[1] = (struct ext_interval){.start = i.start + il * i.stride,
				.width = i.width,
				.rep = ih - il,
				.stride = i.stride};
	}

	if (ih > 0 && ih < i.rep) {
		out[2] = (struct ext_interval){.start = i.start + ih * i.stride,
				.width = i.width,
				.rep = i.rep - ih,
				.stride = i.stride

		};
	}
}

/** Given two intervals A,B, merge them to produce a set of <= three rectangles
 * so that the new set covers the old, but contains no points outside the
 * range of the original intervals, and does not add any points more than
 * than the merge margin away from the intersection of the ranges of A and B.
 *
 * Furthermore, it is assumed that A, B do not have any internal gaps of
 * size < the margin. The resulting set will have any gaps of size <
 * merge_margin either.
 *
 * This function returns a number from 0 to 3; if 0, there was no change to A
 * and B. If larger, that number of margin-disjoint intervals are written into
 * `o`. */
uint32_t merge_intervals(struct ext_interval a, struct ext_interval b,
		struct ext_interval o[static 3], int merge_margin)
{
	if (a.width <= 0 || b.width <= 0 || a.rep <= 0 || b.rep <= 0) {
		wp_log(WP_ERROR,
				"Invalid entry format, Aswrs=%d,%d,%d,%d Bswrs=%d,%d,%d,%d",
				a.start, a.width, a.rep, a.stride, b.start,
				b.width, b.rep, b.stride);
		return 0;
	}

	/* a is lower/outer, b is upper/inner */
	if (a.start > b.start) {
		struct ext_interval tmp = b;
		b = a;
		a = tmp;
	}

	if (a.rep == 1 && b.rep == 1) {
		/* 1 to 1 merge: combine if strides permit. (Q: leave for
		 * postprocessing step?) */
		if (a.stride == b.stride && a.width == b.width &&
				a.start + a.stride == b.start &&
				a.width <= a.stride - merge_margin &&
				b.width <= b.stride - merge_margin) {
			o[0] = (struct ext_interval){
					.start = a.start,
					.width = a.width,
					.stride = a.stride,
					.rep = 2,
			};
			return 1;
		} else if (eint_high(a) + merge_margin <= eint_low(b)) {
			return 0;
		} else {
			o[0] = containing_interval(a, b);
			return 1;
		}
	} else if (a.rep == 1 || b.rep == 1) {
		/* 1 to K merge; extending if possible */
		struct ext_interval ser = a.rep == 1 ? b : a;
		struct ext_interval intv = a.rep == 1 ? a : b;

		int low_cutoff = eint_low(intv) - merge_margin;
		int high_cutoff = eint_high(intv) + merge_margin;

		if (eint_low(ser) >= high_cutoff) {
			return 0;
		}
		if (eint_high(ser) <= low_cutoff) {
			return 0;
		}
		/* we definitely do have some manner of intersection */
		struct ext_interval parts[3];
		split_interval(ser, low_cutoff, high_cutoff, parts);

		if (parts[1].rep == 0) {
			/* the simple interval does not intersect
			 * within margin with any series subinterveals */
			return 0;
		}
		struct ext_interval mid = containing_interval(parts[1], intv);
		if (eint_eq(mid, parts[1])) {
			/* the simple interval is entirely contained
			 * by an existing subinterval of the series */
			o[0] = ser;
			return 1;
		}
		/* return all three parts, if they exist */
		uint32_t n = 0;
		if (parts[0].rep > 0) {
			o[n++] = parts[0];
		}
		o[n++] = mid;
		if (parts[2].rep > 0) {
			o[n++] = parts[2];
		}
		return n;
	} else {
		/* there must be overlap within margin of the limits
		 * for anything nontrivial to happen */
		if (eint_high(a) + merge_margin <= eint_low(b)) {
			return 0;
		}
		int common_low = eint_low(b) -
				 merge_margin; // since a.start < b.start
		int common_high =
				min(eint_high(a), eint_high(b)) + merge_margin;

		/* K to J merge; fall back to brute force,
		 * and to a 'reconstruct' run */
		if (a.stride != b.stride) {
			/* stride-mismatched; this can produce a large number
			 * of small intervals, and is somewhat complicated.
			 * For now we just merge the common stride. */

			if (common_low >= common_high) {
				wp_log(WP_ERROR, "Unexpected");
				return 0;
			}

			struct ext_interval aparts[3], bparts[3];
			split_interval(a, common_low, common_high, aparts);
			split_interval(b, common_low, common_high, bparts);

			uint32_t n = 0;
			/* since a.start < b.start, bparts[0] DNE */
			if (aparts[0].rep > 0) {
				o[n++] = aparts[0];
			}
			/* both central parts exist due to overlap */
			o[n++] = containing_interval(aparts[1], bparts[1]);
			/* which tail is there depends on which end is last,
			 * and extra alignment info */
			if (aparts[2].rep > 0) {
				o[n++] = aparts[2];
			} else if (bparts[2].rep > 0) {
				o[n++] = bparts[2];
			}
			return n;
		} else {
			int stride = a.stride;

			/* key tests: overlaps and gaps */
			int mod_gap = (b.start - a.start) % stride;
			if (mod_gap < 0) {
				mod_gap += stride;
			}

			/* aext, bext: if the gap to the next subinterval class
			 * mod stride is 'negative' or < margin */
			bool aext = mod_gap < a.width + merge_margin;
			bool bext = mod_gap + b.width + merge_margin > stride;
			if (!aext && !bext) {
				/* Neither the A intervals nor the B intervals
				 * can be extended by less than margin to
				 * contain the other class; ergo, no change */
				return 0;
			}

			struct ext_interval aparts[3], bparts[3];
			split_interval(a, common_low, common_high, aparts);
			split_interval(b, common_low, common_high, bparts);

			uint32_t n = 0;
			if (aparts[0].rep > 0) {
				o[n++] = aparts[0];
			}

			if (aext && !bext) {
				if (aparts[1].rep != bparts[1].rep ||
						bparts[1].start <
								aparts[1].start) {
					wp_log(WP_ERROR,
							"Implicit rectangle extension assumptions violated");
					abort();
				}

				aparts[1].width =
						max(a.width, mod_gap + b.width);
				o[n++] = aparts[1];
			} else if (bext && !aext) {
				if (aparts[1].rep != bparts[1].rep ||
						aparts[1].start <
								bparts[1].start) {
					wp_log(WP_ERROR,
							"Implicit rectangle extension assumptions violated");
					abort();
				}

				bparts[1].width = max(b.width,
						a.width + stride - mod_gap);
				o[n++] = bparts[1];
			} else {
				/* aext && bext: Both can be extended, so cover
				 * with a simple interval */
				o[n++] = containing_interval(
						aparts[1], bparts[1]);
			}
			if (aparts[2].rep > 0) {
				o[n++] = aparts[2];
			} else if (bparts[2].rep > 0) {
				o[n++] = bparts[2];
			}
			return n;
		}
	}
}

/** If the internal gaps of an extended interval are too large, replace
 * the interval with a single contiguous block. Also, get rid of
 * meaningless strides */
static struct ext_interval smooth_gaps(struct ext_interval i, int merge_margin)
{
	if (i.width > i.stride - merge_margin) {
		i.width = i.stride * (i.rep - 1) + i.width;
		i.rep = 1;
	}
	return i;
}

/* Yet another binary heap implementation. Supports heapify/pop_min/insert.
 * indexes start at 1. */
struct eint_heap {
	struct ext_interval *data;
	int data_size;
	int count;
};
static void eint_fix_down(struct eint_heap *heap, int s)
{
	struct ext_interval carry = heap->data[s];
	int n = s;
	while (2 * n <= heap->count) {
		bool right_swap = 2 * n < heap->count &&
				  heap->data[2 * n + 1].start <
						  heap->data[2 * n].start;
		int c = right_swap ? 2 * n + 1 : 2 * n;
		if (carry.start > heap->data[c].start) {
			heap->data[n] = heap->data[c];
		} else {
			break;
		}
		n = c;
	}
	heap->data[n] = carry;
}
static void eint_heap_create(struct eint_heap *heap, int nintervals,
		const struct ext_interval *intervals)
{
	int sz = 1;
	while (sz < nintervals) {
		sz *= 2;
	}
	heap->data_size = sz;
	struct ext_interval *data = calloc(sz, sizeof(struct ext_interval));
	heap->data = &data[-1];
	heap->count = nintervals;
	memcpy(heap->data + 1, intervals,
			sizeof(struct ext_interval) * nintervals);

	/* standard heapify */
	for (int s = heap->count / 2; s > 0; s--) {
		eint_fix_down(heap, s);
	}
}
static void eint_heap_destroy(struct eint_heap *heap) { free(&heap->data[1]); }
static struct ext_interval eint_heap_pop_min(struct eint_heap *heap)
{
	struct ext_interval v = heap->data[1];
	heap->data[1] = heap->data[heap->count];
	heap->count--;
	eint_fix_down(heap, 1);
	return v;
}
static void eint_heap_insert(struct eint_heap *heap, struct ext_interval v)
{
	if (heap->count >= heap->data_size) {
		heap->data_size *= 2;
		struct ext_interval *e = realloc(&heap->data[1],
				sizeof(struct ext_interval) * heap->data_size);
		heap->data = &e[-1];
	}
	heap->count++;
	int i = heap->count;
	while (i > 1) {
		int p = i / 2;
		if (heap->data[p].start <= v.start) {
			break;
		}
		heap->data[i] = heap->data[p];
		i = p;
	}
	heap->data[i] = v;
}
struct eint_list {
	struct ext_interval *data;
	int data_size;
	int count;
};

static void eint_list_create(struct eint_list *list, int sz)
{
	int ds = 1;
	while (ds < sz) {
		ds *= 2;
	}
	list->count = 0;
	list->data_size = ds;
	list->data = calloc(list->data_size, sizeof(struct ext_interval));
}

static void eint_list_insert(struct eint_list *list, struct ext_interval e)
{
	if (list->count == list->data_size) {
		list->data_size *= 2;
		struct ext_interval *ret = realloc(list->data,
				list->data_size * sizeof(struct ext_interval));
		/* failure handling, todo */
		list->data = ret;
	}
	list->data[list->count++] = e;
}

void merge_core(const int old_count, struct ext_interval *old_list,
		const int new_count, const struct ext_interval *const new_list,
		int *dst_count, struct ext_interval **dst_list,
		int merge_margin)
{
	/* todo, limit number of copies */
	struct ext_interval *src = malloc(
			(old_count + new_count) * sizeof(struct ext_interval));
	memcpy(src, old_list, old_count * sizeof(struct ext_interval));
	int count = old_count;
	for (int i = 0; i < new_count; i++) {
		struct ext_interval e = smooth_gaps(new_list[i], merge_margin);
		if (e.rep && e.width) {
			src[count++] = e;
		}
	}

	struct eint_heap queue;
	eint_heap_create(&queue, count, src);
	free(src);

	struct eint_list pool, log;
	eint_list_create(&pool, 4);
	eint_list_create(&log, 4);

	/* the scan-based algorithm maintains three collections, and
	 * a cursor scanning from the minimum to the maximum start value:
	 * -> a `log` of intervals which will no longer be modified
	 * -> a `pool` of margin-disjoint intervals
	 * -> a `queue` of intervals to be merged into the pool */
	while (queue.count) {
		const struct ext_interval intv = eint_heap_pop_min(&queue);
		int cursor = intv.start - merge_margin;

		/* Extend pool with new element, recycle */
		int w = 0;
		bool intv_changed = false;
		int r = 0;
		for (; r < pool.count;) {
			const struct ext_interval test = pool.data[r++];
			if (eint_high(test) <= cursor) {
				/* no interaction possible with this or any
				 * future elements */
				eint_list_insert(&log, test);
				continue;
			}

			struct ext_interval products[3];
			uint32_t ne = merge_intervals(
					intv, test, products, merge_margin);
			if (ne == 0) {
				// No change, keep inspected element
				// unchanged
				pool.data[w++] = test;
			} else {
				/* If a portion of the introduced
				 * interval was entirely contained by
				 * the existing interval, the existing
				 * interval is unchanged, and we keep
				 * it. */
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
					pool.data[w++] = test;
				}

				/* If the introduced interval was
				 * unchanged, then we can continue with
				 * this loop, since all preceding merge
				 * operations are still correct */
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
				 * because we cannot rule out collisions
				 * with preceding/following elements */
				for (uint32_t x = 0; x < ne; x++) {
					if (products[x].width) {
						eint_heap_insert(&queue,
								products[x]);
					}
				}

				if (!intv_unchanged) {
					intv_changed = true;
					break;
				}
			}
		}
		if (intv_changed) {
			/* Pass unsuccessful, fixing up any produced
			 * gaps */
			memmove(&pool.data[w], &pool.data[r],
					(pool.count - r) *
							sizeof(struct ext_interval));
			pool.count = w + pool.count - r;
		} else {
			pool.count = w;
			eint_list_insert(&pool, intv);
		}
	}

	/* flush pool remainders to log */
	struct ext_interval *retdata = realloc(log.data,
			(log.count + pool.count) * sizeof(struct ext_interval));
	memcpy(retdata + log.count, pool.data,
			pool.count * sizeof(struct ext_interval));
	*dst_count = log.count + pool.count;
	*dst_list = retdata;

	free(pool.data);
	eint_heap_destroy(&queue);
}

/* This value must be larger than 8, or diffs will explode */
#define MERGE_MARGIN 1024
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

	merge_core(base->ndamage_rects, base->damage, nintervals, new_list,
			&base->ndamage_rects, &base->damage, MERGE_MARGIN);
}

void get_damage_interval(const struct damage *base, int *minincl, int *maxexcl,
		int *total_covered_area)
{
	if (base->damage == DAMAGE_EVERYTHING) {
		*minincl = INT32_MIN;
		*maxexcl = INT32_MAX;
		*total_covered_area = INT32_MAX;
	} else if (base->damage == NULL || base->ndamage_rects == 0) {
		*minincl = INT32_MAX;
		*maxexcl = INT32_MIN;
		*total_covered_area = 0;
	} else {
		int low = INT32_MAX;
		int high = INT32_MIN;
		int tca = 0;
		for (int i = 0; i < base->ndamage_rects; i++) {
			struct ext_interval *v = &base->damage[i];
			low = min(low, v->start);
			high = max(high, v->start + (v->rep - 1) * v->stride +
							 v->width);

			tca += v->rep * v->width;
		}
		double cover_fraction = base->acc_damage_stat / (double)tca;
		wp_log(WP_DEBUG,
				"Damage interval: {%d(%d)} -> [%d, %d) [%d], %f",
				base->ndamage_rects, base->acc_count, low, high,
				tca, cover_fraction);

		*minincl = low;
		*maxexcl = high;
		*total_covered_area = tca;
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
