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

#include "shadow.h"

#include <stdlib.h>
#include <string.h>

struct merge_stack_elem {
	int offset;
	int count;
};
struct merge_stack {
	struct interval *data;
	int size;
	int count;
};

static int stream_merge(int a_count, const struct interval *__restrict__ a_list,
		int b_count, const struct interval *__restrict__ b_list,
		struct interval *__restrict__ c_list, int margin)
{
	int ia = 0, ib = 0, ic = 0;
	int cursor = INT32_MIN;
	(void)a_count;
	(void)b_count;

	/* the loop exit condition appears to be faster than checking
	 * ia<a_count||ib<b_count */
	while (!(a_list[ia].start == INT32_MAX &&
			b_list[ib].start == INT32_MAX)) {
		/* TODO: write a simd optimized version, in (?) kernel_sse.c,
		 * that selects 4 elements at a time. Sentinels are free,
		 * after all */
		struct interval sel;
		if (a_list[ia].start < b_list[ib].start) {
			sel = a_list[ia++];
		} else {
			sel = b_list[ib++];
		}

		/* which path is more likely depends on the structure of
		 * the result; branch prediction works very well here */
		int new_cursor = max(cursor, sel.end);
		if (sel.start >= cursor + margin) {
			c_list[ic++] = sel;
		} else {
			c_list[ic - 1].end = new_cursor;
		}
		cursor = new_cursor;
	}

	/* add end sentinel */
	c_list[ic] = (struct interval){.start = INT32_MAX, .end = INT32_MAX};

	return ic;
}

static int fix_merge_stack_property(int size, struct merge_stack_elem *stack,
		struct merge_stack *base, struct merge_stack *temp,
		int merge_margin, bool force_compact, int *absorbed)
{
	while (size > 1) {
		struct merge_stack_elem top = stack[size - 1];
		struct merge_stack_elem nxt = stack[size - 2];

		if (2 * top.count <= nxt.count && !force_compact) {
			return size;
		}

		if (buf_ensure_size(top.count + nxt.count + 1,
				    sizeof(struct interval), &temp->size,
				    (void **)&temp->data) == -1) {
			wp_error("Failed to resize a merge buffer, some damage intervals may be lost");
			return size;
		}

		int xs = stream_merge(top.count, &base->data[top.offset],
				nxt.count, &base->data[nxt.offset], temp->data,
				merge_margin);
		/* There are more complicated/multi-buffer alternatives with
		 * fewer memory copies, but this is already <20% of stream
		 * merge time */
		memcpy(&base->data[nxt.offset], temp->data,
				(size_t)(xs + 1) * sizeof(struct interval));
		base->count = nxt.offset + xs + 1;

		stack[size - 1] = (struct merge_stack_elem){
				.offset = 0, .count = 0};
		stack[size - 2] = (struct merge_stack_elem){
				.offset = nxt.offset, .count = xs};
		size--;

		*absorbed += (top.count + nxt.count - xs);
	}
	return size;
}

static int unpack_ext_interval(struct interval *vec,
		const struct ext_interval e, int alignment_bits)
{
	int iw = 0;
	int last_end = INT32_MIN;
	for (int ir = 0; ir < e.rep; ir++) {
		int start = e.start + ir * e.stride;
		int end = start + e.width;
		start = (start >> alignment_bits) << alignment_bits;
		end = ((end + (1 << alignment_bits) - 1) >> alignment_bits)
		      << alignment_bits;

		if (start > last_end) {
			vec[iw].start = start;
			vec[iw].end = end;
			last_end = end;
			iw++;
		} else {
			vec[iw - 1].end = end;
			last_end = end;
		}
	}
	/* end sentinel */
	vec[iw] = (struct interval){.start = INT32_MAX, .end = INT32_MAX};
	return iw;
}

/* By writing a mergesort by hand, we can detect duplicates early.
 *
 * TODO: optimize output with run-length-encoded segments
 * TODO: explicit time limiting/adaptive margin! */
void merge_mergesort(const int old_count, struct interval *old_list,
		const int new_count, const struct ext_interval *const new_list,
		int *dst_count, struct interval **dst_list, int merge_margin,
		int alignment_bits)
{
	/* Stack-based mergesort: the buffer at position `i+1`
	 * should be <= 1/2 times the size of the buffer at
	 * position `i`; buffers will be merged
	 * to maintain this invariant */
	// TODO: improve memory management!
	struct merge_stack_elem substack[32];
	int substack_size = 0;
	memset(substack, 0, sizeof(substack));
	struct merge_stack base = {.data = NULL, .count = 0, .size = 0};
	struct merge_stack temp = {.data = NULL, .count = 0, .size = 0};
	if (old_count) {
		/* seed the stack with the previous damage
		 * interval list,
		 * including trailing terminator */
		base.data = old_list;
		base.size = old_count + 1;
		base.count = old_count + 1;
		substack[substack_size++] = (struct merge_stack_elem){
				.offset = 0, .count = old_count};
	}

	int src_count = 0, absorbed = 0;

	for (int jn = 0; jn < new_count; jn++) {
		struct ext_interval e = new_list[jn];
		/* ignore invalid intervals -- also, if e.start
		 * is close to INT32_MIN, the stream merge
		 * breaks */
		if (e.width <= 0 || e.rep <= 0 || e.start < 0) {
			continue;
		}

		/* To limit CPU time, if it is very likely that
		 * an interval would be merged anyway, then
		 * replace it with its containing interval. */
		int remaining = src_count - absorbed;
		bool force_combine = (absorbed > 30000) ||
				     10 * remaining < src_count;

		int64_t intv_end = e.start + e.stride * (int64_t)(e.rep - 1) +
				   e.width;
		if (intv_end >= INT32_MAX) {
			/* overflow protection */
			e.width = INT32_MAX - 1 - e.start;
			e.rep = 1;
		}
		/* Remove internal gaps are smaller than the
		 * margin and hence
		 * would need to be merged away anyway. */
		if (e.width > e.stride - merge_margin || force_combine) {
			e.width = e.stride * (e.rep - 1) + e.width;
			e.rep = 1;
		}

		if (buf_ensure_size(base.count + e.rep + 1,
				    sizeof(struct interval), &base.size,
				    (void **)&base.data) == -1) {
			wp_error("Failed to resize a merge buffer, some damage intervals may be lost");
			continue;
		}

		struct interval *vec = &base.data[base.count];
		int iw = unpack_ext_interval(vec, e, alignment_bits);
		src_count += iw;

		substack[substack_size] = (struct merge_stack_elem){
				.offset = base.count, .count = iw};
		substack_size++;

		base.count += iw + 1;

		/* merge down the stack as far as possible */
		substack_size = fix_merge_stack_property(substack_size,
				substack, &base, &temp, merge_margin, false,
				&absorbed);
	}

	/* collapse the stack into a final interval */
	fix_merge_stack_property(substack_size, substack, &base, &temp,
			merge_margin, true, &absorbed);
	free(temp.data);

	*dst_list = base.data;
	*dst_count = substack[0].count;
}

/* This value must be larger than 8, or diffs will explode */
#define MERGE_MARGIN 256
void merge_damage_records(struct damage *base, int nintervals,
		const struct ext_interval *const new_list, int alignment_bits)
{
	for (int i = 0; i < nintervals; i++) {
		base->acc_damage_stat += new_list[i].width * new_list[i].rep;
		base->acc_count++;
	}

	// Fast return if there is nothing to do
	if (base->damage == DAMAGE_EVERYTHING || nintervals <= 0) {
		return;
	}
	if (nintervals >= (1 << 30) || base->ndamage_intvs >= (1 << 30)) {
		/* avoid overflow in merge routine; also would be cheaper to
		 * damage everything at this point;  */
		damage_everything(base);
		return;
	}

	merge_mergesort(base->ndamage_intvs, base->damage, nintervals, new_list,
			&base->ndamage_intvs, &base->damage, MERGE_MARGIN,
			alignment_bits);
}

void reset_damage(struct damage *base)
{
	if (base->damage != DAMAGE_EVERYTHING) {
		free(base->damage);
	}
	base->damage = NULL;
	base->ndamage_intvs = 0;
	base->acc_damage_stat = 0;
	base->acc_count = 0;
}
void damage_everything(struct damage *base)
{
	if (base->damage != DAMAGE_EVERYTHING) {
		free(base->damage);
	}
	base->damage = DAMAGE_EVERYTHING;
	base->ndamage_intvs = 0;
}
