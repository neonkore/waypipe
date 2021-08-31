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

#include "parsing.h"
#include "main.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <symgen_types.h>

static const char *get_type_name(struct wp_object *obj)
{
	return obj->type ? obj->type->name : "<no type>";
}
const char *get_nth_packed_string(const char *pack, int n)
{
	for (int i = 0; i < n; i++) {
		pack += strlen(pack) + 1;
	}
	return pack;
}

static struct wp_object *tree_rotate_left(struct wp_object *n)
{
	struct wp_object *tmp = n->t_right;
	n->t_right = tmp->t_left;
	tmp->t_left = n;
	return tmp;
}
static struct wp_object *tree_rotate_right(struct wp_object *n)
{
	struct wp_object *tmp = n->t_left;
	n->t_left = tmp->t_right;
	tmp->t_right = n;
	return tmp;
}
static void tree_link_right(struct wp_object **cur, struct wp_object **rn)
{
	(*rn)->t_left = *cur;
	*rn = *cur;
	*cur = (*cur)->t_left;
}
static void tree_link_left(struct wp_object **cur, struct wp_object **ln)
{
	(*ln)->t_right = *cur;
	*ln = *cur;
	*cur = (*cur)->t_right;
}

/* Splay operation, following Sleator+Tarjan, 1985 */
static struct wp_object *tree_branch_splay(struct wp_object *root, uint32_t key)
{
	if (!root) {
		return NULL;
	}
	struct wp_object bg = {.t_left = NULL, .t_right = NULL};
	struct wp_object *ln = &bg;
	struct wp_object *rn = &bg;
	struct wp_object *cur = root;

	while (key != cur->obj_id) {
		if (key < cur->obj_id) {
			if (cur->t_left && key < cur->t_left->obj_id) {
				cur = tree_rotate_right(cur);
			}
			if (!cur->t_left) {
				break;
			}
			tree_link_right(&cur, &rn);
		} else {
			if (cur->t_right && key > cur->t_right->obj_id) {
				cur = tree_rotate_left(cur);
			}
			if (!cur->t_right) {
				break;
			}
			tree_link_left(&cur, &ln);
		}
	}
	ln->t_right = cur->t_left;
	rn->t_left = cur->t_right;
	cur->t_left = bg.t_right;
	cur->t_right = bg.t_left;
	return cur;
}
static void tree_insert(struct wp_object **tree, struct wp_object *new_node)
{
	/* Reset these, just in case */
	new_node->t_left = NULL;
	new_node->t_right = NULL;

	struct wp_object *r = *tree;
	if (!r) {
		*tree = new_node;
		return;
	}
	r = tree_branch_splay(r, new_node->obj_id);
	if (new_node->obj_id < r->obj_id) {
		new_node->t_left = r->t_left;
		new_node->t_right = r;
		r->t_left = NULL;
		r = new_node;
	} else if (new_node->obj_id > r->obj_id) {
		new_node->t_right = r->t_right;
		new_node->t_left = r;
		r->t_right = NULL;
		r = new_node;
	} else {
		/* already in tree, no effect? or do silent override */
	}
	*tree = r;
}
static void tree_remove(struct wp_object **tree, uint32_t key)
{
	struct wp_object *r = *tree;
	r = tree_branch_splay(r, key);
	if (!r || r->obj_id != key) {
		/* wasn't in tree */
		return;
	}
	struct wp_object *lbranch = r->t_left;
	struct wp_object *rbranch = r->t_right;
	if (!lbranch) {
		*tree = rbranch;
		return;
	}
	r = tree_branch_splay(lbranch, key);
	r->t_right = rbranch;
	*tree = r;
}
static struct wp_object *tree_lookup(struct wp_object **tree, uint32_t key)
{
	*tree = tree_branch_splay(*tree, key);
	if (*tree && (*tree)->obj_id == key) {
		return *tree;
	}
	return NULL;
}
static void tree_clear(struct wp_object **tree,
		void (*node_free)(struct wp_object *object))
{
	struct wp_object *root = *tree;
	while (root) {
		root = tree_branch_splay(root, 0);
		struct wp_object *right = root->t_right;
		root->t_right = NULL;
		node_free(root);
		root = right;
	}
	*tree = NULL;
}

void tracker_insert(struct message_tracker *mt, struct wp_object *obj)
{
	struct wp_object *old_obj = tree_lookup(&mt->objtree_root, obj->obj_id);
	if (old_obj) {
		/* We /always/ replace the object, to ensure that map
		 * elements are never duplicated and make the deletion
		 * process cause crashes */
		if (!old_obj->is_zombie) {
			wp_error("Replacing object @%u that already exists: old type %s, new type %s",
					obj->obj_id, get_type_name(old_obj),
					get_type_name(obj));
		}
		/* Zombie objects (server allocated, client deleted) are
		 * only acknowledged destroyed by the server when they
		 * are replaced. */
		tree_remove(&mt->objtree_root, old_obj->obj_id);
		destroy_wp_object(old_obj);
	}

	tree_insert(&mt->objtree_root, obj);
}
void tracker_replace_existing(
		struct message_tracker *mt, struct wp_object *new_obj)
{
	tree_remove(&mt->objtree_root, new_obj->obj_id);
	tree_insert(&mt->objtree_root, new_obj);
}
void tracker_remove(struct message_tracker *mt, struct wp_object *obj)
{
	tree_remove(&mt->objtree_root, obj->obj_id);
}
struct wp_object *tracker_get(struct message_tracker *mt, uint32_t id)
{
	return tree_lookup(&mt->objtree_root, id);
}
struct wp_object *get_object(struct message_tracker *mt, uint32_t id,
		const struct wp_interface *intf)
{
	(void)intf;
	return tracker_get(mt, id);
}

int init_message_tracker(struct message_tracker *mt)
{
	memset(mt, 0, sizeof(*mt));

	/* heap allocate this, so we don't need to protect against adversarial
	 * replacement */
	struct wp_object *disp = create_wp_object(1, the_display_interface);
	if (!disp) {
		return -1;
	}
	tracker_insert(mt, disp);
	return 0;
}
void cleanup_message_tracker(struct message_tracker *mt)
{
	tree_clear(&mt->objtree_root, destroy_wp_object);
}

static bool word_has_empty_bytes(uint32_t v)
{
	return ((v & 0xFF) == 0) || ((v & 0xFF00) == 0) ||
	       ((v & 0xFF0000) == 0) || ((v & 0xFF000000) == 0);
}

bool size_check(const struct msg_data *data, const uint32_t *payload,
		unsigned int true_length, int fd_length)
{
	if (data->n_fds > fd_length) {
		wp_error("Msg overflow, not enough fds %d > %d", data->n_fds,
				fd_length);
		return false;
	}

	const uint16_t *gaps = data->gaps;
	uint32_t pos = 0;
	for (;; gaps++) {
		uint16_t g = (*gaps >> 2);
		uint16_t e = (*gaps & 0x3);
		pos += g;
		if (pos > true_length) {
			wp_error("Msg overflow, not enough words %d > %d", pos,
					true_length);
			return false;
		}
		switch (e) {
		case GAP_CODE_STR: {
			uint32_t x_words = (payload[pos - 1] + 3) / 4;
			uint32_t end_idx = pos + x_words - 1;
			if (end_idx < true_length &&
					!word_has_empty_bytes(
							payload[end_idx])) {
				wp_error("Msg overflow, string termination %d < %d, %d, %x %d",
						pos, true_length, x_words,
						payload[end_idx],
						word_has_empty_bytes(
								payload[end_idx]));
				return false;
			}
			pos += x_words;
		} break;
		case GAP_CODE_ARR:
			pos += (payload[pos - 1] + 3) / 4;
			break;
		case GAP_CODE_OBJ:
			break;
		case GAP_CODE_END:
			return true;
		}
	}
}

/* Given a size-checked request, try to construct all the new objects
 * that the request requires. Return true if successful, false otherwise.
 *
 * The argument `caller_obj` should be the object on which the request was
 * invoked; this function checks to make sure that object is not
 * overwritten by accident/corrupt input.
 */
static bool build_new_objects(const struct msg_data *data,
		const uint32_t *payload, struct message_tracker *mt,
		const struct wp_object *caller_obj, int msg_offset)
{
	const uint16_t *gaps = data->gaps;
	uint32_t pos = 0;
	uint32_t objno = 0;
	for (;; gaps++) {
		uint16_t g = (*gaps >> 2);
		uint16_t e = (*gaps & 0x3);
		pos += g;
		switch (e) {
		case GAP_CODE_STR:
		case GAP_CODE_ARR:
			pos += (payload[pos - 1] + 3) / 4;
			break;
		case GAP_CODE_OBJ: {
			uint32_t new_id = payload[pos - 1];
			if (new_id == caller_obj->obj_id) {
				wp_error("In %s.%s, tried to create object id=%u conflicting with object being called, also id=%u",
						caller_obj->type->name,
						get_nth_packed_string(
								caller_obj->type->msg_names,
								msg_offset),
						new_id, caller_obj->obj_id);
				return false;
			}
			struct wp_object *new_obj = create_wp_object(
					new_id, data->new_objs[objno]);
			if (!new_obj) {
				return false;
			}
			tracker_insert(mt, new_obj);
			objno++;
		} break;
		case GAP_CODE_END:
			return true;
		}
	}
}

int peek_message_size(const void *data)
{
	return (int)(((const uint32_t *)data)[1] >> 16);
}

enum parse_state handle_message(struct globals *g, bool display_side,
		bool from_client, struct char_window *chars,
		struct int_window *fds)
{
	bool to_wire = from_client == !display_side;

	const uint32_t *const header =
			(uint32_t *)&chars->data[chars->zone_start];
	uint32_t obj = header[0];
	int len = (int)(header[1] >> 16);
	int meth = (int)((header[1] << 16) >> 16);

	if (len != chars->zone_end - chars->zone_start) {
		wp_error("Message length disagreement %d vs %d", len,
				chars->zone_end - chars->zone_start);
		return PARSE_ERROR;
	}
	// display: object = 0?
	struct wp_object *objh = tracker_get(&g->tracker, obj);
	if (!objh || !objh->type) {
		wp_debug("Unidentified object %d with %s", obj,
				from_client ? "request" : "event");
		return PARSE_UNKNOWN;
	}

	/* Identify the message type. Messages sent over the wire are tagged
	 * with the number of file descriptors that are bound to the message.
	 * This incidentally limits the number of fds to 31, and number of
	 * messages per type 2047. */
	int num_fds_with_message = -1;
	if (!to_wire) {
		num_fds_with_message = meth >> 11;
		meth = meth & ((1 << 11) - 1);
		if (num_fds_with_message > 0) {
			wp_debug("Reading message tagged with %d fds.",
					num_fds_with_message);
		}
		// Strip out the FD counters
		((uint32_t *)&chars->data[chars->zone_start])[1] &=
				~(uint32_t)((1 << 16) - (1 << 11));
	}

	const struct wp_interface *intf = objh->type;
	int nmsgs = from_client ? intf->nreq : intf->nevt;
	if (meth < 0 || meth >= nmsgs) {
		wp_debug("Unidentified request #%d (of %d) on interface %s",
				meth, nmsgs, intf->name);
		return PARSE_UNKNOWN;
	}
	int meth_offset = from_client ? meth : meth + intf->nreq;
	const struct msg_data *msg = &intf->msgs[meth_offset];

	const uint32_t *payload = header + 2;
	if (!size_check(msg, payload, (unsigned int)len / 4 - 2,
			    fds->zone_end - fds->zone_start)) {
		wp_error("Message %x %s@%u.%s parse length overflow", payload,
				intf->name, objh->obj_id,
				get_nth_packed_string(
						intf->msg_names, meth_offset));
		return PARSE_UNKNOWN;
	}

	if (!build_new_objects(msg, payload, &g->tracker, objh, meth_offset)) {
		return PARSE_UNKNOWN;
	}

	int fds_used = 0;
	struct context ctx = {
			.g = g,
			.tracker = &g->tracker,
			.obj = objh,
			.on_display_side = display_side,
			.drop_this_msg = false,
			.message = (uint32_t *)&chars->data[chars->zone_start],
			.message_length = len,
			.message_available_space =
					chars->size - chars->zone_start,
			.fds = fds,
			.fds_changed = false,
	};
	if (msg->call) {
		(*msg->call)(&ctx, payload, &fds->data[fds->zone_start],
				&g->tracker);
	}
	if (num_fds_with_message >= 0 && msg->n_fds != num_fds_with_message) {
		wp_error("Message used %d file descriptors, but was tagged as using %d",
				msg->n_fds, num_fds_with_message);
	}

	fds_used += msg->n_fds;

	if (objh->obj_id >= 0xff000000 && msg->is_destructor) {
		/* Unfortunately, the wayland server library does not explicitly
		 * acknowledge the client requested deletion of objects that the
		 * wayland server has created; the client assumes success,
		 * except by creating a new object that overrides the existing
		 * id.
		 *
		 * To correctly vanish all events in flight, we mark the element
		 * as having been zombified; it will only be destroyed when a
		 * new element is created to take its place, since there could
		 * still be e.g. data transfers in the channel, and it's best
		 * that those only vanish when needed.
		 *
		 * Fortunately, wl_registry::bind objects are all client
		 * produced.
		 *
		 * TODO: early struct shadow_fd closure for all deletion
		 * requests, with a matching zombie flag to vanish transfers;
		 *
		 * TODO: avert the zombie apocalypse, where the compositor
		 * sends creation notices for a full hierarchy of objects
		 * before it receives the root's .destroy request.
		 */
		objh->is_zombie = true;
	}

	if (ctx.drop_this_msg) {
		wp_debug("Dropping %s.%s, with %d fds", intf->name,
				get_nth_packed_string(
						intf->msg_names, meth_offset),
				fds_used);
		chars->zone_end = chars->zone_start;
		int nmoved = fds->zone_end - fds->zone_start - fds_used;
		memmove(&fds->data[fds->zone_start],
				&fds->data[fds->zone_start + fds_used],
				(size_t)nmoved * sizeof(int));
		fds->zone_end -= fds_used;
		return PARSE_KNOWN;
	}

	if (!ctx.fds_changed) {
		// Default, autoadvance fd queue, unless handler disagreed.
		fds->zone_start += fds_used;

		// Tag message with number of FDs. If the fds were modified
		// nontrivially, (i.e, ctx.fds_changed is true), tagging is
		// handler's responsibility
		if (to_wire) {
			if (fds_used >= 32 || meth >= 2048) {
				wp_error("Message used %d>=32 file descriptors or had index %d>=2048. FD tagging failed, expect a crash.",
						fds_used, meth);
			}
			if (fds_used > 0) {
				wp_debug("Tagging message with %d fds.",
						fds_used);
				((uint32_t *)&chars->data[chars->zone_start])
						[1] |=
						(uint32_t)(fds_used << 11);
			}
		}
	}

	if (fds->zone_end < fds->zone_start) {
		wp_error("Handler error after %s.%s: fdzs = %d > %d = fdze",
				intf->name,
				get_nth_packed_string(
						intf->msg_names, meth_offset),
				fds->zone_start, fds->zone_end);
	}
	// Move the end, in case there were changes
	chars->zone_end = chars->zone_start + ctx.message_length;
	return PARSE_KNOWN;
}

void parse_and_prune_messages(struct globals *g, bool on_display_side,
		bool from_client, struct char_window *source_bytes,
		struct char_window *dest_bytes, struct int_window *fds)
{
	bool anything_unknown = false;
	struct char_window scan_bytes;
	scan_bytes.data = dest_bytes->data;
	scan_bytes.zone_start = dest_bytes->zone_start;
	scan_bytes.zone_end = dest_bytes->zone_start;
	scan_bytes.size = dest_bytes->size;

	DTRACE_PROBE1(waypipe, parse_enter,
			source_bytes->zone_end - source_bytes->zone_start);

	for (; source_bytes->zone_start < source_bytes->zone_end;) {
		if (source_bytes->zone_end - source_bytes->zone_start < 8) {
			// Not enough remaining bytes to parse the
			// header
			wp_debug("Insufficient bytes for header: %d %d",
					source_bytes->zone_start,
					source_bytes->zone_end);
			break;
		}
		int msgsz = peek_message_size(
				&source_bytes->data[source_bytes->zone_start]);
		if (msgsz % 4 != 0) {
			wp_debug("Wayland messages lengths must be divisible by 4");
			break;
		}
		if (source_bytes->zone_start + msgsz > source_bytes->zone_end) {
			wp_debug("Insufficient bytes");
			// Not enough remaining bytes to contain the
			// message
			break;
		}
		if (msgsz < 8) {
			wp_debug("Degenerate message, claimed len=%d", msgsz);
			// Not enough remaining bytes to contain the
			// message
			break;
		}

		/* We copy the message to the trailing end of the
		 * in-progress buffer; the parser may elect to modify
		 * the message's size */
		memcpy(&scan_bytes.data[scan_bytes.zone_start],
				&source_bytes->data[source_bytes->zone_start],
				(size_t)msgsz);
		source_bytes->zone_start += msgsz;
		scan_bytes.zone_end = scan_bytes.zone_start + msgsz;

		enum parse_state pstate = handle_message(g, on_display_side,
				from_client, &scan_bytes, fds);
		if (pstate == PARSE_UNKNOWN || pstate == PARSE_ERROR) {
			anything_unknown = true;
		}
		scan_bytes.zone_start = scan_bytes.zone_end;
	}
	dest_bytes->zone_end = scan_bytes.zone_end;

	if (anything_unknown) {
		// All-un-owned buffers are assumed to have changed.
		// (Note that in some cases, a new protocol could imply
		// a change for an existing buffer; it may make sense to
		// mark everything dirty, then.)

		for (struct shadow_fd_link *lcur = g->map.link.l_next,
					   *lnxt = lcur->l_next;
				lcur != &g->map.link;
				lcur = lnxt, lnxt = lcur->l_next) {
			struct shadow_fd *cur = (struct shadow_fd *)lcur;
			if (!cur->has_owner) {
				cur->is_dirty = true;
			}
		}
	}
	DTRACE_PROBE(waypipe, parse_exit);
	return;
}
