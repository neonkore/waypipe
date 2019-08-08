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

void listset_insert(struct fd_translation_map *map, struct obj_list *lst,
		struct wp_object *obj)
{
	if (!lst->size) {
		lst->size = 4;
		lst->nobj = 0;
		lst->objs = calloc(4, sizeof(struct wp_object *));
	}
	int isz = lst->size;
	while (lst->nobj >= lst->size) {
		lst->size *= 2;
	}
	if (isz != lst->size) {
		lst->objs = realloc(lst->objs,
				lst->size * sizeof(struct wp_object *));
	}
	for (int i = 0; i < lst->nobj; i++) {
		if (lst->objs[i]->obj_id == obj->obj_id) {
			/* We /always/ replace the object, to ensure that map
			 * elements are never duplicated and make the deletion
			 * process cause crashes */
			if (!lst->objs[i]->is_zombie) {
				wp_error("Replacing object @%u that already exists: old type %s, new type %s",
						obj->obj_id,
						get_type_name(lst->objs[i]),
						get_type_name(obj));
			}
			/* Zombie objects (server allocated, client deleted) are
			 * only acknowledged destroyed by the server when they
			 * are replaced. */
			destroy_wp_object(map, lst->objs[i]);
			lst->objs[i] = obj;
			return;
		}
		if (lst->objs[i]->obj_id > obj->obj_id) {
			memmove(lst->objs + i + 1, lst->objs + i,
					(lst->nobj - i) *
							sizeof(struct wp_object *));
			lst->objs[i] = obj;
			lst->nobj++;
			return;
		}
	}
	lst->objs[lst->nobj++] = obj;
}
void listset_remove(struct obj_list *lst, struct wp_object *obj)
{
	for (int i = 0; i < lst->nobj; i++) {
		if (lst->objs[i]->obj_id == obj->obj_id) {
			lst->nobj--;
			if (i < lst->nobj) {
				memmove(lst->objs + i, lst->objs + i + 1,
						(lst->nobj - i) *
								sizeof(struct wp_object *));
			}
			return;
		}
	}

	wp_error("Object not in list");
	return;
}
struct wp_object *listset_get(struct obj_list *lst, uint32_t id)
{
	for (int i = 0; i < lst->nobj; i++) {
		if (lst->objs[i]->obj_id > id) {
			return NULL;
		} else if (lst->objs[i]->obj_id == id) {
			return lst->objs[i];
		}
	}
	return NULL;
}
struct wp_object *get_object(struct message_tracker *mt, uint32_t id,
		const struct wp_interface *intf)
{
	(void)intf;
	return listset_get(&mt->objects, id);
}

void init_message_tracker(struct message_tracker *mt)
{
	memset(mt, 0, sizeof(*mt));

	listset_insert(NULL, &mt->objects,
			create_wp_object(1, the_display_interface));
}
void cleanup_message_tracker(
		struct fd_translation_map *map, struct message_tracker *mt)
{
	for (int i = 0; i < mt->objects.nobj; i++) {
		destroy_wp_object(map, mt->objects.objs[i]);
	}
	free(mt->objects.objs);
}

static int get_handler_idx_for_interface(const struct wp_interface *intf)
{
	for (int i = 0; handlers[i].interface; i++) {
		if (handlers[i].interface == intf) {
			return i;
		}
	}
	return -1;
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

	unsigned int len = data->base_gap;
	if (len > true_length) {
		wp_error("Msg overflow, not enough words %d > %d", len,
				true_length);
		return false;
	}

	for (int i = 0; i < data->n_stretch; i++) {
		/* For strings, the string length /includes/ the null terminator
		 */
		uint32_t x_words = (payload[len - 1] + 3) / 4;
		/* string termination validation */
		if (data->stretch_is_string[i] && x_words) {
			unsigned int end_idx = len + x_words - 1;
			if (end_idx < true_length &&
					!word_has_empty_bytes(
							payload[end_idx])) {
				wp_error("Msg overflow, string termination %d < %d, %d, %x %d",
						len, true_length, x_words,
						payload[end_idx],
						word_has_empty_bytes(
								payload[end_idx]));
				return false;
			}
		}
		len += x_words;
		len += data->trail_gap[i];
		if (len > true_length) {
			wp_error("Msg overflow, post string %d %d > %d", i, len,
					true_length);
			return false;
		}
	}
	return true;
}

/* Given a size-checked request, try to construct all the new objects
 * that the request requires. Return true if successful, false otherwise.
 *
 * The argument `caller_obj` should be the object on which the request was
 * invoked; this function checks to make sure that object is not
 * overwritten by accident/corrupt input.
 */
static bool build_new_objects(const struct msg_data *data,
		const uint32_t *payload, struct fd_translation_map *map,
		struct message_tracker *mt, const struct wp_object *caller_obj)
{
	unsigned int pos = 0;
	int gap_no = 0;
	for (int k = 0; k < data->new_vec_len; k++) {
		if (data->new_obj_idxs[k] == (unsigned int)-1) {
			pos += gap_no == 0 ? data->base_gap
					   : data->trail_gap[gap_no - 1];
			pos += (payload[pos - 1] + 3) / 4;
		} else {
			uint32_t new_id = payload[pos + data->new_obj_idxs[k]];
			if (new_id == caller_obj->obj_id) {
				wp_error("In %s.%s, tried to create object id=%u conflicting with object being called, also id=%u",
						caller_obj->type->name,
						data->name, new_id,
						caller_obj->obj_id);
				return false;
			}
			struct wp_object *new_obj = create_wp_object(
					new_id, data->new_obj_types[k]);
			listset_insert(map, &mt->objects, new_obj);
		}
	}
	return true;
}

int peek_message_size(const void *data)
{
	return (int)(((const uint32_t *)data)[1] >> 16);
}

enum parse_state handle_message(struct globals *g, bool display_side,
		bool from_client, struct char_window *chars,
		struct int_window *fds)
{
	const uint32_t *const header =
			(uint32_t *)&chars->data[chars->zone_start];
	uint32_t obj = header[0];
	int meth = (int)((header[1] << 16) >> 16);
	int len = (int)(header[1] >> 16);
	if (len != chars->zone_end - chars->zone_start) {
		wp_error("Message length disagreement %d vs %d", len,
				chars->zone_end - chars->zone_start);
		return PARSE_ERROR;
	}
	// display: object = 0?
	struct wp_object *objh = listset_get(&g->tracker.objects, obj);

	if (!objh || !objh->type) {
		wp_debug("Unidentified object %d with %s", obj,
				from_client ? "request" : "event");
		return PARSE_UNKNOWN;
	}

	const struct wp_interface *intf = objh->type;
	int type_idx = from_client ? 0 : 1;
	const struct msg_data *msg = NULL;
	if (meth < intf->nfuncs[type_idx] && meth >= 0) {
		msg = &intf->funcs[type_idx][meth];
	} else {
		wp_debug("Unidentified request #%d (of %d) on interface %s",
				meth, intf->nfuncs[type_idx], intf->name);
	}
	if (!msg) {
		wp_debug("Unidentified %s from known object",
				from_client ? "request" : "event");
		return PARSE_UNKNOWN;
	}

	const int handler_idx = get_handler_idx_for_interface(objh->type);
	wp_callfn_t call_fn = NULL;
	if (handler_idx >= 0) {
		const struct msg_handler *handler = &handlers[handler_idx];
		const void *funcs = from_client ? handler->request_handlers
						: handler->event_handlers;
		if (funcs) {
			call_fn = ((const wp_callfn_t *)funcs)[meth];
		}
	}

	const uint32_t *payload = header + 2;
	if (!size_check(msg, payload, len / 4 - 2,
			    fds->zone_end - fds->zone_start)) {
		wp_error("Message %x %s@%u.%s parse length overflow", payload,
				intf->name, objh->obj_id, msg->name);
		return PARSE_UNKNOWN;
	}

	if (!build_new_objects(msg, payload, &g->map, &g->tracker, objh)) {
		return PARSE_UNKNOWN;
	}

	int fds_used = 0;
	struct context ctx = {
			.g = g,
			.obj_list = &g->tracker.objects,
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
	if (call_fn) {
		(*call_fn)(&ctx, payload, &fds->data[fds->zone_start],
				&g->tracker);
	}
	fds_used += msg->n_fds;

	if (objh->obj_id >= 0xff000000 && !strcmp(msg->name, "destroy")) {
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
		wp_debug("Dropping %s.%s, with %d fds", intf->name, msg->name,
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
		// Default, autoadvance fd queue, unless handler disagreed
		fds->zone_start += fds_used;
	}
	if (fds->zone_end < fds->zone_start) {
		wp_error("Handler error after %s.%s: fdzs = %d > %d = fdze",
				intf->name, msg->name, fds->zone_start,
				fds->zone_end);
	}
	// Move the end, in case there were changes
	chars->zone_end = chars->zone_start + ctx.message_length;
	return PARSE_KNOWN;
}
