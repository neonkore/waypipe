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

#include "util.h"

#include <ffi.h>
#include <wayland-util.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
			if (lst->objs[i]->is_zombie) {
				/* Zombie objects (server allocated, client
				 * deleted) are only acknowledged destroyed by
				 * the server when they are replaced */
				destroy_wp_object(map, lst->objs[i]);
				lst->objs[i] = obj;
				return;
			}

			wp_log(WP_ERROR,
					"Inserting object @%u that already exists: old type %s, new type %s",
					obj->obj_id,
					get_type_name(lst->objs[i]),
					get_type_name(obj));
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

	wp_log(WP_ERROR, "Object not in list");
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

static int count_num_args(const struct wl_message *msg)
{
	int n = 0;
	for (const char *c = msg->signature; *c; c++) {
		n += (strchr("afhionsu", *c) != NULL);
	}
	return n;
}
static int count_subhandler_call_types(
		int n, const void *fns, const struct wl_message *msgs)
{
	int m = 0;
	for (int k = 0; k < n; k++) {
		void (*fn)(void) = ((void (*const *)(void))fns)[k];
		if (!fn) {
			continue;
		}
		m += count_num_args(&msgs[k]) + 2;
	}
	return m;
}
static int compute_num_call_types(int *nhandlers, int *nfunctions)
{
	int num_call_types = 0;
	int i = 0;
	int nfuncs = 0;
	for (; handlers[i].interface; i++) {
		// todo: modify generator produce symmetric tables with no
		// event/req distinction
		const struct msg_handler *handler = &handlers[i];
		if (handler->event_handlers) {
			num_call_types += count_subhandler_call_types(
					handler->interface->event_count,
					handler->event_handlers,
					handler->interface->events);
			nfuncs += handler->interface->event_count;
		}
		if (handler->request_handlers) {
			num_call_types += count_subhandler_call_types(
					handler->interface->method_count,
					handler->request_handlers,
					handler->interface->methods);
			nfuncs += handler->interface->method_count;
		}
	}
	*nhandlers = i;
	*nfunctions = nfuncs;
	return num_call_types;
}
static int setup_subhandler_cif(int n, const void *fns,
		const struct wl_message *msgs, int *i_types, ffi_type **types,
		ffi_cif *cifs, bool is_event)
{
	int nused = 0;
	for (int k = 0; k < n; k++) {
		void (*fn)(void) = ((void (*const *)(void))fns)[k];
		if (!fn) {
			continue;
		}
		ffi_type **type_offset = &types[*i_types];

		/* The first two types are reserved here for &context,NULL */
		types[(*i_types)++] = &ffi_type_pointer;
		types[(*i_types)++] = &ffi_type_pointer;

		int nargs = count_num_args(&msgs[k]);
		for (const char *c = msgs[k].signature; *c; c++) {
			switch (*c) {
			case 'a':
				types[(*i_types)++] = &ffi_type_pointer;
				break;
			case 'f':
				types[(*i_types)++] = &ffi_type_sint32;
				break;
			case 'h':
				types[(*i_types)++] = &ffi_type_sint32;
				break;
			case 'i':
				types[(*i_types)++] = &ffi_type_sint32;
				break;
			case 'o':
				types[(*i_types)++] = &ffi_type_pointer;
				break;
			case 'n':
				types[(*i_types)++] =
						is_event ? &ffi_type_pointer
							 : &ffi_type_uint32;
				break;
			case 's':
				types[(*i_types)++] = &ffi_type_pointer;
				break;
			case 'u':
				types[(*i_types)++] = &ffi_type_uint32;
				break;
			default:
				break;
			}
		}
		ffi_prep_cif(&cifs[k], FFI_DEFAULT_ABI,
				(unsigned int)(nargs + 2), &ffi_type_void,
				type_offset);
		nused++;
	}
	return nused;
}

void init_message_tracker(struct message_tracker *mt)
{
	memset(mt, 0, sizeof(*mt));

	listset_insert(NULL, &mt->objects,
			create_wp_object(1, the_display_interface));

	/* Precompute the ffi_cif structures, as ffi_prep_cif takes about as
	 * much time as ffi_call_cif,
	 * and for dense (i.e, damage heavy) message streams both are called
	 * /very/ often */
	int nhandlers = 0;
	int nfunctions = 0;
	int num_call_types = compute_num_call_types(&nhandlers, &nfunctions);
	mt->cif_arg_table = calloc((size_t)num_call_types, sizeof(ffi_type *));
	mt->cif_table = calloc((size_t)nfunctions, sizeof(ffi_cif));
	mt->event_cif_cache = calloc((size_t)nhandlers, sizeof(ffi_cif *));
	mt->request_cif_cache = calloc((size_t)nhandlers, sizeof(ffi_cif *));

	ffi_cif *cif_table = mt->cif_table;
	int i_calltypes = 0;
	int i_functions = 0;
	int k = 0;
	for (int i_handler = 0; handlers[i_handler].interface; i_handler++) {
		const struct msg_handler *handler = &handlers[i_handler];
		if (handler->event_handlers) {
			ffi_cif **cache = (ffi_cif **)mt->event_cif_cache;
			k += setup_subhandler_cif(
					handler->interface->event_count,
					handler->event_handlers,
					handler->interface->events,
					&i_calltypes, mt->cif_arg_table,
					&cif_table[i_functions], true);
			cache[i_handler] = &cif_table[i_functions];
			i_functions += handler->interface->event_count;
		}
		if (handler->request_handlers) {
			ffi_cif **cache = (ffi_cif **)mt->request_cif_cache;
			k += setup_subhandler_cif(
					handler->interface->method_count,
					handler->request_handlers,
					handler->interface->methods,
					&i_calltypes, mt->cif_arg_table,
					&cif_table[i_functions], false);
			cache[i_handler] = &cif_table[i_functions];
			i_functions += handler->interface->method_count;
		}
	}
	wp_log(WP_DEBUG, "Set up %d ffi functions, with %d types total", k,
			i_calltypes);
}
void cleanup_message_tracker(
		struct fd_translation_map *map, struct message_tracker *mt)
{
	for (int i = 0; i < mt->objects.nobj; i++) {
		destroy_wp_object(map, mt->objects.objs[i]);
	}
	free(mt->objects.objs);
	free(mt->cif_table);
	free(mt->cif_arg_table);
	free(mt->event_cif_cache);
	free(mt->request_cif_cache);
}

static int get_handler_idx_for_interface(const struct wl_interface *intf)
{
	for (int i = 0; handlers[i].interface; i++) {
		if (handlers[i].interface == intf) {
			return i;
		}
	}
	return -1;
}

struct uarg {
	union {
		uint32_t ui;
		int32_t si;
		const char *str;
		struct wp_object *obj;
		wl_fixed_t fxd; // from wayland-util.h
		struct {
			struct wl_array *arrptr;
			struct wl_array arr; // from wayland-util.h
		};
	};
};

/* Parse the message payload and apply it to a function, creating new objects
 * and consuming fds */
static void invoke_msg_handler(ffi_cif *cif, const struct wl_interface *intf,
		const struct wl_message *msg, bool is_event,
		const uint32_t *const payload, const int paylen,
		const int *const fd_list, const int fdlen, int *fds_used,
		void (*const func)(void), struct context *ctx,
		struct message_tracker *mt)
{
	/* The types to match these arguments are set up once in
	 * `setup_subhandler_cif` */
	void *call_args_ptr[30];
	if (strlen(msg->signature) > 30) {
		wp_log(WP_ERROR, "Overly long signature for %s.%s: %s",
				intf->name, msg->name, msg->signature);
	}
	struct uarg call_args_val[30];
	void *nullptr = NULL;
	void *addr_of_ctx = ctx;
	call_args_ptr[0] = &addr_of_ctx;
	call_args_ptr[1] = &nullptr;
	int nargs = 2;

	int i = 0;                      // index in message
	int k = 0;                      // current argument index
	const char *c = msg->signature; // current argument value

	for (; *c; c++, k++) {
		// Skip over version specifications, and over null object
		// permission flags
		while ((*c >= '0' && *c <= '9') || *c == '?') {
			c++;
		}
		if (!*c) {
			break;
		}
		switch (*c) {
		case 'a': {
			if (i >= paylen) {
				goto len_overflow;
			}
			uint32_t len = payload[i++];
			if (i + ((int)len + 3) / 4 - 1 >= paylen) {
				goto len_overflow;
			}

			// pass in pointer
			call_args_val[nargs].arr.data = (void *)&payload[i];
			call_args_val[nargs].arr.size = len;
			// fixed allocation. waypipe won't reallocate anyway
			call_args_val[nargs].arr.alloc = (size_t)-1;
			call_args_ptr[nargs] = &call_args_val[nargs].arr;
			i += ((len + 3) / 4);
		} break;
		case 'h': {
			if (*fds_used >= fdlen) {
				goto fd_overflow;
			}
			call_args_val[nargs].si = fd_list[(*fds_used)++];
			call_args_ptr[nargs] = &call_args_val[nargs].si;
			nargs++;
		} break;
		case 'f': {
			if (i >= paylen) {
				goto len_overflow;
			}
			wl_fixed_t v = *((const wl_fixed_t *)&payload[i++]);
			call_args_val[nargs].fxd = v;
			call_args_ptr[nargs] = &call_args_val[nargs].fxd;
			nargs++;
		} break;
		case 'i': {
			if (i >= paylen) {
				goto len_overflow;
			}
			int32_t v = (int32_t)payload[i++];
			call_args_val[nargs].si = v;
			call_args_ptr[nargs] = &call_args_val[nargs].si;
			nargs++;
		} break;
		case 'o': {
			if (i >= paylen) {
				goto len_overflow;
			}
			uint32_t id = payload[i++];
			struct wp_object *lo = listset_get(&mt->objects, id);
			// May always be null, in case client messes up
			call_args_val[nargs].obj = lo;
			call_args_ptr[nargs] = &call_args_val[nargs].obj;
			nargs++;
		} break;
		case 'n': {
			if (i >= paylen) {
				goto len_overflow;
			}
			uint32_t v = payload[i++];
			/* We create the object unconditionally, although
			 * while server requests are handled with the object id,
			 * the client's events are fed the object pointer. */
			struct wp_object *new_obj =
					create_wp_object(v, msg->types[k]);
			listset_insert(&ctx->g->map, &mt->objects, new_obj);

			if (ctx->obj->is_zombie) {
				/* todo: handle misc data ? */
				new_obj->is_zombie = true;
			}

			if (is_event) {
				call_args_val[nargs].obj = new_obj;
				call_args_ptr[nargs] =
						&call_args_val[nargs].obj;
				nargs++;
			} else {
				call_args_val[nargs].ui = new_obj->obj_id;
				call_args_ptr[nargs] = &call_args_val[nargs].ui;
				nargs++;
			}
		} break;
		case 's': {
			if (i >= paylen) {
				goto len_overflow;
			}
			uint32_t len = payload[i++];
			if (i + ((int)len + 3) / 4 - 1 >= paylen) {

				goto len_overflow;
			}
			const char *str = (const char *)&payload[i];
			call_args_val[nargs].str = str;
			call_args_ptr[nargs] = &call_args_val[nargs].str;
			nargs++;

			i += ((len + 3) / 4);
		} break;
		case 'u': {
			if (i >= paylen) {
				goto len_overflow;
			}
			uint32_t v = payload[i++];
			call_args_val[nargs].ui = v;
			call_args_ptr[nargs] = &call_args_val[nargs].ui;
			nargs++;
		} break;

		default:
			wp_log(WP_DEBUG,
					"For %s@%u.%s, unidentified argument type %c",
					intf->name, ctx->obj->obj_id, msg->name,
					*c);
			break;
		}

		continue;
		const char *overflow_type = NULL;
	len_overflow:
		overflow_type = "byte";
		goto overflow;
	fd_overflow:
		overflow_type = "fd";
	overflow:
		wp_log(WP_ERROR,
				"Message %x %s@%u.%s parse length overflow (for %ss), bytes=%d/%d, fds=%d/%d, c=%c",
				payload, intf->name, ctx->obj->obj_id,
				msg->name, overflow_type, 4 * i, 4 * paylen,
				*fds_used, fdlen, *c);
		return;
	}
	if (i != paylen) {
		wp_log(WP_ERROR,
				"Parse error length mismatch for %s.%s: used %d expected %d",
				intf->name, msg->name, i * 4, paylen * 4);
	}

	if (func) {
		ffi_call(cif, func, NULL, call_args_ptr);
	}

	if (ctx->obj->obj_id >= 0xff000000 && !strcmp(msg->name, "destroy")) {
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
		 * TODO: early struct shadow_fd closure for all deletion
		 * requests, with a matching zombie flag to vanish transfers;
		 *
		 * TODO: avert the zombie apocalypse, where the compositor
		 * sends creation notices for a full hierarchy of objects
		 * before it receives the root's .destroy request.
		 */
		ctx->obj->is_zombie = true;
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
	const uint32_t *const header =
			(uint32_t *)&chars->data[chars->zone_start];
	uint32_t obj = header[0];
	int meth = (int)((header[1] << 16) >> 16);
	int len = (int)(header[1] >> 16);
	if (len != chars->zone_end - chars->zone_start) {
		wp_log(WP_ERROR, "Message length disagreement %d vs %d", len,
				chars->zone_end - chars->zone_start);
		return PARSE_ERROR;
	}
	// display: object = 0?
	struct wp_object *objh = listset_get(&g->tracker.objects, obj);

	if (!objh || !objh->type) {
		wp_log(WP_DEBUG, "Unidentified object %d with %s", obj,
				from_client ? "request" : "event");
		return PARSE_UNKNOWN;
	}

	const struct wl_interface *intf = objh->type;
	const struct wl_message *msg = NULL;
	if (from_client) {
		if (meth < intf->method_count && meth >= 0) {
			msg = &intf->methods[meth];
		} else {
			wp_log(WP_DEBUG,
					"Unidentified request #%d (of %d) on interface %s",
					meth, intf->method_count, intf->name);
		}
	} else {
		if (meth < intf->event_count && meth >= 0) {
			msg = &intf->events[meth];
		} else {
			wp_log(WP_ERROR,
					"Unidentified event #%d on interface %s",
					meth, intf->name);
		}
	}
	if (!msg) {
		wp_log(WP_DEBUG, "Unidentified %s from known object",
				from_client ? "request" : "event");
		return PARSE_UNKNOWN;
	}

	const int handler_idx = get_handler_idx_for_interface(objh->type);
	void (*fn)(void) = NULL;
	ffi_cif *cif = NULL;
	if (handler_idx >= 0) {
		const struct msg_handler *handler = &handlers[handler_idx];
		if (from_client && handler->request_handlers) {
			fn = ((void (*const *)(
					void))handler->request_handlers)[meth];
			ffi_cif *cif_list = g->tracker.request_cif_cache
							    [handler_idx];
			cif = &cif_list[meth];
		}
		if (!from_client && handler->event_handlers) {
			fn = ((void (*const *)(
					void))handler->event_handlers)[meth];
			ffi_cif *cif_list =
					g->tracker.event_cif_cache[handler_idx];
			cif = &cif_list[meth];
		}
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
	const uint32_t *payload = ctx.message + 2;
	invoke_msg_handler(cif, intf, msg, !from_client, payload, len / 4 - 2,
			&fds->data[fds->zone_start],
			fds->zone_end - fds->zone_start, &fds_used, fn, &ctx,
			&g->tracker);
	if (ctx.drop_this_msg) {
		wp_log(WP_DEBUG, "Dropping %s.%s, with %d fds", intf->name,
				msg->name, fds_used);
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
		wp_log(WP_ERROR,
				"Handler error after %s.%s: fdzs = %d > %d = fdze",
				intf->name, msg->name, fds->zone_start,
				fds->zone_end);
	}
	// Move the end, in case there were changes
	chars->zone_end = chars->zone_start + ctx.message_length;
	return PARSE_KNOWN;
}
