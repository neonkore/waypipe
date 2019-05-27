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

void listset_insert(struct obj_list *lst, struct wp_object *obj)
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

	wp_log(WP_ERROR, "Object not in list\n");
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

struct wp_object *make_wp_object(uint32_t id, const struct wl_interface *type)
{
	struct wp_object *new_obj = calloc(1, sizeof(struct wp_object));
	new_obj->obj_id = id;
	new_obj->type = type;
	new_obj->owned_buffer = NULL;
	return new_obj;
}

void init_message_tracker(struct message_tracker *mt)
{
	memset(mt, 0, sizeof(*mt));

	listset_insert(&mt->objects, make_wp_object(1, the_display_interface));
}
void cleanup_message_tracker(struct message_tracker *mt)
{
	for (int i = 0; i < mt->objects.nobj; i++) {
		free(mt->objects.objs[i]);
	}
	free(mt->objects.objs);
}

const struct msg_handler *get_handler_for_interface(
		const struct wl_interface *intf)
{
	for (int i = 0; handlers[i].interface; i++) {
		if (handlers[i].interface == intf) {
			return &handlers[i];
		}
	}
	return NULL;
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

static void invoke_msg_handler(const struct wl_message *msg, bool is_event,
		const uint32_t *const payload, const int paylen,
		const int *const fd_list, const int fdlen, int *fds_used,
		void (*const func)(void), struct context *ctx,
		struct message_tracker *mt)
{
	ffi_type *call_types[30];
	void *call_args_ptr[30];
	if (strlen(msg->signature) > 30) {
		wp_log(WP_ERROR, "Overly long signature: %s\n", msg->signature);
	}
	struct uarg call_args_val[30];

	call_types[0] = &ffi_type_pointer;
	call_types[1] = &ffi_type_pointer;

	void *nullptr = NULL;
	void *addr_of_ctx = ctx;
	call_args_ptr[0] = &addr_of_ctx;
	call_args_ptr[1] = &nullptr;
	int nargs = 2;

	int i = 0;                      // index in message
	int k = 0;                      // current argument index
	const char *c = msg->signature; // current argument value

	// TODO: compensate for version strings
	for (; *c; c++, k++) {
		// TODO: truncation safety check, because applications need not
		// be protocol-compliant

		// Skip over version specifications, and over null object
		// permission flags
		while ((*c >= '0' && *c <= '9') || *c == '?') {
			c++;
		}
		if (!*c) {
			break;
		}
		const struct wl_interface *type = msg->types[k];
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
			call_types[nargs] = &ffi_type_pointer;

			i += ((len + 3) / 4);
		} break;
		case 'h': {
			if (*fds_used >= fdlen) {
				goto len_overflow;
			}
			call_args_val[nargs].si = fd_list[(*fds_used)++];
			call_args_ptr[nargs] = &call_args_val[nargs].si;
			call_types[nargs] = &ffi_type_sint32; // see typedef
			nargs++;
		} break;
		case 'f': {
			if (i >= paylen) {
				goto len_overflow;
			}
			wl_fixed_t v = *((const wl_fixed_t *)&payload[i++]);
			call_args_val[nargs].fxd = v;
			call_args_ptr[nargs] = &call_args_val[nargs].fxd;
			call_types[nargs] = &ffi_type_sint32; // see typedef
			nargs++;
		} break;
		case 'i': {
			if (i >= paylen) {
				goto len_overflow;
			}
			int32_t v = (int32_t)payload[i++];
			call_args_val[nargs].si = v;
			call_args_ptr[nargs] = &call_args_val[nargs].si;
			call_types[nargs] = &ffi_type_sint32;
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
			call_types[nargs] = &ffi_type_pointer;
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
			struct wp_object *new_obj = make_wp_object(v, type);
			listset_insert(&mt->objects, new_obj);
			if (is_event) {
				call_args_val[nargs].obj = new_obj;
				call_args_ptr[nargs] =
						&call_args_val[nargs].obj;
				call_types[nargs] = &ffi_type_pointer;
				nargs++;
			} else {
				call_args_val[nargs].ui = new_obj->obj_id;
				call_args_ptr[nargs] = &call_args_val[nargs].ui;
				call_types[nargs] = &ffi_type_uint32;
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
			call_types[nargs] = &ffi_type_pointer;
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
			call_types[nargs] = &ffi_type_uint32;
			nargs++;
		} break;

		default:
			wp_log(WP_DEBUG, "Unidentified message type %c,\n", *c);
			break;
		}

		continue;
	len_overflow:
		wp_log(WP_ERROR,
				"Message parse length overflow, bytes=%d/%d, fds=%d/%d, c=%c\n",
				4 * i, 4 * paylen, *fds_used, fdlen, *c);
		return;
	}
	if (i != paylen) {
		wp_log(WP_ERROR,
				"Parse error length mismatch for %s: used %d expected %d\n",
				msg->name, i * 4, paylen * 4);
	}

	if (func) {
		ffi_cif call_cif;
		ffi_prep_cif(&call_cif, FFI_DEFAULT_ABI, (unsigned int)nargs,
				&ffi_type_void, call_types);
		ffi_call(&call_cif, func, NULL, call_args_ptr);
	}
}

bool handle_message(struct message_tracker *mt, struct fd_translation_map *map,
		bool display_side, bool from_client, void *data, int data_len,
		int *consumed_length, int *fds, int fds_len,
		int *n_consumed_fds, bool *unidentified_changes)
{
	const uint32_t *const header = (uint32_t *)data;
	uint32_t obj = header[0];
	int meth = (int)((header[1] << 16) >> 16);
	int len = (int)(header[1] >> 16);
	*consumed_length = len;
	if (len > data_len) {
		wp_log(WP_ERROR,
				"Message length overflow: %d claimed vs %d available. Keeping message, uninterpreted",
				len, data_len);
		return false;
	}

	// display: object = 0?
	struct wp_object *objh = listset_get(&mt->objects, obj);

	if (objh && objh->type) {
		const struct wl_interface *intf = objh->type;
		const struct wl_message *msg = NULL;
		if (from_client) {
			if (meth < intf->method_count && meth >= 0) {
				msg = &intf->methods[meth];
			} else {
				wp_log(WP_DEBUG,
						"Unidentified request #%d (of %d) on interface %s\n",
						meth, intf->method_count,
						intf->name);
			}
		} else {
			if (meth < intf->event_count && meth >= 0) {
				msg = &intf->events[meth];
			} else {
				wp_log(WP_ERROR,
						"Unidentified event #%d on interface %s\n",
						meth, intf->name);
			}
		}
		if (msg) {
			const struct msg_handler *handler =
					get_handler_for_interface(objh->type);
			void (*fn)(void) = NULL;
			if (handler) {
				if (from_client && handler->request_handlers) {
					fn = ((void (*const *)(
							void))handler->request_handlers)
							[meth];
				}
				if (!from_client && handler->event_handlers) {
					fn = ((void (*const *)(
							void))handler->event_handlers)
							[meth];
				}
			}

			struct context ctx;
			ctx.mt = mt;
			ctx.map = map;
			ctx.obj = objh;
			ctx.on_display_side = display_side;
			ctx.drop_this_msg = false;

			const uint32_t *payload = header + 2;
			invoke_msg_handler(msg, !from_client, payload,
					len / 4 - 2, &fds[*n_consumed_fds],
					fds_len - *n_consumed_fds,
					n_consumed_fds, fn, &ctx, mt);
			// Flag set by the protocol handler function
			if (ctx.drop_this_msg) {
				return false; // DROP
			}
			*unidentified_changes = false;
		} else {
			wp_log(WP_DEBUG, "Unidentified %s from known object\n",
					from_client ? "request" : "event");
			*unidentified_changes = true;
		}
	} else {
		wp_log(WP_DEBUG, "Unidentified object %d with %s\n", obj,
				from_client ? "request" : "event");
		*unidentified_changes = true;
	}
	(void)fds;
	(void)fds_len;
	(void)n_consumed_fds;
	return true; // keep
}
