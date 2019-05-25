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

/* TODO: eventually, create a mode for wayland-scanner that produces just the
 * needed information (constants, and listener structs)
 *
 * Also, make this bundle its own header.
 */
struct wl_proxy;
void wl_proxy_destroy(struct wl_proxy *proxy);
int wl_proxy_add_listener(struct wl_proxy *proxy, void (**implementation)(void),
		void *data);
void wl_proxy_set_user_data(struct wl_proxy *proxy, void *user_data);
void *wl_proxy_get_user_data(struct wl_proxy *proxy);
uint32_t wl_proxy_get_version(struct wl_proxy *proxy);
struct wl_proxy *wl_proxy_marshal_constructor(struct wl_proxy *proxy,
		uint32_t opcode, const struct wl_interface *interface, ...);
struct wl_proxy *wl_proxy_marshal_constructor_versioned(struct wl_proxy *proxy,
		uint32_t opcode, const struct wl_interface *interface,
		uint32_t version, ...);
void wl_proxy_marshal(struct wl_proxy *p, uint32_t opcode, ...);
struct wl_resource;
void wl_resource_post_event(struct wl_resource *resource, uint32_t opcode, ...);
#define WAYLAND_CLIENT_H
#define WAYLAND_SERVER_H
#include <presentation-time-client-defs.h>
#include <presentation-time-server-defs.h>
#include <viewporter-client-defs.h>
#include <viewporter-server-defs.h>
#include <wayland-client-defs.h>
#include <wayland-server-defs.h>
#include <xdg-output-unstable-v1-client-defs.h>
#include <xdg-output-unstable-v1-server-defs.h>
#include <xdg-shell-client-defs.h>
#include <xdg-shell-server-defs.h>
#undef WAYLAND_CLIENT_H
#undef WAYLAND_SERVER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct context {
	struct message_tracker *mt;
	struct wp_object *obj;
	bool drop_this_msg;
	bool can_buffer_changes_result; // unless otherwise indicated by the
					// protocol
};
static void event_wl_display_error(void *data, struct wl_display *wl_display,
		void *object_id, uint32_t code, const char *message)
{
	struct context *context = (struct context *)data;
	(void)context;
	(void)wl_display;
	(void)object_id;
	(void)code;
	(void)message;
}
static void event_wl_display_delete_id(
		void *data, struct wl_display *wl_display, uint32_t id)
{
	struct context *context = (struct context *)data;
	struct wp_object *obj = listset_get(&context->mt->objects, id);
	if (obj) {
		listset_remove(&context->mt->objects, obj);
		// object specific cleanup goes here
		free(obj);
	}

	(void)wl_display;
}
static void request_wl_display_get_registry(struct wl_client *client,
		struct wl_resource *resource, uint32_t registry)
{
	struct context *context = (struct context *)client;
	(void)context;
	(void)resource;
	(void)registry;
}

static void event_wl_registry_global(void *data,
		struct wl_registry *wl_registry, uint32_t name,
		const char *interface, uint32_t version)
{
	struct context *context = (struct context *)data;
	if (!strcmp(interface, "wl_drm")) {
		wp_log(WP_DEBUG, "Hiding wl_drm advertisement\n");
		context->drop_this_msg = true;
	}
	if (!strcmp(interface, "zwp_linux_dmabuf_v1")) {
		wp_log(WP_DEBUG, "Hiding zwp_linux_dmabuf_v1 advertisement\n");
		context->drop_this_msg = true;
	}
	if (!strcmp(interface, "zwlr_export_dmabuf_manager_v1")) {
		wp_log(WP_DEBUG,
				"Hiding zwlr_export_dmabuf_manager_v1 advertisement\n");
		context->drop_this_msg = true;
	}

	(void)wl_registry;
	(void)name;
	(void)version;
}
static void event_wl_registry_global_remove(
		void *data, struct wl_registry *wl_registry, uint32_t name)
{
	struct context *context = (struct context *)data;
	(void)context;
	(void)wl_registry;
	(void)name;
}

static const struct msg_handler handlers[];
void request_wl_registry_bind(struct wl_client *client,
		struct wl_resource *resource, uint32_t name,
		const char *interface, uint32_t version, uint32_t id)
{
	struct context *context = (struct context *)client;
	(void)resource;
	/* Special case handling. This creates a new object matching
	 * (name,interface,version) with id id */
	for (int i = 0; handlers[i].interface; i++) {
		if (!strcmp(interface, handlers[i].interface->name)) {
			struct wp_object *new_obj =
					calloc(1, sizeof(struct wp_object));
			new_obj->obj_id = (int)id;
			new_obj->type = handlers[i].interface;
			listset_insert(&context->mt->objects, new_obj);
			return;
		}
	}
	wp_log(WP_DEBUG, "Binding fail name=%d %s id=%d (v%d)\n", name,
			interface, id, version);
	(void)name;
	(void)version;
}

static void event_wl_buffer_release(void *data, struct wl_buffer *wl_buffer)
{
	struct context *context = (struct context *)data;
	(void)context;
	(void)wl_buffer;
}
static void request_wl_buffer_destroy(
		struct wl_client *client, struct wl_resource *resource)
{

	struct context *context = (struct context *)client;
	// User requests surface destruction
	(void)context;
	(void)resource;
}
static void request_wl_surface_destroy(
		struct wl_client *client, struct wl_resource *resource)
{
	struct context *context = (struct context *)client;
	// User requests surface destruction
	(void)context;
	(void)resource;
}
static void request_wl_surface_damage(struct wl_client *client,
		struct wl_resource *resource, int32_t x, int32_t y,
		int32_t width, int32_t height)
{
	struct context *context = (struct context *)client;
	// A rectangle of the buffer was damaged, hence backing buffers
	// may be updated.
	(void)context;
	(void)resource;
	(void)x;
	(void)y;
	(void)width;
	(void)height;
}
static void event_wl_keyboard_keymap(void *data,
		struct wl_keyboard *wl_keyboard, uint32_t format, int32_t fd,
		uint32_t size)
{
	struct context *context = (struct context *)data;
	(void)wl_keyboard;
	// Exception to the default lack of changes.
	// (Technically a no-op, since the fd should always be new/dirty;
	//  but what happens if the file is recycled?)
	context->can_buffer_changes_result = true;
	(void)format;
	(void)fd;
	(void)size;
}

static const struct wl_display_listener wl_display_event_handler = {
		.error = event_wl_display_error,
		.delete_id = event_wl_display_delete_id};

static const struct wl_display_interface wl_display_request_handler = {
		.get_registry = request_wl_display_get_registry
		// .sync initialized to NULL, due to static storage duration
};
static const struct wl_registry_listener wl_registry_event_handler = {
		.global = event_wl_registry_global,
		.global_remove = event_wl_registry_global_remove};

static const struct wl_registry_interface wl_registry_request_handler = {
		.bind = request_wl_registry_bind};

static const struct wl_buffer_listener wl_buffer_event_handler = {
		.release = event_wl_buffer_release};

static const struct wl_buffer_interface wl_buffer_request_handler = {
		.destroy = request_wl_buffer_destroy};

static const struct wl_surface_listener wl_surface_event_handler = {
		.enter = NULL, .leave = NULL};

static const struct wl_surface_interface wl_surface_request_handler = {
		.destroy = request_wl_surface_destroy,
		.damage = request_wl_surface_damage,
};

static const struct wl_keyboard_listener wl_keyboard_event_handler = {
		.keymap = event_wl_keyboard_keymap};

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

static const struct msg_handler handlers[] = {
		{&wl_display_interface, &wl_display_event_handler,
				&wl_display_request_handler, FDEFFECT_NEVER},
		{&wl_registry_interface, &wl_registry_event_handler,
				&wl_registry_request_handler, FDEFFECT_NEVER},
		{&wl_buffer_interface, &wl_buffer_event_handler,
				&wl_buffer_request_handler, FDEFFECT_MAYBE},
		{&wl_surface_interface, &wl_surface_event_handler,
				&wl_surface_request_handler, FDEFFECT_MAYBE},

		// List all other known global object interface types
		{&wl_compositor_interface, NULL, NULL, FDEFFECT_MAYBE},
		{&wl_subcompositor_interface, NULL, NULL, FDEFFECT_MAYBE},
		{&wl_data_device_manager_interface, NULL, NULL, FDEFFECT_MAYBE},
		{&wl_shm_interface, NULL, NULL, FDEFFECT_MAYBE},
		{&wl_shm_pool_interface, NULL, NULL, FDEFFECT_MAYBE},
		{&xdg_wm_base_interface, NULL, NULL, FDEFFECT_MAYBE},
		{&wp_presentation_interface, NULL, NULL, FDEFFECT_MAYBE},
		{&wl_seat_interface, NULL, NULL, FDEFFECT_MAYBE},
		{&wl_output_interface, NULL, NULL, FDEFFECT_MAYBE},

		// List all interfaces with additional guidance
		{&wl_pointer_interface, NULL, NULL, FDEFFECT_NEVER},
		{&wl_keyboard_interface, &wl_keyboard_event_handler, NULL,
				FDEFFECT_NEVER},
		{&wl_touch_interface, NULL, NULL, FDEFFECT_NEVER},

		{NULL, NULL, NULL, FDEFFECT_MAYBE}};

void init_message_tracker(struct message_tracker *mt)
{
	memset(mt, 0, sizeof(*mt));

	struct wp_object *display_obj = calloc(1, sizeof(struct wp_object));
	display_obj->obj_id = 1;
	display_obj->type = &wl_display_interface;
	listset_insert(&mt->objects, display_obj);
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

static void invoke_msg_handler(const struct wl_message *msg,
		const uint32_t *const payload, const int paylen,
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
			// Consume an fd; TODO
			call_args_val[nargs].si = 9999;
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
			if (type) {
				struct wp_object *new_obj = calloc(
						1, sizeof(struct wp_object));
				new_obj->obj_id = v;
				new_obj->type = type;
				listset_insert(&mt->objects, new_obj);

				call_args_val[nargs].obj = new_obj;
				call_args_ptr[nargs] =
						&call_args_val[nargs].obj;
				call_types[nargs] = &ffi_type_pointer;
				nargs++;
			} else {
				/* I.e, for wl_registry.bind, an object with
				 * NULL type is passed in as its object id */
				call_args_val[nargs].ui = v;
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
				"Message parse length overflow, i=%d, len=%d, c=%c\n",
				i, paylen, *c);
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

bool handle_message(struct message_tracker *mt, bool from_client, void *data,
		int data_len, int *consumed_length, int *fds, int fds_len,
		int *n_consumed_fds, bool *buffer_changes)
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
			ctx.obj = objh;
			ctx.drop_this_msg = false;
			ctx.can_buffer_changes_result = true;
			if (handler && handler->effect == FDEFFECT_NEVER) {
				// Change the default value; handler function
				// may yet override
				ctx.can_buffer_changes_result = false;
			}

			const uint32_t *payload = header + 2;
			invoke_msg_handler(msg, payload, len / 4 - 2, fn, &ctx,
					mt);
			// Flag set by the protocol handler function
			if (ctx.drop_this_msg) {
				return false; // DROP
			}
			*buffer_changes = ctx.can_buffer_changes_result;
		} else {
			wp_log(WP_DEBUG, "Unidentified %s from known object\n",
					from_client ? "request" : "event");
			*buffer_changes = true;
		}
	} else {
		wp_log(WP_DEBUG, "Unidentified object %d with %s\n", obj,
				from_client ? "request" : "event");
		*buffer_changes = true;
	}
	(void)fds;
	(void)fds_len;
	(void)n_consumed_fds;
	return true; // keep
}
