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
};
void event_wl_display_error(void *data, struct wl_display *wl_display,
		void *object_id, uint32_t code, const char *message)
{
	struct context *context = (struct context *)data;
	(void)context;
	(void)wl_display;
	(void)object_id;
	(void)code;
	(void)message;
}
void event_wl_display_delete_id(
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
void request_wl_display_get_registry(struct wl_client *client,
		struct wl_resource *resource, uint32_t registry)
{
	struct context *context = (struct context *)client;
	wp_log(WP_DEBUG, "Getting registry: %lx %lx %d\n", (uint64_t)client,
			(uint64_t)resource, registry);
	(void)context;
	(void)resource;
	(void)registry;
}

void event_wl_registry_global(void *data, struct wl_registry *wl_registry,
		uint32_t name, const char *interface, uint32_t version)
{
	struct context *context = (struct context *)data;
	if (!strcmp(interface, "wl_drm")) {
		wp_log(WP_DEBUG, "Hiding wl_drm advertisement: %lx\n",
				(uint64_t)context);
		context->drop_this_msg = true;
	}
	if (!strcmp(interface, "zwp_linux_dmabuf_v1")) {
		wp_log(WP_DEBUG,
				"Hiding zwp_linux_dmabuf_v1 advertisement: %lx\n",
				(uint64_t)context);
		context->drop_this_msg = true;
	}

	(void)wl_registry;
	(void)name;
	(void)version;
}
void event_wl_registry_global_remove(
		void *data, struct wl_registry *wl_registry, uint32_t name)
{
	struct context *context = (struct context *)data;
	(void)context;
	(void)wl_registry;
	(void)name;
}
void request_wl_registry_bind(struct wl_client *client,
		struct wl_resource *resource, uint32_t name,
		const char *interface, uint32_t version, uint32_t id)
{
	(void)name;
	(void)interface;
	(void)version;
	(void)id;
	(void)resource;
	(void)client;
}

static const struct wl_display_listener wl_display_event_handler = {
		event_wl_display_error, event_wl_display_delete_id};

// Note that the 'sync' request is entirely unrelated to our task, and our
// implementation of it would do nothing
static const struct wl_display_interface wl_display_request_handler = {
		NULL, request_wl_display_get_registry};
static const struct wl_registry_listener wl_registry_event_handler = {
		event_wl_registry_global, event_wl_registry_global_remove};

static const struct wl_registry_interface wl_registry_request_handler = {
		request_wl_registry_bind};

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
struct wp_object *listset_get(struct obj_list *lst, int id)
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

void init_message_tracker(struct message_tracker *mt)
{
	memset(mt, 0, sizeof(*mt));
	mt->handlers[0].interface = &wl_display_interface;
	mt->handlers[0].event_handlers = &wl_display_event_handler;
	mt->handlers[0].request_handlers = &wl_display_request_handler;
	mt->handlers[1].interface = &wl_registry_interface;
	mt->handlers[1].event_handlers = &wl_registry_event_handler;
	mt->handlers[1].request_handlers = &wl_registry_request_handler;

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

struct msg_handler *get_handler_for_interface(
		struct message_tracker *mt, const struct wl_interface *intf)
{
	for (int i = 0; i < 50; i++) {
		if (mt->handlers[i].interface == intf) {
			return &mt->handlers[i];
		}
		if (!mt->handlers[i].interface) {
			return NULL;
		}
	}
	return NULL;
}

struct uarg {
	union {
		uint32_t ui;
		char *str;
		struct wp_object *obj;
	};
};

void invoke_msg_handler(const struct wl_message *msg, const uint32_t *payload,
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

	int k = 0;

	// TODO: compensate for version strings
	for (const char *c = msg->signature; *c; c++, k++) {
		// Skip over version data?
		while (*c >= '0' && *c <= '9') {
			c++;
		}

		const struct wl_interface *type = msg->types[k];
		switch (*c) {
		case 'n': {
			// Point directly into source buffer, if
			// we can.
			uint32_t v = *payload++;

			struct wp_object *new_obj =
					calloc(1, sizeof(struct wp_object));
			new_obj->obj_id = v;
			new_obj->type = type;
			listset_insert(&mt->objects, new_obj);

			call_args_val[nargs].obj = new_obj;
			call_args_ptr[nargs] = &call_args_val[nargs].obj;
			call_types[nargs] = &ffi_type_pointer;
			nargs++;
		} break;
		case 'u': {
			uint32_t v = *payload++;
			call_args_val[nargs].ui = v;
			call_args_ptr[nargs] = &call_args_val[nargs].ui;
			call_types[nargs] = &ffi_type_uint32;
			nargs++;
		} break;
		case 's': {
			uint32_t len = *payload++;
			char *str = (char *)payload;
			call_args_val[nargs].str = str;
			call_args_ptr[nargs] = &call_args_val[nargs].str;
			call_types[nargs] = &ffi_type_pointer;
			nargs++;

			payload += (len / 4);
		} break;
		default:
			wp_log(WP_ERROR, "Unidentified message type %c\n", *c);
			break;
		}
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
		int *n_consumed_fds)
{
	const uint32_t *const header = (uint32_t *)data;
	int obj = (int)header[0];
	int meth = (int)((header[1] << 16) >> 16);
	int len = (int)(header[1] >> 16);
	*consumed_length = len;
	if (len > data_len) {
		wp_log(WP_ERROR,
				"Message length overflow: %d claimed vs %d available",
				len, data_len);
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
			struct msg_handler *handler = get_handler_for_interface(
					mt, objh->type);
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
			const uint32_t *payload = header + 2;
			invoke_msg_handler(msg, payload, fn, &ctx, mt);
			// Flag set by the protocol handler function
			if (ctx.drop_this_msg) {
				return false; // DROP
			}
		}
	}
	(void)fds;
	(void)fds_len;
	(void)n_consumed_fds;
	return true; // keep
}
