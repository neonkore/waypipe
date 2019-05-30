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
#include <wayland-client-defs.h>
#include <wayland-server-defs.h>
// Include order required as some require e.g. &wl_buffer_interface
#include <gtk-primary-selection-client-defs.h>
#include <gtk-primary-selection-server-defs.h>
#include <input-method-unstable-v2-client-defs.h>
#include <input-method-unstable-v2-server-defs.h>
#include <linux-dmabuf-unstable-v1-client-defs.h>
#include <linux-dmabuf-unstable-v1-server-defs.h>
#include <presentation-time-client-defs.h>
#include <presentation-time-server-defs.h>
#include <virtual-keyboard-unstable-v1-client-defs.h>
#include <virtual-keyboard-unstable-v1-server-defs.h>
#include <xdg-shell-client-defs.h>
#include <xdg-shell-server-defs.h>
#undef WAYLAND_CLIENT_H
#undef WAYLAND_SERVER_H

#include "util.h"

#include <stdlib.h>
#include <string.h>

static inline struct context *get_context(void *first_arg, void *second_arg)
{
	(void)second_arg;
	return (struct context *)first_arg;
}

struct wp_shm_pool {
	struct wp_object base;
	struct shadow_fd *owned_buffer;
};

struct wp_buffer {
	struct wp_object base;
	struct shadow_fd *owned_buffer;

	int32_t shm_offset;
	int32_t shm_width;
	int32_t shm_height;
	int32_t shm_stride;
	uint32_t shm_format;
};

struct wp_keyboard {
	struct wp_object base;
	struct shadow_fd *owned_buffer;
};

struct damage_record {
	struct damage_record *next;
	int x, y, width, height;
	bool buffer_coordinates;
};

struct wp_surface {
	struct wp_object base;

	struct damage_record *damage_stack;
	uint32_t attached_buffer_id;
	int32_t scale;
	int32_t transform;
};

void destroy_wp_object(struct fd_translation_map *map, struct wp_object *object)
{
	if (object->type == &wl_shm_pool_interface) {
		struct wp_shm_pool *r = (struct wp_shm_pool *)object;
		if (r->owned_buffer) {
			shadow_decref(map, r->owned_buffer);
		}
	} else if (object->type == &wl_buffer_interface) {
		struct wp_buffer *r = (struct wp_buffer *)object;
		if (r->owned_buffer) {
			shadow_decref(map, r->owned_buffer);
		}
	} else if (object->type == &wl_surface_interface) {
		struct wp_surface *r = (struct wp_surface *)object;
		while (r->damage_stack) {
			struct damage_record *nxt = r->damage_stack->next;
			free(r->damage_stack);
			r->damage_stack = nxt;
		}
	} else if (object->type == &wl_keyboard_interface) {
		struct wp_keyboard *r = (struct wp_keyboard *)object;
		if (r->owned_buffer) {
			shadow_decref(map, r->owned_buffer);
		}
	}
	free(object);
}
struct wp_object *create_wp_object(uint32_t id, const struct wl_interface *type)
{
	/* Note: if custom types are ever implemented for globals, they would
	 * need special replacement logic when the type is set */
	struct wp_object *new_obj;
	if (type == &wl_shm_pool_interface) {
		new_obj = calloc(1, sizeof(struct wp_shm_pool));
	} else if (type == &wl_buffer_interface) {
		new_obj = calloc(1, sizeof(struct wp_buffer));
	} else if (type == &wl_surface_interface) {
		new_obj = calloc(1, sizeof(struct wp_surface));
		((struct wp_surface *)new_obj)->scale = 1;
	} else if (type == &wl_keyboard_interface) {
		new_obj = calloc(1, sizeof(struct wp_keyboard));
	} else {
		new_obj = calloc(1, sizeof(struct wp_object));
	}
	new_obj->obj_id = id;
	new_obj->type = type;
	return new_obj;
}

static void event_wl_display_error(void *data, struct wl_display *wl_display,
		void *object_id, uint32_t code, const char *message)
{
	struct context *context = get_context(data, wl_display);
	(void)context;
	(void)object_id;
	(void)code;
	(void)message;
}
static void event_wl_display_delete_id(
		void *data, struct wl_display *wl_display, uint32_t id)
{
	struct context *context = get_context(data, wl_display);
	struct wp_object *obj = listset_get(&context->mt->objects, id);
	if (obj) {
		listset_remove(&context->mt->objects, obj);
		destroy_wp_object(context->map, obj);
	}
}
static void request_wl_display_get_registry(struct wl_client *client,
		struct wl_resource *resource, uint32_t registry)
{
	struct context *context = get_context(client, resource);
	(void)context;
	(void)registry;
}
static void request_wl_display_sync(struct wl_client *client,
		struct wl_resource *resource, uint32_t callback)
{
	struct context *context = get_context(client, resource);
	(void)context;
	(void)callback;
}

static void event_wl_registry_global(void *data,
		struct wl_registry *wl_registry, uint32_t name,
		const char *interface, uint32_t version)
{
	struct context *context = get_context(data, wl_registry);
	bool hide_me = false;
	hide_me |= !strcmp(interface, "wl_drm");
	hide_me |= !strcmp(interface, "zwp_linux_dmabuf_v1");
	hide_me |= !strcmp(interface, "zwlr_export_dmabuf_manager_v1");
	// deprecated, and waypipe doesn't have logic for it anyway
	hide_me |= !strcmp(interface, "wl_shell");

	if (hide_me) {
		wp_log(WP_DEBUG, "Hiding %s advertisement", interface);
		context->drop_this_msg = true;
	}

	(void)name;
	(void)version;
}
static void event_wl_registry_global_remove(
		void *data, struct wl_registry *wl_registry, uint32_t name)
{
	struct context *context = get_context(data, wl_registry);
	(void)context;
	(void)name;
}
static void request_wl_registry_bind(struct wl_client *client,
		struct wl_resource *resource, uint32_t name,
		const char *interface, uint32_t version, uint32_t id)
{
	struct context *context = get_context(client, resource);
	/* The object has already been created, but its type is NULL */
	struct wp_object *the_object = listset_get(&context->mt->objects, id);
	for (int i = 0; handlers[i].interface; i++) {
		if (!strcmp(interface, handlers[i].interface->name)) {
			// Set the object type
			the_object->type = handlers[i].interface;
			return;
		}
	}
	listset_remove(&context->mt->objects, the_object);
	free(the_object);

	wp_log(WP_DEBUG, "Binding fail name=%d %s id=%d (v%d)", name, interface,
			id, version);
	(void)name;
	(void)version;
}

static void event_wl_buffer_release(void *data, struct wl_buffer *wl_buffer)
{
	struct context *context = get_context(data, wl_buffer);
	(void)context;
}
static void request_wl_buffer_destroy(
		struct wl_client *client, struct wl_resource *resource)
{

	struct context *context = get_context(client, resource);
	(void)context;
}

static int compute_damage_coordinates(int *xlow, int *xhigh, int *ylow,
		int *yhigh, const struct damage_record *rec, int buf_width,
		int buf_height, int transform, int scale)
{
	if (scale <= 0) {
		wp_log(WP_ERROR,
				"Not applying damage due to invalid buffer scale (%d)\n",
				scale);
		return -1;
	}
	if (transform < 0 || transform > 8) {
		wp_log(WP_ERROR,
				"Not applying damage due to invalid buffer transform (%d)\n",
				transform);
		return -1;
	}
	if (rec->buffer_coordinates) {
		wp_log(WP_ERROR, "%d %d %d %d", rec->x, rec->y, rec->width,
				rec->height);
		*xlow = rec->x;
		*xhigh = rec->x + rec->width;
		*ylow = rec->y;
		*yhigh = rec->y + rec->height;
	} else {
		int xl = rec->x * scale;
		int yl = rec->y * scale;
		int xh = (rec->width + rec->x) * scale;
		int yh = (rec->y + rec->height) * scale;

		/* Each of the eight transformations corresponds to a unique set
		 * of reflections: X<->Y | Xflip | Yflip */
		uint32_t magic = 0x14723650;
		/* idx     76543210
		 * xyech = 10101010
		 * xflip = 01101100
		 * yflip = 00110110
		 *         ffff
		 *         21  21
		 *         789 789
		 *         00000000
		 */
		bool xyexch = magic & (1 << (4 * transform));
		bool xflip = magic & (1 << (4 * transform + 1));
		bool yflip = magic & (1 << (4 * transform + 2));
		int ew = xyexch ? buf_height : buf_width;
		int eh = xyexch ? buf_width : buf_height;
		if (xflip) {
			int tmp = ew - xh;
			xh = ew - xl;
			xl = tmp;
		}
		if (yflip) {
			int tmp = eh - yh;
			yh = eh - yl;
			yl = tmp;
		}
		if (xyexch) {
			*xlow = yl;
			*xhigh = yh;
			*ylow = xl;
			*yhigh = xh;
		} else {
			*xlow = xl;
			*xhigh = xh;
			*ylow = yl;
			*yhigh = yh;
		}
	}
	return 0;
}
static void request_wl_surface_attach(struct wl_client *client,
		struct wl_resource *resource, struct wl_resource *buffer,
		int32_t x, int32_t y)
{
	struct context *context = get_context(client, resource);
	(void)x;
	(void)y;
	struct wp_object *bufobj = (struct wp_object *)buffer;
	if (!bufobj) {
		// todo: if nullable, handle error/abort earlier in the chain
		wp_log(WP_ERROR, "Buffer to be attached is null");
		return;
	}
	if (bufobj->type != &wl_buffer_interface) {
		wp_log(WP_ERROR, "Buffer to be attached has the wrong type");
		return;
	}
	struct wp_surface *surface = (struct wp_surface *)context->obj;
	surface->attached_buffer_id = bufobj->obj_id;
}
static void request_wl_surface_commit(
		struct wl_client *client, struct wl_resource *resource)
{
	struct context *context = get_context(client, resource);
	struct wp_surface *surface = (struct wp_surface *)context->obj;
	if (!surface->attached_buffer_id) {
		/* The wl_surface.commit operation applies all "pending state",
		 * much of which we don't care about. Typically, when a
		 * wl_surface is first created, it is soon committed to
		 * atomically update state variables. An attached wl_buffer is
		 * not required.
		 */
		return;
	}
	struct wp_object *obj = listset_get(
			&context->mt->objects, surface->attached_buffer_id);
	if (!obj) {
		wp_log(WP_ERROR, "Attached buffer no longer exists");
		return;
	}
	if (obj->type != &wl_buffer_interface) {
		wp_log(WP_ERROR,
				"Buffer to commit has the wrong type, and may have been recycled");
		return;
	}
	struct wp_buffer *buf = (struct wp_buffer *)obj;
	struct shadow_fd *sfd = buf->owned_buffer;
	if (!sfd) {
		wp_log(WP_ERROR, "wp_buffer to be committed  has no fd");
		return;
	}
	if (sfd->type != FDC_FILE) {
		wp_log(WP_ERROR, "fd associated with surface is not file-like");
		return;
	}
	if (!context->on_display_side) {
		sfd->is_dirty = true;
		int intv_max = INT32_MIN, intv_min = INT32_MAX;

		// Translate damage stack into damage records for the fd buffer
		struct damage_record *rec = surface->damage_stack;
		while (rec) {
			// TODO: take into account transformations
			int xlow, xhigh, ylow, yhigh;
			int r = compute_damage_coordinates(&xlow, &xhigh, &ylow,
					&yhigh, rec, buf->shm_width,
					buf->shm_height, surface->transform,
					surface->scale);
			if (r != -1) {
				/* Clip the damage rectangle to the containing
				 * buffer. */
				xlow = clamp(xlow, 0, buf->shm_width);
				xhigh = clamp(xhigh, 0, buf->shm_width);
				ylow = clamp(ylow, 0, buf->shm_height);
				yhigh = clamp(yhigh, 0, buf->shm_height);

				int low = buf->shm_offset +
					  buf->shm_stride * ylow + xlow;
				int high = buf->shm_offset +
					   buf->shm_stride * yhigh + xhigh;
				intv_max = max(intv_max, high);
				intv_min = min(intv_min, low);
			}

			struct damage_record *nxt = rec->next;
			free(rec);
			rec = nxt;
		}
		surface->damage_stack = NULL;

		sfd->dirty_interval_max =
				max(sfd->dirty_interval_max, intv_max);
		sfd->dirty_interval_min =
				min(sfd->dirty_interval_min, intv_min);
	}
}
static void request_wl_surface_destroy(
		struct wl_client *client, struct wl_resource *resource)
{
	struct context *context = get_context(client, resource);
	(void)context;
}
static void request_wl_surface_damage(struct wl_client *client,
		struct wl_resource *resource, int32_t x, int32_t y,
		int32_t width, int32_t height)
{
	struct context *context = get_context(client, resource);
	if (context->on_display_side) {
		// The display side does not need to track the damage
		return;
	}
	// A rectangle of the buffer was damaged, hence backing buffers
	// may be updated.
	struct damage_record *damage = calloc(1, sizeof(struct damage_record));
	damage->buffer_coordinates = false;
	damage->x = x;
	damage->y = y;
	damage->width = width;
	damage->height = height;

	struct wp_surface *surface = (struct wp_surface *)context->obj;
	damage->next = surface->damage_stack;
	surface->damage_stack = damage;
}
static void request_wl_surface_damage_buffer(struct wl_client *client,
		struct wl_resource *resource, int32_t x, int32_t y,
		int32_t width, int32_t height)
{
	struct context *context = get_context(client, resource);
	if (context->on_display_side) {
		// The display side does not need to track the damage
		return;
	}
	// A rectangle of the buffer was damaged, hence backing buffers
	// may be updated.
	struct damage_record *damage = calloc(1, sizeof(struct damage_record));
	damage->buffer_coordinates = true;
	damage->x = x;
	damage->y = y;
	damage->width = width;
	damage->height = height;

	struct wp_surface *surface = (struct wp_surface *)context->obj;
	damage->next = surface->damage_stack;
	surface->damage_stack = damage;
}
static void request_wl_surface_set_buffer_transform(struct wl_client *client,
		struct wl_resource *resource, int32_t transform)
{
	struct context *context = get_context(client, resource);
	struct wp_surface *surface = (struct wp_surface *)context->obj;
	surface->transform = transform;
}
static void request_wl_surface_set_buffer_scale(struct wl_client *client,
		struct wl_resource *resource, int32_t scale)
{
	struct context *context = get_context(client, resource);
	struct wp_surface *surface = (struct wp_surface *)context->obj;
	surface->scale = scale;
}

static void event_wl_keyboard_keymap(void *data,
		struct wl_keyboard *wl_keyboard, uint32_t format, int32_t fd,
		uint32_t size)
{
	struct context *context = get_context(data, wl_keyboard);

	struct shadow_fd *sfd = get_shadow_for_local_fd(context->map, fd);
	if (!sfd) {
		wp_log(WP_ERROR, "Failed to find shadow matching lfd=%d", fd);
		return;
	}
	if (sfd->type != FDC_FILE || sfd->file_size != size) {
		wp_log(WP_ERROR,
				"keymap candidate RID=%d was not file-like (type=%d), and with size=%ld did not match %d",
				sfd->remote_id, sfd->type, sfd->file_size,
				size);
		return;
	}
	struct wp_keyboard *keyboard = (struct wp_keyboard *)context->obj;
	keyboard->owned_buffer = sfd;
	sfd->has_owner = true;
	sfd->refcount++;
	(void)format;
}

static void request_wl_shm_create_pool(struct wl_client *client,
		struct wl_resource *resource, uint32_t id, int32_t fd,
		int32_t size)
{
	struct context *context = get_context(client, resource);
	struct wp_shm_pool *the_shm_pool = (struct wp_shm_pool *)listset_get(
			&context->mt->objects, id);
	struct shadow_fd *sfd = get_shadow_for_local_fd(context->map, fd);
	if (!sfd) {
		wp_log(WP_ERROR, "Failed to find shadow matching lfd=%d", fd);
		return;
	}
	/* It may be valid for the file descriptor size to be larger than the
	 * immediately advertised size, since the call to wl_shm.create_pool
	 * may be followed by wl_shm_pool.resize, which then increases the size
	 */
	if (sfd->type != FDC_FILE || (int32_t)sfd->file_size < size) {
		wp_log(WP_ERROR,
				"File type or size mismatch for RID=%d with claimed: %d %d | %ld %d",
				sfd->remote_id, sfd->type, FDC_FILE,
				sfd->file_size, size);
		return;
	}

	the_shm_pool->owned_buffer = sfd;
	sfd->has_owner = true;
	sfd->refcount++;
}

static void request_wl_shm_pool_resize(struct wl_client *client,
		struct wl_resource *resource, int32_t size)
{
	struct context *context = get_context(client, resource);
	struct wp_shm_pool *the_shm_pool = (struct wp_shm_pool *)context->obj;

	if (!the_shm_pool->owned_buffer) {
		wp_log(WP_ERROR, "Pool to be resize owns no buffer");
		return;
	}
	if ((int32_t)the_shm_pool->owned_buffer->file_size >= size) {
		// The underlying buffer was already resized by the time
		// this protocol message was received
		return;
	}
	wp_log(WP_ERROR, "Pool resize to %d, TODO", size);
}
static void request_wl_shm_pool_create_buffer(struct wl_client *client,
		struct wl_resource *resource, uint32_t id, int32_t offset,
		int32_t width, int32_t height, int32_t stride, uint32_t format)
{
	struct context *context = get_context(client, resource);
	struct wp_shm_pool *the_shm_pool = (struct wp_shm_pool *)context->obj;
	struct wp_buffer *the_buffer = (struct wp_buffer *)listset_get(
			&context->mt->objects, id);
	if (!the_buffer) {
		wp_log(WP_ERROR, "No buffer available");
		return;
	}
	if (!the_shm_pool->owned_buffer) {
		wp_log(WP_ERROR,
				"Creating a wl_buffer from a pool that does not own an fd");
		return;
	}

	the_buffer->owned_buffer = the_shm_pool->owned_buffer;
	the_buffer->owned_buffer->refcount++;
	the_buffer->shm_offset = offset;
	the_buffer->shm_width = width;
	the_buffer->shm_height = height;
	the_buffer->shm_stride = stride;
	the_buffer->shm_format = format;
}

static const struct wl_display_listener wl_display_event_handler = {
		.error = event_wl_display_error,
		.delete_id = event_wl_display_delete_id};
static const struct wl_display_interface wl_display_request_handler = {
		.get_registry = request_wl_display_get_registry,
		.sync = request_wl_display_sync};
static const struct wl_registry_listener wl_registry_event_handler = {
		.global = event_wl_registry_global,
		.global_remove = event_wl_registry_global_remove};
static const struct wl_registry_interface wl_registry_request_handler = {
		.bind = request_wl_registry_bind};
static const struct wl_buffer_listener wl_buffer_event_handler = {
		.release = event_wl_buffer_release};
static const struct wl_buffer_interface wl_buffer_request_handler = {
		.destroy = request_wl_buffer_destroy};
static const struct wl_surface_interface wl_surface_request_handler = {
		.attach = request_wl_surface_attach,
		.commit = request_wl_surface_commit,
		.damage = request_wl_surface_damage,
		.damage_buffer = request_wl_surface_damage_buffer,
		.destroy = request_wl_surface_destroy,
		.set_buffer_scale = request_wl_surface_set_buffer_scale,
		.set_buffer_transform = request_wl_surface_set_buffer_transform,
};
static const struct wl_keyboard_listener wl_keyboard_event_handler = {
		.keymap = event_wl_keyboard_keymap};
static const struct wl_shm_interface wl_shm_request_handler = {
		.create_pool = request_wl_shm_create_pool,
};
static const struct wl_shm_pool_interface wl_shm_pool_request_handler = {
		.resize = request_wl_shm_pool_resize,
		.create_buffer = request_wl_shm_pool_create_buffer,

};

const struct msg_handler handlers[] = {
		{&wl_display_interface, &wl_display_event_handler,
				&wl_display_request_handler},
		{&wl_registry_interface, &wl_registry_event_handler,
				&wl_registry_request_handler},
		{&wl_buffer_interface, &wl_buffer_event_handler,
				&wl_buffer_request_handler},
		{&wl_surface_interface, NULL, &wl_surface_request_handler},
		{&wl_keyboard_interface, &wl_keyboard_event_handler, NULL},

		/* List all other known global object interface types, so
		 * that the parsing code can identify all fd usages */
		// wayland
		{&wl_compositor_interface, NULL, NULL},
		{&wl_subcompositor_interface, NULL, NULL},
		{&wl_data_device_manager_interface, NULL, NULL},
		{&wl_shm_interface, NULL, &wl_shm_request_handler},
		{&wl_shm_pool_interface, NULL, &wl_shm_pool_request_handler},
		{&wl_seat_interface, NULL, NULL},
		{&wl_output_interface, NULL, NULL},
		// xdg-shell
		{&xdg_wm_base_interface, NULL, NULL},
		// presentation-time
		{&wp_presentation_interface, NULL, NULL},
		// gtk-primary-selection
		{&gtk_primary_selection_device_manager_interface, NULL, NULL},
		// virtual-keyboard
		{&zwp_virtual_keyboard_manager_v1_interface, NULL, NULL},
		// input-method
		{&zwp_input_method_manager_v2_interface, NULL, NULL},
		// linux-dmabuf
		{&zwp_linux_dmabuf_v1_interface, NULL, NULL},

		{NULL, NULL, NULL}};
const struct wl_interface *the_display_interface = &wl_display_interface;
