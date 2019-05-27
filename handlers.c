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

#include "util.h"

#include <stdlib.h>
#include <string.h>

static inline struct context *get_context(void *first_arg, void *second_arg)
{
	(void)second_arg;
	return (struct context *)first_arg;
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
		// object specific cleanup goes here
		free(obj);
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
		wp_log(WP_DEBUG, "Hiding %s advertisement\n", interface);
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

void request_wl_registry_bind(struct wl_client *client,
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

	wp_log(WP_DEBUG, "Binding fail name=%d %s id=%d (v%d)\n", name,
			interface, id, version);
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
	// User requests surface destruction
	// TODO: free backing store?
	(void)context;
}
void request_wl_surface_attach(struct wl_client *client,
		struct wl_resource *resource, struct wl_resource *buffer,
		int32_t x, int32_t y)
{
	struct context *context = get_context(client, resource);
	(void)x;
	(void)y;
	struct wp_object *bufobj = (struct wp_object *)buffer;
	if (!bufobj) {
		// todo: if nullable, handle error/abort earlier in the chain
		wp_log(WP_ERROR, "Buffer to be attached is null\n");
		return;
	}
	if (!bufobj->owned_buffer) {
		wp_log(WP_ERROR, "Buffer to be attached does not own an fd\n");
		return;
	}
	if (context->obj->owned_buffer) {
		context->obj->owned_buffer->refcount--;
		if (context->obj->owned_buffer->refcount == 0) {
			wp_log(WP_ERROR,
					"TODO: unhandled shadow refcount zero\n");
		}
	}
	context->obj->owned_buffer = bufobj->owned_buffer;
	context->obj->owned_buffer->refcount++;
}

void request_wl_surface_commit(
		struct wl_client *client, struct wl_resource *resource)
{
	struct context *context = get_context(client, resource);
	if (!context->obj->owned_buffer) {
		wp_log(WP_ERROR, "Surface to be committed owns no buffer\n");
		return;
	}
	if (!context->on_display_side) {
		context->obj->owned_buffer->is_dirty = true;
	}
}
static void request_wl_surface_destroy(
		struct wl_client *client, struct wl_resource *resource)
{
	struct context *context = get_context(client, resource);
	// User requests surface destruction
	(void)context;
}
static void request_wl_surface_damage(struct wl_client *client,
		struct wl_resource *resource, int32_t x, int32_t y,
		int32_t width, int32_t height)
{
	struct context *context = get_context(client, resource);
	// A rectangle of the buffer was damaged, hence backing buffers
	// may be updated.
	(void)context;
	(void)x;
	(void)y;
	(void)width;
	(void)height;
}
static void event_wl_keyboard_keymap(void *data,
		struct wl_keyboard *wl_keyboard, uint32_t format, int32_t fd,
		uint32_t size)
{
	struct context *context = get_context(data, wl_keyboard);
	(void)context;

	struct shadow_fd *sfd = get_shadow_for_local_fd(context->map, fd);
	if (!sfd) {
		wp_log(WP_ERROR, "Failed to find shadow matching lfd=%d\n", fd);
		return;
	}
	context->obj->owned_buffer = sfd;
	sfd->has_owner = true;
	sfd->refcount++;

	(void)format;

	if (sfd->type != FDC_FILE || (uint32_t)sfd->file_size != size) {
		wp_log(WP_ERROR,
				"File type or size mismatch for RID=%d with claimed: %d %d | %ld %d\n",
				sfd->remote_id, sfd->type, FDC_FILE,
				sfd->file_size, size);
	}
}
static void request_wl_shm_create_pool(struct wl_client *client,
		struct wl_resource *resource, uint32_t id, int32_t fd,
		int32_t size)
{
	struct context *context = get_context(client, resource);
	struct wp_object *the_shm_pool = listset_get(&context->mt->objects, id);
	struct shadow_fd *sfd = get_shadow_for_local_fd(context->map, fd);
	if (!sfd) {
		wp_log(WP_ERROR, "Failed to find shadow matching lfd=%d\n", fd);
		return;
	}
	the_shm_pool->owned_buffer = sfd;
	sfd->has_owner = true;
	sfd->refcount++;
	if (sfd->type != FDC_FILE || (int32_t)sfd->file_size != size) {
		wp_log(WP_ERROR,
				"File type or size mismatch for RID=%d with claimed: %d %d | %ld %d\n",
				sfd->remote_id, sfd->type, FDC_FILE,
				sfd->file_size, size);
	}
}
static void request_wl_shm_pool_resize(struct wl_client *client,
		struct wl_resource *resource, int32_t size)
{
	struct context *context = get_context(client, resource);
	(void)context;
	wp_log(WP_ERROR, "Pool resize to %d\n", size);
}
static void request_wl_shm_pool_create_buffer(struct wl_client *client,
		struct wl_resource *resource, uint32_t id, int32_t offset,
		int32_t width, int32_t height, int32_t stride, uint32_t format)
{
	struct context *context = get_context(client, resource);
	struct wp_object *the_buffer = listset_get(&context->mt->objects, id);
	if (!the_buffer) {
		wp_log(WP_ERROR, "No buffer available");
		return;
	}
	(void)offset;
	(void)width;
	(void)height;
	(void)stride;
	(void)format;
	if (!context->obj->owned_buffer) {
		wp_log(WP_ERROR,
				"Creating a wl_buffer from a pool that does not own an fd");
		return;
	}

	the_buffer->owned_buffer = context->obj->owned_buffer;
	the_buffer->owned_buffer->refcount++;
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

static const struct wl_surface_listener wl_surface_event_handler = {
		.enter = NULL, .leave = NULL};

static const struct wl_surface_interface wl_surface_request_handler = {
		.attach = request_wl_surface_attach,
		.commit = request_wl_surface_commit,
		.destroy = request_wl_surface_destroy,
		.damage = request_wl_surface_damage};
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
		{&wl_surface_interface, &wl_surface_event_handler,
				&wl_surface_request_handler},
		{&wl_keyboard_interface, &wl_keyboard_event_handler, NULL},

		// List all other known global object interface types
		{&wl_compositor_interface, NULL, NULL},
		{&wl_subcompositor_interface, NULL, NULL},
		{&wl_data_device_manager_interface, NULL, NULL},
		{&wl_shm_interface, NULL, &wl_shm_request_handler},
		{&wl_shm_pool_interface, NULL, &wl_shm_pool_request_handler},
		{&xdg_wm_base_interface, NULL, NULL},
		{&wp_presentation_interface, NULL, NULL},
		{&wl_seat_interface, NULL, NULL},
		{&wl_output_interface, NULL, NULL},

		{NULL, NULL, NULL}};
const struct wl_interface *the_display_interface = &wl_display_interface;
