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
#include <wayland-drm-client-defs.h>
#include <wayland-drm-server-defs.h>
#include <wlr-screencopy-unstable-v1-client-defs.h>
#include <wlr-screencopy-unstable-v1-server-defs.h>
#include <xdg-shell-client-defs.h>
#include <xdg-shell-server-defs.h>
#undef WAYLAND_CLIENT_H
#undef WAYLAND_SERVER_H

#include "util.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static inline struct context *get_context(void *first_arg, void *second_arg)
{
	(void)second_arg;
	return (struct context *)first_arg;
}

struct wp_shm_pool {
	struct wp_object base;
	struct shadow_fd *owned_buffer;
};

enum buffer_type { BUF_SHM, BUF_DMA };

// This should be a safe limit for the maximum number of dmabuf planes
#define MAX_DMABUF_PLANES 8

struct wp_buffer {
	struct wp_object base;

	enum buffer_type type;
	struct shadow_fd *shm_buffer;
	int32_t shm_offset;
	int32_t shm_width;
	int32_t shm_height;
	int32_t shm_stride;
	uint32_t shm_format;

	int dmabuf_nplanes;
	int32_t dmabuf_width;
	int32_t dmabuf_height;
	uint32_t dmabuf_format;
	uint32_t dmabuf_flags;
	struct shadow_fd *dmabuf_buffers[MAX_DMABUF_PLANES];
	uint32_t dmabuf_offsets[MAX_DMABUF_PLANES];
	uint32_t dmabuf_strides[MAX_DMABUF_PLANES];
	uint64_t dmabuf_modifiers[MAX_DMABUF_PLANES];
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

struct wp_wlr_screencopy_frame {
	struct wp_object base;
	/* Link to a wp_buffer instead of its underlying data,
	 * because if the buffer object is destroyed early, then
	 * we do not want to accidentally write over a section of a shm_pool
	 * which is now used for transport in the reverse direction.
	 */
	uint32_t buffer_id;
};

struct waypipe_presentation {
	struct wp_object base;

	// reference clock - given clock
	long clock_delta_nsec;
	int clock_id;
};
struct waypipe_presentation_feedback {
	struct wp_object base;
	long clock_delta_nsec;
};

struct wp_linux_dmabuf_params {
	struct wp_object base;

	struct shadow_fd *sfds;

	// These variables are set by 'params.create', and passed on in
	// params.created
	int32_t create_width;
	int32_t create_height;
	uint32_t create_format;
	uint32_t create_flags;

	struct {
		int fd;
		struct shadow_fd *buffer;
		uint32_t offset;
		uint32_t stride;
		uint64_t modifier;
		char *msg;
		int msg_len;
	} add[MAX_DMABUF_PLANES];
	int nplanes;
};

static void free_damage_stack(struct damage_record **root)
{
	if (root && *root) {
		struct damage_record *r = *root;
		while (r) {
			struct damage_record *nxt = r->next;
			free(r);
			r = nxt;
		}
		*root = NULL;
	}
}
void destroy_wp_object(struct fd_translation_map *map, struct wp_object *object)
{
	if (object->type == &wl_shm_pool_interface) {
		struct wp_shm_pool *r = (struct wp_shm_pool *)object;
		if (r->owned_buffer) {
			shadow_decref(map, r->owned_buffer);
		}
	} else if (object->type == &wl_buffer_interface) {
		struct wp_buffer *r = (struct wp_buffer *)object;
		for (int i = 0; i < MAX_DMABUF_PLANES; i++) {
			if (r->dmabuf_buffers[i]) {
				shadow_decref(map, r->dmabuf_buffers[i]);
			}
		}
		if (r->shm_buffer) {
			shadow_decref(map, r->shm_buffer);
		}
	} else if (object->type == &wl_surface_interface) {
		struct wp_surface *r = (struct wp_surface *)object;
		free_damage_stack(&r->damage_stack);
	} else if (object->type == &wl_keyboard_interface) {
		struct wp_keyboard *r = (struct wp_keyboard *)object;
		if (r->owned_buffer) {
			shadow_decref(map, r->owned_buffer);
		}
	} else if (object->type == &zwlr_screencopy_frame_v1_interface) {
		struct wp_wlr_screencopy_frame *r =
				(struct wp_wlr_screencopy_frame *)object;
		(void)r;
	} else if (object->type == &wp_presentation_interface) {
	} else if (object->type == &wp_presentation_feedback_interface) {
	} else if (object->type == &zwp_linux_buffer_params_v1_interface) {
		struct wp_linux_dmabuf_params *r =
				(struct wp_linux_dmabuf_params *)object;
		for (int i = 0; i < MAX_DMABUF_PLANES; i++) {
			if (r->add[i].buffer) {
				shadow_decref(map, r->add[i].buffer);
			}
			// Sometimes multiple entries point to the same buffer
			if (r->add[i].fd != -1) {
				if (close(r->add[i].fd) == -1) {
					wp_log(WP_ERROR,
							"Incorrect close(%d): %s",
							r->add[i].fd,
							strerror(errno));
				}

				for (int k = 0; k < MAX_DMABUF_PLANES; k++) {
					if (r->add[i].fd == r->add[k].fd) {
						r->add[k].fd = -1;
					}
				}
			}
			if (r->add[i].msg) {
				free(r->add[i].msg);
			}
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
	} else if (type == &zwlr_screencopy_frame_v1_interface) {
		new_obj = calloc(1, sizeof(struct wp_wlr_screencopy_frame));
	} else if (type == &wp_presentation_interface) {
		new_obj = calloc(1, sizeof(struct waypipe_presentation));
	} else if (type == &wp_presentation_feedback_interface) {
		new_obj = calloc(1,
				sizeof(struct waypipe_presentation_feedback));
	} else if (type == &zwp_linux_buffer_params_v1_interface) {
		new_obj = calloc(1, sizeof(struct wp_linux_dmabuf_params));
		struct wp_linux_dmabuf_params *params =
				(struct wp_linux_dmabuf_params *)new_obj;
		for (int i = 0; i < MAX_DMABUF_PLANES; i++) {
			params->add[i].fd = -1;
		}
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
	bool requires_rnode = false;
	requires_rnode |= !strcmp(interface, "wl_drm");
	requires_rnode |= !strcmp(interface, "zwp_linux_dmabuf_v1");
	requires_rnode |= !strcmp(interface, "zwlr_export_dmabuf_manager_v1");
	if (requires_rnode) {
		if (init_render_data(&context->map->rdata) == -1) {
			/* A gpu connection supported by waypipe is required on
			 * both sides, since data transfers may occur in both
			 * directions, and
			 * modifying textures may require driver support */
			wp_log(WP_DEBUG,
					"Discarding protocol advertisement for %s, render node support disabled",
					interface);
			context->drop_this_msg = true;
			return;
		}
	}

	bool unsupported = false;
	// todo: needs a working and portable test client
	unsupported |= !strcmp(interface, "zwlr_export_dmabuf_manager_v1");
	// deprecated, and waypipe doesn't have logic for it anyway
	unsupported |= !strcmp(interface, "wl_shell");
	if (unsupported) {
		wp_log(WP_DEBUG, "Hiding %s advertisement, unsupported",
				interface);
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
			if (handlers[i].interface ==
					&wp_presentation_interface) {
				// Replace the object with a specialized version
				listset_remove(&context->mt->objects,
						the_object);
				free(the_object);
				the_object = create_wp_object(
						id, &wp_presentation_interface);
				listset_insert(&context->mt->objects,
						the_object);
			}
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

static int get_shm_bytes_per_pixel(uint32_t format)
{
	switch (format) {
	case WL_SHM_FORMAT_ARGB8888:
	case WL_SHM_FORMAT_XRGB8888:
		return 4;
	case WL_SHM_FORMAT_C8:
	case WL_SHM_FORMAT_RGB332:
	case WL_SHM_FORMAT_BGR233:
		return 1;
	case WL_SHM_FORMAT_XRGB4444:
	case WL_SHM_FORMAT_XBGR4444:
	case WL_SHM_FORMAT_RGBX4444:
	case WL_SHM_FORMAT_BGRX4444:
	case WL_SHM_FORMAT_ARGB4444:
	case WL_SHM_FORMAT_ABGR4444:
	case WL_SHM_FORMAT_RGBA4444:
	case WL_SHM_FORMAT_BGRA4444:
	case WL_SHM_FORMAT_XRGB1555:
	case WL_SHM_FORMAT_XBGR1555:
	case WL_SHM_FORMAT_RGBX5551:
	case WL_SHM_FORMAT_BGRX5551:
	case WL_SHM_FORMAT_ARGB1555:
	case WL_SHM_FORMAT_ABGR1555:
	case WL_SHM_FORMAT_RGBA5551:
	case WL_SHM_FORMAT_BGRA5551:
	case WL_SHM_FORMAT_RGB565:
	case WL_SHM_FORMAT_BGR565:
		return 2;
	case WL_SHM_FORMAT_RGB888:
	case WL_SHM_FORMAT_BGR888:
		return 3;
	case WL_SHM_FORMAT_XBGR8888:
	case WL_SHM_FORMAT_RGBX8888:
	case WL_SHM_FORMAT_BGRX8888:
	case WL_SHM_FORMAT_ABGR8888:
	case WL_SHM_FORMAT_RGBA8888:
	case WL_SHM_FORMAT_BGRA8888:
	case WL_SHM_FORMAT_XRGB2101010:
	case WL_SHM_FORMAT_XBGR2101010:
	case WL_SHM_FORMAT_RGBX1010102:
	case WL_SHM_FORMAT_BGRX1010102:
	case WL_SHM_FORMAT_ARGB2101010:
	case WL_SHM_FORMAT_ABGR2101010:
	case WL_SHM_FORMAT_RGBA1010102:
	case WL_SHM_FORMAT_BGRA1010102:
		return 4;
	case WL_SHM_FORMAT_YUYV:
	case WL_SHM_FORMAT_YVYU:
	case WL_SHM_FORMAT_UYVY:
	case WL_SHM_FORMAT_VYUY:
	case WL_SHM_FORMAT_AYUV:
	case WL_SHM_FORMAT_NV12:
	case WL_SHM_FORMAT_NV21:
	case WL_SHM_FORMAT_NV16:
	case WL_SHM_FORMAT_NV61:
	case WL_SHM_FORMAT_YUV410:
	case WL_SHM_FORMAT_YVU410:
	case WL_SHM_FORMAT_YUV411:
	case WL_SHM_FORMAT_YVU411:
	case WL_SHM_FORMAT_YUV420:
	case WL_SHM_FORMAT_YVU420:
	case WL_SHM_FORMAT_YUV422:
	case WL_SHM_FORMAT_YVU422:
	case WL_SHM_FORMAT_YUV444:
	case WL_SHM_FORMAT_YVU444:
		wp_log(WP_ERROR,
				"Encountered planar wl_shm format %x; marking entire buffer",
				format);
		return -1;
	default:
		wp_log(WP_ERROR, "Unidentified WL_SHM format %x", format);
		return -1;
	}
}
static int compute_damage_coordinates(int *xlow, int *xhigh, int *ylow,
		int *yhigh, const struct damage_record *rec, int buf_width,
		int buf_height, int transform, int scale)
{
	if (scale <= 0) {
		wp_log(WP_ERROR,
				"Not applying damage due to invalid buffer scale (%d)",
				scale);
		return -1;
	}
	if (transform < 0 || transform > 8) {
		wp_log(WP_ERROR,
				"Not applying damage due to invalid buffer transform (%d)",
				transform);
		return -1;
	}
	if (rec->buffer_coordinates) {
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
		/* A null buffer can legitimately be send to remove surface
		 * contents, presumably with shell-defined semantics */
		wp_log(WP_DEBUG, "Buffer to be attached is null");
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
	if (context->on_display_side) {
		/* commit signifies a client-side update only */
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
	if (buf->type == BUF_DMA) {
		for (int i = 0; i < buf->dmabuf_nplanes; i++) {
			struct shadow_fd *sfd = buf->dmabuf_buffers[i];
			if (!sfd) {
				wp_log(WP_ERROR,
						"dmabuf surface buffer is missing plane %d",
						i);
				continue;
			}
			if (sfd->type != FDC_DMABUF) {
				wp_log(WP_ERROR,
						"fd associated with dmabuf surface is not a dmabuf");
				continue;
			}

			// detailed damage tracking is not yet supported
			sfd->is_dirty = true;
			sfd->dirty_interval_max = INT32_MAX;
			sfd->dirty_interval_min = INT32_MIN;
		}
		return;
	} else if (buf->type != BUF_SHM) {
		wp_log(WP_ERROR,
				"wp_buffer is backed neither by DMA nor SHM, not yet supported");
		return;
	}
	struct shadow_fd *sfd = buf->shm_buffer;
	if (!sfd) {
		wp_log(WP_ERROR, "wp_buffer to be committed has no fd");
		return;
	}
	if (sfd->type != FDC_FILE) {
		wp_log(WP_ERROR, "fd associated with surface is not file-like");
		return;
	}
	sfd->is_dirty = true;
	int intv_max = INT32_MIN, intv_min = INT32_MAX;
	int bpp = get_shm_bytes_per_pixel(buf->shm_format);
	if (bpp == -1) {
		sfd->dirty_interval_max = INT32_MAX;
		sfd->dirty_interval_min = INT32_MIN;
		free_damage_stack(&surface->damage_stack);
		return;
	}

	// Translate damage stack into damage records for the fd buffer
	struct damage_record *rec = surface->damage_stack;
	while (rec) {
		// TODO: take into account transformations
		int xlow, xhigh, ylow, yhigh;
		int r = compute_damage_coordinates(&xlow, &xhigh, &ylow, &yhigh,
				rec, buf->shm_width, buf->shm_height,
				surface->transform, surface->scale);
		if (r != -1) {
			/* Clip the damage rectangle to the containing
			 * buffer. */
			xlow = clamp(xlow, 0, buf->shm_width);
			xhigh = clamp(xhigh, 0, buf->shm_width);
			ylow = clamp(ylow, 0, buf->shm_height);
			yhigh = clamp(yhigh, 0, buf->shm_height);

			int low = buf->shm_offset + buf->shm_stride * ylow +
				  bpp * xlow;
			int high = buf->shm_offset + buf->shm_stride * yhigh +
				   bpp * xhigh;
			intv_max = max(intv_max, high);
			intv_min = min(intv_min, low);
		}

		struct damage_record *nxt = rec->next;
		free(rec);
		rec = nxt;
	}
	surface->damage_stack = NULL;

	sfd->dirty_interval_max = max(sfd->dirty_interval_max, intv_max);
	sfd->dirty_interval_min = min(sfd->dirty_interval_min, intv_min);
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

	struct shadow_fd *sfd = translate_fd(context->map, fd);
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
	struct shadow_fd *sfd = translate_fd(context->map, fd);
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
		wp_log(WP_ERROR, "Pool to be resized owns no buffer");
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

	the_buffer->type = BUF_SHM;
	the_buffer->shm_buffer = the_shm_pool->owned_buffer;
	the_buffer->shm_buffer->refcount++;
	the_buffer->shm_offset = offset;
	the_buffer->shm_width = width;
	the_buffer->shm_height = height;
	the_buffer->shm_stride = stride;
	the_buffer->shm_format = format;
}

static void event_zwlr_screencopy_frame_v1_ready(void *data,
		struct zwlr_screencopy_frame_v1 *zwlr_screencopy_frame_v1,
		uint32_t tv_sec_hi, uint32_t tv_sec_lo, uint32_t tv_nsec)
{
	struct context *context = get_context(data, zwlr_screencopy_frame_v1);
	struct wp_wlr_screencopy_frame *frame =
			(struct wp_wlr_screencopy_frame *)context->obj;
	if (!frame->buffer_id) {
		wp_log(WP_ERROR, "frame has no copy target");
		return;
	}
	struct wp_object *obj = (struct wp_object *)listset_get(
			&context->mt->objects, frame->buffer_id);
	if (!obj) {
		wp_log(WP_ERROR, "frame copy target no longer exists");
		return;
	}
	if (obj->type != &wl_buffer_interface) {
		wp_log(WP_ERROR, "frame copy target is not a wl_buffer");
		return;
	}
	struct wp_buffer *buffer = (struct wp_buffer *)obj;
	struct shadow_fd *sfd = buffer->shm_buffer;
	if (!sfd) {
		wp_log(WP_ERROR, "frame copy target does not own any buffers");
		return;
	}
	if (sfd->type != FDC_FILE) {
		wp_log(WP_ERROR,
				"frame copy target buffer file descriptor (RID=%d) was not file-like (type=%d)",
				sfd->remote_id, sfd->type);
		return;
	}
	if (buffer->type != BUF_SHM) {
		wp_log(WP_ERROR,
				"screencopy not yet supported for non-shm-backed buffers");
		return;
	}
	if (!context->on_display_side) {
		// The display side performs the update
		return;
	}
	sfd->is_dirty = true;
	/* The protocol guarantees that the buffer attributes match those of the
	 * written frame */
	int start = buffer->shm_offset;
	int end = buffer->shm_offset + buffer->shm_height * buffer->shm_stride;
	sfd->dirty_interval_min = min(start, sfd->dirty_interval_min);
	sfd->dirty_interval_max = max(end, sfd->dirty_interval_max);

	(void)tv_sec_lo;
	(void)tv_sec_hi;
	(void)tv_nsec;
}
static void request_zwlr_screencopy_frame_v1_copy(struct wl_client *client,
		struct wl_resource *resource, struct wl_resource *buffer)
{
	struct context *context = get_context(client, resource);
	struct wp_wlr_screencopy_frame *frame =
			(struct wp_wlr_screencopy_frame *)context->obj;
	struct wp_object *buf = (struct wp_object *)buffer;
	if (buf->type != &wl_buffer_interface) {
		wp_log(WP_ERROR, "frame copy destination is not a wl_buffer");
		return;
	}
	frame->buffer_id = buf->obj_id;
}

static long timespec_diff(struct timespec val, struct timespec sub)
{
	// Overflows only with 68 year error, insignificant
	return (val.tv_sec - sub.tv_sec) * 1000000000L +
	       (val.tv_nsec - sub.tv_nsec);
}
static void event_wp_presentation_clock_id(void *data,
		struct wp_presentation *wp_presentation, uint32_t clk_id)
{
	struct context *context = get_context(data, wp_presentation);
	struct waypipe_presentation *pres =
			(struct waypipe_presentation *)context->obj;
	pres->clock_id = (int)clk_id;
	int reference_clock = CLOCK_REALTIME;

	if (pres->clock_id == reference_clock) {
		pres->clock_delta_nsec = 0;
	} else {
		/* Estimate the difference in baseline between clocks.
		 * (TODO: Is there a syscall for this?) do median of 3? */
		struct timespec t0, t1, t2;
		clock_gettime(pres->clock_id, &t0);
		clock_gettime(reference_clock, &t1);
		clock_gettime(pres->clock_id, &t2);
		long diff1m0 = timespec_diff(t1, t0);
		long diff2m1 = timespec_diff(t2, t1);
		pres->clock_delta_nsec = (diff1m0 - diff2m1) / 2;
	}
}
static void request_wp_presentation_feedback(struct wl_client *client,
		struct wl_resource *resource, struct wl_resource *surface,
		uint32_t callback)
{
	struct context *context = get_context(client, resource);
	struct waypipe_presentation *pres =
			(struct waypipe_presentation *)context->obj;
	struct waypipe_presentation_feedback *feedback =
			(struct waypipe_presentation_feedback *)listset_get(
					&context->mt->objects, callback);
	(void)surface;

	feedback->clock_delta_nsec = pres->clock_delta_nsec;
}
static void event_wp_presentation_feedback_presented(void *data,
		struct wp_presentation_feedback *wp_presentation_feedback,
		uint32_t tv_sec_hi, uint32_t tv_sec_lo, uint32_t tv_nsec,
		uint32_t refresh, uint32_t seq_hi, uint32_t seq_lo,
		uint32_t flags)
{
	struct context *context = get_context(data, wp_presentation_feedback);
	struct waypipe_presentation_feedback *feedback =
			(struct waypipe_presentation_feedback *)context->obj;

	(void)refresh;
	(void)seq_hi;
	(void)seq_lo;
	(void)flags;

	/* convert local to reference, on display side */
	int dir = context->on_display_side ? 1 : -1;

	uint64_t sec = tv_sec_lo + tv_sec_hi * 0x100000000L;
	long nsec = tv_nsec;
	nsec += dir * feedback->clock_delta_nsec;
	sec = (uint64_t)((long)sec + nsec / 1000000000L);
	nsec = nsec % 1000000000L;
	if (nsec < 0) {
		nsec += 1000000000L;
		sec--;
	}
	// Size not changed, no other edits required
	context->message[2] = (uint32_t)(sec / 0x100000000L);
	context->message[3] = (uint32_t)(sec % 0x100000000L);
	context->message[4] = (uint32_t)nsec;
}

static void event_wl_drm_device(
		void *data, struct wl_drm *wl_drm, const char *name)
{
	struct context *context = get_context(data, wl_drm);
	if (context->on_display_side) {
		/* Replacing the (remote) DRM device path with a local render
		 * node path only is useful on the application side */
		return;
	}

	const char path[] = "/dev/dri/renderD128";
	int path_len = strlen(path);
	int message_bytes = 8 + 4 + 4 * ((path_len + 1 + 3) / 4);
	if (message_bytes > context->message_available_space) {
		wp_log(WP_ERROR,
				"Not enough space to modify DRM device advertisement from '%s' to '%s'",
				name, path);
		return;
	}
	context->message_length = message_bytes;
	uint32_t *payload = context->message + 2;
	memset(payload, 0, (size_t)message_bytes - 8);
	payload[0] = (uint32_t)path_len + 1;
	memcpy(context->message + 3, path, (size_t)path_len);
	uint32_t meth = (context->message[1] << 16) >> 16;
	context->message[1] = meth | ((uint32_t)message_bytes << 16);
}
static void request_wl_drm_create_prime_buffer(struct wl_client *client,
		struct wl_resource *resource, uint32_t id, int32_t name,
		int32_t width, int32_t height, uint32_t format, int32_t offset0,
		int32_t stride0, int32_t offset1, int32_t stride1,
		int32_t offset2, int32_t stride2)
{
	struct context *context = get_context(client, resource);
	struct wp_buffer *buf = (struct wp_buffer *)listset_get(
			&context->mt->objects, id);
	struct shadow_fd *sfd = translate_fd(context->map, name);
	if (sfd->type != FDC_DMABUF) {
		wp_log(WP_ERROR,
				"keymap candidate RID=%d was not a dmabuf (type=%d)",
				sfd->remote_id, sfd->type);
		return;
	}

	buf->type = BUF_DMA;
	buf->dmabuf_nplanes = 1;
	buf->dmabuf_buffers[0] = sfd;
	sfd->has_owner = true;
	sfd->refcount++;
	buf->dmabuf_width = width;
	buf->dmabuf_height = height;
	buf->dmabuf_format = format;
	// handling multiple offsets (?)
	buf->dmabuf_offsets[0] = (uint32_t)offset0;
	buf->dmabuf_strides[0] = (uint32_t)stride0;
	(void)offset1;
	(void)offset2;
	(void)stride1;
	(void)stride2;
}

static void event_zwp_linux_dmabuf_v1_modifier(void *data,
		struct zwp_linux_dmabuf_v1 *zwp_linux_dmabuf_v1,
		uint32_t format, uint32_t modifier_hi, uint32_t modifier_lo)
{
	struct context *context = get_context(data, zwp_linux_dmabuf_v1);
	(void)format;
	// Filter out formats with nonstandard memory layouts; they may not
	// be portable between different GPU generations.
	// (TODO: better configuration and heuristics for this)
	if (modifier_hi || modifier_lo) {
		context->drop_this_msg = true;
	}
}
static void event_zwp_linux_buffer_params_v1_created(void *data,
		struct zwp_linux_buffer_params_v1 *zwp_linux_buffer_params_v1,
		struct wl_buffer *buffer)
{
	struct context *context = get_context(data, zwp_linux_buffer_params_v1);
	struct wp_linux_dmabuf_params *params =
			(struct wp_linux_dmabuf_params *)context->obj;
	struct wp_buffer *buf = (struct wp_buffer *)buffer;
	buf->type = BUF_DMA;
	buf->dmabuf_nplanes = params->nplanes;
	for (int i = 0; i < params->nplanes; i++) {
		if (!params->add[i].buffer) {
			wp_log(WP_ERROR,
					"dmabuf backed wl_buffer plane %d was missing",
					i);
			continue;
		}
		buf->dmabuf_buffers[i] = params->add[i].buffer;
		buf->dmabuf_buffers[i]->refcount++;
		buf->dmabuf_offsets[i] = params->add[i].offset;
		buf->dmabuf_strides[i] = params->add[i].stride;
		buf->dmabuf_modifiers[i] = params->add[i].modifier;
	}
	buf->dmabuf_flags = params->create_flags;
	buf->dmabuf_width = params->create_width;
	buf->dmabuf_height = params->create_height;
	buf->dmabuf_format = params->create_format;
}
static void request_zwp_linux_buffer_params_v1_add(struct wl_client *client,
		struct wl_resource *resource, int32_t fd, uint32_t plane_idx,
		uint32_t offset, uint32_t stride, uint32_t modifier_hi,
		uint32_t modifier_lo)
{
	struct context *context = get_context(client, resource);
	struct wp_linux_dmabuf_params *params =
			(struct wp_linux_dmabuf_params *)context->obj;
	if (params->nplanes != (int)plane_idx) {
		wp_log(WP_ERROR,
				"Expected sequentially assigned plane fds: got new_idx=%d != %d=nplanes",
				plane_idx, params->nplanes);
		return;
	}
	if (params->nplanes >= MAX_DMABUF_PLANES) {
		wp_log(WP_ERROR, "Too many planes");
		return;
	}
	params->nplanes++;
	params->add[plane_idx].fd = fd;
	params->add[plane_idx].offset = offset;
	params->add[plane_idx].stride = stride;
	params->add[plane_idx].modifier =
			modifier_lo + modifier_hi * 0x100000000uL;
	// Only perform rearrangement on the client side, for now
	if (!context->on_display_side) {
		params->add[plane_idx].msg =
				malloc((size_t)context->message_length);
		memcpy(params->add[plane_idx].msg, context->message,
				(size_t)context->message_length);
		params->add[plane_idx].msg_len = context->message_length;

		context->drop_this_msg = true;
	}
}
static int reintroduce_add_msgs(
		struct context *context, struct wp_linux_dmabuf_params *params)
{
	int net_length = context->message_length;
	int nfds = 0;
	for (int i = 0; i < params->nplanes; i++) {
		net_length += params->add[i].msg_len;
		nfds++;
	}
	if (net_length > context->message_available_space) {
		wp_log(WP_ERROR,
				"Not enough space to reintroduce zwp_linux_buffer_params_v1.add message data");
		return -1;
	}
	if (nfds > context->fds->size - context->fds->zone_end) {
		wp_log(WP_ERROR,
				"Not enough space to reintroduce zwp_linux_buffer_params_v1.add message fds");
		return -1;
	}
	// Update fds
	int nmoved = (context->fds->zone_end - context->fds->zone_start);
	memmove(context->fds->data + context->fds->zone_start + nfds,
			context->fds->data + context->fds->zone_start,
			(size_t)nmoved * sizeof(int));
	for (int i = 0; i < params->nplanes; i++) {
		context->fds->data[context->fds->zone_start + i] =
				params->add[i].fd;
	}
	/* We inject `nfds` new file descriptors, and advance the zone
	 * of queued file descriptors forward, since the injected file
	 * descriptors will not be used by the parser, but will still
	 * be transported out. */
	context->fds->zone_start += nfds;
	context->fds->zone_end += nfds;

	// Update data
	char *cmsg = (char *)context->message;
	memmove(cmsg + net_length - context->message_length, cmsg,
			(size_t)context->message_length);
	int start = 0;
	for (int i = 0; i < params->nplanes; i++) {
		memcpy(cmsg + start, params->add[i].msg,
				(size_t)params->add[i].msg_len);
		start += params->add[i].msg_len;
		free(params->add[i].msg);
		params->add[i].msg = NULL;
		params->add[i].msg_len = 0;
	}
	wp_log(WP_DEBUG,
			"Reintroducing add requests for zwp_linux_buffer_params_v1, going from %d to %d bytes",
			context->message_length, net_length);
	context->message_length = net_length;
	context->fds_changed = true;
	return 0;
}
/** After this function is called, all subsets of fds that duplicate an
 * underlying dmabuf will be reduced to select a single fd. */
static void deduplicate_dmabuf_fds(
		struct context *context, struct wp_linux_dmabuf_params *params)
{
	int handles[MAX_DMABUF_PLANES];
	struct gbm_bo *temp_bos[MAX_DMABUF_PLANES];
	memset(temp_bos, 0, sizeof(temp_bos));
	for (int i = 0; i < params->nplanes; i++) {
		handles[i] = get_unique_dmabuf_handle(&context->map->rdata,
				params->add[i].fd, &temp_bos[i]);
	}
	for (int i = 0; i < params->nplanes; i++) {
		destroy_dmabuf(temp_bos[i]);
	}
	for (int i = 0; i < params->nplanes; i++) {
		int lowest = i;
		for (int k = 0; k < i; k++) {
			if (handles[k] == handles[i]) {
				lowest = k;
				break;
			}
		}
		if (lowest != i &&
				params->add[i].fd != params->add[lowest].fd) {
			if (close(params->add[i].fd) == -1) {
				wp_log(WP_ERROR, "Incorrect close(%d): %s",
						params->add[i].fd,
						strerror(errno));
			}
		}
		params->add[i].fd = params->add[lowest].fd;
	}
}
static void request_zwp_linux_buffer_params_v1_create(struct wl_client *client,
		struct wl_resource *resource, int32_t width, int32_t height,
		uint32_t format, uint32_t flags)
{
	struct context *context = get_context(client, resource);
	struct wp_linux_dmabuf_params *params =
			(struct wp_linux_dmabuf_params *)context->obj;
	params->create_flags = flags;
	params->create_width = width;
	params->create_height = height;
	params->create_format = format;
	deduplicate_dmabuf_fds(context, params);
	if (!context->on_display_side) {
		reintroduce_add_msgs(context, params);
	}
	for (int i = 0; i < params->nplanes; i++) {
		struct shadow_fd *sfd =
				translate_fd(context->map, params->add[i].fd);
		if (sfd->type != FDC_DMABUF) {
			wp_log(WP_ERROR,
					"fd #%d for linux-dmabuf request wasn't a dmabuf",
					i);
			continue;
		}
		// Convert the stored fds to buffer pointers now
		params->add[i].buffer = sfd;
		sfd->has_owner = true;
		sfd->refcount++;
	}
	// Avoid closing in destroy_wp_object
	for (int i = 0; i < MAX_DMABUF_PLANES; i++) {
		params->add[i].fd = -1;
	}
	params->nplanes = 0;
}
static void request_zwp_linux_buffer_params_v1_create_immed(
		struct wl_client *client, struct wl_resource *resource,
		uint32_t buffer_id, int32_t width, int32_t height,
		uint32_t format, uint32_t flags)
{
	struct context *context = get_context(client, resource);
	struct wp_linux_dmabuf_params *params =
			(struct wp_linux_dmabuf_params *)context->obj;
	struct wp_buffer *buf = (struct wp_buffer *)listset_get(
			&context->mt->objects, buffer_id);
	buf->type = BUF_DMA;
	buf->dmabuf_nplanes = params->nplanes;
	deduplicate_dmabuf_fds(context, params);
	if (!context->on_display_side) {
		// Do this before we wipe any of the fds
		reintroduce_add_msgs(context, params);
	}
	for (int i = 0; i < params->nplanes; i++) {
		// TODO: pass in stride info and modifier hints
		struct shadow_fd *sfd =
				translate_fd(context->map, params->add[i].fd);
		if (sfd->type != FDC_DMABUF) {
			wp_log(WP_ERROR,
					"fd #%d for linux-dmabuf request wasn't a dmabuf",
					i);
			continue;
		}
		buf->dmabuf_buffers[i] = sfd;
		sfd->has_owner = true;
		sfd->refcount++;
		buf->dmabuf_buffers[i]->refcount++;
		buf->dmabuf_offsets[i] = params->add[i].offset;
		buf->dmabuf_strides[i] = params->add[i].stride;
		buf->dmabuf_modifiers[i] = params->add[i].modifier;
	}
	buf->dmabuf_flags = flags;
	buf->dmabuf_width = width;
	buf->dmabuf_height = height;
	buf->dmabuf_format = format;
	/* Remove fds from params, so they aren't closed when the param object
	 * is destroyed */
	for (int i = 0; i < MAX_DMABUF_PLANES; i++) {
		params->add[i].fd = -1;
	}
	params->nplanes = 0;
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
static const struct zwlr_screencopy_frame_v1_listener
		zwlr_screencopy_frame_v1_event_handler = {
				.ready = event_zwlr_screencopy_frame_v1_ready};
static const struct zwlr_screencopy_frame_v1_interface
		zwlr_screencopy_frame_v1_request_handler = {
				.copy = request_zwlr_screencopy_frame_v1_copy};
static const struct wp_presentation_listener wp_presentation_event_handler = {
		.clock_id = event_wp_presentation_clock_id};
static const struct wp_presentation_interface wp_presentation_request_handler =
		{.feedback = request_wp_presentation_feedback};
static const struct wp_presentation_feedback_listener
		wp_presentation_feedback_event_handler = {
				.presented = event_wp_presentation_feedback_presented};
static const struct wl_drm_listener wl_drm_event_handler = {
		.device = event_wl_drm_device};
static const struct wl_drm_interface wl_drm_request_handler = {
		/* the other 'create_buffer' methods require an authenticated
		 * drm node, which we do never advertise */
		.create_prime_buffer = request_wl_drm_create_prime_buffer};
static const struct zwp_linux_dmabuf_v1_listener
		zwp_linux_dmabuf_v1_event_handler = {
				.modifier = event_zwp_linux_dmabuf_v1_modifier};
static const struct zwp_linux_buffer_params_v1_listener
		zwp_linux_buffer_params_v1_event_handler = {
				.created = event_zwp_linux_buffer_params_v1_created};
static const struct zwp_linux_buffer_params_v1_interface
		zwp_linux_buffer_params_v1_request_handler = {
				.add = request_zwp_linux_buffer_params_v1_add,
				.create = request_zwp_linux_buffer_params_v1_create,
				.create_immed = request_zwp_linux_buffer_params_v1_create_immed,
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
		{&zwlr_screencopy_frame_v1_interface,
				&zwlr_screencopy_frame_v1_event_handler,
				&zwlr_screencopy_frame_v1_request_handler},
		{&wp_presentation_feedback_interface,
				&wp_presentation_feedback_event_handler, NULL},
		{&zwp_linux_buffer_params_v1_interface,
				&zwp_linux_buffer_params_v1_event_handler,
				&zwp_linux_buffer_params_v1_request_handler},

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
		{&wp_presentation_interface, &wp_presentation_event_handler,
				&wp_presentation_request_handler},
		// gtk-primary-selection
		{&gtk_primary_selection_device_manager_interface, NULL, NULL},
		// virtual-keyboard
		{&zwp_virtual_keyboard_manager_v1_interface, NULL, NULL},
		// input-method
		{&zwp_input_method_manager_v2_interface, NULL, NULL},
		// linux-dmabuf
		{&zwp_linux_dmabuf_v1_interface,
				&zwp_linux_dmabuf_v1_event_handler, NULL},
		// linux-dmabuf
		{&zwlr_screencopy_manager_v1_interface, NULL, NULL},
		// linux-dmabuf
		{&wl_drm_interface, &wl_drm_event_handler,
				&wl_drm_request_handler},

		{NULL, NULL, NULL}};
const struct wl_interface *the_display_interface = &wl_display_interface;
