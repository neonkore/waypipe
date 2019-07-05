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
#include "util.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <gtk-primary-selection-defs.h>
#include <input-method-unstable-v2-defs.h>
#include <linux-dmabuf-unstable-v1-defs.h>
#include <presentation-time-defs.h>
#include <virtual-keyboard-unstable-v1-defs.h>
#include <wayland-defs.h>
#include <wayland-drm-defs.h>
#include <wlr-data-control-unstable-v1-defs.h>
#include <wlr-export-dmabuf-unstable-v1-defs.h>
#include <wlr-screencopy-unstable-v1-defs.h>
#include <xdg-shell-defs.h>

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
	int damage_stack_len;

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

struct wp_export_dmabuf_frame {
	struct wp_object base;

	uint32_t width;
	uint32_t height;
	uint32_t format;
	uint64_t modifier;

	// At the moment, no message reordering support, for lack of a client
	// to test it with
	struct {
		struct shadow_fd *buffer;
		uint32_t offset;
		uint32_t stride;
		uint64_t modifier;
	} objects[MAX_DMABUF_PLANES];
	uint32_t nobjects;
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
	if (object->type == &intf_wl_shm_pool) {
		struct wp_shm_pool *r = (struct wp_shm_pool *)object;
		if (r->owned_buffer) {
			shadow_decref_protocol(map, r->owned_buffer);
		}
	} else if (object->type == &intf_wl_buffer) {
		struct wp_buffer *r = (struct wp_buffer *)object;
		for (int i = 0; i < MAX_DMABUF_PLANES; i++) {
			if (r->dmabuf_buffers[i]) {
				shadow_decref_protocol(
						map, r->dmabuf_buffers[i]);
			}
		}
		if (r->shm_buffer) {
			shadow_decref_protocol(map, r->shm_buffer);
		}
	} else if (object->type == &intf_wl_surface) {
		struct wp_surface *r = (struct wp_surface *)object;
		free_damage_stack(&r->damage_stack);
	} else if (object->type == &intf_wl_keyboard) {
		struct wp_keyboard *r = (struct wp_keyboard *)object;
		if (r->owned_buffer) {
			shadow_decref_protocol(map, r->owned_buffer);
		}
	} else if (object->type == &intf_zwlr_screencopy_frame_v1) {
		struct wp_wlr_screencopy_frame *r =
				(struct wp_wlr_screencopy_frame *)object;
		(void)r;
	} else if (object->type == &intf_wp_presentation) {
	} else if (object->type == &intf_wp_presentation_feedback) {
	} else if (object->type == &intf_zwp_linux_buffer_params_v1) {
		struct wp_linux_dmabuf_params *r =
				(struct wp_linux_dmabuf_params *)object;
		for (int i = 0; i < MAX_DMABUF_PLANES; i++) {
			if (r->add[i].buffer) {
				shadow_decref_protocol(map, r->add[i].buffer);
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
	} else if (object->type == &intf_zwlr_export_dmabuf_frame_v1) {
		struct wp_export_dmabuf_frame *r =
				(struct wp_export_dmabuf_frame *)object;
		for (int i = 0; i < MAX_DMABUF_PLANES; i++) {
			if (r->objects[i].buffer) {
				shadow_decref_protocol(
						map, r->objects[i].buffer);
			}
		}
	}
	free(object);
}
struct wp_object *create_wp_object(uint32_t id, const struct wp_interface *type)
{
	/* Note: if custom types are ever implemented for globals, they would
	 * need special replacement logic when the type is set */
	struct wp_object *new_obj;
	if (type == &intf_wl_shm_pool) {
		new_obj = calloc(1, sizeof(struct wp_shm_pool));
	} else if (type == &intf_wl_buffer) {
		new_obj = calloc(1, sizeof(struct wp_buffer));
	} else if (type == &intf_wl_surface) {
		new_obj = calloc(1, sizeof(struct wp_surface));
		((struct wp_surface *)new_obj)->scale = 1;
	} else if (type == &intf_wl_keyboard) {
		new_obj = calloc(1, sizeof(struct wp_keyboard));
	} else if (type == &intf_zwlr_screencopy_frame_v1) {
		new_obj = calloc(1, sizeof(struct wp_wlr_screencopy_frame));
	} else if (type == &intf_wp_presentation) {
		new_obj = calloc(1, sizeof(struct waypipe_presentation));
	} else if (type == &intf_wp_presentation_feedback) {
		new_obj = calloc(1,
				sizeof(struct waypipe_presentation_feedback));
	} else if (type == &intf_zwp_linux_buffer_params_v1) {
		new_obj = calloc(1, sizeof(struct wp_linux_dmabuf_params));
		struct wp_linux_dmabuf_params *params =
				(struct wp_linux_dmabuf_params *)new_obj;
		for (int i = 0; i < MAX_DMABUF_PLANES; i++) {
			params->add[i].fd = -1;
		}
	} else if (type == &intf_zwlr_export_dmabuf_frame_v1) {
		new_obj = calloc(1, sizeof(struct wp_export_dmabuf_frame));
	} else {
		new_obj = calloc(1, sizeof(struct wp_object));
	}
	new_obj->obj_id = id;
	new_obj->type = type;
	new_obj->is_zombie = false;
	return new_obj;
}

void do_wl_display_evt_error(struct context *ctx, struct wp_object *object_id,
		uint32_t code, const char *message)
{
	const char *type_name =
			object_id ? (object_id->type ? object_id->type->name
						     : "<no type>")
				  : "<no object>";
	wp_log(WP_ERROR, "Display sent fatal error message %s, code %u: %s",
			type_name, code, message ? message : "<no message>");
	(void)ctx;
}
void do_wl_display_evt_delete_id(struct context *ctx, uint32_t id)
{
	struct wp_object *obj = listset_get(ctx->obj_list, id);
	/* ensure this isn't miscalled to have wl_display delete itself */
	if (obj && obj != ctx->obj) {
		listset_remove(ctx->obj_list, obj);
		destroy_wp_object(&ctx->g->map, obj);
	}
}
void do_wl_display_req_get_registry(
		struct context *ctx, struct wp_object *registry)
{
	(void)ctx;
	(void)registry;
}
void do_wl_display_req_sync(struct context *ctx, struct wp_object *callback)
{
	(void)ctx;
	(void)callback;
}

void do_wl_registry_evt_global(struct context *ctx, uint32_t name,
		const char *interface, uint32_t version)
{
	if (!interface) {
		wp_log(WP_DEBUG,
				"Interface name provided via wl_registry::global was NULL");
		return;
	}
	bool requires_rnode = false;
	requires_rnode |= !strcmp(interface, "wl_drm");
	requires_rnode |= !strcmp(interface, "zwp_linux_dmabuf_v1");
	requires_rnode |= !strcmp(interface, "zwlr_export_dmabuf_manager_v1");
	if (requires_rnode) {
		if (init_render_data(&ctx->g->render) == -1) {
			/* A gpu connection supported by waypipe is required on
			 * both sides, since data transfers may occur in both
			 * directions, and
			 * modifying textures may require driver support */
			wp_log(WP_DEBUG,
					"Discarding protocol advertisement for %s, render node support disabled",
					interface);
			ctx->drop_this_msg = true;
			return;
		}
	}

	bool unsupported = false;
	// deprecated, and waypipe doesn't have logic for it anyway
	unsupported |= !strcmp(interface, "wl_shell");
	if (unsupported) {
		wp_log(WP_DEBUG, "Hiding %s advertisement, unsupported",
				interface);
		ctx->drop_this_msg = true;
	}

	(void)name;
	(void)version;
}
void do_wl_registry_evt_global_remove(struct context *ctx, uint32_t name)
{
	(void)ctx;
	(void)name;
}

void do_wl_registry_req_bind(struct context *ctx, uint32_t name,
		const char *interface, uint32_t version, struct wp_object *id)
{
	if (!interface) {
		wp_log(WP_DEBUG,
				"Interface name provided to wl_registry::bind was NULL");
		return;
	}
	/* The object has already been created, but its type is NULL */
	struct wp_object *the_object = (struct wp_object *)id;
	uint32_t obj_id = the_object->obj_id;
	for (int i = 0; handlers[i].interface; i++) {
		if (!strcmp(interface, handlers[i].interface->name)) {
			if (!handlers[i].is_global) {
				wp_log(WP_ERROR,
						"Interface %s does not support binding globals",
						handlers[i].interface->name);
				/* exit search, discard unbound object */
				break;
			}

			// Set the object type
			the_object->type = handlers[i].interface;
			if (handlers[i].interface == &intf_wp_presentation) {
				// Replace the object with a specialized
				// version
				listset_remove(ctx->obj_list, the_object);
				free(the_object);
				the_object = create_wp_object(
						obj_id, &intf_wp_presentation);
				listset_insert(&ctx->g->map, ctx->obj_list,
						the_object);
			}
			return;
		}
	}
	listset_remove(ctx->obj_list, the_object);
	free(the_object);

	wp_log(WP_DEBUG, "Binding fail name=%d %s id=%d (v%d)", name, interface,
			id, version);
	(void)name;
	(void)version;
}

void do_wl_buffer_evt_release(struct context *ctx) { (void)ctx; }
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

		/* Each of the eight transformations corresponds to a
		 * unique set of reflections: X<->Y | Xflip | Yflip */
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
void do_wl_surface_req_attach(struct context *ctx, struct wp_object *buffer,
		int32_t x, int32_t y)
{
	(void)x;
	(void)y;
	struct wp_object *bufobj = (struct wp_object *)buffer;
	if (!bufobj) {
		/* A null buffer can legitimately be send to remove
		 * surface contents, presumably with shell-defined
		 * semantics */
		wp_log(WP_DEBUG, "Buffer to be attached is null");
		return;
	}
	if (bufobj->type != &intf_wl_buffer) {
		wp_log(WP_ERROR, "Buffer to be attached has the wrong type");
		return;
	}
	struct wp_surface *surface = (struct wp_surface *)ctx->obj;
	surface->attached_buffer_id = bufobj->obj_id;
}
void do_wl_surface_req_commit(struct context *ctx)
{
	struct wp_surface *surface = (struct wp_surface *)ctx->obj;
	if (!surface->attached_buffer_id) {
		/* The wl_surface.commit operation applies all "pending
		 * state", much of which we don't care about. Typically,
		 * when a wl_surface is first created, it is soon
		 * committed to atomically update state variables. An
		 * attached wl_buffer is not required.
		 */
		return;
	}
	if (ctx->on_display_side) {
		/* commit signifies a client-side update only */
		return;
	}
	struct wp_object *obj =
			listset_get(ctx->obj_list, surface->attached_buffer_id);
	if (!obj) {
		wp_log(WP_ERROR, "Attached buffer no longer exists");
		return;
	}
	if (obj->type != &intf_wl_buffer) {
		wp_log(WP_ERROR,
				"Buffer to commit has the wrong type, and may have been recycled");
		return;
	}
	if (surface->damage_stack_len == 0) {
		// No damage to report
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
			damage_everything(&sfd->damage);
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
	int bpp = get_shm_bytes_per_pixel(buf->shm_format);
	if (bpp == -1) {
		damage_everything(&sfd->damage);
		free_damage_stack(&surface->damage_stack);
		surface->damage_stack_len = 0;
		return;
	}

	struct ext_interval *damage_array =
			malloc(sizeof(struct ext_interval) *
					(size_t)surface->damage_stack_len);
	if (!damage_array) {
		wp_log(WP_ERROR, "Failed to allocate damage array");
		damage_everything(&sfd->damage);
		return;
	}
	int i = 0;

	// Translate damage stack into damage records for the fd buffer
	struct damage_record *rec = surface->damage_stack;
	while (rec) {
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

			damage_array[i].start = buf->shm_offset +
						buf->shm_stride * ylow +
						bpp * xlow;
			damage_array[i].rep = yhigh - ylow;
			damage_array[i].stride = buf->shm_stride;
			damage_array[i].width = bpp * (xhigh - xlow);
			i++;
		}

		struct damage_record *nxt = rec->next;
		free(rec);
		rec = nxt;
	}

	merge_damage_records(&sfd->damage, i, damage_array);
	free(damage_array);
	surface->damage_stack = NULL;
	surface->damage_stack_len = 0;
}
void do_wl_surface_req_damage(struct context *ctx, int32_t x, int32_t y,
		int32_t width, int32_t height)
{
	if (ctx->on_display_side) {
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

	struct wp_surface *surface = (struct wp_surface *)ctx->obj;
	damage->next = surface->damage_stack;
	surface->damage_stack = damage;
	surface->damage_stack_len++;
}
void do_wl_surface_req_damage_buffer(struct context *ctx, int32_t x, int32_t y,
		int32_t width, int32_t height)
{
	if (ctx->on_display_side) {
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

	struct wp_surface *surface = (struct wp_surface *)ctx->obj;
	damage->next = surface->damage_stack;
	surface->damage_stack = damage;
	surface->damage_stack_len++;
}
void do_wl_surface_req_set_buffer_transform(
		struct context *ctx, int32_t transform)
{

	struct wp_surface *surface = (struct wp_surface *)ctx->obj;
	surface->transform = transform;
}
void do_wl_surface_req_set_buffer_scale(struct context *ctx, int32_t scale)
{
	struct wp_surface *surface = (struct wp_surface *)ctx->obj;
	surface->scale = scale;
}
void do_wl_keyboard_evt_keymap(
		struct context *ctx, uint32_t format, int fd, uint32_t size)
{
	size_t fdsz = 0;
	fdcat_t fdtype = get_fd_type(fd, &fdsz);
	if (fdtype != FDC_FILE || fdsz != size) {
		wp_log(WP_ERROR,
				"keymap candidate fd %d was not file-like (type=%s), and with size=%ld did not match %d",
				fd, fdcat_to_str(fdtype), fdsz, size);
		return;
	}

	struct shadow_fd *sfd = translate_fd(&ctx->g->map, &ctx->g->render, fd,
			fdtype, fdsz, NULL, false);
	struct wp_keyboard *keyboard = (struct wp_keyboard *)ctx->obj;
	keyboard->owned_buffer = shadow_incref_protocol(sfd);
	(void)format;
}

void do_wl_shm_req_create_pool(
		struct context *ctx, struct wp_object *id, int fd, int32_t size)
{
	struct wp_shm_pool *the_shm_pool = (struct wp_shm_pool *)id;

	size_t fdsz = 0;
	fdcat_t fdtype = get_fd_type(fd, &fdsz);
	/* It may be valid for the file descriptor size to be larger
	 * than the immediately advertised size, since the call to
	 * wl_shm.create_pool may be followed by wl_shm_pool.resize,
	 * which then increases the size
	 */
	if (fdtype != FDC_FILE || (int32_t)fdsz < size) {
		wp_log(WP_ERROR,
				"File type or size mismatch for fd %d with claimed: %s %s | %ld %d",
				fd, fdcat_to_str(fdtype),
				fdcat_to_str(FDC_FILE), fdsz, size);
		return;
	}

	struct shadow_fd *sfd = translate_fd(&ctx->g->map, &ctx->g->render, fd,
			fdtype, fdsz, NULL, false);
	the_shm_pool->owned_buffer = shadow_incref_protocol(sfd);
}

void do_wl_shm_pool_req_resize(struct context *ctx, int32_t size)
{
	struct wp_shm_pool *the_shm_pool = (struct wp_shm_pool *)ctx->obj;

	if (!the_shm_pool->owned_buffer) {
		wp_log(WP_ERROR, "Pool to be resized owns no buffer");
		return;
	}
	if ((int32_t)the_shm_pool->owned_buffer->buffer_size >= size) {
		// The underlying buffer was already resized by the time
		// this protocol message was received
		return;
	}
	/* The display side will be updated already via buffer update msg */
	if (!ctx->on_display_side) {
		extend_shm_shadow(
				&ctx->g->map, the_shm_pool->owned_buffer, size);
	}
}
void do_wl_shm_pool_req_create_buffer(struct context *ctx, struct wp_object *id,
		int32_t offset, int32_t width, int32_t height, int32_t stride,
		uint32_t format)
{
	struct wp_shm_pool *the_shm_pool = (struct wp_shm_pool *)ctx->obj;
	struct wp_buffer *the_buffer = (struct wp_buffer *)id;
	if (!the_buffer) {
		wp_log(WP_ERROR, "No buffer available");
		return;
	}
	struct shadow_fd *sfd = the_shm_pool->owned_buffer;
	if (!sfd) {
		wp_log(WP_ERROR,
				"Creating a wl_buffer from a pool that does not own an fd");
		return;
	}

	if (sfd->refcount_protocol == 1 && video_supports_shm_format(format) &&
			offset == 0 &&
			stride * height == (int32_t)sfd->buffer_size &&
			ctx->g->config->video_if_possible) {
		/* shm data supports video only when there is a single
		 * wl_buffer that references the underlying file and
		 * furthermore that buffer lays claim to the entire
		 * buffer. Otherwise, handling mixed use cases can
		 * become incredibly complicated.
		 *
		 * Additional complications can happen if the pool is
		 * reused */
		// setup_video_encode(sfd, width, height, stride,
		// format);
	}

	the_buffer->type = BUF_SHM;
	the_buffer->shm_buffer =
			shadow_incref_protocol(the_shm_pool->owned_buffer);
	the_buffer->shm_offset = offset;
	the_buffer->shm_width = width;
	the_buffer->shm_height = height;
	the_buffer->shm_stride = stride;
	the_buffer->shm_format = format;
}

void do_zwlr_screencopy_frame_v1_evt_ready(struct context *ctx,
		uint32_t tv_sec_hi, uint32_t tv_sec_lo, uint32_t tv_nsec)
{
	struct wp_wlr_screencopy_frame *frame =
			(struct wp_wlr_screencopy_frame *)ctx->obj;
	if (!frame->buffer_id) {
		wp_log(WP_ERROR, "frame has no copy target");
		return;
	}
	struct wp_object *obj = (struct wp_object *)listset_get(
			ctx->obj_list, frame->buffer_id);
	if (!obj) {
		wp_log(WP_ERROR, "frame copy target no longer exists");
		return;
	}
	if (obj->type != &intf_wl_buffer) {
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
	if (!ctx->on_display_side) {
		// The display side performs the update
		return;
	}
	sfd->is_dirty = true;
	/* The protocol guarantees that the buffer attributes match
	 * those of the written frame */
	const struct ext_interval interval = {.start = buffer->shm_offset,
			.width = buffer->shm_height * buffer->shm_stride,
			.stride = 0,
			.rep = 1};
	merge_damage_records(&sfd->damage, 1, &interval);

	(void)tv_sec_lo;
	(void)tv_sec_hi;
	(void)tv_nsec;
}
void do_zwlr_screencopy_frame_v1_req_copy(
		struct context *ctx, struct wp_object *buffer)
{
	struct wp_wlr_screencopy_frame *frame =
			(struct wp_wlr_screencopy_frame *)ctx->obj;
	struct wp_object *buf = (struct wp_object *)buffer;
	if (buf->type != &intf_wl_buffer) {
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
void do_wp_presentation_evt_clock_id(struct context *ctx, uint32_t clk_id)
{
	struct waypipe_presentation *pres =
			(struct waypipe_presentation *)ctx->obj;
	pres->clock_id = (int)clk_id;
	int reference_clock = CLOCK_REALTIME;

	if (pres->clock_id == reference_clock) {
		pres->clock_delta_nsec = 0;
	} else {
		/* Estimate the difference in baseline between clocks.
		 * (TODO: Is there a syscall for this?) do median of 3?
		 */
		struct timespec t0, t1, t2;
		clock_gettime(pres->clock_id, &t0);
		clock_gettime(reference_clock, &t1);
		clock_gettime(pres->clock_id, &t2);
		long diff1m0 = timespec_diff(t1, t0);
		long diff2m1 = timespec_diff(t2, t1);
		pres->clock_delta_nsec = (diff1m0 - diff2m1) / 2;
	}
}
void do_wp_presentation_req_feedback(struct context *ctx,
		struct wp_object *surface, struct wp_object *callback)
{
	struct waypipe_presentation *pres =
			(struct waypipe_presentation *)ctx->obj;
	struct waypipe_presentation_feedback *feedback =
			(struct waypipe_presentation_feedback *)callback;
	(void)surface;

	feedback->clock_delta_nsec = pres->clock_delta_nsec;
}
void do_wp_presentation_feedback_evt_presented(struct context *ctx,
		uint32_t tv_sec_hi, uint32_t tv_sec_lo, uint32_t tv_nsec,
		uint32_t refresh, uint32_t seq_hi, uint32_t seq_lo,
		uint32_t flags)
{
	struct waypipe_presentation_feedback *feedback =
			(struct waypipe_presentation_feedback *)ctx->obj;

	(void)refresh;
	(void)seq_hi;
	(void)seq_lo;
	(void)flags;

	/* convert local to reference, on display side */
	int dir = ctx->on_display_side ? 1 : -1;

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
	ctx->message[2] = (uint32_t)(sec / 0x100000000L);
	ctx->message[3] = (uint32_t)(sec % 0x100000000L);
	ctx->message[4] = (uint32_t)nsec;
}

void do_wl_drm_evt_device(struct context *ctx, const char *name)
{

	if (ctx->on_display_side) {
		/* Replacing the (remote) DRM device path with a local
		 * render node path only is useful on the application
		 * side */
		return;
	}
	if (!name) {
		wp_log(WP_DEBUG,
				"Device name provided via wl_drm::device was NULL");
		return;
	}
	if (!ctx->g->render.drm_node_path) {
		/* While the render node should have been initialized in
		 * wl_registry.global, setting this path, we still don't want
		 * to crash even if this gets called by accident */
		wp_log(WP_DEBUG,
				"wl_drm::device, local render node not set up");
		return;
	}
	int path_len = (int)strlen(ctx->g->render.drm_node_path);
	int message_bytes = 8 + 4 + 4 * ((path_len + 1 + 3) / 4);
	if (message_bytes > ctx->message_available_space) {
		wp_log(WP_ERROR,
				"Not enough space to modify DRM device advertisement from '%s' to '%s'",
				name, ctx->g->render.drm_node_path);
		return;
	}
	ctx->message_length = message_bytes;
	uint32_t *payload = ctx->message + 2;
	memset(payload, 0, (size_t)message_bytes - 8);
	payload[0] = (uint32_t)path_len + 1;
	memcpy(ctx->message + 3, ctx->g->render.drm_node_path,
			(size_t)path_len);
	uint32_t meth = (ctx->message[1] << 16) >> 16;
	ctx->message[1] = meth | ((uint32_t)message_bytes << 16);
}
void do_wl_drm_req_create_prime_buffer(struct context *ctx,
		struct wp_object *id, int name, int32_t width, int32_t height,
		uint32_t format, int32_t offset0, int32_t stride0,
		int32_t offset1, int32_t stride1, int32_t offset2,
		int32_t stride2)
{
	struct wp_buffer *buf = (struct wp_buffer *)id;
	struct dmabuf_slice_data info = {
			.num_planes = 1,
			.width = (uint32_t)width,
			.height = (uint32_t)height,
			.modifier = 0,
			.format = format,
			.offsets = {(uint32_t)offset0, (uint32_t)offset1,
					(uint32_t)offset2, 0},
			.strides = {(uint32_t)stride0, (uint32_t)stride1,
					(uint32_t)stride2, 0},
			.using_planes = {true, false, false, false},
	};

	size_t fdsz = 0;
	fdcat_t fdtype = get_fd_type(name, &fdsz);
	if (fdtype != FDC_DMABUF) {
		wp_log(WP_ERROR,
				"create_prime_buffer candidate fd %d was not a dmabuf (type=%s)",
				name, fdcat_to_str(fdtype));
		return;
	}

	struct shadow_fd *sfd = translate_fd(&ctx->g->map, &ctx->g->render,
			name, FDC_DMABUF, 0, &info, false);
	buf->type = BUF_DMA;
	buf->dmabuf_nplanes = 1;
	buf->dmabuf_buffers[0] = shadow_incref_protocol(sfd);
	buf->dmabuf_width = width;
	buf->dmabuf_height = height;
	buf->dmabuf_format = format;
	// handling multiple offsets (?)
	buf->dmabuf_offsets[0] = (uint32_t)offset0;
	buf->dmabuf_strides[0] = (uint32_t)stride0;
}

void do_zwp_linux_dmabuf_v1_evt_modifier(struct context *ctx, uint32_t format,
		uint32_t modifier_hi, uint32_t modifier_lo)
{

	(void)format;
	uint64_t modifier = modifier_hi * 0x100000000uL * modifier_lo;
	// Prevent all advertisements for dmabufs with modifiers
	if (modifier && ctx->g->config->linear_dmabuf) {
		ctx->drop_this_msg = true;
	}
}
void do_zwp_linux_buffer_params_v1_evt_created(
		struct context *ctx, struct wp_object *buffer)
{
	struct wp_linux_dmabuf_params *params =
			(struct wp_linux_dmabuf_params *)ctx->obj;
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
		buf->dmabuf_buffers[i] =
				shadow_incref_protocol(params->add[i].buffer);
		buf->dmabuf_offsets[i] = params->add[i].offset;
		buf->dmabuf_strides[i] = params->add[i].stride;
		buf->dmabuf_modifiers[i] = params->add[i].modifier;
	}
	buf->dmabuf_flags = params->create_flags;
	buf->dmabuf_width = params->create_width;
	buf->dmabuf_height = params->create_height;
	buf->dmabuf_format = params->create_format;
}
void do_zwp_linux_buffer_params_v1_req_add(struct context *ctx, int fd,
		uint32_t plane_idx, uint32_t offset, uint32_t stride,
		uint32_t modifier_hi, uint32_t modifier_lo)
{
	struct wp_linux_dmabuf_params *params =
			(struct wp_linux_dmabuf_params *)ctx->obj;
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
	if (!ctx->on_display_side) {
		params->add[plane_idx].msg =
				malloc((size_t)ctx->message_length);
		memcpy(params->add[plane_idx].msg, ctx->message,
				(size_t)ctx->message_length);
		params->add[plane_idx].msg_len = ctx->message_length;

		ctx->drop_this_msg = true;
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
	if (params->nplanes == 1) {
		return;
	}
	int handles[MAX_DMABUF_PLANES];
	struct gbm_bo *temp_bos[MAX_DMABUF_PLANES];
	memset(temp_bos, 0, sizeof(temp_bos));
	for (int i = 0; i < params->nplanes; i++) {
		handles[i] = get_unique_dmabuf_handle(&context->g->render,
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

void do_zwp_linux_buffer_params_v1_req_create(struct context *ctx,
		int32_t width, int32_t height, uint32_t format, uint32_t flags)
{
	struct wp_linux_dmabuf_params *params =
			(struct wp_linux_dmabuf_params *)ctx->obj;
	params->create_flags = flags;
	params->create_width = width;
	params->create_height = height;
	params->create_format = format;
	deduplicate_dmabuf_fds(ctx, params);
	if (!ctx->on_display_side) {
		reintroduce_add_msgs(ctx, params);
	}
	struct dmabuf_slice_data info = {.width = width,
			.height = height,
			.format = format,
			.num_planes = params->nplanes,
			.strides = {params->add[0].stride,
					params->add[1].stride,
					params->add[2].stride,
					params->add[3].stride},
			.offsets = {params->add[0].offset,
					params->add[1].offset,
					params->add[2].offset,
					params->add[3].offset}};
	for (int i = 0; i < params->nplanes; i++) {
		memset(info.using_planes, 0, sizeof(info.using_planes));
		for (int k = 0; k < min(params->nplanes, 4); k++) {
			if (params->add[k].fd == params->add[i].fd) {
				info.using_planes[k] = 1;
				info.modifier = params->add[k].modifier;
			}
		}
		/* replace the format with something the driver can
		 * probably handle */
		info.format = dmabuf_get_simple_format_for_plane(format, i);
		bool try_video = params->nplanes == 1 &&
				 video_supports_dmabuf_format(
						 format, info.modifier) &&
				 ctx->g->config->video_if_possible;

		size_t fdsz = 0;
		fdcat_t fdtype = get_fd_type(params->add[i].fd, &fdsz);
		if (fdtype != FDC_DMABUF) {
			wp_log(WP_ERROR,
					"fd #%d for linux-dmabuf request wasn't a dmabuf, instead %s",
					i, fdcat_to_str(fdtype));
			continue;
		}

		struct shadow_fd *sfd = translate_fd(&ctx->g->map,
				&ctx->g->render, params->add[i].fd, FDC_DMABUF,
				0, &info, try_video);
		/* increment for each extra time this fd will be sent */
		if (sfd->has_owner) {
			shadow_incref_transfer(sfd);
		}
		// Convert the stored fds to buffer pointers now.
		params->add[i].buffer = shadow_incref_protocol(sfd);
	}
	// Avoid closing in destroy_wp_object
	for (int i = 0; i < MAX_DMABUF_PLANES; i++) {
		params->add[i].fd = -1;
	}
}
void do_zwp_linux_buffer_params_v1_req_create_immed(struct context *ctx,
		struct wp_object *buffer_id, int32_t width, int32_t height,
		uint32_t format, uint32_t flags)
{
	// There isn't really that much unnecessary copying. Note that
	// 'create' may modify messages
	do_zwp_linux_buffer_params_v1_req_create(
			ctx, width, height, format, flags);
	do_zwp_linux_buffer_params_v1_evt_created(ctx, buffer_id);
}

void do_zwlr_export_dmabuf_frame_v1_evt_frame(struct context *ctx,
		uint32_t width, uint32_t height, uint32_t offset_x,
		uint32_t offset_y, uint32_t buffer_flags, uint32_t flags,
		uint32_t format, uint32_t mod_high, uint32_t mod_low,
		uint32_t num_objects)
{
	struct wp_export_dmabuf_frame *frame =
			(struct wp_export_dmabuf_frame *)ctx->obj;

	frame->width = width;
	frame->height = height;
	(void)offset_x;
	(void)offset_y;
	// the 'transient' flag could be cleared, technically
	(void)flags;
	(void)buffer_flags;
	frame->format = format;
	frame->modifier = mod_high * 0x100000000uL + mod_low;
	frame->nobjects = num_objects;
	if (frame->nobjects > MAX_DMABUF_PLANES) {
		wp_log(WP_ERROR, "Too many (%u) frame objects required",
				frame->nobjects);
		frame->nobjects = MAX_DMABUF_PLANES;
	}
}
void do_zwlr_export_dmabuf_frame_v1_evt_object(struct context *ctx,
		uint32_t index, int fd, uint32_t size, uint32_t offset,
		uint32_t stride, uint32_t plane_index)
{
	struct wp_export_dmabuf_frame *frame =
			(struct wp_export_dmabuf_frame *)ctx->obj;
	if (index > frame->nobjects) {
		wp_log(WP_ERROR, "Cannot add frame object with index %u >= %u",
				index, frame->nobjects);
		return;
	}
	if (frame->objects[index].buffer) {
		wp_log(WP_ERROR,
				"Cannot add frame object with index %u, already used",
				frame->nobjects);
		return;
	}

	frame->objects[index].offset = offset;
	frame->objects[index].stride = stride;

	// for lack of a test program, we assume all dmabufs passed in
	// here are distinct, and hence need no 'multiplane' adjustments
	struct dmabuf_slice_data info = {.width = frame->width,
			.height = frame->height,
			.format = frame->format,
			.num_planes = frame->nobjects,
			.strides = {frame->objects[0].stride,
					frame->objects[1].stride,
					frame->objects[2].stride,
					frame->objects[3].stride},
			.offsets = {frame->objects[0].offset,
					frame->objects[1].offset,
					frame->objects[2].offset,
					frame->objects[3].offset},
			.using_planes = {false, false, false, false},
			.modifier = frame->modifier};
	info.using_planes[index] = true;

	size_t fdsz = 0;
	fdcat_t fdtype = get_fd_type(fd, &fdsz);
	if (fdtype != FDC_DMABUF) {
		wp_log(WP_ERROR,
				"fd %d, #%d for wlr-export-dmabuf frame wasn't a dmabuf, instead %s",
				fd, index, fdcat_to_str(fdtype));
		return;
	}

	struct shadow_fd *sfd = translate_fd(&ctx->g->map, &ctx->g->render, fd,
			FDC_DMABUF, 0, &info, false);
	if (sfd->buffer_size < size) {
		wp_log(WP_ERROR,
				"Frame object %u has a dmabuf with less (%u) than the advertised (%u) size",
				index, (uint32_t)sfd->buffer_size, size);
	}

	// Convert the stored fds to buffer pointers now.
	frame->objects[index].buffer = shadow_incref_protocol(sfd);

	// in practice, index+1?
	(void)plane_index;
}
void do_zwlr_export_dmabuf_frame_v1_evt_ready(struct context *ctx,
		uint32_t tv_sec_hi, uint32_t tv_sec_lo, uint32_t tv_nsec)
{

	struct wp_export_dmabuf_frame *frame =
			(struct wp_export_dmabuf_frame *)ctx->obj;
	if (!ctx->on_display_side) {
		/* The client side does not update the buffer */
		return;
	}

	(void)tv_sec_hi;
	(void)tv_sec_lo;
	(void)tv_nsec;
	for (uint32_t i = 0; i < frame->nobjects; i++) {
		struct shadow_fd *sfd = frame->objects[i].buffer;
		if (sfd) {
			sfd->is_dirty = true;
			damage_everything(&sfd->damage);
		}
	}
}
static void translate_data_transfer_fd(struct context *context, int32_t fd)
{
	/* treat the fd as a one-way pipe, even if it is e.g. a file or
	 * socketpair, with additional properties. The fd being sent
	 * around should be, according to the protocol, only written into and
	 * closed */
	translate_fd(&context->g->map, &context->g->render, fd, FDC_PIPE_IW, 0,
			NULL, false);
}
void do_gtk_primary_selection_offer_req_receive(
		struct context *ctx, const char *mime_type, int fd)
{
	translate_data_transfer_fd(ctx, fd);
	(void)mime_type;
}
void do_gtk_primary_selection_source_evt_send(
		struct context *ctx, const char *mime_type, int fd)
{
	translate_data_transfer_fd(ctx, fd);
	(void)mime_type;
}
void do_zwlr_data_control_offer_v1_req_receive(
		struct context *ctx, const char *mime_type, int fd)
{
	translate_data_transfer_fd(ctx, fd);
	(void)mime_type;
}
void do_zwlr_data_control_source_v1_evt_send(
		struct context *ctx, const char *mime_type, int fd)
{
	translate_data_transfer_fd(ctx, fd);
	(void)mime_type;
}
void do_wl_data_offer_req_receive(
		struct context *ctx, const char *mime_type, int fd)
{
	translate_data_transfer_fd(ctx, fd);
	(void)mime_type;
}
void do_wl_data_source_evt_send(
		struct context *ctx, const char *mime_type, int fd)
{
	translate_data_transfer_fd(ctx, fd);
	(void)mime_type;
}

/* Q: embed this section and what follows into 'symgen'? */
static const struct evt_map_wl_display wl_display_event_handler = {
		.error = call_wl_display_evt_error,
		.delete_id = call_wl_display_evt_delete_id};
static const struct req_map_wl_display wl_display_request_handler = {
		.get_registry = call_wl_display_req_get_registry,
		.sync = call_wl_display_req_sync};
static const struct evt_map_wl_registry wl_registry_event_handler = {
		.global = call_wl_registry_evt_global,
		.global_remove = call_wl_registry_evt_global_remove};
static const struct req_map_wl_registry wl_registry_request_handler = {
		.bind = call_wl_registry_req_bind};
static const struct evt_map_wl_buffer wl_buffer_event_handler = {
		.release = call_wl_buffer_evt_release};
static const struct req_map_wl_surface wl_surface_request_handler = {
		.attach = call_wl_surface_req_attach,
		.commit = call_wl_surface_req_commit,
		.damage = call_wl_surface_req_damage,
		.damage_buffer = call_wl_surface_req_damage_buffer,
		.set_buffer_scale = call_wl_surface_req_set_buffer_scale,
		.set_buffer_transform =
				call_wl_surface_req_set_buffer_transform,
};
static const struct evt_map_wl_keyboard wl_keyboard_event_handler = {
		.keymap = call_wl_keyboard_evt_keymap};
static const struct req_map_wl_shm wl_shm_request_handler = {
		.create_pool = call_wl_shm_req_create_pool,
};
static const struct req_map_wl_shm_pool wl_shm_pool_request_handler = {
		.resize = call_wl_shm_pool_req_resize,
		.create_buffer = call_wl_shm_pool_req_create_buffer,
};
static const struct evt_map_zwlr_screencopy_frame_v1
		zwlr_screencopy_frame_v1_event_handler = {
				.ready = call_zwlr_screencopy_frame_v1_evt_ready};
static const struct req_map_zwlr_screencopy_frame_v1
		zwlr_screencopy_frame_v1_request_handler = {
				.copy = call_zwlr_screencopy_frame_v1_req_copy};
static const struct evt_map_wp_presentation wp_presentation_event_handler = {
		.clock_id = call_wp_presentation_evt_clock_id};
static const struct req_map_wp_presentation wp_presentation_request_handler = {
		.feedback = call_wp_presentation_req_feedback};
static const struct evt_map_wp_presentation_feedback wp_presentation_feedback_event_handler =
		{.presented = call_wp_presentation_feedback_evt_presented};
static const struct evt_map_wl_drm wl_drm_event_handler = {
		.device = call_wl_drm_evt_device};
static const struct req_map_wl_drm wl_drm_request_handler = {
		/* the other 'create_buffer' methods require an
		 * authenticated drm node, which we do never advertise
		 */
		.create_prime_buffer = call_wl_drm_req_create_prime_buffer};
static const struct evt_map_zwp_linux_dmabuf_v1 zwp_linux_dmabuf_v1_event_handler =
		{.modifier = call_zwp_linux_dmabuf_v1_evt_modifier};
static const struct evt_map_zwp_linux_buffer_params_v1
		zwp_linux_buffer_params_v1_event_handler = {
				.created = call_zwp_linux_buffer_params_v1_evt_created};
static const struct req_map_zwp_linux_buffer_params_v1
		zwp_linux_buffer_params_v1_request_handler = {
				.add = call_zwp_linux_buffer_params_v1_req_add,
				.create = call_zwp_linux_buffer_params_v1_req_create,
				.create_immed = call_zwp_linux_buffer_params_v1_req_create_immed,
};
static const struct evt_map_zwlr_export_dmabuf_frame_v1
		zwlr_export_dmabuf_frame_v1_event_handler = {
				.frame = call_zwlr_export_dmabuf_frame_v1_evt_frame,
				.object = call_zwlr_export_dmabuf_frame_v1_evt_object,
				.ready = call_zwlr_export_dmabuf_frame_v1_evt_ready,
};
static const struct evt_map_zwlr_data_control_source_v1
		zwlr_data_control_source_v1_event_handler = {
				.send = call_zwlr_data_control_source_v1_evt_send};
static const struct evt_map_gtk_primary_selection_source
		gtk_primary_selection_source_event_handler = {
				.send = call_gtk_primary_selection_source_evt_send};
static const struct evt_map_wl_data_source wl_data_source_event_handler = {
		.send = call_wl_data_source_evt_send};
static const struct req_map_zwlr_data_control_offer_v1
		zwlr_data_control_offer_v1_request_handler = {
				.receive = call_zwlr_data_control_offer_v1_req_receive};
static const struct req_map_gtk_primary_selection_offer
		gtk_primary_selection_offer_request_handler = {
				.receive = call_gtk_primary_selection_offer_req_receive};
static const struct req_map_wl_data_offer wl_data_offer_request_handler = {
		.receive = call_wl_data_offer_req_receive};

const struct msg_handler handlers[] = {
		{&intf_wl_display, &wl_display_event_handler,
				&wl_display_request_handler, false},
		{&intf_wl_registry, &wl_registry_event_handler,
				&wl_registry_request_handler, false},
		{&intf_wl_shm_pool, NULL, &wl_shm_pool_request_handler, false},
		{&intf_wl_buffer, &wl_buffer_event_handler, NULL, false},
		{&intf_wl_surface, NULL, &wl_surface_request_handler, false},
		{&intf_wl_keyboard, &wl_keyboard_event_handler, NULL, false},
		{&intf_zwlr_screencopy_frame_v1,
				&zwlr_screencopy_frame_v1_event_handler,
				&zwlr_screencopy_frame_v1_request_handler,
				false},
		{&intf_wp_presentation_feedback,
				&wp_presentation_feedback_event_handler, NULL,
				false},
		{&intf_zwp_linux_buffer_params_v1,
				&zwp_linux_buffer_params_v1_event_handler,
				&zwp_linux_buffer_params_v1_request_handler,
				false},
		{&intf_zwlr_export_dmabuf_frame_v1,
				&zwlr_export_dmabuf_frame_v1_event_handler,
				NULL, false},

		/* Copy-paste protocol handlers, handled near identically */
		{&intf_zwlr_data_control_offer_v1, NULL,
				&zwlr_data_control_offer_v1_request_handler,
				false},
		{&intf_gtk_primary_selection_offer, NULL,
				&gtk_primary_selection_offer_request_handler,
				false},
		{&intf_wl_data_offer, NULL, &wl_data_offer_request_handler,
				false},

		{&intf_zwlr_data_control_source_v1,
				&zwlr_data_control_source_v1_event_handler,
				NULL, false},
		{&intf_gtk_primary_selection_source,
				&gtk_primary_selection_source_event_handler,
				NULL, false},
		{&intf_wl_data_source, &wl_data_source_event_handler, NULL,
				false},

		/* List all other known global object interface types,
		 * so that the parsing code can identify all fd usages
		 */
		// wayland
		{&intf_wl_compositor, NULL, NULL, true},
		{&intf_wl_subcompositor, NULL, NULL, true},
		{&intf_wl_data_device_manager, NULL, NULL, true},
		{&intf_wl_shm, NULL, &wl_shm_request_handler, true},
		{&intf_wl_seat, NULL, NULL, true},
		{&intf_wl_output, NULL, NULL, true},
		// xdg-shell
		{&intf_xdg_wm_base, NULL, NULL, true},
		// presentation-time
		{&intf_wp_presentation, &wp_presentation_event_handler,
				&wp_presentation_request_handler, true},
		// gtk-primary-selection
		{&intf_gtk_primary_selection_device_manager, NULL, NULL, true},
		// virtual-keyboard
		{&intf_zwp_virtual_keyboard_manager_v1, NULL, NULL, true},
		// input-method
		{&intf_zwp_input_method_manager_v2, NULL, NULL, true},
		// linux-dmabuf
		{&intf_zwp_linux_dmabuf_v1, &zwp_linux_dmabuf_v1_event_handler,
				NULL, true},
		// screencopy-manager
		{&intf_zwlr_screencopy_manager_v1, NULL, NULL, true},
		// wayland-drm
		{&intf_wl_drm, &wl_drm_event_handler, &wl_drm_request_handler,
				true},
		// wlr-export-dmabuf
		{&intf_zwlr_export_dmabuf_manager_v1, NULL, NULL, true},
		// wlr-export-dmabuf
		{&intf_zwlr_data_control_manager_v1, NULL, NULL, true},

		{NULL, NULL, NULL, false}};
const struct wp_interface *the_display_interface = &intf_wl_display;
