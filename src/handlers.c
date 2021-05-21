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

#include "main.h"
#include "parsing.h"
#include "shadow.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <protocols.h>

struct obj_wl_shm_pool {
	struct wp_object base;
	struct shadow_fd *owned_buffer;
};

enum buffer_type { BUF_SHM, BUF_DMA };

// This should be a safe limit for the maximum number of dmabuf planes
#define MAX_DMABUF_PLANES 8

struct obj_wl_buffer {
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

	uint64_t unique_id;
};

struct damage_record {
	int x, y, width, height;
	bool buffer_coordinates;
};

struct damage_list {
	struct damage_record *list;
	int len;
	int size;
};

#define SURFACE_DAMAGE_BACKLOG 7
struct obj_wl_surface {
	struct wp_object base;

	/* The zeroth list is the "current" one, 1st was damage provided at last
	 * commit, etc. */
	struct damage_list damage_lists[SURFACE_DAMAGE_BACKLOG];
	/* Unique buffer identifiers to which the above damage lists apply */
	uint64_t attached_buffer_uids[SURFACE_DAMAGE_BACKLOG];

	uint32_t attached_buffer_id; /* protocol object id */
	int32_t scale;
	int32_t transform;
};

struct obj_wlr_screencopy_frame {
	struct wp_object base;
	/* Link to a wp_buffer instead of its underlying data,
	 * because if the buffer object is destroyed early, then
	 * we do not want to accidentally write over a section of a shm_pool
	 * which is now used for transport in the reverse direction.
	 */
	uint32_t buffer_id;
};

struct obj_wp_presentation {
	struct wp_object base;

	// reference clock - given clock
	int64_t clock_delta_nsec;
	int clock_id;
};
struct obj_wp_presentation_feedback {
	struct wp_object base;
	int64_t clock_delta_nsec;
};

struct obj_zwp_linux_dmabuf_params {
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

struct obj_wlr_export_dmabuf_frame {
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

/* List of interfaces which may be advertised as globals */
static const struct wp_interface *const global_interfaces[] = {
		&intf_gtk_primary_selection_device_manager,
		&intf_wl_compositor,
		&intf_wl_data_device_manager,
		&intf_wl_drm,
		&intf_wl_output,
		&intf_wl_seat,
		&intf_wl_shm,
		&intf_wl_subcompositor,
		&intf_wp_presentation,
		&intf_xdg_wm_base,
		&intf_zwlr_data_control_manager_v1,
		&intf_zwlr_export_dmabuf_manager_v1,
		&intf_zwlr_gamma_control_manager_v1,
		&intf_zwlr_screencopy_manager_v1,
		&intf_zwp_input_method_manager_v2,
		&intf_zwp_linux_dmabuf_v1,
		&intf_zwp_primary_selection_device_manager_v1,
		&intf_zwp_virtual_keyboard_manager_v1,
};
/* List of interfaces which are never advertised as globals */
static const struct wp_interface *const non_global_interfaces[] = {
		&intf_gtk_primary_selection_offer,
		&intf_gtk_primary_selection_source,
		&intf_wl_buffer,
		&intf_wl_data_offer,
		&intf_wl_data_source,
		&intf_wl_display,
		&intf_wl_keyboard,
		&intf_wl_registry,
		&intf_wl_shm_pool,
		&intf_wl_surface,
		&intf_wp_presentation_feedback,
		&intf_zwlr_data_control_offer_v1,
		&intf_zwlr_data_control_source_v1,
		&intf_zwlr_export_dmabuf_frame_v1,
		&intf_zwlr_gamma_control_v1,
		&intf_zwlr_screencopy_frame_v1,
		&intf_zwp_linux_buffer_params_v1,
		&intf_zwp_primary_selection_offer_v1,
		&intf_zwp_primary_selection_source_v1,
};

void destroy_wp_object(struct wp_object *object)
{
	if (object->type == &intf_wl_shm_pool) {
		struct obj_wl_shm_pool *r = (struct obj_wl_shm_pool *)object;
		if (r->owned_buffer) {
			shadow_decref_protocol(r->owned_buffer);
		}
	} else if (object->type == &intf_wl_buffer) {
		struct obj_wl_buffer *r = (struct obj_wl_buffer *)object;
		for (int i = 0; i < MAX_DMABUF_PLANES; i++) {
			if (r->dmabuf_buffers[i]) {
				shadow_decref_protocol(r->dmabuf_buffers[i]);
			}
		}
		if (r->shm_buffer) {
			shadow_decref_protocol(r->shm_buffer);
		}
	} else if (object->type == &intf_wl_surface) {
		struct obj_wl_surface *r = (struct obj_wl_surface *)object;
		for (int i = 0; i < SURFACE_DAMAGE_BACKLOG; i++) {
			free(r->damage_lists[i].list);
		}
	} else if (object->type == &intf_zwlr_screencopy_frame_v1) {
		struct obj_wlr_screencopy_frame *r =
				(struct obj_wlr_screencopy_frame *)object;
		(void)r;
	} else if (object->type == &intf_wp_presentation) {
	} else if (object->type == &intf_wp_presentation_feedback) {
	} else if (object->type == &intf_zwp_linux_buffer_params_v1) {
		struct obj_zwp_linux_dmabuf_params *r =
				(struct obj_zwp_linux_dmabuf_params *)object;
		for (int i = 0; i < MAX_DMABUF_PLANES; i++) {
			if (r->add[i].buffer) {
				shadow_decref_protocol(r->add[i].buffer);
			}
			// Sometimes multiple entries point to the same buffer
			if (r->add[i].fd != -1) {
				checked_close(r->add[i].fd);

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
		struct obj_wlr_export_dmabuf_frame *r =
				(struct obj_wlr_export_dmabuf_frame *)object;
		for (int i = 0; i < MAX_DMABUF_PLANES; i++) {
			if (r->objects[i].buffer) {
				shadow_decref_protocol(r->objects[i].buffer);
			}
		}
	}
	free(object);
}
struct wp_object *create_wp_object(uint32_t id, const struct wp_interface *type)
{
	/* Note: if custom types are ever implemented for globals, they would
	 * need special replacement logic when the type is set */
	size_t sz;
	if (type == &intf_wl_shm_pool) {
		sz = sizeof(struct obj_wl_shm_pool);
	} else if (type == &intf_wl_buffer) {
		sz = sizeof(struct obj_wl_buffer);
	} else if (type == &intf_wl_surface) {
		sz = sizeof(struct obj_wl_surface);
	} else if (type == &intf_zwlr_screencopy_frame_v1) {
		sz = sizeof(struct obj_wlr_screencopy_frame);
	} else if (type == &intf_wp_presentation) {
		sz = sizeof(struct obj_wp_presentation);
	} else if (type == &intf_wp_presentation_feedback) {
		sz = sizeof(struct obj_wp_presentation_feedback);
	} else if (type == &intf_zwp_linux_buffer_params_v1) {
		sz = sizeof(struct obj_zwp_linux_dmabuf_params);
	} else if (type == &intf_zwlr_export_dmabuf_frame_v1) {
		sz = sizeof(struct obj_wlr_export_dmabuf_frame);
	} else {
		sz = sizeof(struct wp_object);
	}

	struct wp_object *new_obj = calloc(1, sz);
	if (!new_obj) {
		wp_error("Failed to allocate new wp_object id=%d type=%s", id,
				type->name);
		return NULL;
	}
	new_obj->obj_id = id;
	new_obj->type = type;
	new_obj->is_zombie = false;

	if (type == &intf_zwp_linux_buffer_params_v1) {
		struct obj_zwp_linux_dmabuf_params *params =
				(struct obj_zwp_linux_dmabuf_params *)new_obj;
		for (int i = 0; i < MAX_DMABUF_PLANES; i++) {
			params->add[i].fd = -1;
		}
	} else if (type == &intf_wl_surface) {
		((struct obj_wl_surface *)new_obj)->scale = 1;
	}
	return new_obj;
}

void do_wl_display_evt_error(struct context *ctx, struct wp_object *object_id,
		uint32_t code, const char *message)
{
	const char *type_name =
			object_id ? (object_id->type ? object_id->type->name
						     : "<no type>")
				  : "<no object>";
	wp_error("Display sent fatal error message %s, code %u: %s", type_name,
			code, message ? message : "<no message>");
	(void)ctx;
}
void do_wl_display_evt_delete_id(struct context *ctx, uint32_t id)
{
	struct wp_object *obj = tracker_get(ctx->tracker, id);
	/* ensure this isn't miscalled to have wl_display delete itself */
	if (obj && obj != ctx->obj) {
		tracker_remove(ctx->tracker, obj);
		destroy_wp_object(obj);
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
		wp_debug("Interface name provided via wl_registry::global was NULL");
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
			wp_debug("Discarding protocol advertisement for %s, render node support disabled",
					interface);
			ctx->drop_this_msg = true;
			return;
		}
	}

	bool unsupported = false;
	// requires novel fd translation, not yet supported
	unsupported |= !strcmp(
			interface, "zwp_linux_explicit_synchronization_v1");
	if (unsupported) {
		wp_debug("Hiding %s advertisement, unsupported", interface);
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
		wp_debug("Interface name provided to wl_registry::bind was NULL");
		return;
	}
	/* The object has already been created, but its type is NULL */
	struct wp_object *the_object = id;
	uint32_t obj_id = the_object->obj_id;

	for (size_t i = 0; i < sizeof(non_global_interfaces) /
					       sizeof(non_global_interfaces[0]);
			i++) {
		if (!strcmp(interface, non_global_interfaces[i]->name)) {
			wp_error("Interface %s does not support binding globals",
					non_global_interfaces[i]->name);
			/* exit search, discard unbound object */
			goto fail;
		}
	}

	for (size_t i = 0; i < sizeof(global_interfaces) /
					       sizeof(global_interfaces[0]);
			i++) {
		if (!strcmp(interface, global_interfaces[i]->name)) {
			// Set the object type
			the_object->type = global_interfaces[i];
			if (global_interfaces[i] == &intf_wp_presentation) {
				struct wp_object *new_object = create_wp_object(
						obj_id, &intf_wp_presentation);
				if (!new_object) {
					return;
				}
				tracker_replace_existing(
						ctx->tracker, new_object);
				free(the_object);
			}
			return;
		}
	}

fail:
	wp_debug("Binding fail name=%d %s id=%d (v%d)", name, interface,
			the_object->obj_id, version);

	tracker_remove(ctx->tracker, the_object);
	free(the_object);

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
		wp_error("Encountered planar wl_shm format %x; marking entire buffer",
				format);
		return -1;
	default:
		wp_error("Unidentified WL_SHM format %x", format);
		return -1;
	}
}
static void compute_damage_coordinates(int *xlow, int *xhigh, int *ylow,
		int *yhigh, const struct damage_record *rec, int buf_width,
		int buf_height, int transform, int scale)
{
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
		uint32_t magic = 0x74125630;
		/* idx     76543210
		 * xyech = 10101010
		 * xflip = 11000110
		 * yflip = 10011100
		 */
		bool xyexch = magic & (1u << (4 * transform));
		bool xflip = magic & (1u << (4 * transform + 1));
		bool yflip = magic & (1u << (4 * transform + 2));
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
		wp_debug("Buffer to be attached is null");
		return;
	}
	if (bufobj->type != &intf_wl_buffer) {
		wp_error("Buffer to be attached has the wrong type");
		return;
	}
	struct obj_wl_surface *surface = (struct obj_wl_surface *)ctx->obj;
	surface->attached_buffer_id = bufobj->obj_id;
}
static void rotate_damage_lists(struct obj_wl_surface *surface)
{
	free(surface->damage_lists[SURFACE_DAMAGE_BACKLOG - 1].list);
	memmove(surface->damage_lists + 1, surface->damage_lists,
			(SURFACE_DAMAGE_BACKLOG - 1) *
					sizeof(struct damage_list));
	memset(surface->damage_lists, 0, sizeof(struct damage_list));
	memmove(surface->attached_buffer_uids + 1,
			surface->attached_buffer_uids,
			(SURFACE_DAMAGE_BACKLOG - 1) * sizeof(uint64_t));
	surface->attached_buffer_uids[0] = 0;
}
void do_wl_surface_req_commit(struct context *ctx)
{
	struct obj_wl_surface *surface = (struct obj_wl_surface *)ctx->obj;

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
			tracker_get(ctx->tracker, surface->attached_buffer_id);
	if (!obj) {
		wp_error("Attached buffer no longer exists");
		return;
	}
	if (obj->type != &intf_wl_buffer) {
		wp_error("Buffer to commit has the wrong type, and may have been recycled");
		return;
	}
	struct obj_wl_buffer *buf = (struct obj_wl_buffer *)obj;
	surface->attached_buffer_uids[0] = buf->unique_id;
	if (buf->type == BUF_DMA) {
		rotate_damage_lists(surface);

		for (int i = 0; i < buf->dmabuf_nplanes; i++) {
			struct shadow_fd *sfd = buf->dmabuf_buffers[i];
			if (!sfd) {
				wp_error("dmabuf surface buffer is missing plane %d",
						i);
				continue;
			}

			if (!(sfd->type == FDC_DMABUF ||
					    sfd->type == FDC_DMAVID_IR)) {
				wp_error("fd associated with dmabuf surface is not a dmabuf");
				continue;
			}

			// detailed damage tracking is not yet supported
			sfd->is_dirty = true;
			damage_everything(&sfd->damage);
		}
		return;
	} else if (buf->type != BUF_SHM) {
		wp_error("wp_buffer is backed neither by DMA nor SHM, not yet supported");
		return;
	}

	struct shadow_fd *sfd = buf->shm_buffer;
	if (!sfd) {
		wp_error("wp_buffer to be committed has no fd");
		return;
	}
	if (sfd->type != FDC_FILE) {
		wp_error("fd associated with surface is not file-like");
		return;
	}
	sfd->is_dirty = true;
	int bpp = get_shm_bytes_per_pixel(buf->shm_format);
	if (bpp == -1) {
		goto backup;
	}
	if (surface->scale <= 0) {
		wp_error("Invalid buffer scale during commit (%d), assuming everything damaged",
				surface->scale);
		goto backup;
	}
	if (surface->transform < 0 || surface->transform >= 8) {
		wp_error("Invalid buffer transform during commit (%d), assuming everything damaged",
				surface->transform);
		goto backup;
	}

	/* The damage specified as of wl_surface commit indicates which region
	 * of the surface has changed between the last commit and the current
	 * one. However, the last time the attached buffer was used may have
	 * been several commits ago, so we need to replay all the damage up
	 * to the current point. */
	int age = -1;
	int n_damaged_rects = surface->damage_lists[0].len;
	for (int j = 1; j < SURFACE_DAMAGE_BACKLOG; j++) {
		if (surface->attached_buffer_uids[0] ==
				surface->attached_buffer_uids[j]) {
			age = j;
			break;
		}
		n_damaged_rects += surface->damage_lists[j].len;
	}
	if (age == -1) {
		/* cannot find last time buffer+surface combo was used */
		goto backup;
	}

	struct ext_interval *damage_array = malloc(
			sizeof(struct ext_interval) * (size_t)n_damaged_rects);
	if (!damage_array) {
		wp_error("Failed to allocate damage array");
		goto backup;
	}
	int i = 0;

	// Translate damage stack into damage records for the fd buffer
	for (int k = 0; k < age; k++) {
		const struct damage_list *frame_damage =
				&surface->damage_lists[k];
		for (int j = 0; j < frame_damage->len; j++) {
			int xlow, xhigh, ylow, yhigh;
			compute_damage_coordinates(&xlow, &xhigh, &ylow, &yhigh,
					&frame_damage->list[j], buf->shm_width,
					buf->shm_height, surface->transform,
					surface->scale);

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
	}

	merge_damage_records(&sfd->damage, i, damage_array,
			ctx->g->threads.diff_alignment_bits);
	free(damage_array);
	rotate_damage_lists(surface);
backup:
	if (1) {
		/* damage the entire buffer (but no other part of the shm_pool)
		 */
		struct ext_interval full_surface_damage;
		full_surface_damage.start = buf->shm_offset;
		full_surface_damage.rep = 1;
		full_surface_damage.stride = 0;
		full_surface_damage.width = buf->shm_stride * buf->shm_height;
		merge_damage_records(&sfd->damage, 1, &full_surface_damage,
				ctx->g->threads.diff_alignment_bits);
	}
	rotate_damage_lists(surface);
	return;
}
static void append_damage_record(struct obj_wl_surface *surface, int32_t x,
		int32_t y, int32_t width, int32_t height,
		bool in_buffer_coordinates)
{
	struct damage_list *current = &surface->damage_lists[0];
	if (buf_ensure_size(current->len + 1, sizeof(struct damage_record),
			    &current->size, (void **)&current->list) == -1) {
		wp_error("Failed to allocate space for damage list, dropping damage record");
		return;
	}

	// A rectangle of the buffer was damaged, hence backing buffers
	// may be updated.
	struct damage_record *damage = &current->list[current->len++];
	damage->buffer_coordinates = in_buffer_coordinates;
	damage->x = x;
	damage->y = y;
	damage->width = width;
	damage->height = height;
}
void do_wl_surface_req_damage(struct context *ctx, int32_t x, int32_t y,
		int32_t width, int32_t height)
{
	if (ctx->on_display_side) {
		// The display side does not need to track the damage
		return;
	}
	append_damage_record((struct obj_wl_surface *)ctx->obj, x, y, width,
			height, false);
}
void do_wl_surface_req_damage_buffer(struct context *ctx, int32_t x, int32_t y,
		int32_t width, int32_t height)
{
	if (ctx->on_display_side) {
		// The display side does not need to track the damage
		return;
	}
	append_damage_record((struct obj_wl_surface *)ctx->obj, x, y, width,
			height, true);
}
void do_wl_surface_req_set_buffer_transform(
		struct context *ctx, int32_t transform)
{

	struct obj_wl_surface *surface = (struct obj_wl_surface *)ctx->obj;
	surface->transform = transform;
}
void do_wl_surface_req_set_buffer_scale(struct context *ctx, int32_t scale)
{
	struct obj_wl_surface *surface = (struct obj_wl_surface *)ctx->obj;
	surface->scale = scale;
}
void do_wl_keyboard_evt_keymap(
		struct context *ctx, uint32_t format, int fd, uint32_t size)
{
	size_t fdsz = 0;
	enum fdcat fdtype = get_fd_type(fd, &fdsz);
	if (fdtype == FDC_UNKNOWN) {
		fdtype = FDC_FILE;
		fdsz = (size_t)size;
	}
	if (fdtype != FDC_FILE || fdsz != size) {
		wp_error("keymap candidate fd %d was not file-like (type=%s), and with size=%zu did not match %u",
				fd, fdcat_to_str(fdtype), fdsz, size);
		return;
	}

	struct shadow_fd *sfd = translate_fd(&ctx->g->map, &ctx->g->render, fd,
			FDC_FILE, fdsz, NULL, false, false);
	if (!sfd) {
		wp_error("Failed to create shadow for keymap fd=%d", fd);
		return;
	}
	/* The keyboard file descriptor is never changed after being sent.
	 * Mark the shadow structure as owned by the protocol, so it can be
	 * automatically deleted as soon as the fd has been transferred. */
	sfd->has_owner = true;
	(void)format;
}

void do_wl_shm_req_create_pool(
		struct context *ctx, struct wp_object *id, int fd, int32_t size)
{
	struct obj_wl_shm_pool *the_shm_pool = (struct obj_wl_shm_pool *)id;

	if (size <= 0) {
		wp_error("Ignoring attempt to create a wl_shm_pool with size %d",
				size);
	}

	size_t fdsz = 0;
	enum fdcat fdtype = get_fd_type(fd, &fdsz);
	if (fdtype == FDC_UNKNOWN) {
		fdtype = FDC_FILE;
		fdsz = (size_t)size;
	}
	/* It may be valid for the file descriptor size to be larger
	 * than the immediately advertised size, since the call to
	 * wl_shm.create_pool may be followed by wl_shm_pool.resize,
	 * which then increases the size
	 */
	if (fdtype != FDC_FILE || (int32_t)fdsz < size) {
		wp_error("File type or size mismatch for fd %d with claimed: %s %s | %zu %u",
				fd, fdcat_to_str(fdtype),
				fdcat_to_str(FDC_FILE), fdsz, size);
		return;
	}

	struct shadow_fd *sfd = translate_fd(&ctx->g->map, &ctx->g->render, fd,
			FDC_FILE, fdsz, NULL, false, false);
	if (!sfd) {
		return;
	}
	the_shm_pool->owned_buffer = shadow_incref_protocol(sfd);
	/* We only send shm_pool updates when the buffers created from the
	 * pool are used. Some applications make the pool >> actual buffers,
	 * so this can reduce communication by a lot*/
	reset_damage(&sfd->damage);
}

void do_wl_shm_pool_req_resize(struct context *ctx, int32_t size)
{
	struct obj_wl_shm_pool *the_shm_pool =
			(struct obj_wl_shm_pool *)ctx->obj;

	if (!the_shm_pool->owned_buffer) {
		wp_error("Pool to be resized owns no buffer");
		return;
	}
	if ((int32_t)the_shm_pool->owned_buffer->buffer_size >= size) {
		// The underlying buffer was already resized by the time
		// this protocol message was received
		return;
	}
	/* The display side will be updated already via buffer update msg */
	if (!ctx->on_display_side) {
		extend_shm_shadow(&ctx->g->map, &ctx->g->threads,
				the_shm_pool->owned_buffer, (size_t)size);
	}
}
void do_wl_shm_pool_req_create_buffer(struct context *ctx, struct wp_object *id,
		int32_t offset, int32_t width, int32_t height, int32_t stride,
		uint32_t format)
{
	struct obj_wl_shm_pool *the_shm_pool =
			(struct obj_wl_shm_pool *)ctx->obj;
	struct obj_wl_buffer *the_buffer = (struct obj_wl_buffer *)id;
	if (!the_buffer) {
		wp_error("No buffer available");
		return;
	}
	struct shadow_fd *sfd = the_shm_pool->owned_buffer;
	if (!sfd) {
		wp_error("Creating a wl_buffer from a pool that does not own an fd");
		return;
	}

	the_buffer->type = BUF_SHM;
	the_buffer->shm_buffer =
			shadow_incref_protocol(the_shm_pool->owned_buffer);
	the_buffer->shm_offset = offset;
	the_buffer->shm_width = width;
	the_buffer->shm_height = height;
	the_buffer->shm_stride = stride;
	the_buffer->shm_format = format;
	the_buffer->unique_id = ctx->g->tracker.buffer_seqno++;
}

void do_zwlr_screencopy_frame_v1_evt_ready(struct context *ctx,
		uint32_t tv_sec_hi, uint32_t tv_sec_lo, uint32_t tv_nsec)
{
	struct obj_wlr_screencopy_frame *frame =
			(struct obj_wlr_screencopy_frame *)ctx->obj;
	if (!frame->buffer_id) {
		wp_error("frame has no copy target");
		return;
	}
	struct wp_object *obj = (struct wp_object *)tracker_get(
			ctx->tracker, frame->buffer_id);
	if (!obj) {
		wp_error("frame copy target no longer exists");
		return;
	}
	if (obj->type != &intf_wl_buffer) {
		wp_error("frame copy target is not a wl_buffer");
		return;
	}
	struct obj_wl_buffer *buffer = (struct obj_wl_buffer *)obj;
	struct shadow_fd *sfd = buffer->shm_buffer;
	if (!sfd) {
		wp_error("frame copy target does not own any buffers");
		return;
	}
	if (sfd->type != FDC_FILE) {
		wp_error("frame copy target buffer file descriptor (RID=%d) was not file-like (type=%d)",
				sfd->remote_id, sfd->type);
		return;
	}
	if (buffer->type != BUF_SHM) {
		wp_error("screencopy not yet supported for non-shm-backed buffers");
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
	merge_damage_records(&sfd->damage, 1, &interval,
			ctx->g->threads.diff_alignment_bits);

	(void)tv_sec_lo;
	(void)tv_sec_hi;
	(void)tv_nsec;
}
void do_zwlr_screencopy_frame_v1_req_copy(
		struct context *ctx, struct wp_object *buffer)
{
	struct obj_wlr_screencopy_frame *frame =
			(struct obj_wlr_screencopy_frame *)ctx->obj;
	struct wp_object *buf = (struct wp_object *)buffer;
	if (buf->type != &intf_wl_buffer) {
		wp_error("frame copy destination is not a wl_buffer");
		return;
	}
	frame->buffer_id = buf->obj_id;
}

static int64_t timespec_diff(struct timespec val, struct timespec sub)
{
	// Overflows only with 68 year error, insignificant
	return (val.tv_sec - sub.tv_sec) * 1000000000LL +
	       (val.tv_nsec - sub.tv_nsec);
}
void do_wp_presentation_evt_clock_id(struct context *ctx, uint32_t clk_id)
{
	struct obj_wp_presentation *pres =
			(struct obj_wp_presentation *)ctx->obj;
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
		int64_t diff1m0 = timespec_diff(t1, t0);
		int64_t diff2m1 = timespec_diff(t2, t1);
		pres->clock_delta_nsec = (diff1m0 - diff2m1) / 2;
	}
}
void do_wp_presentation_req_feedback(struct context *ctx,
		struct wp_object *surface, struct wp_object *callback)
{
	struct obj_wp_presentation *pres =
			(struct obj_wp_presentation *)ctx->obj;
	struct obj_wp_presentation_feedback *feedback =
			(struct obj_wp_presentation_feedback *)callback;
	(void)surface;

	feedback->clock_delta_nsec = pres->clock_delta_nsec;
}
void do_wp_presentation_feedback_evt_presented(struct context *ctx,
		uint32_t tv_sec_hi, uint32_t tv_sec_lo, uint32_t tv_nsec,
		uint32_t refresh, uint32_t seq_hi, uint32_t seq_lo,
		uint32_t flags)
{
	struct obj_wp_presentation_feedback *feedback =
			(struct obj_wp_presentation_feedback *)ctx->obj;

	(void)refresh;
	(void)seq_hi;
	(void)seq_lo;
	(void)flags;

	/* convert local to reference, on display side */
	int dir = ctx->on_display_side ? 1 : -1;

	uint64_t sec = tv_sec_lo + tv_sec_hi * 0x100000000uLL;
	int64_t nsec = tv_nsec;
	nsec += dir * feedback->clock_delta_nsec;
	sec = (uint64_t)((int64_t)sec + nsec / 1000000000LL);
	nsec = nsec % 1000000000L;
	if (nsec < 0) {
		nsec += 1000000000L;
		sec--;
	}
	// Size not changed, no other edits required
	ctx->message[2] = (uint32_t)(sec / 0x100000000uLL);
	ctx->message[3] = (uint32_t)(sec % 0x100000000uLL);
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
		wp_debug("Device name provided via wl_drm::device was NULL");
		return;
	}
	if (!ctx->g->render.drm_node_path) {
		/* While the render node should have been initialized in
		 * wl_registry.global, setting this path, we still don't want
		 * to crash even if this gets called by accident */
		wp_debug("wl_drm::device, local render node not set up");
		return;
	}
	int path_len = (int)strlen(ctx->g->render.drm_node_path);
	int message_bytes = 8 + 4 + 4 * ((path_len + 1 + 3) / 4);
	if (message_bytes > ctx->message_available_space) {
		wp_error("Not enough space to modify DRM device advertisement from '%s' to '%s'",
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
	struct obj_wl_buffer *buf = (struct obj_wl_buffer *)id;
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

	if (is_dmabuf(name) == 0) {
		size_t fdsz = 0;
		enum fdcat fdtype = get_fd_type(name, &fdsz);
		wp_error("create_prime_buffer candidate fd %d was not a dmabuf (type=%s)",
				name, fdcat_to_str(fdtype));
		return;
	}

	struct shadow_fd *sfd = translate_fd(&ctx->g->map, &ctx->g->render,
			name, FDC_DMABUF, 0, &info, true, false);
	if (!sfd) {
		return;
	}
	buf->type = BUF_DMA;
	buf->dmabuf_nplanes = 1;
	buf->dmabuf_buffers[0] = shadow_incref_protocol(sfd);
	buf->dmabuf_width = width;
	buf->dmabuf_height = height;
	buf->dmabuf_format = format;
	// handling multiple offsets (?)
	buf->dmabuf_offsets[0] = (uint32_t)offset0;
	buf->dmabuf_strides[0] = (uint32_t)stride0;
	buf->unique_id = ctx->g->tracker.buffer_seqno++;
}

void do_zwp_linux_dmabuf_v1_evt_modifier(struct context *ctx, uint32_t format,
		uint32_t modifier_hi, uint32_t modifier_lo)
{

	(void)format;
	uint64_t modifier = modifier_hi * 0x100000000uLL + modifier_lo;
	// Prevent all advertisements for dmabufs with modifiers
	if (ctx->g->config->only_linear_dmabuf) {
		if (modifier != 0 && modifier != ((1uLL << 56) - 1)) {
			ctx->drop_this_msg = true;
		}
	}
}
void do_zwp_linux_buffer_params_v1_evt_created(
		struct context *ctx, struct wp_object *buffer)
{
	struct obj_zwp_linux_dmabuf_params *params =
			(struct obj_zwp_linux_dmabuf_params *)ctx->obj;
	struct obj_wl_buffer *buf = (struct obj_wl_buffer *)buffer;
	buf->type = BUF_DMA;
	buf->dmabuf_nplanes = params->nplanes;
	for (int i = 0; i < params->nplanes; i++) {
		if (!params->add[i].buffer) {
			wp_error("dmabuf backed wl_buffer plane %d was missing",
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
	buf->unique_id = ctx->g->tracker.buffer_seqno++;
}
void do_zwp_linux_buffer_params_v1_req_add(struct context *ctx, int fd,
		uint32_t plane_idx, uint32_t offset, uint32_t stride,
		uint32_t modifier_hi, uint32_t modifier_lo)
{
	struct obj_zwp_linux_dmabuf_params *params =
			(struct obj_zwp_linux_dmabuf_params *)ctx->obj;
	if (params->nplanes != (int)plane_idx) {
		wp_error("Expected sequentially assigned plane fds: got new_idx=%d != %d=nplanes",
				plane_idx, params->nplanes);
		return;
	}
	if (params->nplanes >= MAX_DMABUF_PLANES) {
		wp_error("Too many planes");
		return;
	}
	params->nplanes++;
	params->add[plane_idx].fd = fd;
	params->add[plane_idx].offset = offset;
	params->add[plane_idx].stride = stride;
	params->add[plane_idx].modifier =
			modifier_lo + modifier_hi * 0x100000000uLL;
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
static int reintroduce_add_msgs(struct context *context,
		struct obj_zwp_linux_dmabuf_params *params)
{
	int net_length = context->message_length;
	int nfds = 0;
	for (int i = 0; i < params->nplanes; i++) {
		net_length += params->add[i].msg_len;
		nfds++;
	}
	if (net_length > context->message_available_space) {
		wp_error("Not enough space to reintroduce zwp_linux_buffer_params_v1.add message data");
		return -1;
	}
	if (nfds > context->fds->size - context->fds->zone_end) {
		wp_error("Not enough space to reintroduce zwp_linux_buffer_params_v1.add message fds");
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
		/* Tag the message as having one file descriptor */
		((uint32_t *)(cmsg + start))[1] |= (uint32_t)(1 << 11);
		start += params->add[i].msg_len;
		free(params->add[i].msg);
		params->add[i].msg = NULL;
		params->add[i].msg_len = 0;
	}
	wp_debug("Reintroducing add requests for zwp_linux_buffer_params_v1, going from %d to %d bytes",
			context->message_length, net_length);
	context->message_length = net_length;
	context->fds_changed = true;
	return 0;
}
/** After this function is called, all subsets of fds that duplicate an
 * underlying dmabuf will be reduced to select a single fd. */
static void deduplicate_dmabuf_fds(struct context *context,
		struct obj_zwp_linux_dmabuf_params *params)
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
			checked_close(params->add[i].fd);
		}
		params->add[i].fd = params->add[lowest].fd;
	}
}

void do_zwp_linux_buffer_params_v1_req_create(struct context *ctx,
		int32_t width, int32_t height, uint32_t format, uint32_t flags)
{
	struct obj_zwp_linux_dmabuf_params *params =
			(struct obj_zwp_linux_dmabuf_params *)ctx->obj;
	params->create_flags = flags;
	params->create_width = width;
	params->create_height = height;
	params->create_format = format;
	deduplicate_dmabuf_fds(ctx, params);
	if (!ctx->on_display_side) {
		reintroduce_add_msgs(ctx, params);
	}
	struct dmabuf_slice_data info = {.width = (uint32_t)width,
			.height = (uint32_t)height,
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
	bool all_same_fds = true;
	for (int i = 1; i < params->nplanes; i++) {
		if (params->add[i].fd != params->add[0].fd) {
			all_same_fds = false;
		}
	}

	for (int i = 0; i < params->nplanes; i++) {
		memset(info.using_planes, 0, sizeof(info.using_planes));
		for (int k = 0; k < min(params->nplanes, 4); k++) {
			if (params->add[k].fd == params->add[i].fd) {
				info.using_planes[k] = 1;
				info.modifier = params->add[k].modifier;
			}
		}

		if (is_dmabuf(params->add[i].fd) == 0) {
			size_t fdsz = 0;
			enum fdcat fdtype =
					get_fd_type(params->add[i].fd, &fdsz);
			wp_error("fd #%d for linux-dmabuf request was not a dmabuf, instead %s",
					i, fdcat_to_str(fdtype));
			continue;
		}

		enum fdcat res_type = FDC_DMABUF;
		if (ctx->g->config->video_if_possible) {
			// TODO: multibuffer support
			if (all_same_fds && video_supports_dmabuf_format(format,
							    info.modifier)) {
				res_type = ctx->on_display_side ? FDC_DMAVID_IW
								: FDC_DMAVID_IR;
			}
		}

		struct shadow_fd *sfd = translate_fd(&ctx->g->map,
				&ctx->g->render, params->add[i].fd, res_type, 0,
				&info, false, false);
		if (!sfd) {
			continue;
		}
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
	struct obj_wlr_export_dmabuf_frame *frame =
			(struct obj_wlr_export_dmabuf_frame *)ctx->obj;

	frame->width = width;
	frame->height = height;
	(void)offset_x;
	(void)offset_y;
	// the 'transient' flag could be cleared, technically
	(void)flags;
	(void)buffer_flags;
	frame->format = format;
	frame->modifier = mod_high * 0x100000000uLL + mod_low;
	frame->nobjects = num_objects;
	if (frame->nobjects > MAX_DMABUF_PLANES) {
		wp_error("Too many (%u) frame objects required",
				frame->nobjects);
		frame->nobjects = MAX_DMABUF_PLANES;
	}
}
void do_zwlr_export_dmabuf_frame_v1_evt_object(struct context *ctx,
		uint32_t index, int fd, uint32_t size, uint32_t offset,
		uint32_t stride, uint32_t plane_index)
{
	struct obj_wlr_export_dmabuf_frame *frame =
			(struct obj_wlr_export_dmabuf_frame *)ctx->obj;
	if (index > frame->nobjects) {
		wp_error("Cannot add frame object with index %u >= %u", index,
				frame->nobjects);
		return;
	}
	if (frame->objects[index].buffer) {
		wp_error("Cannot add frame object with index %u, already used",
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
			.num_planes = (int32_t)frame->nobjects,
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

	if (is_dmabuf(fd) == 0) {
		size_t fdsz = 0;
		enum fdcat fdtype = get_fd_type(fd, &fdsz);
		wp_error("fd %d, #%d for wlr-export-dmabuf frame wasn't a dmabuf, instead %s",
				fd, index, fdcat_to_str(fdtype));
		return;
	}

	struct shadow_fd *sfd = translate_fd(&ctx->g->map, &ctx->g->render, fd,
			FDC_DMABUF, 0, &info, false, false);
	if (!sfd) {
		return;
	}
	if (sfd->buffer_size < size) {
		wp_error("Frame object %u has a dmabuf with less (%u) than the advertised (%u) size",
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

	struct obj_wlr_export_dmabuf_frame *frame =
			(struct obj_wlr_export_dmabuf_frame *)ctx->obj;
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
	(void)translate_fd(&context->g->map, &context->g->render, fd, FDC_PIPE,
			0, NULL, false, true);
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
void do_zwp_primary_selection_offer_v1_req_receive(
		struct context *ctx, const char *mime_type, int fd)
{
	translate_data_transfer_fd(ctx, fd);
	(void)mime_type;
}
void do_zwp_primary_selection_source_v1_evt_send(
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

void do_zwlr_gamma_control_v1_req_set_gamma(struct context *ctx, int fd)
{
	size_t fdsz = 0;
	enum fdcat fdtype = get_fd_type(fd, &fdsz);
	if (fdtype == FDC_UNKNOWN) {
		fdtype = FDC_FILE;
		/* fdsz fallback? */
	}
	// TODO: use file size from earlier in the protocol, because some
	// systems may send file-like objects not supporting fstat
	if (fdtype != FDC_FILE) {
		wp_error("gamma ramp fd %d was not file-like (type=%s)", fd,
				fdcat_to_str(fdtype));
		return;
	}
	struct shadow_fd *sfd = translate_fd(&ctx->g->map, &ctx->g->render, fd,
			FDC_FILE, fdsz, NULL, false, false);
	if (!sfd) {
		return;
	}
	/* Mark the shadow structure as owned by the protocol, but do not
	 * increase the protocol refcount, so that as soon as it gets
	 * transferred it is destroyed */
	sfd->has_owner = true;
}

const struct wp_interface *the_display_interface = &intf_wl_display;
