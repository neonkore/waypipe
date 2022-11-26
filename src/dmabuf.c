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

#include "dmabuf.h"
#include "util.h"

#ifndef HAS_DMABUF

int init_render_data(struct render_data *data)
{
	data->disabled = true;
	(void)data;
	return -1;
}
void cleanup_render_data(struct render_data *data) { (void)data; }
struct gbm_bo *import_dmabuf(struct render_data *rd, int fd, size_t *size,
		const struct dmabuf_slice_data *info)
{
	(void)rd;
	(void)fd;
	(void)size;
	(void)info;
	return NULL;
}
int get_unique_dmabuf_handle(
		struct render_data *rd, int fd, struct gbm_bo **temporary_bo)
{
	(void)rd;
	(void)fd;
	(void)temporary_bo;
	return -1;
}
struct gbm_bo *make_dmabuf(
		struct render_data *rd, const struct dmabuf_slice_data *info)
{
	(void)rd;
	(void)info;
	return NULL;
}
int export_dmabuf(struct gbm_bo *bo)
{
	(void)bo;
	return -1;
}
void destroy_dmabuf(struct gbm_bo *bo) { (void)bo; }
void *map_dmabuf(struct gbm_bo *bo, bool write, void **map_handle,
		uint32_t *exp_stride)
{
	(void)bo;
	(void)write;
	(void)map_handle;
	(void)exp_stride;
	return NULL;
}
int unmap_dmabuf(struct gbm_bo *bo, void *map_handle)
{
	(void)bo;
	(void)map_handle;
	return 0;
}

uint32_t dmabuf_get_simple_format_for_plane(uint32_t format, int plane)
{
	(void)format;
	(void)plane;
	return 0;
}

uint32_t dmabuf_get_stride(struct gbm_bo *bo)
{
	(void)bo;
	return 0;
}
#else /* HAS_DMABUF */

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <gbm.h>

int init_render_data(struct render_data *data)
{
	/* render node support can be disabled either by choice
	 * or when a previous version fails */
	if (data->disabled) {
		return -1;
	}

	if (data->drm_fd != -1) {
		// Silent return, idempotent
		return 0;
	}
	const char *card = data->drm_node_path ? data->drm_node_path
					       : "/dev/dri/renderD128";

	int drm_fd = open(card, O_RDWR | O_CLOEXEC | O_NOCTTY);
	if (drm_fd == -1) {
		wp_error("Failed to open drm fd for %s: %s", card,
				strerror(errno));
		data->disabled = true;
		return -1;
	}

	struct gbm_device *dev = gbm_create_device(drm_fd);
	if (!dev) {
		data->disabled = true;
		checked_close(drm_fd);
		wp_error("Failed to create gbm device from drm_fd");
		return -1;
	}

	data->drm_fd = drm_fd;
	data->dev = dev;
	/* Set the path to the card used for protocol handlers to see */
	data->drm_node_path = card;
	/* Assume true initially, fall back to old buffer creation path
	 * if the newer path errors out */
	data->supports_modifiers = true;
	return 0;
}
void cleanup_render_data(struct render_data *data)
{
	if (data->drm_fd != -1) {
		gbm_device_destroy(data->dev);
		checked_close(data->drm_fd);
		data->dev = NULL;
		data->drm_fd = -1;
	}
}

static bool dmabuf_info_valid(const struct dmabuf_slice_data *info)
{
	if (info->height > (1u << 24) || info->width > (1u << 24) ||
			info->num_planes > 4 || info->num_planes == 0) {
		wp_error("Invalid DMABUF slice data: height " PRIu32
			 " width " PRIu32 " num_planes " PRIu32,
				info->height, info->width, info->num_planes);
		return false;
	}
	return true;
}

struct gbm_bo *import_dmabuf(struct render_data *rd, int fd, size_t *size,
		const struct dmabuf_slice_data *info)
{
	struct gbm_bo *bo;
	if (!dmabuf_info_valid(info)) {
		return NULL;
	}

	/* Multiplanar formats are all rather badly supported by
	 * drivers/libgbm/libdrm/compositors/applications/everything. */
	struct gbm_import_fd_modifier_data data;
	// Select all plane metadata associated to planes linked
	// to this fd
	data.modifier = info->modifier;
	data.num_fds = 0;
	uint32_t simple_format = 0;

	for (int i = 0; i < info->num_planes; i++) {
		if (info->using_planes[i]) {
			data.fds[data.num_fds] = fd;
			data.strides[data.num_fds] = (int)info->strides[i];
			data.offsets[data.num_fds] = (int)info->offsets[i];
			data.num_fds++;
			if (!simple_format) {
				simple_format = dmabuf_get_simple_format_for_plane(
						info->format, i);
			}
		}
	}
	if (!simple_format) {
		simple_format = info->format;
	}
	data.width = info->width;
	data.height = info->height;
	data.format = simple_format;
	bo = gbm_bo_import(rd->dev, GBM_BO_IMPORT_FD_MODIFIER, &data,
			GBM_BO_USE_RENDERING);
	if (!bo) {
		wp_error("Failed to import dmabuf (format %x, modifier %" PRIx64
			 ") to gbm bo: %s",
				info->format, info->modifier, strerror(errno));
		return NULL;
	}

	/* todo: find out how to correctly map multiplanar formats */
	*size = gbm_bo_get_stride(bo) * gbm_bo_get_height(bo);

	return bo;
}

int get_unique_dmabuf_handle(
		struct render_data *rd, int fd, struct gbm_bo **temporary_bo)
{
	struct gbm_import_fd_data data;
	data.fd = fd;
	data.width = 1;
	data.stride = 1;
	data.height = 1;
	data.format = GBM_FORMAT_R8;
	*temporary_bo = gbm_bo_import(
			rd->dev, GBM_BO_IMPORT_FD, &data, GBM_BO_USE_RENDERING);
	if (!*temporary_bo) {
		return -1;
	}
	// This effectively reduces to DRM_IOCTL_PRIME_FD_TO_HANDLE. Is the
	// runtime dependency worth it?
	int handle = gbm_bo_get_handle(*temporary_bo).s32;
	return handle;
}

struct gbm_bo *make_dmabuf(
		struct render_data *rd, const struct dmabuf_slice_data *info)
{
	struct gbm_bo *bo;
	if (!dmabuf_info_valid(info)) {
		return NULL;
	}

retry:
	if (!rd->supports_modifiers ||
			info->modifier == DRM_FORMAT_MOD_INVALID) {
		uint32_t simple_format = dmabuf_get_simple_format_for_plane(
				info->format, 0);
		/* If the modifier is nonzero, assume that the backend
		 * preferred modifier matches it. With this old API, there
		 * really isn't any way to do this better */
		bo = gbm_bo_create(rd->dev, info->width, info->height,
				simple_format,
				GBM_BO_USE_RENDERING |
						(info->modifier ? 0
								: GBM_BO_USE_LINEAR));
		if (!bo) {
			wp_error("Failed to make dmabuf (old path): %s",
					strerror(errno));
			return NULL;
		}
		uint64_t mod = gbm_bo_get_modifier(bo);
		if (info->modifier != DRM_FORMAT_MOD_INVALID &&
				mod != DRM_FORMAT_MOD_INVALID &&
				mod != info->modifier) {
			wp_error("DMABUF with format %08x, autoselected modifier %" PRIx64
				 " does not match desired %" PRIx64
				 ", expect a crash",
					simple_format, mod, info->modifier);
		}
	} else {
		uint64_t modifiers[2] = {info->modifier, GBM_BO_USE_RENDERING};
		uint32_t simple_format = dmabuf_get_simple_format_for_plane(
				info->format, 0);

		/* Whether just size and modifiers suffice to replicate
		 * a surface is driver dependent, and requires actual testing
		 * with the hardware.
		 *
		 * i915 DRM ioctls cover size, swizzling, tiling state, only.
		 * amdgpu, size + allocation domain/caching/align flags
		 * etnaviv, size + caching flags
		 * tegra, vc4: size + tiling + flags
		 * radeon: size + tiling + flags, including pitch
		 *
		 * Note that gbm doesn't have a specific api for creating
		 * buffers with minimal information, or even just getting
		 * the size of the buffer contents.
		 */
		bo = gbm_bo_create_with_modifiers(rd->dev, info->width,
				info->height, simple_format, modifiers, 2);
		if (!bo && errno == ENOSYS) {
			wp_debug("Creating a DMABUF with modifiers explicitly set is not supported; retrying");
			rd->supports_modifiers = false;
			goto retry;
		}
		if (!bo) {
			wp_error("Failed to make dmabuf (with format %x, modifier %" PRIx64
				 "): %s",
					simple_format, info->modifier,
					strerror(errno));
			return NULL;
		}
	}
	return bo;
}
int export_dmabuf(struct gbm_bo *bo)
{
	int fd = gbm_bo_get_fd(bo);
	if (fd == -1) {
		wp_error("Failed to export dmabuf: %s", strerror(errno));
	}
	return fd;
}
void destroy_dmabuf(struct gbm_bo *bo)
{
	if (bo) {
		gbm_bo_destroy(bo);
	}
}

void *map_dmabuf(struct gbm_bo *bo, bool write, void **map_handle,
		uint32_t *exp_stride)
{
	if (!bo) {
		wp_error("Tried to map null gbm_bo");
		return NULL;
	}

	/* With i965, the map handle MUST initially point to a NULL pointer;
	 * otherwise the handler silently exits, sometimes with misleading errno
	 * :-(
	 */
	*map_handle = NULL;
	uint32_t stride;
	uint32_t width = gbm_bo_get_width(bo);
	uint32_t height = gbm_bo_get_height(bo);
	/* As of writing, with amdgpu, GBM_BO_TRANSFER_WRITE invalidates
	 * regions not written to during the mapping, while iris preserves
	 * the original buffer contents. GBM documentation does not say which
	 * WRITE behavior is correct. What the individual drivers do may change
	 * in the future. Specifying READ_WRITE preserves the old contents with
	 * both drivers. */
	uint32_t flags = write ? GBM_BO_TRANSFER_READ_WRITE
			       : GBM_BO_TRANSFER_READ;
	void *data = gbm_bo_map(
			bo, 0, 0, width, height, flags, &stride, map_handle);
	if (!data) {
		// errno is useless here
		wp_error("Failed to map dmabuf");
		return NULL;
	}
	*exp_stride = stride;
	return data;
}
int unmap_dmabuf(struct gbm_bo *bo, void *map_handle)
{
	gbm_bo_unmap(bo, map_handle);
	return 0;
}

// TODO: support DRM formats, like DRM_FORMAT_RGB888_A8 and
// DRM_FORMAT_ARGB16161616F, defined in drm_fourcc.h.
struct multiplanar_info {
	uint32_t format;
	struct {
		int subsample_w;
		int subsample_h;
		int cpp;
	} planes[3];
};
static const struct multiplanar_info plane_table[] = {
		{GBM_FORMAT_NV12, {{1, 1, 1}, {2, 2, 2}}},
		{GBM_FORMAT_NV21, {{1, 1, 1}, {2, 2, 2}}},
		{GBM_FORMAT_NV16, {{1, 1, 1}, {2, 1, 2}}},
		{GBM_FORMAT_NV61, {{1, 1, 1}, {2, 1, 2}}},
		{GBM_FORMAT_YUV410, {{1, 1, 1}, {4, 4, 1}, {4, 4, 1}}},
		{GBM_FORMAT_YVU410, {{1, 1, 1}, {4, 4, 1}, {4, 4, 1}}},
		{GBM_FORMAT_YUV411, {{1, 1, 1}, {4, 1, 1}, {4, 1, 1}}},
		{GBM_FORMAT_YVU411, {{1, 1, 1}, {4, 1, 1}, {4, 1, 1}}},
		{GBM_FORMAT_YUV420, {{1, 1, 1}, {2, 2, 1}, {2, 2, 1}}},
		{GBM_FORMAT_YVU420, {{1, 1, 1}, {2, 2, 1}, {2, 2, 1}}},
		{GBM_FORMAT_YUV422, {{1, 1, 1}, {2, 1, 1}, {2, 1, 1}}},
		{GBM_FORMAT_YVU422, {{1, 1, 1}, {2, 1, 1}, {2, 1, 1}}},
		{GBM_FORMAT_YUV444, {{1, 1, 1}, {1, 1, 1}, {1, 1, 1}}},
		{GBM_FORMAT_YVU444, {{1, 1, 1}, {1, 1, 1}, {1, 1, 1}}}, {0}};

uint32_t dmabuf_get_simple_format_for_plane(uint32_t format, int plane)
{
	const uint32_t by_cpp[] = {0, GBM_FORMAT_R8, GBM_FORMAT_GR88,
			GBM_FORMAT_RGB888, GBM_BO_FORMAT_ARGB8888};
	for (int i = 0; plane_table[i].format; i++) {
		if (plane_table[i].format == format) {
			int cpp = plane_table[i].planes[plane].cpp;
			return by_cpp[cpp];
		}
	}
	if (format == GBM_FORMAT_YUYV || format == GBM_FORMAT_YVYU ||
			format == GBM_FORMAT_UYVY ||
			format == GBM_FORMAT_VYUY ||
			format == GBM_FORMAT_AYUV) {
		return by_cpp[4];
	}
	return format;
}
uint32_t dmabuf_get_stride(struct gbm_bo *bo) { return gbm_bo_get_stride(bo); }

#endif /* HAS_DMABUF */
