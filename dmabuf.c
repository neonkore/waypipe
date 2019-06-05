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
#include <fcntl.h>
#include <linux/dma-buf.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
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
	// todo: make this a command line option
	const char card[] = "/dev/dri/renderD128";

	int drm_fd = open(card, O_RDWR | O_CLOEXEC);
	if (drm_fd == -1) {
		wp_log(WP_ERROR, "Failed to open drm fd for %s: %s", card,
				strerror(errno));
		data->disabled = true;
		return -1;
	}

	struct gbm_device *dev = gbm_create_device(drm_fd);
	if (!dev) {
		data->disabled = true;
		close(drm_fd);
		wp_log(WP_ERROR, "Failed to create gbm device from drm_fd");
		return -1;
	}

	data->drm_fd = drm_fd;
	data->dev = dev;
	return 0;
}
void cleanup_render_data(struct render_data *data)
{
	if (data->drm_fd != -1) {
		gbm_device_destroy(data->dev);
		close(data->drm_fd);
		data->dev = NULL;
		data->drm_fd = -1;
	}
}

struct gbm_bo *import_dmabuf(struct render_data *rd, int fd, size_t *size,
		struct dmabuf_slice_data *info)
{
	ssize_t endp = lseek(fd, 0, SEEK_END);
	if (endp == -1) {
		wp_log(WP_ERROR,
				"Failed to estimate dmabuf size with lseek: %s",
				strerror(errno));
		return NULL;
	}
	if (lseek(fd, SEEK_SET, 0) == -1) {
		wp_log(WP_ERROR, "Failed to reset dmabuf offset with lseek: %s",
				strerror(errno));
		return NULL;
	}
	*size = (size_t)endp;

	/* Multiplanar formats are all rather badly supported by
	 * drivers/libgbm/libdrm/compositors/applications/everything. */
	struct gbm_import_fd_modifier_data data;
	data.num_fds = 1;
	data.fds[0] = fd;
	if (info && info->num_planes == 1) {
		// Assume only one plane contains contents? otherwise fall
		// back....
		data.modifier = info->modifier;
		int which = 0;
		for (int i = 0; i < 4; i++) {
			if (info->using_planes[i]) {
				which = i;
			}
		}
		data.strides[0] = (int)info->strides[which];
		data.offsets[0] = (int)info->offsets[which];
		data.width = info->width;
		data.height = info->height;
		data.format = info->format;
	} else {
		data.offsets[0] = 0;
		data.strides[0] = 1024;
		data.width = 256;
		data.height = (uint32_t)(endp + 1023) / 1024;
		data.format = GBM_FORMAT_XRGB8888;
		data.modifier = 0;
	}

	struct gbm_bo *bo = gbm_bo_import(rd->dev, GBM_BO_IMPORT_FD_MODIFIER,
			&data, GBM_BO_USE_RENDERING);
	if (!bo) {
		wp_log(WP_ERROR, "Failed to import dmabuf to gbm bo",
				strerror(errno));
		return NULL;
	}

	return bo;
}

bool is_dmabuf(int fd)
{
	// Prepare an invalid request, with a dma-buf specific IOCTL
	struct dma_buf_sync sync;
	sync.flags = 0;
	if (ioctl(fd, DMA_BUF_IOCTL_SYNC, &sync) != -1) {
		wp_log(WP_ERROR,
				"DMAbuf test ioctl succeeded when it should have errored");
		return false;
	}
	if (errno == EINVAL) {
		return true;
	} else if (errno == ENOTTY) {
		return false;
	} else {
		wp_log(WP_ERROR,
				"Unexpected error from dmabuf detection probe: %d, %s",
				errno, strerror(errno));
		return false;
	}
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

struct gbm_bo *make_dmabuf(struct render_data *rd, const char *data,
		size_t size, struct dmabuf_slice_data *info)
{
	struct gbm_bo *bo;
	if (!info || info->num_planes == 0) {
		uint32_t width = 512;
		uint32_t height =
				(uint32_t)(size + 4 * width - 1) / (4 * width);
		uint32_t format = GBM_FORMAT_XRGB8888;
		/* Set modifiers to linear, the most likely/portable format */
		bo = gbm_bo_create(rd->dev, width, height, format,
				GBM_BO_USE_LINEAR | GBM_BO_USE_RENDERING);
	} else {
		uint64_t modifiers[2] = {info->modifier, GBM_BO_USE_RENDERING};
		// assuming the format is a very standard one which can be
		// created by gbm_bo;
		int which = 0;
		for (int i = 0; i < (int)info->num_planes; i++) {
			if (info->using_planes[i]) {
				which = i;
			}
		}
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
		int eff_height = size / info->strides[which] + 1;
		bo = gbm_bo_create_with_modifiers(rd->dev, info->width,
				eff_height, info->format, modifiers, 2);
	}
	if (!bo) {
		wp_log(WP_ERROR, "Failed to make dmabuf: %s", strerror(errno));
		return NULL;
	}

	void *handle = NULL;
	// unfortunately, there is no easy way to estimate the writeable region
	void *dst = map_dmabuf(bo, true, &handle);
	if (!dst) {
		gbm_bo_destroy(bo);
		return NULL;
	}
	memcpy(dst, data, size);
	// no error message :-(, even though unmap ~ commit
	unmap_dmabuf(bo, handle);
	return bo;
}
int export_dmabuf(struct gbm_bo *bo)
{
	int fd = gbm_bo_get_fd(bo);
	if (fd == -1) {
		wp_log(WP_ERROR, "Failed to export dmabuf: %s",
				strerror(errno));
	}
	return fd;
}
void destroy_dmabuf(struct gbm_bo *bo)
{
	if (bo) {
		gbm_bo_destroy(bo);
	}
}

void *map_dmabuf(struct gbm_bo *bo, bool write, void **map_handle)
{
	/* With i965, the map handle MUST initially point to a NULL pointer;
	 * otherwise the handler silently exits, sometimes with misleading errno
	 * :-(
	 */
	*map_handle = NULL;
	uint32_t stride;
	uint32_t width = gbm_bo_get_width(bo);
	uint32_t height = gbm_bo_get_height(bo);
	void *data = gbm_bo_map(bo, 0, 0, width, height,
			write ? GBM_BO_TRANSFER_WRITE : GBM_BO_TRANSFER_READ,
			&stride, map_handle);
	if (!data) {
		// errno is useless here
		wp_log(WP_ERROR, "Failed to map dmabuf");
	}
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
	for (int i = 0; plane_table[i].format; i++) {
		if (plane_table[i].format == format) {
			int cpp = plane_table[i].planes[plane].cpp;
			const uint32_t by_cpp[] = {0, GBM_FORMAT_R8,
					GBM_FORMAT_GR88, GBM_FORMAT_RGB888,
					GBM_BO_FORMAT_ARGB8888};
			return by_cpp[cpp];
		}
	}
	return format;
}
