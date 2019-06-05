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
	const char card[] = "/dev/dri/renderD128";
	// Try 1: DRM dumb buffers
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

struct gbm_bo *import_dmabuf(struct render_data *rd, int fd, size_t *size)
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
	/* TODO: delay this invocation until we parse the protocol and are given
	 * metadata. Note: for the multiplanar buffers, this would, in the worst
	 * case, require that we block or reorder the 'add_fd' calls until
	 * someone calls create. Also, how are the multiplanar/multifd formats
	 * mapped? */
	struct gbm_import_fd_data data;
	data.fd = fd;
	data.width = 256;
	data.stride = 1024;
	data.height = (uint32_t)(endp + 1023) / 1024;
	data.format = GBM_FORMAT_XRGB8888;
	struct gbm_bo *bo = gbm_bo_import(
			rd->dev, GBM_BO_IMPORT_FD, &data, GBM_BO_USE_RENDERING);
	if (!bo) {
		wp_log(WP_ERROR, "Failed to import dmabuf to gbm bo",
				strerror(errno));
		return NULL;
	}

	return bo;
}

int read_dmabuf(int fd, void *mapptr, size_t size, void *destination)
{
	// Assuming mmap worked
	if (!mapptr) {
		wp_log(WP_ERROR, "dmabuf to read was null");
		return -1;
	}
	struct dma_buf_sync sync;
	sync.flags = DMA_BUF_SYNC_START | DMA_BUF_SYNC_READ;
	if (ioctl(fd, DMA_BUF_IOCTL_SYNC, &sync) == -1) {
		wp_log(WP_ERROR, "Failed to start sync guard on dmabuf: %s",
				strerror(errno));
	}
	memcpy(destination, mapptr, size);

	sync.flags = DMA_BUF_SYNC_END | DMA_BUF_SYNC_READ;
	if (ioctl(fd, DMA_BUF_IOCTL_SYNC, &sync) == -1) {
		wp_log(WP_ERROR, "Failed to end sync guard on dmabuf: %s",
				strerror(errno));
	}
	return 0;
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

struct gbm_bo *make_dmabuf(
		struct render_data *rd, const char *data, size_t size)
{
	uint32_t width = 512;
	uint32_t height = (uint32_t)(size + 4 * width - 1) / (4 * width);
	uint32_t format = GBM_FORMAT_XRGB8888;
	/* Set modifiers to linear, since incoming buffers also will be, thanks
	 * to the modifier restrictions set in handlers.c */
	struct gbm_bo *bo = gbm_bo_create(rd->dev, width, height, format,
			GBM_BO_USE_LINEAR | GBM_BO_USE_RENDERING);
	if (!bo) {
		wp_log(WP_ERROR, "Failed to make dmabuf: %s", strerror(errno));
		return NULL;
	}
	void *handle = NULL;
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
