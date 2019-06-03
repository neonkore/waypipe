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

#include <drm.h>
#include <xf86drm.h>
#include <xf86drmMode.h>

#ifdef HAS_LIBDRM_INTEL
#include <i915_drm.h>
#include <intel_bufmgr.h>
#endif

struct driver_api {
	void *(*setup_bufmgr)(int drm_fd);
	void (*cleanup_bufmgr)(void *bufmgr);
	void *(*create)(void *bufmgr, size_t size, const void *misc);
	void (*destroy)(void *bo);
	void *(*read_map)(void *bo, size_t size);
	int (*read_unmap)(void *bo, size_t size);
	void *(*write_map)(void *bo, size_t size);
	int (*write_unmap)(void *bo, size_t size);
	void *(*load_dmabuf)(void *bufmgr, int fd, size_t size);
	int (*export_dmabuf)(void *bo);
};

#ifdef HAS_LIBDRM_INTEL
static void *intel_setup_bufmgr(int drm_fd)
{
	drm_intel_bufmgr *bufmgr = drm_intel_bufmgr_gem_init(drm_fd, 32);
	if (!bufmgr) {
		wp_log(WP_ERROR, "Failed to init intel bufmgr");
		return NULL;
	}
	return bufmgr;
}
static void intel_cleanup_bufmgr(void *bufmgr)
{
	drm_intel_bufmgr_destroy(bufmgr);
}
static void *intel_create(void *bufmgr, size_t size, const void *data)
{
	/* with intel, tiling modes require extra space, and have
	 * additional size constraints, in a sometimes GPU
	 * generation-dependent fashion. Ultimately, the 'alloc_tiled'
	 * request sometimes depends on size and stride; the other
	 * 'alloc_*' variants lack tiling and only depend on size.
	 *
	 * While size is easy to reconstruct (llseek), and tiling can be
	 * identified, we can't so easily query the stride. Maybe it
	 * gets lost in translation to (prime) dmabuf ?
	 */
	int height = ((int)size + 1023) / 1024;

	unsigned int tilemode = I915_TILING_NONE;
	unsigned long pitch = 256 * 4;
	//  why don't we use the BO_ALLOC_FOR_RENDER hint?
	drm_intel_bo *bo = drm_intel_bo_alloc_tiled(
			bufmgr, "test", 256, height, 4, &tilemode, &pitch, 0);

	if (drm_intel_bo_map(bo, true) != 0) {
		wp_log(WP_ERROR, "Failed to map intel buffer object");
		return NULL;
	}
	size_t bufsize = (size_t)height * 256 * 4;
	memcpy(bo->virtual, data, size > bufsize ? bufsize : size);
	if (drm_intel_bo_unmap(bo) != 0) {
		wp_log(WP_ERROR, "Failed to unmap intel buffer object");
		return NULL;
	}
	return bo;
}
static void intel_destroy(void *bo) { drm_intel_bo_unreference(bo); }
static void *intel_wmap(void *bo, size_t size)
{
	(void)size;
	drm_intel_bo *ibo = (drm_intel_bo *)bo;
	if (drm_intel_bo_map(ibo, true) != 0) {
		wp_log(WP_ERROR, "Failed to wmap intel buffer object");
		return NULL;
	}
	return ibo->virtual;
}
static void *intel_rmap(void *bo, size_t size)
{
	(void)size;
	drm_intel_bo *ibo = (drm_intel_bo *)bo;
	if (drm_intel_bo_map(ibo, false) != 0) {
		wp_log(WP_ERROR, "Failed to rmap intel buffer object");
		return NULL;
	}
	return ibo->virtual;
}
static int intel_unmap(void *bo, size_t size)
{
	/* TODO: map with GTT or just regular map? */
	(void)size;
	if (drm_intel_bo_unmap(bo) != 0) {
		wp_log(WP_ERROR, "Failed to unmap intel buffer object");
		return -1;
	}
	return 0;
}
static int intel_export_dmabuf(void *bo)
{
	int dmabuf_fd = -1;
	if (drm_intel_bo_gem_export_to_prime(bo, &dmabuf_fd) != 0 ||
			dmabuf_fd == -1) {
		wp_log(WP_ERROR,
				"Failed to export intel buffer object to dmabuf");
		return -1;
	}
	return dmabuf_fd;
}
static void *intel_load_dmabuf(void *bufmgr, int fd, size_t size)
{
	drm_intel_bo *bo = drm_intel_bo_gem_create_from_prime(
			bufmgr, fd, (int)size);
	if (!bo) {
		wp_log(WP_ERROR,
				"Failed to import intel buffer object from dmabuf");
		return NULL;
	}
	uint32_t tiling_mode = (uint32_t)-1, swizzle_mode = (uint32_t)-1;
	if (drm_intel_bo_get_tiling(bo, &tiling_mode, &swizzle_mode) == -1) {
		drm_intel_bo_unreference(bo);
		wp_log(WP_ERROR, "Failed to acq tiling state");
		return NULL;
	}
	wp_log(WP_DEBUG, "Newly loaded buffer has: tiling=%x swizzle=%x",
			tiling_mode, swizzle_mode);
	return bo;
}
static const struct driver_api intel_api = {.setup_bufmgr = intel_setup_bufmgr,
		.cleanup_bufmgr = intel_cleanup_bufmgr,
		.create = intel_create,
		.destroy = intel_destroy,
		.read_map = intel_rmap,
		.read_unmap = intel_unmap,
		.write_map = intel_wmap,
		.write_unmap = intel_unmap,
		.load_dmabuf = intel_load_dmabuf,
		.export_dmabuf = intel_export_dmabuf};
#endif

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
	/* NOTE: a generic render client can only query the version,
	 * query capabilities, relate PRIME handles to (DMABUF) fds,
	 * and close GEM objects. We must therefore use driver specific
	 * code. See also the DRM_RENDER_ALLOW flag in the kernel. */
	drmVersionPtr ver = drmGetVersion(drm_fd);
	const struct driver_api *api = NULL;
#ifdef HAS_LIBDRM_INTEL
	if (!strcmp(ver->name, "i915")) {
		api = &intel_api;
	}
#endif
	if (!api) {
		close(drm_fd);
		wp_log(WP_ERROR, "waypipe doesn't have support for driver: %s",
				ver->name);
		drmFreeVersion(ver);
		data->disabled = true;
		return -1;
	}
	drmFreeVersion(ver);

	void *bufmgr = api->setup_bufmgr(drm_fd);
	if (!bufmgr) {
		close(drm_fd);
		data->disabled = true;
		return -1;
	}
	data->api = api;
	data->bufmgr = bufmgr;
	data->drm_fd = drm_fd;
	return 0;
}
void cleanup_render_data(struct render_data *data)
{
	if (data->drm_fd != -1) {
		data->api->cleanup_bufmgr(data->bufmgr);
		close(data->drm_fd);
		data->bufmgr = NULL;
		data->api = NULL;
		data->drm_fd = -1;
	}
}

void *import_dmabuf(struct render_data *rd, int fd, size_t *size)
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
	return rd->api->load_dmabuf(rd->bufmgr, fd, (size_t)endp);
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
void *make_dma_buf(struct render_data *rd, const char *data, size_t size)
{
	void *bo = rd->api->create(rd->bufmgr, size, (void *)data);
	return bo;
}
int export_dmabuf(struct render_data *rd, size_t size, void *bo)
{
	(void)size;
	return rd->api->export_dmabuf(bo);
}
void destroy_dmabuf(struct render_data *rd, void *bo) { rd->api->destroy(bo); }

void *map_dmabuf(struct render_data *rd, size_t size, void *bo, bool write)
{
	if (write) {
		return rd->api->write_map(bo, size);
	} else {
		return rd->api->read_map(bo, size);
	}
}
int unmap_dmabuf(struct render_data *rd, size_t size, void *bo, void *ptr,
		bool was_for_write)
{
	(void)ptr;
	if (was_for_write) {
		return rd->api->write_unmap(bo, size);
	} else {
		return rd->api->write_unmap(bo, size);
	}
}
