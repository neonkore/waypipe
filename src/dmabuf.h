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
#ifndef WAYPIPE_DMABUF_H
#define WAYPIPE_DMABUF_H

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef void *VADisplay;
typedef unsigned int VAGenericID;
typedef VAGenericID VAConfigID;
struct render_data {
	bool disabled;
	int drm_fd;
	const char *drm_node_path;
	struct gbm_device *dev;
	bool supports_modifiers;
	/* video hardware context */
	bool av_disabled;
	int av_bpf;
	int av_video_fmt;
	struct AVBufferRef *av_hwdevice_ref;
	struct AVBufferRef *av_drmdevice_ref;
	VADisplay av_vadisplay;
	VAConfigID av_copy_config;
};

/** Additional information to help serialize a dmabuf */
struct dmabuf_slice_data {
	/* This information partially duplicates that of a gbm_bo. However, for
	 * instance with weston, it is possible for the compositor to handle
	 * multibuffer multiplanar images, even though a driver may only support
	 * multiplanar images derived from a single underlying dmabuf. */
	uint32_t width;
	uint32_t height;
	uint32_t format;
	int32_t num_planes;
	uint32_t offsets[4];
	uint32_t strides[4];
	uint64_t modifier;
	// to which planes is the matching dmabuf assigned?
	uint8_t using_planes[4];
	char pad[4];
};
static_assert(sizeof(struct dmabuf_slice_data) == 64, "size check");

int init_render_data(struct render_data *);
void cleanup_render_data(struct render_data *);
struct gbm_bo *make_dmabuf(
		struct render_data *rd, const struct dmabuf_slice_data *info);
int export_dmabuf(struct gbm_bo *bo);
/** Import DMABUF to a GBM buffer object. */
struct gbm_bo *import_dmabuf(struct render_data *rd, int fd, size_t *size,
		const struct dmabuf_slice_data *info);
void destroy_dmabuf(struct gbm_bo *bo);
/** Map a DMABUF for reading or for writing */
void *map_dmabuf(struct gbm_bo *bo, bool write, void **map_handle,
		uint32_t *exp_stride);
int unmap_dmabuf(struct gbm_bo *bo, void *map_handle);
/** The handle values are unique among the set of currently active buffer
 * objects. To compare a set of buffer objects, produce handles in a batch, and
 * then free the temporary buffer objects in a batch */
int get_unique_dmabuf_handle(
		struct render_data *rd, int fd, struct gbm_bo **temporary_bo);
uint32_t dmabuf_get_simple_format_for_plane(uint32_t format, int plane);
uint32_t dmabuf_get_stride(struct gbm_bo *bo);

/** Returns the number of bytes per pixel for WL or DRM format 'format', if the
 * format is an RGBA-type single plane format. For YUV-type or planar formats,
 * returns -1. */
int get_shm_bytes_per_pixel(uint32_t format);

#ifndef DRM_FORMAT_MOD_INVALID
#define DRM_FORMAT_MOD_INVALID 0x00ffffffffffffffULL
#endif

#endif // WAYPIPE_DMABUF_H
