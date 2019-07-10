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

#if !defined(HAS_VIDEO) || !defined(HAS_DMABUF)

void setup_video_logging() {}
bool video_supports_dmabuf_format(uint32_t format, uint64_t modifier)
{
	(void)format;
	(void)modifier;
	return false;
}
bool video_supports_shm_format(uint32_t format)
{
	(void)format;
	return false;
}
void pad_video_mirror_size(int width, int height, int stride, int *new_width,
		int *new_height, int *new_min_size)
{
	(void)width;
	(void)height;
	(void)stride;
	(void)new_width;
	(void)new_height;
	(void)new_min_size;
}
void destroy_video_data(struct shadow_fd *sfd) { (void)sfd; }
void setup_video_encode(struct shadow_fd *sfd) { (void)sfd; }
void setup_video_decode(struct shadow_fd *sfd) { (void)sfd; }
void collect_video_from_mirror(struct shadow_fd *sfd,
		struct transfer_stack *transfers, struct bytebuf_stack *blocks,
		bool first)
{
	(void)sfd;
	(void)transfers;
	(void)blocks;
	(void)first;
}
void apply_video_packet(struct shadow_fd *sfd, size_t size, const char *data)
{
	(void)sfd;
	(void)size;
	(void)data;
}

#else /* HAS_VIDEO */

#include <libavcodec/avcodec.h>
#include <libavutil/display.h>
#include <libavutil/hwcontext_drm.h>
#include <libavutil/imgutils.h>
#include <libavutil/log.h>
#include <libavutil/opt.h>
#include <libavutil/pixdesc.h>
#include <libswscale/swscale.h>
#include <unistd.h>

/* these are equivalent to the GBM formats */
#include <libdrm/drm_fourcc.h>

#define VIDEO_HW_ENCODER "h264_vaapi"
#define VIDEO_SW_ENCODER "libx264"
#define VIDEO_DECODER "h264"

static enum AVPixelFormat drm_to_av(uint32_t format)
{
	/* The avpixel formats are specified with reversed endianness relative
	 * to DRM formats */
	switch (format) {
	case DRM_FORMAT_C8:
		/* indexed */
		return AV_PIX_FMT_NONE;

	case DRM_FORMAT_R8:
		return AV_PIX_FMT_GRAY8;

	case DRM_FORMAT_RGB565:
		return AV_PIX_FMT_RGB565LE;

	/* there really isn't a matching format, because no fast video
	 * codec supports alpha. Expect unusual error patterns */
	case DRM_FORMAT_GR88:
		return AV_PIX_FMT_YUYV422;

	case DRM_FORMAT_RGB888:
		return AV_PIX_FMT_BGR24;
	case DRM_FORMAT_BGR888:
		return AV_PIX_FMT_RGB24;

	case DRM_FORMAT_XRGB8888:
		return AV_PIX_FMT_BGR0;
	case DRM_FORMAT_XBGR8888:
		return AV_PIX_FMT_RGB0;
	case DRM_FORMAT_RGBX8888:
		return AV_PIX_FMT_0BGR;
	case DRM_FORMAT_BGRX8888:
		return AV_PIX_FMT_0RGB;

	/* there do not appear to be equivalents for these 10-bit formats */
	case DRM_FORMAT_XRGB2101010:
	case DRM_FORMAT_XBGR2101010:
		return AV_PIX_FMT_NONE;

	default:
		return AV_PIX_FMT_NONE;
	}
}

static enum AVPixelFormat shm_to_av(uint32_t format)
{
	if (format == 0) {
		return AV_PIX_FMT_BGR0;
	}
	return drm_to_av(format);
}

bool video_supports_dmabuf_format(uint32_t format, uint64_t modifier)
{
	if (modifier == DRM_FORMAT_MOD_LINEAR &&
			drm_to_av(format) != AV_PIX_FMT_NONE) {
		return true;
	}
	return false;
}
bool video_supports_shm_format(uint32_t format)
{
	if (format == 0) {
		return true;
	}
	return video_supports_dmabuf_format(format, 0);
}

static void video_log_callback(
		void *aux, int level, const char *fmt, va_list args)
{
	(void)aux;
	enum log_level wp_level =
			(level <= AV_LOG_WARNING) ? WP_ERROR : WP_DEBUG;
	log_handler_func_t fn = log_funcs[wp_level];
	if (!fn) {
		return;
	}
	char buf[1024];
	int len = vsnprintf(buf, 1023, fmt, args);
	while (buf[len - 1] == '\n' && len > 1) {
		buf[len - 1] = 0;
		len--;
	}
	(*fn)("ffmpeg", 0, wp_level, "%s", buf);
}

void setup_video_logging()
{
	if (log_funcs[WP_DEBUG]) {
		av_log_set_level(AV_LOG_VERBOSE);
	} else {
		av_log_set_level(AV_LOG_WARNING);
	}
	av_log_set_callback(video_log_callback);
}

void destroy_video_data(struct shadow_fd *sfd)
{
	if (sfd->video_context) {
		/* free contexts (which, theoretically, could have hooks into
		 * frames/packets) first */
		avcodec_free_context(&sfd->video_context);
		sws_freeContext(sfd->video_color_context);
		if (sfd->video_yuv_frame_data) {
			av_freep(sfd->video_yuv_frame_data);
		}
		av_frame_free(&sfd->video_local_frame);
		av_frame_free(&sfd->video_yuv_frame);
		av_packet_free(&sfd->video_packet);
	}
}

/* see AVFrame::video documentation; needed due to overreads with SIMD  */
#define VIDEO_MIRROR_EXTRA_BYTES 16

void pad_video_mirror_size(int width, int height, int stride, int *new_width,
		int *new_height, int *new_min_size)
{
	/* Encoding video with YUV420P is significantly faster than encoding
	 * video with the YUV444P format. However, when using YUV420P, x264
	 * imposes an additional condition, that the image width and height
	 * be divisible by 2, so that there are no UV entries covering less than
	 * a 2x2 field. Furthermore, if the image sizes for sws_scale disagree,
	 * then the function becomes significantly more expensive.
	 *
	 * A solution that avoids this scaling is to pretend that the user
	 * buffers actually have slightly larger sizes, which are correctly
	 * aligned. This will produce border artifacts when the left/right
	 * sides of an image disagree, but the video encoding wasn't meant to
	 * be efficient anyway.
	 *
	 * Hopefully libswscale doesn't add sanity checks for stride vs.
	 *width...
	 **/
	int m = 2;
	int nwidth = align(width, m);
	int nheight = align(height, m);
	if (new_width) {
		*new_width = nwidth;
	}
	if (new_height) {
		*new_height = nheight;
	}
	if (new_min_size) {
		/* the extra +8 * (m - 1) are because the width may have
		 * increased by up to (m-1), making libswscale overread each
		 * line. */
		*new_min_size = nheight * stride + VIDEO_MIRROR_EXTRA_BYTES +
				8 * (m - 1);
	}
}

int init_hwcontext(struct render_data *rd)
{
	if (rd->av_disabled) {
		return -1;
	}
	if (rd->av_hwdevice_ref != NULL) {
		return 0;
	}
	if (init_render_data(rd) == -1) {
		rd->av_disabled = true;
		return -1;
	}

	// Q: what does this even do?
	rd->av_drmdevice_ref = av_hwdevice_ctx_alloc(AV_HWDEVICE_TYPE_DRM);
	if (!rd->av_drmdevice_ref) {
		wp_error("Failed to allocate AV DRM device context");
		rd->av_disabled = true;
		return -1;
	}
	AVHWDeviceContext *hwdc =
			(AVHWDeviceContext *)rd->av_drmdevice_ref->data;
	AVDRMDeviceContext *dctx = hwdc->hwctx;
	dctx->fd = rd->drm_fd;
	if (av_hwdevice_ctx_init(rd->av_drmdevice_ref)) {
		wp_error("Failed to initialize AV DRM device context");
	}

	/* We create a derived context here, to ensure that the drm fd matches
	 * that which was used to create the DMABUFs. Also, this ensures that
	 * the VA implementation doesn't look for a connection via e.g. Wayland
	 * or X11 */
	if (av_hwdevice_ctx_create_derived(&rd->av_hwdevice_ref,
			    AV_HWDEVICE_TYPE_VAAPI, rd->av_drmdevice_ref,
			    0) < 0) {
		wp_error("Failed to create VAAPI hardware device");
	}

	return 0;
}

void cleanup_hwcontext(struct render_data *rd)
{
	rd->av_disabled = true;
	if (rd->av_hwdevice_ref) {
		av_buffer_unref(&rd->av_hwdevice_ref);
	}
	if (rd->av_drmdevice_ref) {
		av_buffer_unref(&rd->av_drmdevice_ref);
	}
}

static void configure_low_latency_enc_context(
		struct AVCodecContext *ctx, bool sw)
{
	// "time" is only meaningful in terms of the frames
	// provided
	ctx->time_base = (AVRational){1, 25};
	ctx->framerate = (AVRational){25, 1};

	/* B-frames are directly tied to latency, since each one
	 * is predicted using its preceding and following
	 * frames. The gop size is chosen by the driver. */
	ctx->gop_size = -1;
	ctx->max_b_frames = 0; // Q: how to get this to zero?
	// low latency
	ctx->delay = 0;
	ctx->thread_count = 1;

	if (sw) {
		ctx->bit_rate = 3000000;
		if (av_opt_set(ctx->priv_data, "preset", "ultrafast", 0) != 0) {
			wp_error("Failed to set x264 encode ultrafast preset");
		}
		if (av_opt_set(ctx->priv_data, "tune", "zerolatency", 0) != 0) {
			wp_error("Failed to set x264 encode zerolatency");
		}
	} else {
		/* with i965/gen8, hardware encoding is faster but has
		 * significantly worse quality per bitrate than x264 */
		ctx->bit_rate = 9000000;
		if (av_opt_set(ctx->priv_data, "quality", "7", 0) != 0) {
			wp_error("Failed to set h264 encode quality");
		}
		if (av_opt_set(ctx->priv_data, "profile", "main", 0) != 0) {
			wp_error("Failed to set h264 encode main profile");
		}
	}
}

static int setup_hwvideo_encode(struct shadow_fd *sfd, struct render_data *rd)
{
	int nplanes = av_pix_fmt_count_planes(
			drm_to_av(sfd->dmabuf_info.format));
	if (nplanes != 1) {
		wp_error("Equivalent AV format %s has too many (%d) planes",
				av_get_pix_fmt_name(drm_to_av(
						sfd->dmabuf_info.format)),
				nplanes);
		return -1;
	}

	/* NV12 is the preferred format for Intel VAAPI; see also
	 * intel-vaapi-driver/src/i965_drv_video.c . Packed formats like
	 * YUV420P typically don't work. */
	const enum AVPixelFormat videofmt = AV_PIX_FMT_NV12;
	struct AVCodec *codec = avcodec_find_encoder_by_name(VIDEO_HW_ENCODER);
	if (!codec) {
		wp_error("Failed to find encoder \"" VIDEO_HW_ENCODER "\"");
		return -1;
	}
	struct AVCodecContext *ctx = avcodec_alloc_context3(codec);
	configure_low_latency_enc_context(ctx, false);
	/* see i965_drv_video.c, i965_suface_external_memory() [sic] ; to
	 * map a frame, its dimensions must already be aligned. Tiling modes
	 * have even stronger alignment restrictions */
	ctx->width = sfd->dmabuf_info.width - sfd->dmabuf_info.width % 16;
	ctx->height = sfd->dmabuf_info.height - sfd->dmabuf_info.height % 16;

	AVHWFramesConstraints *constraints =
			av_hwdevice_get_hwframe_constraints(
					rd->av_hwdevice_ref, NULL);
	if (!constraints) {
		wp_error("Failed to get hardware frame constraints");
		goto fail_hwframe_constraints;
	}
	enum AVPixelFormat hw_format = constraints->valid_hw_formats[0];
	av_hwframe_constraints_free(&constraints);

	AVBufferRef *frame_ref = av_hwframe_ctx_alloc(rd->av_hwdevice_ref);
	if (!frame_ref) {
		wp_error("Failed to allocate frame reference");
		goto fail_frameref;
	}

	AVHWFramesContext *fctx = (AVHWFramesContext *)frame_ref->data;
	/* hw fmt is e.g. "vaapi_vld" */
	fctx->format = hw_format;
	fctx->sw_format = videofmt;
	fctx->width = ctx->width;
	fctx->height = ctx->height;

	int err = av_hwframe_ctx_init(frame_ref);
	if (err < 0) {
		wp_error("Failed to init hardware frame context, %s",
				av_err2str(err));
		goto fail_hwframe_init;
	}

	ctx->pix_fmt = hw_format;
	ctx->hw_frames_ctx = av_buffer_ref(frame_ref);
	if (!ctx->hw_frames_ctx) {
		wp_error("Failed to reference hardware frame context for codec context");
		goto fail_ctx_hwfctx;
	}

	int open_err = avcodec_open2(ctx, codec, NULL);
	if (open_err < 0) {
		wp_error("Failed to open codec: %s", av_err2str(open_err));
		goto fail_codec_open;
	}

	/* Create a VAAPI frame linked to the sfd DMABUF */
	struct AVDRMFrameDescriptor *framedesc =
			av_mallocz(sizeof(struct AVDRMFrameDescriptor));
	if (!framedesc) {
		wp_error("Failed to allocate DRM frame descriptor");
		goto fail_framedesc_alloc;
	}
	/* todo: multiplanar support */
	framedesc->nb_objects = 1;
	framedesc->objects[0].format_modifier = sfd->dmabuf_info.modifier;
	framedesc->objects[0].fd = dup(sfd->fd_local);
	framedesc->objects[0].size = sfd->buffer_size;
	framedesc->nb_layers = 1;
	framedesc->layers[0].format = sfd->dmabuf_info.format;
	framedesc->layers[0].planes[0].object_index = 0;
	framedesc->layers[0].planes[0].offset = sfd->dmabuf_info.offsets[0];
	framedesc->layers[0].planes[0].pitch = sfd->dmabuf_info.strides[0];
	framedesc->layers[0].nb_planes = av_pix_fmt_count_planes(
			drm_to_av(sfd->dmabuf_info.format));

	AVFrame *local_frame = av_frame_alloc();
	if (!local_frame) {
		wp_error("Failed to allocate local frame");
		goto fail_frame_alloc;
	}
	local_frame->width = ctx->width;
	local_frame->height = ctx->height;
	local_frame->format = AV_PIX_FMT_DRM_PRIME;
	local_frame->buf[0] = av_buffer_create((uint8_t *)framedesc,
			sizeof(struct AVDRMFrameDescriptor),
			av_buffer_default_free, local_frame, 0);
	if (!local_frame->buf[0]) {
		wp_error("Failed to reference count frame DRM description");
		goto fail_framedesc_ref;
	}
	local_frame->data[0] = (uint8_t *)framedesc;
	local_frame->hw_frames_ctx = av_buffer_ref(frame_ref);
	if (!local_frame->hw_frames_ctx) {
		wp_error("Failed to reference hardware frame context for local frame");
		goto fail_frame_hwfctx;
	}

	AVFrame *yuv_frame = av_frame_alloc();
	if (!yuv_frame) {
		wp_error("Failed to allocate yuv frame");
		goto fail_yuv_frame;
	}
	yuv_frame->format = hw_format;
	yuv_frame->hw_frames_ctx = av_buffer_ref(frame_ref);
	if (!yuv_frame->hw_frames_ctx) {
		wp_error("Failed to reference hardware frame context for yuv frame");
		goto fail_yuv_hwfctx;
	}

	int map_err = av_hwframe_map(yuv_frame, local_frame, 0);
	if (map_err) {
		wp_error("Failed to map (DRM) local frame to (hardware) yuv frame: %s",
				av_err2str(map_err));
		goto fail_map;
	}

	struct AVPacket *pkt = av_packet_alloc();
	if (!pkt) {
		wp_error("Failed to allocate av packet");
		goto fail_pkt_alloc;
	}

	av_buffer_unref(&frame_ref);

	sfd->video_context = ctx;
	sfd->video_local_frame = local_frame;
	sfd->video_yuv_frame = yuv_frame;
	sfd->video_packet = pkt;
	return 0;

fail_pkt_alloc:
fail_map:
fail_yuv_hwfctx:
	av_frame_free(&yuv_frame);
fail_yuv_frame:
fail_framedesc_ref:
fail_frame_hwfctx:
	av_frame_free(&local_frame);
fail_frame_alloc:
fail_framedesc_alloc:
fail_codec_open:
fail_ctx_hwfctx:
fail_hwframe_init:
	av_buffer_unref(&frame_ref);
fail_frameref:
fail_hwframe_constraints:
	avcodec_free_context(&ctx);

	return -1;
}

void setup_video_encode(struct shadow_fd *sfd, struct render_data *rd)
{
	bool has_hw = init_hwcontext(rd) == 0;
	/* Attempt hardware encoding, and if it doesn't succeed, fall back
	 * to software encoding */
	if (has_hw && setup_hwvideo_encode(sfd, rd) == 0) {
		return;
	}

	enum AVPixelFormat avpixfmt = shm_to_av(sfd->dmabuf_info.format);
	if (avpixfmt == AV_PIX_FMT_NONE) {
		wp_error("Failed to find matching AvPixelFormat	for %x",
				sfd->dmabuf_info.format);
		return;
	}
	enum AVPixelFormat videofmt = AV_PIX_FMT_YUV420P;
	if (sws_isSupportedInput(avpixfmt) == 0) {
		wp_error("frame format %s not supported",
				av_get_pix_fmt_name(avpixfmt));
		return;
	}
	if (sws_isSupportedInput(videofmt) == 0) {
		wp_error("videofmt %s not supported",
				av_get_pix_fmt_name(videofmt));
		return;
	}

	// Try to set up a video encoding and a video decoding
	// stream with AVCodec, although transmissions in each
	// direction are relatively independent. TODO: use
	// hardware support only if available.

	/* note: "libx264rgb" should, if compiled in, support RGB directly */
	struct AVCodec *codec = avcodec_find_encoder_by_name(VIDEO_SW_ENCODER);
	if (!codec) {
		wp_error("Failed to find encoder for h264");
		return;
	}

	struct AVCodecContext *ctx = avcodec_alloc_context3(codec);

	struct AVPacket *pkt = av_packet_alloc();

	pad_video_mirror_size(sfd->dmabuf_info.width, sfd->dmabuf_info.height,
			sfd->dmabuf_info.strides[0], &ctx->width, &ctx->height,
			NULL);
	ctx->pix_fmt = videofmt;
	configure_low_latency_enc_context(ctx, true);

	bool near_perfect = false;
	if (near_perfect && av_opt_set(ctx->priv_data, "crf", "0", 0) != 0) {
		wp_error("Failed to set x264 crf");
	}

	// option: crf = 0

	if (avcodec_open2(ctx, codec, NULL) < 0) {
		wp_error("Failed to open codec");
		return;
	}

	struct AVFrame *frame = av_frame_alloc();
	if (!frame) {
		wp_error("Could not allocate video frame");
		return;
	}
	frame->format = avpixfmt;
	/* adopt padded sizes */
	frame->width = ctx->width;
	frame->height = ctx->height;
	frame->linesize[0] = sfd->dmabuf_info.strides[0];

	struct AVFrame *yuv_frame = av_frame_alloc();
	yuv_frame->width = ctx->width;
	yuv_frame->height = ctx->height;
	yuv_frame->format = videofmt;
	if (av_image_alloc(yuv_frame->data, yuv_frame->linesize,
			    yuv_frame->width, yuv_frame->height, videofmt,
			    64) < 0) {
		wp_error("Failed to allocate temp image");
		return;
	}
	struct SwsContext *sws = sws_getContext(frame->width, frame->height,
			avpixfmt, yuv_frame->width, yuv_frame->height, videofmt,
			SWS_BILINEAR, NULL, NULL, NULL);
	if (!sws) {
		wp_error("Could not create software color conversion context");
		return;
	}

	sfd->video_yuv_frame = yuv_frame;
	/* recorded pointer to be freed to match av_image_alloc */
	sfd->video_yuv_frame_data = &yuv_frame->data[0];
	sfd->video_local_frame = frame;
	sfd->video_packet = pkt;
	sfd->video_context = ctx;
	sfd->video_color_context = sws;
}

void setup_video_decode(struct shadow_fd *sfd, struct render_data *rd)
{
	bool has_hw = init_hwcontext(rd) == 0;
	(void)has_hw;

	uint32_t drm_format = sfd->dmabuf_info.format;
	int width = sfd->dmabuf_info.width;
	int height = sfd->dmabuf_info.height;
	int stride = sfd->dmabuf_info.strides[0];

	enum AVPixelFormat avpixfmt = shm_to_av(drm_format);
	if (avpixfmt == AV_PIX_FMT_NONE) {
		wp_error("Failed to find matching AvPixelFormat for %x",
				drm_format);
		return;
	}
	enum AVPixelFormat videofmt = AV_PIX_FMT_YUV420P /*AV_PIX_FMT_YUV420P*/;

	if (sws_isSupportedInput(avpixfmt) == 0) {
		wp_error("source pixel format %x not supported", avpixfmt);
		return;
	}
	if (sws_isSupportedInput(videofmt) == 0) {
		wp_error("AV_PIX_FMT_YUV420P not supported");
		return;
	}

	struct AVCodec *codec = avcodec_find_decoder(AV_CODEC_ID_H264);
	if (!codec) {
		wp_error("Failed to find decoder for h264");
	}

	struct AVCodecContext *ctx = avcodec_alloc_context3(codec);
	if (!ctx) {
		wp_error("Failed to allocate context");
	}

	/* set context dimensions */
	pad_video_mirror_size(
			width, height, stride, &ctx->width, &ctx->height, NULL);
	ctx->pix_fmt = videofmt;
	ctx->delay = 0;
	ctx->thread_count = 1;
	if (avcodec_open2(ctx, codec, NULL) < 0) {
		wp_error("Failed to open codec");
	}

	struct AVFrame *frame = av_frame_alloc();
	if (!frame) {
		wp_error("Could not allocate video frame");
	}
	frame->format = avpixfmt;
	/* adopt padded sizes */
	frame->width = ctx->width;
	frame->height = ctx->height;
	frame->linesize[0] = stride;

	struct AVFrame *yuv_frame = av_frame_alloc();
	/* match context dimensions */
	yuv_frame->width = ctx->width;
	yuv_frame->height = ctx->height;
	yuv_frame->format = videofmt;
	if (!yuv_frame) {
		wp_error("Could not allocate video yuv_frame");
	}

	struct SwsContext *sws = sws_getContext(yuv_frame->width,
			yuv_frame->height, videofmt, frame->width,
			frame->height, avpixfmt, SWS_BILINEAR, NULL, NULL,
			NULL);
	if (!sws) {
		wp_error("Could not create software color conversion context");
	}

	struct AVPacket *pkt = av_packet_alloc();
	if (!pkt) {
		wp_error("Could not allocate video packet");
	}

	sfd->video_local_frame = frame;
	sfd->video_yuv_frame = yuv_frame;
	sfd->video_yuv_frame_data = NULL; /* yuv_frame not allocated by us */
	sfd->video_packet = pkt;
	sfd->video_context = ctx;
	sfd->video_color_context = sws;
}

void collect_video_from_mirror(struct shadow_fd *sfd,
		struct transfer_stack *transfers, struct bytebuf_stack *blocks,
		bool first)
{
	if (sfd->video_color_context) {
		/* If using software encoding, need to convert to YUV */
		void *handle = NULL;
		void *data = map_dmabuf(sfd->dmabuf_bo, false, &handle);
		if (!data) {
			return;
		}
		memcpy(sfd->mem_mirror, data, sfd->buffer_size);
		unmap_dmabuf(sfd->dmabuf_bo, handle);

		sfd->video_local_frame->data[0] = (uint8_t *)sfd->mem_mirror;
		for (int i = 1; i < AV_NUM_DATA_POINTERS; i++) {
			sfd->video_local_frame->data[i] = NULL;
		}

		if (sws_scale(sfd->video_color_context,
				    (const uint8_t *const *)sfd
						    ->video_local_frame->data,
				    sfd->video_local_frame->linesize, 0,
				    sfd->video_local_frame->height,
				    sfd->video_yuv_frame->data,
				    sfd->video_yuv_frame->linesize) < 0) {
			wp_error("Failed to perform color conversion");
		}
	}

	sfd->video_yuv_frame->pts = sfd->video_frameno++;
	int sendstat = avcodec_send_frame(
			sfd->video_context, sfd->video_yuv_frame);
	if (sendstat < 0) {
		wp_error("Failed to create frame: %s", av_err2str(sendstat));
		return;
	}
	// assume 1-1 frames to packets, at the moment
	int recvstat = avcodec_receive_packet(
			sfd->video_context, sfd->video_packet);
	if (recvstat == AVERROR(EINVAL)) {
		wp_error("Failed to receive packet");
		return;
	} else if (recvstat == AVERROR(EAGAIN)) {
		wp_error("Packet needs more input");
		// Clearly, the solution is to resend the
		// original frame ? but _lag_
	}
	if (recvstat == 0) {
		struct AVPacket *pkt = sfd->video_packet;
		buf_ensure_size(transfers->count + 1, sizeof(struct transfer),
				&transfers->size, (void **)&transfers->data);
		buf_ensure_size(blocks->count + 1 + first,
				sizeof(struct bytebuf), &blocks->size,
				(void **)&blocks->data);

		struct transfer *tf = &transfers->data[transfers->count++];
		tf->type = sfd->type;
		tf->obj_id = sfd->remote_id;
		tf->special.block_meta = (uint32_t)sfd->buffer_size;
		tf->nblocks = 1 + first;
		tf->subtransfer_idx = blocks->count;
		if (first) {
			struct bytebuf *header = &blocks->data[blocks->count++];
			header->size = sizeof(struct dmabuf_slice_data);
			header->data = (char *)&sfd->dmabuf_info;
		}
		free(sfd->video_buffer);
		sfd->video_buffer = (char *)malloc(align(pkt->buf->size, 8));
		memcpy(sfd->video_buffer, pkt->buf->data,
				(size_t)pkt->buf->size);
		struct bytebuf *bb = &blocks->data[blocks->count++];
		bb->size = (size_t)pkt->buf->size;
		bb->data = (char *)sfd->video_buffer;

		av_packet_unref(pkt);
	} else if (first) {
		struct transfer *tf = setup_single_block_transfer(transfers,
				blocks, sizeof(struct dmabuf_slice_data),
				(const char *)&sfd->dmabuf_info);
		// Q: use a subtype 'FDC_VIDEODMABUF ?'
		tf->type = sfd->type;
		tf->obj_id = sfd->remote_id;
		tf->special.block_meta = (uint32_t)sfd->buffer_size;
	}
}

void apply_video_packet(struct shadow_fd *sfd, size_t size, const char *data)
{
	// We unpack directly one mem_mirror
	sfd->video_local_frame->data[0] = (uint8_t *)sfd->mem_mirror;
	for (int i = 1; i < AV_NUM_DATA_POINTERS; i++) {
		sfd->video_local_frame->data[i] = NULL;
	}

	// padding, requires zerod overflow for read
	sfd->video_packet->data = (uint8_t *)data;
	sfd->video_packet->size = size;

	int sendstat = avcodec_send_packet(
			sfd->video_context, sfd->video_packet);
	char errbuf[256];
	strcpy(errbuf, "Unknown error");
	if (sendstat < 0) {
		av_strerror(sendstat, errbuf, sizeof(errbuf));
		wp_error("Failed to send packet: %s", errbuf);
	}

	/* Receive all produced frames, ignoring all but the most recent */
	while (true) {
		int recvstat = avcodec_receive_frame(
				sfd->video_context, sfd->video_yuv_frame);
		if (recvstat == 0) {
			/* Handle frame immediately, since the next receive run
			 * will clear it again */
			if (sws_scale(sfd->video_color_context,
					    (const uint8_t *const *)sfd
							    ->video_yuv_frame
							    ->data,
					    sfd->video_yuv_frame->linesize, 0,
					    sfd->video_yuv_frame->height,
					    sfd->video_local_frame->data,
					    sfd->video_local_frame->linesize) <
					0) {
				wp_error("Failed to perform color conversion");
			}

			if (!sfd->dmabuf_bo) {
				// ^ was not previously able to create buffer
				wp_error("DMABUF was not created");
				return;
			}
			/* Copy data onto DMABUF */
			void *handle = NULL;
			void *data = map_dmabuf(sfd->dmabuf_bo, true, &handle);
			if (!data) {
				return;
			}
			memcpy(data, sfd->mem_mirror, sfd->buffer_size);
			unmap_dmabuf(sfd->dmabuf_bo, handle);
		} else {
			if (recvstat != AVERROR(EAGAIN)) {
				strcpy(errbuf, "Unknown error");
				av_strerror(sendstat, errbuf, sizeof(errbuf));
				wp_error("Failed to receive frame due to error: %s",
						errbuf);
			}
			break;
		}
	}
}

#endif /* HAS_VIDEO && HAS_DMABUF */
