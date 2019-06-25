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

#ifndef HAS_VIDEO

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
void setup_video_encode(struct shadow_fd *sfd, int width, int height,
		int stride, uint32_t drm_format)
{
	(void)sfd;
	(void)width;
	(void)height;
	(void)stride;
	(void)drm_format;
}
void setup_video_decode(struct shadow_fd *sfd, int width, int height,
		int stride, uint32_t drm_format)
{
	(void)sfd;
	(void)width;
	(void)height;
	(void)stride;
	(void)drm_format;
}
void collect_video_from_mirror(struct shadow_fd *sfd, int *ntransfers,
		struct transfer transfers[], int *nblocks,
		struct bytebuf blocks[], bool first)
{
	(void)sfd;
	(void)ntransfers;
	(void)transfers;
	(void)nblocks;
	(void)blocks;
	(void)first;
}
void apply_video_packet_to_mirror(
		struct shadow_fd *sfd, size_t size, const char *data)
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

#ifdef HAS_DMABUF
/* these are equivalent to the GBM formats */
#include <libdrm/drm_fourcc.h>

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
	 * codec supports alpha */
	case DRM_FORMAT_GR88:
		return AV_PIX_FMT_NONE;

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
#endif

static enum AVPixelFormat shm_to_av(uint32_t format)
{
	if (format == 0) {
		return AV_PIX_FMT_BGR0;
	}
#ifdef HAS_DMABUF
	return drm_to_av(format);
#else
	return AV_PIX_FMT_NONE;
#endif
}

bool video_supports_dmabuf_format(uint32_t format, uint64_t modifier)
{
#ifdef HAS_DMABUF
	if (modifier == DRM_FORMAT_MOD_LINEAR &&
			drm_to_av(format) != AV_PIX_FMT_NONE) {
		return true;
	}
#else
	(void)format;
	(void)modifier;
#endif
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
		av_frame_free(&sfd->video_reg_frame);
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

void setup_video_encode(struct shadow_fd *sfd, int width, int height,
		int stride, uint32_t drm_format)
{
	enum AVPixelFormat avpixfmt = shm_to_av(drm_format);
	if (avpixfmt == AV_PIX_FMT_NONE) {
		wp_log(WP_ERROR, "Failed to find matching AvPixelFormat	for %x",
				drm_format);
		return;
	}
	enum AVPixelFormat videofmt = AV_PIX_FMT_YUV420P;
	if (sws_isSupportedInput(avpixfmt) == 0) {
		wp_log(WP_ERROR, "frame format %x not supported", avpixfmt);
		return;
	}
	if (sws_isSupportedInput(videofmt) == 0) {
		wp_log(WP_ERROR, "videofmt %x not supported", videofmt);
		return;
	}

	// Try to set up a video encoding and a video decoding
	// stream with AVCodec, although transmissions in each
	// direction are relatively independent. TODO: use
	// hardware support only if available.

	/* note: "libx264rgb" should, if compiled in, support RGB
directly */
	struct AVCodec *codec = avcodec_find_encoder(AV_CODEC_ID_H264);
	if (!codec) {
		wp_log(WP_ERROR, "Failed to find encoder for h264");
		return;
	}

	struct AVCodecContext *ctx = avcodec_alloc_context3(codec);

	struct AVPacket *pkt = av_packet_alloc();

	ctx->bit_rate = 3000000;
	pad_video_mirror_size(
			width, height, stride, &ctx->width, &ctx->height, NULL);
	// "time" is only meaningful in terms of the frames
	// provided
	ctx->time_base = (AVRational){1, 25};
	ctx->framerate = (AVRational){25, 1};

	/* B-frames are directly tied to latency, since each one
	 * is predicted using its preceding and following
	 * frames. The gop size is chosen by the driver. */
	ctx->gop_size = -1;
	ctx->max_b_frames = 0; // Q: how to get this to zero?
	ctx->pix_fmt = videofmt;
	// low latency
	ctx->delay = 0;
	ctx->thread_count = 1;
	if (av_opt_set(ctx->priv_data, "preset", "ultrafast", 0) != 0) {
		wp_log(WP_ERROR, "Failed to set x264 encode ultrafast preset");
	}
	if (av_opt_set(ctx->priv_data, "tune", "zerolatency", 0) != 0) {
		wp_log(WP_ERROR, "Failed to set x264 encode zerolatency");
	}

	bool near_perfect = false;
	if (near_perfect && av_opt_set(ctx->priv_data, "crf", "0", 0) != 0) {
		wp_log(WP_ERROR, "Failed to set x264 crf");
	}

	// option: crf = 0

	if (avcodec_open2(ctx, codec, NULL) < 0) {
		wp_log(WP_ERROR, "Failed to open codec");
		return;
	}

	struct AVFrame *frame = av_frame_alloc();
	if (!frame) {
		wp_log(WP_ERROR, "Could not allocate video frame");
		return;
	}
	frame->format = avpixfmt;
	/* adopt padded sizes */
	frame->width = ctx->width;
	frame->height = ctx->height;
	frame->linesize[0] = stride;

	struct AVFrame *yuv_frame = av_frame_alloc();
	yuv_frame->width = ctx->width;
	yuv_frame->height = ctx->height;
	yuv_frame->format = videofmt;
	if (av_image_alloc(yuv_frame->data, yuv_frame->linesize,
			    yuv_frame->width, yuv_frame->height, videofmt,
			    64) < 0) {
		wp_log(WP_ERROR, "Failed to allocate temp image");
		return;
	}
	struct SwsContext *sws = sws_getContext(frame->width, frame->height,
			avpixfmt, yuv_frame->width, yuv_frame->height, videofmt,
			SWS_BILINEAR, NULL, NULL, NULL);
	if (!sws) {
		wp_log(WP_ERROR,
				"Could not create software color conversion context");
		return;
	}

	sfd->video_codec = codec;
	sfd->video_yuv_frame = yuv_frame;
	/* recorded pointer to be freed to match av_image_alloc */
	sfd->video_yuv_frame_data = &yuv_frame->data[0];
	sfd->video_reg_frame = frame;
	sfd->video_packet = pkt;
	sfd->video_context = ctx;
	sfd->video_color_context = sws;
}

void setup_video_decode(struct shadow_fd *sfd, int width, int height,
		int stride, uint32_t drm_format)
{
	enum AVPixelFormat avpixfmt = shm_to_av(drm_format);
	if (avpixfmt == AV_PIX_FMT_NONE) {
		wp_log(WP_ERROR, "Failed to find matching AvPixelFormat for %x",
				drm_format);
		return;
	}
	enum AVPixelFormat videofmt = AV_PIX_FMT_YUV420P /*AV_PIX_FMT_YUV420P*/;

	if (sws_isSupportedInput(avpixfmt) == 0) {
		wp_log(WP_ERROR, "source pixel format %x not supported",
				avpixfmt);
		return;
	}
	if (sws_isSupportedInput(videofmt) == 0) {
		wp_log(WP_ERROR, "AV_PIX_FMT_YUV420P not supported");
		return;
	}

	struct AVCodec *codec = avcodec_find_decoder(AV_CODEC_ID_H264);
	if (!codec) {
		wp_log(WP_ERROR, "Failed to find decoder for h264");
	}

	struct AVCodecContext *ctx = avcodec_alloc_context3(codec);
	if (!ctx) {
		wp_log(WP_ERROR, "Failed to allocate context");
	}

	/* set context dimensions */
	pad_video_mirror_size(
			width, height, stride, &ctx->width, &ctx->height, NULL);
	ctx->pix_fmt = videofmt;
	ctx->delay = 0;
	ctx->thread_count = 1;
	if (avcodec_open2(ctx, codec, NULL) < 0) {
		wp_log(WP_ERROR, "Failed to open codec");
	}

	struct AVFrame *frame = av_frame_alloc();
	if (!frame) {
		wp_log(WP_ERROR, "Could not allocate video frame");
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
		wp_log(WP_ERROR, "Could not allocate video yuv_frame");
	}

	struct SwsContext *sws = sws_getContext(yuv_frame->width,
			yuv_frame->height, videofmt, frame->width,
			frame->height, avpixfmt, SWS_BILINEAR, NULL, NULL,
			NULL);
	if (!sws) {
		wp_log(WP_ERROR,
				"Could not create software color conversion context");
	}

	struct AVPacket *pkt = av_packet_alloc();
	if (!pkt) {
		wp_log(WP_ERROR, "Could not allocate video packet");
	}

	sfd->video_codec = codec;
	sfd->video_reg_frame = frame;
	sfd->video_yuv_frame = yuv_frame;
	sfd->video_yuv_frame_data = NULL; /* yuv_frame not allocated by us */
	sfd->video_packet = pkt;
	sfd->video_context = ctx;
	sfd->video_color_context = sws;
}

void collect_video_from_mirror(struct shadow_fd *sfd, int *ntransfers,
		struct transfer transfers[], int *nblocks,
		struct bytebuf blocks[], bool first)
{

	sfd->video_reg_frame->data[0] = (uint8_t *)sfd->mem_mirror;
	for (int i = 1; i < AV_NUM_DATA_POINTERS; i++) {
		sfd->video_reg_frame->data[i] = NULL;
	}

	if (sws_scale(sfd->video_color_context,
			    (const uint8_t *const *)sfd->video_reg_frame->data,
			    sfd->video_reg_frame->linesize, 0,
			    sfd->video_reg_frame->height,
			    sfd->video_yuv_frame->data,
			    sfd->video_yuv_frame->linesize) < 0) {
		wp_log(WP_ERROR, "Failed to perform color conversion");
	}

	sfd->video_yuv_frame->pts = sfd->video_frameno++;
	int sendstat = avcodec_send_frame(
			sfd->video_context, sfd->video_yuv_frame);
	char errbuf[256];
	strcpy(errbuf, "Unknown error");
	if (sendstat < 0) {
		av_strerror(sendstat, errbuf, sizeof(errbuf));
		wp_log(WP_ERROR, "Failed to create frame: %s", errbuf);
		return;
	}
	// assume 1-1 frames to packets, at the moment
	int recvstat = avcodec_receive_packet(
			sfd->video_context, sfd->video_packet);
	if (recvstat == AVERROR(EINVAL)) {
		wp_log(WP_ERROR, "Failed to receive packet");
		return;
	} else if (recvstat == AVERROR(EAGAIN)) {
		wp_log(WP_ERROR, "Packet needs more input");
		// Clearly, the solution is to resend the
		// original frame ? but _lag_
	}
	if (recvstat == 0) {
		// we can unref the packet when? after sending?
		// on the next arrival?
		struct AVPacket *pkt = sfd->video_packet;
		size_t tsize;
		if (first) {
			// For the first frame, we must prepend
			// the video slice data
			free(sfd->video_buffer);
			sfd->video_buffer = calloc(
					align(pkt->buf->size + sizeof(struct dmabuf_slice_data),
							8),
					1);
			memcpy(sfd->video_buffer, &sfd->dmabuf_info,
					sizeof(struct dmabuf_slice_data));
			memcpy(sfd->video_buffer + sizeof(struct dmabuf_slice_data),
					pkt->buf->data, pkt->buf->size);
			tsize = pkt->buf->size +
				sizeof(struct dmabuf_slice_data);
		} else {
			free(sfd->video_buffer);
			size_t sz = pkt->buf->size;
			sfd->video_buffer = malloc(align(sz, 8));
			memcpy(sfd->video_buffer, pkt->buf->data, sz);
			tsize = sz;
		}
		av_packet_unref(pkt);

		struct transfer *tf = setup_single_block_transfer(ntransfers,
				transfers, nblocks, blocks, tsize,
				sfd->video_buffer);
		tf->type = sfd->type;
		tf->obj_id = sfd->remote_id;
		tf->special.block_meta = (uint32_t)sfd->buffer_size |
					 FILE_SIZE_VIDEO_FLAG;
	} else if (first) {
		struct transfer *tf = setup_single_block_transfer(ntransfers,
				transfers, nblocks, blocks,
				sizeof(struct dmabuf_slice_data),
				(const char *)&sfd->dmabuf_info);
		// Q: use a subtype 'FDC_VIDEODMABUF ?'
		tf->type = sfd->type;
		tf->obj_id = sfd->remote_id;
		tf->special.block_meta = (uint32_t)sfd->buffer_size |
					 FILE_SIZE_VIDEO_FLAG;
	}
}

void apply_video_packet_to_mirror(
		struct shadow_fd *sfd, size_t size, const char *data)
{
	// We unpack directly one mem_mirror
	sfd->video_reg_frame->data[0] = (uint8_t *)sfd->mem_mirror;
	for (int i = 1; i < AV_NUM_DATA_POINTERS; i++) {
		sfd->video_reg_frame->data[i] = NULL;
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
		wp_log(WP_ERROR, "Failed to send packet: %s", errbuf);
	}

	while (true) {
		// Apply all produced frames
		int recvstat = avcodec_receive_frame(
				sfd->video_context, sfd->video_yuv_frame);
		if (recvstat == 0) {
			if (sws_scale(sfd->video_color_context,
					    (const uint8_t *const *)sfd
							    ->video_yuv_frame
							    ->data,
					    sfd->video_yuv_frame->linesize, 0,
					    sfd->video_yuv_frame->height,
					    sfd->video_reg_frame->data,
					    sfd->video_reg_frame->linesize) <
					0) {
				wp_log(WP_ERROR,
						"Failed to perform color conversion");
			}

		} else {
			if (recvstat != AVERROR(EAGAIN)) {
				strcpy(errbuf, "Unknown error");
				av_strerror(sendstat, errbuf, sizeof(errbuf));
				wp_log(WP_ERROR,
						"Failed to receive frame due to error: %s",
						errbuf);
			}
			break;
		}
		// the scale/copy operation output is
		// already onto mem_mirror
	}
}

#endif /* HAS_VIDEO */
