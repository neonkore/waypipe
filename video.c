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

#include <libavformat/avformat.h>
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
#endif

bool video_supports_dmabuf_format(uint32_t format, uint64_t modifier)
{
#ifdef HAS_DMABUF
	if (format == DRM_FORMAT_XRGB8888 &&
			modifier == DRM_FORMAT_MOD_LINEAR) {
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
	(void)format;
	return false;
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

		sws_freeContext(sfd->video_color_context);
		av_frame_free(&sfd->video_reg_frame);
		av_frame_free(&sfd->video_yuv_frame);
		avcodec_free_context(&sfd->video_context);
		av_packet_free(&sfd->video_packet);
	}
}

void setup_video_encode(struct shadow_fd *sfd, int width, int height,
		int stride, uint32_t drm_format)
{
	(void)drm_format;

	// Try to set up a video encoding and a video decoding
	// stream with AVCodec, although transmissions in each
	// direction are relatively independent. TODO: use
	// hardware support only if available.
	struct AVCodec *codec = avcodec_find_encoder(AV_CODEC_ID_H264);
	if (!codec) {
		wp_log(WP_ERROR, "Failed to find encoder for h264");
	}

	struct AVCodecContext *ctx = avcodec_alloc_context3(codec);

	struct AVPacket *pkt = av_packet_alloc();

	ctx->bit_rate = 3000000;
	// non-odd resolution ?
	ctx->width = align(width, 8);
	ctx->height = align(height, 8);
	// "time" is only meaningful in terms of the frames
	// provided
	ctx->time_base = (AVRational){1, 25};
	ctx->framerate = (AVRational){25, 1};

	/* B-frames are directly tied to latency, since each one
	 * is predicted using its preceding and following
	 * frames. The gop size is chosen by the driver. */
	ctx->gop_size = -1;
	ctx->max_b_frames = 0; // Q: how to get this to zero?
	ctx->pix_fmt = AV_PIX_FMT_YUV420P;
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
	}

	struct AVFrame *frame = av_frame_alloc();
	if (!frame) {
		wp_log(WP_ERROR, "Could not allocate video frame");
	}
	frame->format = AV_PIX_FMT_BGR0;
	frame->width = ctx->width;
	frame->height = ctx->height;
	frame->linesize[0] = stride;

	struct AVFrame *yuv_frame = av_frame_alloc();
	yuv_frame->width = ctx->width;
	yuv_frame->height = ctx->height;
	yuv_frame->format = AV_PIX_FMT_YUV420P;
	if (av_image_alloc(yuv_frame->data, yuv_frame->linesize,
			    yuv_frame->width, yuv_frame->height,
			    AV_PIX_FMT_YUV420P, 64) < 0) {
		wp_log(WP_ERROR, "Failed to allocate temp image");
	}

	if (sws_isSupportedInput(AV_PIX_FMT_BGR0) == 0) {
		wp_log(WP_ERROR, "AV_PIX_FMT_BGR0 not supported");
	}
	if (sws_isSupportedInput(AV_PIX_FMT_YUV420P) == 0) {
		wp_log(WP_ERROR, "AV_PIX_FMT_YUV420P not supported");
	}

	struct SwsContext *sws = sws_getContext(ctx->width, ctx->height,
			AV_PIX_FMT_BGR0, ctx->width, ctx->height,
			AV_PIX_FMT_YUV420P, SWS_BILINEAR, NULL, NULL, NULL);
	if (!sws) {
		wp_log(WP_ERROR,
				"Could not create software color conversion context");
	}

	sfd->video_codec = codec;
	sfd->video_yuv_frame = yuv_frame;
	sfd->video_reg_frame = frame;
	sfd->video_packet = pkt;
	sfd->video_context = ctx;
	sfd->video_color_context = sws;
}

void setup_video_decode(struct shadow_fd *sfd, int width, int height,
		int stride, uint32_t drm_format)
{
	(void)drm_format;

	struct AVCodec *codec = avcodec_find_decoder(AV_CODEC_ID_H264);
	if (!codec) {
		wp_log(WP_ERROR, "Failed to find decoder for h264");
	}

	struct AVCodecContext *ctx = avcodec_alloc_context3(codec);

	struct AVPacket *pkt = av_packet_alloc();
	// non-odd resolution ?
	ctx->width = align(width, 8);
	ctx->height = align(height, 8);
	ctx->pix_fmt = AV_PIX_FMT_YUV420P;
	ctx->delay = 0;
	ctx->thread_count = 1;
	if (avcodec_open2(ctx, codec, NULL) < 0) {
		wp_log(WP_ERROR, "Failed to open codec");
	}

	struct AVFrame *frame = av_frame_alloc();
	if (!frame) {
		wp_log(WP_ERROR, "Could not allocate video frame");
	}
	frame->format = AV_PIX_FMT_BGR0;
	frame->width = ctx->width;
	frame->height = ctx->height;
	frame->linesize[0] = stride;

	if (sws_isSupportedInput(AV_PIX_FMT_BGR0) == 0) {
		wp_log(WP_ERROR, "AV_PIX_FMT_BGR0 not supported");
	}
	if (sws_isSupportedInput(AV_PIX_FMT_YUV420P) == 0) {
		wp_log(WP_ERROR, "AV_PIX_FMT_YUV420P not supported");
	}

	struct SwsContext *sws = sws_getContext(ctx->width, ctx->height,
			AV_PIX_FMT_YUV420P, ctx->width, ctx->height,
			AV_PIX_FMT_BGR0, SWS_BILINEAR, NULL, NULL, NULL);
	if (!sws) {
		wp_log(WP_ERROR,
				"Could not create software color conversion context");
	}

	struct AVFrame *yuv_frame = av_frame_alloc();
	yuv_frame->width = ctx->width;
	yuv_frame->height = ctx->height;
	yuv_frame->format = AV_PIX_FMT_YUV420P;

	sfd->video_codec = codec;
	sfd->video_reg_frame = frame;
	sfd->video_yuv_frame = yuv_frame;
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

	av_frame_make_writable(sfd->video_yuv_frame);
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
		tf->special.file_actual_size = (int)sfd->dmabuf_size;
	} else if (first) {
		struct transfer *tf = setup_single_block_transfer(ntransfers,
				transfers, nblocks, blocks,
				sizeof(struct dmabuf_slice_data),
				(const char *)&sfd->dmabuf_info);
		// Q: use a subtype 'FDC_VIDEODMABUF ?'
		tf->type = sfd->type;
		tf->obj_id = sfd->remote_id;
		tf->special.file_actual_size = (int)sfd->dmabuf_size;
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
				char errbuf[256];
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
