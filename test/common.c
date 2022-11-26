/*
 * Copyright © 2021 Manuel Stoeckl
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
#include "common.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

uint64_t time_value = 0;
uint64_t local_time_offset = 0;

void *read_file_into_mem(const char *path, size_t *len)
{
	int fd = open(path, O_RDONLY | O_NOCTTY);
	if (fd == -1) {
		fprintf(stderr, "Failed to open '%s'", path);
		return NULL;
	}
	*len = (size_t)lseek(fd, 0, SEEK_END);
	if (*len == 0) {
		checked_close(fd);
		return EXIT_SUCCESS;
	}
	lseek(fd, 0, SEEK_SET);
	void *buf = malloc(*len);
	if (read(fd, buf, *len) == -1) {
		return NULL;
	}
	checked_close(fd);
	return buf;
}

void send_wayland_msg(struct test_state *src, const struct msg msg,
		struct transfer_queue *transfers)
{
	/* assume every message uses up 1usec */
	time_value += 1000;

	struct char_window proto_mid;
	// todo: test_(re)alloc for tests, to abort (but still pass?) if
	// allocations fail?
	proto_mid.data = calloc(16384, 1);
	proto_mid.size = 16384;
	proto_mid.zone_start = 0;
	proto_mid.zone_end = 0;

	struct int_window fd_window;
	fd_window.size = msg.nfds + 1024;
	fd_window.data = calloc((size_t)fd_window.size, sizeof(int));
	fd_window.zone_start = 0;
	fd_window.zone_end = 0;
	if (msg.nfds > 0) {
		memcpy(fd_window.data, msg.fds,
				sizeof(uint32_t) * (size_t)msg.nfds);
	}
	fd_window.zone_end = msg.nfds;

	/* The protocol source window is an exact copy of the message, and only
	 * zone_start/zone_end are ever modified */
	struct char_window proto_src;
	proto_src.data = calloc((size_t)msg.len, sizeof(uint32_t));
	proto_src.size = msg.len * (int)sizeof(uint32_t);
	memcpy(proto_src.data, msg.data, (size_t)proto_src.size);
	proto_src.zone_start = 0;
	proto_src.zone_end = proto_src.size;

	local_time_offset = src->local_time_offset;
	parse_and_prune_messages(&src->glob, src->display_side,
			!src->display_side, &proto_src, &proto_mid, &fd_window);

	if (fd_window.zone_start != fd_window.zone_end) {
		wp_error("Not all fds were consumed, final unused window %d %d",
				fd_window.zone_start, fd_window.zone_end);
		src->failed = true;
		goto cleanup;
	}

	/* Replace fds with RIDs in place */
	for (int i = 0; i < fd_window.zone_start; i++) {
		struct shadow_fd *sfd = get_shadow_for_local_fd(
				&src->glob.map, fd_window.data[i]);
		if (!sfd) {
			/* Autodetect type + create shadow fd */
			size_t fdsz = 0;
			enum fdcat fdtype =
					get_fd_type(fd_window.data[i], &fdsz);
			sfd = translate_fd(&src->glob.map, &src->glob.render,
					fd_window.data[i], fdtype, fdsz, NULL,
					false);
		}
		if (sfd) {
			fd_window.data[i] = sfd->remote_id;
		} else {
			wp_error("failed to translate");
			src->failed = true;
			goto cleanup;
		}
	}

	for (struct shadow_fd_link *lcur = src->glob.map.link.l_next,
				   *lnxt = lcur->l_next;
			lcur != &src->glob.map.link;
			lcur = lnxt, lnxt = lcur->l_next) {
		struct shadow_fd *cur = (struct shadow_fd *)lcur;
		collect_update(&src->glob.threads, cur, transfers,
				src->config.old_video_mode);
		destroy_shadow_if_unreferenced(cur);
	}

	decref_transferred_rids(
			&src->glob.map, fd_window.zone_start, fd_window.data);

	{
		start_parallel_work(&src->glob.threads,
				&transfers->async_recv_queue);
		bool is_done;
		struct task_data task;
		while (request_work_task(&src->glob.threads, &task, &is_done)) {
			run_task(&task, &src->glob.threads.threads[0]);
			src->glob.threads.tasks_in_progress--;
		}
		(void)transfer_load_async(transfers);
	}

	for (struct shadow_fd_link *lcur = src->glob.map.link.l_next,
				   *lnxt = lcur->l_next;
			lcur != &src->glob.map.link;
			lcur = lnxt, lnxt = lcur->l_next) {
		/* Note: finish_update() may delete `cur` */
		struct shadow_fd *cur = (struct shadow_fd *)lcur;
		finish_update(cur);
		destroy_shadow_if_unreferenced(cur);
	}

	if (fd_window.zone_start > 0) {
		size_t tsz = sizeof(uint32_t) *
			     (1 + (size_t)fd_window.zone_start);
		void *tmsg = calloc(tsz, 1);
		((uint32_t *)tmsg)[0] = transfer_header(tsz, WMSG_INJECT_RIDS);
		memcpy((char *)tmsg + 4, fd_window.data,
				4 * (size_t)fd_window.zone_start);
		transfer_add(transfers, tsz, tmsg);
	}
	if (proto_mid.zone_end > 0) {
		size_t tsz = sizeof(uint32_t) + (size_t)proto_mid.zone_end;
		void *tmsg = calloc(tsz, 1);
		((uint32_t *)tmsg)[0] = transfer_header(tsz, WMSG_PROTOCOL);
		memcpy((char *)tmsg + 4, proto_mid.data,
				(size_t)proto_mid.zone_end);
		transfer_add(transfers, tsz, tmsg);
	}
cleanup:
	free(proto_src.data);
	free(proto_mid.data);
	free(fd_window.data);
}
void receive_wire(struct test_state *dst, struct transfer_queue *transfers)
{
	struct char_window proto_mid;
	proto_mid.data = NULL;
	proto_mid.size = 0;
	proto_mid.zone_start = 0;
	proto_mid.zone_end = 0;

	const size_t fd_padding = 1024;
	struct int_window fd_window;
	fd_window.data = calloc(fd_padding, 4);
	fd_window.size = (int)fd_padding;
	fd_window.zone_start = 0;
	fd_window.zone_end = 0;

	struct char_window proto_end;
	proto_end.data = calloc(16384, 1);
	proto_end.size = 16384;
	proto_end.zone_start = 0;
	proto_end.zone_end = 0;

	for (int i = 0; i < transfers->end; i++) {
		char *msg = transfers->vecs[i].iov_base;
		size_t real_sz = transfers->vecs[i].iov_len;
		uint32_t header = ((uint32_t *)msg)[0];
		size_t sz = transfer_size(header);
		if (sz != real_sz) {
			wp_error("Transfer nominal size %zu did not match actual %zu",
					sz, real_sz);
			goto cleanup;
		}
		/* note: we assume there is at most one inj_rid message
		 * per batch*/
		if (transfer_type(header) == WMSG_PROTOCOL) {
			void *ndata = realloc(proto_mid.data,
					(size_t)proto_mid.zone_end + (sz - 4));
			if (!ndata) {
				wp_error("Failed to reallocate recv side proto data");
				goto cleanup;
			}
			proto_mid.data = ndata;
			memcpy(proto_mid.data + proto_mid.zone_end, msg + 4,
					sz - 4);
			proto_mid.zone_end += (int)(sz - 4);
			proto_mid.size = proto_mid.zone_end;
		} else if (transfer_type(header) == WMSG_INJECT_RIDS) {
			void *ndata = realloc(fd_window.data,
					sizeof(int) * (size_t)fd_window.zone_end +
							(sz - 4) + fd_padding);
			if (!ndata) {
				wp_error("Failed to reallocate recv side fd data");
				goto cleanup;
			}
			fd_window.data = ndata;
			memcpy(fd_window.data + fd_window.zone_end, msg + 4,
					sz - 4);
			fd_window.zone_end += (int)(sz - 4) / 4;
			fd_window.size = fd_window.zone_end;
		} else {
			int rid = (int)((uint32_t *)msg)[1];
			struct bytebuf bb;
			bb.data = msg;
			bb.size = sz;
			int r = apply_update(&dst->glob.map, &dst->glob.threads,
					&dst->glob.render,
					transfer_type(header), rid, &bb);
			if (r < 0) {
				wp_error("Applying update failed");
				goto cleanup;
			}
		}
	}

	/* Convert RIDs back to fds */
	for (int i = fd_window.zone_start; i < fd_window.zone_end; i++) {
		struct shadow_fd *sfd = get_shadow_for_rid(
				&dst->glob.map, fd_window.data[i]);
		if (sfd) {
			fd_window.data[i] = sfd->fd_local;
		} else {
			fd_window.data[i] = -1;
			wp_error("Failed to get shadow_fd for RID=%d, index %d",
					fd_window.data[i], i);
		}
	}

	local_time_offset = dst->local_time_offset;
	parse_and_prune_messages(&dst->glob, dst->display_side,
			dst->display_side, &proto_mid, &proto_end, &fd_window);

	/* Finally, take the output fds, and append them to the output stack;
	 * ditto with the output messages. Assume for now messages are 1-in
	 * 1-out */
	dst->nrcvd++;
	dst->rcvd = realloc(dst->rcvd, sizeof(struct msg) * (size_t)dst->nrcvd);
	struct msg *lastmsg = &dst->rcvd[dst->nrcvd - 1];
	memset(lastmsg, 0, sizeof(struct msg));

	/* Save the fds that were marked used (which should be all of them) */
	if (fd_window.zone_start > 0) {
		lastmsg->nfds = fd_window.zone_start;
		lastmsg->fds = malloc(
				sizeof(int) * (size_t)fd_window.zone_start);
		for (int i = 0; i < fd_window.zone_start; i++) {
			/* duplicate fd, so it's still usable if shadowfd gone
			 */
			lastmsg->fds[i] = dup(fd_window.data[i]);
		}
	}
	if (proto_end.zone_end > 0) {
		lastmsg->len = proto_end.zone_end;
		lastmsg->data = malloc(
				sizeof(uint32_t) * (size_t)proto_end.zone_end);
		memcpy(lastmsg->data, proto_end.data,
				(size_t)proto_end.zone_end);
	}

cleanup:
	free(proto_end.data);
	free(proto_mid.data);
	free(fd_window.data);
}

/* Sends a Wayland protocol message to src, and records output messages
 * in dst. */
void send_protocol_msg(struct test_state *src, struct test_state *dst,
		const struct msg msg)
{
	if (src->failed || dst->failed) {
		wp_error("at least one side broken, skipping msg");
		return;
	}

	struct transfer_queue transfers;
	memset(&transfers, 0, sizeof(transfers));
	pthread_mutex_init(&transfers.async_recv_queue.lock, NULL);

	/* On destination side, a bit easier; process transfers, and
	 * then deliver all messages */
	send_wayland_msg(src, msg, &transfers);
	receive_wire(dst, &transfers);

	cleanup_transfer_queue(&transfers);
}

int setup_state(struct test_state *s, bool display_side, bool has_gpu)
{
	memset(s, 0, sizeof(*s));

	s->config = (struct main_config){.drm_node = NULL,
			.n_worker_threads = 1,
			.compression = COMP_NONE,
			.compression_level = 0,
			.no_gpu = !has_gpu,
			.only_linear_dmabuf = true,
			.video_if_possible = false,
			.video_bpf = 120000,
			.video_fmt = VIDEO_H264,
			.prefer_hwvideo = false,
			.old_video_mode = false};

	s->glob.config = &s->config;
	s->glob.render = (struct render_data){
			.drm_node_path = s->config.drm_node,
			.drm_fd = -1,
			.dev = NULL,
			.disabled = s->config.no_gpu,
			.av_disabled = s->config.no_gpu ||
				       !s->config.prefer_hwvideo,
			.av_bpf = s->config.video_bpf,
			.av_video_fmt = (int)s->config.video_fmt,
			.av_hwdevice_ref = NULL,
			.av_drmdevice_ref = NULL,
			.av_vadisplay = NULL,
			.av_copy_config = 0,
	};

	// leave render data to be set up on demand, just as in
	// main_loop?
	// TODO: what compositors _don't_ support GPU stuff?

	setup_thread_pool(&s->glob.threads, s->config.compression,
			s->config.compression_level,
			s->config.n_worker_threads);
	setup_translation_map(&s->glob.map, display_side);
	init_message_tracker(&s->glob.tracker);
	setup_video_logging();
	s->display_side = display_side;

	// TODO: make a transfer queue for outgoing stuff

	return 0;
}

void cleanup_state(struct test_state *s)
{
	cleanup_message_tracker(&s->glob.tracker);
	cleanup_translation_map(&s->glob.map);
	cleanup_render_data(&s->glob.render);
	cleanup_hwcontext(&s->glob.render);
	cleanup_thread_pool(&s->glob.threads);

	for (int i = 0; i < s->nrcvd; i++) {
		free(s->rcvd[i].data);
		for (int j = 0; j < s->rcvd[i].nfds; j++) {
			checked_close(s->rcvd[i].fds[j]);
		}
		free(s->rcvd[i].fds);
	}
	free(s->rcvd);
}

void test_log_handler(const char *file, int line, enum log_level level,
		const char *fmt, ...)
{
	(void)level;
	printf("[%s:%d] ", file, line);
	va_list args;
	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
	printf("\n");
}

void test_atomic_log_handler(const char *file, int line, enum log_level level,
		const char *fmt, ...)
{
	pthread_t tid = pthread_self();
	char msg[1024];
	int nwri = 0;
	nwri += sprintf(msg + nwri, "%" PRIx64 " [%s:%3d] ", (uint64_t)tid,
			file, line);

	va_list args;
	va_start(args, fmt);
	nwri += vsnprintf(msg + nwri, (size_t)(1022 - nwri), fmt, args);
	va_end(args);

	msg[nwri++] = '\n';
	msg[nwri] = 0;

	(void)write(STDOUT_FILENO, msg, (size_t)nwri);
	(void)level;
}
