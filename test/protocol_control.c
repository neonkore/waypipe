/*
 * Copyright © 2020 Manuel Stoeckl
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
#include "util.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

struct msg {
	uint32_t *data;
	int len;
	int *fds;
	int nfds;
};
struct test_state {
	struct main_config config;
	struct globals glob;
	bool display_side;
	bool failed;
	/* messages received from the other side */
	int nrcvd;
	struct msg *rcvd;
};
struct msgtransfer {
	struct test_state *src;
	struct test_state *dst;
};

/* Sends a Wayland protocol message to src, and records output messages
 * in dst. */
static void send_protocol_msg(struct test_state *src, struct test_state *dst,
		const struct msg msg)
{
	if (src->failed || dst->failed) {
		wp_error("at least one side broken, skipping msg");
		return;
	}

	struct char_window proto_src;
	proto_src.data = calloc(16384, 1);
	proto_src.size = 16384;
	proto_src.zone_start = 0;
	memcpy(proto_src.data, msg.data, sizeof(uint32_t) * (size_t)msg.len);
	proto_src.zone_end = (int)sizeof(uint32_t) * msg.len;

	struct char_window proto_mid;
	// todo: test_(re)alloc for tests, to abort (but still pass?) if
	// allocations fail?
	proto_mid.data = calloc(16384, 1);
	proto_mid.size = 16384;
	proto_mid.zone_start = 0;
	proto_mid.zone_end = 0;

	struct int_window fd_window;
	fd_window.data = calloc(1024, 4);
	fd_window.size = 1024;
	fd_window.zone_start = 0;
	fd_window.zone_end = 0;

	struct char_window proto_end;
	proto_end.data = calloc(16384, 1);
	proto_end.size = 16384;
	proto_end.zone_start = 0;
	proto_end.zone_end = 0;

	struct transfer_queue transfers;
	memset(&transfers, 0, sizeof(transfers));
	pthread_mutex_init(&transfers.async_recv_queue.lock, NULL);

	if (msg.nfds > 0) {
		memcpy(fd_window.data, msg.fds,
				sizeof(uint32_t) * (size_t)msg.nfds);
	}
	fd_window.zone_end = msg.nfds;

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
					false, false);
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
		collect_update(&src->glob.threads, cur, &transfers,
				src->config.old_video_mode);
		destroy_shadow_if_unreferenced(cur);
	}

	decref_transferred_rids(
			&src->glob.map, fd_window.zone_start, fd_window.data);

	{
		start_parallel_work(&src->glob.threads,
				&transfers.async_recv_queue);
		bool is_done;
		struct task_data task;
		while (request_work_task(&src->glob.threads, &task, &is_done)) {
			run_task(&task, &src->glob.threads.threads[0]);
			src->glob.threads.tasks_in_progress--;
		}
		(void)transfer_load_async(&transfers);
	}

	/* On destination side, a bit easier; process transfers, and
	 * then deliver all messages */

	for (int i = 0; i < transfers.end; i++) {
		char *msg = transfers.vecs[i].iov_base;
		uint32_t header = ((uint32_t *)msg)[0];
		size_t sz = transfer_size(header);
		int rid = (int)((uint32_t *)msg)[1];
		struct bytebuf bb;
		bb.data = msg;
		bb.size = sz;
		int r = apply_update(&dst->glob.map, &dst->glob.threads,
				&dst->glob.render, transfer_type(header), rid,
				&bb);
		if (r < 0) {
			wp_error("Applying update failed");
			goto cleanup;
		}
	}

	/* Convert RIDs back to fds */
	fd_window.zone_end = fd_window.zone_start;
	fd_window.zone_start = 0;
	for (int i = fd_window.zone_start; i < fd_window.zone_end; i++) {
		fd_window.data[i] = get_shadow_for_rid(
				&dst->glob.map, fd_window.data[i])
						    ->fd_local;
	}

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
	free(proto_src.data);
	free(proto_mid.data);
	free(proto_end.data);
	free(fd_window.data);
	cleanup_transfer_queue(&transfers);
}

static int setup_state(struct test_state *s, bool display_side)
{
	memset(s, 0, sizeof(*s));

	s->config = (struct main_config){.drm_node = NULL,
			.n_worker_threads = 1,
			.compression = COMP_NONE,
			.compression_level = 0,
			.no_gpu = false,
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
static void cleanup_state(struct test_state *s)
{
	cleanup_message_tracker(&s->glob.tracker);
	cleanup_translation_map(&s->glob.map);
	cleanup_render_data(&s->glob.render);
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

static void msg(const struct msgtransfer tx, uint32_t id, uint32_t msgno,
		size_t arglen, const uint32_t *args)
{
	struct msg m;
	m.fds = NULL;
	m.nfds = 0;
	m.data = calloc(arglen + 2, sizeof(uint32_t));
	m.data[0] = id;
	m.data[1] = (uint32_t)(((arglen + 2) * 4) << 16) | msgno;
	if (arglen > 0) {
		memcpy(&m.data[2], args, arglen * sizeof(uint32_t));
	}

	m.len = (int)arglen + 2;

	send_protocol_msg(tx.src, tx.dst, m);
	free(m.data);
}

static void msg_fd(const struct msgtransfer tx, uint32_t id, uint32_t msgno,
		size_t arglen, const uint32_t *args, int fd)
{
	struct msg m;
	m.fds = calloc(1, sizeof(int));
	/* duplicate fd, so it stays alive even if shadowfd holding it dies */
	m.fds[0] = dup(fd);
	m.nfds = 1;
	m.data = calloc(arglen + 2, sizeof(uint32_t));
	m.data[0] = id;
	m.data[1] = (uint32_t)(((arglen + 2) * 4) << 16) | msgno;
	if (arglen > 0) {
		memcpy(&m.data[2], args, arglen * sizeof(uint32_t));
	}

	m.len = (int)arglen + 2;

	send_protocol_msg(tx.src, tx.dst, m);
	free(m.data);
	free(m.fds);
}
static void global_msg(const struct msgtransfer tx, uint32_t id, int globnum,
		const char *type, int version)
{
	size_t typesz = (strlen(type) + 3) / 4;
	uint32_t *args = calloc(3 + typesz, sizeof(uint32_t));
	args[0] = (uint32_t)globnum;
	args[1] = (uint32_t)strlen(type);
	memcpy(args + 2, type, strlen(type));
	args[2 + typesz] = (uint32_t)version;
	msg(tx, id, 0, 3 + typesz, args);
	free(args);
}
static void bind_msg(const struct msgtransfer tx, uint32_t id, int globnum,
		const char *type, int version, uint32_t new_id)
{
	size_t typesz = (strlen(type) + 3) / 4;
	uint32_t *args = calloc(4 + typesz, sizeof(uint32_t));
	args[0] = (uint32_t)globnum;
	args[1] = (uint32_t)strlen(type);
	memcpy(args + 2, type, strlen(type));
	args[2 + typesz] = (uint32_t)version;
	args[3 + typesz] = new_id;
	msg(tx, id, 0, 4 + typesz, args);
	free(args);
}

static char *make_filled_pattern(size_t size, uint32_t contents)
{
	uint32_t *mem = calloc(size, 1);
	for (size_t i = 0; i < size / 4; i++) {
		mem[i] = contents;
	}
	return (char *)mem;
}

static int make_filled_file(size_t size, const char *contents)
{
	int fd = create_anon_file();
	ftruncate(fd, (off_t)size);

	uint32_t *mem = (uint32_t *)mmap(
			NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	memcpy(mem, contents, size);
	munmap(mem, size);
	return fd;
}

static bool check_file_contents(int fd, size_t size, const char *contents)
{
	if (fd == -1) {
		return false;
	}
	uint32_t *mem = (uint32_t *)mmap(
			NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
	bool match = memcmp(mem, contents, size) == 0;
	munmap(mem, size);
	return match;
}
static int get_only_fd_from_msg(const struct test_state *s)
{

	if (s->rcvd && s->rcvd[s->nrcvd - 1].nfds == 1) {
		return s->rcvd[s->nrcvd - 1].fds[0];
	} else {
		return -1;
	}
}
static int get_fd_from_nth_to_last_msg(const struct test_state *s, int nth)
{
	if (!s->rcvd || s->nrcvd < nth) {
		return -1;
	}
	const struct msg *m = &s->rcvd[s->nrcvd - nth];
	if (m->nfds != 1) {
		return -1;
	}
	return m->fds[0];
}

static bool test_fixed_shm_buffer_copy()
{
	fprintf(stdout, "\nshm_pool+buffer test\n");

	struct test_state comp; /* compositor */
	struct test_state app;  /* application */
	if (setup_state(&comp, true) == -1 || setup_state(&app, false) == -1) {
		wp_error("Test setup failed");
		return true;
	}
	bool pass = true;
	struct msgtransfer CA = {.src = &comp, .dst = &app};
	struct msgtransfer AC = {.src = &app, .dst = &comp};

	char *testpat = make_filled_pattern(16384, 0xFEDCBA98);
	int fd = make_filled_file(16384, testpat);
	int ret_fd = -1;

	// -> wl_display@1.get_registry(new id wl_registry@2)
	msg(AC, 0x1, 1, 1, (uint32_t[]){0x2});
	// wl_registry@2.global(1, "wl_shm", 1)
	// wl_registry@2.global(2, "wl_compositor", 1)
	global_msg(CA, 0x2, 1, "wl_shm", 1);
	global_msg(CA, 0x2, 2, "wl_compositor", 1);
	// -> wl_registry@2.bind(1, "wl_shm", 1, new id [unknown]@3)
	// -> wl_registry@2.bind(2, "wl_compositor", 3, new id [unknown]@4)
	bind_msg(AC, 0x2, 1, "wl_shm", 1, 0x3);
	bind_msg(AC, 0x2, 2, "wl_compositor", 1, 0x4);
	// -> wl_shm@3.create_pool(new id wl_shm_pool@5, fd ?, 16384)
	msg_fd(AC, 0x3, 0, 2, (uint32_t[]){0x5, 16384}, fd);
	ret_fd = get_only_fd_from_msg(&comp);
	// -> wl_shm_pool@5.create_buffer(new id wl_buffer@6, 0, 64, 64,
	// 256, 0x30334258)
	msg(AC, 0x5, 0, 6, (uint32_t[]){0x6, 0, 64, 64, 256, 0x30334258});
	// -> wl_compositor@4.create_surface(new id wl_surface@7)
	msg(AC, 0x4, 0, 1, (uint32_t[]){0x7});
	// -> wl_surface@7.attach(wl_buffer@6, 0, 0)
	msg(AC, 0x7, 1, 3, (uint32_t[]){0x6, 0, 0});
	// -> wl_surface@7.damage(0, 0, 64, 64)
	msg(AC, 0x7, 2, 4, (uint32_t[]){0, 0, 64, 64});
	// -> wl_surface@7.commit()
	msg(AC, 0x7, 6, 0, NULL);

	/* confirm receipt of fd with the correct contents; if not,
	 * reject */
	if (ret_fd == -1) {
		wp_error("Fd not passed through");
		pass = false;
		goto end;
	}
	pass = check_file_contents(ret_fd, 16384, testpat);
	if (!pass) {
		wp_error("Failed to transfer file");
	}
end:
	free(testpat);
	checked_close(fd);
	cleanup_state(&comp);
	cleanup_state(&app);
	return pass;
}

static bool test_fixed_keymap_copy()
{
	fprintf(stdout, "\nKeymap test\n");
	struct test_state comp; /* compositor */
	struct test_state app;  /* application */
	if (setup_state(&comp, true) == -1 || setup_state(&app, false) == -1) {
		wp_error("Test setup failed");
		return true;
	}
	bool pass = true;
	struct msgtransfer CA = {.src = &comp, .dst = &app};
	struct msgtransfer AC = {.src = &app, .dst = &comp};

	char *testpat = make_filled_pattern(16384, 0xFEDCBA98);
	int fd = make_filled_file(16384, testpat);
	int ret_fd = -1;

	// -> wl_display@1.get_registry(new id wl_registry@2)
	msg(AC, 0x1, 1, 1, (uint32_t[]){0x2});
	// wl_registry@2.global(1, "wl_seat", 7)
	global_msg(CA, 0x2, 1, "wl_seat", 7);
	// -> wl_registry@2.bind(1, "wl_seat", 7, new id [unknown]@3)
	bind_msg(AC, 0x2, 1, "wl_seat", 7, 0x3);
	// wl_seat@3.capabilities(3)
	msg(CA, 0x3, 0, 1, (uint32_t[]){3});
	// -> wl_seat@3.get_keyboard(new id wl_keyboard@4)
	msg(AC, 0x3, 1, 1, (uint32_t[]){0x4});
	// wl_keyboard@4.keymap(1, fd ?, 16384)
	msg_fd(CA, 0x4, 0, 2, (uint32_t[]){1, 16384}, fd);
	ret_fd = get_only_fd_from_msg(&app);

	/* confirm receipt of fd with the correct contents; if not,
	 * reject */
	if (ret_fd == -1) {
		wp_error("Fd not passed through");
		pass = false;
		goto end;
	}
	pass = check_file_contents(ret_fd, 16384, testpat);
	if (!pass) {
		wp_error("Failed to transfer file");
	}

end:
	free(testpat);
	checked_close(fd);
	cleanup_state(&comp);
	cleanup_state(&app);
	return pass;
}

#define DMABUF_FORMAT 875713112

static int create_dmabuf(void)
{
	struct render_data rd;
	memset(&rd, 0, sizeof(rd));
	rd.drm_fd = -1;
	rd.av_disabled = true;

	const size_t test_width = 256;
	const size_t test_height = 384;
	const size_t test_cpp = 4;
	const size_t test_size = test_width * test_height * test_cpp;
	const struct dmabuf_slice_data slice_data = {
			.width = (uint32_t)test_width,
			.height = (uint32_t)test_height,
			.format = DMABUF_FORMAT,
			.num_planes = 1,
			.modifier = 0,
			.offsets = {0, 0, 0, 0},
			.strides = {(uint32_t)(test_width * test_cpp), 0, 0, 0},
			.using_planes = {true, false, false, false},
	};

	int dmafd = -1;
	if (init_render_data(&rd) == -1) {
		return -1;
	}
	struct gbm_bo *bo = make_dmabuf(&rd, test_size, &slice_data);
	if (!bo) {
		goto end;
	}

	void *map_handle = NULL;
	void *data = map_dmabuf(bo, true, &map_handle);
	if (!data) {
		destroy_dmabuf(bo);
		goto end;
	}
	/* TODO: the best test pattern is a colored gradient, so we can
	 * check whether the copy flips things or not */
	memset(data, 0x80, test_size);
	unmap_dmabuf(bo, map_handle);

	dmafd = export_dmabuf(bo);
	if (dmafd == -1) {
		goto end;
	}
	destroy_dmabuf(bo);

end:
	cleanup_render_data(&rd);

	return dmafd;
}

static bool test_fixed_dmabuf_copy()
{
	fprintf(stdout, "\n DMABUF test\n");

	int dmabufd = create_dmabuf();
	if (dmabufd == -1) {
		return true;
	}
	struct test_state comp; /* compositor */
	struct test_state app;  /* application */
	if (setup_state(&comp, true) == -1 || setup_state(&app, false) == -1) {
		wp_error("Test setup failed");
		return true;
	}
	bool pass = true;
	struct msgtransfer CA = {.src = &comp, .dst = &app};
	struct msgtransfer AC = {.src = &app, .dst = &comp};
	int ret_fd = -1;

	// -> wl_display@1.get_registry(new id wl_registry@2)
	msg(AC, 0x1, 1, 1, (uint32_t[]){0x2});
	// wl_registry@2.global(1, "zwp_linux_dmabuf_v1", 1)
	// wl_registry@2.global(2, "wl_compositor", 1)
	global_msg(CA, 0x2, 1, "zwp_linux_dmabuf_v1", 1);
	global_msg(CA, 0x2, 2, "wl_compositor", 1);
	// -> wl_registry@2.bind(1, "zwp_linux_dmabuf_v1", 1, new id
	// [unknown]@3)
	// -> wl_registry@2.bind(2, "wl_compositor", 3, new id [unknown]@4)
	bind_msg(AC, 0x2, 1, "zwp_linux_dmabuf_v1", 1, 0x3);
	bind_msg(AC, 0x2, 2, "wl_compositor", 1, 0x4);
	// zwp_linux_dmabuf_v1@3.modifier(875713112, 0, 0)
	msg(CA, 0x3, 1, 3, (uint32_t[]){DMABUF_FORMAT, 0, 0});
	// -> zwp_linux_dmabuf_v1@3.create_params(new id
	// zwp_linux_buffer_params_v1@5)
	// -> zwp_linux_buffer_params_v1@5.add(fd 41, 0, 0, 1024, 0, 0)
	// -> zwp_linux_buffer_params_v1@5.create_immed(new id wl_buffer@6, 256,
	// 256, 875713112, 0)
	// -> zwp_linux_buffer_params_v1@5.destroy()
	msg(AC, 0x3, 1, 1, (uint32_t[]){0x5});
	msg_fd(AC, 0x5, 1, 5, (uint32_t[]){0, 0, 256 * 4, 0, 0}, dmabufd);
	msg(AC, 0x5, 3, 5, (uint32_t[]){0x6, 256, 384, DMABUF_FORMAT, 0});
	/* this message + previous, after reordering, are treated as one
	 * bundle; if that is fixed, this will break, and 1 should become 2 */
	ret_fd = get_fd_from_nth_to_last_msg(&comp, 1);
	msg(AC, 0x5, 0, 0, NULL);

	// -> wl_compositor@4.create_surface(new id wl_surface@7)
	msg(AC, 0x4, 0, 1, (uint32_t[]){0x7});
	// -> wl_surface@7.attach(wl_buffer@6, 0, 0)
	msg(AC, 0x7, 1, 3, (uint32_t[]){0x6, 0, 0});
	// -> wl_surface@7.damage(0, 0, 64, 64)
	msg(AC, 0x7, 2, 4, (uint32_t[]){0, 0, 64, 64});
	// -> wl_surface@7.commit()
	msg(AC, 0x7, 6, 0, NULL);

	if (ret_fd == -1) {
		wp_error("Fd not passed through");
		pass = false;
		goto end;
	}
	// TODO: verify that the FD contents are correct

end:
	checked_close(dmabufd);
	cleanup_state(&comp);
	cleanup_state(&app);
	return pass;
}

/* Check whether the video encoding feature can replicate a uniform
 * color image */
static bool test_fixed_video_color_copy(enum video_coding_fmt fmt, bool hw)
{
	(void)fmt;
	(void)hw;
	/* todo: back out if no dmabuf support or no video support */
	return true;
}

log_handler_func_t log_funcs[2] = {test_log_handler, test_log_handler};
int main(int argc, char **argv)
{
	(void)argc;
	(void)argv;

	int ntest = 6;
	int nsuccess = 0;
	nsuccess += test_fixed_shm_buffer_copy();
	nsuccess += test_fixed_keymap_copy();
	nsuccess += test_fixed_dmabuf_copy();
	nsuccess += test_fixed_video_color_copy(VIDEO_H264, false);
	nsuccess += test_fixed_video_color_copy(VIDEO_H264, true);
	nsuccess += test_fixed_video_color_copy(VIDEO_VP9, false);
	// TODO: add a copy-paste test, and screencapture
	fprintf(stdout, "%d of %d cases passed\n", nsuccess, ntest);
	return (nsuccess == ntest) ? EXIT_SUCCESS : EXIT_FAILURE;
}
