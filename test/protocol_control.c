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

#include "protocol_functions.h"

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

static void print_pass(bool pass)
{
	fprintf(stdout, "%s\n", pass ? "PASS" : "FAIL");
}

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
		struct shadow_fd *sfd = get_shadow_for_rid(
				&dst->glob.map, fd_window.data[i]);
		if (sfd) {
			fd_window.data[i] = sfd->fd_local;
		} else {
			fd_window.data[i] = -1;
			wp_error("Failed to get shadow_fd for RID=%d",
					fd_window.data[i]);
		}
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
	if (mem == MAP_FAILED) {
		wp_error("Failed to map file");
		return -1;
	}
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

static void msg_send_handler(struct transfer_states *ts, struct test_state *src,
		struct test_state *dst)
{
	struct msg m;
	m.data = ts->msg_space;
	m.fds = ts->fd_space;
	m.len = (int)ts->msg_size;
	m.nfds = (int)ts->fd_size;
	for (int i = 0; i < m.nfds; i++) {
		m.fds[i] = dup(m.fds[i]);
		if (m.fds[i] == -1) {
			wp_error("Invalid fd provided");
		}
	}
	send_protocol_msg(src, dst, m);
	memset(ts->msg_space, 0, sizeof(ts->msg_space));
	memset(ts->fd_space, 0, sizeof(ts->fd_space));
}

static bool test_fixed_shm_buffer_copy()
{
	fprintf(stdout, "\n  shm_pool+buffer test\n");

	struct test_state comp; /* compositor */
	struct test_state app;  /* application */
	if (setup_state(&comp, true) == -1 || setup_state(&app, false) == -1) {
		wp_error("Test setup failed");
		return true;
	}
	bool pass = true;

	struct transfer_states T = {
			.app = &app, .comp = &comp, .send = msg_send_handler};

	char *testpat = make_filled_pattern(16384, 0xFEDCBA98);
	int fd = make_filled_file(16384, testpat);
	int ret_fd = -1;

	struct wp_objid display = {0x1}, registry = {0x2}, shm = {0x3},
			compositor = {0x4}, pool = {0x5}, buffer = {0x6},
			surface = {0x7};

	send_wl_display_req_get_registry(&T, display, registry);
	send_wl_registry_evt_global(&T, registry, 1, "wl_shm", 1);
	send_wl_registry_evt_global(&T, registry, 2, "wl_compositor", 1);
	send_wl_registry_req_bind(&T, registry, 1, "wl_shm", 1, shm);
	send_wl_registry_req_bind(
			&T, registry, 2, "wl_compositor", 1, compositor);
	send_wl_shm_req_create_pool(&T, shm, pool, fd, 16384);
	ret_fd = get_only_fd_from_msg(&comp);
	send_wl_shm_pool_req_create_buffer(
			&T, pool, buffer, 0, 64, 64, 256, 0x30334258);
	send_wl_compositor_req_create_surface(&T, compositor, surface);
	send_wl_surface_req_attach(&T, surface, buffer, 0, 0);
	send_wl_surface_req_damage(&T, surface, 0, 0, 64, 64);
	send_wl_surface_req_commit(&T, surface);

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

	print_pass(pass);
	return pass;
}

static bool test_fixed_keymap_copy()
{
	fprintf(stdout, "\n  Keymap test\n");
	struct test_state comp; /* compositor */
	struct test_state app;  /* application */
	if (setup_state(&comp, true) == -1 || setup_state(&app, false) == -1) {
		wp_error("Test setup failed");
		return true;
	}
	bool pass = true;

	char *testpat = make_filled_pattern(16384, 0xFEDCBA98);
	int fd = make_filled_file(16384, testpat);
	int ret_fd = -1;

	struct transfer_states T = {
			.app = &app, .comp = &comp, .send = msg_send_handler};
	struct wp_objid display = {0x1}, registry = {0x2}, seat = {0x3},
			keyboard = {0x4};

	send_wl_display_req_get_registry(&T, display, registry);
	send_wl_registry_evt_global(&T, registry, 1, "wl_seat", 7);
	send_wl_registry_req_bind(&T, registry, 1, "wl_seat", 7, seat);
	send_wl_seat_evt_capabilities(&T, seat, 3);
	send_wl_seat_req_get_keyboard(&T, seat, keyboard);
	send_wl_keyboard_evt_keymap(&T, keyboard, 1, fd, 16384);
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

	print_pass(pass);
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

end:
	destroy_dmabuf(bo);
	cleanup_render_data(&rd);

	return dmafd;
}

static bool test_fixed_dmabuf_copy()
{
	fprintf(stdout, "\n  DMABUF test\n");

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
	int ret_fd = -1;

	struct transfer_states T = {
			.app = &app, .comp = &comp, .send = msg_send_handler};
	struct wp_objid display = {0x1}, registry = {0x2}, linux_dmabuf = {0x3},
			compositor = {0x4}, params = {0x5}, buffer = {0x6},
			surface = {0x7};

	send_wl_display_req_get_registry(&T, display, registry);
	send_wl_registry_evt_global(&T, registry, 1, "zwp_linux_dmabuf_v1", 1);
	send_wl_registry_evt_global(&T, registry, 2, "wl_compositor", 1);
	send_wl_registry_req_bind(&T, registry, 1, "zwp_linux_dmabuf_v1", 1,
			linux_dmabuf);
	send_wl_registry_req_bind(
			&T, registry, 12, "wl_compositor", 1, compositor);
	send_zwp_linux_dmabuf_v1_evt_modifier(
			&T, linux_dmabuf, DMABUF_FORMAT, 0, 0);
	send_zwp_linux_dmabuf_v1_req_create_params(&T, linux_dmabuf, params);
	send_zwp_linux_buffer_params_v1_req_add(
			&T, params, dmabufd, 0, 0, 256 * 4, 0, 0);
	send_zwp_linux_buffer_params_v1_req_create_immed(
			&T, params, buffer, 256, 384, DMABUF_FORMAT, 0);
	/* this message + previous, after reordering, are treated as one
	 * bundle; if that is fixed, this will break, and 1 should become 2 */
	ret_fd = get_fd_from_nth_to_last_msg(&comp, 1);
	send_zwp_linux_buffer_params_v1_req_destroy(&T, params);
	send_wl_compositor_req_create_surface(&T, compositor, surface);
	send_wl_surface_req_attach(&T, surface, buffer, 0, 0);
	send_wl_surface_req_damage(&T, surface, 0, 0, 64, 64);
	send_wl_surface_req_commit(&T, surface);

	if (ret_fd == -1) {
		wp_error("Fd not passed through");
		pass = false;
		goto end;
	}
	// TODO: verify that the FD contents are correct

end:
	checked_close(dmabufd);
	/* todo: the drm_fd may be dup'd by libgbm but not freed */
	cleanup_state(&comp);
	cleanup_state(&app);

	print_pass(pass);
	return pass;
}

enum data_device_type {
	DDT_WAYLAND,
	DDT_GTK_PRIMARY,
	DDT_PRIMARY,
	DDT_WLR,
};
static const char *const data_device_type_strs[] = {"wayland main",
		"gtk primary selection", "primary selection",
		"wlroots data control"};

/* Confirm that wl_data_offer.receive creates a pipe matching the input */
static bool test_data_offer(enum data_device_type type)
{
	fprintf(stdout, "\n  Data offer test: %s\n",
			data_device_type_strs[type]);
	struct test_state comp, app;
	if (setup_state(&comp, true) == -1 || setup_state(&app, false) == -1) {
		wp_error("Test setup failed");
		return true;
	}
	bool pass = true;

	int src_pipe[2];
	pipe(src_pipe);
	int ret_fd = -1;

	struct transfer_states T = {
			.app = &app, .comp = &comp, .send = msg_send_handler};
	struct wp_objid display = {0x1}, registry = {0x2}, ddman = {0x3},
			seat = {0x4}, ddev = {0x5}, offer = {0xff000001};

	send_wl_display_req_get_registry(&T, display, registry);
	send_wl_registry_evt_global(&T, registry, 1, "wl_seat", 7);
	send_wl_registry_req_bind(&T, registry, 1, "wl_seat", 7, seat);
	switch (type) {
	case DDT_WAYLAND:
		send_wl_registry_evt_global(
				&T, registry, 2, "wl_data_device_manager", 3);
		send_wl_registry_req_bind(&T, registry, 2,
				"wl_data_device_manager", 3, ddman);
		send_wl_data_device_manager_req_get_data_device(
				&T, ddman, ddev, seat);
		send_wl_data_device_evt_data_offer(&T, ddev, offer);
		send_wl_data_offer_evt_offer(
				&T, offer, "text/plain;charset=utf-8");
		send_wl_data_device_evt_selection(&T, ddev, offer);
		send_wl_data_offer_req_receive(&T, offer,
				"text/plain;charset=utf-8", src_pipe[1]);
		break;
	case DDT_GTK_PRIMARY:
		send_wl_registry_evt_global(&T, registry, 2,
				"gtk_primary_selection_device_manager", 1);
		send_wl_registry_req_bind(&T, registry, 2,
				"gtk_primary_selection_device_manager", 1,
				ddman);
		send_gtk_primary_selection_device_manager_req_get_device(
				&T, ddman, ddev, seat);
		send_gtk_primary_selection_device_evt_data_offer(
				&T, ddev, offer);
		send_gtk_primary_selection_offer_evt_offer(
				&T, offer, "text/plain;charset=utf-8");
		send_gtk_primary_selection_device_evt_selection(
				&T, ddev, offer);
		send_gtk_primary_selection_offer_req_receive(&T, offer,
				"text/plain;charset=utf-8", src_pipe[1]);
		break;
	case DDT_PRIMARY:
		send_wl_registry_evt_global(&T, registry, 2,
				"zwp_primary_selection_device_manager_v1", 1);
		send_wl_registry_req_bind(&T, registry, 2,
				"zwp_primary_selection_device_manager_v1", 1,
				ddman);
		send_zwp_primary_selection_device_manager_v1_req_get_device(
				&T, ddman, ddev, seat);
		send_zwp_primary_selection_device_v1_evt_data_offer(
				&T, ddev, offer);
		send_zwp_primary_selection_offer_v1_evt_offer(
				&T, offer, "text/plain;charset=utf-8");
		send_zwp_primary_selection_device_v1_evt_selection(
				&T, ddev, offer);
		send_zwp_primary_selection_offer_v1_req_receive(&T, offer,
				"text/plain;charset=utf-8", src_pipe[1]);
		break;
	case DDT_WLR:
		send_wl_registry_evt_global(&T, registry, 2,
				"zwlr_data_control_manager_v1", 1);
		send_wl_registry_req_bind(&T, registry, 2,
				"zwlr_data_control_manager_v1", 1, ddman);
		send_zwlr_data_control_manager_v1_req_get_data_device(
				&T, ddman, ddev, seat);
		send_zwlr_data_control_device_v1_evt_data_offer(
				&T, ddev, offer);
		send_zwlr_data_control_offer_v1_evt_offer(
				&T, offer, "text/plain;charset=utf-8");
		send_zwlr_data_control_device_v1_evt_selection(&T, ddev, offer);
		send_zwlr_data_control_offer_v1_req_receive(&T, offer,
				"text/plain;charset=utf-8", src_pipe[1]);
		break;
	}
	ret_fd = get_only_fd_from_msg(&comp);

	/* confirm receipt of fd with the correct contents; if not,
	 * reject */
	if (ret_fd == -1) {
		wp_error("Fd not passed through");
		pass = false;
		goto end;
	}
	uint8_t tmp;
	if (write(ret_fd, &tmp, 1) != 1) {
		wp_error("Fd not writable");
		pass = false;
		goto end;
	}
end:

	checked_close(src_pipe[0]);
	checked_close(src_pipe[1]);
	cleanup_state(&comp);
	cleanup_state(&app);

	print_pass(pass);
	return pass;
}

/* Confirm that wl_data_source.data_offer creates a pipe matching the input */
static bool test_data_source(enum data_device_type type)
{
	fprintf(stdout, "\n  Data source test: %s\n",
			data_device_type_strs[type]);
	struct test_state comp, app;
	if (setup_state(&comp, true) == -1 || setup_state(&app, false) == -1) {
		wp_error("Test setup failed");
		return true;
	}
	bool pass = true;

	int dst_pipe[2];
	pipe(dst_pipe);
	int ret_fd = -1;

	struct transfer_states T = {
			.app = &app, .comp = &comp, .send = msg_send_handler};
	struct wp_objid display = {0x1}, registry = {0x2}, ddman = {0x3},
			seat = {0x4}, ddev = {0x5}, dsource = {0x6};

	send_wl_display_req_get_registry(&T, display, registry);
	send_wl_registry_evt_global(&T, registry, 1, "wl_seat", 7);
	send_wl_registry_req_bind(&T, registry, 1, "wl_seat", 7, seat);
	switch (type) {
	case DDT_WAYLAND:
		send_wl_registry_evt_global(
				&T, registry, 2, "wl_data_device_manager", 1);
		send_wl_registry_req_bind(&T, registry, 2,
				"wl_data_device_manager", 1, ddman);
		send_wl_data_device_manager_req_get_data_device(
				&T, ddman, ddev, seat);
		send_wl_data_device_manager_req_create_data_source(
				&T, ddman, dsource);
		send_wl_data_source_req_offer(
				&T, dsource, "text/plain;charset=utf-8");
		send_wl_data_device_req_set_selection(&T, ddev, dsource, 9999);
		send_wl_data_source_evt_send(&T, dsource,
				"text/plain;charset=utf-8", dst_pipe[0]);
		break;
	case DDT_GTK_PRIMARY:
		send_wl_registry_evt_global(&T, registry, 2,
				"gtk_primary_selection_device_manager", 1);
		send_wl_registry_req_bind(&T, registry, 2,
				"gtk_primary_selection_device_manager", 1,
				ddman);
		send_gtk_primary_selection_device_manager_req_get_device(
				&T, ddman, ddev, seat);
		send_gtk_primary_selection_device_manager_req_create_source(
				&T, ddman, dsource);
		send_gtk_primary_selection_source_req_offer(
				&T, dsource, "text/plain;charset=utf-8");
		send_gtk_primary_selection_device_req_set_selection(
				&T, ddev, dsource, 9999);
		send_gtk_primary_selection_source_evt_send(&T, dsource,
				"text/plain;charset=utf-8", dst_pipe[0]);
		break;
	case DDT_PRIMARY:
		send_wl_registry_evt_global(&T, registry, 2,
				"zwp_primary_selection_device_manager_v1", 1);
		send_wl_registry_req_bind(&T, registry, 2,
				"zwp_primary_selection_device_manager_v1", 1,
				ddman);
		send_zwp_primary_selection_device_manager_v1_req_get_device(
				&T, ddman, ddev, seat);
		send_zwp_primary_selection_device_manager_v1_req_create_source(
				&T, ddman, dsource);
		send_zwp_primary_selection_source_v1_req_offer(
				&T, dsource, "text/plain;charset=utf-8");
		send_zwp_primary_selection_device_v1_req_set_selection(
				&T, ddev, dsource, 9999);
		send_zwp_primary_selection_source_v1_evt_send(&T, dsource,
				"text/plain;charset=utf-8", dst_pipe[0]);
		break;
	case DDT_WLR:
		send_wl_registry_evt_global(&T, registry, 2,
				"zwlr_data_control_manager_v1", 1);
		send_wl_registry_req_bind(&T, registry, 2,
				"zwlr_data_control_manager_v1", 1, ddman);
		send_zwlr_data_control_manager_v1_req_get_data_device(
				&T, ddman, ddev, seat);
		send_zwlr_data_control_manager_v1_req_create_data_source(
				&T, ddman, dsource);
		send_zwlr_data_control_source_v1_req_offer(
				&T, dsource, "text/plain;charset=utf-8");
		send_zwlr_data_control_device_v1_req_set_selection(
				&T, ddev, dsource);
		send_zwlr_data_control_source_v1_evt_send(&T, dsource,
				"text/plain;charset=utf-8", dst_pipe[0]);
		break;
	}
	ret_fd = get_only_fd_from_msg(&app);

	/* confirm receipt of fd with the correct contents; if not,
	 * reject */
	if (ret_fd == -1) {
		wp_error("Fd not passed through");
		pass = false;
		goto end;
	}
	/* todo: check readable */
end:

	checked_close(dst_pipe[0]);
	checked_close(dst_pipe[1]);
	cleanup_state(&comp);
	cleanup_state(&app);

	print_pass(pass);
	return pass;
}

/* Check that gamma_control copies the input file */
static bool test_gamma_control()
{
	fprintf(stdout, "\n  Gamma control test\n");
	struct test_state comp, app;
	if (setup_state(&comp, true) == -1 || setup_state(&app, false) == -1) {
		wp_error("Test setup failed");
		return true;
	}
	bool pass = true;

	int ret_fd = -1;

	char *testpat = make_filled_pattern(1024, 0x12345678);
	int fd = make_filled_file(1024, testpat);

	struct transfer_states T = {
			.app = &app, .comp = &comp, .send = msg_send_handler};
	struct wp_objid display = {0x1}, registry = {0x2},
			gamma_manager = {0x3}, output = {0x4},
			gamma_control = {0x5};

	send_wl_display_req_get_registry(&T, display, registry);
	send_wl_registry_evt_global(
			&T, registry, 1, "zwlr_gamma_control_manager_v1", 1);
	send_wl_registry_req_bind(&T, registry, 1,
			"zwlr_gamma_control_manager_v1", 1, gamma_manager);
	send_wl_registry_evt_global(&T, registry, 1, "wl_output", 3);
	send_wl_registry_req_bind(&T, registry, 1, "wl_output", 3, output);
	send_zwlr_gamma_control_manager_v1_req_get_gamma_control(
			&T, gamma_manager, gamma_control, output);
	send_zwlr_gamma_control_v1_evt_gamma_size(&T, gamma_control, 1024);
	send_zwlr_gamma_control_v1_req_set_gamma(&T, gamma_control, fd);

	ret_fd = get_only_fd_from_msg(&comp);

	/* confirm receipt of fd with the correct contents; if not,
	 * reject */
	if (ret_fd == -1) {
		wp_error("Fd not passed through");
		pass = false;
		goto end;
	}
	pass = check_file_contents(ret_fd, 1024, testpat);
	if (!pass) {
		wp_error("Failed to transfer file");
	}
end:

	free(testpat);
	checked_close(fd);
	cleanup_state(&comp);
	cleanup_state(&app);

	print_pass(pass);
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

	set_initial_fds();

	int ntest = 15;
	int nsuccess = 0;
	nsuccess += test_fixed_shm_buffer_copy();
	nsuccess += test_fixed_keymap_copy();
	nsuccess += test_fixed_dmabuf_copy();
	nsuccess += test_data_offer(DDT_WAYLAND);
	nsuccess += test_data_offer(DDT_PRIMARY);
	nsuccess += test_data_offer(DDT_GTK_PRIMARY);
	nsuccess += test_data_offer(DDT_WLR);
	nsuccess += test_data_source(DDT_WAYLAND);
	nsuccess += test_data_source(DDT_PRIMARY);
	nsuccess += test_data_source(DDT_GTK_PRIMARY);
	nsuccess += test_data_source(DDT_WLR);
	nsuccess += test_gamma_control();
	nsuccess += test_fixed_video_color_copy(VIDEO_H264, false);
	nsuccess += test_fixed_video_color_copy(VIDEO_H264, true);
	nsuccess += test_fixed_video_color_copy(VIDEO_VP9, false);
	// TODO: add a copy-paste test, and screencapture.
	// TODO: add tests for handling of common errors, e.g. invalid fd,
	// or type confusion

	fprintf(stdout, "\n%d of %d cases passed\n", nsuccess, ntest);

	check_unclosed_fds();

	return (nsuccess == ntest) ? EXIT_SUCCESS : EXIT_FAILURE;
}
