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

#include "common.h"
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

struct msgtransfer {
	struct test_state *src;
	struct test_state *dst;
};

/* Override the libc clock_gettime, so we can test presentation-time
 * protocol. Note: the video drivers sometimes call this function. */
int clock_gettime(clockid_t clock_id, struct timespec *tp)
{
	/* Assume every call costs 1ns */
	time_value += 1;

	if (clock_id == CLOCK_REALTIME) {
		tp->tv_sec = (int64_t)(time_value / 1000000000uLL);
		tp->tv_nsec = (int64_t)(time_value % 1000000000uLL);
	} else {
		tp->tv_sec = (int64_t)((time_value + local_time_offset) /
				       1000000000uLL);
		tp->tv_nsec = (int64_t)((time_value + local_time_offset) %
					1000000000uLL);
	}
	return 0;
}

static void print_pass(bool pass)
{
	fprintf(stdout, "%s\n", pass ? "PASS" : "FAIL");
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

	off_t fsize = lseek(fd, 0, SEEK_END);
	if (fsize != (off_t)size) {
		wp_error("fd size mismatch: %zu %zu\n", fsize, size);
		return -1;
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
static int setup_tstate(struct transfer_states *ts)
{
	memset(ts, 0, sizeof(*ts));
	ts->send = msg_send_handler;
	ts->comp = calloc(1, sizeof(struct test_state));
	ts->app = calloc(1, sizeof(struct test_state));
	if (!ts->comp || !ts->app) {
		goto fail_alloc;
	}
	if (setup_state(ts->comp, true, true) == -1) {
		goto fail_comp_setup;
	}
	if (setup_state(ts->app, false, true) == -1) {
		goto fail_app_setup;
	}
	return 0;

fail_app_setup:
	cleanup_state(ts->app);
fail_comp_setup:
	cleanup_state(ts->comp);
fail_alloc:
	free(ts->comp);
	free(ts->app);
	return -1;
}
static void cleanup_tstate(struct transfer_states *ts)
{
	cleanup_state(ts->comp);
	cleanup_state(ts->app);
	free(ts->comp);
	free(ts->app);
}

static bool test_fixed_shm_buffer_copy(void)
{
	fprintf(stdout, "\n  shm_pool+buffer test\n");

	struct transfer_states T;
	if (setup_tstate(&T) == -1) {
		wp_error("Test setup failed");
		return true;
	}
	bool pass = true;

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
	ret_fd = get_only_fd_from_msg(T.comp);
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
	cleanup_tstate(&T);

	print_pass(pass);
	return pass;
}

static bool test_fixed_shm_screencopy_copy(void)
{
	fprintf(stdout, "\n screencopy test\n");

	struct transfer_states T;
	if (setup_tstate(&T) == -1) {
		wp_error("Test setup failed");
		return true;
	}
	bool pass = true;

	char *testpat_orig = make_filled_pattern(16384, 0xFEDCBA98);
	char *testpat_screen = make_filled_pattern(16384, 0x77557755);
	int fd = make_filled_file(16384, testpat_orig);
	int ret_fd = -1;

	struct wp_objid display = {0x1}, registry = {0x2}, shm = {0x3},
			output = {0x4}, pool = {0x5}, buffer = {0x6},
			frame = {0x7}, screencopy = {0x8};

	send_wl_display_req_get_registry(&T, display, registry);
	send_wl_registry_evt_global(&T, registry, 1, "wl_shm", 1);
	send_wl_registry_evt_global(&T, registry, 2, "wl_output", 1);
	send_wl_registry_evt_global(
			&T, registry, 3, "zwlr_screencopy_manager_v1", 1);
	send_wl_registry_req_bind(&T, registry, 1, "wl_shm", 1, shm);
	send_wl_registry_req_bind(&T, registry, 2, "wl_output", 1, output);
	send_wl_registry_req_bind(&T, registry, 3, "zwlr_screencopy_manager_v1",
			1, screencopy);
	send_wl_shm_req_create_pool(&T, shm, pool, fd, 16384);
	ret_fd = get_only_fd_from_msg(T.comp);
	if (ret_fd == -1) {
		wp_error("Fd not passed through");
		pass = false;
		goto end;
	}
	send_zwlr_screencopy_manager_v1_req_capture_output(
			&T, screencopy, frame, 0, output);
	send_zwlr_screencopy_frame_v1_evt_buffer(&T, frame, 0, 64, 64, 16384);
	send_wl_shm_pool_req_create_buffer(
			&T, pool, buffer, 0, 64, 64, 256, 0x30334258);
	send_zwlr_screencopy_frame_v1_req_copy(&T, frame, buffer);

	uint32_t *mem = (uint32_t *)mmap(NULL, 16384, PROT_READ | PROT_WRITE,
			MAP_SHARED, ret_fd, 0);
	memcpy(mem, testpat_screen, 16384);
	munmap(mem, 16384);

	send_zwlr_screencopy_frame_v1_evt_flags(&T, frame, 0);
	send_zwlr_screencopy_frame_v1_evt_ready(&T, frame, 0, 12345, 600000000);

	/* confirm receipt of fd with the correct contents; if not,
	 * reject */
	if (ret_fd == -1) {
		wp_error("Fd not passed through");
		pass = false;
		goto end;
	}
	pass = check_file_contents(fd, 16384, testpat_screen);
	if (!pass) {
		wp_error("Failed to transfer file");
	}
end:
	free(testpat_screen);
	free(testpat_orig);
	checked_close(fd);
	cleanup_tstate(&T);

	print_pass(pass);
	return pass;
}

static bool test_fixed_keymap_copy(void)
{
	fprintf(stdout, "\n  Keymap test\n");
	struct transfer_states T;
	if (setup_tstate(&T) == -1) {
		wp_error("Test setup failed");
		return true;
	}
	bool pass = true;

	char *testpat = make_filled_pattern(16384, 0xFEDCBA98);
	int fd = make_filled_file(16384, testpat);
	int ret_fd = -1;

	struct wp_objid display = {0x1}, registry = {0x2}, seat = {0x3},
			keyboard = {0x4};

	send_wl_display_req_get_registry(&T, display, registry);
	send_wl_registry_evt_global(&T, registry, 1, "wl_seat", 7);
	send_wl_registry_req_bind(&T, registry, 1, "wl_seat", 7, seat);
	send_wl_seat_evt_capabilities(&T, seat, 3);
	send_wl_seat_req_get_keyboard(&T, seat, keyboard);
	send_wl_keyboard_evt_keymap(&T, keyboard, 1, fd, 16384);
	ret_fd = get_only_fd_from_msg(T.app);

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
	cleanup_tstate(&T);

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
	struct gbm_bo *bo = make_dmabuf(&rd, &slice_data);
	if (!bo) {
		goto end;
	}

	void *map_handle = NULL;
	uint32_t stride;
	void *data = map_dmabuf(bo, true, &map_handle, &stride);
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

enum dmabuf_copy_type {
	COPY_LINUX_DMABUF,
	COPY_LINUX_DMABUF_INDIR,
	COPY_DRM_PRIME,
	COPY_WLR_EXPORT,
};

static bool test_fixed_dmabuf_copy(enum dmabuf_copy_type type)
{
	const char *const types[] = {"linux-dmabuf", "linux-dmabuf-indir",
			"drm-prime", "wlr-export"};
	fprintf(stdout, "\n  DMABUF test, %s\n", types[(int)type]);

	int dmabufd = create_dmabuf();
	const int width = 256, height = 384;
	if (dmabufd == -1) {
		return true;
	}
	struct transfer_states T;
	if (setup_tstate(&T) == -1) {
		wp_error("Test setup failed");
		return true;
	}
	bool pass = true;
	int ret_fd = -1;

	switch (type) {
	case COPY_LINUX_DMABUF: {
		struct wp_objid display = {0x1}, registry = {0x2},
				linux_dmabuf = {0x3}, compositor = {0x4},
				params = {0x5}, buffer = {0x6}, surface = {0x7};

		send_wl_display_req_get_registry(&T, display, registry);
		send_wl_registry_evt_global(
				&T, registry, 1, "zwp_linux_dmabuf_v1", 1);
		send_wl_registry_evt_global(
				&T, registry, 2, "wl_compositor", 1);
		send_wl_registry_req_bind(&T, registry, 1,
				"zwp_linux_dmabuf_v1", 1, linux_dmabuf);
		send_wl_registry_req_bind(&T, registry, 12, "wl_compositor", 1,
				compositor);
		send_zwp_linux_dmabuf_v1_evt_modifier(
				&T, linux_dmabuf, DMABUF_FORMAT, 0, 0);
		send_zwp_linux_dmabuf_v1_req_create_params(
				&T, linux_dmabuf, params);
		send_zwp_linux_buffer_params_v1_req_add(
				&T, params, dmabufd, 0, 0, 256 * 4, 0, 0);
		send_zwp_linux_buffer_params_v1_req_create_immed(
				&T, params, buffer, 256, 384, DMABUF_FORMAT, 0);
		/* this message + previous, after reordering, are treated as one
		 * bundle; if that is fixed, this will break, and 1 should
		 * become 2 */
		ret_fd = get_fd_from_nth_to_last_msg(T.comp, 1);
		send_zwp_linux_buffer_params_v1_req_destroy(&T, params);
		send_wl_compositor_req_create_surface(&T, compositor, surface);
		send_wl_surface_req_attach(&T, surface, buffer, 0, 0);
		send_wl_surface_req_damage(&T, surface, 0, 0, 64, 64);
		send_wl_surface_req_commit(&T, surface);
	} break;
	case COPY_LINUX_DMABUF_INDIR: {
		struct wp_objid display = {0x1}, registry = {0x2},
				linux_dmabuf = {0x3}, compositor = {0x4},
				params = {0x5}, buffer = {0x6}, surface = {0x7};

		send_wl_display_req_get_registry(&T, display, registry);
		send_wl_registry_evt_global(
				&T, registry, 1, "zwp_linux_dmabuf_v1", 1);
		send_wl_registry_evt_global(
				&T, registry, 2, "wl_compositor", 1);
		send_wl_registry_req_bind(&T, registry, 1,
				"zwp_linux_dmabuf_v1", 1, linux_dmabuf);
		send_wl_registry_req_bind(&T, registry, 12, "wl_compositor", 1,
				compositor);
		send_zwp_linux_dmabuf_v1_evt_modifier(
				&T, linux_dmabuf, DMABUF_FORMAT, 0, 0);
		send_zwp_linux_dmabuf_v1_req_create_params(
				&T, linux_dmabuf, params);
		send_zwp_linux_buffer_params_v1_req_add(
				&T, params, dmabufd, 0, 0, 256 * 4, 0, 0);
		send_zwp_linux_buffer_params_v1_req_create(
				&T, params, 256, 384, DMABUF_FORMAT, 0);
		/* this message + previous, after reordering, are treated as one
		 * bundle; if that is fixed, this will break, and 1 should
		 * become 2 */
		ret_fd = get_fd_from_nth_to_last_msg(T.comp, 1);
		send_zwp_linux_buffer_params_v1_evt_created(&T, params, buffer);
		send_zwp_linux_buffer_params_v1_req_destroy(&T, params);
		send_wl_compositor_req_create_surface(&T, compositor, surface);
		send_wl_surface_req_attach(&T, surface, buffer, 0, 0);
		send_wl_surface_req_damage(&T, surface, 0, 0, 64, 64);
		send_wl_surface_req_commit(&T, surface);
	} break;
	case COPY_DRM_PRIME: {
		struct wp_objid display = {0x1}, registry = {0x2},
				wl_drm = {0x3}, compositor = {0x4},
				buffer = {0x5}, surface = {0x6};

		send_wl_display_req_get_registry(&T, display, registry);
		send_wl_registry_evt_global(&T, registry, 1, "wl_drm", 1);
		send_wl_registry_evt_global(
				&T, registry, 2, "wl_compositor", 1);
		send_wl_registry_req_bind(&T, registry, 1, "wl_drm", 1, wl_drm);
		send_wl_registry_req_bind(&T, registry, 12, "wl_compositor", 1,
				compositor);

		send_wl_drm_evt_device(&T, wl_drm, "/dev/dri/renderD128");
		send_wl_drm_evt_format(&T, wl_drm, DMABUF_FORMAT);
		send_wl_drm_evt_capabilities(&T, wl_drm, 1);
		send_wl_drm_req_create_prime_buffer(&T, wl_drm, buffer, dmabufd,
				width, height, DMABUF_FORMAT, 0, width * 4, 0,
				0, 0, 0);

		ret_fd = get_fd_from_nth_to_last_msg(T.comp, 1);
		send_wl_compositor_req_create_surface(&T, compositor, surface);
		send_wl_surface_req_attach(&T, surface, buffer, 0, 0);
		send_wl_surface_req_damage(&T, surface, 0, 0, 64, 64);
		send_wl_surface_req_commit(&T, surface);
	} break;

	case COPY_WLR_EXPORT: {
		/* note: here the compositor creates and sends fd to client */

		struct wp_objid display = {0x1}, registry = {0x2},
				export_manager = {0x3}, output = {0x4},
				dmabuf_frame = {0x5};

		send_wl_display_req_get_registry(&T, display, registry);
		send_wl_registry_evt_global(&T, registry, 1,
				"zwlr_export_dmabuf_manager_v1", 1);
		send_wl_registry_evt_global(&T, registry, 2, "wl_output", 1);
		send_wl_registry_req_bind(&T, registry, 1,
				"zwlr_export_dmabuf_manager_v1", 1,
				export_manager);
		send_wl_registry_req_bind(
				&T, registry, 12, "wl_output", 1, output);

		send_zwlr_export_dmabuf_manager_v1_req_capture_output(
				&T, export_manager, dmabuf_frame, 1, output);
		send_zwlr_export_dmabuf_frame_v1_evt_frame(&T, dmabuf_frame,
				width, height, 0, 0, 0, 1, DMABUF_FORMAT, 0, 0,
				1);
		send_zwlr_export_dmabuf_frame_v1_evt_object(&T, dmabuf_frame, 0,
				dmabufd, width * height * 4, 0, width * 4, 0);
		ret_fd = get_only_fd_from_msg(T.app);
		send_zwlr_export_dmabuf_frame_v1_evt_ready(
				&T, dmabuf_frame, 555555, 555555555, 333333333);
	} break;
	}

	if (ret_fd == -1) {
		wp_error("Fd not passed through");
		pass = false;
		goto end;
	}
	// TODO: verify that the FD contents are correct

end:
	checked_close(dmabufd);
	/* todo: the drm_fd may be dup'd by libgbm but not freed */
	cleanup_tstate(&T);

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
	struct transfer_states T;
	if (setup_tstate(&T) == -1) {
		wp_error("Test setup failed");
		return true;
	}
	bool pass = true;

	int src_pipe[2];
	pipe(src_pipe);
	int ret_fd = -1;

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
	ret_fd = get_only_fd_from_msg(T.comp);

	/* confirm receipt of fd with the correct contents; if not,
	 * reject */
	if (ret_fd == -1) {
		wp_error("Fd not passed through");
		pass = false;
		goto end;
	}
	uint8_t tmp = 0xab;
	if (write(ret_fd, &tmp, 1) != 1) {
		wp_error("Fd not writable");
		pass = false;
		goto end;
	}
end:

	checked_close(src_pipe[0]);
	checked_close(src_pipe[1]);
	cleanup_tstate(&T);

	print_pass(pass);
	return pass;
}

/* Confirm that wl_data_source.data_offer creates a pipe matching the input */
static bool test_data_source(enum data_device_type type)
{
	fprintf(stdout, "\n  Data source test: %s\n",
			data_device_type_strs[type]);
	struct transfer_states T;
	if (setup_tstate(&T) == -1) {
		wp_error("Test setup failed");
		return true;
	}
	bool pass = true;

	int dst_pipe[2];
	pipe(dst_pipe);
	int ret_fd = -1;

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
	ret_fd = get_only_fd_from_msg(T.app);

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
	cleanup_tstate(&T);

	print_pass(pass);
	return pass;
}

/* Check that gamma_control copies the input file */
static bool test_gamma_control(void)
{
	fprintf(stdout, "\n  Gamma control test\n");
	struct transfer_states T;
	if (setup_tstate(&T) == -1) {
		wp_error("Test setup failed");
		return true;
	}
	bool pass = true;

	int ret_fd = -1;

	char *testpat = make_filled_pattern(1024, 0x12345678);
	int fd = make_filled_file(1024, testpat);

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

	ret_fd = get_only_fd_from_msg(T.comp);

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
	cleanup_tstate(&T);

	print_pass(pass);
	return pass;
}

/* Check that gamma_control copies the input file */
static bool test_presentation_time(void)
{
	fprintf(stdout, "\n  Presentation time test\n");
	struct transfer_states T;
	if (setup_tstate(&T) == -1) {
		wp_error("Test setup failed");
		return true;
	}
	bool pass = true;

	struct wp_objid display = {0x1}, registry = {0x2}, presentation = {0x3},
			compositor = {0x4}, surface = {0x5}, feedback = {0x6};
	T.app->local_time_offset = 500;
	T.comp->local_time_offset = 600;

	send_wl_display_req_get_registry(&T, display, registry);
	send_wl_registry_evt_global(&T, registry, 1, "wp_presentation", 1);
	send_wl_registry_evt_global(&T, registry, 2, "wl_compositor", 1);
	send_wl_registry_req_bind(
			&T, registry, 1, "wp_presentation", 1, presentation);
	/* todo: run another branch with CLOCK_REALTIME */
	send_wp_presentation_evt_clock_id(&T, presentation, CLOCK_MONOTONIC);
	send_wl_registry_req_bind(
			&T, registry, 12, "wl_compositor", 1, compositor);
	send_wl_compositor_req_create_surface(&T, compositor, surface);

	send_wl_surface_req_damage(&T, surface, 0, 0, 64, 64);

	send_wp_presentation_req_feedback(&T, presentation, surface, feedback);
	send_wl_surface_req_commit(&T, surface);
	send_wp_presentation_feedback_evt_presented(
			&T, feedback, 0, 30, 120000, 16666666, 0, 0, 7);
	const struct msg *const last_msg = &T.app->rcvd[T.app->nrcvd - 1];
	uint32_t tv_sec_hi = last_msg->data[2], tv_sec_lo = last_msg->data[3],
		 tv_nsec = last_msg->data[4];
	if (tv_nsec != 120000 + T.app->local_time_offset -
					T.comp->local_time_offset) {
		wp_error("Time translation failed %d %d %d", tv_sec_hi,
				tv_sec_lo, tv_nsec);
		pass = false;
		goto end;
	}

	/* look at timestamp */
	if (!pass) {
		goto end;
	}
end:
	cleanup_tstate(&T);

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

	int ntest = 20;
	int nsuccess = 0;
	nsuccess += test_fixed_shm_buffer_copy();
	nsuccess += test_fixed_shm_screencopy_copy();
	nsuccess += test_fixed_keymap_copy();
	nsuccess += test_fixed_dmabuf_copy(COPY_LINUX_DMABUF);
	nsuccess += test_fixed_dmabuf_copy(COPY_LINUX_DMABUF_INDIR);
	nsuccess += test_fixed_dmabuf_copy(COPY_DRM_PRIME);
	nsuccess += test_fixed_dmabuf_copy(COPY_WLR_EXPORT);
	nsuccess += test_data_offer(DDT_WAYLAND);
	nsuccess += test_data_offer(DDT_PRIMARY);
	nsuccess += test_data_offer(DDT_GTK_PRIMARY);
	nsuccess += test_data_offer(DDT_WLR);
	nsuccess += test_data_source(DDT_WAYLAND);
	nsuccess += test_data_source(DDT_PRIMARY);
	nsuccess += test_data_source(DDT_GTK_PRIMARY);
	nsuccess += test_data_source(DDT_WLR);
	nsuccess += test_gamma_control();
	nsuccess += test_presentation_time();
	nsuccess += test_fixed_video_color_copy(VIDEO_H264, false);
	nsuccess += test_fixed_video_color_copy(VIDEO_H264, true);
	nsuccess += test_fixed_video_color_copy(VIDEO_VP9, false);
	// TODO: add tests for handling of common errors, e.g. invalid fd,
	// or type confusion

	fprintf(stdout, "\n%d of %d cases passed\n", nsuccess, ntest);

	check_unclosed_fds();

	return (nsuccess == ntest) ? EXIT_SUCCESS : EXIT_FAILURE;
}
