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

#include "util.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sys/mman.h>

#include <ffi.h>
#include <wayland-util.h>

void invoke_msg_handler(ffi_cif *cif, const struct wl_interface *intf,
		const struct wl_message *msg, bool is_event,
		const uint32_t *const payload, const int paylen,
		const int *const fd_list, const int fdlen, int *fds_used,
		void (*const func)(void), struct context *ctx,
		struct message_tracker *mt, struct fd_translation_map *map);

static bool called = false;
static void testfn_client(struct context *ctx, void *noop, struct wp_object *a0,
		int a1, int32_t a2, uint32_t a3, struct wp_object *a4,
		const char *a5, uint32_t a6)
{
	called = true;
	printf("%d called with: a0=%u, a1=%d, a2=%d, a3=%u, a4=%u, a5=\"%s\", a6=%u\n",
			ctx->obj->obj_id, a0->obj_id, a1, a2, a3, a4->obj_id,
			a5, a6);
	(void)noop;
}
static void testfn_server(struct context *ctx, void *noop, uint32_t a0, int a1,
		int32_t a2, uint32_t a3, struct wp_object *a4, const char *a5,
		uint32_t a6)
{
	called = true;
	printf("%d called with: a0=%u, a1=%d, a2=%d, a3=%u, a4=%u, a5=\"%s\", a6=%u\n",
			ctx->obj->obj_id, a0, a1, a2, a3, a4->obj_id, a5, a6);
	(void)noop;
}

log_handler_func_t log_funcs[2] = {test_log_handler, test_log_handler};
int main(int argc, char **argv)
{
	(void)argc;
	(void)argv;

	struct wl_interface dummy_intf = {0};
	dummy_intf.name = "test";

	struct wl_interface result_intf = {0};
	result_intf.name = "result";

	struct wl_message msg;
	msg.name = "test";
	msg.signature = "2nhiu?osu";
	const struct wl_interface *typevec[] = {&result_intf, NULL, NULL, NULL,
			&result_intf, NULL, NULL};
	msg.types = typevec;
	ffi_type *types_client[] = {&ffi_type_pointer, &ffi_type_pointer,
			&ffi_type_pointer, &ffi_type_sint, &ffi_type_sint32,
			&ffi_type_uint32, &ffi_type_pointer, &ffi_type_pointer,
			&ffi_type_uint32};
	ffi_type *types_server[] = {&ffi_type_pointer, &ffi_type_pointer,
			&ffi_type_uint32, &ffi_type_sint, &ffi_type_sint32,
			&ffi_type_uint32, &ffi_type_pointer, &ffi_type_pointer,
			&ffi_type_uint32};
	ffi_cif cif_client;
	ffi_cif cif_server;
	ffi_prep_cif(&cif_client, FFI_DEFAULT_ABI, 8, &ffi_type_void,
			types_client);
	ffi_prep_cif(&cif_server, FFI_DEFAULT_ABI, 8, &ffi_type_void,
			types_server);

	struct message_tracker mt;
	init_message_tracker(&mt);
	struct wp_object *old_display = listset_get(&mt.objects, 1);
	listset_remove(&mt.objects, old_display);
	destroy_wp_object(NULL, old_display);

	struct fd_translation_map map;
	setup_translation_map(&map, false, COMP_NONE, 1);
	struct wp_object arg_obj;
	arg_obj.type = &dummy_intf;
	arg_obj.is_zombie = false;
	arg_obj.obj_id = 1;
	listset_insert(&map, &mt.objects, &arg_obj);

	struct wp_object obj;
	obj.type = &dummy_intf;
	obj.is_zombie = false;
	obj.obj_id = 0;

	struct context ctx = {.obj = &obj, .g = NULL};

	int actual_fdlen = 1;
	int fds[1] = {99};
	uint32_t new_id = 51;
	uint32_t payload[] = {new_id, 11, (uint32_t)-1, arg_obj.obj_id, 13,
			0x61626162, 0x61626162, 0x61626162, 0x00000061, 777};
	int actual_length = (int)(sizeof(payload) / sizeof(uint32_t));

	bool all_success = true;
	int fds_used;
	for (int fdlen = actual_fdlen; fdlen >= 0; fdlen--) {
		for (int length = actual_length; length >= 0; length--) {
			bool expect_success = fdlen == actual_fdlen &&
					      length == actual_length;
			printf("Trying: %d/%d %d/%d\n", length, actual_length,
					fdlen, actual_fdlen);

			called = false;
			fds_used = 0;
			invoke_msg_handler(&cif_client, &dummy_intf, &msg, true,
					payload, length, fds, fdlen, &fds_used,
					(void (*)(void))testfn_client, &ctx,
					&mt, &map);
			all_success &= called == expect_success;
			if (called != expect_success) {
				wp_log(WP_ERROR,
						"client FAIL at %d/%d chars, %d/%d fds",
						length, actual_length, fdlen,
						actual_fdlen);
			}

			struct wp_object *new_obj =
					listset_get(&mt.objects, new_id);
			if (new_obj) {
				listset_remove(&mt.objects, new_obj);
				destroy_wp_object(&map, new_obj);
			}

			called = false;
			fds_used = 0;
			invoke_msg_handler(&cif_server, &dummy_intf, &msg,
					false, payload, length, fds, fdlen,
					&fds_used,
					(void (*)(void))testfn_server, &ctx,
					&mt, &map);
			all_success &= called == expect_success;
			if (called != expect_success) {
				wp_log(WP_ERROR,
						"server FAIL at %d/%d chars, %d/%d fds",
						length, actual_length, fdlen,
						actual_fdlen);
			}
			new_obj = listset_get(&mt.objects, new_id);
			if (new_obj) {
				listset_remove(&mt.objects, new_obj);
				destroy_wp_object(&map, new_obj);
			}
		}
	}
	listset_remove(&mt.objects, &arg_obj);
	cleanup_message_tracker(&map, &mt);
	cleanup_translation_map(&map);

	printf("Net result: %s\n", all_success ? "pass" : "FAIL");
	return all_success ? EXIT_SUCCESS : EXIT_FAILURE;
}
