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

#include "common.h"
#include "parsing.h"
#include "shadow.h"
#include "util.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "protocol-test-proto.h"

/* from parsing.c */
bool size_check(const struct msg_data *data, const uint32_t *payload,
		unsigned int true_length, int fd_length);

void do_xtype_req_blue(struct context *ctx, const char *interface,
		uint32_t version, struct wp_object *id, int b, int32_t c,
		uint32_t d, struct wp_object *e, const char *f, uint32_t g)
{
	char buf[256];
	sprintf(buf, "%s %u %u %d %d %u %u %s %u", interface, version,
			id ? id->obj_id : 0, b, c, d, e ? e->obj_id : 0, f, g);
	printf("%s\n", buf);
	ctx->drop_this_msg =
			strcmp(buf, "babacba 4441 992 7771 3331 4442 991 (null) 4443") !=
			0;
}
void do_xtype_evt_yellow(struct context *ctx, uint32_t c)
{
	char buf[256];
	sprintf(buf, "%u", c);
	printf("%s\n", buf);
	ctx->drop_this_msg = strcmp(buf, "4441") != 0;
}
void do_ytype_req_green(struct context *ctx, uint32_t a, const char *b,
		const char *c, int d, const char *e, struct wp_object *f,
		uint32_t g_count, const uint8_t *g_val)
{
	char buf[256];
	sprintf(buf, "%u %s %s %d %s %u %u %x|%x|%x|%x|%x|%x|%x|%x", a, b, c, d,
			e, f ? f->obj_id : 0, g_count, g_val[0], g_val[1],
			g_val[2], g_val[3], g_val[4], g_val[5], g_val[6],
			g_val[7]);
	printf("%s\n", buf);
	ctx->drop_this_msg =
			strcmp(buf, "4441 bea (null) 7771 cbbc 991 8 81|80|81|80|90|99|99|99") !=
			0;
}
void do_ytype_evt_red(struct context *ctx, struct wp_object *a, int32_t b,
		int c, struct wp_object *d, int32_t e, int32_t f,
		struct wp_object *g, int32_t h, uint32_t i, const char *j,
		int k, uint32_t l_count, const uint8_t *l_val, uint32_t n,
		const char *m, struct wp_object *o, int p, struct wp_object *q)
{
	char buf[256];
	sprintf(buf, "%u %d %d %u %d %d %u %d %u %s %d %u %x|%x|%x %u %s %u %d %u",
			a ? a->obj_id : 0, b, c, d ? d->obj_id : 0, e, f,
			g ? g->obj_id : 0, h, i, j, k, l_count, l_val[0],
			l_val[1], l_val[2], n, m, o ? o->obj_id : 0, p,
			q ? q->obj_id : 0);
	printf("%s\n", buf);
	ctx->drop_this_msg =
			strcmp(buf, "0 33330 8881 0 33331 33332 0 33333 44440 bcaba 8882 3 80|80|80 99990 (null) 992 8883 991") !=
			0;
}

struct wire_test {
	const struct wp_interface *intf;
	int msg_offset;
	int fds[4];
	uint32_t words[50];
	int nfds;
	int nwords;
};

static inline uint32_t pack_u32(uint8_t a0, uint8_t a1, uint8_t a2, uint8_t a3)
{
	union {
		uint8_t s[4];
		uint32_t v;
	} u;
	u.s[0] = a0;
	u.s[1] = a1;
	u.s[2] = a2;
	u.s[3] = a3;
	return u.v;
}

log_handler_func_t log_funcs[2] = {test_log_handler, test_log_handler};
int main(int argc, char **argv)
{
	(void)argc;
	(void)argv;

	struct message_tracker mt;
	init_message_tracker(&mt);
	struct wp_object *old_display = tracker_get(&mt, 1);
	tracker_remove(&mt, old_display);
	destroy_wp_object(old_display);

	struct wp_object xobj;
	xobj.type = &intf_xtype;
	xobj.is_zombie = false;
	xobj.obj_id = 991;
	tracker_insert(&mt, &xobj);

	struct wp_object yobj;
	yobj.type = &intf_ytype;
	yobj.is_zombie = false;
	yobj.obj_id = 992;
	tracker_insert(&mt, &yobj);

	struct context ctx = {.obj = &xobj, .g = NULL};

	struct wire_test tests[] = {
			{&intf_xtype, 0, {7771},
					{8, pack_u32(0x62, 0x61, 0x62, 0x61),
							pack_u32(0x63, 0x62,
									0x61,
									0),
							4441, yobj.obj_id, 3331,
							4442, xobj.obj_id, 0,
							4443},
					1, 10},
			{&intf_xtype, 1, {0}, {4441}, 0, 1},
			{&intf_ytype, 0, {7771},
					{4441, 4, pack_u32(0x62, 0x65, 0x61, 0),
							0, 5,
							pack_u32(0x63, 0x62,
									0x62,
									0x63),
							pack_u32(0, 0x99, 0x99,
									0x99),
							xobj.obj_id, 8,
							pack_u32(0x81, 0x80,
									0x81,
									0x80),
							pack_u32(0x90, 0x99,
									0x99,
									0x99)},
					1, 11},
			{&intf_ytype, 1, {8881, 8882, 8883},
					{7770, 33330, 7771, 33331, 33332, 7773,
							33333, 44440, 6,
							pack_u32(0x62, 0x63,
									0x61,
									0x62),
							pack_u32(0x61, 0, 0x99,
									0x99),
							3,
							pack_u32(0x80, 0x80,
									0x80,
									0x11),
							99990, 0, yobj.obj_id,
							xobj.obj_id},
					3, 17}};

	bool all_success = true;
	for (size_t t = 0; t < sizeof(tests) / sizeof(tests[0]); t++) {
		struct wire_test *wt = &tests[t];

		ctx.drop_this_msg = false;
		wp_callfn_t func = wt->intf->msgs[wt->msg_offset].call;

		(*func)(&ctx, wt->words, wt->fds, &mt);
		if (ctx.drop_this_msg) {
			all_success = false;
		}
		printf("Function call %s.%s, %s\n", wt->intf->name,
				get_nth_packed_string(wt->intf->msg_names,
						wt->msg_offset),
				ctx.drop_this_msg ? "FAIL" : "pass");

		for (int fdlen = wt->nfds; fdlen >= 0; fdlen--) {
			for (int length = wt->nwords; length >= 0; length--) {
				if (fdlen != wt->nfds && length < wt->nwords) {
					/* the fd check is really trivial */
					continue;
				}

				bool expect_success = (wt->nwords == length) &&
						      (fdlen == wt->nfds);
				printf("Trying: %d/%d words, %d/%d fds\n",
						length, wt->nwords, fdlen,
						wt->nfds);

				bool sp = size_check(
						&wt->intf->msgs[wt->msg_offset],
						wt->words, (unsigned int)length,
						fdlen);
				if (sp != expect_success) {
					wp_error("size check FAIL (%c, expected %c) at %d/%d chars, %d/%d fds",
							sp ? 'Y' : 'n',
							expect_success ? 'Y'
								       : 'n',
							length, wt->nwords,
							fdlen, wt->nfds);
				}
				all_success &= (sp == expect_success);
			}
		}
	}

	tracker_remove(&mt, &xobj);
	tracker_remove(&mt, &yobj);
	cleanup_message_tracker(&mt);

	printf("Net result: %s\n", all_success ? "pass" : "FAIL");
	return all_success ? EXIT_SUCCESS : EXIT_FAILURE;
}
