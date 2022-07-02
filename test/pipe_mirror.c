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
#include "shadow.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static int shadow_sync(struct fd_translation_map *src_map,
		struct fd_translation_map *dst_map)
{
	struct transfer_queue queue;
	memset(&queue, 0, sizeof(queue));
	pthread_mutex_init(&queue.async_recv_queue.lock, NULL);

	read_readable_pipes(src_map);

	for (struct shadow_fd_link *lcur = src_map->link.l_next,
				   *lnxt = lcur->l_next;
			lcur != &src_map->link;
			lcur = lnxt, lnxt = lcur->l_next) {
		struct shadow_fd *sfd = (struct shadow_fd *)lcur;
		collect_update(NULL, sfd, &queue, false);
		/* collecting updates can reset `remote_can_X` state, so
		 * garbage collect the sfd */
		destroy_shadow_if_unreferenced(sfd);
	}
	for (int i = 0; i < queue.end; i++) {
		if (queue.vecs[i].iov_len < 8) {
			cleanup_transfer_queue(&queue);
			wp_error("Invalid message");
			return -1;
		}
		const uint32_t *header =
				(const uint32_t *)queue.vecs[i].iov_base;
		struct bytebuf msg;
		msg.data = queue.vecs[i].iov_base;
		msg.size = transfer_size(header[0]);
		if (apply_update(dst_map, NULL, NULL, transfer_type(header[0]),
				    (int32_t)header[1], &msg) == -1) {
			wp_error("Update failed");
			cleanup_transfer_queue(&queue);
			return -1;
		}
	}
	flush_writable_pipes(dst_map);

	int nt = queue.end;
	cleanup_transfer_queue(&queue);
	return nt;
}

static int create_pseudo_pipe(bool can_read, bool can_write,
		bool half_open_socket, int *spec_end, int *opp_end)
{
	bool pipe_possible = can_read != can_write;
	int pipe_fds[2];
	if (half_open_socket || !pipe_possible) {
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, pipe_fds) == -1) {
			wp_error("Socketpair failed");
			return -1;
		}
		if (!can_read) {
			shutdown(pipe_fds[0], SHUT_RD);
		}
		if (!can_write) {
			shutdown(pipe_fds[0], SHUT_WR);
		}
	} else {
		if (pipe(pipe_fds) == -1) {
			wp_error("Pipe failed");
			return -1;
		}
		if (can_write) {
			int tmp = pipe_fds[0];
			pipe_fds[0] = pipe_fds[1];
			pipe_fds[1] = tmp;
		}
	}
	*spec_end = pipe_fds[0];
	*opp_end = pipe_fds[1];
	return 0;
}

static char fd_is_readable(int fd)
{
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1) {
		wp_error("fctnl F_GETFL failed!");
		return '?';
	}
	flags = flags & O_ACCMODE;
	return (flags == O_RDONLY || flags == O_RDWR) ? 'R' : 'n';
}

static char fd_is_writable(int fd)
{
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1) {
		wp_error("fctnl F_GETFL failed!");
		return '?';
	}
	flags = flags & O_ACCMODE;
	return (flags == O_WRONLY || flags == O_RDWR) ? 'W' : 'n';
}

static void print_pipe_state(const char *desc, struct pipe_state *p)
{
	printf("%s state: %c %c %c %c%s\n", desc, p->can_read ? 'R' : 'n',
			p->can_write ? 'W' : 'n',
			p->remote_can_read ? 'R' : 'n',
			p->remote_can_write ? 'W' : 'n',
			p->pending_w_shutdown ? " shutdownWpending" : "");
}

static bool test_pipe_mirror(bool close_src, bool can_read, bool can_write,
		bool half_open_socket, bool interpret_as_force_iw)
{
	if (can_read == can_write && half_open_socket) {
		return true;
	}
	printf("\nTesting:%s%s%s%s%s\n", can_read ? " read" : "",
			can_write ? " write" : "",
			half_open_socket ? " socket" : "",
			interpret_as_force_iw ? " force_iw" : "",
			close_src ? " close_src" : " close_dst");
	int spec_end, opp_end, anti_end = -1;
	if (create_pseudo_pipe(can_read, can_write, half_open_socket, &spec_end,
			    &opp_end) == -1) {
		return false;
	}

	struct fd_translation_map src_map;
	setup_translation_map(&src_map, false);

	struct fd_translation_map dst_map;
	setup_translation_map(&dst_map, true);

	bool success = true;

	/* Step 1: replicate */
	struct shadow_fd *src_shadow = translate_fd(&src_map, NULL, spec_end,
			FDC_PIPE, 0, NULL, interpret_as_force_iw);
	shadow_decref_transfer(src_shadow);
	int rid = src_shadow->remote_id;
	if (shadow_sync(&src_map, &dst_map) == -1) {
		success = false;
		goto cleanup;
	}
	struct shadow_fd *dst_shadow = get_shadow_for_rid(&dst_map, rid);
	if (!dst_shadow) {
		printf("Failed to create remote shadow structure\n");
		success = false;
		goto cleanup;
	}
	anti_end = dup(dst_shadow->fd_local);
	shadow_decref_transfer(dst_shadow);

	if (set_nonblocking(anti_end) == -1 || set_nonblocking(opp_end) == -1) {
		printf("Failed to make user fds nonblocking\n");
		success = false;
		goto cleanup;
	}
	printf("spec %c %c %c %c | opp %c %c | anti %c %c\n",
			can_read ? 'R' : 'n', can_write ? 'W' : 'n',
			fd_is_readable(spec_end), fd_is_writable(spec_end),
			fd_is_readable(opp_end), fd_is_writable(opp_end),
			fd_is_readable(anti_end), fd_is_writable(anti_end));

	print_pipe_state("dst", &dst_shadow->pipe);
	print_pipe_state("src", &src_shadow->pipe);

	/* Step 2: transfer tests */
	for (int i = 0; i < 4; i++) {
		bool from_src = i % 2;

		/* Smaller than a pipe buffer, so writing should always succeed
		 */
		char buf[4096];
		memset(buf, rand(), sizeof(buf));

		int write_fd = from_src ? opp_end : anti_end;
		int read_fd = from_src ? anti_end : opp_end;
		const char *target = from_src ? "src" : "dst";
		const char *antitarget = from_src ? "dst" : "src";

		if (fd_is_writable(write_fd) != 'W') {
			/* given proper replication, the reverse end should
			 * be readable */
			continue;
		}

		int amt = max(rand() % 4096, 1);
		ssize_t ret = write(write_fd, buf, (size_t)amt);
		if (ret == amt) {
			struct shadow_fd *mod_sfd =
					from_src ? src_shadow : dst_shadow;
			mod_sfd->pipe.readable = true;

			/* Write successful */
			if (shadow_sync(from_src ? &src_map : &dst_map,
					    from_src ? &dst_map : &src_map) ==
					-1) {
				success = false;
				goto cleanup;
			}

			bool believe_read = can_read && !interpret_as_force_iw;
			bool expect_transfer_fail =
					(from_src && !believe_read) ||
					(!from_src && !can_write);

			// todo: try multiple sync cycles (?)
			ssize_t rr = read(read_fd, buf, 4096);
			bool tf_pass = rr == amt;
			if (!expect_transfer_fail) {
				/* on some systems, pipe is bidirectional,
				 * making some additional transfers succeed.
				 * This is fine. */
				success = success && tf_pass;
			}
			const char *resdesc = tf_pass != expect_transfer_fail
							      ? "expected"
							      : "unexpected";
			if (tf_pass) {
				printf("Send packet to %s, and received it from %s, %s\n",
						target, antitarget, resdesc);
			} else {
				printf("Failed to receive packet from %s, %d %zd %s, %s\n",
						antitarget, read_fd, rr,
						strerror(errno), resdesc);
			}
		}
	}

	/* Step 3: close one end, and verify that the other end is closed */
	// TODO: test partial shutdowns as well, all 2^4 cases for a single
	// cycle; and test epipe closing by queuing additional data
	struct shadow_fd *cls_shadow = close_src ? src_shadow : dst_shadow;
	if (close_src) {
		checked_close(opp_end);
		opp_end = -1;
	} else {
		checked_close(anti_end);
		anti_end = -1;
	}

	bool shutdown_deletes = (cls_shadow->pipe.can_read &&
				 !cls_shadow->pipe.can_write);
	/* Special cases, which aren't very important */
	shutdown_deletes |= (interpret_as_force_iw &&
			     !cls_shadow->pipe.can_write && close_src);

	cls_shadow->pipe.readable = cls_shadow->pipe.can_read;
	cls_shadow->pipe.writable = cls_shadow->pipe.can_write;

	if (shadow_sync(close_src ? &src_map : &dst_map,
			    close_src ? &dst_map : &src_map) == -1) {
		success = false;
		goto cleanup;
	}
	bool deleted_shadows = true;
	if (dst_map.link.l_next != &dst_map.link) {
		print_pipe_state("dst", &dst_shadow->pipe);
		deleted_shadows = false;
	}
	if (src_map.link.l_next != &src_map.link) {
		print_pipe_state("src", &src_shadow->pipe);
		deleted_shadows = false;
	}

	bool correct_teardown = deleted_shadows == shutdown_deletes;
	success = success && correct_teardown;
	printf("Deleted shadows: %c (expected %c)\n",
			deleted_shadows ? 'Y' : 'n',
			shutdown_deletes ? 'Y' : 'n');

	printf("Test: %s\n", success ? "pass" : "FAIL");
cleanup:
	if (anti_end != -1) {
		checked_close(anti_end);
	}
	if (opp_end != -1) {
		checked_close(opp_end);
	}
	cleanup_translation_map(&src_map);
	cleanup_translation_map(&dst_map);

	return success;
}

log_handler_func_t log_funcs[2] = {NULL, test_log_handler};
int main(int argc, char **argv)
{
	(void)argc;
	(void)argv;

	struct sigaction act;
	act.sa_handler = SIG_IGN;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	if (sigaction(SIGPIPE, &act, NULL) == -1) {
		printf("Sigaction failed\n");
		return EXIT_SUCCESS;
	}

	srand(0);
	bool all_success = true;
	for (uint32_t bits = 0; bits < 32; bits++) {
		bool pass = test_pipe_mirror(bits & 1, bits & 2, bits & 4,
				bits & 8, bits & 16);
		all_success = all_success && pass;
	}
	printf("\nSuccess: %c\n", all_success ? 'Y' : 'n');
	return all_success ? EXIT_SUCCESS : EXIT_FAILURE;
}
