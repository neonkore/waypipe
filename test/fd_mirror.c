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

#define _GNU_SOURCE
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <sys/mman.h>

static const enum compression_mode comp_modes[] = {
#ifdef HAS_LZ4
		COMP_LZ4,
#endif
#ifdef HAS_ZSTD
		COMP_ZSTD,
#endif
		COMP_NONE,
};

static int update_file(int file_fd, size_t sz, int seqno)
{
	if (rand() % 11 == 0) {
		/* no change */
		return 0;
	}

	void *data = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_SHARED, file_fd,
			0);
	if (data == MAP_FAILED) {
		return -1;
	}

	size_t start = (size_t)rand() % sz;
	size_t end = (size_t)rand() % sz;
	if (start > end) {
		size_t tmp = start;
		start = end;
		end = tmp;
	}
	memset((char *)data + start, seqno, end - start);

	munmap(data, sz);
	return end - start;
}

static void combine_transfer_blocks(struct transfer *transfer,
		struct bytebuf *ret_block, int nblocks, struct bytebuf *blocks)
{
	size_t net_size = 0;
	for (int i = 0; i < nblocks; i++) {
		net_size += blocks[i].size;
	}
	ret_block->size = net_size;
	ret_block->data = malloc(net_size);
	size_t pos = 0;
	for (int i = 0; i < nblocks; i++) {
		memcpy(ret_block->data + pos, blocks[i].data, blocks[i].size);
		pos += blocks[i].size;
	}
	transfer->subtransfers = ret_block;
	transfer->nblocks = 1;
}

static bool check_match(int orig_fd, int copy_fd)
{
	size_t csz = 0, osz = 0;
	fdcat_t ctype = get_fd_type(copy_fd, &csz);
	fdcat_t otype = get_fd_type(orig_fd, &osz);
	if (ctype != otype || csz != osz) {
		wp_log(WP_ERROR,
				"Mirrored file descriptor has different type or size: ot=%d ct=%d | os=%d cs=%d",
				otype, ctype, (int)osz, (int)csz);
		return false;
	}

	void *cdata = mmap(NULL, csz, PROT_READ, MAP_SHARED, copy_fd, 0);
	if (cdata == MAP_FAILED) {
		return false;
	}
	void *odata = mmap(NULL, osz, PROT_READ, MAP_SHARED, orig_fd, 0);
	if (odata == MAP_FAILED) {
		munmap(cdata, csz);
		return false;
	}

	bool pass = memcmp(cdata, odata, csz) == 0;

	munmap(odata, osz);
	munmap(cdata, csz);
	if (!pass) {
		wp_log(WP_ERROR, "Mirrored file descriptor contents differ");
	}

	return pass;
}

static bool test_transfer(struct fd_translation_map *src_map,
		struct fd_translation_map *dst_map, int rid, int ndiff)
{
	int ntransfers = 0, nblocks = 0;
	struct transfer transfers[10];
	struct bytebuf blocks[20];

	struct shadow_fd *src_shadow = get_shadow_for_rid(src_map, rid);
	collect_update(src_map, src_shadow, &ntransfers, transfers, &nblocks,
			blocks);

	if (ndiff == 0) {
		if (ntransfers > 0) {
			wp_log(WP_ERROR,
					"Collecting updates gave a transfer when none was expected",
					ntransfers);
			return false;
		}
		return true;
	}
	if (ntransfers != 1) {
		wp_log(WP_ERROR,
				"Collecting updates gave a unexpected number (%d) of transfers",
				ntransfers);
		return false;
	}

	struct transfer res_transfer = transfers[0];
	struct bytebuf ret_block;
	combine_transfer_blocks(&res_transfer, &ret_block, nblocks, blocks);
	apply_update(dst_map, NULL, &res_transfer);
	free(ret_block.data);

	/* first round, this only exists after the transfer */
	struct shadow_fd *dst_shadow = get_shadow_for_rid(dst_map, rid);

	return check_match(src_shadow->fd_local, dst_shadow->fd_local);
}

/* This test closes the provided file fd */
static bool test_mirror(int new_file_fd, size_t sz,
		int (*update)(int fd, size_t sz, int seqno),
		enum compression_mode comp_mode, int n_src_threads,
		int n_dst_threads)
{
	struct fd_translation_map src_map;
	setup_translation_map(&src_map, false, comp_mode, n_src_threads);

	struct fd_translation_map dst_map;
	setup_translation_map(&dst_map, true, comp_mode, n_dst_threads);

	// Force multithreading
	if (n_src_threads > 1) {
		src_map.diffcomp_thread_threshold = 1000;
		src_map.comp_thread_threshold = 1000;
	}
	if (n_dst_threads > 1) {
		dst_map.diffcomp_thread_threshold = 1000;
		dst_map.comp_thread_threshold = 1000;
	}

	struct shadow_fd *src_shadow =
			translate_fd(&src_map, NULL, new_file_fd, NULL, false);
	struct shadow_fd *dst_shadow = NULL;
	int rid = src_shadow->remote_id;

	bool pass = true;
	for (int i = 0; i < 5; i++) {
		bool fwd = i == 0 || i % 2;

		int target_fd = fwd ? src_shadow->fd_local
				    : dst_shadow->fd_local;
		int ndiff = i > 0 ? (*update)(target_fd, sz, i) : (int)sz;
		if (ndiff == -1) {
			pass = false;
			break;
		}
		bool subpass;
		if (fwd) {
			src_shadow->is_dirty = true;
			damage_everything(&src_shadow->damage);
			subpass = test_transfer(&src_map, &dst_map, rid, ndiff);
		} else {
			dst_shadow->is_dirty = true;
			damage_everything(&dst_shadow->damage);
			subpass = test_transfer(&dst_map, &src_map, rid, ndiff);
		}
		pass &= subpass;
		if (!pass) {
			break;
		}

		dst_shadow = get_shadow_for_rid(&dst_map, rid);
	}

	cleanup_translation_map(&src_map);
	cleanup_translation_map(&dst_map);
	return pass;
}

log_handler_func_t log_funcs[2] = {NULL, test_log_handler};
int main(int argc, char **argv)
{
	(void)argc;
	(void)argv;

	if (mkdir("test", S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) == -1 &&
			errno != EEXIST) {
		wp_log(WP_ERROR,
				"Not allowed to create test directory, cannot run tests.");
		return EXIT_FAILURE;
	}

	bool all_success = true;
	srand(0);
	for (size_t c = 0; c < sizeof(comp_modes) / sizeof(comp_modes[0]);
			c++) {
		for (int gt = 1; gt <= 5; gt++) {
			for (int rt = 1; rt <= 3; rt++) {
				size_t test_size = (1u << 15) + 259;
				uint8_t *test_pattern = malloc(test_size);
				for (size_t i = 0; i < test_size; i++) {
					test_pattern[i] = (uint8_t)i;
				}

				int file_fd = open("test/file",
						O_CREAT | O_RDWR | O_TRUNC,
						0644);
				if (file_fd == -1) {
					wp_log(WP_ERROR,
							"Failed to create test file: %s",
							strerror(errno));
					continue;
				}
				if (write(file_fd, test_pattern, test_size) !=
						(ssize_t)test_size) {
					wp_log(WP_ERROR,
							"Failed to write to test file: %s",
							strerror(errno));
					close(file_fd);
					continue;
				}
				free(test_pattern);

				bool pass = test_mirror(file_fd, test_size,
						update_file, comp_modes[c], gt,
						rt);

				printf("Tested comp=%d src_thread=%d dst_thread=%d, %s\n",
						(int)c, gt, rt,
						pass ? "pass" : "FAIL");
				all_success &= pass;
			}
		}
	}

	return all_success ? EXIT_SUCCESS : EXIT_FAILURE;
}
