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

#ifdef HAS_DMABUF
#include <gbm.h>
#define TEST_2CPP_FORMAT GBM_FORMAT_GR88
#else
#define TEST_2CPP_FORMAT 0
#endif

static int update_file(int file_fd, struct gbm_bo *bo, size_t sz, int seqno)
{
	(void)bo;
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
	return (int)(end - start);
}

static int update_dmabuf(int file_fd, struct gbm_bo *bo, size_t sz, int seqno)
{
	(void)file_fd;
	if (rand() % 11 == 0) {
		/* no change */
		return 0;
	}

	void *map_handle = NULL;
	void *data = map_dmabuf(bo, true, &map_handle);
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

	unmap_dmabuf(bo, map_handle);
	return (int)(end - start);
}

static void combine_transfer_blocks(struct bytebuf_stack *blocks)
{
	size_t net_size = 0;
	for (int i = 0; i < blocks->count; i++) {
		net_size += blocks->data[i].size;
	}
	struct bytebuf ret_block;
	ret_block.size = net_size;
	ret_block.data = malloc(net_size);
	size_t pos = 0;
	for (int i = 0; i < blocks->count; i++) {
		memcpy(ret_block.data + pos, blocks->data[i].data,
				blocks->data[i].size);
		pos += blocks->data[i].size;
	}
	blocks->data[0] = ret_block;
	blocks->count = 1;
}

static bool check_match(int orig_fd, int copy_fd, struct gbm_bo *orig_bo,
		struct gbm_bo *copy_bo)
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

	void *ohandle = NULL, *chandle = NULL;
	void *cdata = NULL, *odata = NULL;
	if (otype == FDC_FILE) {
		cdata = mmap(NULL, csz, PROT_READ, MAP_SHARED, copy_fd, 0);
		if (cdata == MAP_FAILED) {
			return false;
		}
		odata = mmap(NULL, osz, PROT_READ, MAP_SHARED, orig_fd, 0);
		if (odata == MAP_FAILED) {
			munmap(cdata, csz);
			return false;
		}
	} else if (otype == FDC_DMABUF) {
		cdata = map_dmabuf(copy_bo, false, &chandle);
		if (cdata == MAP_FAILED) {
			return false;
		}
		odata = map_dmabuf(orig_bo, false, &ohandle);
		if (odata == MAP_FAILED) {
			unmap_dmabuf(copy_bo, chandle);
			return false;
		}
	}

	bool pass = memcmp(cdata, odata, csz) == 0;

	if (otype == FDC_FILE) {
		munmap(odata, osz);
		munmap(cdata, csz);
	} else if (otype == FDC_DMABUF) {
		unmap_dmabuf(orig_bo, ohandle);
		unmap_dmabuf(copy_bo, chandle);
	}

	if (!pass) {
		wp_log(WP_ERROR, "Mirrored file descriptor contents differ");
	}

	return pass;
}

static bool test_transfer(struct fd_translation_map *src_map,
		struct fd_translation_map *dst_map, int rid, int ndiff,
		struct render_data *render_data)
{

	struct transfer_stack transfers;
	transfers.size = 1;
	transfers.count = 0;
	transfers.data = calloc(1, sizeof(struct transfer));
	struct bytebuf_stack blocks;
	blocks.size = 1;
	blocks.count = 0;
	blocks.data = calloc(1, sizeof(struct bytebuf));

	struct shadow_fd *src_shadow = get_shadow_for_rid(src_map, rid);
	collect_update(src_map, src_shadow, &transfers, &blocks);

	if (ndiff == 0) {
		free(transfers.data);
		free(blocks.data);
		if (transfers.count > 0) {
			wp_log(WP_ERROR,
					"Collecting updates gave a transfer when none was expected",
					transfers.count);
			return false;
		}
		return true;
	}
	if (transfers.count != 1) {
		wp_log(WP_ERROR,
				"Collecting updates gave a unexpected number (%d) of transfers",
				transfers.count);
		free(transfers.data);
		free(blocks.data);
		return false;
	}

	combine_transfer_blocks(&blocks);
	apply_update(dst_map, render_data, &transfers.data[0], &blocks.data[0]);
	free(blocks.data[0].data);
	free(transfers.data);
	free(blocks.data);

	/* first round, this only exists after the transfer */
	struct shadow_fd *dst_shadow = get_shadow_for_rid(dst_map, rid);

	return check_match(src_shadow->fd_local, dst_shadow->fd_local,
			src_shadow->dmabuf_bo, dst_shadow->dmabuf_bo);
}

/* This test closes the provided file fd */
static bool test_mirror(int new_file_fd, size_t sz,
		int (*update)(int fd, struct gbm_bo *bo, size_t sz, int seqno),
		enum compression_mode comp_mode, int n_src_threads,
		int n_dst_threads, struct render_data *rd,
		struct dmabuf_slice_data *slice_data)
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

	size_t fdsz = 0;
	fdcat_t fdtype = get_fd_type(new_file_fd, &fdsz);
	struct shadow_fd *src_shadow = translate_fd(&src_map, rd, new_file_fd,
			fdtype, fdsz, slice_data, false);
	struct shadow_fd *dst_shadow = NULL;
	int rid = src_shadow->remote_id;

	bool pass = true;
	for (int i = 0; i < 5; i++) {
		bool fwd = i == 0 || i % 2;

		int target_fd = fwd ? src_shadow->fd_local
				    : dst_shadow->fd_local;
		struct gbm_bo *target_bo = fwd ? src_shadow->dmabuf_bo
					       : dst_shadow->dmabuf_bo;
		int ndiff = i > 0 ? (*update)(target_fd, target_bo, sz, i)
				  : (int)sz;
		if (ndiff == -1) {
			pass = false;
			break;
		}
		bool subpass;
		if (fwd) {
			src_shadow->is_dirty = true;
			damage_everything(&src_shadow->damage);
			subpass = test_transfer(
					&src_map, &dst_map, rid, ndiff, rd);
		} else {
			dst_shadow->is_dirty = true;
			damage_everything(&dst_shadow->damage);
			subpass = test_transfer(
					&dst_map, &src_map, rid, ndiff, rd);
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

	/* to avoid warnings when the driver dmabuf size constraints require
	 * significant alignment, the width/height are already 64 aligned */
	size_t test_width = 256;
	size_t test_height = 320;
	size_t test_cpp = 2;

	size_t test_size = test_width * test_height * test_cpp;
	uint8_t *test_pattern = malloc(test_size);
	for (size_t i = 0; i < test_size; i++) {
		test_pattern[i] = (uint8_t)i;
	}

	struct render_data rd = {
			.drm_node_path = NULL,
			.drm_fd = -1,
			.dev = NULL,
			.disabled = false,
	};
	bool has_dmabuf = TEST_2CPP_FORMAT != 0;
	if (has_dmabuf && init_render_data(&rd) == -1) {
		has_dmabuf = false;
	}

	struct dmabuf_slice_data slice_data = {.width = (uint32_t)test_width,
			.height = (uint32_t)test_height,
			.format = TEST_2CPP_FORMAT,
			.num_planes = 1,
			.modifier = 0,
			.offsets = {0, 0, 0, 0},
			.strides = {(uint32_t)(test_width * test_cpp), 0, 0, 0},
			.using_planes = {true, false, false, false}};

	bool all_success = true;
	srand(0);
	for (size_t c = 0; c < sizeof(comp_modes) / sizeof(comp_modes[0]);
			c++) {
		for (int gt = 1; gt <= 5; gt++) {
			for (int rt = 1; rt <= 3; rt++) {
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

				bool pass = test_mirror(file_fd, test_size,
						update_file, comp_modes[c], gt,
						rt, &rd, &slice_data);

				printf("  FILE comp=%d src_thread=%d dst_thread=%d, %s\n",
						(int)c, gt, rt,
						pass ? "pass" : "FAIL");
				all_success &= pass;

				if (has_dmabuf) {
					struct gbm_bo *bo = make_dmabuf(&rd,
							(const char *)test_pattern,
							test_size, &slice_data);
					if (!bo) {
						has_dmabuf = false;
						continue;
					}
					int dmafd = export_dmabuf(bo);
					if (dmafd == -1) {
						has_dmabuf = false;
						continue;
					}
					destroy_dmabuf(bo);

					bool dpass = test_mirror(dmafd,
							test_size,
							update_dmabuf,
							comp_modes[c], gt, rt,
							&rd, &slice_data);

					printf("DMABUF comp=%d src_thread=%d dst_thread=%d, %s\n",
							(int)c, gt, rt,
							dpass ? "pass"
							      : "FAIL");
					all_success &= dpass;
				}
			}
		}
	}

	cleanup_render_data(&rd);
	free(test_pattern);

	printf("All pass: %c\n", all_success ? 'Y' : 'n');
	return all_success ? EXIT_SUCCESS : EXIT_FAILURE;
}
