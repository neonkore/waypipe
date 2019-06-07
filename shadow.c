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

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

bool fdcat_ispipe(fdcat_t t)
{
	return t == FDC_PIPE_IR || t == FDC_PIPE_RW || t == FDC_PIPE_IW;
}

struct shadow_fd *get_shadow_for_local_fd(
		struct fd_translation_map *map, int lfd)
{
	for (struct shadow_fd *cur = map->list; cur; cur = cur->next) {
		if (cur->fd_local == lfd) {
			return cur;
		}
	}
	return NULL;
}
struct shadow_fd *get_shadow_for_rid(struct fd_translation_map *map, int rid)
{
	for (struct shadow_fd *cur = map->list; cur; cur = cur->next) {
		if (cur->remote_id == rid) {
			return cur;
		}
	}
	return NULL;
}
static void destroy_unlinked_sfd(
		struct fd_translation_map *map, struct shadow_fd *shadow)
{
	if (shadow->type == FDC_FILE) {
		munmap(shadow->file_mem_local, shadow->file_size);
		free(shadow->file_mem_mirror);
		free(shadow->file_diff_buffer);
		if (shadow->file_shm_buf_name[0]) {
			shm_unlink(shadow->file_shm_buf_name);
		}
	} else if (shadow->type == FDC_DMABUF) {
		destroy_dmabuf(shadow->dmabuf_bo);
		free(shadow->dmabuf_mem_mirror);
		free(shadow->dmabuf_diff_buffer);
	} else if (fdcat_ispipe(shadow->type)) {
		if (shadow->pipe_fd != shadow->fd_local &&
				shadow->pipe_fd != -1 &&
				shadow->pipe_fd != -2) {
			close(shadow->pipe_fd);
		}
		free(shadow->pipe_recv.data);
		free(shadow->pipe_send.data);
	}
	if (shadow->fd_local != -2 && shadow->fd_local != -1) {
		if (close(shadow->fd_local) == -1) {
			wp_log(WP_ERROR, "Incorrect close(%d): %s",
					shadow->fd_local, strerror(errno));
		}
	}
	free(shadow);
	(void)map;
}

void cleanup_translation_map(struct fd_translation_map *map)
{
	struct shadow_fd *cur = map->list;
	map->list = NULL;
	while (cur) {
		struct shadow_fd *shadow = cur;
		cur = shadow->next;
		shadow->next = NULL;
		destroy_unlinked_sfd(map, shadow);
	}
	cleanup_render_data(&map->rdata);
}
fdcat_t get_fd_type(int fd, size_t *size)
{
	struct stat fsdata;
	memset(&fsdata, 0, sizeof(fsdata));
	int ret = fstat(fd, &fsdata);
	if (ret == -1) {
		wp_log(WP_ERROR, "The fd %d is not file-like: %s", fd,
				strerror(errno));
		return FDC_UNKNOWN;
	} else if (S_ISREG(fsdata.st_mode)) {
		if (size) {
			*size = (size_t)fsdata.st_size;
		}
		return FDC_FILE;
	} else if (S_ISFIFO(fsdata.st_mode) || S_ISCHR(fsdata.st_mode)) {
		if (!S_ISFIFO(fsdata.st_mode)) {
			wp_log(WP_ERROR,
					"The fd %d, size %ld, mode %x is a character device. Proceeding under the assumption that it is pipe-like.",
					fd, fsdata.st_size, fsdata.st_mode);
		}
		int flags = fcntl(fd, F_GETFL, 0);
		if (flags == -1) {
			wp_log(WP_ERROR, "fctnl F_GETFL failed!");
		}
		if ((flags & O_ACCMODE) == O_RDONLY) {
			return FDC_PIPE_IR;
		} else if ((flags & O_ACCMODE) == O_WRONLY) {
			return FDC_PIPE_IW;
		} else {
			return FDC_PIPE_RW;
		}
	} else if (is_dmabuf(fd)) {
		return FDC_DMABUF;
	} else {
		wp_log(WP_ERROR,
				"The fd %d has an unusual mode %x (type=%x): blk=%d chr=%d dir=%d lnk=%d reg=%d fifo=%d sock=%d; expect an application crash!",
				fd, fsdata.st_mode, fsdata.st_mode & __S_IFMT,
				S_ISBLK(fsdata.st_mode),
				S_ISCHR(fsdata.st_mode),
				S_ISDIR(fsdata.st_mode),
				S_ISLNK(fsdata.st_mode),
				S_ISREG(fsdata.st_mode),
				S_ISFIFO(fsdata.st_mode),
				S_ISSOCK(fsdata.st_mode), strerror(errno));
		return FDC_UNKNOWN;
	}
}

struct shadow_fd *translate_fd(struct fd_translation_map *map, int fd,
		struct dmabuf_slice_data *info)
{
	struct shadow_fd *cur = map->list;
	while (cur) {
		if (cur->fd_local == fd) {
			return cur;
		}
		cur = cur->next;
	}

	// Create a new translation map.
	struct shadow_fd *shadow = calloc(1, sizeof(struct shadow_fd));
	shadow->next = map->list;
	map->list = shadow;
	shadow->fd_local = fd;
	shadow->file_mem_local = NULL;
	shadow->file_mem_mirror = NULL;
	shadow->file_size = (size_t)-1;
	shadow->remote_id = (map->max_local_id++) * map->local_sign;
	shadow->type = FDC_UNKNOWN;
	// File changes must be propagated
	shadow->is_dirty = true;
	shadow->dirty_interval_max = INT32_MAX;
	shadow->dirty_interval_min = INT32_MIN;
	shadow->has_owner = false;
	/* Start the number of expected transfers to channel remaining at one,
	 * and number of protocol objects referencing this shadow_fd at zero.*/
	shadow->refcount_transfer = 1;
	shadow->refcount_protocol = 0;

	wp_log(WP_DEBUG, "Creating new shadow buffer for local fd %d", fd);

	size_t fsize = 0;
	shadow->type = get_fd_type(fd, &fsize);
	if (shadow->type == FDC_FILE) {
		// We have a file-like object
		shadow->file_size = fsize;
		// both r/w permissions, because the size the allocates the
		// memory does not always have to be the size that modifies it
		shadow->file_mem_local = mmap(NULL, shadow->file_size,
				PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		if (!shadow->file_mem_local) {
			wp_log(WP_ERROR, "Mmap failed!");
			return shadow;
		}
		// This will be created at the first transfer
		shadow->file_mem_mirror = NULL;
	} else if (fdcat_ispipe(shadow->type)) {
		// Make this end of the pipe nonblocking, so that we can include
		// it in our main loop.
		set_fnctl_flag(shadow->fd_local, O_NONBLOCK);
		shadow->pipe_fd = shadow->fd_local;

		// Allocate a reasonably small read buffer
		shadow->pipe_recv.size = 16384;
		shadow->pipe_recv.data = calloc(shadow->pipe_recv.size, 1);

		shadow->pipe_onlyhere = true;
	} else if (shadow->type == FDC_DMABUF) {
		shadow->dmabuf_size = 0;

		init_render_data(&map->rdata);
		shadow->dmabuf_bo = import_dmabuf(&map->rdata, shadow->fd_local,
				&shadow->dmabuf_size, info);
		if (!shadow->dmabuf_bo) {
			return shadow;
		}
		if (info) {
			memcpy(&shadow->dmabuf_info, info,
					sizeof(struct dmabuf_slice_data));
		} else {
			// already zero initialized (no information).
		}
		// to be created on first transfer
		shadow->dmabuf_mem_mirror = NULL;
		shadow->dmabuf_diff_buffer = NULL;
		shadow->type = FDC_DMABUF;
	}
	return shadow;
}

/** Construct a very simple binary diff format, designed to be fast for small
 * changes in big files, and entire-file changes in essentially random files.
 * Tries not to read beyond the end of the input buffers, because they are often
 * mmap'd. Simultaneously updates the `base` buffer to match the `changed`
 * buffer.
 *
 * Requires that `diff` point to a memory buffer of size `size + 8`.
 */
static void construct_diff(size_t size, size_t range_min, size_t range_max,
		char *__restrict__ base, const char *__restrict__ changed,
		size_t *diffsize, char *__restrict__ diff)
{
	uint64_t nblocks = size / 8;
	uint64_t *__restrict__ base_blocks = (uint64_t *)base;
	const uint64_t *__restrict__ changed_blocks = (const uint64_t *)changed;
	uint64_t *__restrict__ diff_blocks = (uint64_t *)diff;
	uint64_t ntrailing = size - 8 * nblocks;
	uint64_t nskip = 0, ncopy = 0;
	uint64_t cursor = 0;
	uint64_t blockrange_min = range_min / 8;
	uint64_t blockrange_max = (range_max + 7) / 8;
	if (blockrange_max > nblocks) {
		blockrange_max = nblocks;
	}
	diff_blocks[0] = 0;
	bool skipping = true;
	/* we paper over gaps of a given window size, to avoid fine grained
	 * context switches */
	const uint64_t window_size = 128;
	uint64_t last_header = 0;
	for (uint64_t i = blockrange_min; i < blockrange_max; i++) {
		uint64_t changed_val = changed_blocks[i];
		uint64_t base_val = base_blocks[i];
		if (skipping) {
			if (base_val != changed_val) {
				skipping = false;
				last_header = cursor++;
				diff_blocks[last_header] = i << 32;
				nskip = 0;

				diff_blocks[cursor++] = changed_val;
				ncopy = 1;
				base_blocks[i] = changed_val;
			} else {
				nskip++;
			}
		} else {
			if (base_val == changed_val) {
				nskip++;
			} else {
				nskip = 0;
			}
			base_blocks[i] = changed_val;
			if (nskip > window_size) {
				skipping = true;
				cursor -= (nskip - 1);
				ncopy -= (nskip - 1);
				diff_blocks[last_header] |= i - (nskip - 1);
				ncopy = 0;
			} else {
				diff_blocks[cursor++] = changed_val;
				ncopy++;
			}
		}
	}
	// We do not add a final 'skip' block, because the unpacking routine
	if (!skipping) {
		diff_blocks[last_header] |= blockrange_max - nskip;
		cursor -= nskip;
	}
	if (ntrailing > 0) {
		for (uint64_t i = 0; i < ntrailing; i++) {
			diff[cursor * 8 + i] = changed[nblocks * 8 + i];
			base[cursor * 8 + i] = changed[nblocks * 8 + i];
		}
	}
	*diffsize = cursor * 8 + ntrailing;
}
static void apply_diff(size_t size, char *__restrict__ base, size_t diffsize,
		const char *__restrict__ diff)
{
	uint64_t nblocks = size / 8;
	uint64_t ndiffblocks = diffsize / 8;
	uint64_t *__restrict__ base_blocks = (uint64_t *)base;
	uint64_t *__restrict__ diff_blocks = (uint64_t *)diff;
	uint64_t ntrailing = size - 8 * nblocks;
	if (ntrailing != (diffsize - 8 * ndiffblocks)) {
		wp_log(WP_ERROR, "Trailing bytes mismatch for diff.");
		return;
	}
	for (uint64_t i = 0; i < ndiffblocks;) {
		uint64_t block = diff_blocks[i];
		uint64_t nfrom = block >> 32;
		uint64_t nto = (block << 32) >> 32;
		if (nto > nblocks || nfrom >= nto ||
				i + (nto - nfrom) >= ndiffblocks) {
			wp_log(WP_ERROR,
					"Invalid copy range [%ld,%ld) > %ld=nblocks or [%ld,%ld) > %ld=ndiffblocks",
					nfrom, nto, nblocks, i + 1,
					i + 1 + (nto - nfrom), ndiffblocks);
			return;
		}
		memcpy(base_blocks + nfrom, diff_blocks + i + 1,
				8 * (nto - nfrom));
		i += nto - nfrom + 1;
	}
	if (ntrailing > 0) {
		for (uint64_t i = 0; i < ntrailing; i++) {
			base[nblocks * 8 + i] = diff[ndiffblocks * 8 + i];
		}
	}
}

void collect_update(struct shadow_fd *cur, int *ntransfers,
		struct transfer transfers[])
{
	if (cur->type == FDC_FILE) {
		if (!cur->is_dirty) {
			// File is clean, we have no reason to believe
			// that its contents could have changed
			return;
		}
		// Clear dirty state
		cur->is_dirty = false;
		int intv_min = clamp(cur->dirty_interval_min, 0,
				(int)cur->file_size);
		int intv_max = clamp(cur->dirty_interval_max, 0,
				(int)cur->file_size);
		cur->dirty_interval_min = INT32_MAX;
		cur->dirty_interval_max = INT32_MIN;

		if (!cur->file_mem_mirror) {
			// increase space, to avoid overflow when
			// writing this buffer along with padding
			cur->file_mem_mirror =
					calloc(align(cur->file_size, 8), 1);
			// 8 extra bytes for worst case diff expansion
			cur->file_diff_buffer =
					calloc(align(cur->file_size + 8, 8), 1);
			memcpy(cur->file_mem_mirror, cur->file_mem_local,
					cur->file_size);
			// new transfer, we send file contents verbatim
			int nt = (*ntransfers)++;
			transfers[nt].data = cur->file_mem_mirror;
			transfers[nt].size = cur->file_size;
			transfers[nt].type = cur->type;
			transfers[nt].obj_id = cur->remote_id;
			transfers[nt].special = 0;
		}
		if (intv_min >= intv_max) {
			return;
		}
		bool delta = memcmp(cur->file_mem_local + intv_min,
					     (cur->file_mem_mirror + intv_min),
					     (size_t)(intv_max - intv_min)) !=
			     0;
		if (!delta) {
			return;
		}
		if (!cur->file_diff_buffer) {
			/* Create diff buffer by need for remote files
			 */
			cur->file_diff_buffer = calloc(cur->file_size + 8, 1);
		}

		size_t diffsize;
		wp_log(WP_DEBUG, "Diff construction start");
		construct_diff(cur->file_size, (size_t)intv_min,
				(size_t)intv_max, cur->file_mem_mirror,
				cur->file_mem_local, &diffsize,
				cur->file_diff_buffer);
		wp_log(WP_DEBUG, "Diff construction end: %ld/%ld", diffsize,
				cur->file_size);
		if (diffsize > 0) {
			int nt = (*ntransfers)++;
			transfers[nt].obj_id = cur->remote_id;
			transfers[nt].data = cur->file_diff_buffer;
			transfers[nt].type = cur->type;
			transfers[nt].size = diffsize;
			transfers[nt].special = 0;
		}
	} else if (cur->type == FDC_DMABUF) {
		// If buffer is clean, do not check for changes
		if (!cur->is_dirty) {
			return;
		}
		cur->is_dirty = false;

		bool first = false;
		if (!cur->dmabuf_mem_mirror) {
			cur->dmabuf_mem_mirror = calloc(1, cur->dmabuf_size);
			// 8 extra bytes for diff messages, or
			// alternatively for type header info
			size_t diffb_size =
					(size_t)max(sizeof(struct dmabuf_slice_data),
							8) +
					(size_t)align((int)cur->dmabuf_size, 8);
			cur->dmabuf_diff_buffer = calloc(diffb_size, 1);
			first = true;
		}
		void *handle = NULL;
		if (!cur->dmabuf_bo) {
			// ^ was not previously able to create buffer
			return;
		}
		void *data = map_dmabuf(cur->dmabuf_bo, false, &handle);
		if (!data) {
			return;
		}
		if (first) {
			// Write diff with a header, and build mirror,
			// only touching data once
			memcpy(cur->dmabuf_mem_mirror, data, cur->dmabuf_size);
			memcpy(cur->dmabuf_diff_buffer, &cur->dmabuf_info,
					sizeof(struct dmabuf_slice_data));
			memcpy(cur->dmabuf_diff_buffer +
							sizeof(struct dmabuf_slice_data),
					cur->dmabuf_mem_mirror,
					cur->dmabuf_size);
			// new transfer, we send file contents verbatim

			wp_log(WP_DEBUG, "Sending initial dmabuf");
			int nt = (*ntransfers)++;
			transfers[nt].data = cur->dmabuf_diff_buffer;
			transfers[nt].size = cur->dmabuf_size +
					     sizeof(struct dmabuf_slice_data);
			transfers[nt].type = cur->type;
			transfers[nt].obj_id = cur->remote_id;
			transfers[nt].special = 0;
		} else {
			bool delta = memcmp(cur->dmabuf_mem_mirror, data,
					cur->dmabuf_size);
			if (delta) {
				// TODO: damage region support!
				size_t diffsize;
				wp_log(WP_DEBUG, "Diff construction start");
				construct_diff(cur->dmabuf_size, 0,
						cur->dmabuf_size,
						cur->dmabuf_mem_mirror, data,
						&diffsize,
						cur->dmabuf_diff_buffer);
				wp_log(WP_DEBUG,
						"Diff construction end: %ld/%ld",
						diffsize, cur->dmabuf_size);

				int nt = (*ntransfers)++;
				transfers[nt].obj_id = cur->remote_id;
				transfers[nt].data = cur->dmabuf_diff_buffer;
				transfers[nt].type = cur->type;
				transfers[nt].size = diffsize;
				transfers[nt].special = 0;
			}
		}
		if (unmap_dmabuf(cur->dmabuf_bo, handle) == -1) {
			// there was an issue unmapping; unmap_dmabuf
			// will log error
			return;
		}
	} else if (fdcat_ispipe(cur->type)) {
		// Pipes always update, no matter what the message
		// stream indicates. Hence no cur->is_dirty flag check
		if (cur->pipe_recv.used > 0 || cur->pipe_onlyhere ||
				(cur->pipe_lclosed && !cur->pipe_rclosed)) {
			cur->pipe_onlyhere = false;
			wp_log(WP_DEBUG,
					"Adding update to pipe RID=%d, with %ld bytes, close %c",
					cur->remote_id, cur->pipe_recv.used,
					(cur->pipe_lclosed &&
							!cur->pipe_rclosed)
							? 'Y'
							: 'n');
			int nt = (*ntransfers)++;
			transfers[nt].data = cur->pipe_recv.data;
			transfers[nt].size = cur->pipe_recv.used;
			transfers[nt].type = cur->type;
			transfers[nt].obj_id = cur->remote_id;
			transfers[nt].special = 0;
			if (cur->pipe_lclosed && !cur->pipe_rclosed) {
				transfers[nt].special = 1;
				cur->pipe_rclosed = true;
				close(cur->pipe_fd);
				cur->pipe_fd = -2;
			}
			// clear
			cur->pipe_recv.used = 0;
		}
	}
}

void apply_update(struct fd_translation_map *map, const struct transfer *transf)
{
	struct shadow_fd *cur = map->list;
	bool found = false;
	while (cur) {
		if (cur->remote_id == transf->obj_id) {
			found = true;
			break;
		}

		cur = cur->next;
	}

	if (found) {
		if (cur->type == FDC_FILE) {
			if (transf->type != cur->type) {
				wp_log(WP_ERROR, "Transfer type mismatch %d %d",
						transf->type, cur->type);
			}

			// `memsize+8` is the worst-case diff expansion
			if (transf->size > cur->file_size + 8) {
				wp_log(WP_ERROR,
						"Transfer size mismatch %ld %ld",
						transf->size, cur->file_size);
			}
			apply_diff(cur->file_size, cur->file_mem_mirror,
					transf->size, transf->data);
			apply_diff(cur->file_size, cur->file_mem_local,
					transf->size, transf->data);
		} else if (fdcat_ispipe(cur->type)) {
			bool rw_match = cur->type == FDC_PIPE_RW &&
					transf->type == FDC_PIPE_RW;
			bool iw_match = cur->type == FDC_PIPE_IW &&
					transf->type == FDC_PIPE_IR;
			bool ir_match = cur->type == FDC_PIPE_IR &&
					transf->type == FDC_PIPE_IW;
			if (!rw_match && !iw_match && !ir_match) {
				wp_log(WP_ERROR,
						"Transfer type contramismatch %d %d",
						transf->type, cur->type);
			}

			ssize_t netsize = cur->pipe_send.used +
					  (ssize_t)transf->size;
			if (cur->pipe_send.size <= 1024) {
				cur->pipe_send.size = 1024;
			}
			while (cur->pipe_send.size < netsize) {
				cur->pipe_send.size *= 2;
			}
			if (cur->pipe_send.data) {
				cur->pipe_send.data = realloc(
						cur->pipe_send.data,
						cur->pipe_send.size);
			} else {
				cur->pipe_send.data =
						calloc(cur->pipe_send.size, 1);
			}
			memcpy(cur->pipe_send.data + cur->pipe_send.used,
					transf->data, transf->size);
			cur->pipe_send.used += (ssize_t)transf->size;

			// The pipe itself will be flushed/or closed later by
			// flush_writable_pipes
			cur->pipe_writable = true;

			if (transf->special) {
				cur->pipe_rclosed = true;
			}
		} else if (cur->type == FDC_DMABUF) {
			wp_log(WP_DEBUG, "Applying dmabuf damage");
			apply_diff(cur->dmabuf_size, cur->dmabuf_mem_mirror,
					transf->size, transf->data);
			void *handle = NULL;
			if (!cur->dmabuf_bo) {
				wp_log(WP_ERROR,
						"Applying update to nonexistent dma buffer object rid=%d",
						cur->remote_id);
				return;
			}
			void *data = map_dmabuf(cur->dmabuf_bo, true, &handle);
			if (!data) {
				return;
			}
			apply_diff(cur->dmabuf_size, data, transf->size,
					transf->data);
			if (unmap_dmabuf(cur->dmabuf_bo, handle) == -1) {
				// there was an issue unmapping; unmap_dmabuf
				// will log error
				return;
			}
		}
		return;
	}

	wp_log(WP_DEBUG, "Introducing new fd, remoteid=%d", transf->obj_id);
	struct shadow_fd *shadow = calloc(1, sizeof(struct shadow_fd));
	shadow->next = map->list;
	map->list = shadow;
	shadow->remote_id = transf->obj_id;
	shadow->fd_local = -1;
	shadow->type = transf->type;
	shadow->is_dirty = false;
	shadow->dirty_interval_max = INT32_MIN;
	shadow->dirty_interval_min = INT32_MAX;
	/* Start the object reference at one, so that, if it is owned by
	 * some known protocol object, it can not be deleted until the fd
	 * has at least be transferred over the Wayland connection */
	shadow->refcount_transfer = 1;
	shadow->refcount_protocol = 0;
	if (shadow->type == FDC_FILE) {
		shadow->file_mem_local = NULL;
		shadow->file_size = transf->size;
		shadow->file_mem_mirror = calloc(shadow->file_size, 1);
		// The first time only, the transfer data is a direct copy of
		// the source
		memcpy(shadow->file_mem_mirror, transf->data, transf->size);
		// The PID should be unique during the lifetime of the program
		sprintf(shadow->file_shm_buf_name, "/waypipe%d-data_%d",
				getpid(), shadow->remote_id);

		shadow->fd_local = shm_open(shadow->file_shm_buf_name,
				O_RDWR | O_CREAT | O_TRUNC, 0644);
		if (shadow->fd_local == -1) {
			wp_log(WP_ERROR,
					"Failed to create shm file for object %d: %s",
					shadow->remote_id, strerror(errno));
			return;
		}
		if (ftruncate(shadow->fd_local, shadow->file_size) == -1) {
			wp_log(WP_ERROR,
					"Failed to resize shm file %s to size %ld for reason: %s",
					shadow->file_shm_buf_name,
					shadow->file_size, strerror(errno));
			return;
		}
		shadow->file_mem_local = mmap(NULL, shadow->file_size,
				PROT_READ | PROT_WRITE, MAP_SHARED,
				shadow->fd_local, 0);
		memcpy(shadow->file_mem_local, shadow->file_mem_mirror,
				shadow->file_size);
	} else if (fdcat_ispipe(shadow->type)) {
		int pipedes[2];
		if (transf->type == FDC_PIPE_RW) {
			if (socketpair(AF_UNIX, SOCK_STREAM, 0, pipedes) ==
					-1) {
				wp_log(WP_ERROR,
						"Failed to create a socketpair: %s",
						strerror(errno));
				return;
			}
		} else {
			if (pipe(pipedes) == -1) {
				wp_log(WP_ERROR, "Failed to create a pipe: %s",
						strerror(errno));
				return;
			}
		}

		/* We pass 'fd_local' to the client, although we only read and
		 * write from pipe_fd if it exists. */
		if (transf->type == FDC_PIPE_IW) {
			// Read end is 0; the other process writes
			shadow->fd_local = pipedes[1];
			shadow->pipe_fd = pipedes[0];
			shadow->type = FDC_PIPE_IR;
		} else if (transf->type == FDC_PIPE_IR) {
			// Write end is 1; the other process reads
			shadow->fd_local = pipedes[0];
			shadow->pipe_fd = pipedes[1];
			shadow->type = FDC_PIPE_IW;
		} else { // FDC_PIPE_RW
			// Here, it doesn't matter which end is which
			shadow->fd_local = pipedes[0];
			shadow->pipe_fd = pipedes[1];
			shadow->type = FDC_PIPE_RW;
		}

		if (set_fnctl_flag(shadow->pipe_fd, O_NONBLOCK) == -1) {
			wp_log(WP_ERROR,
					"Failed to make private pipe end nonblocking: %s",
					strerror(errno));
			return;
		}

		// Allocate a reasonably small read buffer
		shadow->pipe_recv.size = 16384;
		shadow->pipe_recv.data = calloc(shadow->pipe_recv.size, 1);
		shadow->pipe_onlyhere = false;
	} else if (shadow->type == FDC_DMABUF) {
		wp_log(WP_DEBUG, "Creating remote DMAbuf of %d bytes",
				(int)transf->size);
		shadow->dmabuf_size = transf->size;
		// Create mirror from first transfer
		shadow->dmabuf_mem_mirror = calloc(shadow->dmabuf_size, 1);
		memcpy(shadow->dmabuf_mem_mirror, transf->data, transf->size);
		// The file can only actually be created when we know what type
		// it is?
		if (init_render_data(&map->rdata) == 1) {
			shadow->fd_local = -1;
			return;
		}
		struct dmabuf_slice_data *info =
				(struct dmabuf_slice_data *)transf->data;
		char *contents =
				transf->data + sizeof(struct dmabuf_slice_data);
		size_t contents_size =
				transf->size - sizeof(struct dmabuf_slice_data);

		shadow->dmabuf_bo = make_dmabuf(
				&map->rdata, contents, contents_size, info);
		if (!shadow->dmabuf_bo) {
			shadow->fd_local = -1;
			return;
		}
		memcpy(&shadow->dmabuf_info, info,
				sizeof(struct dmabuf_slice_data));
		shadow->fd_local = export_dmabuf(shadow->dmabuf_bo);
	} else {
		wp_log(WP_ERROR, "Creating unknown file type updates");
	}
}

static bool destroy_shadow_if_unreferenced(
		struct fd_translation_map *map, struct shadow_fd *sfd)
{
	if (sfd->refcount_protocol == 0 && sfd->refcount_transfer == 0 &&
			sfd->has_owner) {
		for (struct shadow_fd *cur = map->list, *prev = NULL; cur;
				prev = cur, cur = cur->next) {
			if (cur == sfd) {
				if (!prev) {
					map->list = cur->next;
				} else {
					prev->next = cur->next;
				}
				break;
			}
		}

		destroy_unlinked_sfd(map, sfd);
		return true;
	} else if (sfd->refcount_protocol < 0 || sfd->refcount_transfer < 0) {
		wp_log(WP_ERROR,
				"Negative refcount for rid=%d: %d protocol references, %d transfer references",
				sfd->remote_id, sfd->refcount_protocol,
				sfd->refcount_transfer);
	}
	return false;
}
bool shadow_decref_protocol(
		struct fd_translation_map *map, struct shadow_fd *sfd)
{
	sfd->refcount_protocol--;
	return destroy_shadow_if_unreferenced(map, sfd);
}

bool shadow_decref_transfer(
		struct fd_translation_map *map, struct shadow_fd *sfd)
{
	sfd->refcount_transfer--;
	return destroy_shadow_if_unreferenced(map, sfd);
}
struct shadow_fd *shadow_incref_protocol(struct shadow_fd *sfd)
{
	sfd->has_owner = true;
	sfd->refcount_protocol++;
	return sfd;
}
struct shadow_fd *shadow_incref_transfer(struct shadow_fd *sfd)
{
	sfd->refcount_transfer++;
	return sfd;
}

void decref_transferred_fds(struct fd_translation_map *map, int nfds, int fds[])
{
	for (int i = 0; i < nfds; i++) {
		struct shadow_fd *sfd = get_shadow_for_local_fd(map, fds[i]);
		shadow_decref_transfer(map, sfd);
	}
}
void decref_transferred_rids(
		struct fd_translation_map *map, int nids, int ids[])
{
	for (int i = 0; i < nids; i++) {
		struct shadow_fd *sfd = get_shadow_for_rid(map, ids[i]);
		shadow_decref_transfer(map, sfd);
	}
}

int count_npipes(const struct fd_translation_map *map)
{
	int np = 0;
	for (struct shadow_fd *cur = map->list; cur; cur = cur->next) {
		if (fdcat_ispipe(cur->type)) {
			np++;
		}
	}
	return np;
}
int fill_with_pipes(const struct fd_translation_map *map, struct pollfd *pfds,
		bool check_read)
{
	int np = 0;
	for (struct shadow_fd *cur = map->list; cur; cur = cur->next) {
		if (fdcat_ispipe(cur->type)) {
			if (!cur->pipe_lclosed) {
				pfds[np].fd = cur->pipe_fd;
				pfds[np].events = 0;
				if (check_read &&
						(cur->type == FDC_PIPE_RW ||
								cur->type == FDC_PIPE_IR)) {
					pfds[np].events |= POLLIN;
				}
				if (cur->pipe_send.used > 0) {
					pfds[np].events |= POLLOUT;
				}
				np++;
			}
		}
	}
	return np;
}

static struct shadow_fd *get_shadow_for_pipe_fd(
		struct fd_translation_map *map, int pipefd)
{
	for (struct shadow_fd *cur = map->list; cur; cur = cur->next) {
		if (fdcat_ispipe(cur->type) && cur->pipe_fd == pipefd) {
			return cur;
		}
	}
	return NULL;
}

void mark_pipe_object_statuses(
		struct fd_translation_map *map, int nfds, struct pollfd *pfds)
{
	for (int i = 0; i < nfds; i++) {
		int lfd = pfds[i].fd;
		struct shadow_fd *sfd = get_shadow_for_pipe_fd(map, lfd);
		if (!sfd) {
			wp_log(WP_ERROR,
					"Failed to find shadow struct for .pipe_fd=%d",
					lfd);
			continue;
		}
		if (pfds[i].revents & POLLIN) {
			sfd->pipe_readable = true;
		}
		if (pfds[i].revents & POLLOUT) {
			sfd->pipe_writable = true;
		}
		if (pfds[i].revents & POLLHUP) {
			sfd->pipe_lclosed = true;
		}
	}
}

void flush_writable_pipes(struct fd_translation_map *map)
{
	for (struct shadow_fd *cur = map->list; cur; cur = cur->next) {
		if (fdcat_ispipe(cur->type) && cur->pipe_writable &&
				cur->pipe_send.used > 0) {
			cur->pipe_writable = false;
			wp_log(WP_DEBUG, "Flushing %ld bytes into RID=%d",
					cur->pipe_send.used, cur->remote_id);
			ssize_t changed =
					write(cur->pipe_fd, cur->pipe_send.data,
							cur->pipe_send.used);

			if (changed == -1) {
				wp_log(WP_ERROR,
						"Failed to write into pipe with remote_id=%d: %s",
						cur->remote_id,
						strerror(errno));
			} else if (changed == 0) {
				wp_log(WP_DEBUG, "Zero write event");
			} else {
				cur->pipe_send.used -= changed;
				if (cur->pipe_send.used) {
					memmove(cur->pipe_send.data,
							cur->pipe_send.data +
									changed,
							cur->pipe_send.used);
				} else {
					free(cur->pipe_send.data);
					cur->pipe_send.data = NULL;
					cur->pipe_send.size = 0;
					cur->pipe_send.used = 0;
				}
			}
		}
	}
}
void read_readable_pipes(struct fd_translation_map *map)
{
	for (struct shadow_fd *cur = map->list; cur; cur = cur->next) {
		if (fdcat_ispipe(cur->type) && cur->pipe_readable &&
				cur->pipe_recv.size > cur->pipe_recv.used) {
			cur->pipe_readable = false;
			ssize_t changed = read(cur->pipe_fd,
					cur->pipe_recv.data +
							cur->pipe_recv.used,
					cur->pipe_recv.size -
							cur->pipe_recv.used);
			if (changed == -1) {
				wp_log(WP_ERROR,
						"Failed to read from pipe with remote_id=%d: %s",
						cur->remote_id,
						strerror(errno));
			} else if (changed == 0) {
				wp_log(WP_DEBUG, "Zero write event");
			} else {
				wp_log(WP_DEBUG,
						"Read %ld more bytes from RID=%d",
						changed, cur->remote_id);
				cur->pipe_recv.used += changed;
			}
		}
	}
}

void close_local_pipe_ends(struct fd_translation_map *map)
{
	for (struct shadow_fd *cur = map->list; cur; cur = cur->next) {
		if (fdcat_ispipe(cur->type) && cur->fd_local != -2 &&
				cur->fd_local != cur->pipe_fd) {
			close(cur->fd_local);
			cur->fd_local = -2;
		}
	}
}

void close_rclosed_pipes(struct fd_translation_map *map)
{
	for (struct shadow_fd *cur = map->list; cur; cur = cur->next) {
		if (fdcat_ispipe(cur->type) && cur->pipe_rclosed &&
				!cur->pipe_lclosed) {
			close(cur->pipe_fd);
			if (cur->pipe_fd == cur->fd_local) {
				cur->fd_local = -2;
			}
			cur->pipe_fd = -2;
			cur->pipe_lclosed = true;
		}
	}
}
