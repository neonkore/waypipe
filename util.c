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
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

log_cat_t waypipe_loglevel = WP_ERROR;

const char *static_timestamp(void)
{
	static char msg[64];
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	double time = (ts.tv_sec % 100) * 1. + ts.tv_nsec * 1e-9;
	sprintf(msg, "%9.6f", time);
	return msg;
}

ssize_t iovec_read(int conn, char *buf, size_t buflen, int *fds, int *numfds)
{
	char cmsgdata[(CMSG_LEN(28 * sizeof(int32_t)))];
	struct iovec the_iovec;
	the_iovec.iov_len = buflen;
	the_iovec.iov_base = buf;
	struct msghdr msg;
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &the_iovec;
	msg.msg_iovlen = 1;
	msg.msg_control = &cmsgdata;
	msg.msg_controllen = sizeof(cmsgdata);
	msg.msg_flags = 0;
	ssize_t ret = recvmsg(conn, &msg, MSG_DONTWAIT);

	if (fds && numfds) {
		int maxfds = *numfds;
		*numfds = 0;

		// Read cmsg
		struct cmsghdr *header = CMSG_FIRSTHDR(&msg);
		while (header) {
			if (header->cmsg_level == SOL_SOCKET &&
					header->cmsg_type == SCM_RIGHTS) {
				int *data = (int *)CMSG_DATA(header);
				int nf = (header->cmsg_len -
							 sizeof(struct cmsghdr)) /
					 sizeof(int);
				for (int i = 0; i < nf && *numfds < maxfds;
						i++) {
					fds[(*numfds)++] = data[i];
				}
			}

			header = CMSG_NXTHDR(&msg, header);
		}
	}
	return ret;
}
ssize_t iovec_write(int conn, const char *buf, size_t buflen, const int *fds,
		int numfds)
{
	struct iovec the_iovec;
	the_iovec.iov_len = buflen;
	the_iovec.iov_base = (char *)buf;
	struct msghdr msg;
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &the_iovec;
	msg.msg_iovlen = 1;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = 0;

	union {
		char buf[CMSG_SPACE(sizeof(int) * 28)];
		struct cmsghdr align;
	} uc;
	memset(uc.buf, 0, sizeof(uc.buf));

	if (numfds > 0) {
		msg.msg_control = uc.buf;
		msg.msg_controllen = sizeof(uc.buf);
		struct cmsghdr *frst = CMSG_FIRSTHDR(&msg);
		frst->cmsg_level = SOL_SOCKET;
		frst->cmsg_type = SCM_RIGHTS;
		memcpy(CMSG_DATA(frst), fds, numfds * sizeof(int));
		frst->cmsg_len = CMSG_LEN(numfds * sizeof(int));
		msg.msg_controllen = CMSG_SPACE(numfds * sizeof(int));
		wp_log(WP_DEBUG, "Writing %d fds to cmsg data\n", numfds);
	}

	ssize_t ret = sendmsg(conn, &msg, 0);
	return ret;
}

void cleanup_translation_map(struct fd_translation_map *map)
{
	struct shadow_fd *cur = map->list;
	map->list = NULL;
	while (cur) {
		struct shadow_fd *shadow = cur;

		close(shadow->fd_local);
		if (shadow->memsize != (size_t)-1) {
			munmap(shadow->mem_local, shadow->memsize);
			free(shadow->mem_mirror);
		}
		if (shadow->shm_buf_name[0]) {
			shm_unlink(shadow->shm_buf_name);
		}

		cur = shadow->next;
		shadow->next = NULL;
		free(shadow);
	}
}
void translate_fds(struct fd_translation_map *map, int nfds, const int fds[],
		int ids[])
{
	for (int i = 0; i < nfds; i++) {
		struct shadow_fd *cur = map->list;
		int the_fd = fds[i];
		bool found = false;
		while (cur) {
			if (cur->fd_local == the_fd) {
				ids[i] = cur->remote_id;
				found = true;
				break;
			}

			cur = cur->next;
		}
		if (found) {
			continue;
		}
		// Create a new translation map.
		struct shadow_fd *shadow = calloc(1, sizeof(struct shadow_fd));
		shadow->next = map->list;
		map->list = shadow;
		shadow->fd_local = the_fd;
		shadow->mem_local = NULL;
		shadow->mem_mirror = NULL;
		shadow->memsize = (size_t)-1;
		shadow->remote_id = (map->max_local_id++) * map->local_sign;
		ids[i] = shadow->remote_id;

		wp_log(WP_DEBUG, "Creating new shadow buffer for local fd %d\n",
				the_fd);

		struct stat fsdata;
		memset(&fsdata, 0, sizeof(fsdata));
		int ret = fstat(the_fd, &fsdata);
		if (ret != -1) {
			// We have a file-like object
			shadow->memsize = fsdata.st_size;
			// both r/w permissions, because the size the allocates
			// the memory does not always have to be the size that
			// modifies it
			shadow->mem_local = mmap(NULL, shadow->memsize,
					PROT_READ | PROT_WRITE, MAP_SHARED,
					the_fd, 0);
			if (!shadow->mem_local) {
				wp_log(WP_ERROR, "Mmap failed!\n");
				continue;
			}
			// This will be created at the first transfer
			shadow->mem_mirror = NULL;
		} else {
			wp_log(WP_ERROR, "The fd %d is not file-like\n",
					the_fd);
		}
	}
}
void collect_updates(struct fd_translation_map *map, int *ntransfers,
		struct transfer transfers[])
{
	int nt = 0;
	for (struct shadow_fd *cur = map->list; cur; cur = cur->next) {
		if (cur->memsize == (size_t)-1) {
			wp_log(WP_ERROR,
					"shadowlist element not transferrable\n");
			continue;
		}

		if (!cur->mem_mirror) {
			cur->mem_mirror = calloc(cur->memsize, 1);
		} else if (memcmp(cur->mem_local, cur->mem_mirror,
					   cur->memsize) == 0) {
			continue;
		}

		memcpy(cur->mem_mirror, cur->mem_local, cur->memsize);
		transfers[nt].data = cur->mem_mirror;
		transfers[nt].size = cur->memsize;
		transfers[nt].obj_id = cur->remote_id;
		nt++;
	}
	*ntransfers = nt;
}

void pack_pipe_message(size_t *msglen, char **msg, int waylen,
		const char *waymsg, int nids, const int ids[], int ntransfers,
		const struct transfer transfers[])
{
	// TODO: network byte order everything!

	size_t size = sizeof(size_t); // including the header
	size += nids * (2 * sizeof(int));
	for (int i = 0; i < ntransfers; i++) {
		size_t num_longs = (transfers[i].size + 7) / 8;
		size += 2 * sizeof(int) + 8 * num_longs;
	}
	size_t waymsg_longs = (size_t)(waylen + 7) / 8;
	size += 2 * sizeof(int) + 8 * waymsg_longs;

	void *data = calloc(size, 1);
	size_t *cursor = data;
	*cursor++ = size - sizeof(size_t); // size excluding this header
	for (int i = 0; i < nids; i++) {
		int *sd = (int *)cursor;
		sd[0] = ids[i];
		sd[1] = -1;
		cursor++;
	}
	for (int i = 0; i < ntransfers; i++) {
		int *sd = (int *)cursor;
		sd[0] = transfers[i].obj_id;
		sd[1] = transfers[i].size;
		char *cd = (char *)cursor;
		memcpy(cd + 8, transfers[i].data, transfers[i].size);

		size_t num_longs = (transfers[i].size + 7) / 8;
		cursor += 1 + num_longs;
	}

	int *wsd = (int *)cursor;
	wsd[0] = 0; // the actual message
	wsd[1] = waylen;
	char *wcd = (char *)cursor;
	memcpy(wcd + 8, waymsg, waylen);

	*msg = data;
	*msglen = size;
}

void unpack_pipe_message(size_t msglen, const char *msg, int *waylen,
		char **waymsg, int *nids, int ids[], int *ntransfers,
		struct transfer transfers[])
{
	(void)msglen;
	int ni = 0, nt = 0;
	size_t *cursor = (size_t *)msg;
	while (true) {
		int *sd = (int *)cursor;
		int obj_id = sd[0];
		int obj_len = sd[1];
		if (obj_len != -1) {
			char *data = ((char *)cursor) + 8;
			if (obj_id == 0) {
				*waylen = obj_len;
				*waymsg = data;
				break;
			} else {
				// Add to list of data transfers
				transfers[nt].obj_id = obj_id;
				transfers[nt].size = obj_len;
				transfers[nt].data = data;
				nt++;
			}
			int nlongs = (obj_len + 7) / 8;
			cursor += 1 + nlongs;
		} else {
			// Add to list of file descriptors passed along
			ids[ni++] = obj_id;

			cursor += 1;
		}
	}
	*nids = ni;
	*ntransfers = nt;
}

void untranslate_ids(struct fd_translation_map *map, int nids, const int ids[],
		int fds[])
{
	for (int i = 0; i < nids; i++) {
		struct shadow_fd *cur = map->list;
		int the_id = ids[i];
		bool found = false;
		while (cur) {
			if (cur->remote_id == the_id) {
				fds[i] = cur->fd_local;
				found = true;
				break;
			}

			cur = cur->next;
		}
		if (!found) {
			wp_log(WP_ERROR,
					"Could not untranslate remote id %d in map\n",
					the_id);
			fds[i] = -1;
		}
	}
}
static void apply_update(
		struct fd_translation_map *map, const struct transfer *transf)
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
		if (transf->size != cur->memsize) {
			wp_log(WP_ERROR, "Transfer size mismatch %ld %ld\n",
					transf->size, cur->memsize);
		}
		memcpy(cur->mem_mirror, transf->data, transf->size);
		memcpy(cur->mem_local, cur->mem_mirror, transf->size);
		return;
	}

	struct shadow_fd *shadow = calloc(1, sizeof(struct shadow_fd));
	shadow->next = map->list;
	map->list = shadow;
	shadow->mem_local = NULL;
	shadow->memsize = transf->size;
	shadow->remote_id = transf->obj_id;
	shadow->mem_mirror = calloc(shadow->memsize, 1);
	memcpy(shadow->mem_mirror, transf->data, transf->size);
	sprintf(shadow->shm_buf_name, "/waypipe-data_%d", shadow->remote_id);

	shadow->fd_local = shm_open(
			shadow->shm_buf_name, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (shadow->fd_local == -1) {
		wp_log(WP_ERROR,
				"Failed to create shm file for object %d: %s\n",
				shadow->remote_id, strerror(errno));
		return;
	}
	if (ftruncate(shadow->fd_local, shadow->memsize) == -1) {
		wp_log(WP_ERROR,
				"Failed to resize shm file %s to size %ld for reason: %s\n",
				shadow->shm_buf_name, shadow->memsize,
				strerror(errno));
		return;
	}
	shadow->mem_local = mmap(NULL, shadow->memsize, PROT_READ | PROT_WRITE,
			MAP_SHARED, shadow->fd_local, 0);
	memcpy(shadow->mem_local, shadow->mem_mirror, shadow->memsize);
}
void apply_updates(struct fd_translation_map *map, int ntransfers,
		const struct transfer transfers[])
{
	for (int i = 0; i < ntransfers; i++) {
		apply_update(map, &transfers[i]);
	}
}

ssize_t read_size_then_buf(int fd, char **msg)
{
	*msg = NULL;
	ssize_t nbytes = 0;
	ssize_t nrc = read(fd, &nbytes, sizeof(ssize_t));
	if (nrc == 0) {
		return 0;
	}
	if (nrc < (ssize_t)sizeof(ssize_t)) {
		return -1;
	}
	char *tmpbuf = calloc(nbytes, 1);
	ssize_t nread = 0;
	while (nread < nbytes) {
		ssize_t nr = read(fd, tmpbuf + nread, nbytes - nread);
		if (nr <= 0) {
			break;
		}
		nread += nr;
	}
	if (nread < nbytes) {
		free(tmpbuf);
		return -1;
	}
	*msg = tmpbuf;
	return nbytes;
}
