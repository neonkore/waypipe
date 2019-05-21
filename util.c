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
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

bool shutdown_flag = false;
char waypipe_log_mode = '?';
log_cat_t waypipe_loglevel = WP_ERROR;

void handle_sigint(int sig)
{
	(void)sig;
	char buf[20];
	int pid = getpid();
	sprintf(buf, "SIGINT(%d)\n", pid);
	write(STDOUT_FILENO, buf, strlen(buf));
	if (!shutdown_flag) {
		shutdown_flag = true;
	} else {
		const char msg[] = "Second SIGINT, aborting.\n";
		write(STDERR_FILENO, msg, sizeof(msg));
		abort();
	}
}

int set_fnctl_flag(int fd, int the_flag)
{
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1) {
		return -1;
	}
	return fcntl(fd, F_SETFL, flags | the_flag);
}

bool fdcat_ispipe(fdcat_t t)
{
	return t == FDC_PIPE_IR || t == FDC_PIPE_RW || t == FDC_PIPE_IW;
}

int setup_nb_socket(const char *socket_path, int nmaxclients)
{
	struct sockaddr_un saddr;
	int sock;

	if (strlen(socket_path) >= sizeof(saddr.sun_path)) {
		wp_log(WP_ERROR,
				"Socket path is too long and would be truncated: %s\n",
				socket_path);
		return -1;
	}

	saddr.sun_family = AF_UNIX;
	strncpy(saddr.sun_path, socket_path, sizeof(saddr.sun_path) - 1);
	sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (sock == -1) {
		wp_log(WP_ERROR, "Error creating socket: %s\n",
				strerror(errno));
		return -1;
	}
	if (set_fnctl_flag(sock, O_NONBLOCK | O_CLOEXEC) == -1) {
		wp_log(WP_ERROR, "Error making socket nonblocking: %s\n",
				strerror(errno));
		close(sock);
		return -1;
	}
	if (bind(sock, (struct sockaddr *)&saddr, sizeof(saddr)) == -1) {
		wp_log(WP_ERROR, "Error binding socket: %s\n", strerror(errno));
		close(sock);
		return -1;
	}
	if (listen(sock, nmaxclients) == -1) {
		wp_log(WP_ERROR, "Error listening to socket: %s\n",
				strerror(errno));
		close(sock);
		unlink(socket_path);
		return -1;
	}
	return sock;
}

const char *static_timestamp(void)
{
	static char msg[64];
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	double time = (ts.tv_sec % 100) * 1. + ts.tv_nsec * 1e-9;
	sprintf(msg, "%9.6f", time);
	return msg;
}

ssize_t iovec_read(int conn, char *buf, size_t buflen, int *fds, int *numfds,
		int maxfds)
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
		if (shadow->type == FDC_FILE) {
			munmap(shadow->file_mem_local, shadow->file_size);
			free(shadow->file_mem_mirror);
			free(shadow->file_diff_buffer);
			if (shadow->file_shm_buf_name[0]) {
				shm_unlink(shadow->file_shm_buf_name);
			}
		} else if (fdcat_ispipe(shadow->type)) {
			close(shadow->pipe_fd);
			if (shadow->pipe_fd != shadow->fd_local) {
				close(shadow->fd_local);
			}
			free(shadow->pipe_recv.data);
			free(shadow->pipe_send.data);
		}

		cur = shadow->next;
		shadow->next = NULL;
		free(shadow);
	}
}
static int translate_fd(struct fd_translation_map *map, int fd)
{
	struct shadow_fd *cur = map->list;
	while (cur) {
		if (cur->fd_local == fd) {
			return cur->remote_id;
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

	wp_log(WP_DEBUG, "Creating new shadow buffer for local fd %d\n", fd);

	struct stat fsdata;
	memset(&fsdata, 0, sizeof(fsdata));
	int ret = fstat(fd, &fsdata);
	if (ret == -1) {
		wp_log(WP_ERROR, "The fd %d is not file-like\n", fd);
		return shadow->remote_id;
	}
	if (S_ISREG(fsdata.st_mode)) {

		// We have a file-like object
		shadow->file_size = fsdata.st_size;
		// both r/w permissions, because the size the allocates
		// the memory does not always have to be the size that
		// modifies it
		shadow->file_mem_local = mmap(NULL, shadow->file_size,
				PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		if (!shadow->file_mem_local) {
			wp_log(WP_ERROR, "Mmap failed!\n");
			return shadow->remote_id;
		}
		// This will be created at the first transfer
		shadow->file_mem_mirror = NULL;
		shadow->type = FDC_FILE;
	} else {
		if (!S_ISFIFO(fsdata.st_mode)) {
			/* For example, weston-terminal passes the master
			 * connection of the terminal which was acquired with
			 * forkpty; it probably links to a character device */
			wp_log(WP_ERROR,
					"The fd %d is neither a pipe nor a regular file. Proceeding under the assumption that it is pipe-like.\n",
					fd);
		}
		int flags = fcntl(fd, F_GETFL, 0);
		if (flags == -1) {
			wp_log(WP_ERROR, "fctnl F_GETFL failed!\n");
		}
		if ((flags & O_ACCMODE) == O_RDONLY) {
			shadow->type = FDC_PIPE_IR;
		} else if ((flags & O_ACCMODE) == O_WRONLY) {
			shadow->type = FDC_PIPE_IW;
		} else {
			shadow->type = FDC_PIPE_RW;
		}

		// Make this end of the pipe nonblocking, so that we can include
		// it in our main loop.
		set_fnctl_flag(shadow->fd_local, O_NONBLOCK);
		shadow->pipe_fd = shadow->fd_local;

		// Allocate a reasonably small read buffer
		shadow->pipe_recv.size = 16384;
		shadow->pipe_recv.data = calloc(shadow->pipe_recv.size, 1);

		shadow->pipe_onlyhere = true;
	}

	return shadow->remote_id;
}
void translate_fds(struct fd_translation_map *map, int nfds, const int fds[],
		int ids[])
{
	for (int i = 0; i < nfds; i++) {
		ids[i] = translate_fd(map, fds[i]);
	}
}
/** Construct a very simple binary diff format, designed to be fast for small
 * changes in big files, and entire-file changes in essentially random files.
 * Tries not to read beyond the end of the input buffers, because they are often
 * mmap'd.
 *
 * Requires that `diff` point to a memory buffer of size `size + 8`.
 */
static void construct_diff(size_t size, const char *__restrict__ base,
		const char *__restrict__ changed, size_t *diffsize,
		char *__restrict__ diff)
{
	uint64_t nblocks = size / 8;
	uint64_t *__restrict__ base_blocks = (uint64_t *)base;
	uint64_t *__restrict__ changed_blocks = (uint64_t *)changed;
	uint64_t *__restrict__ diff_blocks = (uint64_t *)diff;
	uint64_t ntrailing = size - 8 * nblocks;
	uint64_t nskip = 0, ncopy = 0;
	uint64_t cursor = 0;
	diff_blocks[0] = 0;
	bool skipping = true;
	/* we paper over gaps of a given window size, to avoid fine grained
	 * context switches */
	const uint64_t window_size = 128;
	uint64_t last_header = 0;
	for (uint64_t i = 0; i < nblocks; i++) {
		if (skipping) {
			if (base_blocks[i] != changed_blocks[i]) {
				skipping = false;
				last_header = cursor++;
				diff_blocks[last_header] = i << 32;
				nskip = 0;

				diff_blocks[cursor++] = changed_blocks[i];
				ncopy = 1;
			} else {
				nskip++;
			}
		} else {
			if (base_blocks[i] == changed_blocks[i]) {
				nskip++;
			} else {
				nskip = 0;
			}
			if (nskip > window_size) {
				skipping = true;
				cursor -= (nskip - 1);
				ncopy -= (nskip - 1);
				diff_blocks[last_header] |= i - (nskip - 1);
				ncopy = 0;
			} else {
				diff_blocks[cursor++] = changed_blocks[i];
				ncopy++;
			}
		}
	}
	// We do not add a final 'skip' block, because the unpacking routine
	if (!skipping) {
		diff_blocks[last_header] |= nblocks - nskip;
		cursor -= nskip;
	}
	if (ntrailing > 0) {
		for (uint64_t i = 0; i < ntrailing; i++) {
			diff[cursor * 8 + i] = changed[nblocks * 8 + i];
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
					"Invalid copy range [%ld,%ld) > %ld=nblocks or [%ld,%ld) > %ld=ndiffblocks\n",
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

void collect_updates(struct fd_translation_map *map, int *ntransfers,
		struct transfer transfers[])
{
	for (struct shadow_fd *cur = map->list; cur; cur = cur->next) {
		if (cur->type == FDC_FILE) {
			if (!cur->file_mem_mirror) {
				cur->file_mem_mirror =
						calloc(cur->file_size, 1);
				// 8 extra bytes for worst case diff expansion
				cur->file_diff_buffer =
						calloc(cur->file_size + 8, 1);
				memcpy(cur->file_mem_mirror,
						cur->file_mem_local,
						cur->file_size);
				// new transfer, we send file contents verbatim
				int nt = (*ntransfers)++;
				transfers[nt].data = cur->file_mem_mirror;
				transfers[nt].size = cur->file_size;
				transfers[nt].type = cur->type;
				transfers[nt].obj_id = cur->remote_id;
				transfers[nt].special = 0;
			} else if (memcmp(cur->file_mem_local,
						   cur->file_mem_mirror,
						   cur->file_size) == 0) {
				continue;
			}
			size_t diffsize;
			wp_log(WP_DEBUG, "Diff construction start\n");
			construct_diff(cur->file_size, cur->file_mem_mirror,
					cur->file_mem_local, &diffsize,
					cur->file_diff_buffer);
			// update mirror
			apply_diff(cur->file_size, cur->file_mem_mirror,
					diffsize, cur->file_diff_buffer);
			wp_log(WP_DEBUG, "Diff construction end: %ld/%ld\n",
					diffsize, cur->file_size);

			int nt = (*ntransfers)++;
			transfers[nt].obj_id = cur->remote_id;
			transfers[nt].data = cur->file_diff_buffer;
			transfers[nt].type = cur->type;
			transfers[nt].size = diffsize;
			transfers[nt].special = 0;
		} else if (fdcat_ispipe(cur->type)) {
			if (cur->pipe_recv.used > 0 || cur->pipe_onlyhere ||
					(cur->pipe_lclosed &&
							!cur->pipe_rclosed)) {
				cur->pipe_onlyhere = false;
				wp_log(WP_DEBUG,
						"Adding update to pipe RID=%d, with %ld bytes, close %c\n",
						cur->remote_id,
						cur->pipe_recv.used,
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
}

struct pipe_elem_header {
	int id;
	int type;
	int size;
	int special;
};

void pack_pipe_message(size_t *msglen, char **msg, int nids, const int ids[],
		int ntransfers, const struct transfer transfers[])
{
	// TODO: network byte order everything, content aware, somewhere in the
	// chain!

	size_t size = sizeof(size_t); // including the header
	size += nids * sizeof(struct pipe_elem_header);
	for (int i = 0; i < ntransfers; i++) {
		size_t num_longs = (transfers[i].size + 7) / 8;
		size += sizeof(struct pipe_elem_header) + 8 * num_longs;
	}

	void *data = calloc(size, 1);
	size_t *cursor = data;
	*cursor++ = size - sizeof(size_t); // size excluding this header
	for (int i = 0; i < nids; i++) {
		struct pipe_elem_header *sd = (struct pipe_elem_header *)cursor;
		sd->id = ids[i];
		sd->type = -1;
		sd->size = -1;
		sd->special = 0;
		cursor += sizeof(struct pipe_elem_header) / sizeof(size_t);
	}
	for (int i = 0; i < ntransfers; i++) {
		struct pipe_elem_header *sd = (struct pipe_elem_header *)cursor;
		sd->id = transfers[i].obj_id;
		sd->type = transfers[i].type;
		sd->size = transfers[i].size;
		sd->special = transfers[i].special;
		char *cd = (char *)cursor;
		memcpy(cd + sizeof(struct pipe_elem_header), transfers[i].data,
				transfers[i].size);

		size_t num_longs = (transfers[i].size + 7) / 8;
		cursor += (sizeof(struct pipe_elem_header) / sizeof(size_t)) +
			  num_longs;
	}

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
	size_t *end = (size_t *)(msg + msglen);
	while (cursor < end) {
		struct pipe_elem_header *sd = (struct pipe_elem_header *)cursor;
		if (sd->size != -1) {
			char *data = ((char *)cursor) + 16;
			if (sd->id == 0) {
				// There can only be one of these blocks
				*waylen = sd->size;
				*waymsg = data;
			} else {
				// Add to list of data transfers
				transfers[nt].obj_id = sd->id;
				transfers[nt].size = (size_t)sd->size;
				transfers[nt].type = (fdcat_t)sd->type;
				transfers[nt].data = data;
				transfers[nt].special = sd->special;
				nt++;
			}
			int nlongs = (sd->size + 7) / 8;
			cursor += (sizeof(struct pipe_elem_header) /
						  sizeof(size_t)) +
				  nlongs;
		} else {
			// Add to list of file descriptors passed along
			ids[ni++] = sd->id;

			cursor += (sizeof(struct pipe_elem_header) /
					sizeof(size_t));
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
					"Could not untranslate remote id %d in map. Application will probably crash.\n",
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
		if (cur->type == FDC_FILE) {
			if (transf->type != cur->type) {
				wp_log(WP_ERROR,
						"Transfer type mismatch %d %d\n",
						transf->type, cur->type);
			}

			// `memsize+8` is the worst-case diff expansion
			if (transf->size > cur->file_size + 8) {
				wp_log(WP_ERROR,
						"Transfer size mismatch %ld %ld\n",
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
						"Transfer type contramismatch %d %d\n",
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
		}
		return;
	}

	wp_log(WP_DEBUG, "Introducing new fd, remoteid=%d\n", transf->obj_id);
	struct shadow_fd *shadow = calloc(1, sizeof(struct shadow_fd));
	shadow->next = map->list;
	map->list = shadow;
	shadow->remote_id = transf->obj_id;
	shadow->fd_local = -1;
	shadow->type = transf->type;
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
					"Failed to create shm file for object %d: %s\n",
					shadow->remote_id, strerror(errno));
			return;
		}
		if (ftruncate(shadow->fd_local, shadow->file_size) == -1) {
			wp_log(WP_ERROR,
					"Failed to resize shm file %s to size %ld for reason: %s\n",
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
						"Failed to create a socketpair: %s\n",
						strerror(errno));
				return;
			}
		} else {
			if (pipe(pipedes) == -1) {
				wp_log(WP_ERROR,
						"Failed to create a pipe: %s\n",
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
					"Failed to make private pipe end nonblocking: %s\n",
					strerror(errno));
			return;
		}

		// Allocate a reasonably small read buffer
		shadow->pipe_recv.size = 16384;
		shadow->pipe_recv.data = calloc(shadow->pipe_recv.size, 1);
		shadow->pipe_onlyhere = false;
	} else {
		wp_log(WP_ERROR, "Creating unknown file type updates\n");
	}
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

void wait_on_children(struct kstack **children, int options)
{
	struct kstack *cur = *children;
	struct kstack **prv = children;
	while (cur) {
		if (waitpid(cur->pid, NULL, options) > 0) {
			wp_log(WP_DEBUG, "Child handler %d has died\n",
					cur->pid);
			struct kstack *nxt = cur->nxt;
			free(cur);
			cur = nxt;
			*prv = nxt;
		} else {
			prv = &cur->nxt;
			cur = cur->nxt;
		}
	}
}

int count_npipes(const struct fd_translation_map *map)
{
	int np = 0;
	for (struct shadow_fd *cur = map->list; cur; cur = cur->next) {
		if (fdcat_ispipe(cur->type)) {
			if (!cur->pipe_lclosed) {
				np++;
			}
		}
	}
	return np;
}
void fill_with_pipes(const struct fd_translation_map *map, struct pollfd *pfds)
{
	unsigned int np = 0;
	for (struct shadow_fd *cur = map->list; cur; cur = cur->next) {
		if (fdcat_ispipe(cur->type)) {
			if (!cur->pipe_lclosed) {
				pfds[np].fd = cur->pipe_fd;
				if (cur->type == FDC_PIPE_RW) {
					pfds[np].events = POLLIN | POLLOUT;
				} else if (cur->type == FDC_PIPE_IR) {
					pfds[np].events = POLLIN;
				} else if (cur->type == FDC_PIPE_IW) {
					pfds[np].events = POLLOUT;
				}
				np++;
			}
		}
	}
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
					"Failed to find shadow struct for .pipe_fd=%d\n",
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
			wp_log(WP_DEBUG, "Flushing %ld bytes into RID=%d\n",
					cur->pipe_send.used, cur->remote_id);
			ssize_t changed =
					write(cur->pipe_fd, cur->pipe_send.data,
							cur->pipe_send.used);

			if (changed == -1) {
				wp_log(WP_ERROR,
						"Failed to write into pipe with remote_id=%d: %s\n",
						cur->remote_id,
						strerror(errno));
			} else if (changed == 0) {
				wp_log(WP_DEBUG, "Zero write event\n");
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
						"Failed to read from pipe with remote_id=%d: %s\n",
						cur->remote_id,
						strerror(errno));
			} else if (changed == 0) {
				wp_log(WP_DEBUG, "Zero write event\n");
			} else {
				wp_log(WP_DEBUG,
						"Read %ld more bytes from RID=%d\n",
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
