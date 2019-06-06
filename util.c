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
#include <stdarg.h>
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
#include <sys/uio.h>
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
				"Socket path is too long and would be truncated: %s",
				socket_path);
		return -1;
	}

	saddr.sun_family = AF_UNIX;
	strncpy(saddr.sun_path, socket_path, sizeof(saddr.sun_path) - 1);
	sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (sock == -1) {
		wp_log(WP_ERROR, "Error creating socket: %s", strerror(errno));
		return -1;
	}
	if (set_fnctl_flag(sock, O_NONBLOCK | O_CLOEXEC) == -1) {
		wp_log(WP_ERROR, "Error making socket nonblocking: %s",
				strerror(errno));
		close(sock);
		return -1;
	}
	if (bind(sock, (struct sockaddr *)&saddr, sizeof(saddr)) == -1) {
		wp_log(WP_ERROR, "Error binding socket at %s: %s", socket_path,
				strerror(errno));
		close(sock);
		return -1;
	}
	if (listen(sock, nmaxclients) == -1) {
		wp_log(WP_ERROR, "Error listening to socket at %s: %s",
				socket_path, strerror(errno));
		close(sock);
		unlink(socket_path);
		return -1;
	}
	return sock;
}

void wp_log_handler(const char *file, int line, log_cat_t level,
		const char *fmt, ...)
{
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	double time = (ts.tv_sec % 100) * 1. + ts.tv_nsec * 1e-9;
	int pid = getpid();

	char mode;
	if (waypipe_log_mode == 'S') {
		mode = level == WP_DEBUG ? 's' : 'S';
	} else {
		mode = level == WP_DEBUG ? 'c' : 'C';
	}

	char msg[1024];
	int nwri = sprintf(msg, "%c%d:%9.6f [%s:%3d] ", mode, pid, time, file,
			line);
	va_list args;
	va_start(args, fmt);
	nwri += vsnprintf(msg + nwri, (size_t)(1020 - nwri), fmt, args);
	va_end(args);

	if (waypipe_log_mode == 'c') {
		/* to avoid 'staircase' rendering when using the ssh helper
		 * mode, and -t argument */
		msg[nwri++] = '\r';
		msg[nwri++] = '\n';
		msg[nwri++] = 0;
	} else {
		msg[nwri++] = '\n';
		msg[nwri++] = 0;
	}
	// single short writes are atomic for pipes, at least
	write(STDERR_FILENO, msg, (size_t)nwri);
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
	ssize_t ret = recvmsg(conn, &msg, 0);

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
				// todo: close overflow...
			}

			header = CMSG_NXTHDR(&msg, header);
		}
	}
	return ret;
}
// The maximum number of fds libwayland can recvmsg at once
#define MAX_LIBWAY_FDS 28
ssize_t iovec_write(int conn, const char *buf, size_t buflen, const int *fds,
		int numfds, int *nfds_written)
{
	bool overflow = numfds > MAX_LIBWAY_FDS;

	struct iovec the_iovec;
	the_iovec.iov_len = overflow ? 1 : buflen;
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
		char buf[CMSG_SPACE(sizeof(int) * MAX_LIBWAY_FDS)];
		struct cmsghdr align;
	} uc;
	memset(uc.buf, 0, sizeof(uc.buf));

	if (numfds > 0) {
		msg.msg_control = uc.buf;
		msg.msg_controllen = sizeof(uc.buf);
		struct cmsghdr *frst = CMSG_FIRSTHDR(&msg);
		frst->cmsg_level = SOL_SOCKET;
		frst->cmsg_type = SCM_RIGHTS;
		*nfds_written = min(numfds, MAX_LIBWAY_FDS);
		size_t nwritten = (size_t)(*nfds_written);
		memcpy(CMSG_DATA(frst), fds, nwritten * sizeof(int));
		for (int i = 0; i < numfds; i++) {
			int flags = fcntl(fds[i], F_GETFL, 0);
			if (flags == -1 && errno == EBADF) {
				wp_log(WP_ERROR, "Writing invalid fd %d",
						fds[i]);
			}
		}

		frst->cmsg_len = CMSG_LEN(nwritten * sizeof(int));
		msg.msg_controllen = CMSG_SPACE(nwritten * sizeof(int));
		wp_log(WP_DEBUG, "Writing %d fds to cmsg data", *nfds_written);
	} else {
		*nfds_written = 0;
	}

	ssize_t ret = sendmsg(conn, &msg, 0);
	return ret;
}

struct pipe_elem_header {
	int32_t id;
	int32_t type;
	int32_t size;
	int32_t special;
};

/* The data transfers from an application to the channel consist of a length
 * prefix, followed by a series of transfer blocks. This structure maintains
 * the transfer block state, with the end goal of transport using 'writev' */
struct block_transfer {
	int total_size;

	int ntransfers;
	char *meta_header;
	struct pipe_elem_header *transfer_block_headers;

	int nblocks;
	struct iovec *blocks;
	// Tracking how much of the message has been transferred
	int blocks_written;
};

/* This state corresponds to the in-progress transfer from the program
 * (compositor or application) and its pipes/buffers to the channel. */
enum wm_state { WM_WAITING_FOR_PROGRAM, WM_WAITING_FOR_CHANNEL };
struct way_msg_state {
	// These aren't quite a ring-buffer
	int dbuffer_maxsize;
	int dbuffer_edited_maxsize;
	int dbuffer_end;
	int dbuffer_carryover_start;
	int dbuffer_carryover_end;

	int rbuffer_count;
	enum wm_state state;
	/* The large packed message to be written to the channel */
	char *dbuffer;        // messages
	char *dbuffer_edited; // messages are copied to here
	int *rbuffer;         // rids
	struct int_window fds;

	/* Buffer data to be writev'd */
	struct block_transfer cmsg;
};

/* This state corresponds to the in-progress transfer from the channel
 * to the program and the buffers/pipes on which will be written. */
enum cm_state { CM_WAITING_FOR_PROGRAM, CM_WAITING_FOR_CHANNEL };
struct chan_msg_state {
	enum cm_state state;

	/* The large packed message read from the channel */
	int cmsg_end;
	int cmsg_size;
	int dbuffer_start;
	int dbuffer_end;
	int dbuffer_edited_maxsize;
	int fbuffer_maxsize;
	int fbuffer_count;
	int tfbuffer_count;
	int rbuffer_count;
	int *rbuffer;         // rids
	int *tfbuffer;        // fds to be immediately transferred
	int *fbuffer;         // fds for use
	char *dbuffer;        // pointer to message block
	char *dbuffer_edited; // messages are copied to here
	char *cmsg_buffer;
};

static int interpret_chanmsg(struct chan_msg_state *cmsg,
		struct fd_translation_map *map, struct message_tracker *mt,
		bool display_side)
{
	// Parsing decomposition
	cmsg->rbuffer_count = 0;
	cmsg->tfbuffer_count = 0;

	cmsg->dbuffer = NULL;
	cmsg->dbuffer_start = 0;
	cmsg->dbuffer_end = 0;

	wp_log(WP_DEBUG, "Read %d byte msg, unpacking", cmsg->cmsg_size);

	int ntransfers = 0;
	struct transfer transfers[50];
	unpack_pipe_message((size_t)cmsg->cmsg_size, cmsg->cmsg_buffer,
			&cmsg->dbuffer_end, &cmsg->dbuffer,
			&cmsg->rbuffer_count, cmsg->rbuffer, &ntransfers,
			transfers);

	wp_log(WP_DEBUG,
			"Read %d byte msg, %d fds, %d transfers. Data buffer has %d bytes",
			cmsg->cmsg_size, cmsg->rbuffer_count, ntransfers,
			cmsg->dbuffer_end);

	apply_updates(map, ntransfers, transfers);

	untranslate_ids(map, cmsg->rbuffer_count, cmsg->rbuffer,
			cmsg->tfbuffer);
	cmsg->tfbuffer_count = cmsg->rbuffer_count;
	if (cmsg->tfbuffer_count > 0) {
		// Append the new file descriptors to
		// the parsing queue
		memcpy(cmsg->fbuffer + cmsg->fbuffer_count, cmsg->tfbuffer,
				sizeof(int) * (size_t)cmsg->tfbuffer_count);
		cmsg->fbuffer_count += cmsg->tfbuffer_count;
	}

	if (cmsg->dbuffer) {
		/* While by construction, the provided
		 * message buffer should be aligned with
		 * individual message boundaries, it is
		 * not guaranteed that all file
		 * descriptors provided will be used by
		 * the messages */
		struct char_window src;
		src.data = cmsg->dbuffer;
		src.zone_start = 0;
		src.zone_end = cmsg->dbuffer_end;
		src.size = cmsg->dbuffer_end;
		struct char_window dst;
		dst.data = cmsg->dbuffer_edited;
		dst.zone_start = 0;
		dst.zone_end = 0;
		dst.size = cmsg->dbuffer_edited_maxsize;
		struct int_window fds;
		fds.data = cmsg->fbuffer;
		fds.zone_start = 0;
		fds.zone_end = cmsg->fbuffer_count;
		fds.size = cmsg->fbuffer_maxsize;
		parse_and_prune_messages(mt, map, display_side, display_side,
				&src, &dst, &fds);
		if (src.zone_start != cmsg->dbuffer_end) {
			wp_log(WP_ERROR,
					"did not expect partial messages over channel, only parsed %d/%d bytes",
					src.zone_start, cmsg->dbuffer_end);
			return -1;
		}
		/* Update file descriptor queue */
		if (cmsg->fbuffer_count > fds.zone_start) {
			memmove(cmsg->fbuffer, cmsg->fbuffer + fds.zone_start,
					sizeof(int) * (size_t)(cmsg->fbuffer_count -
								      fds.zone_start));
		}
		cmsg->fbuffer_count -= fds.zone_start;

		cmsg->dbuffer = cmsg->dbuffer_edited;
		cmsg->dbuffer_start = 0;
		cmsg->dbuffer_end = dst.zone_end;
	}
	return 0;
}
static int advance_chanmsg_chanread(struct chan_msg_state *cmsg, int chanfd,
		bool display_side, struct fd_translation_map *map,
		struct message_tracker *mt)
{
	// Read header, then read main contents
	if (cmsg->cmsg_size == 0) {
		uint64_t size = 0;
		ssize_t r = read(chanfd, &size, sizeof(size));
		if (r == -1 && errno == EWOULDBLOCK) {
			wp_log(WP_DEBUG, "Read would block");
			return 0;
		} else if (r == -1) {
			wp_log(WP_ERROR, "chanfd read failure: %s",
					strerror(errno));
			return -1;
		} else if (r == 0) {
			wp_log(WP_DEBUG, "Channel connection closed");
			return -1;
		} else if (r < (ssize_t)sizeof(uint64_t)) {
			wp_log(WP_ERROR,
					"insufficient starting read block %ld of 8 bytes",
					r);
			return -1;
		} else if (size > (1 << 30)) {
			wp_log(WP_ERROR, "Invalid transfer block size %ld",
					size);
			return -1;
		} else {
			cmsg->cmsg_buffer = malloc(size);
			cmsg->cmsg_end = 0;
			cmsg->cmsg_size = (int)size;
		}
	} else {
		while (cmsg->cmsg_end < cmsg->cmsg_size) {
			ssize_t r = read(chanfd,
					cmsg->cmsg_buffer + cmsg->cmsg_end,
					(size_t)(cmsg->cmsg_size -
							cmsg->cmsg_end));
			if (r == -1 && errno == EWOULDBLOCK) {
				return 0;
			} else if (r == -1) {
				wp_log(WP_ERROR, "chanfd read failure: %s",
						strerror(errno));
				return -1;
			} else if (r == 0) {
				wp_log(WP_ERROR, "chanfd closed");
				return -1;
			} else {
				cmsg->cmsg_end += r;
			}
		}
		if (cmsg->cmsg_end == cmsg->cmsg_size) {
			if (interpret_chanmsg(cmsg, map, mt, display_side) ==
					-1) {
				return -1;
			}
			cmsg->state = CM_WAITING_FOR_PROGRAM;
		}
	}
	return 0;
}
static int advance_chanmsg_progwrite(struct chan_msg_state *cmsg, int progfd,
		bool display_side, struct fd_translation_map *map)
{
	const char *progdesc = display_side ? "compositor" : "application";
	// Write as much as possible
	while (cmsg->dbuffer_start < cmsg->dbuffer_end) {
		int nfds_written = 0;
		ssize_t wc = iovec_write(progfd,
				cmsg->dbuffer + cmsg->dbuffer_start,
				(size_t)(cmsg->dbuffer_end -
						cmsg->dbuffer_start),
				cmsg->tfbuffer, cmsg->tfbuffer_count,
				&nfds_written);
		if (wc == -1 && errno == EWOULDBLOCK) {
			wp_log(WP_DEBUG, "Write to the %s would block",
					progdesc);
			return 0;
		} else if (wc == -1) {
			wp_log(WP_ERROR, "%s write failure %ld: %s", progdesc,
					wc, strerror(errno));
			return -1;
		} else if (wc == 0) {
			wp_log(WP_ERROR, "%s has closed", progdesc);
			return -1;
		} else {
			cmsg->dbuffer_start += wc;
			wp_log(WP_DEBUG,
					"Wrote, have done %d/%d bytes in chunk %ld, %d/%d fds",
					cmsg->dbuffer_start, cmsg->dbuffer_end,
					wc, nfds_written, cmsg->tfbuffer_count);
			// We send as many fds as we can with the first batch
			decref_transferred_fds(
					map, nfds_written, cmsg->tfbuffer);
			memmove(cmsg->tfbuffer, cmsg->tfbuffer + nfds_written,
					(size_t)nfds_written * sizeof(int));
			cmsg->tfbuffer_count -= nfds_written;
		}
	}
	if (cmsg->dbuffer_start == cmsg->dbuffer_end) {
		wp_log(WP_DEBUG, "Write to the %s succeeded", progdesc);
		close_local_pipe_ends(map);
		cmsg->state = CM_WAITING_FOR_CHANNEL;
		free(cmsg->cmsg_buffer);
		cmsg->cmsg_buffer = NULL;
		cmsg->cmsg_size = 0;
		cmsg->cmsg_end = 0;
	}
	return 0;
}
static int advance_chanmsg_transfer(struct fd_translation_map *map,
		struct message_tracker *mt, int chanfd, int progfd,
		bool display_side, struct chan_msg_state *cmsg,
		bool any_changes)
{
	if (!any_changes) {
		return 0;
	}
	if (cmsg->state == CM_WAITING_FOR_CHANNEL) {
		return advance_chanmsg_chanread(
				cmsg, chanfd, display_side, map, mt);
	} else {
		return advance_chanmsg_progwrite(
				cmsg, progfd, display_side, map);
	}
}

static int advance_waymsg_chanwrite(
		struct way_msg_state *wmsg, int chanfd, bool display_side)
{
	const char *progdesc = display_side ? "compositor" : "application";
	// Waiting for channel write to complete
	struct block_transfer *bt = &wmsg->cmsg;
	while (bt->blocks_written < bt->nblocks) {
		ssize_t wr = writev(chanfd, &bt->blocks[bt->blocks_written],
				bt->nblocks - bt->blocks_written);
		if (wr == -1 && errno == EWOULDBLOCK) {
			break;
		} else if (wr == -1 && errno == EAGAIN) {
			continue;
		} else if (wr == -1) {
			wp_log(WP_ERROR, "chanfd write failure: %s",
					strerror(errno));
			return -1;
		} else if (wr == 0) {
			wp_log(WP_ERROR, "chanfd has closed");
			return 0;
		}
		size_t uwr = (size_t)wr;
		while (uwr > 0 && bt->blocks_written < bt->nblocks) {
			size_t left = bt->blocks[bt->blocks_written].iov_len;
			if (left > uwr) {
				/* Block partially completed */
				bt->blocks[bt->blocks_written].iov_len -= uwr;
				bt->blocks[bt->blocks_written].iov_base =
						(void *)((char *)bt->blocks[bt->blocks_written]
										.iov_base +
								uwr);
				uwr = 0;
			} else {
				/* Block completed */
				bt->blocks[bt->blocks_written].iov_len = 0;
				bt->blocks[bt->blocks_written].iov_base = NULL;
				uwr -= left;
				bt->blocks_written++;
			}
			/* Skip past zero-length blocks */
			while (bt->blocks_written < bt->nblocks &&
					bt->blocks[bt->blocks_written].iov_len ==
							0) {
				bt->blocks_written++;
			}
		}
	}
	if (bt->blocks_written == bt->nblocks) {
		wp_log(WP_DEBUG,
				"The %d-byte, %d block message from %s to channel has been written",
				bt->total_size, bt->nblocks, progdesc);
		free(bt->blocks);
		free(bt->meta_header);
		free(bt->transfer_block_headers);
		bt->blocks = NULL;
		bt->meta_header = NULL;
		bt->transfer_block_headers = NULL;
		bt->total_size = 0;
		bt->blocks_written = 0;
		bt->nblocks = 0;
		bt->ntransfers = 0;
		wmsg->state = WM_WAITING_FOR_PROGRAM;
	}
	return 0;
}
static int advance_waymsg_progread(struct way_msg_state *wmsg,
		struct fd_translation_map *map, struct message_tracker *mt,
		int progfd, bool display_side, bool progsock_readable)
{
	const char *progdesc = display_side ? "compositor" : "application";
	// We have data to read from programs/pipes
	int ntransfers = 0;
	struct transfer transfers[50];
	ssize_t rc = -1;
	int old_fbuffer_end = wmsg->fds.zone_end;
	if (progsock_readable) {
		// Read /once/
		int nmaxfds = wmsg->fds.size - wmsg->fds.zone_end;
		rc = iovec_read(progfd, wmsg->dbuffer + wmsg->dbuffer_end,
				(size_t)(wmsg->dbuffer_maxsize -
						wmsg->dbuffer_end),
				wmsg->fds.data, &wmsg->fds.zone_end, nmaxfds);
		if (rc == -1 && errno == EWOULDBLOCK) {
			// do nothing
		} else if (rc == -1) {
			wp_log(WP_ERROR, "%s read failure: %s", progdesc,
					strerror(errno));
			return -1;
		} else if (rc == 0) {
			wp_log(WP_ERROR, "%s has closed", progdesc);
			return 0;
		} else {
			// We have successfully read some data.
			rc += wmsg->dbuffer_end;
		}
	}

	if (rc > 0) {
		wp_log(WP_DEBUG,
				"Read %d new file descriptors, have %d total now",
				wmsg->fds.zone_end - old_fbuffer_end,
				wmsg->fds.zone_end);

		struct char_window src;
		src.data = wmsg->dbuffer;
		src.zone_start = 0;
		src.zone_end = (int)rc;
		src.size = wmsg->dbuffer_maxsize;
		struct char_window dst;
		dst.data = wmsg->dbuffer_edited;
		dst.zone_start = 0;
		dst.zone_end = 0;
		dst.size = wmsg->dbuffer_edited_maxsize;

		parse_and_prune_messages(mt, map, display_side, !display_side,
				&src, &dst, &wmsg->fds);

		/* Translate all fds in the zone read by the protocol,
		 * creating shadow structures if needed. The window-queue
		 * is then reset */
		wmsg->rbuffer_count = wmsg->fds.zone_start;
		translate_fds(map, wmsg->fds.zone_start, wmsg->fds.data,
				wmsg->rbuffer);
		memmove(wmsg->fds.data, wmsg->fds.data + wmsg->fds.zone_start,
				sizeof(int) * (size_t)(wmsg->fds.zone_end -
							      wmsg->fds.zone_start));
		wmsg->fds.zone_end -= wmsg->fds.zone_start;
		wmsg->fds.zone_start = 0;

		/* Specify the range of recycled bytes */
		if (rc > src.zone_start) {
			wmsg->dbuffer_carryover_start = src.zone_start;
			wmsg->dbuffer_carryover_end = (int)rc;
		} else {
			wmsg->dbuffer_carryover_start = 0;
			wmsg->dbuffer_carryover_end = 0;
		}

		if (dst.zone_end > 0) {
			wp_log(WP_DEBUG,
					"We are transferring a data buffer with %ld bytes",
					dst.zone_end);
			transfers[0].obj_id = 0;
			transfers[0].size = dst.zone_end;
			transfers[0].data = wmsg->dbuffer_edited;
			transfers[0].type = FDC_UNKNOWN;
			ntransfers = 1;
		}
	}

	read_readable_pipes(map);
	collect_updates(map, &ntransfers, transfers);
	if (ntransfers > 0) {
		pack_pipe_message(&wmsg->cmsg, wmsg->rbuffer_count,
				wmsg->rbuffer, ntransfers, transfers);

		decref_transferred_rids(
				map, wmsg->rbuffer_count, wmsg->rbuffer);
		wp_log(WP_DEBUG,
				"Packed message size (%d fds, %d blobs, %d blocks): %d",
				wmsg->rbuffer_count, ntransfers,
				wmsg->cmsg.nblocks, wmsg->cmsg.total_size);

		// Introduce carryover data
		if (wmsg->dbuffer_carryover_end > 0) {
			memmove(wmsg->dbuffer,
					wmsg->dbuffer + wmsg->dbuffer_carryover_start,
					(size_t)(wmsg->dbuffer_carryover_end -
							wmsg->dbuffer_carryover_start));
			wmsg->dbuffer_end = wmsg->dbuffer_carryover_end -
					    wmsg->dbuffer_carryover_start;
		} else {
			wmsg->dbuffer_end = 0;
		}
		wmsg->dbuffer_carryover_end = 0;
		wmsg->dbuffer_carryover_start = 0;
		wmsg->rbuffer_count = 0;
		wmsg->state = WM_WAITING_FOR_CHANNEL;
	}
	return 0;
}
static int advance_waymsg_transfer(struct fd_translation_map *map,
		struct message_tracker *mt, int chanfd, int progfd,
		bool display_side, struct way_msg_state *wmsg,
		bool progsock_readable)
{
	if (wmsg->state == WM_WAITING_FOR_CHANNEL) {
		return advance_waymsg_chanwrite(wmsg, chanfd, display_side);
	} else {
		return advance_waymsg_progread(wmsg, map, mt, progfd,
				display_side, progsock_readable);
	}
}

int main_interface_loop(int chanfd, int progfd, bool no_gpu, bool display_side)
{
	const char *progdesc = display_side ? "compositor" : "application";
	if (set_fnctl_flag(chanfd, O_NONBLOCK | O_CLOEXEC) == -1) {
		wp_log(WP_ERROR,
				"Error making channel connection nonblocking: %s",
				strerror(errno));
		close(chanfd);
		close(progfd);
		return EXIT_FAILURE;
	}
	if (set_fnctl_flag(progfd, O_NONBLOCK | O_CLOEXEC) == -1) {
		wp_log(WP_ERROR, "Error making %s connection nonblocking: %s",
				progdesc, strerror(errno));
		close(chanfd);
		close(progfd);
		return EXIT_FAILURE;
	}

	struct way_msg_state way_msg;
	way_msg.state = WM_WAITING_FOR_PROGRAM;
	/* AFAIK, there is not documented upper bound for the size of a Wayland
	 * protocol message, but libwayland (in wl_buffer_put) effectively
	 * limits message sizes to 4096 bytes. We must therefore adopt a limit
	 * as least as large. */
	way_msg.dbuffer_maxsize = 4096;
	way_msg.dbuffer_carryover_end = 0;
	way_msg.dbuffer_carryover_start = 0;
	way_msg.dbuffer_end = 0;
	way_msg.dbuffer = malloc((size_t)way_msg.dbuffer_maxsize);
	way_msg.fds.size = 128;
	way_msg.fds.zone_start = 0;
	way_msg.fds.zone_end = 0;
	way_msg.fds.data = malloc((size_t)way_msg.fds.size * sizeof(int));
	way_msg.rbuffer = malloc((size_t)way_msg.fds.size * sizeof(int));
	way_msg.rbuffer_count = 0;
	way_msg.dbuffer_edited_maxsize = 2 * way_msg.dbuffer_maxsize;
	way_msg.dbuffer_edited = malloc((size_t)way_msg.dbuffer_edited_maxsize);
	way_msg.cmsg.blocks = NULL;
	way_msg.cmsg.nblocks = 0;
	way_msg.cmsg.transfer_block_headers = NULL;
	way_msg.cmsg.ntransfers = 0;
	way_msg.cmsg.meta_header = NULL;
	way_msg.cmsg.blocks_written = 0;

	struct chan_msg_state chan_msg;
	chan_msg.state = CM_WAITING_FOR_CHANNEL;
	chan_msg.fbuffer_maxsize = 128;
	chan_msg.fbuffer_count = 0;
	chan_msg.fbuffer =
			malloc((size_t)chan_msg.fbuffer_maxsize * sizeof(int));
	chan_msg.rbuffer_count = 0;
	chan_msg.rbuffer =
			malloc((size_t)chan_msg.fbuffer_maxsize * sizeof(int));
	chan_msg.tfbuffer =
			malloc((size_t)chan_msg.fbuffer_maxsize * sizeof(int));
	chan_msg.tfbuffer_count = 0;
	chan_msg.cmsg_size = 0;
	chan_msg.cmsg_end = 0;
	chan_msg.cmsg_buffer = NULL;
	chan_msg.dbuffer_start = 0;
	chan_msg.dbuffer_end = 0;
	chan_msg.dbuffer = NULL;
	chan_msg.dbuffer_edited_maxsize = way_msg.dbuffer_maxsize * 2;
	chan_msg.dbuffer_edited =
			malloc((size_t)chan_msg.dbuffer_edited_maxsize);

	struct fd_translation_map fdtransmap = {
			.local_sign = (display_side ? -1 : 1),
			.list = NULL,
			.max_local_id = 1,
			.rdata = {.disabled = no_gpu,
					.drm_fd = -1,
					.dev = NULL}};
	struct message_tracker mtracker;
	init_message_tracker(&mtracker);

	while (!shutdown_flag) {
		struct pollfd *pfds = NULL;
		int psize = 2 + count_npipes(&fdtransmap);
		pfds = calloc((size_t)psize, sizeof(struct pollfd));
		pfds[0].fd = chanfd;
		pfds[1].fd = progfd;
		pfds[0].events = 0;
		pfds[1].events = 0;
		if (way_msg.state == WM_WAITING_FOR_CHANNEL) {
			pfds[0].events |= POLLOUT;
		} else {
			pfds[1].events |= POLLIN;
		}
		if (chan_msg.state == CM_WAITING_FOR_CHANNEL) {
			pfds[0].events |= POLLIN;
		} else {
			pfds[1].events |= POLLOUT;
		}
		bool check_read = way_msg.state == WM_WAITING_FOR_PROGRAM;
		int npoll = 2 +
			    fill_with_pipes(&fdtransmap, pfds + 2, check_read);

		int r = poll(pfds, (nfds_t)npoll, -1);
		if (r == -1) {
			free(pfds);
			if (errno == EINTR) {
				wp_log(WP_ERROR,
						"poll interrupted: shutdown=%c",
						shutdown_flag ? 'Y' : 'n');
				continue;
			} else {
				wp_log(WP_ERROR,
						"poll failed due to, stopping: %s",
						strerror(errno));
				break;
			}
		}

		mark_pipe_object_statuses(&fdtransmap, npoll - 2, pfds + 2);
		bool progsock_readable = pfds[1].revents & POLLIN;
		bool chanmsg_active = (pfds[0].revents & POLLIN) ||
				      (pfds[1].revents & POLLOUT);
		bool hang_up = (pfds[0].revents & POLLHUP) ||
			       (pfds[1].revents & POLLHUP);
		free(pfds);
		if (hang_up) {
			wp_log(WP_ERROR, "Connection hang-up detected");
			break;
		}

		// Q: randomize the order of these?, to highlight accidental
		// dependencies?
		if (advance_chanmsg_transfer(&fdtransmap, &mtracker, chanfd,
				    progfd, display_side, &chan_msg,
				    chanmsg_active) == -1) {
			break;
		}
		if (advance_waymsg_transfer(&fdtransmap, &mtracker, chanfd,
				    progfd, display_side, &way_msg,
				    progsock_readable) == -1) {
			break;
		}
		// Periodic maintenance. It doesn't matter who does this
		flush_writable_pipes(&fdtransmap);
		close_rclosed_pipes(&fdtransmap);
	}

	cleanup_message_tracker(&fdtransmap, &mtracker);
	cleanup_translation_map(&fdtransmap);
	free(way_msg.dbuffer);
	free(way_msg.fds.data);
	free(way_msg.rbuffer);
	free(way_msg.cmsg.meta_header);
	free(way_msg.cmsg.blocks);
	free(way_msg.cmsg.transfer_block_headers);
	free(way_msg.dbuffer_edited);
	// We do not free chan_msg.dbuffer, as it is a subset of cmsg_buffer
	free(chan_msg.tfbuffer);
	free(chan_msg.fbuffer);
	free(chan_msg.rbuffer);
	free(chan_msg.cmsg_buffer);
	free(chan_msg.dbuffer_edited);
	close(chanfd);
	close(progfd);
	return EXIT_SUCCESS;
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
void translate_fds(struct fd_translation_map *map, int nfds, const int fds[],
		int ids[])
{
	for (int i = 0; i < nfds; i++) {
		ids[i] = translate_fd(map, fds[i], NULL)->remote_id;
	}
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

void collect_updates(struct fd_translation_map *map, int *ntransfers,
		struct transfer transfers[])
{
	for (struct shadow_fd *cur = map->list; cur; cur = cur->next) {
		if (cur->type == FDC_FILE) {
			if (!cur->is_dirty) {
				// File is clean, we have no reason to believe
				// that its contents could have changed
				continue;
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
				cur->file_mem_mirror = calloc(
						align(cur->file_size, 8), 1);
				// 8 extra bytes for worst case diff expansion
				cur->file_diff_buffer = calloc(
						align(cur->file_size + 8, 8),
						1);
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
			}
			if (intv_min >= intv_max) {
				continue;
			}
			bool delta = memcmp(cur->file_mem_local + intv_min,
						     (cur->file_mem_mirror +
								     intv_min),
						     (size_t)(intv_max -
								     intv_min)) !=
				     0;
			if (!delta) {
				continue;
			}
			if (!cur->file_diff_buffer) {
				/* Create diff buffer by need for remote files
				 */
				cur->file_diff_buffer =
						calloc(cur->file_size + 8, 1);
			}

			size_t diffsize;
			wp_log(WP_DEBUG, "Diff construction start");
			construct_diff(cur->file_size, (size_t)intv_min,
					(size_t)intv_max, cur->file_mem_mirror,
					cur->file_mem_local, &diffsize,
					cur->file_diff_buffer);
			wp_log(WP_DEBUG, "Diff construction end: %ld/%ld",
					diffsize, cur->file_size);
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
				continue;
			}
			cur->is_dirty = false;

			bool first = false;
			if (!cur->dmabuf_mem_mirror) {
				cur->dmabuf_mem_mirror =
						calloc(1, cur->dmabuf_size);
				// 8 extra bytes for diff messages, or
				// alternatively for type header info
				size_t diffb_size =
						(size_t)max(sizeof(struct dmabuf_slice_data),
								8) +
						(size_t)align((int)cur->dmabuf_size,
								8);
				cur->dmabuf_diff_buffer = calloc(diffb_size, 1);
				first = true;
			}
			void *handle = NULL;
			if (!cur->dmabuf_bo) {
				// ^ was not previously able to create buffer
				continue;
			}
			void *data = map_dmabuf(cur->dmabuf_bo, false, &handle);
			if (!data) {
				continue;
			}
			if (first) {
				// Write diff with a header, and build mirror,
				// only touching data once
				memcpy(cur->dmabuf_mem_mirror, data,
						cur->dmabuf_size);
				memcpy(cur->dmabuf_diff_buffer,
						&cur->dmabuf_info,
						sizeof(struct dmabuf_slice_data));
				memcpy(cur->dmabuf_diff_buffer +
								sizeof(struct dmabuf_slice_data),
						cur->dmabuf_mem_mirror,
						cur->dmabuf_size);
				// new transfer, we send file contents verbatim

				wp_log(WP_DEBUG, "Sending initial dmabuf");
				int nt = (*ntransfers)++;
				transfers[nt].data = cur->dmabuf_diff_buffer;
				transfers[nt].size =
						cur->dmabuf_size +
						sizeof(struct dmabuf_slice_data);
				transfers[nt].type = cur->type;
				transfers[nt].obj_id = cur->remote_id;
				transfers[nt].special = 0;
			} else {
				bool delta = memcmp(cur->dmabuf_mem_mirror,
						data, cur->dmabuf_size);
				if (delta) {
					// TODO: damage region support!
					size_t diffsize;
					wp_log(WP_DEBUG,
							"Diff construction start");
					construct_diff(cur->dmabuf_size, 0,
							cur->dmabuf_size,
							cur->dmabuf_mem_mirror,
							data, &diffsize,
							cur->dmabuf_diff_buffer);
					wp_log(WP_DEBUG,
							"Diff construction end: %ld/%ld",
							diffsize,
							cur->dmabuf_size);

					int nt = (*ntransfers)++;
					transfers[nt].obj_id = cur->remote_id;
					transfers[nt].data =
							cur->dmabuf_diff_buffer;
					transfers[nt].type = cur->type;
					transfers[nt].size = diffsize;
					transfers[nt].special = 0;
				}
			}
			if (unmap_dmabuf(cur->dmabuf_bo, handle) == -1) {
				// there was an issue unmapping; unmap_dmabuf
				// will log error
				continue;
			}
		} else if (fdcat_ispipe(cur->type)) {
			// Pipes always update, no matter what the message
			// stream indicates. Hence no cur->is_dirty flag check
			if (cur->pipe_recv.used > 0 || cur->pipe_onlyhere ||
					(cur->pipe_lclosed &&
							!cur->pipe_rclosed)) {
				cur->pipe_onlyhere = false;
				wp_log(WP_DEBUG,
						"Adding update to pipe RID=%d, with %ld bytes, close %c",
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

void pack_pipe_message(struct block_transfer *bt, int nids, const int ids[],
		int ntransfers, const struct transfer transfers[])
{
	// TODO: network byte order everything, content aware, somewhere in the
	// chain!

	bt->nblocks = ntransfers * 2 + 1;
	bt->ntransfers = ntransfers;
	bt->transfer_block_headers = calloc((size_t)bt->ntransfers,
			sizeof(struct pipe_elem_header));
	bt->blocks = calloc((size_t)bt->nblocks, sizeof(struct iovec));
	const size_t header_size =
			sizeof(uint64_t) +
			(size_t)nids * sizeof(struct pipe_elem_header);
	size_t total_size = header_size;

	for (int i = 0; i < ntransfers; i++) {
		struct pipe_elem_header *sd = &bt->transfer_block_headers[i];
		sd->id = transfers[i].obj_id;
		sd->type = (int)transfers[i].type;
		sd->size = (int)transfers[i].size;
		sd->special = transfers[i].special;

		size_t tsize = transfers[i].size;
		size_t num_longs = (tsize + sizeof(uint64_t) - 1) /
				   sizeof(uint64_t);
		bt->blocks[2 * i + 1].iov_len = sizeof(struct pipe_elem_header);
		bt->blocks[2 * i + 1].iov_base = sd;

		bt->blocks[2 * i + 2].iov_len = sizeof(uint64_t) * num_longs;
		bt->blocks[2 * i + 2].iov_base = transfers[i].data;

		total_size += sizeof(struct pipe_elem_header) +
			      sizeof(uint64_t) * num_longs;
	}

	uint64_t *cursor = calloc(header_size, 1);
	bt->meta_header = (char *)cursor;
	*cursor++ = total_size - sizeof(uint64_t); // size, excluding itself
	for (int i = 0; i < nids; i++) {
		struct pipe_elem_header *sd = (struct pipe_elem_header *)cursor;
		sd->id = ids[i];
		sd->type = -1;
		sd->size = -1;
		sd->special = 0;
		cursor += sizeof(struct pipe_elem_header) / sizeof(uint64_t);
	}
	bt->blocks[0].iov_len = header_size;
	bt->blocks[0].iov_base = bt->meta_header;
	bt->total_size = (int)total_size;
}

void unpack_pipe_message(size_t msglen, const char *msg, int *waylen,
		char **waymsg, int *nids, int ids[], int *ntransfers,
		struct transfer transfers[])
{
	if (msglen % 8 != 0) {
		wp_log(WP_ERROR, "Unpacking uneven message, size %ld=%ld mod 8",
				msglen, msglen % 8);
		*nids = 0;
		*ntransfers = 0;
		return;
	}
	int ni = 0, nt = 0;
	const uint64_t *cursor = (const uint64_t *)msg;
	const uint64_t *end = (const uint64_t *)(msg + msglen);
	while (cursor < end) {
		struct pipe_elem_header *sd = (struct pipe_elem_header *)cursor;
		if (sd->size != -1) {
			const char *data = ((const char *)cursor) + 16;
			if (sd->id == 0) {
				// There can only be one of these blocks
				*waylen = sd->size;
				*waymsg = (char *)data;
			} else {
				// Add to list of data transfers
				transfers[nt].obj_id = sd->id;
				transfers[nt].size = (size_t)sd->size;
				transfers[nt].type = (fdcat_t)sd->type;
				transfers[nt].data = (char *)data;
				transfers[nt].special = sd->special;
				nt++;
			}
			size_t nlongs = ((size_t)sd->size + 7) / 8;
			if (nlongs > msglen / 8) {
				wp_log(WP_ERROR,
						"Excessively long buffer: length: %ld x uint64_t",
						nlongs);
				return;
			}
			cursor += (sizeof(struct pipe_elem_header) /
						  sizeof(uint64_t)) +
				  nlongs;
		} else {
			// Add to list of file descriptors passed along
			ids[ni++] = sd->id;

			cursor += (sizeof(struct pipe_elem_header) /
					sizeof(uint64_t));
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
					"Could not untranslate remote id %d in map. Application will probably crash.",
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
void apply_updates(struct fd_translation_map *map, int ntransfers,
		const struct transfer transfers[])
{
	for (int i = 0; i < ntransfers; i++) {
		apply_update(map, &transfers[i]);
	}
}

void wait_on_children(struct kstack **children, int options)
{
	struct kstack *cur = *children;
	struct kstack **prv = children;
	while (cur) {
		if (waitpid(cur->pid, NULL, options) > 0) {
			wp_log(WP_DEBUG, "Child handler %d has died", cur->pid);
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

void parse_and_prune_messages(struct message_tracker *mt,
		struct fd_translation_map *map, bool on_display_side,
		bool from_client, struct char_window *source_bytes,
		struct char_window *dest_bytes, struct int_window *fds)
{
	bool anything_unknown = false;
	struct char_window scan_bytes;
	scan_bytes.data = dest_bytes->data;
	scan_bytes.zone_start = dest_bytes->zone_start;
	scan_bytes.zone_end = dest_bytes->zone_start;
	scan_bytes.size = dest_bytes->size;

	for (; source_bytes->zone_start < source_bytes->zone_end;) {
		if (source_bytes->zone_end - source_bytes->zone_start < 8) {
			// Not enough remaining bytes to parse the header
			wp_log(WP_DEBUG, "Insufficient bytes for header: %d %d",
					source_bytes->zone_start,
					source_bytes->zone_end);
			break;
		}
		int msgsz = peek_message_size(
				&source_bytes->data[source_bytes->zone_start]);
		if (source_bytes->zone_start + msgsz > source_bytes->zone_end) {
			wp_log(WP_DEBUG, "Insufficient bytes");
			// Not enough remaining bytes to contain the message
			break;
		}
		if (msgsz < 8) {
			wp_log(WP_DEBUG, "Degenerate message, claimed len=%d",
					msgsz);
			// Not enough remaining bytes to contain the message
			break;
		}

		/* We copy the message to the trailing end of the in-progress
		 * buffer; the parser may elect to modify the message's size */
		memcpy(&scan_bytes.data[scan_bytes.zone_start],
				&source_bytes->data[source_bytes->zone_start],
				(size_t)msgsz);
		source_bytes->zone_start += msgsz;
		scan_bytes.zone_end = scan_bytes.zone_start + msgsz;

		enum parse_state pstate = handle_message(mt, map,
				on_display_side, from_client, &scan_bytes, fds);
		if (pstate == PARSE_UNKNOWN || pstate == PARSE_ERROR) {
			anything_unknown = true;
		}
		scan_bytes.zone_start = scan_bytes.zone_end;
	}
	dest_bytes->zone_end = scan_bytes.zone_end;

	if (anything_unknown) {
		// All-un-owned buffers are assumed to have changed.
		// (Note that in some cases, a new protocol could imply a change
		// for an existing buffer; it may make sense to mark everything
		// dirty, then.)
		for (struct shadow_fd *cur = map->list; cur; cur = cur->next) {
			if (!cur->has_owner) {
				cur->is_dirty = true;
			}
		}
	}
	return;
}
