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

#include "main.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

// The maximum number of fds libwayland can recvmsg at once
#define MAX_LIBWAY_FDS 28
static ssize_t iovec_read(
		int conn, char *buf, size_t buflen, struct int_window *fds)
{
	char cmsgdata[(CMSG_LEN(MAX_LIBWAY_FDS * sizeof(int32_t)))];
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

	// Read cmsg
	struct cmsghdr *header = CMSG_FIRSTHDR(&msg);
	while (header) {
		struct cmsghdr *nxt_hdr = CMSG_NXTHDR(&msg, header);
		if (header->cmsg_level != SOL_SOCKET ||
				header->cmsg_type != SCM_RIGHTS) {
			header = nxt_hdr;
			continue;
		}

		int *data = (int *)CMSG_DATA(header);
		int nf = (int)((header->cmsg_len - CMSG_LEN(0)) / sizeof(int));

		if (buf_ensure_size(fds->zone_end + nf, sizeof(int), &fds->size,
				    (void **)&fds->data) == -1) {
			wp_error("Failed to allocate space for new fds");
			errno = ENOMEM;
			ret = -1;
		} else {
			for (int i = 0; i < nf; i++) {
				fds->data[fds->zone_end++] = data[i];
			}
		}

		header = nxt_hdr;
	}
	return ret;
}

static ssize_t iovec_write(int conn, const char *buf, size_t buflen,
		const int *fds, int numfds, int *nfds_written)
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
				wp_error("Writing invalid fd %d", fds[i]);
			}
		}

		frst->cmsg_len = CMSG_LEN(nwritten * sizeof(int));
		msg.msg_controllen = CMSG_SPACE(nwritten * sizeof(int));
		wp_debug("Writing %d fds to cmsg data", *nfds_written);
	} else {
		*nfds_written = 0;
	}

	ssize_t ret = sendmsg(conn, &msg, 0);
	return ret;
}

static int translate_fds(struct fd_translation_map *map,
		struct render_data *render, int nfds, const int fds[],
		int ids[])
{
	for (int i = 0; i < nfds; i++) {
		struct shadow_fd *sfd = get_shadow_for_local_fd(map, fds[i]);
		if (!sfd) {
			/* Autodetect type + create shadow fd */
			size_t fdsz = 0;
			enum fdcat fdtype = get_fd_type(fds[i], &fdsz);
			sfd = translate_fd(map, render, fds[i], fdtype, fdsz,
					NULL, false, false);
		}
		if (sfd) {
			ids[i] = sfd->remote_id;
		} else {
			return -1;
		}
	}
	return 0;
}
/** Given a list of global ids, and an up-to-date translation map, produce local
 * file descriptors */
static void untranslate_ids(struct fd_translation_map *map, int nids,
		const int *ids, int *fds)
{
	for (int i = 0; i < nids; i++) {
		struct shadow_fd *shadow = get_shadow_for_rid(map, ids[i]);
		if (!shadow) {
			wp_error("Could not untranslate remote id %d in map. Application will probably crash.",
					ids[i]);
			fds[i] = -1;
		} else {
			fds[i] = shadow->fd_local;
		}
	}
}

enum wm_state { WM_WAITING_FOR_PROGRAM, WM_WAITING_FOR_CHANNEL, WM_TERMINAL };
/** This state corresponds to the in-progress transfer from the program
 * (compositor or application) and its pipes/buffers to the channel. */
struct way_msg_state {
	enum wm_state state;

	/** Window zone contains the message data which has been read
	 * but not yet parsed/copied to proto_write */
	struct char_window proto_read;
	/** Buffer of complete protocol messages to be written to the channel */
	struct char_window proto_write;

	/** Queue of fds to be used by protocol parser */
	struct int_window fds;

	/** Individual messages, to be sent out via writev and deleted on
	 * acknowledgement */
	struct transfer_queue transfers;
	/** bytes written in this cycle, for debug */
	int total_written;
	/** Maximum chunk size to writev at once*/
	int max_iov;

	/** Transfers to send after the compute queue is empty */
	int ntrailing;
	struct iovec trailing[3];

	/** Statically allocated message acknowledgement messages; due
	 * to the way they are updated out of order, at most two are needed */
	struct wmsg_ack ack_msgs[2];
};

enum cm_state { CM_WAITING_FOR_PROGRAM, CM_WAITING_FOR_CHANNEL, CM_TERMINAL };
/** This state corresponds to the in-progress transfer from the channel
 * to the program and the buffers/pipes on which will be written. */
struct chan_msg_state {
	enum cm_state state;

	/** Edited protocol data which is being written to the program */
	struct char_window proto_write;

	/**< FDs that should immediately be transferred to the program */
	struct int_window transf_fds;
	/**< FD queue for the protocol parser */
	struct int_window proto_fds;

#define RECV_GOAL_READ_SIZE 131072
	char *recv_buffer; // ring-like buffer for message data
	size_t recv_size;
	size_t recv_start; // (recv_buffer+rev_start) should be a message header
	size_t recv_end;   // last byte read from channel, always >=recv_start
	int recv_unhandled_messages; // number of messages to parse
};

/** State used by both forward and reverse messages */
struct cross_state {
	/* Which was the last received message received from the other
	 * application, for which acknowledgement was sent? */
	uint32_t last_acked_msgno;
	/* Which was the last message number received from the other
	 * application? */
	uint32_t last_received_msgno;
	/* What was the highest number message received from the other
	 * application? (matches last_received, unless we needed a restart */
	uint32_t newest_received_msgno;
	/* Which was the last message number sent to the other application which
	 * was acknowledged by that side? */
	uint32_t last_confirmed_msgno;
};

static int interpret_chanmsg(struct chan_msg_state *cmsg,
		struct cross_state *cxs, struct globals *g, bool display_side,
		char *packet)
{
	uint32_t size_and_type = *(uint32_t *)packet;
	size_t unpadded_size = transfer_size(size_and_type);
	enum wmsg_type type = transfer_type(size_and_type);
	if (type == WMSG_CLOSE) {
		/* No new messages from the channel to the program will be
		 * allowed after this */
		cmsg->state = CM_TERMINAL;

		wp_debug("Other side has closed");
		if (unpadded_size < 8) {
			return ERR_FATAL;
		}
		int32_t code = ((int32_t *)packet)[1];
		if (code == ERR_FATAL) {
			return ERR_FATAL;
		} else if (code == ERR_NOMEM) {
			return ERR_NOMEM;
		} else {
			return ERR_STOP;
		}
	} else if (type == WMSG_RESTART) {
		struct wmsg_restart *ackm = (struct wmsg_restart *)packet;
		wp_debug("Received restart message: remote last saw ack %d (we last recvd %d, acked %d)",
				ackm->last_ack_received,
				cxs->last_received_msgno,
				cxs->last_acked_msgno);
		cxs->last_received_msgno = ackm->last_ack_received;
		return 0;
	} else if (type == WMSG_ACK_NBLOCKS) {
		struct wmsg_ack *ackm = (struct wmsg_ack *)packet;

		if (ackm->messages_received >= cxs->last_received_msgno) {
			cxs->last_confirmed_msgno = ackm->messages_received;
		}
		return 0;
	} else {
		cxs->last_received_msgno++;
		if (cxs->last_received_msgno <= cxs->newest_received_msgno) {
			/* Skip packet, as we already received it */
			wp_debug("Ignoring replayed message %d (newest=%d)",
					cxs->last_received_msgno,
					cxs->newest_received_msgno);
			return 0;
		}
		cxs->newest_received_msgno = cxs->last_received_msgno;
	}

	if (type == WMSG_INJECT_RIDS) {
		const int32_t *fds = &((const int32_t *)packet)[1];
		int nfds = (int)((unpadded_size - sizeof(uint32_t)) /
				 sizeof(int32_t));

		if (buf_ensure_size(nfds, sizeof(int), &cmsg->transf_fds.size,
				    (void **)&cmsg->transf_fds.data) == -1) {
			wp_error("Allocation failure for fd transfer queue, expect a crash");
			return ERR_NOMEM;
		}
		/* Reset transfer buffer; all fds in here were already sent */
		cmsg->transf_fds.zone_start = 0;
		cmsg->transf_fds.zone_end = nfds;
		untranslate_ids(&g->map, nfds, fds, cmsg->transf_fds.data);
		if (nfds > 0) {
			if (buf_ensure_size(cmsg->proto_fds.zone_end + nfds,
					    sizeof(int), &cmsg->proto_fds.size,
					    (void **)&cmsg->proto_fds.data) ==
					-1) {
				wp_error("Allocation failure for fd protocol queue");
				return ERR_NOMEM;
			}

			// Append the new file descriptors to the parsing queue
			memcpy(cmsg->proto_fds.data + cmsg->proto_fds.zone_end,
					cmsg->transf_fds.data,
					sizeof(int) * (size_t)nfds);
			cmsg->proto_fds.zone_end += nfds;
		}
		return 0;
	} else if (type == WMSG_PROTOCOL) {
		/* While by construction, the provided message buffer should be
		 * aligned with individual message boundaries, it is not
		 * guaranteed that all file descriptors provided will be used by
		 * the messages. This makes fd handling more complicated. */
		int protosize = (int)(unpadded_size - sizeof(uint32_t));
		// TODO: have message editing routines ensure size, so
		// that this limit can be tighter
		if (buf_ensure_size(protosize + 1024, 1,
				    &cmsg->proto_write.size,
				    (void **)&cmsg->proto_write.data) == -1) {
			wp_error("Allocation failure for message workspace");
			return ERR_NOMEM;
		}
		cmsg->proto_write.zone_end = 0;
		cmsg->proto_write.zone_start = 0;

		struct char_window src;
		src.data = packet + sizeof(uint32_t);
		src.zone_start = 0;
		src.zone_end = protosize;
		src.size = protosize;
		parse_and_prune_messages(g, display_side, display_side, &src,
				&cmsg->proto_write, &cmsg->proto_fds);
		if (src.zone_start != src.zone_end) {
			wp_error("did not expect partial messages over channel, only parsed %d/%d bytes",
					src.zone_start, src.zone_end);
			return ERR_FATAL;
		}
		/* Update file descriptor queue */
		if (cmsg->proto_fds.zone_end > cmsg->proto_fds.zone_start) {
			memmove(cmsg->proto_fds.data,
					cmsg->proto_fds.data +
							cmsg->proto_fds.zone_start,
					sizeof(int) * (size_t)(cmsg->proto_fds.zone_end >
								      cmsg->proto_fds.zone_start));
			cmsg->proto_fds.zone_end -= cmsg->proto_fds.zone_start;
		}
		return 0;
	} else {
		if (unpadded_size < sizeof(struct wmsg_basic)) {
			wp_error("Message is too small to contain header+RID, %d bytes",
					unpadded_size);
			return ERR_FATAL;
		}
		const struct wmsg_basic *op_header =
				(const struct wmsg_basic *)packet;
		struct bytebuf msg = {
				.data = packet,
				.size = unpadded_size,
		};
		wp_debug("Received %s for RID=%d (len %d)",
				wmsg_type_to_str(type), op_header->remote_id,
				unpadded_size);
		return apply_update(&g->map, &g->threads, &g->render, type,
				op_header->remote_id, &msg);
	}
}

static int advance_chanmsg_chanread(struct chan_msg_state *cmsg,
		struct cross_state *cxs, int chanfd, bool display_side,
		struct globals *g)
{
	/* Setup read operation to be able to read a minimum number of bytes,
	 * wrapping around as early as overlap conditions permit */
	if (cmsg->recv_unhandled_messages == 0) {
		struct iovec vec[2];
		memset(vec, 0, sizeof(vec));
		int nvec;
		if (cmsg->recv_start == cmsg->recv_end) {
			/* A fresh packet */
			cmsg->recv_start = 0;
			cmsg->recv_end = 0;
			nvec = 1;
			vec[0].iov_base = cmsg->recv_buffer;
			vec[0].iov_len = (size_t)(cmsg->recv_size / 2);
		} else if (cmsg->recv_end <
				cmsg->recv_start + sizeof(uint32_t)) {
			/* Didn't quite finish reading the header */
			int recvsz = (int)cmsg->recv_size;
			if (buf_ensure_size((int)cmsg->recv_end +
							    RECV_GOAL_READ_SIZE,
					    1, &recvsz,
					    (void **)&cmsg->recv_buffer) ==
					-1) {
				wp_error("Allocation failure, resizing receive buffer failed");
				return ERR_NOMEM;
			}
			cmsg->recv_size = (size_t)recvsz;

			nvec = 1;
			vec[0].iov_base = cmsg->recv_buffer + cmsg->recv_end;
			vec[0].iov_len = RECV_GOAL_READ_SIZE;
		} else {
			/* Continuing an old packet; space made available last
			 * time */
			uint32_t *header = (uint32_t *)&cmsg->recv_buffer
							   [cmsg->recv_start];
			size_t sz = alignz(transfer_size(*header), 4);

			size_t read_end = cmsg->recv_start + sz;
			bool wraparound =
					cmsg->recv_start >= RECV_GOAL_READ_SIZE;
			if (!wraparound) {
				read_end = maxu(read_end,
						cmsg->recv_end +
								RECV_GOAL_READ_SIZE);
			}
			int recvsz = (int)cmsg->recv_size;
			if (buf_ensure_size((int)read_end, 1, &recvsz,
					    (void **)&cmsg->recv_buffer) ==
					-1) {
				wp_error("Allocation failure, resizing receive buffer failed");
				return ERR_NOMEM;
			}
			cmsg->recv_size = (size_t)recvsz;

			nvec = 1;
			vec[0].iov_base = cmsg->recv_buffer + cmsg->recv_end;
			vec[0].iov_len = read_end - cmsg->recv_end;
			if (wraparound) {
				nvec = 2;
				vec[1].iov_base = cmsg->recv_buffer;
				vec[1].iov_len = cmsg->recv_start;
			}
		}

		ssize_t r = readv(chanfd, vec, nvec);
		if (r == -1 && (errno == EWOULDBLOCK || errno == EAGAIN)) {
			wp_debug("Read would block");
			return 0;
		} else if (r == 0 || (r == -1 && errno == ECONNRESET)) {
			wp_debug("Channel connection closed");
			return ERR_DISCONN;
		} else if (r == -1) {
			wp_error("chanfd read failure: %s", strerror(errno));
			return ERR_FATAL;
		} else {
			if (nvec == 2 && (size_t)r >= vec[0].iov_len) {
				/* Complete parsing this message */
				int cm_ret = interpret_chanmsg(cmsg, cxs, g,
						display_side,
						cmsg->recv_buffer +
								cmsg->recv_start);
				if (cm_ret < 0) {
					return cm_ret;
				}

				cmsg->recv_start = 0;
				cmsg->recv_end = (size_t)r - vec[0].iov_len;

				if (cmsg->proto_write.zone_start <
						cmsg->proto_write.zone_end) {
					goto next_stage;
				}
			} else {
				cmsg->recv_end += (size_t)r;
			}
		}
	}

	/* Recount unhandled messages */
	cmsg->recv_unhandled_messages = 0;
	size_t i = cmsg->recv_start;
	while (i + sizeof(uint32_t) <= cmsg->recv_end) {
		uint32_t *header = (uint32_t *)&cmsg->recv_buffer[i];
		size_t sz = alignz(transfer_size(*header), 4);
		if (sz == 0) {
			wp_error("Encountered malformed zero size packet");
			return ERR_FATAL;
		}
		i += sz;
		if (i > cmsg->recv_end) {
			break;
		}
		cmsg->recv_unhandled_messages++;
	}

	while (cmsg->recv_unhandled_messages > 0) {
		char *packet_start = &cmsg->recv_buffer[cmsg->recv_start];
		uint32_t *header = (uint32_t *)packet_start;
		size_t sz = transfer_size(*header);
		int cm_ret = interpret_chanmsg(
				cmsg, cxs, g, display_side, packet_start);
		if (cm_ret < 0) {
			return cm_ret;
		}
		cmsg->recv_start += alignz(sz, 4);
		cmsg->recv_unhandled_messages--;

		if (cmsg->proto_write.zone_start < cmsg->proto_write.zone_end) {
			goto next_stage;
		}
	}
	return 0;
next_stage:
	/* When protocol data was sent, switch to trying to write the protocol
	 * data to its socket, before trying to parse any other message */
	cmsg->state = CM_WAITING_FOR_PROGRAM;
	DTRACE_PROBE(waypipe, chanmsg_program_wait);
	return 0;
}
static int advance_chanmsg_progwrite(struct chan_msg_state *cmsg, int progfd,
		bool display_side, struct globals *g)
{
	const char *progdesc = display_side ? "compositor" : "application";
	// Write as much as possible
	while (cmsg->proto_write.zone_start < cmsg->proto_write.zone_end) {
		ssize_t wc = iovec_write(progfd,
				cmsg->proto_write.data +
						cmsg->proto_write.zone_start,
				(size_t)(cmsg->proto_write.zone_end -
						cmsg->proto_write.zone_start),
				cmsg->transf_fds.data,
				cmsg->transf_fds.zone_end,
				&cmsg->transf_fds.zone_start);
		if (wc == -1 && (errno == EWOULDBLOCK || errno == EAGAIN)) {
			wp_debug("Write to the %s would block", progdesc);
			return 0;
		} else if (wc == -1 &&
				(errno == EPIPE || errno == ECONNRESET)) {
			wp_error("%s has closed", progdesc);
			/* The program has closed its end of the connection,
			 * so waypipe can also cease to process all messages and
			 * data updates that would be directed to it */
			cmsg->state = CM_TERMINAL;
			return ERR_STOP;
		} else if (wc == -1) {
			wp_error("%s write failure %zd: %s", progdesc, wc,
					strerror(errno));
			return ERR_FATAL;
		} else {
			cmsg->proto_write.zone_start += (int)wc;
			wp_debug("Wrote to %s, %d/%d bytes in chunk %zd, %d/%d fds",
					progdesc, cmsg->proto_write.zone_start,
					cmsg->proto_write.zone_end, wc,
					cmsg->transf_fds.zone_start,
					cmsg->transf_fds.zone_end);

			if (cmsg->transf_fds.zone_start > 0) {
				decref_transferred_fds(&g->map,
						cmsg->transf_fds.zone_start,
						cmsg->transf_fds.data);
				memmove(cmsg->transf_fds.data,
						cmsg->transf_fds.data +
								cmsg->transf_fds.zone_start,
						(size_t)(cmsg->transf_fds.zone_end -
								cmsg->transf_fds.zone_start) *
								sizeof(int));
				cmsg->transf_fds.zone_end -=
						cmsg->transf_fds.zone_start;
			}
		}
	}
	if (cmsg->proto_write.zone_start == cmsg->proto_write.zone_end) {
		wp_debug("Write to the %s succeeded", progdesc);
		cmsg->state = CM_WAITING_FOR_CHANNEL;
		DTRACE_PROBE(waypipe, chanmsg_channel_wait);
	}
	return 0;
}
static int advance_chanmsg_transfer(struct globals *g,
		struct chan_msg_state *cmsg, struct cross_state *cxs,
		bool display_side, int chanfd, int progfd, bool any_changes)
{
	if (!any_changes) {
		return 0;
	}
	if (cmsg->state == CM_WAITING_FOR_CHANNEL) {
		return advance_chanmsg_chanread(
				cmsg, cxs, chanfd, display_side, g);
	} else if (cmsg->state == CM_WAITING_FOR_PROGRAM) {
		return advance_chanmsg_progwrite(cmsg, progfd, display_side, g);
	}
	return 0;
}

static void clear_old_transfers(
		struct transfer_queue *td, uint32_t inclusive_cutoff)
{
	for (int i = 0; i < td->end; i++) {
		if (td->vecs[i].iov_len == 0) {
			wp_error("Unexpected zero sized item %d [%d,%d)", i,
					td->start, td->end);
		}
	}
	int k = 0;
	for (int i = 0; i < td->start; i++) {
		if (td->meta[i].msgno > inclusive_cutoff) {
			break;
		}
		if (!td->meta[i].static_alloc) {
			free(td->vecs[i].iov_base);
		}
		td->vecs[i].iov_base = NULL;
		td->vecs[i].iov_len = 0;
		k = i + 1;
	}
	if (k > 0) {
		size_t nshift = (size_t)(td->end - k);
		memmove(td->meta, td->meta + k, nshift * sizeof(td->meta[0]));
		memmove(td->vecs, td->vecs + k, nshift * sizeof(td->vecs[0]));
		td->start -= k;
		td->end -= k;
	}
}

/* Returns 0 sucessful -1 if fatal error, -2 if closed */
static int partial_write_transfer(int chanfd, struct transfer_queue *td,
		int *total_written, int max_iov)
{
	// Waiting for channel write to complete
	if (td->start < td->end) {
		/* Advance the current element by amount actually written */
		char *orig_base = td->vecs[td->start].iov_base;
		size_t orig_len = td->vecs[td->start].iov_len;
		td->vecs[td->start].iov_base =
				orig_base + td->partial_write_amt;
		td->vecs[td->start].iov_len = orig_len - td->partial_write_amt;
		int count = min(max_iov, td->end - td->start);
		ssize_t wr = writev(chanfd, &td->vecs[td->start], count);
		td->vecs[td->start].iov_base = orig_base;
		td->vecs[td->start].iov_len = orig_len;

		if (wr == -1 && (errno == EWOULDBLOCK || errno == EAGAIN)) {
			return 0;
		} else if (wr == -1 &&
				(errno == ECONNRESET || errno == EPIPE)) {
			wp_debug("Channel connection closed");
			return ERR_DISCONN;
		} else if (wr == -1) {
			wp_error("chanfd write failure: %s", strerror(errno));
			return ERR_FATAL;
		}

		size_t uwr = (size_t)wr;
		*total_written += (int)wr;
		while (uwr > 0 && td->start < td->end) {
			/* Skip past zero-length blocks */
			if (td->vecs[td->start].iov_len == 0) {
				td->start++;
				continue;
			}
			size_t left = td->vecs[td->start].iov_len -
				      td->partial_write_amt;
			if (left > uwr) {
				/* Block partially completed */
				td->partial_write_amt += uwr;
				uwr = 0;
			} else {
				/* Block completed */
				td->partial_write_amt = 0;
				uwr -= left;
				td->start++;
			}
		}
	}
	return 0;
}

static int advance_waymsg_chanwrite(struct way_msg_state *wmsg,
		struct cross_state *cxs, struct globals *g, int chanfd,
		bool display_side)
{
	const char *progdesc = display_side ? "compositor" : "application";

	/* Copy the data in the transfer queue to the write queue. */
	(void)transfer_load_async(&wmsg->transfers);

	// First, clear out any transfers that are no longer needed
	clear_old_transfers(&wmsg->transfers, cxs->last_confirmed_msgno);

	/* Acknowledge the other side's transfers as soon as possible */
	if (cxs->last_acked_msgno != cxs->last_received_msgno) {
		if (transfer_ensure_size(&wmsg->transfers,
				    wmsg->transfers.end + 1) == -1) {
			wp_error("Failed to allocate space for ack message transfer");
			goto ackmsg_fail;
		}
		/* To avoid infinite regress, receive acknowledgement
		 * messages do not themselves increase the message counters. */
		uint32_t ack_msgno;
		if (wmsg->transfers.start == wmsg->transfers.end) {
			ack_msgno = wmsg->transfers.last_msgno;
		} else {
			ack_msgno = wmsg->transfers.meta[wmsg->transfers.start]
						    .msgno;
		}

		/* This is the next point where messages can be changed */
		int next_slot = (wmsg->transfers.partial_write_amt > 0)
						? wmsg->transfers.start + 1
						: wmsg->transfers.start;
		struct wmsg_ack *not_in_prog_msg = NULL;
		struct wmsg_ack *queued_msg = NULL;
		for (size_t i = 0; i < 2; i++) {
			if (wmsg->transfers.partial_write_amt > 0 &&
					wmsg->transfers.vecs[wmsg->transfers.start]
									.iov_base ==
							&wmsg->ack_msgs[i]) {
				not_in_prog_msg = &wmsg->ack_msgs[1 - i];
			}
			if (wmsg->transfers.vecs[next_slot].iov_base ==
					&wmsg->ack_msgs[i]) {
				queued_msg = &wmsg->ack_msgs[i];
			}
		}

		if (!queued_msg) {
			/* Insert a message--which is not partially written--
			 * in the next available slot, pushing forward other
			 * messages */
			if (!not_in_prog_msg) {
				queued_msg = &wmsg->ack_msgs[0];
			} else {
				queued_msg = not_in_prog_msg;
			}

			if (next_slot < wmsg->transfers.end) {
				size_t nmoved = (size_t)(wmsg->transfers.end -
							 next_slot);
				memmove(wmsg->transfers.vecs + next_slot + 1,
						wmsg->transfers.vecs +
								next_slot,
						sizeof(*wmsg->transfers.vecs) *
								nmoved);
				memmove(wmsg->transfers.meta + next_slot + 1,
						wmsg->transfers.meta +
								next_slot,
						sizeof(*wmsg->transfers.meta) *
								nmoved);
			}
			wmsg->transfers.vecs[next_slot].iov_len =
					sizeof(struct wmsg_ack);
			wmsg->transfers.vecs[next_slot].iov_base = queued_msg;
			wmsg->transfers.meta[next_slot].msgno = ack_msgno;
			wmsg->transfers.meta[next_slot].static_alloc = true;
			wmsg->transfers.end++;
		}

		/* Modify the message which is now next up in the transfer
		 * queue */
		queued_msg->size_and_type = transfer_header(
				sizeof(struct wmsg_ack), WMSG_ACK_NBLOCKS);
		queued_msg->messages_received = cxs->last_received_msgno;
		cxs->last_acked_msgno = cxs->last_received_msgno;
	ackmsg_fail:;
	}

	int ret = partial_write_transfer(chanfd, &wmsg->transfers,
			&wmsg->total_written, wmsg->max_iov);
	if (ret < 0) {
		return ret;
	}

	bool is_done = false;
	struct task_data task;
	bool has_task = request_work_task(&g->threads, &task, &is_done);

	/* Run a task ourselves, making use of the main thread */
	if (has_task) {
		run_task(&task, &g->threads.threads[0]);

		pthread_mutex_lock(&g->threads.work_mutex);
		g->threads.tasks_in_progress--;
		pthread_mutex_unlock(&g->threads.work_mutex);
		/* To skip the next poll */
		uint8_t triv = 0;
		if (write(g->threads.selfpipe_w, &triv, 1) == -1) {
			wp_error("Failed to write to self-pipe");
		}
	}

	if (is_done) {
		/* It's possible for the last task to complete between
		 * `transfer_load_async` and `request_work_task` in this
		 * function, so copy out any remaining messages.`*/
		(void)transfer_load_async(&wmsg->transfers);
	}

	if (is_done && wmsg->ntrailing > 0) {
		for (int i = 0; i < wmsg->ntrailing; i++) {
			transfer_add(&wmsg->transfers,
					wmsg->trailing[i].iov_len,
					wmsg->trailing[i].iov_base);
		}

		wmsg->ntrailing = 0;
		memset(wmsg->trailing, 0, sizeof(wmsg->trailing));
	}

	if (wmsg->transfers.start == wmsg->transfers.end && is_done) {
		for (struct shadow_fd_link *lcur = g->map.link.l_next,
					   *lnxt = lcur->l_next;
				lcur != &g->map.link;
				lcur = lnxt, lnxt = lcur->l_next) {
			/* Note: finish_update() may delete `cur` */
			struct shadow_fd *cur = (struct shadow_fd *)lcur;
			finish_update(cur);
			destroy_shadow_if_unreferenced(cur);
		}

		/* Reset work queue */
		pthread_mutex_lock(&g->threads.work_mutex);
		if (g->threads.stack_count > 0 ||
				g->threads.tasks_in_progress > 0) {
			wp_error("Multithreading state failure");
		}
		g->threads.do_work = false;
		g->threads.stack_count = 0;
		g->threads.tasks_in_progress = 0;
		pthread_mutex_unlock(&g->threads.work_mutex);

		DTRACE_PROBE(waypipe, channel_write_end);
		size_t unacked_bytes = 0;
		for (int i = 0; i < wmsg->transfers.end; i++) {
			unacked_bytes += wmsg->transfers.vecs[i].iov_len;
		}

		wp_debug("Sent %d-byte message from %s to channel; %zu-bytes in flight",
				wmsg->total_written, progdesc, unacked_bytes);

		/* do not delete the used transfers yet; we need a remote
		 * acknowledgement */
		wmsg->total_written = 0;
		wmsg->state = WM_WAITING_FOR_PROGRAM;
	}
	return 0;
}
static int advance_waymsg_progread(struct way_msg_state *wmsg,
		struct globals *g, int progfd, bool display_side,
		bool progsock_readable)
{
	const char *progdesc = display_side ? "compositor" : "application";
	// We have data to read from programs/pipes
	bool new_proto_data = false;
	int old_fbuffer_end = wmsg->fds.zone_end;
	if (progsock_readable) {
		// Read /once/
		ssize_t rc = iovec_read(progfd,
				wmsg->proto_read.data +
						wmsg->proto_read.zone_end,
				(size_t)(wmsg->proto_read.size -
						wmsg->proto_read.zone_end),
				&wmsg->fds);
		if (rc == -1 && (errno == EWOULDBLOCK || errno == EAGAIN)) {
			// do nothing
		} else if (rc == 0 || (rc == -1 && errno == ECONNRESET)) {
			wp_error("%s has closed", progdesc);
			// state transitions handled in main loop
			return ERR_STOP;
		} else if (rc == -1) {
			wp_error("%s read failure: %s", progdesc,
					strerror(errno));
			return ERR_FATAL;
		} else {
			// We have successfully read some data.
			wmsg->proto_read.zone_end += (int)rc;
			new_proto_data = true;
		}
	}

	if (new_proto_data) {
		wp_debug("Read %d new file descriptors, have %d total now",
				wmsg->fds.zone_end - old_fbuffer_end,
				wmsg->fds.zone_end);

		if (buf_ensure_size(wmsg->proto_read.size + 1024, 1,
				    &wmsg->proto_write.size,
				    (void **)&wmsg->proto_write.data) == -1) {
			wp_error("Allocation failure for message workspace");
			return ERR_NOMEM;
		}

		wmsg->proto_write.zone_start = 0;
		wmsg->proto_write.zone_end = 0;
		parse_and_prune_messages(g, display_side, !display_side,
				&wmsg->proto_read, &wmsg->proto_write,
				&wmsg->fds);

		/* Recycle partial message bytes */
		if (wmsg->proto_read.zone_start > 0) {
			if (wmsg->proto_read.zone_end >
					wmsg->proto_read.zone_start) {
				memmove(wmsg->proto_read.data,
						wmsg->proto_read.data +
								wmsg->proto_read.zone_start,
						(size_t)(wmsg->proto_read.zone_end -
								wmsg->proto_read.zone_start));
			}
			wmsg->proto_read.zone_end -=
					wmsg->proto_read.zone_start;
			wmsg->proto_read.zone_start = 0;
		}
	}

	read_readable_pipes(&g->map);

	for (struct shadow_fd_link *lcur = g->map.link.l_next,
				   *lnxt = lcur->l_next;
			lcur != &g->map.link;
			lcur = lnxt, lnxt = lcur->l_next) {
		/* Note: finish_update() may delete `cur` */
		struct shadow_fd *cur = (struct shadow_fd *)lcur;
		collect_update(&g->threads, cur, &wmsg->transfers,
				g->config->old_video_mode);
		/* collecting updates can reset `pipe.remote_can_X` state, so
		 * garbage collect the sfd immediately after */
		destroy_shadow_if_unreferenced(cur);
	}

	int num_mt_tasks = start_parallel_work(
			&g->threads, &wmsg->transfers.async_recv_queue);

	if (new_proto_data) {
		/* Send all file descriptors which have been used by the
		 * protocol parser, translating them if this has not already
		 * been done */
		if (wmsg->fds.zone_start > 0) {
			size_t act_size = (size_t)wmsg->fds.zone_start *
							  sizeof(int32_t) +
					  sizeof(uint32_t);
			uint32_t *msg = malloc(act_size);
			if (!msg) {
				// TODO: use a ring buffer for allocations,
				// and figure out how to block until it is clear
				wp_error("Failed to allocate file desc tx msg");
				return ERR_NOMEM;
			}
			msg[0] = transfer_header(act_size, WMSG_INJECT_RIDS);
			int32_t *rbuffer = (int32_t *)(msg + 1);

			/* Translate and adjust refcounts */
			if (translate_fds(&g->map, &g->render,
					    wmsg->fds.zone_start,
					    wmsg->fds.data, rbuffer) == -1) {
				free(msg);
				return ERR_FATAL;
			}
			decref_transferred_rids(
					&g->map, wmsg->fds.zone_start, rbuffer);
			memmove(wmsg->fds.data,
					wmsg->fds.data + wmsg->fds.zone_start,
					sizeof(int) * (size_t)(wmsg->fds.zone_end -
								      wmsg->fds.zone_start));
			wmsg->fds.zone_end -= wmsg->fds.zone_start;
			wmsg->fds.zone_start = 0;

			/* Add message to trailing queue */
			wmsg->trailing[wmsg->ntrailing].iov_len = act_size;
			wmsg->trailing[wmsg->ntrailing].iov_base = msg;
			wmsg->ntrailing++;
		}
		if (wmsg->proto_write.zone_end > 0) {
			wp_debug("We are transferring a data buffer with %d bytes",
					wmsg->proto_write.zone_end);
			size_t act_size = (size_t)wmsg->proto_write.zone_end +
					  sizeof(uint32_t);
			uint32_t protoh = transfer_header(
					act_size, WMSG_PROTOCOL);

			uint8_t *copy_proto = malloc(alignz(act_size, 4));
			if (!copy_proto) {
				wp_error("Failed to allocate protocol tx msg");
				return ERR_NOMEM;
			}
			memcpy(copy_proto, &protoh, sizeof(uint32_t));
			memcpy(copy_proto + sizeof(uint32_t),
					wmsg->proto_write.data,
					(size_t)wmsg->proto_write.zone_end);
			memset(copy_proto + sizeof(uint32_t) +
							wmsg->proto_write
									.zone_end,
					0, alignz(act_size, 4) - act_size);

			wmsg->trailing[wmsg->ntrailing].iov_len =
					alignz(act_size, 4);
			wmsg->trailing[wmsg->ntrailing].iov_base = copy_proto;
			wmsg->ntrailing++;
		}
	}

	int n_transfers = wmsg->transfers.end - wmsg->transfers.start;
	size_t net_bytes = 0;
	for (int i = wmsg->transfers.start; i < wmsg->transfers.end; i++) {
		net_bytes += wmsg->transfers.vecs[i].iov_len;
	}

	if (n_transfers > 0 || num_mt_tasks > 0 || wmsg->ntrailing > 0) {
		wp_debug("Channel message start (%d blobs, %d bytes, %d trailing, %d tasks)",
				n_transfers, net_bytes, wmsg->ntrailing,
				num_mt_tasks);
		wmsg->state = WM_WAITING_FOR_CHANNEL;
		DTRACE_PROBE(waypipe, channel_write_start);
	}
	return 0;
}
static int advance_waymsg_transfer(struct globals *g,
		struct way_msg_state *wmsg, struct cross_state *cxs,
		bool display_side, int chanfd, int progfd,
		bool progsock_readable)
{
	if (wmsg->state == WM_WAITING_FOR_CHANNEL) {
		return advance_waymsg_chanwrite(
				wmsg, cxs, g, chanfd, display_side);
	} else if (wmsg->state == WM_WAITING_FOR_PROGRAM) {
		return advance_waymsg_progread(wmsg, g, progfd, display_side,
				progsock_readable);
	}
	return 0;
}

static int read_new_chanfd(int linkfd, struct int_window *recon_fds)
{
	uint8_t tmp = 0;
	ssize_t rd = iovec_read(linkfd, (char *)&tmp, 1, recon_fds);
	if (rd == -1 && (errno == EWOULDBLOCK || errno == EAGAIN)) {
		// do nothing
		return -1;
	} else if (rd == 0 || (rd == -1 && errno == ECONNRESET)) {
		wp_error("link has closed");
		// sentinel value, to indicate that linkfd should be closed
		return -2;
	} else if (rd == -1) {
		wp_error("link read failure: %s", strerror(errno));
		return -1;
	}
	for (int i = 0; i < recon_fds->zone_end - 1; i++) {
		checked_close(recon_fds->data[i]);
	}
	int ret_fd = -1;
	if (recon_fds->zone_end > 0) {
		ret_fd = recon_fds->data[recon_fds->zone_end - 1];
	}
	recon_fds->zone_end = 0;
	return ret_fd;
}

static int reconnect_loop(int linkfd, int progfd, struct int_window *recon_fds)
{
	while (!shutdown_flag) {
		struct pollfd rcfs[2];
		rcfs[0].fd = linkfd;
		rcfs[0].events = POLLIN;
		rcfs[0].revents = 0;
		rcfs[1].fd = progfd;
		rcfs[1].events = 0;
		rcfs[1].revents = 0;
		int r = poll(rcfs, 2, -1);
		if (r == -1) {
			if (errno == EINTR) {
				continue;
			} else {
				break;
			}
		}
		if (rcfs[0].revents & POLLIN) {
			int nfd = read_new_chanfd(linkfd, recon_fds);
			if (nfd != -1) {
				return nfd;
			}
		}
		if (rcfs[0].revents & POLLHUP || rcfs[1].revents & POLLHUP) {
			return -1;
		}
	}
	return -1;
}

static void reset_connection(struct cross_state *cxs,
		struct chan_msg_state *cmsg, struct way_msg_state *wmsg,
		int chanfd)
{
	/* Discard partial read transfer, throwing away complete but unread
	 * messages, and trailing remnants */
	cmsg->recv_end = 0;
	cmsg->recv_start = 0;
	cmsg->recv_unhandled_messages = 0;

	clear_old_transfers(&wmsg->transfers, cxs->last_confirmed_msgno);
	wp_debug("Resetting connection: %d blocks unacknowledged",
			wmsg->transfers.end);
	if (wmsg->transfers.end > 0) {
		/* If there was any data in flight, restart. If there wasn't
		 * anything in flight, then the remote side shouldn't notice the
		 * difference */
		struct wmsg_restart restart;
		restart.size_and_type =
				transfer_header(sizeof(restart), WMSG_RESTART);
		restart.last_ack_received = cxs->last_confirmed_msgno;
		wmsg->transfers.start = 0;
		wmsg->transfers.partial_write_amt = 0;
		wp_debug("Sending restart message: last ack=%d",
				restart.last_ack_received);
		if (write(chanfd, &restart, sizeof(restart)) !=
				sizeof(restart)) {
			wp_error("Failed to write restart message");
		}
	}

	if (set_nonblocking(chanfd) == -1) {
		wp_error("Error making new channel connection nonblocking: %s",
				strerror(errno));
	}

	(void)cxs;
}

static int set_connections_nonblocking(
		int chanfd, int progfd, int linkfd, bool display_side)
{
	const char *progdesc = display_side ? "compositor" : "application";
	if (set_nonblocking(chanfd) == -1) {
		wp_error("Error making channel connection nonblocking: %s",
				strerror(errno));
		return -1;
	}
	if (set_nonblocking(progfd) == -1) {
		wp_error("Error making %s connection nonblocking: %s", progdesc,
				strerror(errno));
		return -1;
	}
	if (linkfd != -1 && set_nonblocking(linkfd) == -1) {
		wp_error("Error making link connection nonblocking: %s",
				strerror(errno));
		return -1;
	}
	return 0;
}

int main_interface_loop(int chanfd, int progfd, int linkfd,
		const struct main_config *config, bool display_side)
{
	if (set_connections_nonblocking(chanfd, progfd, linkfd, display_side) ==
			-1) {
		if (linkfd != -1) {
			checked_close(linkfd);
		}
		checked_close(chanfd);
		checked_close(progfd);
		return EXIT_FAILURE;
	}
	const char *progdesc = display_side ? "compositor" : "application";
	wp_debug("Running main loop on %s side", progdesc);

	struct way_msg_state way_msg;
	memset(&way_msg, 0, sizeof(way_msg));
	struct chan_msg_state chan_msg;
	memset(&chan_msg, 0, sizeof(chan_msg));
	struct cross_state cross_data;
	memset(&cross_data, 0, sizeof(cross_data));
	struct globals g;
	memset(&g, 0, sizeof(g));

	way_msg.state = WM_WAITING_FOR_PROGRAM;
	/* AFAIK, there is no documented upper bound for the size of a
	 * Wayland protocol message, but libwayland (in wl_buffer_put)
	 * effectively limits message sizes to 4096 bytes. We must
	 * therefore adopt a limit as least as large. */
	const int max_read_size = 4096;
	way_msg.proto_read.size = max_read_size;
	way_msg.proto_read.data = malloc((size_t)way_msg.proto_read.size);
	way_msg.fds.size = 128;
	way_msg.fds.data = malloc((size_t)way_msg.fds.size * sizeof(int));
	way_msg.proto_write.size = 2 * max_read_size;
	way_msg.proto_write.data = malloc((size_t)way_msg.proto_write.size);
	way_msg.max_iov = get_iov_max();
	int mut_ret = pthread_mutex_init(
			&way_msg.transfers.async_recv_queue.lock, NULL);
	if (mut_ret) {
		wp_error("Mutex creation failed: %s", strerror(mut_ret));
		goto init_failure_cleanup;
	}

	chan_msg.state = CM_WAITING_FOR_CHANNEL;
	chan_msg.recv_size = 2 * RECV_GOAL_READ_SIZE;
	chan_msg.recv_buffer = malloc((size_t)chan_msg.recv_size);
	chan_msg.proto_write.size = max_read_size * 2;
	chan_msg.proto_write.data = malloc((size_t)chan_msg.proto_write.size);
	if (!chan_msg.proto_write.data || !chan_msg.recv_buffer ||
			!way_msg.proto_write.data || !way_msg.fds.data ||
			!way_msg.proto_read.data) {
		wp_error("Failed to allocate a message scratch buffer");
		goto init_failure_cleanup;
	}

	/* The first packet received will be #1 */
	way_msg.transfers.last_msgno = 1;

	g.config = config;
	g.render = (struct render_data){
			.drm_node_path = config->drm_node,
			.drm_fd = -1,
			.dev = NULL,
			.disabled = config->no_gpu,
			.av_disabled = config->no_gpu ||
				       !config->prefer_hwvideo,
			.av_bpf = config->video_bpf,
			.av_video_fmt = (int)config->video_fmt,
			.av_hwdevice_ref = NULL,
			.av_drmdevice_ref = NULL,
			.av_vadisplay = NULL,
			.av_copy_config = 0,
	};
	if (setup_thread_pool(&g.threads, config->compression,
			    config->compression_level,
			    config->n_worker_threads) == -1) {
		goto init_failure_cleanup;
	}
	setup_translation_map(&g.map, display_side);
	if (init_message_tracker(&g.tracker) == -1) {
		goto init_failure_cleanup;
	}
	setup_video_logging();

	struct int_window recon_fds = {
			.data = NULL,
			.size = 0,
			.zone_start = 0,
			.zone_end = 0,
	};

	bool needs_new_channel = false;
	struct pollfd *pfds = NULL;
	int pfds_size = 0;
	int exit_code = 0;
	while (!shutdown_flag && exit_code == 0 &&
			!(way_msg.state == WM_TERMINAL &&
					chan_msg.state == CM_TERMINAL)) {
		int psize = 4 + count_npipes(&g.map);
		if (buf_ensure_size(psize, sizeof(struct pollfd), &pfds_size,
				    (void **)&pfds) == -1) {
			wp_error("Allocation failure, not enough space for pollfds");
			exit_code = ERR_NOMEM;
			break;
		}
		pfds[0].fd = chanfd;
		pfds[1].fd = progfd;
		pfds[2].fd = linkfd;
		pfds[3].fd = g.threads.selfpipe_r;
		pfds[0].events = 0;
		pfds[1].events = 0;
		pfds[2].events = POLLIN;
		pfds[3].events = POLLIN;
		if (way_msg.state == WM_WAITING_FOR_CHANNEL) {
			pfds[0].events |= POLLOUT;
		} else if (way_msg.state == WM_WAITING_FOR_PROGRAM) {
			pfds[1].events |= POLLIN;
		}
		if (chan_msg.state == CM_WAITING_FOR_CHANNEL) {
			pfds[0].events |= POLLIN;
		} else if (chan_msg.state == CM_WAITING_FOR_PROGRAM) {
			pfds[1].events |= POLLOUT;
		}
		bool check_read = way_msg.state == WM_WAITING_FOR_PROGRAM;
		int npoll = 4 + fill_with_pipes(&g.map, pfds + 4, check_read);

		bool own_msg_pending =
				(cross_data.last_acked_msgno !=
						cross_data.last_received_msgno) &&
				way_msg.state == WM_WAITING_FOR_PROGRAM;
		bool unread_chan_msgs =
				chan_msg.state == CM_WAITING_FOR_CHANNEL &&
				chan_msg.recv_unhandled_messages > 0;

		int poll_delay = -1;
		if (unread_chan_msgs) {
			/* There is work to do, so continue */
			poll_delay = 0;
		}
		if (own_msg_pending) {
			/* To coalesce acknowledgements, we wait for a minimum
			 * amount */
			poll_delay = 20;
		}
		int r = poll(pfds, (nfds_t)npoll, poll_delay);
		if (r == -1) {
			if (errno == EINTR) {
				wp_error("poll interrupted: shutdown=%c",
						shutdown_flag ? 'Y' : 'n');
				continue;
			} else {
				wp_error("poll failed due to, stopping: %s",
						strerror(errno));
				exit_code = ERR_FATAL;
				break;
			}
		}
		if (pfds[3].revents & POLLIN) {
			/* After the self pipe has been used to wake up the
			 * connection, drain it */
			char tmp[64];
			(void)read(g.threads.selfpipe_r, tmp, sizeof(tmp));
		}

		mark_pipe_object_statuses(&g.map, npoll - 4, pfds + 4);
		/* POLLHUP sometimes implies POLLIN, but not on all systems.
		 * Checking POLLHUP|POLLIN means that we can detect EOF when
		 * we actually do try to read from the sockets, but also, if
		 * there was data in the pipe just before the hang up, then we
		 * can read and handle that data. */
		bool progsock_readable = pfds[1].revents & (POLLIN | POLLHUP);
		bool chanmsg_active = (pfds[0].revents & (POLLIN | POLLHUP)) ||
				      (pfds[1].revents & POLLOUT) ||
				      unread_chan_msgs;

		bool maybe_new_channel = (pfds[2].revents & (POLLIN | POLLHUP));
		if (maybe_new_channel) {
			int new_fd = read_new_chanfd(linkfd, &recon_fds);
			if (new_fd >= 0) {
				if (chanfd != -1) {
					checked_close(chanfd);
				}
				chanfd = new_fd;
				reset_connection(&cross_data, &chan_msg,
						&way_msg, chanfd);
				needs_new_channel = false;
			} else if (new_fd == -2) {
				wp_error("Link to root process hang-up detected");
				checked_close(linkfd);
				linkfd = -1;
			}
		}
		if (needs_new_channel && linkfd != -1) {
			wp_error("Channel hang up detected, waiting for reconnection");
			int new_fd = reconnect_loop(linkfd, progfd, &recon_fds);
			if (new_fd < 0) {
				// -1 is read failure or misc error, -2 is HUP
				exit_code = ERR_FATAL;
				break;
			} else {
				/* Actually handle the reconnection/reset state
				 */
				if (chanfd != -1) {
					checked_close(chanfd);
				}
				chanfd = new_fd;
				reset_connection(&cross_data, &chan_msg,
						&way_msg, chanfd);
				needs_new_channel = false;
			}
		} else if (needs_new_channel) {
			wp_error("Channel hang up detected, no reconnection link, fatal");
			exit_code = ERR_FATAL;
			break;
		}

		// Q: randomize the order of these?, to highlight
		// accidental dependencies?
		for (int m = 0; m < 2; m++) {
			int tr;
			if (m == 0) {
				tr = advance_chanmsg_transfer(&g, &chan_msg,
						&cross_data, display_side,
						chanfd, progfd, chanmsg_active);
			} else {
				tr = advance_waymsg_transfer(&g, &way_msg,
						&cross_data, display_side,
						chanfd, progfd,
						progsock_readable);
			}

			if (tr >= 0) {
				/* do nothing */
			} else if (tr == ERR_DISCONN) {
				/* Channel connection has at least
				 * partially been shut down, so close it
				 * fully. */
				checked_close(chanfd);
				chanfd = -1;
				if (linkfd == -1) {
					wp_error("Channel hang up detected, no reconnection link, fatal");
					exit_code = ERR_FATAL;
					break;
				}
				needs_new_channel = true;
			} else if (tr == ERR_STOP) {
				if (m == 0) {
					/* Stop returned while writing: Wayland
					 * connection has at least partially
					 * shut down, so close it fully. */
					checked_close(progfd);
					progfd = -1;
				} else {
					/* Stop returned while reading */
					checked_close(progfd);
					progfd = -1;
					if (way_msg.state ==
							WM_WAITING_FOR_PROGRAM) {
						way_msg.state = WM_TERMINAL;
					}
					if (chan_msg.state == CM_WAITING_FOR_PROGRAM ||
							chan_msg.recv_start ==
									chan_msg.recv_end) {
						chan_msg.state = CM_TERMINAL;
					}
				}
			} else {
				/* Fatal error, close and flush */
				exit_code = tr;
				break;
			}

			/* If the program connection has closed, and
			 * there waypipe is not currently transferring
			 * any message to the channel, then shutdown the
			 * program->channel transfers. (The reverse
			 * situation with the chnanel connection is not
			 * a cause for permanent closure, thanks to
			 * reconnection support */
			if (progfd == -1) {
				if (way_msg.state == WM_WAITING_FOR_PROGRAM) {
					way_msg.state = WM_TERMINAL;
				}
				if (chan_msg.state == CM_WAITING_FOR_PROGRAM ||
						chan_msg.recv_start ==
								chan_msg.recv_end) {
					chan_msg.state = CM_TERMINAL;
				}
			}
		}

		// Periodic maintenance. It doesn't matter who does this
		flush_writable_pipes(&g.map);
	}
	free(pfds);
	free(recon_fds.data);
	wp_debug("Exiting main loop (%d, %d, %d), attempting close message",
			exit_code, way_msg.state, chan_msg.state);

init_failure_cleanup:
	/* It's possible, but very very unlikely, that waypipe gets closed
	 * while Wayland protocol messages are being written to the program
	 * and the most recent message was only partially written. */
	exit_code = ERR_FATAL;
	if (chan_msg.proto_write.zone_start != chan_msg.proto_write.zone_end) {
		wp_debug("Final write to %s was incomplete, %d/%d", progdesc,
				chan_msg.proto_write.zone_start,
				chan_msg.proto_write.zone_end);
	}

	if (!display_side && progfd != -1) {
		if (exit_code == ERR_FATAL) {
			/* wl_display@1, code 3: waypipe internal error */
			uint32_t fatal_msg[11] = {0x1, 44u << 16, 0x1, 3, 23, 0,
					0, 0, 0, 0, 0};
			memcpy(fatal_msg + 5, "waypipe internal error", 23);
			if (write(progfd, &fatal_msg, sizeof(fatal_msg)) ==
					-1) {
				wp_error("Failed to send waypipe error notification: %s",
						strerror(errno));
			}
		} else if (exit_code == ERR_NOMEM) {
			/* wl_display@1, code 2: no memory */
			uint32_t nomem_msg[8] = {
					0x1, 32u << 16, 0x1, 2, 10, 0, 0};
			memcpy(nomem_msg + 5, "no memory", 10);
			if (write(progfd, &nomem_msg, sizeof(nomem_msg)) ==
					-1) {
				wp_error("Failed to send OOM notification: %s",
						strerror(errno));
			}
		}
	}

	/* Attempt to notify remote end that the application has closed,
	 * waiting at most for a very short amount of time */
	if (way_msg.transfers.start != way_msg.transfers.end) {
		wp_error("Final write to channel was incomplete, %d+%zu/%d",
				way_msg.transfers.start,
				way_msg.transfers.partial_write_amt,
				way_msg.transfers.end);
	}

	if (chanfd != -1) {
		struct pollfd close_poll;
		close_poll.fd = chanfd;
		close_poll.events = POLLOUT;
		int close_ret = poll(&close_poll, 1, 200);
		if (close_ret == 0) {
			wp_debug("Exit poll timed out");
		}
		uint32_t close_msg[2];
		close_msg[0] = transfer_header(sizeof(close_msg), WMSG_CLOSE);
		close_msg[1] = exit_code == ERR_STOP ? 0 : (uint32_t)exit_code;
		wp_debug("Sending close message, modecode=%d", close_msg[1]);
		if (write(chanfd, &close_msg, sizeof(close_msg)) == -1) {
			wp_error("Failed to send close notification: %s",
					strerror(errno));
		}
	} else {
		wp_debug("Channel closed, hence no close notification");
	}

	cleanup_thread_pool(&g.threads);
	cleanup_message_tracker(&g.tracker);
	cleanup_translation_map(&g.map);
	cleanup_render_data(&g.render);
	cleanup_hwcontext(&g.render);
	free(way_msg.proto_read.data);
	free(way_msg.proto_write.data);
	free(way_msg.fds.data);
	cleanup_transfer_queue(&way_msg.transfers);
	for (int i = 0; i < way_msg.ntrailing; i++) {
		free(way_msg.trailing[i].iov_base);
	}
	free(chan_msg.transf_fds.data);
	free(chan_msg.proto_fds.data);
	free(chan_msg.recv_buffer);
	free(chan_msg.proto_write.data);

	if (chanfd != -1) {
		checked_close(chanfd);
	}
	if (progfd != -1) {
		checked_close(progfd);
	}
	if (linkfd != -1) {
		checked_close(linkfd);
	}
	return EXIT_SUCCESS;
}
