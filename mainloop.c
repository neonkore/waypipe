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

#if !defined(__FreeBSD__)
/* CMSG_LEN isn't part of any X/Open version */
#define _XOPEN_SOURCE 700
#endif

#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
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

		for (int i = 0; i < nf; i++) {
			buf_ensure_size(fds->zone_end + 1, sizeof(int),
					&fds->size, (void **)&fds->data);
			fds->data[fds->zone_end++] = data[i];
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

static void translate_fds(struct fd_translation_map *map,
		struct render_data *render, int nfds, const int fds[],
		int ids[])
{
	for (int i = 0; i < nfds; i++) {
		/* Autodetect type */
		size_t fdsz = 0;
		fdcat_t fdtype = get_fd_type(fds[i], &fdsz);
		ids[i] = translate_fd(map, render, fds[i], fdtype, fdsz, NULL)
					 ->remote_id;
	}
}
/** Given a list of global ids, and an up-to-date translation map, produce local
 * file descriptors */
static void untranslate_ids(struct fd_translation_map *map, int nids,
		const int ids[], int fds[])
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

/**
 * Given a set of messages and fds, parse the messages, and if indicated
 * by parsing logic, compact the message buffer by removing selected
 * messages.
 *
 * Messages with file descriptors should not be compacted.
 *
 * The amount of the message buffer read is written to `data_used`
 * The new size of the message buffer, after compaction, is
 * `data_newsize` The number of file descriptors read by the protocol is
 * `fds_used`.
 */
static void parse_and_prune_messages(struct globals *g, bool on_display_side,
		bool from_client, struct char_window *source_bytes,
		struct char_window *dest_bytes, struct int_window *fds)
{
	bool anything_unknown = false;
	struct char_window scan_bytes;
	scan_bytes.data = dest_bytes->data;
	scan_bytes.zone_start = dest_bytes->zone_start;
	scan_bytes.zone_end = dest_bytes->zone_start;
	scan_bytes.size = dest_bytes->size;

	DTRACE_PROBE1(waypipe, parse_enter,
			source_bytes->zone_end - source_bytes->zone_start);

	for (; source_bytes->zone_start < source_bytes->zone_end;) {
		if (source_bytes->zone_end - source_bytes->zone_start < 8) {
			// Not enough remaining bytes to parse the
			// header
			wp_debug("Insufficient bytes for header: %d %d",
					source_bytes->zone_start,
					source_bytes->zone_end);
			break;
		}
		int msgsz = peek_message_size(
				&source_bytes->data[source_bytes->zone_start]);
		if (source_bytes->zone_start + msgsz > source_bytes->zone_end) {
			wp_debug("Insufficient bytes");
			// Not enough remaining bytes to contain the
			// message
			break;
		}
		if (msgsz < 8) {
			wp_debug("Degenerate message, claimed len=%d", msgsz);
			// Not enough remaining bytes to contain the
			// message
			break;
		}

		/* We copy the message to the trailing end of the
		 * in-progress buffer; the parser may elect to modify
		 * the message's size */
		memcpy(&scan_bytes.data[scan_bytes.zone_start],
				&source_bytes->data[source_bytes->zone_start],
				(size_t)msgsz);
		source_bytes->zone_start += msgsz;
		scan_bytes.zone_end = scan_bytes.zone_start + msgsz;

		enum parse_state pstate = handle_message(g, on_display_side,
				from_client, &scan_bytes, fds);
		if (pstate == PARSE_UNKNOWN || pstate == PARSE_ERROR) {
			anything_unknown = true;
		}
		scan_bytes.zone_start = scan_bytes.zone_end;
	}
	dest_bytes->zone_end = scan_bytes.zone_end;

	if (anything_unknown) {
		// All-un-owned buffers are assumed to have changed.
		// (Note that in some cases, a new protocol could imply
		// a change for an existing buffer; it may make sense to
		// mark everything dirty, then.)
		for (struct shadow_fd *cur = g->map.list; cur;
				cur = cur->next) {
			if (!cur->has_owner) {
				cur->is_dirty = true;
			}
		}
	}
	DTRACE_PROBE(waypipe, parse_exit);
	return;
}

struct pipe_elem_header {
	int32_t id;
	int32_t type;
	int32_t size;
	int32_t special;
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

	/* Individual transfer chunks and headers, sent out via writev */
	struct transfer_data transfers;
	int total_written;

	/* transfers to send after the compute queue is empty */
	int ntrailing;
	struct iovec trailing[3];
};

/* This state corresponds to the in-progress transfer from the channel
 * to the program and the buffers/pipes on which will be written. */
enum cm_state { CM_WAITING_FOR_PROGRAM, CM_WAITING_FOR_CHANNEL };
struct chan_msg_state {
	enum cm_state state;

	/* The large packed message read from the channel */
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
	char *dbuffer_edited; // messages are copied to here

#define RECV_GOAL_READ_SIZE 131072
	char *recv_buffer; // ring-like buffer for message data
	int recv_size;
	int recv_start; // (recv_buffer+rev_start) should be a message header
	int recv_end;   // last byte read from channel, always >=recv_start
	int recv_unhandled_messages; // number of messages to parse
};

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
		wp_debug("Other side has closed");
		return -1;
	} else if (type == WMSG_RESTART) {
		struct wmsg_restart *ackm = (struct wmsg_restart *)packet;
		wp_debug("Received restart message: remote last saw ack %d (we last sent %d)",
				ackm->last_ack_received,
				cxs->last_received_msgno);
		cxs->last_received_msgno = ackm->last_ack_received;
		return 0;
	} else if (type == WMSG_ACK_NBLOCKS) {
		struct wmsg_ack *ackm = (struct wmsg_ack *)packet;
		cxs->last_confirmed_msgno = ackm->messages_received;
		return 0;
	} else {
		cxs->last_received_msgno++;
		if (cxs->last_received_msgno < cxs->newest_received_msgno) {
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
		int nfds = (unpadded_size - sizeof(uint32_t)) / sizeof(int32_t);

		cmsg->tfbuffer_count = nfds;
		untranslate_ids(&g->map, nfds, fds, cmsg->tfbuffer);
		if (cmsg->tfbuffer_count > 0) {
			// Append the new file descriptors to
			// the parsing queue
			memcpy(cmsg->fbuffer + cmsg->fbuffer_count,
					cmsg->tfbuffer,
					sizeof(int) * (size_t)cmsg->tfbuffer_count);
			cmsg->fbuffer_count += cmsg->tfbuffer_count;
		}
	} else if (type == WMSG_PROTOCOL) {
		/* While by construction, the provided message buffer should be
		 * aligned with individual message boundaries, it is not
		 * guaranteed that all file descriptors provided will be used by
		 * the messages. This makes fd handling more complicated. */
		struct char_window src;
		size_t protosize = unpadded_size - sizeof(uint32_t);
		src.data = packet + sizeof(uint32_t);
		src.zone_start = 0;
		src.zone_end = protosize;
		src.size = protosize;
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
		parse_and_prune_messages(g, display_side, display_side, &src,
				&dst, &fds);
		if (src.zone_start != src.zone_end) {
			wp_error("did not expect partial messages over channel, only parsed %d/%d bytes",
					src.zone_start, src.zone_end);
			return -1;
		}
		/* Update file descriptor queue */
		if (cmsg->fbuffer_count > fds.zone_start) {
			memmove(cmsg->fbuffer, cmsg->fbuffer + fds.zone_start,
					sizeof(int) * (size_t)(cmsg->fbuffer_count -
								      fds.zone_start));
		}
		cmsg->fbuffer_count -= fds.zone_start;

		cmsg->dbuffer_start = 0;
		cmsg->dbuffer_end = dst.zone_end;
	} else {
		int32_t rid = ((int32_t *)packet)[1];
		struct bytebuf msg = {
				.data = packet,
				.size = unpadded_size,
		};
		wp_debug("Received %s for RID=%d (len %d)",
				wmsg_type_to_str(type), rid, unpadded_size);
		apply_update(&g->map, &g->threads, &g->render, type, rid, &msg);
	}
	return 0;
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
				cmsg->recv_start + (int)sizeof(uint32_t)) {
			/* Didn't quite finish reading the header */
			buf_ensure_size(cmsg->recv_end + RECV_GOAL_READ_SIZE, 1,
					&cmsg->recv_size,
					(void **)&cmsg->recv_buffer);

			nvec = 1;
			vec[0].iov_base = cmsg->recv_buffer + cmsg->recv_end;
			vec[0].iov_len = RECV_GOAL_READ_SIZE;
		} else {
			/* Continuing an old packet; space made available last
			 * time */
			uint32_t *header = (uint32_t *)&cmsg->recv_buffer
							   [cmsg->recv_start];
			size_t sz = alignu(transfer_size(*header), 16);

			size_t read_end = cmsg->recv_start + sz;
			bool wraparound =
					cmsg->recv_start >= RECV_GOAL_READ_SIZE;
			if (!wraparound) {
				read_end = maxu(read_end,
						cmsg->recv_end +
								RECV_GOAL_READ_SIZE);
			}
			buf_ensure_size((int)read_end, 1, &cmsg->recv_size,
					(void **)&cmsg->recv_buffer);

			nvec = 1;
			vec[0].iov_base = cmsg->recv_buffer + cmsg->recv_end;
			vec[0].iov_len = read_end - (size_t)cmsg->recv_end;
			if (wraparound) {
				nvec = 2;
				vec[1].iov_base = cmsg->recv_buffer;
				vec[1].iov_len = cmsg->recv_start;
			}
		}

		ssize_t r = readv(chanfd, vec, nvec);
		if (r == -1 && errno == EWOULDBLOCK) {
			wp_debug("Read would block");
			return 0;
		} else if (r == -1) {
			wp_error("chanfd read failure: %s", strerror(errno));
			return -1;
		} else if (r == 0) {
			wp_debug("Channel connection closed");
			return -2;
		} else {
			if (nvec == 2 && (size_t)r >= vec[0].iov_len) {
				/* Complete parsing this message */
				if (interpret_chanmsg(cmsg, cxs, g,
						    display_side,
						    cmsg->recv_buffer +
								    cmsg->recv_start) ==
						-1) {
					return -1;
				}

				cmsg->recv_start = 0;
				cmsg->recv_end = (int)r - (int)vec[0].iov_len;

				if (cmsg->dbuffer_start < cmsg->dbuffer_end) {
					goto next_stage;
				}
			} else {
				cmsg->recv_end += r;
			}
		}
	}

	/* Recount unhandled messages */
	cmsg->recv_unhandled_messages = 0;
	int i = cmsg->recv_start;
	while (i + (int)sizeof(uint32_t) < cmsg->recv_end) {
		uint32_t *header = (uint32_t *)&cmsg->recv_buffer[i];
		size_t sz = alignu(transfer_size(*header), 16);
		if (sz == 0) {
			wp_error("Encountered malformed zero size packet");
			return -1;
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
		if (interpret_chanmsg(cmsg, cxs, g, display_side,
				    packet_start) == -1) {
			return -1;
		}
		cmsg->recv_start += alignu(sz, 16);
		cmsg->recv_unhandled_messages--;

		if (cmsg->dbuffer_start < cmsg->dbuffer_end) {
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
	while (cmsg->dbuffer_start < cmsg->dbuffer_end) {
		int nfds_written = 0;
		ssize_t wc = iovec_write(progfd,
				cmsg->dbuffer_edited + cmsg->dbuffer_start,
				(size_t)(cmsg->dbuffer_end -
						cmsg->dbuffer_start),
				cmsg->tfbuffer, cmsg->tfbuffer_count,
				&nfds_written);
		if (wc == -1 && errno == EWOULDBLOCK) {
			wp_debug("Write to the %s would block", progdesc);
			return 0;
		} else if (wc == -1) {
			wp_error("%s write failure %ld: %s", progdesc, wc,
					strerror(errno));
			return -1;
		} else if (wc == 0) {
			wp_error("%s has closed", progdesc);
			return -1;
		} else {
			cmsg->dbuffer_start += wc;
			wp_debug("Wrote to %s, %d/%d bytes in chunk %ld, %d/%d fds",
					progdesc, cmsg->dbuffer_start,
					cmsg->dbuffer_end, wc, nfds_written,
					cmsg->tfbuffer_count);
			// We send as many fds as we can with the first
			// batch
			decref_transferred_fds(
					&g->map, nfds_written, cmsg->tfbuffer);
			memmove(cmsg->tfbuffer, cmsg->tfbuffer + nfds_written,
					(size_t)nfds_written * sizeof(int));
			cmsg->tfbuffer_count -= nfds_written;
		}
	}
	if (cmsg->dbuffer_start == cmsg->dbuffer_end) {
		wp_debug("Write to the %s succeeded", progdesc);
		close_local_pipe_ends(&g->map);
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
	} else {
		return advance_chanmsg_progwrite(cmsg, progfd, display_side, g);
	}
}

static void clear_old_transfers(
		struct transfer_data *td, uint32_t inclusive_cutoff)
{
	int k = 0;
	for (int i = 0; i < td->start; i++) {
		if (td->msgno[i] > inclusive_cutoff) {
			break;
		}
		if (td->data[i].iov_base != &td->zeros) {
			free(td->data[i].iov_base);
		}
		td->data[i].iov_base = NULL;
		td->data[i].iov_len = 0;
		k = i + 1;
	}
	if (k > 0) {
		memmove(td->msgno, td->msgno + k,
				(td->end - k) * sizeof(td->msgno[0]));
		memmove(td->data, td->data + k,
				(td->end - k) * sizeof(td->data[0]));
		td->start -= k;
		td->end -= k;
	}
}

/* Returns 0 if done, 1 if partial, -1 if fatal error, -2 if closed */
static int partial_write_transfer(
		int chanfd, struct transfer_data *td, int *total_written)
{
	// Waiting for channel write to complete
	while (td->start < td->end) {
		/* Advance the current element by amount actually written */
		char *orig_base = td->data[td->start].iov_base;
		size_t orig_len = td->data[td->start].iov_len;
		td->data[td->start].iov_base =
				orig_base + td->partial_write_amt;
		td->data[td->start].iov_len = orig_len - td->partial_write_amt;
		int count = min(IOV_MAX, td->end - td->start);
		ssize_t wr = writev(chanfd, &td->data[td->start], count);
		td->data[td->start].iov_base = orig_base;
		td->data[td->start].iov_len = orig_len;

		if (wr == -1 && errno == EWOULDBLOCK) {
			break;
		} else if (wr == -1 && errno == EAGAIN) {
			continue;
		} else if (wr == -1) {
			wp_error("chanfd write failure: %s", strerror(errno));
			return -1;
		} else if (wr == 0) {
			wp_debug("Channel connection closed");
			return -2;
		}

		size_t uwr = (size_t)wr;
		*total_written += wr;
		while (uwr > 0 && td->start < td->end) {
			/* Skip past zero-length blocks */
			if (td->data[td->start].iov_len == 0) {
				td->start++;
				continue;
			}
			size_t left = td->data[td->start].iov_len -
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
	if (td->start == td->end) {
		td->partial_write_amt = 0;
		return 0;
	} else {
		return 1;
	}
}

static int advance_waymsg_chanwrite(struct way_msg_state *wmsg,
		struct cross_state *cxs, struct globals *g, int chanfd,
		bool display_side)
{
	const char *progdesc = display_side ? "compositor" : "application";
	struct transfer_data *td = &wmsg->transfers;

	// First, clear out any transfers that are no longer needed
	pthread_mutex_lock(&td->lock);
	for (int i = 0; i < td->end; i++) {
		if (td->data[i].iov_len == 0) {
			wp_error("ZERO SIZE ITEM FAIL: %d [%d,%d)", i,
					td->start, td->end);
		}
	}
	clear_old_transfers(td, cxs->last_confirmed_msgno);
	int ret = partial_write_transfer(chanfd, td, &wmsg->total_written);
	pthread_mutex_unlock(&td->lock);
	if (ret < 0) {
		return ret;
	}

	bool is_done = false;
	struct task_data task;
	task.type = TASK_STOP;
	pthread_mutex_lock(&g->threads.work_mutex);
	is_done = g->threads.queue_end == g->threads.queue_start &&
		  g->threads.queue_in_progress == 0;
	if (g->threads.queue_start < g->threads.queue_end) {
		int i = g->threads.queue_start;
		if (g->threads.queue[i].type != TASK_STOP) {
			task = g->threads.queue[i];
			g->threads.queue_start++;
			g->threads.queue_in_progress++;
		}
	}
	pthread_mutex_unlock(&g->threads.work_mutex);

	/* Run a task ourselves, making use of the main thread */
	if (task.type != TASK_STOP) {
		run_task(&task, &g->threads.threads[0]);

		pthread_mutex_lock(&g->threads.work_mutex);
		g->threads.queue_in_progress--;
		pthread_mutex_unlock(&g->threads.work_mutex);
		/* To skip the next poll */
		uint8_t triv = 0;
		if (write(g->threads.selfpipe_w, &triv, 1) == -1) {
			wp_error("Failed to write to self-pipe");
		}
	}

	if (is_done && wmsg->ntrailing > 0) {
		pthread_mutex_lock(&td->lock);
		for (int i = 0; i < wmsg->ntrailing; i++) {
			transfer_add(td, wmsg->trailing[i].iov_len,
					wmsg->trailing[i].iov_base,
					td->last_msgno++);
		}
		pthread_mutex_unlock(&td->lock);

		wmsg->ntrailing = 0;
		memset(wmsg->trailing, 0, sizeof(wmsg->trailing));
		ret = 1;
	}

	if (ret == 0 && is_done) {
		for (struct shadow_fd *cur = g->map.list, *nxt = NULL; cur;
				cur = nxt) {
			/* Note: finish_update() may delete `cur` */
			nxt = cur->next;
			finish_update(&g->map, cur);
		}
		/* Reset work queue */
		pthread_mutex_lock(&g->threads.work_mutex);
		g->threads.queue_start = 0;
		g->threads.queue_end = 0;
		g->threads.queue_in_progress = 0;
		pthread_mutex_unlock(&g->threads.work_mutex);

		DTRACE_PROBE(waypipe, channel_write_end);
		int unacked_bytes = 0;
		for (int i = 0; i < td->end; i++) {
			unacked_bytes += td->data[i].iov_len;
		}

		wp_debug("Sent %d-byte message from %s to channel; %d-bytes in flight",
				wmsg->total_written, progdesc, unacked_bytes);

		/* do not delete the used transfers yet; we need a remote
		 * acknowledgement */
		wmsg->total_written = 0;
		wmsg->state = WM_WAITING_FOR_PROGRAM;
	}
	return 0;
}
static int advance_waymsg_progread(struct way_msg_state *wmsg,
		struct cross_state *cxs, struct globals *g, int progfd,
		bool display_side, bool progsock_readable)
{
	const char *progdesc = display_side ? "compositor" : "application";
	// We have data to read from programs/pipes
	ssize_t rc = -1;
	int old_fbuffer_end = wmsg->fds.zone_end;
	if (progsock_readable) {
		// Read /once/
		rc = iovec_read(progfd, wmsg->dbuffer + wmsg->dbuffer_end,
				(size_t)(wmsg->dbuffer_maxsize -
						wmsg->dbuffer_end),
				&wmsg->fds);
		if (rc == -1 && errno == EWOULDBLOCK) {
			// do nothing
		} else if (rc == -1) {
			wp_error("%s read failure: %s", progdesc,
					strerror(errno));
			return -1;
		} else if (rc == 0) {
			wp_error("%s has closed", progdesc);
			return 0;
		} else {
			// We have successfully read some data.
			rc += wmsg->dbuffer_end;
		}
	}

	struct char_window dst;
	dst.data = wmsg->dbuffer_edited;
	dst.zone_start = 0;
	dst.zone_end = 0;
	dst.size = wmsg->dbuffer_edited_maxsize;
	if (rc > 0) {
		wp_debug("Read %d new file descriptors, have %d total now",
				wmsg->fds.zone_end - old_fbuffer_end,
				wmsg->fds.zone_end);

		struct char_window src;
		src.data = wmsg->dbuffer;
		src.zone_start = 0;
		src.zone_end = (int)rc;
		src.size = wmsg->dbuffer_maxsize;

		parse_and_prune_messages(g, display_side, !display_side, &src,
				&dst, &wmsg->fds);

		/* Translate all fds in the zone read by the protocol,
		 * creating shadow structures if needed. The
		 * window-queue is then reset */
		wmsg->rbuffer_count = wmsg->fds.zone_start;
		translate_fds(&g->map, &g->render, wmsg->fds.zone_start,
				wmsg->fds.data, wmsg->rbuffer);
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
	}

	read_readable_pipes(&g->map);

	/* Acknowledge the other side's transfers as soon as possible */
	if (cxs->last_acked_msgno != cxs->last_received_msgno) {
		struct wmsg_ack *ackm = calloc(1, sizeof(struct wmsg_ack));
		ackm->size_and_type = transfer_header(
				sizeof(struct wmsg_ack), WMSG_ACK_NBLOCKS);
		ackm->messages_received = cxs->last_received_msgno;
		cxs->last_acked_msgno = cxs->last_received_msgno;
		/* To avoid infinite regress, receive acknowledgement
		 * messages do not themselves increase the message counters. */

		pthread_mutex_lock(&wmsg->transfers.lock);
		transfer_add(&wmsg->transfers, sizeof(struct wmsg_ack), ackm,
				wmsg->transfers.last_msgno);
		pthread_mutex_unlock(&wmsg->transfers.lock);
	}

	for (struct shadow_fd *cur = g->map.list; cur; cur = cur->next) {
		collect_update(&g->map, &g->threads, cur, &wmsg->transfers);
	}

	if (rc > 0) {
		/* Inject file descriptors and parse the protocol after
		 * collecting the updates produced from them */
		if (wmsg->rbuffer_count > 0) {
			size_t act_size =
					wmsg->rbuffer_count * sizeof(int32_t) +
					sizeof(uint32_t);
			size_t pad_size = alignu(act_size, 16);
			uint32_t *msg = malloc(pad_size);
			msg[0] = transfer_header(act_size, WMSG_INJECT_RIDS);
			memcpy(&msg[1], wmsg->rbuffer,
					wmsg->rbuffer_count * sizeof(int32_t));
			memset(&msg[1 + wmsg->rbuffer_count], 0,
					pad_size - act_size);
			decref_transferred_rids(&g->map, wmsg->rbuffer_count,
					wmsg->rbuffer);
			wmsg->rbuffer_count = 0;

			wmsg->trailing[wmsg->ntrailing].iov_len = pad_size;
			wmsg->trailing[wmsg->ntrailing].iov_base = msg;
			wmsg->ntrailing++;
		}
		if (dst.zone_end > 0) {
			wp_debug("We are transferring a data buffer with %ld bytes",
					dst.zone_end);
			size_t act_size = dst.zone_end + sizeof(uint32_t);
			uint32_t protoh = transfer_header(
					act_size, WMSG_PROTOCOL);

			uint8_t *copy_proto = malloc(alignu(act_size, 16));
			memcpy(copy_proto, &protoh, sizeof(uint32_t));
			memcpy(copy_proto + sizeof(uint32_t), dst.data,
					dst.zone_end);
			memset(copy_proto + sizeof(uint32_t) + dst.zone_end, 0,
					alignu(act_size, 16) - act_size);

			wmsg->trailing[wmsg->ntrailing].iov_len =
					alignu(act_size, 16);
			wmsg->trailing[wmsg->ntrailing].iov_base = copy_proto;
			wmsg->ntrailing++;
		}

		// Introduce carryover data
		if (wmsg->dbuffer_carryover_end > 0) {
			wp_debug("Carryover: %d bytes",
					wmsg->dbuffer_carryover_end -
							wmsg->dbuffer_carryover_start);
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
	}

	int n_tasks = 0;
	pthread_mutex_lock(&g->threads.work_mutex);
	n_tasks = g->threads.queue_end;
	pthread_mutex_unlock(&g->threads.work_mutex);

	int n_transfers = 0;
	pthread_mutex_lock(&wmsg->transfers.lock);
	n_transfers = wmsg->transfers.end - wmsg->transfers.start;
	pthread_mutex_unlock(&wmsg->transfers.lock);

	if (n_transfers > 0 || n_tasks > 0 || wmsg->ntrailing > 0) {
		size_t net_bytes = 0;
		for (int i = wmsg->transfers.start; i < wmsg->transfers.end;
				i++) {
			net_bytes += wmsg->transfers.data[i].iov_len;
		}

		wp_debug("Channel message start (%d fds, %d blobs, %d bytes, %d trailing, %d tasks)",
				wmsg->rbuffer_count,
				wmsg->transfers.end - wmsg->transfers.start,
				net_bytes, wmsg->ntrailing, n_tasks);
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
	} else {
		return advance_waymsg_progread(wmsg, cxs, g, progfd,
				display_side, progsock_readable);
	}
}

static int read_new_chanfd(int linkfd, struct int_window *recon_fds)
{
	uint8_t tmp = 0;
	ssize_t rd = iovec_read(linkfd, (char *)&tmp, 1, recon_fds);
	if (rd == -1 && errno == EWOULDBLOCK) {
		// do nothing
		return -1;
	} else if (rd == -1) {
		wp_error("link read failure: %s", strerror(errno));
		return -1;
	} else if (rd == 0) {
		wp_error("link has closed");
		return -1;
	}
	for (int i = 0; i < recon_fds->zone_end - 1; i++) {
		close(recon_fds->data[i]);
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
		restart.pad3 = 0;
		restart.pad4 = 0;
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

int main_interface_loop(int chanfd, int progfd, int linkfd,
		const struct main_config *config, bool display_side)
{
	const char *progdesc = display_side ? "compositor" : "application";
	if (set_nonblocking(chanfd) == -1) {
		wp_error("Error making channel connection nonblocking: %s",
				strerror(errno));
		close(linkfd);
		close(chanfd);
		close(progfd);
		return EXIT_FAILURE;
	}
	if (set_nonblocking(progfd) == -1) {
		wp_error("Error making %s connection nonblocking: %s", progdesc,
				strerror(errno));
		close(linkfd);
		close(chanfd);
		close(progfd);
		return EXIT_FAILURE;
	}
	if (set_nonblocking(linkfd) == -1) {
		wp_error("Error making %s connection nonblocking: %s", progdesc,
				strerror(errno));
		close(linkfd);
		close(chanfd);
		close(progfd);
		return EXIT_FAILURE;
	}

	struct way_msg_state way_msg;
	way_msg.state = WM_WAITING_FOR_PROGRAM;
	/* AFAIK, there is no documented upper bound for the size of a
	 * Wayland protocol message, but libwayland (in wl_buffer_put)
	 * effectively limits message sizes to 4096 bytes. We must
	 * therefore adopt a limit as least as large. */
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
	memset(&way_msg.transfers, 0, sizeof(struct transfer_data));
	pthread_mutex_init(&way_msg.transfers.lock, NULL);
	way_msg.total_written = 0;
	way_msg.ntrailing = 0;
	memset(way_msg.trailing, 0, sizeof(way_msg.trailing));

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
	chan_msg.recv_size = 2 * RECV_GOAL_READ_SIZE;
	chan_msg.recv_buffer = malloc(chan_msg.recv_size);
	chan_msg.recv_start = 0;
	chan_msg.recv_end = 0;
	chan_msg.dbuffer_start = 0;
	chan_msg.dbuffer_end = 0;
	chan_msg.dbuffer_edited_maxsize = way_msg.dbuffer_maxsize * 2;
	chan_msg.dbuffer_edited =
			malloc((size_t)chan_msg.dbuffer_edited_maxsize);

	struct globals g;
	g.config = config;
	g.render = (struct render_data){
			.drm_node_path = config->drm_node,
			.drm_fd = -1,
			.dev = NULL,
			.disabled = config->no_gpu,
			.av_disabled = config->no_gpu ||
				       !config->prefer_hwvideo,
			.av_hwdevice_ref = NULL,
			.av_drmdevice_ref = NULL,
			.av_vadisplay = NULL,
			.av_copy_config = 0,
	};
	setup_thread_pool(&g.threads, config->compression,
			config->n_worker_threads);
	setup_translation_map(&g.map, display_side);
	init_message_tracker(&g.tracker);
	setup_video_logging();

	struct cross_state cross_data = {
			.last_acked_msgno = 0,
			.last_received_msgno = 0,
	};

	struct int_window recon_fds = {
			.data = NULL,
			.size = 0,
			.zone_start = 0,
			.zone_end = 0,
	};

	bool needs_new_channel = false;
	struct pollfd *pfds = NULL;
	int pfds_size = 0;
	while (!shutdown_flag) {
		int psize = 4 + count_npipes(&g.map);
		buf_ensure_size(psize, sizeof(struct pollfd), &pfds_size,
				(void **)&pfds);
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
		} else {
			pfds[1].events |= POLLIN;
		}
		if (chan_msg.state == CM_WAITING_FOR_CHANNEL) {
			pfds[0].events |= POLLIN;
		} else {
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
				break;
			}
		}

		mark_pipe_object_statuses(&g.map, npoll - 4, pfds + 4);
		bool progsock_readable = pfds[1].revents & POLLIN;
		bool chanmsg_active = (pfds[0].revents & POLLIN) ||
				      (pfds[1].revents & POLLOUT) ||
				      unread_chan_msgs;
		/* Whether or not POLLHUP is actually set appears to depend on
		 * if the shutdown is full or partial, and on the OS */
		bool user_hang_up = pfds[1].revents & POLLHUP;
		bool link_hang_up = pfds[2].revents & POLLHUP;
		bool maybe_new_channel = pfds[2].revents & POLLIN;
		if (pfds[0].revents & POLLHUP) {
			needs_new_channel = true;
		}
		if (pfds[3].revents & POLLIN) {
			/* After the self pipe has been used to wake up the
			 * connection, drain it */
			char tmp[64];
			(void)read(g.threads.selfpipe_r, tmp, sizeof(tmp));
		}
		if (user_hang_up) {
			wp_error("Connection hang-up detected");
			break;
		}
		if (link_hang_up) {
			wp_error("Link to root process hang-up detected");
			break;
		}
		if (maybe_new_channel) {
			int new_fd = read_new_chanfd(linkfd, &recon_fds);
			if (new_fd != -1) {
				close(chanfd);
				chanfd = new_fd;
				reset_connection(&cross_data, &chan_msg,
						&way_msg, chanfd);
				needs_new_channel = false;
			}
		}
		if (needs_new_channel) {
			wp_error("Channel hang up detected, waiting for reconnection");
			int new_fd = reconnect_loop(linkfd, progfd, &recon_fds);
			if (new_fd == -1) {
				break;
			} else {
				/* Actually handle the reconnection/reset state
				 */
				close(chanfd);
				chanfd = new_fd;
				reset_connection(&cross_data, &chan_msg,
						&way_msg, chanfd);
				needs_new_channel = false;
			}
		}

		// Q: randomize the order of these?, to highlight
		// accidental dependencies?
		int chanmsg_ret = advance_chanmsg_transfer(&g, &chan_msg,
				&cross_data, display_side, chanfd, progfd,
				chanmsg_active);
		if (chanmsg_ret == -1) {
			break;
		}
		int waymsg_ret = advance_waymsg_transfer(&g, &way_msg,
				&cross_data, display_side, chanfd, progfd,
				progsock_readable);
		if (waymsg_ret == -1) {
			break;
		}
		if (chanmsg_ret == -2 || waymsg_ret == -2) {
			/* The channel connection has either partially or fully
			 * closed */
			needs_new_channel = true;
		}

		// Periodic maintenance. It doesn't matter who does this
		flush_writable_pipes(&g.map);
		close_rclosed_pipes(&g.map);
	}
	wp_debug("Exiting main loop, attempting close message");

	/* Attempt to notify remote end that the application has closed */
	uint32_t close_msg[4] = {transfer_header(16, WMSG_CLOSE), 0, 0, 0};
	(void)write(chanfd, close_msg, sizeof(close_msg));

	free(pfds);
	free(recon_fds.data);

	cleanup_thread_pool(&g.threads);
	cleanup_message_tracker(&g.map, &g.tracker);
	cleanup_translation_map(&g.map);
	cleanup_render_data(&g.render);
	free(way_msg.dbuffer);
	free(way_msg.fds.data);
	free(way_msg.rbuffer);
	free(way_msg.dbuffer_edited);
	pthread_mutex_destroy(&way_msg.transfers.lock);
	for (int i = 0; i < way_msg.transfers.end; i++) {
		if (way_msg.transfers.data[i].iov_base !=
				way_msg.transfers.zeros) {
			free(way_msg.transfers.data[i].iov_base);
		}
	}
	free(way_msg.transfers.msgno);
	free(way_msg.transfers.data);
	for (int i = 0; i < way_msg.ntrailing; i++) {
		free(way_msg.trailing[i].iov_base);
	}
	// We do not free chan_msg.dbuffer, as it is a subset of
	// cmsg_buffer
	free(chan_msg.tfbuffer);
	free(chan_msg.fbuffer);
	free(chan_msg.rbuffer);
	free(chan_msg.recv_buffer);
	free(chan_msg.dbuffer_edited);
	close(chanfd);
	close(progfd);
	close(linkfd);
	return EXIT_SUCCESS;
}
