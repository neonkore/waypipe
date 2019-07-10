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

static void collect_updates(struct fd_translation_map *map,
		struct transfer_stack *transfers, struct bytebuf_stack *blocks)
{
	for (struct shadow_fd *cur = map->list; cur; cur = cur->next) {
		collect_update(map, cur, transfers, blocks);
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

/* The data transfers from an application to the channel consist of a
 * length prefix, followed by a series of transfer blocks. This
 * structure maintains the transfer block state, with the end goal of
 * transport using 'writev' */
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

/** Set up metadata and headers for the data transfer to the channel. */
static void pack_pipe_message(struct block_transfer *bt, int nids,
		const int ids[], const struct transfer_stack *transfers,
		const struct bytebuf_stack *blocks)
{
	// TODO: network byte order everything, content aware, somewhere
	// in the chain!

	bt->nblocks = 1;
	for (int i = 0; i < transfers->count; i++) {
		// header + data blocks
		bt->nblocks += 1 + transfers->data[i].nblocks;
	}

	bt->ntransfers = transfers->count;
	bt->transfer_block_headers = calloc((size_t)bt->ntransfers,
			sizeof(struct pipe_elem_header));
	bt->blocks = calloc((size_t)bt->nblocks, sizeof(struct iovec));
	const size_t header_size =
			sizeof(uint64_t) +
			(size_t)nids * sizeof(struct pipe_elem_header);
	size_t total_size = header_size;

	int i_block = 1;
	for (int i = 0; i < transfers->count; i++) {
		struct pipe_elem_header *sd = &bt->transfer_block_headers[i];
		struct transfer *transfer = &transfers->data[i];
		sd->id = transfer->obj_id;
		sd->type = (int)transfer->type;
		sd->size = 0;
		struct bytebuf *subseq =
				&blocks->data[transfer->subtransfer_idx];
		for (int k = 0; k < transfer->nblocks; k++) {
			sd->size += subseq[k].size;
		}
		sd->special = transfer->special.raw;

		bt->blocks[i_block].iov_len = sizeof(struct pipe_elem_header);
		bt->blocks[i_block].iov_base = sd;

		for (int k = 0; k < transfer->nblocks; k++) {
			bt->blocks[i_block + 1 + k].iov_len = subseq[k].size;
			bt->blocks[i_block + 1 + k].iov_base = subseq[k].data;
		}
		size_t num_longs = (size_t)ceildiv(sd->size, sizeof(uint64_t));
		size_t extrabytes =
				num_longs * sizeof(uint64_t) - (size_t)sd->size;
		// each block should space for <=8 trailing bytes anyway
		bt->blocks[i_block + transfer->nblocks].iov_len += extrabytes;

		total_size += sizeof(struct pipe_elem_header) +
			      sizeof(uint64_t) * num_longs;

		i_block += 1 + transfer->nblocks;
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

/** Unpack the buffer containing message data, the id list, and file
 * updates. All returned pointers refer to positions in the source
 * buffer. Each transfer structure will point to the single block
 * containing its concatenated data */
static void unpack_pipe_message(size_t msglen, const char *msg, int *waylen,
		char **waymsg, int *nids, int ids[],
		struct transfer_stack *transfers, struct bytebuf_stack *blocks)
{
	if (msglen % 8 != 0) {
		wp_error("Unpacking uneven message, size %ld=%ld mod 8", msglen,
				msglen % 8);
		*nids = 0;
		transfers->count = 0;
		return;
	}
	int ni = 0;
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
				int nt = transfers->count++;
				int nb = blocks->count++;
				buf_ensure_size(transfers->count,
						sizeof(struct transfer),
						&transfers->size,
						(void **)&transfers->data);
				buf_ensure_size(blocks->count,
						sizeof(struct bytebuf),
						&blocks->size,
						(void **)&blocks->data);
				// Add to list of data transfers
				transfers->data[nt].obj_id = sd->id;
				transfers->data[nt].type = (fdcat_t)sd->type;
				transfers->data[nt].special.raw = sd->special;
				blocks->data[nb].data = (char *)data;
				blocks->data[nb].size = (size_t)sd->size;
				transfers->data[nt].nblocks = 1;
				transfers->data[nt].subtransfer_idx = nb;
			}
			size_t nlongs = ((size_t)sd->size + 7) / 8;
			if (nlongs > msglen / 8) {
				wp_error("Excessively long buffer: length: %ld x uint64_t",
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
}

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

	/* Individual transfer chunks and headers */
	struct transfer_stack transfers;
	struct bytebuf_stack blocks;

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

	struct transfer_stack transfers;
	struct bytebuf_stack blocks;
};

static int interpret_chanmsg(struct chan_msg_state *cmsg, struct globals *g,
		bool display_side)
{
	// Parsing decomposition
	cmsg->rbuffer_count = 0;
	cmsg->tfbuffer_count = 0;

	cmsg->dbuffer = NULL;
	cmsg->dbuffer_start = 0;
	cmsg->dbuffer_end = 0;

	wp_debug("Read %d byte msg, unpacking", cmsg->cmsg_size);

	cmsg->transfers.count = 0;
	cmsg->blocks.count = 0;
	unpack_pipe_message((size_t)cmsg->cmsg_size, cmsg->cmsg_buffer,
			&cmsg->dbuffer_end, &cmsg->dbuffer,
			&cmsg->rbuffer_count, cmsg->rbuffer, &cmsg->transfers,
			&cmsg->blocks);

	wp_debug("Read %d byte msg, %d fds, %d transfers. Data buffer has %d bytes",
			cmsg->cmsg_size, cmsg->rbuffer_count,
			cmsg->transfers.count, cmsg->dbuffer_end);

	for (int i = 0; i < cmsg->transfers.count; i++) {
		const struct transfer *transfer = &cmsg->transfers.data[i];
		const struct bytebuf *block =
				transfer->nblocks
						? &cmsg->blocks.data
								   [transfer->subtransfer_idx]
						: NULL;
		apply_update(&g->map, &g->render, transfer, block);
	}

	untranslate_ids(&g->map, cmsg->rbuffer_count, cmsg->rbuffer,
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
		parse_and_prune_messages(g, display_side, display_side, &src,
				&dst, &fds);
		if (src.zone_start != cmsg->dbuffer_end) {
			wp_error("did not expect partial messages over channel, only parsed %d/%d bytes",
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
		bool display_side, struct globals *g)
{
	// Read header, then read main contents
	if (cmsg->cmsg_size == 0) {
		uint64_t size = 0;
		ssize_t r = read(chanfd, &size, sizeof(size));
		if (r == -1 && errno == EWOULDBLOCK) {
			wp_debug("Read would block");
			return 0;
		} else if (r == -1) {
			wp_error("chanfd read failure: %s", strerror(errno));
			return -1;
		} else if (r == 0) {
			wp_debug("Channel connection closed");
			return -1;
		} else if (r < (ssize_t)sizeof(uint64_t)) {
			wp_error("insufficient starting read block %ld of 8 bytes",
					r);
			return -1;
		} else if (size > (1 << 30)) {
			wp_error("Invalid transfer block size %ld", size);
			return -1;
		} else if (size == 0) {
			wp_error("Meaningless zero-byte transfer");
			return -1;
		} else {
			DTRACE_PROBE1(waypipe, channel_read_start, size);
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
				wp_error("chanfd read failure: %s",
						strerror(errno));
				return -1;
			} else if (r == 0) {
				wp_error("chanfd closed");
				return -1;
			} else {
				cmsg->cmsg_end += r;
			}
		}
		if (cmsg->cmsg_end == cmsg->cmsg_size) {
			DTRACE_PROBE(waypipe, channel_read_end);
			if (interpret_chanmsg(cmsg, g, display_side) == -1) {
				return -1;
			}
			cmsg->state = CM_WAITING_FOR_PROGRAM;
			DTRACE_PROBE(waypipe, chanmsg_program_wait);
		}
	}
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
				cmsg->dbuffer + cmsg->dbuffer_start,
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
			wp_debug("Wrote, have done %d/%d bytes in chunk %ld, %d/%d fds",
					cmsg->dbuffer_start, cmsg->dbuffer_end,
					wc, nfds_written, cmsg->tfbuffer_count);
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
		free(cmsg->cmsg_buffer);
		cmsg->cmsg_buffer = NULL;
		cmsg->cmsg_size = 0;
		cmsg->cmsg_end = 0;
		cmsg->state = CM_WAITING_FOR_CHANNEL;
		DTRACE_PROBE(waypipe, chanmsg_channel_wait);
	}
	return 0;
}
static int advance_chanmsg_transfer(struct globals *g, int chanfd, int progfd,
		bool display_side, struct chan_msg_state *cmsg,
		bool any_changes)
{
	if (!any_changes) {
		return 0;
	}
	if (cmsg->state == CM_WAITING_FOR_CHANNEL) {
		return advance_chanmsg_chanread(cmsg, chanfd, display_side, g);
	} else {
		return advance_chanmsg_progwrite(cmsg, progfd, display_side, g);
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
			wp_error("chanfd write failure: %s", strerror(errno));
			return -1;
		} else if (wr == 0) {
			wp_error("chanfd has closed");
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
		DTRACE_PROBE(waypipe, channel_write_end);
		wp_debug("The %d-byte, %d block message from %s to channel has been written",
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
		struct globals *g, int progfd, bool display_side,
		bool progsock_readable)
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

	wmsg->transfers.count = 0;
	wmsg->blocks.count = 0;

	if (rc > 0) {
		wp_debug("Read %d new file descriptors, have %d total now",
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

		if (dst.zone_end > 0) {
			wp_debug("We are transferring a data buffer with %ld bytes",
					dst.zone_end);
			wmsg->transfers.data[0].obj_id = 0;
			wmsg->transfers.data[0].nblocks = 1;
			wmsg->transfers.data[0].subtransfer_idx = 0;
			wmsg->blocks.data[0].size = dst.zone_end;
			wmsg->blocks.data[0].data = wmsg->dbuffer_edited;
			wmsg->transfers.data[0].type = FDC_UNKNOWN;
			wmsg->transfers.count = 1;
			wmsg->blocks.count = 1;
		}
	}

	read_readable_pipes(&g->map);
	collect_updates(&g->map, &wmsg->transfers, &wmsg->blocks);
	if (wmsg->transfers.count > 0) {
		pack_pipe_message(&wmsg->cmsg, wmsg->rbuffer_count,
				wmsg->rbuffer, &wmsg->transfers, &wmsg->blocks);
		wmsg->transfers.count = 0;
		wmsg->blocks.count = 0;

		decref_transferred_rids(
				&g->map, wmsg->rbuffer_count, wmsg->rbuffer);
		wp_debug("Packed message size (%d fds, %d blobs, %d blocks): %d",
				wmsg->rbuffer_count, wmsg->transfers.count,
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
		DTRACE_PROBE1(waypipe, channel_write_start,
				wmsg->cmsg.total_size);
	}
	return 0;
}
static int advance_waymsg_transfer(struct globals *g, int chanfd, int progfd,
		bool display_side, struct way_msg_state *wmsg,
		bool progsock_readable)
{
	if (wmsg->state == WM_WAITING_FOR_CHANNEL) {
		return advance_waymsg_chanwrite(wmsg, chanfd, display_side);
	} else {
		return advance_waymsg_progread(wmsg, g, progfd, display_side,
				progsock_readable);
	}
}

int main_interface_loop(int chanfd, int progfd,
		const struct main_config *config, bool display_side)
{
	const char *progdesc = display_side ? "compositor" : "application";
	if (set_nonblocking(chanfd) == -1) {
		wp_error("Error making channel connection nonblocking: %s",
				strerror(errno));
		close(chanfd);
		close(progfd);
		return EXIT_FAILURE;
	}
	if (set_nonblocking(progfd) == -1) {
		wp_error("Error making %s connection nonblocking: %s", progdesc,
				strerror(errno));
		close(chanfd);
		close(progfd);
		return EXIT_FAILURE;
	}

	struct way_msg_state way_msg;
	way_msg.state = WM_WAITING_FOR_PROGRAM;
	/* AFAIK, there is not documented upper bound for the size of a
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
	way_msg.cmsg.blocks = NULL;
	way_msg.cmsg.nblocks = 0;
	way_msg.cmsg.transfer_block_headers = NULL;
	way_msg.cmsg.ntransfers = 0;
	way_msg.cmsg.meta_header = NULL;
	way_msg.cmsg.blocks_written = 0;
	way_msg.transfers.size = 8;
	way_msg.transfers.count = 0;
	way_msg.transfers.data = malloc((size_t)way_msg.transfers.size *
					sizeof(struct transfer));
	way_msg.blocks.size = 16;
	way_msg.blocks.count = 0;
	way_msg.blocks.data = malloc(
			(size_t)way_msg.blocks.size * sizeof(struct bytebuf));

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
	chan_msg.transfers.size = 8;
	chan_msg.transfers.count = 0;
	chan_msg.transfers.data = malloc((size_t)chan_msg.transfers.size *
					 sizeof(struct transfer));
	chan_msg.blocks.size = 8;
	chan_msg.blocks.count = 0;
	chan_msg.blocks.data = malloc(
			(size_t)chan_msg.blocks.size * sizeof(struct bytebuf));

	struct globals g;
	g.config = config;
	g.render = (struct render_data){.drm_node_path = config->drm_node,
			.drm_fd = -1,
			.dev = NULL,
			.disabled = config->no_gpu};
	setup_translation_map(&g.map, display_side, config->compression,
			config->n_worker_threads);
	init_message_tracker(&g.tracker);
	setup_video_logging();

	while (!shutdown_flag) {
		struct pollfd *pfds = NULL;
		int psize = 2 + count_npipes(&g.map);
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
		int npoll = 2 + fill_with_pipes(&g.map, pfds + 2, check_read);

		int r = poll(pfds, (nfds_t)npoll, -1);
		if (r == -1) {
			free(pfds);
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

		mark_pipe_object_statuses(&g.map, npoll - 2, pfds + 2);
		bool progsock_readable = pfds[1].revents & POLLIN;
		bool chanmsg_active = (pfds[0].revents & POLLIN) ||
				      (pfds[1].revents & POLLOUT);
		bool hang_up = (pfds[0].revents & POLLHUP) ||
			       (pfds[1].revents & POLLHUP);
		free(pfds);
		if (hang_up) {
			wp_error("Connection hang-up detected");
			break;
		}

		// Q: randomize the order of these?, to highlight
		// accidental dependencies?
		if (advance_chanmsg_transfer(&g, chanfd, progfd, display_side,
				    &chan_msg, chanmsg_active) == -1) {
			break;
		}
		if (advance_waymsg_transfer(&g, chanfd, progfd, display_side,
				    &way_msg, progsock_readable) == -1) {
			break;
		}
		// Periodic maintenance. It doesn't matter who does this
		flush_writable_pipes(&g.map);
		close_rclosed_pipes(&g.map);
	}

	cleanup_message_tracker(&g.map, &g.tracker);
	cleanup_translation_map(&g.map);
	cleanup_render_data(&g.render);
	free(way_msg.dbuffer);
	free(way_msg.fds.data);
	free(way_msg.rbuffer);
	free(way_msg.cmsg.meta_header);
	free(way_msg.cmsg.blocks);
	free(way_msg.cmsg.transfer_block_headers);
	free(way_msg.dbuffer_edited);
	free(way_msg.transfers.data);
	free(way_msg.blocks.data);
	// We do not free chan_msg.dbuffer, as it is a subset of
	// cmsg_buffer
	free(chan_msg.tfbuffer);
	free(chan_msg.fbuffer);
	free(chan_msg.rbuffer);
	free(chan_msg.cmsg_buffer);
	free(chan_msg.dbuffer_edited);
	free(chan_msg.transfers.data);
	free(chan_msg.blocks.data);
	close(chanfd);
	close(progfd);
	return EXIT_SUCCESS;
}
