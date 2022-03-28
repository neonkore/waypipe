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
#ifndef WAYPIPE_PARSING_H
#define WAYPIPE_PARSING_H

#include <stdbool.h>
#include <stdint.h>

struct char_window;
struct int_window;
struct fd_translation_map;
struct main_config;

struct wp_interface;
/** An object used by the wayland protocol. Specific types may extend
 * this struct, using the following data as a header */
struct wp_object {
	struct wp_object *t_left, *t_right; // inline tree implementation
	const struct wp_interface *type;    // Use to lookup the message handler
	uint32_t obj_id;
	bool is_zombie; // object deleted but not yet acknowledged remotely
};
struct message_tracker {
	/* Tree containing all objects that are currently alive or zombie */
	struct wp_object *objtree_root;
	/* sequence number to discriminate between wl_buffer objects; object ids
	 * and pointers are not guaranteed to be unique */
	uint64_t buffer_seqno;
};
/** Context object, to be passed to the protocol handler functions */
struct context {
	struct globals *const g;
	struct message_tracker *const tracker;
	struct wp_object *obj;
	bool drop_this_msg;
	/* If true, running as waypipe client, and interfacing with compositor's
	 * buffers */
	const bool on_display_side;
	/* The transferred message can be rewritten in place, and resized, as
	 * long as there is space available. Setting 'fds_changed' will
	 * prevent the fd zone start from autoincrementing after running
	 * the function, which may be useful when injecting messages with fds */
	const int message_available_space;
	uint32_t *const message;
	int message_length;
	bool fds_changed;
	struct int_window *const fds;
};

/** Add a protocol object to the list, replacing any preceding object with
 * the same id. */
void tracker_insert(struct message_tracker *mt, struct wp_object *obj);
void tracker_remove(struct message_tracker *mt, struct wp_object *obj);
/** Replace an object that is already in the protocol list with a new object
 * that has the same id; will silently fail if id not present */
void tracker_replace_existing(
		struct message_tracker *mt, struct wp_object *obj);
struct wp_object *tracker_get(struct message_tracker *mt, uint32_t id);

int init_message_tracker(struct message_tracker *mt);
void cleanup_message_tracker(struct message_tracker *mt);

/** Read message size from header; the 8 bytes beyond data must exist */
int peek_message_size(const void *data);
/** Generate the second uint32_t field of a message header; this assumes no
 * fds or equivalently no fd count subfield */
static inline uint32_t message_header_2(uint32_t size_bytes, uint32_t msgno)
{
	return (size_bytes << 16) | msgno;
}
const char *get_nth_packed_string(const char *pack, int n);
enum parse_state { PARSE_KNOWN, PARSE_UNKNOWN, PARSE_ERROR };
/**
 * The return value is false iff the given message should be dropped.
 * The flag `unidentified_changes` is set to true if the message does
 * not correspond to a known protocol.
 *
 * The message data payload may be modified and increased in size.
 *
 * The window `chars` should start at the message start, end
 * at its end, and indicate remaining space.
 * The window `fds` should start at the next fd in the queue, ends
 * with the last.
 *
 * The start and end of `chars` will be moved to the new end of the message.
 * The end of `fds` may be moved if any fds are inserted or discarded.
 * The start of fds will be moved, depending on how many fds were consumed.
 */
enum parse_state handle_message(struct globals *g, bool on_display_side,
		bool from_client, struct char_window *chars,
		struct int_window *fds);
/**
 * Given a set of messages and fds, parse the messages, and if indicated
 * by parsing logic, compact the message buffer by removing selected
 * messages, or edit message contents.
 *
 * The `source_bytes` window indicates the range of unread data; it's
 * zone start point will be advanced. The 'dest_bytes' window indicates
 * the range of written data; it's zone end point will be advanced.
 *
 * The file descriptor queue `fds` will have its start advanced, leaving only
 * file descriptors that have not yet been read. Further edits may be made
 * to inject new file descriptors.
 */
void parse_and_prune_messages(struct globals *g, bool on_display_side,
		bool from_client, struct char_window *source_bytes,
		struct char_window *dest_bytes, struct int_window *fds);

// handlers.c
/** Create a new Wayland protocol object of the given type; some types
 * produce structs extending from wp_object */
struct wp_object *create_wp_object(
		uint32_t it, const struct wp_interface *type);
/** Type-specific destruction routines, also dereferencing linked shadow_fds */
void destroy_wp_object(struct wp_object *object);

extern const struct wp_interface *the_display_interface;

#endif // WAYPIPE_PARSING_H
