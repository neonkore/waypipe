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
	const struct wp_interface *type; // Use to lookup the message handler
	uint32_t obj_id;
	bool is_zombie; // object deleted but not yet acknowledged remotely
};
/** List of all Wayland protocol objects */
struct obj_list {
	struct wp_object **objs;
	int nobj;
	int size;
};
struct message_tracker {
	// objects all have a 'type'
	// creating a new type <-> binding it in the 'interface' list, via
	// registry. each type produces 'callbacks'
	struct obj_list objects;
	/* sequence number to discriminate between wl_buffer objects; object ids
	 * and pointers are not guaranteed to be unique */
	uint64_t buffer_seqno;
};
/** Context object, to be passed to the protocol handler functions */
struct context {
	struct globals *const g;
	struct obj_list *const obj_list;
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
 * the same id. Returns -1 on allocation failure. */
int listset_insert(struct fd_translation_map *map, struct obj_list *lst,
		struct wp_object *obj);
void listset_remove(struct obj_list *lst, struct wp_object *obj);
/** Replace an object that is already in the protocol list with a new object
 * that has the same id; will silently fail if id not present */
void listset_replace_existing(struct obj_list *lst, struct wp_object *obj);
struct wp_object *listset_get(struct obj_list *lst, uint32_t id);

int init_message_tracker(struct message_tracker *mt);
void cleanup_message_tracker(
		struct fd_translation_map *map, struct message_tracker *mt);

/** Read message size from header; the 8 bytes beyond data must exist */
int peek_message_size(const void *data);
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

// handlers.c
/** Create a new Wayland protocol object of the given type; some types
 * produce structs extending from wp_object */
struct wp_object *create_wp_object(
		uint32_t it, const struct wp_interface *type);
/** Type-specific destruction routines, also dereferencing linked shadow_fds */
void destroy_wp_object(
		struct fd_translation_map *map, struct wp_object *object);

extern const struct wp_interface *the_display_interface;

#endif // WAYPIPE_PARSING_H
