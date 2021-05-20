#ifndef SYMGEN_TYPES_H
#define SYMGEN_TYPES_H
#include <stdbool.h>
#include <stdint.h>
struct context;
struct message_tracker;
struct wp_object;
typedef void (*wp_callfn_t)(struct context *ctx, const uint32_t *payload, const int *fds, struct message_tracker *mt);
#define GAP_CODE_END 0x0
#define GAP_CODE_OBJ 0x1
#define GAP_CODE_ARR 0x2
#define GAP_CODE_STR 0x3
struct msg_data {
	/* Number of 4-byte blocks until next nontrivial input.
	 * (Note: 16-bit length is sufficient since message lengths also 16-bit)
	 * Lowest 2 bits indicate if what follows is end/obj/array/string */
	const uint16_t* gaps;
	/* Pointer to new object types, can be null if none indicated */
	const struct wp_interface **new_objs;
	/* Function pointer to parse + invoke do_ handler */
	const wp_callfn_t call;
	/* Number of associated file descriptors */
	const int16_t n_fds;
	/* Whether message destroys the object */
	bool is_destructor;
};
struct wp_interface {
	/* msgs[0..nreq-1] are reqs; msgs[nreq..nreq+nevt-1] are evts */
	const struct msg_data *msgs;
	const int nreq, nevt;
	/* The name of the interface */
	const char *name;
	/* The names of the messages, in order; stored tightly packed */
	const char *msg_names;
};
/* User should define this function. */
struct wp_object *get_object(struct message_tracker *mt, uint32_t id, const struct wp_interface *intf);
#endif /* SYMGEN_TYPES_H */
