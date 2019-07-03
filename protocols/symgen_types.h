#ifndef SYMGEN_TYPES_H
#define SYMGEN_TYPES_H
#include <stdbool.h>
#include <stdint.h>
struct context;
struct message_tracker;
struct wp_object;
typedef void (*wp_callfn_t)(struct context *ctx, const uint32_t *payload, const int *fds, struct message_tracker *mt);
struct msg_data {
	const char *name;
	const int n_stretch;
	const unsigned int base_gap;
	const unsigned int *trail_gap;
	const bool *stretch_is_string;
	const int n_fds;
	const int new_vec_len;
	const unsigned int *new_obj_idxs;/* there are special 'spacer' fields at each string/arr, =-1*/
	const struct wp_interface **new_obj_types;
};
struct wp_interface {
	const char *name;
	/* 0=request, 1=event */
	const struct msg_data *funcs[2];
	const int nfuncs[2];
};
/* User should define this function. */
struct wp_object *get_object(struct message_tracker *mt, uint32_t id, const struct wp_interface *intf);
#endif /* SYMGEN_TYPES_H */
