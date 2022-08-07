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

#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

int parse_uint32(const char *str, uint32_t *val)
{
	if (!str[0] || (str[0] == '0' && str[1])) {
		return -1;
	}
	uint64_t v = 0;
	for (const char *cursor = str; *cursor; cursor++) {
		if (*cursor < '0' || *cursor > '9') {
			return -1;
		}
		uint64_t s = (uint64_t)(*cursor - '0');
		v *= 10;
		v += s;
		if (v >= (1uLL << 32)) {
			return -1;
		}
	}
	*val = (uint32_t)v;
	return 0;
}

/* An integer-to-string converter which is async-signal-safe, unlike sprintf */
static char *uint_to_str(uint32_t i, char buf[static 11])
{
	char *pos = &buf[10];
	*pos = '\0';
	while (i) {
		--pos;
		*pos = (char)((i % 10) + (uint32_t)'0');
		i /= 10;
	}
	return pos;
}
size_t multi_strcat(char *dest, size_t dest_space, ...)
{
	size_t net_len = 0;
	va_list args;
	va_start(args, dest_space);
	while (true) {
		const char *str = va_arg(args, const char *);
		if (!str) {
			break;
		}
		net_len += strlen(str);
		if (net_len >= dest_space) {
			va_end(args);
			dest[0] = '\0';
			return 0;
		}
	}
	va_end(args);
	va_start(args, dest_space);
	char *pos = dest;
	while (true) {
		const char *str = va_arg(args, const char *);
		if (!str) {
			break;
		}
		size_t len = strlen(str);
		memcpy(pos, str, len);
		pos += len;
	}
	va_end(args);
	*pos = '\0';
	return net_len;
}

bool shutdown_flag = false;
uint64_t inherited_fds[4] = {0, 0, 0, 0};
void handle_sigint(int sig)
{
	(void)sig;
	char buf[48];
	char tmp[11];
	const char *pidstr = uint_to_str((uint32_t)getpid(), tmp);
	const char *trailing = shutdown_flag ? "), second interrupt, aborting\n"
					     : ")\n";
	size_t len = multi_strcat(
			buf, sizeof(buf), "SIGINT(", pidstr, trailing, NULL);
	(void)write(STDERR_FILENO, buf, len);

	if (!shutdown_flag) {
		shutdown_flag = true;
	} else {
		abort();
	}
}

int set_nonblocking(int fd)
{
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1) {
		return -1;
	}
	return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int set_cloexec(int fd)
{
	int flags = fcntl(fd, F_GETFD, 0);
	if (flags == -1) {
		return -1;
	}
	return fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}

int setup_nb_socket(int cwd_fd, struct socket_path path, int nmaxclients,
		int *folder_fd_out, int *socket_fd_out)
{
	if (path.filename->sun_family != AF_UNIX) {
		wp_error("Address family should be AF_UNIX, was %d",
				path.filename->sun_family);
		return -1;
	}
	if (strchr(path.filename->sun_path, '/')) {
		wp_error("Address '%s' should be a pure filename and not contain any forward slashes",
				path.filename->sun_path);
		return -1;
	}

	int sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock == -1) {
		wp_error("Error creating socket: %s", strerror(errno));
		return -1;
	}
	if (set_nonblocking(sock) == -1) {
		wp_error("Error making socket nonblocking: %s",
				strerror(errno));
		checked_close(sock);
		return -1;
	}

	int folder_fd = open_folder(path.folder);
	if (folder_fd == -1) {
		wp_error("Error opening folder in which to connect to socket: %s",
				strerror(errno));
		checked_close(sock);
		return -1;
	}
	if (fchdir(folder_fd) == -1) {
		wp_error("Error changing to folder '%s'", path.folder);
		checked_close(sock);
		checked_close(folder_fd);
		return -1;
	}

	if (bind(sock, (struct sockaddr *)path.filename,
			    sizeof(*path.filename)) == -1) {
		wp_error("Error binding socket at %s: %s",
				path.filename->sun_path, strerror(errno));
		checked_close(sock);
		checked_close(folder_fd);
		if (fchdir(cwd_fd) == -1) {
			wp_error("Error returning to current working directory");
		}
		return -1;
	}
	if (listen(sock, nmaxclients) == -1) {
		wp_error("Error listening to socket at %s: %s",
				path.filename->sun_path, strerror(errno));
		checked_close(sock);
		checked_close(folder_fd);
		unlink(path.filename->sun_path);

		if (fchdir(cwd_fd) == -1) {
			wp_error("Error returning to current working directory");
		}
		return -1;
	}

	if (fchdir(cwd_fd) == -1) {
		wp_error("Error returning to current working directory");
	}
	*folder_fd_out = folder_fd;
	*socket_fd_out = sock;
	return 0;
}

int connect_to_socket_at_folder(int cwd_fd, int folder_fd,
		const struct sockaddr_un *filename, int *socket_fd)
{
	if (filename->sun_family != AF_UNIX) {
		wp_error("Address family should be AF_UNIX, was %d",
				filename->sun_family);
		return -1;
	}
	if (strchr(filename->sun_path, '/')) {
		wp_error("Address '%s' should be a pure filename and not contain any forward slashes",
				filename->sun_path);
		return -1;
	}

	int chanfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (chanfd == -1) {
		wp_error("Error creating socket: %s", strerror(errno));
		return -1;
	}
	if (fchdir(folder_fd) == -1) {
		wp_error("Error changing to folder\n");
		checked_close(chanfd);
		return -1;
	}

	if (connect(chanfd, (struct sockaddr *)filename, sizeof(*filename)) ==
			-1) {
		wp_error("Error connecting to socket (%s): %s",
				filename->sun_path, strerror(errno));
		checked_close(chanfd);
		if (fchdir(cwd_fd) == -1) {
			wp_error("Error returning to current working directory");
		}
		return -1;
	}
	if (fchdir(cwd_fd) == -1) {
		wp_error("Error returning to current working directory");
	}
	*socket_fd = chanfd;
	return 0;
}

int connect_to_socket(int cwd_fd, struct socket_path path, int *folder_fd_out,
		int *socket_fd_out)
{
	int folder_fd = open_folder(path.folder);
	if (folder_fd == -1) {
		wp_error("Error opening folder in which to connect to socket: %s",
				strerror(errno));
		return -1;
	}

	int ret = connect_to_socket_at_folder(
			cwd_fd, folder_fd, path.filename, socket_fd_out);
	if (folder_fd_out && ret == 0) {
		*folder_fd_out = folder_fd;
	} else {
		checked_close(folder_fd);
	}
	return ret;
}

int split_socket_path(char *src_path, struct sockaddr_un *rel_socket)
{
	size_t l = strlen(src_path);
	if (l == 0) {
		wp_error("Socket path to split is empty");
		return -1;
	}
	size_t s = l;
	while (src_path[s] != '/' && s > 0) {
		s--;
	}
	if (l - s >= sizeof(rel_socket->sun_path)) {
		wp_error("Filename part '%s' of socket path is too long: %zu bytes >= sizeof(sun_path) = %zu",
				src_path + s, l - s,
				sizeof(rel_socket->sun_path));
		return -1;
	}

	size_t t = (src_path[s] == '/') ? s + 1 : 0;
	rel_socket->sun_family = AF_UNIX;
	memset(rel_socket->sun_path, 0x3f, sizeof(rel_socket->sun_path));
	memcpy(rel_socket->sun_path, src_path + t, l - t + 1);
	src_path[s] = '\0';

	return 0;
}

void unlink_at_folder(int orig_dir_fd, int target_dir_fd,
		const char *target_dir_name, const char *filename)
{
	if (fchdir(target_dir_fd) == -1) {
		wp_error("Error switching folder to '%s': %s",
				target_dir_name ? target_dir_name : "(null)",
				strerror(errno));
		return;
	}
	if (unlink(filename) == -1) {
		wp_error("Unlinking '%s' in '%s' failed: %s", filename,
				target_dir_name ? target_dir_name : "(null)",
				strerror(errno));
	}
	if (fchdir(orig_dir_fd) == -1) {
		wp_error("Error switching folder back to cwd: %s",
				strerror(errno));
	}
}

bool files_equiv(int fd_a, int fd_b)
{
	struct stat stat_a, stat_b;
	if (fstat(fd_a, &stat_a) == -1) {
		wp_error("fstat failed, %s", strerror(errno));
		return false;
	}
	if (fstat(fd_b, &stat_b) == -1) {
		wp_error("fstat failed, %s", strerror(errno));
		return false;
	}
	return (stat_a.st_dev == stat_b.st_dev) &&
	       (stat_a.st_ino == stat_b.st_ino);
}

void set_initial_fds(void)
{
	struct pollfd checklist[256];
	for (int i = 0; i < 256; i++) {
		checklist[i].fd = i;
		checklist[i].events = 0;
		checklist[i].revents = 0;
	}
	if (poll(checklist, 256, 0) == -1) {
		wp_error("fd-checking poll failed: %s", strerror(errno));
		return;
	}
	for (int i = 0; i < 256; i++) {
		if (!(checklist[i].revents & POLLNVAL)) {
			inherited_fds[i / 64] |= (1uLL << (i % 64));
		}
	}
}

void check_unclosed_fds(void)
{
	/* Verify that all file descriptors have been closed. Since most
	 * instances have <<256 file descriptors open at a given time, it is
	 * safe to only check up to that level */
	struct pollfd checklist[256];
	for (int i = 0; i < 256; i++) {
		checklist[i].fd = i;
		checklist[i].events = 0;
		checklist[i].revents = 0;
	}
	if (poll(checklist, 256, 0) == -1) {
		wp_error("fd-checking poll failed: %s", strerror(errno));
		return;
	}
	for (int i = 0; i < 256; i++) {
		bool initial_fd = (inherited_fds[i / 64] &
						  (1uLL << (i % 64))) != 0;
		if (initial_fd) {
			if (checklist[i].revents & POLLNVAL) {
				wp_error("Unexpected closed fd %d", i);
			}
		} else {
			if (checklist[i].revents & POLLNVAL) {
				continue;
			}
#ifdef __linux__
			char fd_path[64];
			char link[256];
			sprintf(fd_path, "/proc/self/fd/%d", i);
			ssize_t len = readlink(fd_path, link, sizeof(link) - 1);
			if (len == -1) {
				wp_error("Failed to readlink /proc/self/fd/%d for unexpected open fd %d",
						i, i);
			} else {
				link[len] = '\0';
				if (!strcmp(link, "/var/lib/sss/mc/passwd")) {
					wp_debug("Known issue, leaked fd %d to /var/lib/sss/mc/passwd",
							i);
				} else {
					wp_debug("Unexpected open fd %d: %s", i,
							link);
				}
			}
#else
			wp_debug("Unexpected open fd %d", i);
#endif
		}
	}
}

size_t print_display_error(char *dest, size_t dest_space, uint32_t error_code,
		const char *message)
{
	if (dest_space < 20) {
		return 0;
	}
	size_t msg_len = strlen(message) + 1;
	size_t net_len = 4 * ((msg_len + 0x3) / 4) + 20;
	if (net_len > dest_space) {
		return 0;
	}
	uint32_t header[5] = {0x1, (uint32_t)net_len << 16, 0x1, error_code,
			(uint32_t)msg_len};
	memcpy(dest, header, sizeof(header));
	memcpy(dest + sizeof(header), message, msg_len);
	if (msg_len % 4 != 0) {
		size_t trailing = 4 - msg_len % 4;
		uint8_t zeros[4] = {0, 0, 0, 0};
		memcpy(dest + sizeof(header) + msg_len, zeros, trailing);
	}
	return net_len;
}

size_t print_wrapped_error(char *dest, size_t dest_space, const char *message)
{
	size_t msg_len = print_display_error(
			dest + 4, dest_space - 4, 3, message);
	if (msg_len == 0) {
		return 0;
	}
	uint32_t header = transfer_header(msg_len + 4, WMSG_PROTOCOL);
	memcpy(dest, &header, sizeof(header));
	return msg_len + 4;
}

int send_one_fd(int socket, int fd)
{
	union {
		char buf[CMSG_SPACE(sizeof(int))];
		struct cmsghdr align;
	} uc;
	memset(uc.buf, 0, sizeof(uc.buf));
	struct cmsghdr *frst = (struct cmsghdr *)(uc.buf);
	frst->cmsg_level = SOL_SOCKET;
	frst->cmsg_type = SCM_RIGHTS;
	*((int *)CMSG_DATA(frst)) = fd;
	frst->cmsg_len = CMSG_LEN(sizeof(int));

	struct iovec the_iovec;
	the_iovec.iov_len = 1;
	uint8_t dummy_data = 1;
	the_iovec.iov_base = &dummy_data;
	struct msghdr msg;
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &the_iovec;
	msg.msg_iovlen = 1;
	msg.msg_flags = 0;
	msg.msg_control = uc.buf;
	msg.msg_controllen = CMSG_SPACE(sizeof(int));

	return (int)sendmsg(socket, &msg, 0);
}

bool wait_for_pid_and_clean(pid_t *target_pid, int *status, int options,
		struct conn_map *map)
{
	bool found = false;
	while (1) {
		int stat;
		pid_t r = waitpid((pid_t)-1, &stat, options);
		if (r == 0 || (r == -1 && (errno == ECHILD ||
							  errno == EINTR))) {
			// Valid exit reasons, not an error
			errno = 0;
			return found;
		} else if (r == -1) {
			wp_error("waitpid failed: %s", strerror(errno));
			return found;
		}

		wp_debug("Child process %d has died", r);
		if (map) {
			/* Clean out all entries matching that pid */
			int iw = 0;
			for (int ir = 0; ir < map->count; ir++) {
				map->data[iw] = map->data[ir];
				if (map->data[ir].pid != r) {
					iw++;
				} else {
					checked_close(map->data[ir].linkfd);
				}
			}
			map->count = iw;
		}

		if (r == *target_pid) {
			*target_pid = 0;
			*status = stat;
			found = true;
		}
	}
}

int buf_ensure_size(int count, size_t obj_size, int *space, void **data)
{
	int x = *space;
	if (count <= x) {
		return 0;
	}
	if (count >= INT32_MAX / 2 || count <= 0) {
		return -1;
	}
	if (x < 1) {
		x = 1;
	}
	while (x < count) {
		x *= 2;
	}
	void *new_data = realloc(*data, (size_t)x * obj_size);
	if (!new_data) {
		return -1;
	}
	*data = new_data;
	*space = x;
	return 0;
}

static const char *const wmsg_types[] = {
		"WMSG_PROTOCOL",
		"WMSG_INJECT_RIDS",
		"WMSG_OPEN_FILE",
		"WMSG_EXTEND_FILE",
		"WMSG_OPEN_DMABUF",
		"WMSG_BUFFER_FILL",
		"WMSG_BUFFER_DIFF",
		"WMSG_OPEN_IR_PIPE",
		"WMSG_OPEN_IW_PIPE",
		"WMSG_OPEN_RW_PIPE",
		"WMSG_PIPE_TRANSFER",
		"WMSG_PIPE_SHUTDOWN_R",
		"WMSG_PIPE_SHUTDOWN_W",
		"WMSG_OPEN_DMAVID_SRC",
		"WMSG_OPEN_DMAVID_DST",
		"WMSG_SEND_DMAVID_PACKET",
		"WMSG_ACK_NBLOCKS",
		"WMSG_RESTART",
		"WMSG_CLOSE",
		"WMSG_OPEN_DMAVID_SRC_V2",
		"WMSG_OPEN_DMAVID_DST_V2",
};
const char *wmsg_type_to_str(enum wmsg_type tp)
{
	if (tp >= sizeof(wmsg_types) / sizeof(wmsg_types[0])) {
		return "???";
	}
	return wmsg_types[tp];
}
bool wmsg_type_is_known(enum wmsg_type tp)
{
	return (size_t)tp < (sizeof(wmsg_types) / sizeof(wmsg_types[0]));
}

int transfer_ensure_size(struct transfer_queue *transfers, int count)
{
	int sz = transfers->size;
	if (buf_ensure_size(count, sizeof(*transfers->vecs), &sz,
			    (void **)&transfers->vecs) == -1) {
		return -1;
	}
	sz = transfers->size;
	if (buf_ensure_size(count, sizeof(*transfers->meta), &sz,
			    (void **)&transfers->meta) == -1) {
		return -1;
	}
	transfers->size = sz;
	return 0;
}

int transfer_add(struct transfer_queue *w, size_t size, void *data)
{
	if (size == 0) {
		return 0;
	}
	if (transfer_ensure_size(w, w->end + 1) == -1) {
		return -1;
	}

	w->vecs[w->end].iov_len = size;
	w->vecs[w->end].iov_base = data;
	w->meta[w->end].msgno = w->last_msgno;
	w->meta[w->end].static_alloc = false;
	w->end++;
	w->last_msgno++;
	return 0;
}

void transfer_async_add(struct thread_msg_recv_buf *q, void *data, size_t sz)
{
	struct iovec vec;
	vec.iov_len = sz;
	vec.iov_base = data;
	pthread_mutex_lock(&q->lock);
	q->data[q->zone_end++] = vec;
	pthread_mutex_unlock(&q->lock);
}

int transfer_load_async(struct transfer_queue *w)
{
	pthread_mutex_lock(&w->async_recv_queue.lock);
	int zstart = w->async_recv_queue.zone_start;
	int zend = w->async_recv_queue.zone_end;
	w->async_recv_queue.zone_start = zend;
	pthread_mutex_unlock(&w->async_recv_queue.lock);

	for (int i = zstart; i < zend; i++) {
		struct iovec v = w->async_recv_queue.data[i];
		memset(&w->async_recv_queue.data[i], 0, sizeof(struct iovec));
		if (v.iov_len == 0 || v.iov_base == NULL) {
			wp_error("Unexpected empty message");
			continue;
		}
		/* Only fill/diff messages are received async, so msgno
		 * is always incremented */
		if (transfer_add(w, v.iov_len, v.iov_base) == -1) {
			wp_error("Failed to add message to transfer queue");
			pthread_mutex_unlock(&w->async_recv_queue.lock);
			return -1;
		}
	}
	return 0;
}

void cleanup_transfer_queue(struct transfer_queue *td)
{
	for (int i = td->async_recv_queue.zone_start;
			i < td->async_recv_queue.zone_end; i++) {
		free(td->async_recv_queue.data[i].iov_base);
	}
	pthread_mutex_destroy(&td->async_recv_queue.lock);
	free(td->async_recv_queue.data);
	for (int i = 0; i < td->end; i++) {
		if (!td->meta[i].static_alloc) {
			free(td->vecs[i].iov_base);
		}
	}
	free(td->vecs);
	free(td->meta);
}
