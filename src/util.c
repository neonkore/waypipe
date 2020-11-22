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
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

bool shutdown_flag = false;
void handle_sigint(int sig)
{
	(void)sig;
	char buf[20];
	int pid = getpid();
	sprintf(buf, "SIGINT(%d)\n", pid);
	(void)write(STDOUT_FILENO, buf, strlen(buf));
	if (!shutdown_flag) {
		shutdown_flag = true;
	} else {
		const char msg[] = "Second SIGINT, aborting.\n";
		(void)write(STDERR_FILENO, msg, sizeof(msg));
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

int setup_nb_socket(const char *socket_path, int nmaxclients)
{
	struct sockaddr_un saddr;
	int sock;

	if (strlen(socket_path) >= sizeof(saddr.sun_path)) {
		wp_error("Socket path is too long and would be truncated: %s",
				socket_path);
		return -1;
	}

	saddr.sun_family = AF_UNIX;
	strncpy(saddr.sun_path, socket_path, sizeof(saddr.sun_path) - 1);
	sock = socket(AF_UNIX, SOCK_STREAM, 0);
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
	if (bind(sock, (struct sockaddr *)&saddr, sizeof(saddr)) == -1) {
		wp_error("Error binding socket at %s: %s", socket_path,
				strerror(errno));
		checked_close(sock);
		return -1;
	}
	if (listen(sock, nmaxclients) == -1) {
		wp_error("Error listening to socket at %s: %s", socket_path,
				strerror(errno));
		checked_close(sock);
		unlink(socket_path);
		return -1;
	}
	return sock;
}

int connect_to_socket(const char *socket_path)
{
	struct sockaddr_un saddr;
	int chanfd;
	saddr.sun_family = AF_UNIX;
	int len = (int)strlen(socket_path);
	if (len >= (int)sizeof(saddr.sun_path)) {
		wp_error("Socket path (%s) is too long, at %d bytes",
				socket_path, len);
		return -1;
	}
	memcpy(saddr.sun_path, socket_path, (size_t)(len + 1));

	chanfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (chanfd == -1) {
		wp_error("Error creating socket: %s", strerror(errno));
		return -1;
	}

	if (connect(chanfd, (struct sockaddr *)&saddr, sizeof(saddr)) == -1) {
		wp_error("Error connecting to socket (%s): %s", socket_path,
				strerror(errno));
		checked_close(chanfd);
		return -1;
	}
	return chanfd;
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

void test_log_handler(const char *file, int line, enum log_level level,
		const char *fmt, ...)
{
	(void)level;
	printf("[%s:%d] ", file, line);
	va_list args;
	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
	printf("\n");
}

void test_atomic_log_handler(const char *file, int line, enum log_level level,
		const char *fmt, ...)
{
	pthread_t tid = pthread_self();
	char msg[1024];
	int nwri = 0;
	nwri += sprintf(msg + nwri, "%" PRIx64 " [%s:%3d] ", (uint64_t)tid,
			file, line);

	va_list args;
	va_start(args, fmt);
	nwri += vsnprintf(msg + nwri, (size_t)(1022 - nwri), fmt, args);
	va_end(args);

	msg[nwri++] = '\n';
	msg[nwri] = 0;

	(void)write(STDOUT_FILENO, msg, (size_t)nwri);
	(void)level;
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

static const char *wmsg_types[] = {
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
};
const char *wmsg_type_to_str(enum wmsg_type tp)
{
	if (tp >= sizeof(wmsg_types) / sizeof(wmsg_types[0])) {
		return "???";
	}
	return wmsg_types[tp];
}

int transfer_add(struct transfer_queue *w, size_t size, void *data,
		bool is_ack_msg)
{
	if (size == 0) {
		return 0;
	}
	int sz = w->size;
	if (buf_ensure_size(w->end + 1, sizeof(struct iovec), &sz,
			    (void **)&w->vecs) == -1) {
		return -1;
	}
	sz = w->size;
	if (buf_ensure_size(w->end + 1, sizeof(struct iovec), &sz,
			    (void **)&w->msgnos) == -1) {
		return -1;
	}
	w->size = sz;

	w->vecs[w->end].iov_len = size;
	w->vecs[w->end].iov_base = data;
	w->msgnos[w->end] = w->last_msgno;
	w->end++;
	if (!is_ack_msg) {
		w->last_msgno++;
	}

	return true;
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
		if (transfer_add(w, v.iov_len, v.iov_base, false) == -1) {
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
		free(td->vecs[i].iov_base);
	}
	free(td->vecs);
	free(td->msgnos);
}
