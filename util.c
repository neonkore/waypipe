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

#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>


int iovec_read(int conn, char* buf, size_t buflen, int* fds, int* numfds) {
	char cmsgdata[ (CMSG_LEN(28 * sizeof(int32_t))) ];
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
	ssize_t ret = recvmsg(conn, &msg, MSG_DONTWAIT);

	// parse FDS

	return ret;
}
int iovec_write(int conn, char* buf, size_t buflen, int* fds, int* numfds) {
//	char cmsgdata[ (CMSG_LEN(28 * sizeof(int32_t))) ];
	struct iovec the_iovec;
	the_iovec.iov_len = buflen;
	the_iovec.iov_base = buf;
	struct msghdr msg;
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &the_iovec;
	msg.msg_iovlen = 1;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = 0;
	ssize_t ret = sendmsg(conn, &msg, 0);

	// parse FDS

	return ret;
}
