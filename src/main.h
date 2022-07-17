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
#ifndef WAYPIPE_MAIN_H
#define WAYPIPE_MAIN_H

#include "parsing.h"
#include "shadow.h"
#include "util.h"

struct main_config {
	const char *drm_node;
	int n_worker_threads;
	enum compression_mode compression;
	int compression_level;
	bool no_gpu;
	bool only_linear_dmabuf;
	bool video_if_possible;
	int video_bpf;
	enum video_coding_fmt video_fmt;
	bool prefer_hwvideo;
	bool old_video_mode;
};
struct globals {
	const struct main_config *config;
	struct fd_translation_map map;
	struct render_data render;
	struct message_tracker tracker;
	struct thread_pool threads;
};

/** Main processing loop
 *
 * chanfd: connected socket to channel
 * progfd: connected socket to Wayland program
 * linkfd: optional socket providing new chanfds. (-1 means not provided)
 *
 * Returns either EXIT_SUCCESS or EXIT_FAILURE (if exit caused by an error.)
 */
int main_interface_loop(int chanfd, int progfd, int linkfd,
		const struct main_config *config, bool display_side);

/** Act as a Wayland server */
int run_server(int cwd_fd, struct socket_path socket_path,
		const char *display_suffix, const char *control_path,
		const struct main_config *config, bool oneshot,
		bool unlink_at_end, char *const app_argv[],
		bool login_shell_if_backup);
/** Act as a Wayland client */
int run_client(int cwd_fd, const char *sock_folder_name, int sock_folder_fd,
		const char *sock_filename, const struct main_config *config,
		bool oneshot, const char *wayland_socket, pid_t eol_pid,
		int channelsock);
/** Run benchmarking tool; n_worker_threads defined as with \ref main_config */
int run_bench(float bandwidth_mBps, uint32_t test_size, int n_worker_threads);

#endif // WAYPIPE_MAIN_H
