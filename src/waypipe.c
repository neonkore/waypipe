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

#include "main.h"

#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

enum waypipe_mode {
	MODE_FAIL = 0x0,
	MODE_SSH = 0x1,
	MODE_CLIENT = 0x2,
	MODE_SERVER = 0x4,
	MODE_RECON = 0x8,
	MODE_BENCH = 0x10
};

static bool log_to_tty = false;
static enum waypipe_mode log_mode = MODE_FAIL;
static bool log_anti_staircase = false;
log_handler_func_t log_funcs[2] = {NULL, NULL};

/* Usage: Wrapped to 79 characters */
static const char usage_string[] =
		"Usage: waypipe [options] mode ...\n"
		"A proxy for Wayland protocol applications.\n"
		"Example: waypipe ssh user@server weston-terminal\n"
		"\n"
		"Modes:\n"
		"  ssh [...]    Wrap an ssh invocation to run waypipe on both ends of the\n"
		"                 connection, and automatically forward Wayland applications.\n"
		"  server CMD   Run remotely to invoke CMD and forward application data through\n"
		"                 a socket to a matching 'waypipe client' instance.\n"
		"  client       Run locally to create a Unix socket to which 'waypipe server'\n"
		"                 instances can connect.\n"
		"  recon C T    Reconnect a 'waypipe server' instance. Writes the new Unix\n"
		"                 socket path T to the control pipe C.\n"
		"  bench B      Given a connection bandwidth B in MB/sec, estimate the best\n"
		"                 compression level used to send data\n"
		"\n"
		"Options:\n"
		"  -c, --compress C     choose compression method: lz4[=#], zstd=[=#], none\n"
		"  -d, --debug          print debug messages\n"
		"  -h, --help           display this help and exit\n"
		"  -n, --no-gpu         disable protocols which would use GPU resources\n"
		"  -o, --oneshot        only permit one connected application\n"
		"  -s, --socket S       set the socket path to either create or connect to:\n"
		"                         server default: /tmp/waypipe-server.sock\n"
		"                         client default: /tmp/waypipe-client.sock\n"
		"                         ssh: sets the prefix for the socket path\n"
		"  -v, --version        print waypipe version and exit\n"
		"      --allow-tiled    allow gpu buffers (DMABUFs) with format modifiers\n"
		"      --control C      server,ssh: set control pipe to reconnect server\n"
		"      --display D      server,ssh: the Wayland display name or path\n"
		"      --drm-node R     set the local render node. default: /dev/dri/renderD128\n"
		"      --remote-node R  ssh: set the remote render node path\n"
		"      --remote-bin R   ssh: set the remote waypipe binary. default: waypipe\n"
		"      --login-shell    server: if server CMD is empty, run a login shell\n"
		"      --threads T      set thread pool size, default=hardware threads/2\n"
		"      --unlink-socket  server: unlink the socket that waypipe connects to\n"
		"      --video          compress certain linear dmabufs only with a video codec\n"
		"      --hwvideo        use --video, and try hardware enc/decoding if available\n"
		"\n";

static int usage(int retcode)
{
	FILE *ostream = retcode == EXIT_SUCCESS ? stderr : stdout;
	fprintf(ostream, usage_string);
	return retcode;
}

static void log_handler(const char *file, int line, enum log_level level,
		const char *fmt, ...)
{
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	int pid = getpid();

	char mode;
	if (log_mode == MODE_SERVER) {
		mode = level == WP_DEBUG ? 's' : 'S';
	} else {
		mode = level == WP_DEBUG ? 'c' : 'C';
	}

	char msg[1024];
	int nwri = 0;
	if (log_to_tty) {
		msg[nwri++] = '\x1b';
		msg[nwri++] = '[';
		msg[nwri++] = '3';
		/* blue for waypipe client, green for waypipe server,
		 * (or unformatted for waypipe server if no pty is made */
		msg[nwri++] = log_mode == MODE_SERVER ? '2' : '4';
		msg[nwri++] = 'm';
		if (level == WP_ERROR) {
			/* bold errors */
			msg[nwri++] = '\x1b';
			msg[nwri++] = '[';
			msg[nwri++] = '1';
			msg[nwri++] = 'm';
		}
	}

	int sec = (int)(ts.tv_sec % 100);
	int usec = (int)(ts.tv_nsec / 1000);
	nwri += sprintf(msg + nwri, "%c%d:%3d.%06d [%s:%3d] ", mode, pid, sec,
			usec, file, line);

	va_list args;
	va_start(args, fmt);
	nwri += vsnprintf(msg + nwri, (size_t)(1000 - nwri), fmt, args);
	va_end(args);

	if (log_to_tty) {
		msg[nwri++] = '\x1b';
		msg[nwri++] = '[';
		msg[nwri++] = '0';
		msg[nwri++] = 'm';

		/* to avoid 'staircase' rendering when ssh has the '-t' flag
		 * and sets raw mode for the shared terminal output */
		if (log_anti_staircase) {
			msg[nwri++] = '\r';
		}
	}
	msg[nwri++] = '\n';
	msg[nwri] = 0;

	// single short writes are atomic for pipes, at least
	(void)write(STDERR_FILENO, msg, (size_t)nwri);
}

static void handle_noop(int sig) { (void)sig; }

/* Configure signal handling policies */
static int setup_sighandlers()
{
	struct sigaction ia; // SIGINT: abort operations, and set a flag
	ia.sa_handler = handle_sigint;
	sigemptyset(&ia.sa_mask);
	ia.sa_flags = 0;
	struct sigaction ca; // SIGCHLD: restart operations, but EINTR on poll
	ca.sa_handler = handle_noop;
	sigemptyset(&ca.sa_mask);
	ca.sa_flags = SA_RESTART | SA_NOCLDSTOP;
	struct sigaction pa;
	pa.sa_handler = SIG_IGN;
	sigemptyset(&pa.sa_mask);
	pa.sa_flags = 0;
	if (sigaction(SIGINT, &ia, NULL) == -1) {
		wp_error("Failed to set signal action for SIGINT");
		return -1;
	}
	if (sigaction(SIGCHLD, &ca, NULL) == -1) {
		wp_error("Failed to set signal action for SIGCHLD");
		return -1;
	}
	if (sigaction(SIGPIPE, &pa, NULL) == -1) {
		wp_error("Failed to set signal action for SIGPIPE");
		return -1;
	}
	return 0;
}

/* produces a random token with a low accidental collision probability */
static void fill_rand_token(char tok[static 8])
{
	struct timespec tp;
	clock_gettime(CLOCK_REALTIME, &tp);
	uint32_t seed = (uint32_t)(getpid() + tp.tv_sec + (tp.tv_nsec << 2));
	srand(seed);
	for (int i = 0; i < 8; i++) {
		unsigned int r = ((unsigned int)rand()) % 62;
		if (r < 26) {
			tok[i] = (char)(r + 'a');
		} else if (r < 52) {
			tok[i] = (char)(r - 26 + 'A');
		} else {
			tok[i] = (char)(r - 52 + '0');
		}
	}
}

/* Scan a suffix which is either empty or has the form =N, returning true
 * if it matches */
static bool parse_level_choice(const char *str, int *dest, int defval)
{
	if (str[0] == '\0') {
		*dest = defval;
		return true;
	}
	if (str[0] != '=') {
		return false;
	}
	char *endptr = NULL;
	int dv = (int)strtol(str + 1, &endptr, 10);
	if (*endptr != 0) {
		return false;
	}
	*dest = dv;
	return true;
}

/* Identifies the index at which the `destination` occurs in an openssh command,
 * and also sets a boolean if pty allocation was requested by an ssh flag */
static int locate_openssh_cmd_hostname(
		int argc, char *const *argv, bool *allocates_pty)
{
	/* Based on command line help for openssh 8.0 */
	char fixletters[] = "46AaCfGgKkMNnqsTtVvXxYy";
	char argletters[] = "BbcDEeFIiJLlmOopQRSWw";
	int dstidx = 0;
	while (dstidx < argc) {
		if (argv[dstidx][0] == '-' &&
				strchr(argletters, argv[dstidx][1]) != NULL &&
				argv[dstidx][2] == 0) {
			dstidx += 2;
			continue;
		}
		if (argv[dstidx][0] == '-' &&
				strchr(fixletters, argv[dstidx][1]) != NULL) {
			for (const char *c = &argv[dstidx][1]; *c; c++) {
				*allocates_pty |= (*c == 't');
				*allocates_pty &= (*c != 'T');
			}
			dstidx++;
			continue;
		}
		if (argv[dstidx][0] == '-' && argv[dstidx][1] == '-' &&
				argv[dstidx][2] == 0) {
			dstidx++;
			break;
		}

		break;
	}
	if (dstidx >= argc || argv[dstidx][0] == '-') {
		return -1;
	}
	return dstidx;
}

/* Send the socket at 'recon_path' to the control socket at 'control_path'.
 * Because connections are made by address, the waypipe server root process
 * must be able to connect to the `recon path`. */
static int run_recon(const char *control_path, const char *recon_path)
{
	size_t len = strlen(recon_path);
	if (len >= 108) {
		fprintf(stderr, "Reconnection socket path \"%s\" too long, %d>=%d\n",
				control_path, (int)len, 108);
		return EXIT_FAILURE;
	}
	int cfd = open(control_path, O_WRONLY);
	if (cfd == -1) {
		fprintf(stderr, "Failed to open control pipe at \"%s\"\n",
				control_path);
		return EXIT_FAILURE;
	}
	ssize_t written = write(cfd, recon_path, len + 1);
	if ((size_t)written != len + 1) {
		close(cfd);
		fprintf(stderr, "Failed to write to control pipe\n");
		return EXIT_FAILURE;
	}
	close(cfd);
	return EXIT_SUCCESS;
}

#define ARG_DISPLAY 1001
#define ARG_DRMNODE 1002
#define ARG_ALLOW_TILED 1003
#define ARG_LOGIN_SHELL 1004
#define ARG_REMOTENODE 1005
#define ARG_THREADS 1006
#define ARG_UNLINK 1007
#define ARG_VIDEO 1008
#define ARG_HWVIDEO 1009
#define ARG_CONTROL 1010
#define ARG_WAYPIPE_BINARY 1011

static const struct option options[] = {
		{"compress", required_argument, NULL, 'c'},
		{"debug", no_argument, NULL, 'd'},
		{"help", no_argument, NULL, 'h'},
		{"no-gpu", no_argument, NULL, 'n'},
		{"oneshot", no_argument, NULL, 'o'},
		{"socket", required_argument, NULL, 's'},
		{"version", no_argument, NULL, 'v'},
		{"allow-tiled", no_argument, NULL, ARG_ALLOW_TILED},
		{"unlink-socket", no_argument, NULL, ARG_UNLINK},
		{"drm-node", required_argument, NULL, ARG_DRMNODE},
		{"remote-node", required_argument, NULL, ARG_REMOTENODE},
		{"remote-bin", required_argument, NULL, ARG_WAYPIPE_BINARY},
		{"login-shell", no_argument, NULL, ARG_LOGIN_SHELL},
		{"video", no_argument, NULL, ARG_VIDEO},
		{"hwvideo", no_argument, NULL, ARG_HWVIDEO},
		{"threads", required_argument, NULL, ARG_THREADS},
		{"display", required_argument, NULL, ARG_DISPLAY},
		{"control", required_argument, NULL, ARG_CONTROL},
		{0, 0, NULL, 0}};
struct arg_permissions {
	int val;
	uint32_t mode_mask;
};
#define ALL_MODES (uint32_t) - 1
static const struct arg_permissions arg_permissions[] = {
		{'c', MODE_SSH | MODE_CLIENT | MODE_SERVER},
		{'d', ALL_MODES},
		{'h', ALL_MODES},
		{'n', MODE_SSH | MODE_CLIENT | MODE_SERVER},
		{'o', MODE_SSH | MODE_CLIENT | MODE_SERVER},
		{'s', MODE_SSH | MODE_CLIENT | MODE_SERVER},
		{'v', ALL_MODES},
		{ARG_ALLOW_TILED, MODE_SSH | MODE_CLIENT | MODE_SERVER},
		{ARG_UNLINK, MODE_SERVER},
		{ARG_DRMNODE, MODE_SERVER},
		{ARG_REMOTENODE, MODE_SSH},
		{ARG_WAYPIPE_BINARY, MODE_SSH},
		{ARG_LOGIN_SHELL, MODE_SERVER},
		{ARG_VIDEO, MODE_SSH | MODE_CLIENT | MODE_SERVER},
		{ARG_HWVIDEO, MODE_SSH | MODE_CLIENT | MODE_SERVER},
		{ARG_THREADS, MODE_SSH | MODE_CLIENT | MODE_SERVER |
						MODE_BENCH},
		{ARG_DISPLAY, MODE_SSH | MODE_SERVER},
		{ARG_CONTROL, MODE_SSH | MODE_SERVER},
};

int main(int argc, char **argv)
{
	bool help = false;
	bool version = false;
	bool fail = false;
	bool debug = false;
	bool oneshot = false;
	bool unlink_at_end = false;
	bool login_shell = false;
	char *remote_drm_node = NULL;
	char *comp_string = NULL;
	char *nthread_string = NULL;
	char *wayland_display = NULL;
	char *waypipe_binary = "waypipe";
	char *control_path = NULL;
	const char *socketpath = NULL;

	struct main_config config = {.n_worker_threads = 0,
			.drm_node = NULL,
			.compression = COMP_NONE,
			.compression_level = 0,
			.no_gpu = false,
			.only_linear_dmabuf = true,
			.video_if_possible = false,
			.prefer_hwvideo = false};

	/* We do not parse any getopt arguments happening after the mode choice
	 * string, so as not to interfere with them. */
	enum waypipe_mode mode = MODE_FAIL;
	int mode_argc = 0;
	while (mode_argc < argc) {
		if (!strcmp(argv[mode_argc], "ssh")) {
			mode = MODE_SSH;
			break;
		}
		if (!strcmp(argv[mode_argc], "client")) {
			mode = MODE_CLIENT;
			break;
		}
		if (!strcmp(argv[mode_argc], "server")) {
			mode = MODE_SERVER;
			break;
		}
		if (!strcmp(argv[mode_argc], "recon")) {
			mode = MODE_RECON;
			break;
		}
		if (!strcmp(argv[mode_argc], "bench")) {
			mode = MODE_BENCH;
			break;
		}
		mode_argc++;
	}

	while (true) {
		int option_index;
		int opt = getopt_long(mode_argc, argv, "c:dhnos:v", options,
				&option_index);

		if (opt == -1) {
			break;
		}
		const struct arg_permissions *perms = NULL;
		for (size_t k = 0;
				k < sizeof(arg_permissions) /
						    sizeof(arg_permissions[0]);
				k++) {
			if (arg_permissions[k].val == opt) {
				perms = &arg_permissions[k];
			}
		}
		if (!perms) {
			fail = true;
			break;
		}
		if (!(mode & perms->mode_mask) && mode != MODE_FAIL) {
			fprintf(stderr, "Option %s is not allowed in mode %s\n",
					options[option_index].name,
					argv[mode_argc]);
			return EXIT_FAILURE;
		}

		switch (opt) {
		case 'c':
			if (!strcmp(optarg, "none")) {
				config.compression = COMP_NONE;
				config.compression_level = 0;
			} else if (!strncmp(optarg, "lz4", 3) &&
					parse_level_choice(optarg + 3,
							&config.compression_level,
							-1)) {
#ifdef HAS_LZ4
				config.compression = COMP_LZ4;
#else
				fprintf(stderr, "LZ4 compression not available: is the library installed?\n");
				return EXIT_FAILURE;
#endif
			} else if (!strncmp(optarg, "zstd", 4) &&
					parse_level_choice(optarg + 4,
							&config.compression_level,
							5)) {
#ifdef HAS_ZSTD
				config.compression = COMP_ZSTD;
#else
				fprintf(stderr, "ZSTD compression not available: is the library installed?\n");
				return EXIT_FAILURE;
#endif
			} else {
				fail = true;
			}
			comp_string = optarg;
			break;
		case 'd':
			debug = true;
			break;
		case 'h':
			help = true;
			break;
		case 'n':
			config.no_gpu = true;
			break;
		case 'o':
			oneshot = true;
			break;
		case 's':
			socketpath = optarg;
			break;
		case 'v':
			version = true;
			break;
		case ARG_DISPLAY:
			wayland_display = optarg;
			break;
		case ARG_CONTROL:
			control_path = optarg;
			break;
		case ARG_UNLINK:
			unlink_at_end = true;
			break;
		case ARG_DRMNODE:
			config.drm_node = optarg;
			break;
		case ARG_REMOTENODE:
			remote_drm_node = optarg;
			break;
		case ARG_LOGIN_SHELL:
			login_shell = true;
			break;
		case ARG_ALLOW_TILED:
			config.only_linear_dmabuf = false;
			break;
		case ARG_VIDEO:
			config.video_if_possible = true;
			break;
		case ARG_HWVIDEO:
			config.video_if_possible = true;
			config.prefer_hwvideo = true;
			break;
		case ARG_THREADS: {
			char *endptr;
			config.n_worker_threads =
					(int)strtol(optarg, &endptr, 10);
			nthread_string = optarg;
			if (*endptr != 0 || config.n_worker_threads < 0) {
				fail = true;
			}
		} break;
		case ARG_WAYPIPE_BINARY:
			waypipe_binary = optarg;
			break;
		default:
			fail = true;
			break;
		}
	}

	argv += optind;
	argc -= optind;
	if (fail) {
		return usage(EXIT_FAILURE);
	} else if (version) {
		fprintf(stdout, "waypipe " WAYPIPE_VERSION "\n");
		return EXIT_SUCCESS;
	} else if (argc < 1) {
		return usage(EXIT_FAILURE);
	} else if (help) {
		return usage(EXIT_SUCCESS);
	} else if (mode == MODE_FAIL) {
		return usage(EXIT_FAILURE);
	}
	if (mode == MODE_CLIENT && argc > 1) {
		// In client mode, we do not start an application
		return usage(EXIT_FAILURE);
	} else if (mode == MODE_RECON && argc != 3) {
		// The reconnection helper takes exactly two trailing arguments
		return usage(EXIT_FAILURE);
	} else if (mode == MODE_BENCH && argc != 2) {
		return usage(EXIT_FAILURE);
	}
	argv++;
	argc--;
	if (argc > 0 && !strcmp(argv[0], "--")) {
		argv++;
		argc--;
	}

	if (debug) {
		log_funcs[0] = log_handler;
	}
	log_funcs[1] = log_handler;
	log_mode = mode;
	log_anti_staircase = false;
	log_to_tty = isatty(STDERR_FILENO);

	if (setup_sighandlers() == -1) {
		return EXIT_FAILURE;
	}

	bool via_socket = getenv("WAYLAND_SOCKET") != NULL;
	if (via_socket) {
		oneshot = true;
	}

	if (mode == MODE_RECON) {
		return run_recon(argv[0], argv[1]);
	} else if (mode == MODE_BENCH) {
		char *endptr = NULL;
		float bw = strtof(argv[0], &endptr);
		if (*endptr != 0) {
			wp_error("Failed to parse bandwidth '%s' in MB/sec\n",
					argv[0]);
			return EXIT_FAILURE;
		}
		return run_bench(bw, config.n_worker_threads);
	} else if (mode == MODE_CLIENT) {
		if (!socketpath) {
			socketpath = "/tmp/waypipe-client.sock";
		}
		return run_client(socketpath, &config, oneshot, via_socket, 0);
	} else if (mode == MODE_SERVER) {
		char *const *app_argv = (char *const *)argv;
		if (!socketpath) {
			socketpath = "/tmp/waypipe-server.sock";
		}
		char display_path[20];
		if (!wayland_display) {
			char rbytes[9];
			fill_rand_token(rbytes);
			rbytes[8] = 0;
			sprintf(display_path, "wayland-%s", rbytes);
			wayland_display = display_path;
		}
		return run_server(socketpath, wayland_display, control_path,
				&config, oneshot, unlink_at_end, app_argv,
				login_shell);
	} else {
		if (!socketpath) {
			socketpath = "/tmp/waypipe";
		}
		const size_t max_splen =
				(int)sizeof(((struct sockaddr_un *)NULL)
								->sun_path) -
				22;
		if (strlen(socketpath) > max_splen) {
			fprintf(stderr, "Socket path prefix '%s' is too long (more than %d bytes).\n",
					socketpath, (int)max_splen);
			return EXIT_FAILURE;
		}

		char rbytes[9];
		fill_rand_token(rbytes);
		rbytes[8] = 0;

		char clientsock[110];
		memset(clientsock, 0, sizeof(clientsock));
		sprintf(clientsock, "%s-client-%s.sock", socketpath, rbytes);

		bool allocates_pty = false;
		int dstidx = locate_openssh_cmd_hostname(
				argc, argv, &allocates_pty);
		if (dstidx < 0) {
			fprintf(stderr, "waypipe: Failed to locate destination in ssh command string\n");
			return EXIT_FAILURE;
		}
		/* If there are no arguments following the destination */
		bool needs_login_shell = dstidx + 1 == argc;
		if (needs_login_shell || allocates_pty) {
			log_anti_staircase = true;
		}

		pid_t conn_pid = fork();
		if (conn_pid == -1) {
			wp_error("Fork failure");
			return EXIT_FAILURE;
		} else if (conn_pid == 0) {
			char linkage[256];
			char serversock[110];
			char remote_display[20];
			sprintf(serversock, "%s-server-%s.sock", socketpath,
					rbytes);
			sprintf(linkage, "%s:%s", serversock, clientsock);
			sprintf(remote_display, "wayland-%s", rbytes);
			if (!wayland_display) {
				wayland_display = remote_display;
			}

			int nextra = 12 + debug + oneshot +
				     2 * (remote_drm_node != NULL) +
				     2 * (control_path != NULL) +
				     2 * (config.compression != COMP_NONE) +
				     config.video_if_possible +
				     !config.only_linear_dmabuf +
				     2 * needs_login_shell +
				     2 * (config.n_worker_threads != 0);
			char **arglist = calloc((size_t)(argc + nextra),
					sizeof(char *));

			int offset = 0;
			arglist[offset++] = "/usr/bin/ssh";
			if (needs_login_shell) {
				/* Force tty allocation, if we are attempting
				 * a login shell. The user-override is a -T
				 * flag, and a second -t will ensure a login
				 * shell even if waypipe ssh was not run from a
				 * pty. Unfortunately, -t disables newline
				 * translation on the local side; see
				 * `log_handler`. */
				arglist[offset++] = "-t";
			}
			arglist[offset++] = "-R";
			arglist[offset++] = linkage;
			for (int i = 0; i <= dstidx; i++) {
				arglist[offset + i] = argv[i];
			}
			arglist[dstidx + 1 + offset++] = waypipe_binary;
			if (debug) {
				arglist[dstidx + 1 + offset++] = "-d";
			}
			if (oneshot) {
				arglist[dstidx + 1 + offset++] = "-o";
			}
			if (config.compression != COMP_NONE) {
				arglist[dstidx + 1 + offset++] = "-c";
				arglist[dstidx + 1 + offset++] = comp_string;
			}
			if (needs_login_shell) {
				arglist[dstidx + 1 + offset++] =
						"--login-shell";
			}
			if (config.video_if_possible) {
				arglist[dstidx + 1 + offset++] =
						config.prefer_hwvideo
								? "--hwvideo"
								: "--video";
			}
			if (!config.only_linear_dmabuf) {
				arglist[dstidx + 1 + offset++] =
						"--allow-tiled";
			}
			if (remote_drm_node) {
				arglist[dstidx + 1 + offset++] = "--drm-node";
				arglist[dstidx + 1 + offset++] =
						remote_drm_node;
			}
			if (config.n_worker_threads != 0) {
				arglist[dstidx + 1 + offset++] = "--threads";
				arglist[dstidx + 1 + offset++] = nthread_string;
			}
			if (control_path) {
				arglist[dstidx + 1 + offset++] = "--control";
				arglist[dstidx + 1 + offset++] = control_path;
			}
			arglist[dstidx + 1 + offset++] = "--unlink-socket";
			arglist[dstidx + 1 + offset++] = "-s";
			arglist[dstidx + 1 + offset++] = serversock;
			arglist[dstidx + 1 + offset++] = "--display";
			arglist[dstidx + 1 + offset++] = wayland_display;
			arglist[dstidx + 1 + offset++] = "server";
			for (int i = dstidx + 1; i < argc; i++) {
				arglist[offset + i] = argv[i];
			}
			arglist[argc + offset] = NULL;

			// execvp effectively frees arglist
			execvp(arglist[0], arglist);
			wp_error("Fork failed");
			free(arglist);
			return EXIT_FAILURE;
		} else {
			return run_client(clientsock, &config, oneshot,
					via_socket, conn_pid);
		}
	}
}
