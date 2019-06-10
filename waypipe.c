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

#define _XOPEN_SOURCE 700

#include "util.h"

#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

int run_server(const char *socket_path, const char *drm_node,
		enum compression_mode compression, bool oneshot,
		bool unlink_at_end, const char *application,
		char *const app_argv[]);
int run_client(const char *socket_path, const char *drm_node,
		enum compression_mode compression, bool oneshot, bool no_gpu,
		pid_t eol_pid);

/* Usage: Wrapped to 79 characters */
static const char usage_string[] =
		"Usage: waypipe [options] mode ...\n"
		"A proxy for Wayland protocol applications.\n"
		"Example: waypipe ssh -C user@place weston-terminal\n"
		"\n"
		"Modes:\n"
		"  ssh [...]    Wrap an ssh invocation to run waypipe on both ends of the\n"
		"                 connection, and automatically forward Wayland applications.\n"
		"  server CMD   Run remotely to invoke CMD and forward application data through\n"
		"                 a socket to a matching 'waypipe client' instance.\n"
		"  client       Run locally to create a Unix socket to which 'waypipe server'\n"
		"                 instances can connect.\n"
		"\n"
		"Options:\n"
		"  -c, --compress C     select compression method from: lz4, zstd, none\n"
		"  -d, --debug          print debug messages\n"
		"  -h, --help           display this help and exit\n"
		"  -n, --no-gpu         disable protocols which would use GPU resources\n"
		"  -o, --oneshot        only permit one connected application\n"
		"  -s, --socket S       set the socket path to either create or connect to:\n"
		"                         server default: /tmp/waypipe-server.sock\n"
		"                         client default: /tmp/waypipe-client.sock\n"
		"                         ssh mode: sets the prefix for the socket path\n"
		"  -v, --version        print waypipe version and exit\n"
		"      --drm-node R     set the local render node. default: /dev/dri/renderD128\n"
		"      --remote-node R  ssh mode: set the remote render node path\n"
		"      --login-shell    server mode: if server CMD is empty, run a login shell\n"
		"      --unlink-socket  server mode: unlink the socket that waypipe connects to\n"
		"\n";

static int usage(int retcode)
{
	FILE *ostream = retcode == EXIT_SUCCESS ? stderr : stdout;
	fprintf(ostream, usage_string);
	return retcode;
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

static int locate_openssh_cmd_hostname(int argc, char *const *argv)
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

/* requires >=256 byte shell/shellname buffers */
static void setup_login_shell_command(char shell[static 256],
		char shellname[static 256], bool login_shell)
{
	strcpy(shellname, "-sh");
	strcpy(shell, "/bin/sh");

	// Select the preferred shell on the system
	char *shell_env = getenv("SHELL");
	if (!shell_env) {
		return;
	}
	int len = (int)strlen(shell_env);
	if (len >= 254) {
		fprintf(stderr, "Environment variable $SHELL is too long at %d bytes, falling back to %s\n",
				len, shell);
		return;
	}
	strcpy(shell, shell_env);
	if (login_shell) {
		/* Create a login shell. The convention for this is to prefix
		 * the name of the shell with a single hyphen */
		int start = len;
		for (; start-- > 0;) {
			if (shell[start] == '/') {
				start++;
				break;
			}
		}
		shellname[0] = '-';
		strcpy(shellname + 1, shell + start);
	} else {
		strcpy(shellname, shell);
	}
}

void handle_noop(int sig) { (void)sig; }

#define ARG_UNLINK 1001
#define ARG_DRMNODE 1002
#define ARG_REMOTENODE 1003
#define ARG_LOGIN_SHELL 1004

static const struct option options[] = {
		{"compress", required_argument, NULL, 'c'},
		{"debug", no_argument, NULL, 'd'},
		{"help", no_argument, NULL, 'h'},
		{"no-gpu", no_argument, NULL, 'n'},
		{"oneshot", no_argument, NULL, 'o'},
		{"socket", required_argument, NULL, 's'},
		{"version", no_argument, NULL, 'v'},
		{"unlink-socket", no_argument, NULL, ARG_UNLINK},
		{"drm-node", required_argument, NULL, ARG_DRMNODE},
		{"remote-node", required_argument, NULL, ARG_REMOTENODE},
		{"login-shell", no_argument, NULL, ARG_LOGIN_SHELL},
		{0, 0, NULL, 0}};

enum waypipe_mode { MODE_FAIL, MODE_SSH, MODE_CLIENT, MODE_SERVER };

int main(int argc, char **argv)
{
	bool help = false;
	bool version = false;
	bool fail = false;
	bool debug = false;
	bool nogpu = false;
	bool oneshot = false;
	bool unlink_at_end = false;
	bool login_shell = false;
	const char *drm_node = NULL;
	char *remote_drm_node = NULL;
	const char *socketpath = NULL;
	enum compression_mode compression = COMP_NONE;

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
		mode_argc++;
	}

	while (true) {
		int option_index;
		int opt = getopt_long(mode_argc, argv, "c:dhnos:v", options,
				&option_index);

		if (opt == -1) {
			break;
		}

		switch (opt) {
		case 'c':
			if (!strcmp(optarg, "none")) {
				compression = COMP_NONE;
			} else if (!strcmp(optarg, "lz4")) {
				compression = COMP_LZ4;
			} else if (!strcmp(optarg, "zstd")) {
				compression = COMP_ZSTD;
			} else {
				fail = true;
			}
			break;
		case 'd':
			debug = true;
			break;
		case 'h':
			help = true;
			break;
		case 'n':
			nogpu = true;
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
		case ARG_UNLINK:
			if (mode != MODE_SERVER) {
				fail = true;
			}
			unlink_at_end = true;
			break;
		case ARG_DRMNODE:
			drm_node = optarg;
			break;
		case ARG_REMOTENODE:
			if (mode != MODE_SSH) {
				fail = true;
			}
			remote_drm_node = optarg;
			break;
		case ARG_LOGIN_SHELL:
			if (mode != MODE_SERVER) {
				fail = true;
			}
			login_shell = true;
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
	}
	argv++;
	argc--;
	if (argc > 0 && !strcmp(argv[0], "--")) {
		argv++;
		argc--;
	}
	waypipe_loglevel = debug ? WP_DEBUG : WP_ERROR;
	waypipe_log_mode = (mode == MODE_SSH)
					   ? 'c'
					   : (mode == MODE_CLIENT ? 'C' : 'S');

	// Setup signals
	struct sigaction ia; // SIGINT: abort operations, and set a flag
	ia.sa_handler = handle_sigint;
	sigemptyset(&ia.sa_mask);
	ia.sa_flags = 0;
	struct sigaction ca; // SIGCHLD: restart operations, but EINTR on poll
	ca.sa_handler = handle_noop;
	sigemptyset(&ca.sa_mask);
	ca.sa_flags = SA_RESTART | SA_NOCLDSTOP;
	if (sigaction(SIGINT, &ia, NULL) == -1) {
		wp_log(WP_ERROR, "Failed to set signal action for SIGINT");
		return EXIT_FAILURE;
	}
	if (sigaction(SIGCHLD, &ca, NULL) == -1) {
		wp_log(WP_ERROR, "Failed to set signal action for SIGCHLD");
		return EXIT_FAILURE;
	}

	if (mode == MODE_CLIENT) {
		if (!socketpath) {
			socketpath = "/tmp/waypipe-client.sock";
		}
		return run_client(socketpath, drm_node, compression, oneshot,
				nogpu, 0);
	} else if (mode == MODE_SERVER) {
		char *const *app_argv = (char *const *)argv;
		const char *application = app_argv[0];
		char shell[256];
		char shellname[256];
		char *shellcmd[2] = {shellname, NULL};
		if (argc == 0) {
			setup_login_shell_command(
					shell, shellname, login_shell);
			application = shell;
			app_argv = shellcmd;
		}
		if (!socketpath) {
			socketpath = "/tmp/waypipe-server.sock";
		}
		return run_server(socketpath, drm_node, compression, oneshot,
				unlink_at_end, application, app_argv);
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

		char linkage[256];
		char serversock[110];
		char clientsock[110];
		sprintf(serversock, "%s-server-%s.sock", socketpath, rbytes);
		sprintf(clientsock, "%s-client-%s.sock", socketpath, rbytes);
		sprintf(linkage, "%s:%s", serversock, clientsock);

		pid_t conn_pid = fork();
		if (conn_pid == -1) {
			wp_log(WP_ERROR, "Fork failure");
			return EXIT_FAILURE;
		} else if (conn_pid == 0) {
			int dstidx = locate_openssh_cmd_hostname(argc, argv);
			if (dstidx < 0) {
				fprintf(stderr, "waypipe: Failed to locate destination in ssh command string\n");
				return EXIT_FAILURE;
			}

			/* If there are no arguments following the destination
			 */
			bool needs_login_shell = dstidx + 1 == argc;

			int nextra = 10 + debug + oneshot +
				     2 * (remote_drm_node != NULL) +
				     2 * (compression != COMP_NONE) +
				     needs_login_shell;
			char **arglist = calloc(argc + nextra, sizeof(char *));

			int offset = 0;
			arglist[offset++] = "/usr/bin/ssh";
			/* Force tty allocation. The user-override is a -T flag.
			 * Unfortunately, -t disables newline translation on the
			 * local side; see `wp_log_handler`. */
			arglist[offset++] = "-t";
			arglist[offset++] = "-R";
			arglist[offset++] = linkage;
			for (int i = 0; i <= dstidx; i++) {
				arglist[offset + i] = argv[i];
			}
			/* NOTE: the remote waypipe instance must be in
			 * the default PATH */
			arglist[dstidx + 1 + offset++] = "waypipe";
			if (debug) {
				arglist[dstidx + 1 + offset++] = "-d";
			}
			if (oneshot) {
				arglist[dstidx + 1 + offset++] = "-o";
			}
			if (compression != COMP_NONE) {
				arglist[dstidx + 1 + offset++] = "-c";
				arglist[dstidx + 1 + offset++] =
						compression == COMP_LZ4
								? "lz4"
								: "zstd";
			}
			if (needs_login_shell) {
				arglist[dstidx + 1 + offset++] =
						"--login-shell";
			}
			if (remote_drm_node) {
				arglist[dstidx + 1 + offset++] = "--drm-node";
				arglist[dstidx + 1 + offset++] =
						remote_drm_node;
			}
			arglist[dstidx + 1 + offset++] = "--unlink-socket";
			arglist[dstidx + 1 + offset++] = "-s";
			arglist[dstidx + 1 + offset++] = serversock;
			arglist[dstidx + 1 + offset++] = "server";
			for (int i = dstidx + 1; i < argc; i++) {
				arglist[offset + i] = argv[i];
			}
			arglist[argc + offset] = NULL;

			// execvp effectively frees arglist
			execvp(arglist[0], arglist);
			wp_log(WP_ERROR, "Fork failed");
			free(arglist);
			return EXIT_FAILURE;
		} else {
			return run_client(clientsock, drm_node, compression,
					oneshot, nogpu, conn_pid);
		}
	}
}
