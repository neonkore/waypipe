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
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

int run_server(const char *socket_path, bool oneshot, bool unlink_at_end,
		const char *application, char *const app_argv[]);
int run_client(const char *socket_path, bool oneshot, bool no_gpu,
		pid_t eol_pid);

/* Usage: Wrapped to 72 characters */
static const char usage_string[] =
		"usage: waypipe [OPTION] mode [arguments...]\n\n"
		"A proxy for wayland applications. It can be run as a client on the\n"
		"side with a wayland compositor, as server on the remote system, or\n"
		"by wrapping an ssh invocation to automatically set up forwarding.\n"
		"\n"
		"modes:\n"
		"    ssh              Will run ssh with the given arguments, invoking\n"
		"                       waypipe locally and remotely to forward wayland\n"
		"                       connections as well. Assumes the remote copy of\n"
		"                       waypipe is in the default PATH.\n"
		"    server           Emulate a wayland compositor and forward all\n"
		"                       client data to the given socket (by default, at\n"
		"                       /tmp/waypipe-server.sock).\n"
		"    client           Emulate a wayland client and forward all\n"
		"                       compositor data to the given socket (by\n"
		"                       default, /tmp/waypipe-client.sock)\n"
		"options:\n"
		"    -d,  --debug     Print debug messages.\n"
		"    -h,  --help      Display this help and exit.\n"
		"    -n,  --no-gpu    Disable protocols which would use GPU resources\n"
		"    -o,  --oneshot   Only permit one client\n"
		"    -s,  --socket S  Set the socket path, on which waypipe listens\n"
		"                       if it is a client, and to which waypipe\n"
		"                       connects if it is a server. In ssh mode, forms\n"
		"                       the prefix of the socket path.\n"
		"    -u,  --unlink    If in server mode, unlink the socket once\n"
		"                       no more connections will be made to it.\n"
		"    -v,  --version   Print waypipe version.\n";

static int usage(int retcode)
{
	FILE *ostream = retcode == EXIT_SUCCESS ? stderr : stdout;
	fprintf(ostream, usage_string);
	return retcode;
}

static void fill_rand_token(char tok[static 8])
{
	// TODO: replace with a true random value; time() overlaps /very/ easily
	srand(time(NULL));
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

static bool strcont(char v, const char *string)
{
	while (true) {
		if (*string == 0) {
			return false;
		} else if (*string == v) {
			return true;
		}
		string++;
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
				strcont(argv[dstidx][1], argletters) &&
				argv[dstidx][2] == 0) {
			dstidx += 2;
			continue;
		}
		if (argv[dstidx][0] == '-' &&
				strcont(argv[dstidx][1], fixletters)) {
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
static void setup_login_shell_command(
		char shell[static 256], char shellname[static 256])
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
	/* Create a login shell. The convention for this is to prefix the name
	 * of the shell with a single hyphen */
	int start = len;
	for (; start-- > 0;) {
		if (shell[start] == '/') {
			start++;
			break;
		}
	}
	shellname[0] = '-';
	strcpy(shellname + 1, shell + start);
}

void handle_noop(int sig) { (void)sig; }

static const struct option options[] = {{"debug", no_argument, NULL, 'd'},
		{"help", no_argument, NULL, 'h'},
		{"no-gpu", no_argument, NULL, 'n'},
		{"oneshot", no_argument, NULL, 'o'},
		{"socket", required_argument, NULL, 's'},
		{"unlink", no_argument, NULL, 'u'},
		{"version", no_argument, NULL, 'v'}, {0, 0, NULL, 0}};

int main(int argc, char **argv)
{
	bool help = false;
	bool version = false;
	bool fail = false;
	bool debug = false;
	bool nogpu = false;
	bool oneshot = false;
	bool unlink_at_end = false;
	bool is_client, setup_ssh;
	const char *socketpath = NULL;

	/* We do not parse any getopt arguments happening after the mode choice
	 * string, so as not to interfere with them. */
	int mode_argc = 0;
	while (mode_argc < argc) {
		if (!strcmp(argv[mode_argc], "ssh") ||
				!strcmp(argv[mode_argc], "client") ||
				!strcmp(argv[mode_argc], "server")) {
			break;
		}
		mode_argc++;
	}

	while (true) {
		int option_index;
		int opt = getopt_long(mode_argc, argv, "dhnos:uv", options,
				&option_index);

		if (opt == -1) {
			break;
		}

		switch (opt) {
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
		case 'u':
			unlink_at_end = true;
			break;
		case 'v':
			version = true;
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
		// todo: immediately useful error message
		return usage(EXIT_FAILURE);
	} else if (help) {
		return usage(EXIT_SUCCESS);
	} else if (!strcmp(argv[0], "ssh")) {
		is_client = true;
		setup_ssh = true;
	} else if (!strcmp(argv[0], "client")) {
		is_client = true;
		setup_ssh = false;
	} else if (!strcmp(argv[0], "server")) {
		is_client = false;
		setup_ssh = false;
	} else {
		return usage(EXIT_FAILURE);
	}
	if ((is_client && !setup_ssh) && argc > 1) {
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
	waypipe_log_mode = setup_ssh ? 'c' : (is_client ? 'C' : 'S');

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

	if (is_client) {
		if (setup_ssh) {
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
			sprintf(serversock, "%s-server-%s.sock", socketpath,
					rbytes);
			sprintf(clientsock, "%s-client-%s.sock", socketpath,
					rbytes);
			sprintf(linkage, "%s:%s", serversock, clientsock);

			pid_t conn_pid = fork();
			if (conn_pid == -1) {
				wp_log(WP_ERROR, "Fork failure");
				return EXIT_FAILURE;
			} else if (conn_pid == 0) {
				int dstidx = locate_openssh_cmd_hostname(
						argc, argv);
				if (dstidx < 0) {
					fprintf(stderr, "Failed to locate destination in ssh command string\n");
					return EXIT_FAILURE;
				}

				int nextra = 10 + debug + oneshot;
				char **arglist = calloc(
						argc + nextra, sizeof(char *));

				int offset = 0;
				arglist[offset++] = "/usr/bin/ssh";
				/* Force tty allocation. The user-override is a
				 * -T flag. Unfortunately, -t disables newline
				 * translation on the local side; see
				 * `wp_log_handler`.
				 */
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
				arglist[dstidx + 1 + offset++] = "-u";
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
				return run_client(clientsock, oneshot, nogpu,
						conn_pid);
			}
		} else {
			if (!socketpath) {
				socketpath = "/tmp/waypipe-client.sock";
			}
			return run_client(socketpath, oneshot, nogpu, 0);
		}
	} else {
		char *const *app_argv = (char *const *)argv;
		const char *application = app_argv[0];
		char shell[256];
		char shellname[256];
		char *shellcmd[2] = {shellname, NULL};
		if (argc == 0) {
			setup_login_shell_command(shell, shellname);
			application = shell;
			app_argv = shellcmd;
		}
		if (!socketpath) {
			socketpath = "/tmp/waypipe-server.sock";
		}
		return run_server(socketpath, oneshot, unlink_at_end,
				application, app_argv);
	}
}
