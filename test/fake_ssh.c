/*
 * Copyright © 2021 Manuel Stoeckl
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

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int usage(void)
{
	fprintf(stderr, "usage: fake_ssh [-R A:B] [-t] destination command...\n");
	return EXIT_FAILURE;
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		return usage();
	}
	argv++;
	argc--;

	bool pseudoterminal = false;
	char *link = NULL;
	char *destination = NULL;
	while (argc > 0) {
		if (strcmp(argv[0], "-t") == 0) {
			pseudoterminal = true;
			argv++;
			argc--;
		} else if (strcmp(argv[0], "-R") == 0) {
			link = argv[1];
			argv += 2;
			argc -= 2;
		} else {
			destination = argv[0];
			argv++;
			argc--;
			break;
		}
	}

	if (link) {
		char *p1 = link, *p2 = NULL;
		for (char *c = link; *c; c++) {
			if (*c == ':') {
				*c = '\0';
				p2 = c + 1;
				break;
			}
		}
		if (!p2) {
			fprintf(stderr, "Failed to split forwarding descriptor '%s'\n",
					p1);
			return EXIT_FAILURE;
		}
		unlink(p1);
		if (symlink(p2, p1) == -1) {
			fprintf(stderr, "Symlinking '%s' to '%s' failed\n", p2,
					p1);
			return EXIT_FAILURE;
		}
	}
	(void)destination;
	(void)pseudoterminal;

	if (execvp(argv[0], argv) == -1) {
		fprintf(stderr, "Failed to run program '%s'\n", argv[0]);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
