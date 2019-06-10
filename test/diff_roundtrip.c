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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int buf_ndiff(size_t size, const char *left, const char *right,
		const char *leftname, const char *rightname)
{
	if (!memcmp(left, right, size)) {
		return 0;
	}

	int nchanged = 0;
	for (size_t i = 0; i < size; i++) {
		nchanged += (left[i] != right[i]);
		if (left[i] != right[i]) {
			fprintf(stderr, "Disagreement at i=%d, %s=%02x, %s=%02x\n",
					(int)i, leftname,
					(uint32_t)(uint8_t)left[i], rightname,
					(uint32_t)(uint8_t)right[i]);
		}
	}

	return nchanged;
}

static int ideal_round(
		size_t bufsize, char *base, const char *changed, char *other)
{
	char *diff = calloc(bufsize + 8, 1);
	size_t diffsize = 0;
	construct_diff(bufsize, 0, bufsize, base, changed, &diffsize, diff);
	apply_diff(bufsize, other, diffsize, diff);
	free(diff);
	int nch = 0;
	if ((nch = buf_ndiff(bufsize, changed, base, "changed", "base"))) {
		fprintf(stderr, "Diff failed, base and changed disagree, at %d bytes\n",
				nch);
		return EXIT_FAILURE;
	}
	if ((nch = buf_ndiff(bufsize, changed, other, "changed", "other"))) {
		fprintf(stderr, "Diff failed, other and changed disagree, at %d bytes\n",
				nch);
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
	(void)argc;
	(void)argv;

	bool all_success = true;
	size_t bufsize = 333333;

	char *changed = calloc(bufsize, 1);
	for (size_t i = 0; i < bufsize; i++) {
		changed[i] = (i * 251) % 256;
	}
	memset(changed + bufsize / 5, 0, bufsize / 7);

	char *zerobase = calloc(bufsize, 1);
	char *zeroclone = calloc(bufsize, 1);

	all_success &= ideal_round(bufsize, zerobase, changed, zeroclone) ==
		       EXIT_SUCCESS;

	free(zerobase);
	free(zeroclone);
	free(changed);

	return all_success ? EXIT_SUCCESS : EXIT_FAILURE;
}
