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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "config-waypipe.h"

#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(__linux__) && defined(__arm__)
#include <asm/hwcap.h>
#include <sys/auxv.h>
#elif defined(__FreeBSD__) && defined(__arm__)
#include <sys/auxv.h>
#endif

#if defined(__linux__)
/* memfd_create was introduced in glibc 2.27 */
#if !defined(__GLIBC__) || (__GLIBC__ >= 2 && __GLIBC_MINOR__ >= 27)
#define HAS_MEMFD 1
#endif
#endif

int create_anon_file(void)
{
	int new_fileno;
#ifdef HAS_MEMFD
	new_fileno = memfd_create("waypipe", 0);
#elif defined(SHM_ANON)
	new_fileno = shm_open(SHM_ANON, O_RDWR, 0600);
#else
	/* WARNING: this can be rather file-system
	 * intensive */
	char template[256] = "/tmp/waypipe_XXXXXX";
	new_fileno = mkstemp(template);
	unlink(template);
#endif
	return new_fileno;
}

int get_hardware_thread_count(void)
{
	return (int)sysconf(_SC_NPROCESSORS_ONLN);
}

int get_iov_max(void) { return (int)sysconf(_SC_IOV_MAX); }

#ifdef HAVE_NEON
bool neon_available(void)
{
	/* The actual methods are platform-dependent */
#if defined(__linux__) && defined(__arm__)
	return (getauxval(AT_HWCAP) & HWCAP_NEON) != 0;
#elif defined(__FreeBSD__) && defined(__arm__)
	unsigned long hwcap = 0;
	elf_aux_info(AT_HWCAP, &hwcap, sizeof(hwcap));
	return (hwcap & HWCAP_NEON) != 0;
#endif
	return true;
}
#endif
