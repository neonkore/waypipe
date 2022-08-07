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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

#if defined(__linux__)
#define HAS_O_PATH 1
#endif

int create_anon_file(void)
{
	int new_fileno;
#ifdef HAS_MEMFD
	new_fileno = memfd_create("waypipe", 0);
#elif defined(SHM_ANON)
	new_fileno = shm_open(SHM_ANON, O_RDWR, 0600);
#else
	// Fallback code. Should not be used from multiple threads
	static int counter = 0;
	int pid = getpid();
	counter++;
	char tmp_name[64];
	sprintf(tmp_name, "/waypipe%d-data_%d", pid, counter);
	new_fileno = shm_open(tmp_name, O_EXCL | O_RDWR | O_CREAT, 0644);
	if (new_fileno == -1) {
		return -1;
	}
	(void)shm_unlink(tmp_name);
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

static void *align_ptr(void *ptr, size_t alignment)
{
	return (uint8_t *)ptr + ((alignment - (uintptr_t)ptr) % alignment);
}
void *zeroed_aligned_alloc(size_t bytes, size_t alignment, void **handle)
{
	if (*handle) {
		/* require a clean handle */
		return NULL;
	}
	*handle = calloc(bytes + alignment - 1, 1);
	return align_ptr(*handle, alignment);
}
void *zeroed_aligned_realloc(size_t old_size_bytes, size_t new_size_bytes,
		size_t alignment, void *data, void **handle)
{
	/* warning: this might copy a lot of data */
	if (new_size_bytes <= 2 * old_size_bytes) {
		void *old_handle = *handle;
		ptrdiff_t old_offset = (uint8_t *)data - (uint8_t *)old_handle;

		void *new_handle = realloc(
				old_handle, new_size_bytes + alignment - 1);
		if (!new_handle) {
			return NULL;
		}
		void *new_data = align_ptr(new_handle, alignment);
		ptrdiff_t new_offset =
				(uint8_t *)new_data - (uint8_t *)new_handle;
		if (old_offset != new_offset) {
			/* realloc broke alignment offset */
			memmove((uint8_t *)new_data + new_offset,
					(uint8_t *)new_data + old_offset,
					new_size_bytes > old_size_bytes
							? old_size_bytes
							: new_size_bytes);
		}
		if (new_size_bytes > old_size_bytes) {
			memset((uint8_t *)new_data + old_size_bytes, 0,
					new_size_bytes - old_size_bytes);
		}
		*handle = new_handle;
		return new_data;
	} else {
		void *new_handle = calloc(new_size_bytes + alignment - 1, 1);
		if (!new_handle) {
			return NULL;
		}
		void *new_data = align_ptr(new_handle, alignment);
		memcpy(new_data, data,
				new_size_bytes > old_size_bytes
						? old_size_bytes
						: new_size_bytes);
		free(*handle);
		*handle = new_handle;
		return new_data;
	}
}
void zeroed_aligned_free(void *data, void **handle)
{
	(void)data;
	free(*handle);
	*handle = NULL;
}

int open_folder(const char *name)
{
	const char *path = name[0] ? name : ".";
#ifdef HAS_O_PATH
	return open(path, O_PATH);
#else
	return open(path, O_RDONLY | O_DIRECTORY);
#endif
}
