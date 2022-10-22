#define _GNU_SOURCE 

#include <stdio.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#define FILE_FLAGS  (O_CREAT | O_RDWR | O_TRUNC)
#define FILE_MODE   (0775)

#define FILE_SIZE_1  (0x100000)
#define FILE_SIZE_2  (0x200000)

#define MMAP_PROT    (PROT_READ  | PROT_WRITE)
#define MMAP_FLAGS   (MAP_SHARED | MAP_FILE)

#define WRITE_DATA  (0xab)

typedef struct outbuf {
	char *name;
	unsigned char *buf;
	uint64_t len;
	int fd;
} outbuf_t;

static int _g_mmap_(outbuf_t *out, uint64_t filesize);
static void _g_munmap_(outbuf_t *out);
static int _g_open_(outbuf_t *out, char *name);
static void _g_close_(outbuf_t *out);

static int _g_open_(outbuf_t *out, char *name)
{
	int ret;

	ret = open(name, FILE_FLAGS, FILE_MODE);
	if (ret < 0) {
		printf("Open %s failed: %d\n", name, errno);
		exit(EXIT_FAILURE);
	}

	out->fd = ret;

	return 0;
}

static void _g_close_(outbuf_t *out)
{
	if (out->len != 0) {
		_g_munmap_(out);
	}

	close(out->fd);
	out->fd = -1;
}

static void _g_munmap_(outbuf_t *out)
{
	if (out->buf != NULL) {
		munmap(out->buf, out->len);
		out->buf = NULL;
		out->len = 0;
	}
}

static int _g_mmap_(outbuf_t *out, uint64_t filesize)
{
	int ret;
	void *addr;

	if (out->len != 0) {
		_g_munmap_(out);
	}

	for (;;) {
#if 0
		ret = syscall(__NR_fallocate, out->fd, 0,0, filesize);
#else
		ret = fallocate(out->fd, 0, 0, filesize);
#endif
		if (ret == 0) {
			break;
		} else if (errno != EINTR) {
			break;
		}
	}

	if (ret != 0) {
		printf("fallocate failed: %d\n", errno);
		exit(EXIT_FAILURE);
	}

	ret = ftruncate(out->fd, filesize);
	if (ret == -1) {
		printf("ftruncate failed: %d\n", errno);
		exit(EXIT_FAILURE);
	}

	addr = mmap(NULL, filesize, MMAP_PROT, MMAP_FLAGS, out->fd, 0);
	if (addr == (void *)(-1)) {
		printf("mmap failed: %d\n", errno);
		exit(EXIT_FAILURE);
	}

	out->buf = addr;
	out->len = filesize;

	return 0;
}

static void _g_write_(outbuf_t *out, uint64_t offset, uint64_t len)
{
	if ((out->buf == NULL) || (out->len == 0)) {
		return;
	}

	memset((void *)((uint64_t)(out->buf) + offset), WRITE_DATA, len);
}

static int _g_check_(outbuf_t *out, uint64_t offset)
{
	unsigned int i;
	unsigned char d;
	int ret = 0;

	if ((out->buf == NULL) || (out->len == 0)) {
		return 0;
	}

	for (i = 0; i < 32; i++) {
		d = *(out->buf + i);
		if (d != WRITE_DATA) {
			ret = -1;
			break;
		}
	}

	return ret;
}

int main(int argc, char **argv)
{
	outbuf_t outbuf;
	int ret;
	char name[128];
	long long s, loop = 10;

	if (argc == 1) {
		loop = 1;
	} else if (argc == 2) {
		loop = atoll((const char *)(argv[1]));
	} else {
		printf("invalid input args.\n");
		return 0;
	}

	for (s = 0; s < loop; s++) {
		srandom(time(NULL));
		sprintf(name, "/tmp/_g_mmap_%ld_%ld", random(), s);

		outbuf.buf = NULL;
		outbuf.len = 0;
		outbuf.fd = -1;

		printf("test: %ld, %s\n", s,  name);

		ret = _g_open_(&outbuf, name);
		if (ret < 0) {
			exit(EXIT_FAILURE);
		}

		ret = _g_mmap_(&outbuf, FILE_SIZE_1);
		if (ret < 0) {
			_g_close_(&outbuf);
			remove((const char *)name);
			exit(EXIT_FAILURE);
		}

		_g_write_(&outbuf, 0, FILE_SIZE_1);

		ret = _g_mmap_(&outbuf, FILE_SIZE_2);
		if (ret < 0) {
			_g_close_(&outbuf);
			remove((const char *)name);
			exit(EXIT_FAILURE);
		}

		ret =  _g_check_(&outbuf, 0);
		if (ret < 0) {
			printf("check error............\n");
			exit(EXIT_FAILURE);
		}

		_g_munmap_(&outbuf);
		_g_close_(&outbuf);

		remove((const char *)name);
	}

	return 0;
}
