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
#include <signal.h>
#include <sys/wait.h>

#define FILE_FLAGS  (O_CREAT | O_RDWR | O_TRUNC)
#define FILE_MODE   (0775)

#define FILE_SIZE_1  (0x123460)
#define FILE_SIZE_2  (0x233459)

#define MMAP_PROT    (PROT_READ  | PROT_WRITE)
#define MMAP_FLAGS   (MAP_SHARED | MAP_FILE)

#define WRITE_DATA  (0xab)

#define BASE_NAME "/tmp/_g_mmap"

typedef struct outbuf {
	char *name;
	unsigned char *buf;
	uint64_t len;
	int fd;
	int eintr_count;
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
		return -1;
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

	out->eintr_count = 0;
	for (;;) {
#if 0
		ret = syscall(__NR_fallocate, out->fd, 0,0, filesize);
#else
		ret = fallocate(out->fd, 0, 0, filesize);
#endif
		if (ret == 0) {
			break;
		}

		if (errno == EINTR) {
			out->eintr_count++;
			continue;
		}
	}

	if (ret != 0) {
		printf("fallocate failed: %d\n", errno);
		return -1;
	}

	ret = ftruncate(out->fd, filesize);
	if (ret == -1) {
		printf("ftruncate failed: %d\n", errno);
		return -1;
	}

	addr = mmap(NULL, filesize, MMAP_PROT, MMAP_FLAGS, out->fd, 0);
	if (addr == (void *)(-1)) {
		printf("mmap failed: %d\n", errno);
		return -1;
	}

	out->buf = addr;
	out->len = filesize;

	return 0;
}

static void _g_write_(outbuf_t *out, uint64_t len)
{
	if ((out->buf == NULL) || (out->len == 0)) {
		return;
	}

	memset((void *)(out->buf), WRITE_DATA, len);
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

int run(long long loop)
{
	outbuf_t outbuf;
	int ret;
	char name[128];
	long long s;

	for (s = 0; s < loop; s++) {
		srandom(time(NULL));
		sprintf(name, BASE_NAME, "_%ld_%ld", random(), s);

		outbuf.buf = NULL;
		outbuf.len = 0;
		outbuf.fd = -1;

		/* printf("test: %ld, %s\n", s,  name); */

		ret = _g_open_(&outbuf, name);
		if (ret < 0) {
			return -1;
		}

		ret = _g_mmap_(&outbuf, FILE_SIZE_1);
		if (ret < 0) {
			_g_close_(&outbuf);
			remove((const char *)name);
			return -1;
		}

		_g_write_(&outbuf, FILE_SIZE_1);

		ret = _g_mmap_(&outbuf, FILE_SIZE_2);
		if (ret < 0) {
			_g_close_(&outbuf);
			remove((const char *)name);
			return -1;
		}

		ret =  _g_check_(&outbuf, 0);
		if (ret < 0) {
			printf("check file %s error, please hexdump it, eintr %d.\n", name, outbuf.eintr_count);
			return -1;
		}

		_g_munmap_(&outbuf);
		_g_close_(&outbuf);

		remove((const char *)name);
	}

	return 0;
}

void send_signal()
{
	pid_t ppid;

	ppid = getppid();
	while(1) {
		usleep(100);
		kill(ppid, SIGUSR1);

		usleep(125);
		kill(ppid, SIGUSR2);
	}
}

void sig_handle(int signum)
{
	static int i = 0, j = 0, k = 0;

	switch(signum) {
	case SIGUSR1:
		i = i + 1;
		break;
	case SIGUSR2:
		j = j + 1;
		break;
	default:
		k = k + 1;
		break;
	}

	i = k + 1;
	j = i + 1;
	k = j + 1;
}

int main(int argc, char **argv)
{
	long long loop = 10;
	pid_t pid;
	int ret, wstatus;

	if (argc == 1) {
		loop = 2000;
	} else if (argc == 2) {
		loop = atoll((const char *)(argv[1]));
	} else {
		printf("invalid input args.\n");
		return 0;
	}

	signal(SIGUSR1, sig_handle);
	signal(SIGUSR2, sig_handle);

	pid = fork();
	if (pid == 0) {
		/* child */
		send_signal();
	} else {
		ret = run(loop);
		kill(pid, SIGKILL);
		waitpid(pid, &wstatus, 0);
		if (ret < 0) {
			return -1;
		}
	}

	return 0;
}
