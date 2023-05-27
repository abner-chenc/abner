#define _GNU_SOURCE             /* See feature_test_macros(7) */

#include <stdio.h>
#include <ctype.h>
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#define handle_error_en(en, msg) \
	do { errno = en; perror(msg); exit(EXIT_FAILURE); } while (0)
#define handle_error(msg) \
	do { perror(msg); exit(EXIT_FAILURE); } while (0)

#define FILE_FLAGS  (O_CREAT | O_RDWR | O_TRUNC)
#define FILE_MODE   (0775)

#define FILE_SIZE_1  (0x223460)
#define FILE_SIZE_2  (0x333459)

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

struct thread_info {
	pthread_t thread_id;
	int thread_num;
	void *thread_handle;
	long long cmd_arg;
	int sig;
};

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

int run_fallocate(long long loop)
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

static void thread_fallocate(void *arg)
{
	struct thread_info *tinfo = arg;
	pid_t pid, tid;

	pid = getpid();
	tid = pthread_self();

	printf("thread#%d: pid=%u, tid = %u\n", tinfo->thread_num, pid, tid);

	do {
		run_fallocate(tinfo->cmd_arg);
	} while (0);
}

static void thread_send_exit(int signum)
{
	switch(signum) {
	case SIGQUIT:
		pthread_exit(NULL);
		break;
	default:
		break;
	}
}

static void thread_send_signal(void *arg)
{
	struct thread_info *tinfo = arg;
	pid_t pid, tid;

	pid = getpid();
	tid = pthread_self();

	signal(tinfo->sig, thread_send_exit);

	printf("thread#%d: pid=%u, tid = %u\n", tinfo->thread_num, pid, tid);

	do {
		usleep(100);
		kill(pid, SIGUSR1);

		usleep(125);
		kill(pid, SIGUSR2);
	} while (1);
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

struct thread_info tinfo[] = {
	{0, 0, thread_fallocate,   0,       0},
	{0, 0, thread_send_signal, 0, SIGQUIT},
};

int main(int argc, char *argv[])
{
	long long loop = 0;
	pthread_attr_t attr;
	int s, tnum, num_threads;

	if (argc == 1) {
		loop = 5000;
	} else if (argc == 2) {
		loop = atoll((const char *)(argv[1]));
	} else {
		printf("invalid input args.\n");
		return 0;
	}

	signal(SIGUSR1, sig_handle);
	signal(SIGUSR2, sig_handle);

	num_threads = sizeof(tinfo)/sizeof(struct thread_info);
	s = pthread_attr_init(&attr);
	if (s != 0)
		handle_error_en(s, "pthread_attr_init");

	for (tnum = 0; tnum < num_threads; tnum++) {
		tinfo[tnum].thread_num = tnum;
		tinfo[tnum].cmd_arg = loop;
		s = pthread_create(&tinfo[tnum].thread_id, &attr, tinfo[tnum].thread_handle, &tinfo[tnum]);
		if (s != 0)
			handle_error_en(s, "pthread_create");
	}

	s = pthread_attr_destroy(&attr);
	if (s != 0)
		handle_error_en(s, "pthread_attr_destroy");

	for (tnum = 0; tnum < num_threads; tnum++) {
		if (tinfo[tnum].sig != 0) {
			s = pthread_kill(tinfo[tnum].thread_id, tinfo[tnum].sig);
			if (s != 0)
				handle_error_en(s, "pthread_kill");
		}

		s = pthread_join(tinfo[tnum].thread_id, NULL);
		if (s != 0)
			handle_error_en(s, "pthread_join");
		printf("Joined with thread %d\n", tinfo[tnum].thread_num);
	}

	exit(EXIT_SUCCESS);
}
