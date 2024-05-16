#define _GNU_SOURCE             /* See feature_test_macros(7) */

#include <stdio.h>
#include <ctype.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#define handle_error_en(en, msg) \
	do { errno = en; perror(msg); exit(EXIT_FAILURE); } while (0)
#define handle_error(msg) \
	do { perror(msg); exit(EXIT_FAILURE); } while (0)


struct thread_info {
	pthread_t thread_id;
	int thread_num;
	void *thread_handle;
	long long run_cnt;
	const char *cmd_arg;
};

static void thread_exec(void *arg)
{
	struct thread_info *tinfo = arg;
	long long cnt;
	pid_t pid, tid;
	int ret;

	pid = getpid();
	tid = pthread_self();
	//printf("thread#%d: pid = %u, tid = %u, run_cnt = %lu\n", tinfo->thread_num, pid, tid, tinfo->run_cnt);
	for (cnt = 0; cnt < tinfo->run_cnt; cnt++) {

		printf("thread#%d: %lu\n", tinfo->thread_num, cnt);
		ret = execl(tinfo->cmd_arg, NULL);
		if (ret < 0) {
			printf("exec %s failed, ret %d\n", tinfo->cmd_arg, ret);
		}
	}
}

struct thread_info tinfo[] = {
	{0, 0, thread_exec, 0, "/bin/ls"},
	{0, 0, thread_exec, 0, "/bin/ls"},
};

int main(int argc, char *argv[])
{
	long long loop = 0;
	pthread_attr_t attr;
	int s, tnum, num_threads;

	if (argc == 1) {
		loop = 50000;
	} else if (argc == 2) {
		loop = atoll((const char *)(argv[1]));
	} else {
		printf("invalid input args.\n");
		return 0;
	}

	num_threads = sizeof(tinfo)/sizeof(struct thread_info);
	s = pthread_attr_init(&attr);
	if (s != 0)
		handle_error_en(s, "pthread_attr_init");

	for (tnum = 0; tnum < num_threads; tnum++) {
		tinfo[tnum].thread_num = tnum;
		tinfo[tnum].run_cnt = loop;
		s = pthread_create(&tinfo[tnum].thread_id, &attr, tinfo[tnum].thread_handle, &tinfo[tnum]);
		if (s != 0)
			handle_error_en(s, "pthread_create");
	}

	s = pthread_attr_destroy(&attr);
	if (s != 0)
		handle_error_en(s, "pthread_attr_destroy");

	for (tnum = 0; tnum < num_threads; tnum++) {
		s = pthread_join(tinfo[tnum].thread_id, NULL);
		if (s != 0)
			handle_error_en(s, "pthread_join");
		printf("Joined with thread %d\n", tinfo[tnum].thread_num);
	}

	exit(EXIT_SUCCESS);
}
