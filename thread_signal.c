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
#include <time.h>
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
};

void signal_handler(int signum, siginfo_t *siginfo, void *uctx)
{
	static int i = 0, j = 0, k = 0;

	switch(signum) {
	case SIGUSR1:
	case SIGUSR2:
	case SIGFPE:
	case SIGHUP:
	case SIGALRM:
	case SIGCHLD:
		i = i + 1;
		break;

	case SIGQUIT:
		pthread_exit(NULL);
		break;
	default:
		j = j + 1;
		break;
	}

	k = j + i;
}

static void thread_sigusr1(void *arg)
{
	struct thread_info *tinfo = arg;
	pid_t pid, tid;

	pid = getpid();
	tid = pthread_self();
	printf("#%s: pid=%u, tid = %u\n", __func__, pid, tid);

	do {
		usleep(50);
		pthread_kill(tinfo->thread_id, SIGUSR1);
	} while (1);
}

static void thread_sigusr2(void *arg)
{
	struct thread_info *tinfo = arg;
	pid_t pid, tid;

	pid = getpid();
	tid = pthread_self();
	printf("#%s: pid=%u, tid = %u\n", __func__, pid, tid);

	do {
		usleep(50);
		pthread_kill(tinfo->thread_id, SIGUSR2);
	} while (1);
}

static void thread_sigfpe(void *arg)
{
	struct thread_info *tinfo = arg;
	pid_t pid, tid;

	pid = getpid();
	tid = pthread_self();
	printf("#%s: pid=%u, tid = %u\n", __func__, pid, tid);

	do {
		usleep(50);
		pthread_kill(tinfo->thread_id, SIGFPE);
	} while (1);
}

static void thread_sighup(void *arg)
{
	struct thread_info *tinfo = arg;
	pid_t pid, tid;

	pid = getpid();
	tid = pthread_self();
	printf("#%s: pid=%u, tid = %u\n", __func__, pid, tid);

	do {
		usleep(50);
		pthread_kill(tinfo->thread_id, SIGHUP);
	} while (1);
}

static void thread_sigalrm(void *arg)
{
	struct thread_info *tinfo = arg;
	pid_t pid, tid;

	pid = getpid();
	tid = pthread_self();
	printf("#%s: pid=%u, tid = %u\n", __func__, pid, tid);

	do {
		usleep(50);
		pthread_kill(tinfo->thread_id, SIGALRM);
	} while (1);
}

static void thread_sigchld(void *arg)
{
	struct thread_info *tinfo = arg;
	pid_t pid, tid;

	pid = getpid();
	tid = pthread_self();
	printf("#%s: pid=%u, tid = %u\n", __func__, pid, tid);

	do {
		usleep(50);
		pthread_kill(tinfo->thread_id, SIGCHLD);
	} while (1);
}

struct thread_info tinfo[] = {
	{0, 0, thread_sigusr1},
	{0, 0, thread_sigusr2},
	{0, 0, thread_sigfpe},
	{0, 0, thread_sighup},
	{0, 0, thread_sigalrm},
	{0, 0, thread_sigchld},
};

int main(int argc, char *argv[])
{
	struct sigaction curact= {0};
	pthread_attr_t attr;
	int s, tnum, num_threads;
	time_t start_time, cur_time;
	long long elapsed_sec, run_sec;

	if (argc == 1) {
		run_sec = 100;
	} else if (argc == 2) {
		run_sec = atoll((const char *)(argv[1]));
	} else {
		printf("invalid input args.\n");
		return 0;
	}

	curact.sa_sigaction = signal_handler;
	curact.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_RESTART;
	sigfillset(&(curact.sa_mask));

	s = sigaction(SIGUSR1, (const struct sigaction *)(&curact), NULL);
	if (s != 0)
		handle_error_en(s, "sgaction SIGUSR1");

	s = sigaction(SIGUSR2, (const struct sigaction *)(&curact), NULL);
	if (s != 0)
		handle_error_en(s, "sgaction SIGUSR2");

	s = sigaction(SIGFPE,  (const struct sigaction *)(&curact), NULL);
	if (s != 0)
		handle_error_en(s, "sgaction SIGGFPE");

	s = sigaction(SIGHUP,  (const struct sigaction *)(&curact), NULL);
	if (s != 0)
		handle_error_en(s, "sgaction SIGHUP");

	s = sigaction(SIGALRM, (const struct sigaction *)(&curact), NULL);
	if (s != 0)
		handle_error_en(s, "sgaction SIGALRM");

	s = sigaction(SIGCHLD, (const struct sigaction *)(&curact), NULL);
	if (s != 0)
		handle_error_en(s, "sgaction SIGCHLD");

	s = sigaction(SIGQUIT, (const struct sigaction *)(&curact), NULL);
	if (s != 0)
		handle_error_en(s, "sgaction SIGQUIT");

	num_threads = sizeof(tinfo)/sizeof(struct thread_info);
	start_time = time(NULL);
	s = pthread_attr_init(&attr);
	if (s != 0)
		handle_error_en(s, "pthread_attr_init");

	for (tnum = 0; tnum < num_threads; tnum++) {
		tinfo[tnum].thread_num = tnum;
		s = pthread_create(&tinfo[tnum].thread_id, &attr, tinfo[tnum].thread_handle, &tinfo[tnum]);
		if (s != 0)
			handle_error_en(s, "pthread_create");
	}

	s = pthread_attr_destroy(&attr);
	if (s != 0)
		handle_error_en(s, "pthread_attr_destroy");

	do {
		sleep(5);
		cur_time = time(NULL);
		elapsed_sec = (long long)(difftime(cur_time, start_time));
		printf("## except: %lu secs, elapsed: %lu secs\n", run_sec, elapsed_sec);
		if (elapsed_sec >= run_sec) {
			break;
		}
	} while (1);

	for (tnum = 0; tnum < num_threads; tnum++) {
		s = pthread_kill(tinfo[tnum].thread_id, SIGQUIT);
		if (s != 0)
			handle_error_en(s, "pthread_kill");

		s = pthread_join(tinfo[tnum].thread_id, NULL);
		if (s != 0)
			handle_error_en(s, "pthread_join");
		printf("Joined with thread %d\n", tinfo[tnum].thread_num);
	}

	exit(EXIT_SUCCESS);
}
