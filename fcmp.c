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
#include <ucontext.h>
#include <math.h>
#include <complex.h>

#define handle_error_en(en, msg) \
	do { errno = en; perror(msg); exit(EXIT_FAILURE); } while (0)

#define handle_error(msg) \
	do { perror(msg); exit(EXIT_FAILURE); } while (0)

#define __CHECK_FPR__
#define __CHECK_FCC__
#define __CHECK_FCS__


#define MAX_RUN_CNT  9999999999
#define MAX_TASK     4

typedef struct loong64_fp_reg {
	uint64_t fpr[32];
	uint64_t fcc[8];
	uint64_t fcs;
} fpregs_t;

#define FCS_MASK 0x1f1f031f
#define __dbar__(level)  __asm__ __volatile__("dbar " #level);

#define __set_fp_reg__(num, val)                \
	__asm__ __volatile__(                   \
	"movgr2fr.d  " "$f"#num ", %0\n"        \
	:                                       \
	:"r"(val)                               \
	: "memory"                              \
	);                                      \


#define __get_fp_reg__(num, ret)                \
	__asm__ __volatile__(                   \
	"movfr2gr.d  " "%0," "$f"#num"\n"       \
	:"=&r" (ret)                            \
	:                                       \
	: "memory"                              \
	);                                      \


#define __set_fcc_reg__(num, val)               \
	__asm__ __volatile__(                   \
	"movgr2cf  " "$fcc"#num ", %0\n"        \
	:                                       \
	:"r" (val)                              \
	: "memory"                              \
	);                                      \


#define __get_fcc_reg__(num, ret)               \
	__asm__ __volatile__(                   \
	"movcf2gr  " "%0," "$fcc"#num"\n"       \
	:"=&r" (ret)                            \
	:                                       \
	: "memory"                             \
	);                                      \


#define __set_fcs_reg__(num, val)               \
	__asm__ __volatile__(                   \
	"movgr2fcsr  " "$r"#num ", %0\n"        \
	:                                       \
	:"r" (val)                              \
	: "memory"                             \
	);                                      \


#define __get_fcs_reg__(num, ret)               \
	__asm__ __volatile__(                   \
	"movfcsr2gr  " "%0, " "$r"#num"\n"      \
	:"=&r" (ret)                            \
	:                                       \
	: "memory"                             \
	);                                      \


static void set_fp_reg(fpregs_t *fpregs)
{
#ifdef __CHECK_FPR__
	__dbar__(0);
	__set_fp_reg__(0,  fpregs->fpr[0]);
	__set_fp_reg__(1,  fpregs->fpr[1]);
	__set_fp_reg__(2,  fpregs->fpr[2]);
	__set_fp_reg__(3,  fpregs->fpr[3]);
	__set_fp_reg__(4,  fpregs->fpr[4]);
	__set_fp_reg__(5,  fpregs->fpr[5]);
	__set_fp_reg__(6,  fpregs->fpr[6]);
	__set_fp_reg__(7,  fpregs->fpr[7]);
	__set_fp_reg__(8,  fpregs->fpr[8]);
	__set_fp_reg__(9,  fpregs->fpr[9]);
	__set_fp_reg__(10, fpregs->fpr[10]);
	__set_fp_reg__(11, fpregs->fpr[11]);
	__set_fp_reg__(12, fpregs->fpr[12]);
	__set_fp_reg__(13, fpregs->fpr[13]);
	__set_fp_reg__(14, fpregs->fpr[14]);
	__set_fp_reg__(15, fpregs->fpr[15]);
	__set_fp_reg__(16, fpregs->fpr[16]);
	__set_fp_reg__(17, fpregs->fpr[17]);
	__set_fp_reg__(18, fpregs->fpr[18]);
	__set_fp_reg__(19, fpregs->fpr[19]);
	__set_fp_reg__(20, fpregs->fpr[20]);
	__set_fp_reg__(21, fpregs->fpr[21]);
	__set_fp_reg__(22, fpregs->fpr[22]);
	__set_fp_reg__(23, fpregs->fpr[23]);
	__set_fp_reg__(24, fpregs->fpr[24]);
	__set_fp_reg__(25, fpregs->fpr[25]);
	__set_fp_reg__(26, fpregs->fpr[26]);
	__set_fp_reg__(27, fpregs->fpr[27]);
	__set_fp_reg__(28, fpregs->fpr[28]);
	__set_fp_reg__(29, fpregs->fpr[29]);
	__set_fp_reg__(30, fpregs->fpr[30]);
	__set_fp_reg__(31, fpregs->fpr[31]);
	__dbar__(0);
#endif

#ifdef __CHECK_FCC__
	__set_fcc_reg__(0, fpregs->fcc[0])
	__set_fcc_reg__(1, fpregs->fcc[1])
	__set_fcc_reg__(2, fpregs->fcc[2])
	__set_fcc_reg__(3, fpregs->fcc[3])
	__set_fcc_reg__(4, fpregs->fcc[4])
	__set_fcc_reg__(5, fpregs->fcc[5])
	__set_fcc_reg__(6, fpregs->fcc[6])
	__set_fcc_reg__(7, fpregs->fcc[7])
	__dbar__(0);
#endif

#ifdef __CHECK_FCS__
	__set_fcs_reg__(0, fpregs->fcs)
	__dbar__(0);
#endif
}

static void get_fp_reg(fpregs_t *fpregs)
{
#ifdef __CHECK_FPR__
	__dbar__(0);
	__get_fp_reg__(0,  fpregs->fpr[0]);
	__get_fp_reg__(1,  fpregs->fpr[1]);
	__get_fp_reg__(2,  fpregs->fpr[2]);
	__get_fp_reg__(3,  fpregs->fpr[3]);
	__get_fp_reg__(4,  fpregs->fpr[4]);
	__get_fp_reg__(5,  fpregs->fpr[5]);
	__get_fp_reg__(6,  fpregs->fpr[6]);
	__get_fp_reg__(7,  fpregs->fpr[7]);
	__get_fp_reg__(8,  fpregs->fpr[8]);
	__get_fp_reg__(9,  fpregs->fpr[9]);
	__get_fp_reg__(10, fpregs->fpr[10]);
	__get_fp_reg__(11, fpregs->fpr[11]);
	__get_fp_reg__(12, fpregs->fpr[12]);
	__get_fp_reg__(13, fpregs->fpr[13]);
	__get_fp_reg__(14, fpregs->fpr[14]);
	__get_fp_reg__(15, fpregs->fpr[15]);
	__get_fp_reg__(16, fpregs->fpr[16]);
	__get_fp_reg__(17, fpregs->fpr[17]);
	__get_fp_reg__(18, fpregs->fpr[18]);
	__get_fp_reg__(19, fpregs->fpr[19]);
	__get_fp_reg__(20, fpregs->fpr[20]);
	__get_fp_reg__(21, fpregs->fpr[21]);
	__get_fp_reg__(22, fpregs->fpr[22]);
	__get_fp_reg__(23, fpregs->fpr[23]);
	__get_fp_reg__(24, fpregs->fpr[24]);
	__get_fp_reg__(25, fpregs->fpr[25]);
	__get_fp_reg__(26, fpregs->fpr[26]);
	__get_fp_reg__(27, fpregs->fpr[27]);
	__get_fp_reg__(28, fpregs->fpr[28]);
	__get_fp_reg__(29, fpregs->fpr[29]);
	__get_fp_reg__(30, fpregs->fpr[30]);
	__get_fp_reg__(31, fpregs->fpr[31]);
	__dbar__(0);
#endif

#ifdef __CHECK_FCC__
	__get_fcc_reg__(0, fpregs->fcc[0]);
	__get_fcc_reg__(1, fpregs->fcc[1]);
	__get_fcc_reg__(2, fpregs->fcc[2]);
	__get_fcc_reg__(3, fpregs->fcc[3]);
	__get_fcc_reg__(4, fpregs->fcc[4]);
	__get_fcc_reg__(5, fpregs->fcc[5]);
	__get_fcc_reg__(6, fpregs->fcc[6]);
	__get_fcc_reg__(7, fpregs->fcc[7]);
	__dbar__(0);
#endif

#ifdef __CHECK_FCS__
	 __get_fcs_reg__(0, fpregs->fcs);
	 fpregs->fcs = fpregs->fcs & FCS_MASK;
	__dbar__(0);
#endif
}

static int check_fp_reg(fpregs_t *o_fpregs, fpregs_t *c_fpregs, pid_t cur_pid, uint64_t cur_cnt)
{
	int err = 0;

#ifdef __CHECK_FPR__
	for (int i = 0; i < 32; i++) {
		if (o_fpregs->fpr[i] != c_fpregs->fpr[i]) {
			printf("#Process-%lu: %lu: o_fpr[%d](0x%016x) != c_fpr[%d](0x%016x)\n", \
				cur_pid, cur_cnt, i, o_fpregs->fpr[i], i, c_fpregs->fpr[i]);
			err = 1;
		}
	}
#endif

#ifdef __CHECK_FCC__
	for (int i = 0; i < 8; i++) {
		if (o_fpregs->fcc[i] != c_fpregs->fcc[i]) {
			printf("#Process-%lu: %lu: o_fcc[%d](0x%0x) != c_fcc[%d](0x%0x)\n", \
				cur_pid, cur_cnt, i, o_fpregs->fcc[i], i, c_fpregs->fcc[i]);
			err = 1;
		}
	}
#endif

#ifdef __CHECK_FCS__
	if (o_fpregs->fcs != c_fpregs->fcs) {
		printf("#Process-%lu: %lu: o_fcs(0x%0x) != c_fcs(0x%0x)\n", \
				cur_pid, cur_cnt, o_fpregs->fcs, c_fpregs->fcs);
		err = 1;
	}
#endif

	return err;
}

static int copy_from_go_test()
{
	double complex a = 18.524326844631712+5.243569495096618*I;
	double complex b = 7.184979016894728+4.5467452848182965*I;
	double complex c = 0.868570705971341-0.49556526182577254*I;
	double complex d = -0.8685707059713409+0.4955652618257723*I;
	double complex m = 0;
	double complex n = 0;
	double complex p = 0;
	double complex q = 0;
	double e = 0;
	double f = 0;
	uint64_t i = 0;
	uint64_t fcsr0, fcsr1;
	uint64_t fcc0, fcc1;

	while (1) {
		__get_fcs_reg__(0, fcsr0);
		m = a + (c * b);
		n = a + (d * b);
		if ((p != m) || (q != n)) {
			printf("i = %d\n", i);
			printf("p = %.64f，q = %.64f\n", p, q);
			printf("m = %.64f, n = %.64f\n\n", m, n);
		}

		p = m;
		q = n;
		f = e;
		e++;

		__get_fcs_reg__(0, fcsr1);
		if ((f + 1.0) != e) {
			__get_fcc_reg__(0, fcc0);
			printf("e=%f, f=%f, f+1=%f, fcsr0=%x, fcsr1=%x, fcc0=%x\n", e, f, f+1, fcsr0, fcsr1, fcc0);
			//break;
		}

		if ((double)(i+1) != e) {
			 __get_fcc_reg__(0, fcc1);
			printf("i=%d, e=%f, i+1=%f, fcsr0=%x, fcsr1=%x, fcc1=%x\n", i, e, (double)(i+1), fcsr0, fcsr1, fcc1);
			//break;
		}

		i++;
	}

	return 1;
}

static void task_send_exit(int signum)
{
	switch(signum) {
	case SIGQUIT:
		exit(0);
		break;
	default:
		break;
	}
}

static void task_send_signal(pid_t to_pid)
{
	pid_t cur_pid;

        cur_pid = getpid();
	sleep(2);

        signal(SIGQUIT, task_send_exit);

	printf("#Process-%lu: start send signal SIGUSR1, SIGUSR2 to pid %lu\n", cur_pid, to_pid);

        do {
                kill(to_pid, SIGUSR1);
                usleep(5);
                kill(to_pid, SIGUSR2);
                usleep(5);
        } while (1);
}

static void sig_handle(int signum)
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

static void task_fp_check(void)
{
	fpregs_t o_fpregs;
	fpregs_t c_fpregs;
	uint64_t cur_cnt = 0;
	pid_t cur_pid;
	int err;

	signal(SIGUSR1, sig_handle);
	signal(SIGUSR2, sig_handle);

	cur_pid = getpid();

	printf("#Process-%lu: run_cnt = %lu, cur_cnt = %lu\n", cur_pid, MAX_RUN_CNT, cur_cnt);

#if 0
	err = copy_from_go_test();
	if (err) {
		exit(0);
	}
#endif

	for (int i = 0; i < 32; i++) {
		o_fpregs.fpr[i] = (uint64_t)cur_pid;
	}

	for (int i = 0; i < 8; i++) {
		o_fpregs.fcc[i] = ((uint64_t)cur_pid >> i) & 0x1;
	}

	o_fpregs.fcs = ((uint64_t)cur_pid + 0x1) & FCS_MASK;
	set_fp_reg(&o_fpregs);

	for (cur_cnt = 0; cur_cnt < MAX_RUN_CNT; cur_cnt++) {
		for (int i = 0; i < 32; i++) {
			c_fpregs.fpr[i] = 0;
		}

		for (int i = 0; i < 8; i++) {
			c_fpregs.fcc[i] = 0;
		}
		c_fpregs.fcs = 0;

		get_fp_reg(&c_fpregs);
		err = check_fp_reg(&o_fpregs, &c_fpregs, cur_pid, cur_cnt);
		if (err) {
			//break;
		}
	}
}

int main(int argc, char *argv[])
{
	pid_t pid;

	for (int i = 0; i < MAX_TASK; i++) {
		pid = fork();
		if (pid == 0) {
			printf("Child PID: %d, Parent PID: %d\n", getpid(), getppid());
			pid = fork();
			if (pid == 0) {
				task_fp_check();
			} else {
				task_send_signal(pid);
			}
			break;
		} else if (pid < 0) {
			perror("fork failed");
			break;
		}
	}

	if (pid > 0) {
		//task_send_signal(pid);
		while ((pid_t)wait(NULL) != -1) {
			sched_yield();
		}
	}

	return 0;
}
