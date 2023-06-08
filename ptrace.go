package main

/*
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>

int create_progress()
{
	pid_t pid;

	pid = fork();
	if (pid == 0) {
		while(1) {
			usleep(200);
		}
	}

	return (int)pid;
}

void send_signal_kill(pid_t pid)
{
	kill(pid, SIGKILL);
}
*/
import "C"

import (
	"fmt"
	"syscall"
)

func main() {
	var pid int
	var regs syscall.PtraceRegs

	pid = int(C.create_progress())
	if pid > 0 {
		fmt.Printf("pid: %d\n", pid)
		err := syscall.PtraceAttach(pid)
		if err != nil {
			fmt.Printf("attach err: %v\n", err)
		}

		defer C.send_signal_kill(C.int(pid))
		defer syscall.PtraceDetach(pid)

		var status syscall.WaitStatus
		for {
			wpid, err := syscall.Wait4(pid, &status, syscall.WALL, nil)
			if err != nil {
				panic(err)
			}
			fmt.Printf("wpid: %d\n", wpid)
			if wpid == pid {
				break
			}
		}

		err = syscall.PtraceGetRegs(pid, &regs)
		if err != nil {
			fmt.Printf("getregs err: %v\n", err)
		}

		fmt.Printf("regs: %v\n", regs)
	}
}
