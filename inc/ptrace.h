#ifndef _PTRACE_HEADER_H_
#define _PTRACE_HEADER_H_

#include <sys/ptrace.h>		// ptrace
#include <sys/wait.h>		// waitpid
#include <linux/ptrace.h>
#include <sys/user.h>		// struct user_regs_struct
#include <sys/uio.h>		// struct iovec for arm64
#include <errno.h>		// errno
#include <elf.h>		// NT_PRSTATUS
#include <string.h>		// strerror

#ifdef __x86_64__
#include <sys/reg.h>		// ORIG_RAX
#endif

#include <syscall.h>		// SYS_getpid
//#include "debug.h"		// PRINT

union u {
    long val;
    char str[8];
} input;

/**
 * Start the tracee syscall and wait until it traps back.
 * */
static inline int ptrace_syscall(pid_t pid)
{
        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1)
		return -1;
        if (waitpid(pid, 0, 0) == -1)
		return -2;
	return 0;
}

static inline int ptrace_syscall_status(pid_t pid, int *status)
{
	*status = 0;
	if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1)
		return -1;
	if (waitpid(pid, status, 0) == -1)
		return -2;
	return 0;
}

/**
 * Replace the x86 syscall with a SYS_getpid.
 * */
static inline int syscall_getpid(pid_t pid)
{
	int ret = 0;
#ifdef __x86_64__
	ret = ptrace(PTRACE_POKEUSER, pid, 8*ORIG_RAX, SYS_getpid);
#endif
	return ret;
}

/**
 * Replace the x86 syscall with a SYS_dup.
 * (Increase the descriptor table index, to replace accept4, etc.)
 * */
static inline int syscall_dup(pid_t pid)
{
	int ret = 0;
#ifdef __x86_64__
	ret = ptrace(PTRACE_POKEUSER, pid, 8*ORIG_RAX, SYS_dup);
#endif
	return ret;
}

/**
 * Update the syscall return value with retval.
 * */
static inline int update_retval(pid_t pid, int64_t retval)
{
	int ret = 0;
#ifdef __x86_64__
	ret = ptrace(PTRACE_POKEUSER, pid, 8*RAX, retval);
#endif
	return ret;
}

/**
 * Operations on get regs, retval, PC value.
 * */
long get_regs_args(pid_t pid, struct user_regs_struct *regs, int64_t args[]);
long long get_retval(pid_t pid, struct user_regs_struct *regs, int *term);
uint64_t get_pc(pid_t pid);

/**
 * Update or retrieve child memory data.
 * */
int update_child_data(pid_t pid, long long dst, char *src, size_t len);
int get_child_data(pid_t pid, char *dst, long long src, size_t len);


#endif
