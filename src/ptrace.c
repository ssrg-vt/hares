#include "ptrace.h"
#include "log.h"

/**
 * Get syscall arguments from user_regs_struct
 * Arch-dependent part
 * */
#ifdef __x86_64__
/**
 * x86_64 useds rsi, rdi, rdx, r10, r8, r9 for syscall params,
 *       rax for syscall num, and rax for the retval.
 * See "man 2 syscall"
 * */
static inline int x86_get_sc_args(struct user_regs_struct regs,
				  int64_t args[])
{
    args[0] = regs.rdi;  args[1] = regs.rsi;  args[2] = regs.rdx;
    args[3] = regs.r10;  args[4] = regs.r8;   args[5] = regs.r9;
    return regs.orig_rax;
}
#endif
#ifdef __aarch64__
/**
 * arm64 uses x0 - x5 for the syscall params,
 *     x8 for the syscall num, and x0 for the retval.
 * See "man 2 syscall"
 * */
static inline int arm64_get_sc_args(struct user_regs_struct regs,
				    int64_t args[])
{
    args[0] = regs.regs[0];  args[1] = regs.regs[1];  args[2] = regs.regs[2];
    args[3] = regs.regs[3];  args[4] = regs.regs[4];  args[5] = regs.regs[5];
    return regs.regs[8];
}
#endif

/**
 * Get the current register value from user_regs_struct, parse the register
 * value into a 6 element syscall param array.
 * */
long get_regs_args(pid_t pid, struct user_regs_struct *regs, int64_t args[])
{
	long syscall_num;
	if (ptrace(PTRACE_GETREGS, pid, 0, regs) == -1)
		log_error("PTRACE_GETREGS %s", strerror(errno));
        syscall_num = x86_get_sc_args(*regs, args);
	return syscall_num;
}

/**
 * Get the register value again on syscall exits. Return the syscall retval.
 * */
long long get_retval(pid_t pid, struct user_regs_struct *regs, int *term)
{
	if (ptrace(PTRACE_GETREGS, pid, 0, regs) == -1) {
		fputs(" = ?\n", stderr);
		if (errno == ESRCH) {	// No such process
			if (term != NULL) *term = 1;
			log_info("%s: rdi: %lld.\n", strerror(errno), regs->rdi);
			return 0;
		}
		log_error("%s", strerror(errno));
	}
	return regs->rax;
}

uint64_t get_pc(pid_t pid)
{
	struct user_regs_struct regs;
	int64_t pc64;
#ifdef __x86_64__
	if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
		log_error("PTRACE_GETREGS %s", strerror(errno));
	pc64 = regs.rip;
#endif
#ifdef __aarch64__
	struct iovec iov;
	iov.iov_base = &regs;
	iov.iov_len = sizeof(regs);
        if (ptrace(PTRACE_GETREGSET, pid, 1, &iov) == -1)
		log_error("ptrace_getregset error %s.", strerror(errno));
	pc64 = regs.pc;
#endif
	return pc64;
}


// ================ Methods to get/modify child memory space ================
/**
 * Copy data from parent address space (src, len) to child process (pid, dst).
 * Use PTRACE_POKEDATA to modify child memory.
 * input is a union of 8 bytes.
 * */
int update_child_data(pid_t pid, long long dst, char *src, size_t len)
{
	long ret;
	size_t cnt = len / sizeof(long long);
	size_t i;

	memset(&input, 0, sizeof(input));
	if (cnt*sizeof(long long) < len) cnt++;	// verify whether need cnt+1
	for (i = 0; i < cnt; i++) {
		memcpy(input.str, src+i*8, 8);
		ret = ptrace(PTRACE_POKEDATA, pid, dst+i*8, input.val);
		if (ret) log_error("%s error", __func__);
	}

	return 0;
}

/**
 * Copy data from child memory space (pid, src, len) to parent space (dst).
 * With PTRACE_GETREGS, we can only get the child syscall param value, not the
 * real memory content. To get child memory content, we have to use
 * PTRACE_PEEKDATA and retrieve memory in 8 bytes granularity.
 * @dst: monitor buf address.
 * @src: child (tracee) memory start address.
 * @len: the length of the memory to read.
 * */
int get_child_data(pid_t pid, char *dst, long long src, size_t len)
{
	size_t cnt = len / sizeof(long long);
	size_t i;
	memset(&input, 0, sizeof(input));

	if (cnt*8 < len) cnt++;	// if cnt%8 != 0, we need cnt++
	for (i = 0; i < cnt; i++) {
		input.val = ptrace(PTRACE_PEEKDATA, pid, src+8*i, 0);
		memcpy(dst+8*i, input.str, 8);
	}
	dst[len] = 0;
	return 0;
}

/**
 * Get child param string from a child space pointer (pid, src).
 * */
int get_child_data_str(pid_t pid, char *dst, long long src)
{
/*	size_t i;
	for (i = 0; i < 100; i++) {
		input.val = ptrace(PTRACE_PEEKDATA, pid, src+8*i, 0);
		memcpy(dst+8*i, input.str, 8);
	}*/

	return 0;
}
