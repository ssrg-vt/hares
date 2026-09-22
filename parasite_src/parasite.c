#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <pthread.h>
#include <errno.h>
#include <poll.h>
#include <string.h>
#include <linux/userfaultfd.h>  /* Definition of UFFD* constants */
#include <sys/ioctl.h>
#include <compel/infect-rpc.h>
#include <compel/plugins/plugin-fds.h>
#include <compel/plugins/std.h>

/*
 * userfaultfd write-protect (UFFD-WP) was added to the kernel UAPI in Linux 5.7.
 * The paper's SGX node ran a 5.15 kernel; provide a fallback so the parasite
 * also builds against older <linux/userfaultfd.h> (e.g. the Ubuntu 20.04 stock
 * 5.4 UAPI headers). The guard makes this inert on kernels that already define
 * these, so there is no conflict on newer systems.
 */
#ifndef UFFDIO_WRITEPROTECT
struct uffdio_writeprotect {
	struct uffdio_range range;
	__u64 mode;
};
#define UFFDIO_WRITEPROTECT_MODE_WP       ((__u64)1 << 0)
#define UFFDIO_WRITEPROTECT_MODE_DONTWAKE ((__u64)1 << 1)
#define _UFFDIO_WRITEPROTECT              (0x06)
#define UFFDIO_WRITEPROTECT \
	_IOWR(UFFDIO, _UFFDIO_WRITEPROTECT, struct uffdio_writeprotect)
#endif

#define PARASITE_CMD_GET_STDIN_FD         PARASITE_USER_CMDS
#define PARASITE_CMD_GET_STDOUT_FD        PARASITE_USER_CMDS + 1
#define PARASITE_CMD_GET_STDERR_FD        PARASITE_USER_CMDS + 2
#define PARASITE_CMD_GET_STDUFLT_FD       PARASITE_USER_CMDS + 3
#define PARASITE_CMD_SET_MADVISE_NO_NEED  PARASITE_USER_CMDS + 4
#define PARASITE_CORRECT_HEAP_OFFSET      PARASITE_USER_CMDS + 5
#define PARASITE_CMD_REM_STDUFLT_FD       PARASITE_USER_CMDS + 6
#define PARASITE_CMD_CREATE_MMAP          PARASITE_USER_CMDS + 7

#define PAGE_SIZE 4096
char *dummy_addr = NULL;

static int set_madvise(void *addr, size_t len, int advice_type)
{
  int ret;
  ret = sys_madvise(addr, len, advice_type);
  if (ret) {
    return ret;
  }
  return 0;
}

static int create_new_map(uint64_t desired_addr, uint64_t no_of_pages)
{
    int ret = 0;
    char *addr;
    int page_size;
    u_int64_t noPages;
    u_int64_t memorySize;

    page_size = PAGE_SIZE;
    noPages = no_of_pages;
    memorySize = noPages * page_size;

    addr = sys_mmap(desired_addr, memorySize, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE|MAP_FIXED, -1, 0);
    if(addr == MAP_FAILED){
           return -1;
    }

    return 0;
}

static int correct_heap_offset(uint64_t memory_size)
{
    int ret = 0;

    dummy_addr = sys_brk(memory_size);
    if(dummy_addr == MAP_FAILED){
        return -1;
    }

    return ret;
}

static int send_uffd(uint64_t desired_addr, uint16_t no_of_pages){
    int page_size;
    u_int64_t noPages;
    u_int64_t memorySize;
    char* addr;
    long ufFd = -1;
    int ret = 0;

    //userfaultfd stuffs
    struct uffdio_api ufFd_api;
    struct uffdio_register ufFd_register;
  
    page_size = PAGE_SIZE;
    noPages = no_of_pages;
    memorySize = noPages * page_size;

    ufFd = sys_userfaultfd(O_CLOEXEC| O_NONBLOCK);
    if(ufFd < 0){
	    return ufFd;
    }

    //UFFDIO_API ioctl
    ufFd_api.api = UFFD_API;
    ufFd_api.features = 0;
    if(ret = sys_ioctl(ufFd, UFFDIO_API, &ufFd_api)){
	    goto out_fail;
    }
    

    addr = desired_addr;
    ufFd_register.range.start = (unsigned long long)addr;
    ufFd_register.range.len   = memorySize;
    ufFd_register.mode = UFFDIO_REGISTER_MODE_WP;
    if(ret = sys_ioctl(ufFd, UFFDIO_REGISTER, &ufFd_register)){
        goto out_fail;
    }

    ufFd_register.range.start = (unsigned long long)addr;
    ufFd_register.range.len   = memorySize;
    ufFd_register.mode = UFFDIO_WRITEPROTECT_MODE_WP;
    if(ret = sys_ioctl(ufFd, UFFDIO_WRITEPROTECT, &ufFd_register)){
        goto out_fail;
    }

    if(ret = fds_send_fd(ufFd) < 0){
        goto out_fail;
    }

    if(ret = sys_close(ufFd))
        return ret;

    return ret;

out_fail:
    sys_close(ufFd);
    return ret;
}

static int unregister_uffd(long uffFd, uint64_t desired_addr, uint16_t no_of_pages){
    struct uffdio_register ufFd_register;
    char* addr;
    addr = desired_addr;
    int ret = 0;

    ufFd_register.range.start = (unsigned long long)addr;
    ufFd_register.range.len   = no_of_pages * PAGE_SIZE;

    int ufFd = fds_recv_fd();

    if(ret = sys_ioctl(ufFd, UFFDIO_UNREGISTER, &ufFd_register.range))
        return ret;

    if(ret = sys_close(ufFd))
        return ret;

    return 0;
}

/*
 * Stubs for std compel plugin.
 */
int compel_main(void *arg_p, unsigned int arg_s)
{
	return 0;
}
int parasite_trap_cmd(int cmd, void *args)
{
	return 0;
}
void parasite_cleanup(void)
{}

int parasite_daemon_cmd(int cmd, void *args)
{
    int page_size;
    uint64_t noPages;
    uint64_t memorySize;
    uint64_t addr, noOfPages;
    int uffd;
    int ret;
    
    //userfaultfd stuffs
    struct uffdio_api ufFd_api;
    struct uffdio_register ufFd_register;

	switch (cmd)
	{
	case PARASITE_CMD_GET_STDIN_FD:
		return (fds_send_fd(STDIN_FILENO) < 0);
		break;
	
	case PARASITE_CMD_GET_STDOUT_FD:
		return (fds_send_fd(STDOUT_FILENO) < 0);
		break;
	
	case PARASITE_CMD_GET_STDERR_FD:
		return (fds_send_fd(STDERR_FILENO) < 0);
		break;

	case PARASITE_CMD_GET_STDUFLT_FD:
        addr = *(uint64_t*)args;
        noOfPages = *(uint64_t*)(args + 8);
		return (send_uffd(addr, noOfPages));
		break;
    
    case PARASITE_CMD_REM_STDUFLT_FD:
        uffd = *(long*)(args);
        addr = *(uint64_t*)(args + 8);
        noOfPages = *(uint64_t*)(args + 16);
        return (unregister_uffd(uffd, addr, noOfPages));
        break;
  
    case PARASITE_CMD_SET_MADVISE_NO_NEED:
        return set_madvise((*(uint64_t *)args), PAGE_SIZE, MADV_DONTNEED);
        break;
        
    case PARASITE_CORRECT_HEAP_OFFSET:
        return correct_heap_offset(*(uint64_t *)args);
        break;
    
    case PARASITE_CMD_CREATE_MMAP:
        addr = *(uint64_t*)(args);
        noOfPages = *(uint64_t*)(args + 8);
        return create_new_map(addr, noOfPages);
        break;

	default:
		break;
	}

	return 0;
}	
