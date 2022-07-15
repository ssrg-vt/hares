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


#define PARASITE_CMD_GET_STDIN_FD         PARASITE_USER_CMDS
#define PARASITE_CMD_GET_STDOUT_FD        PARASITE_USER_CMDS + 1
#define PARASITE_CMD_GET_STDERR_FD        PARASITE_USER_CMDS + 2
#define PARASITE_CMD_GET_STDUFLT_FD       PARASITE_USER_CMDS + 3
#define PARASITE_CMD_SET_MADVISE_NO_NEED  PARASITE_USER_CMDS + 4

#define PAGE_SIZE 4096

static int set_madvise(void *addr, size_t len, int advice_type)
{
  int ret;
  ret = sys_madvise(addr, len, advice_type);
  if (ret) {
    return ret;
  }
  return 0;
}

static int send_uffd(uint64_t desired_addr, uint16_t no_of_pages){
    int page_size;
    u_int64_t noPages;
    u_int64_t memorySize;
    char* addr;
    long ufFd = -1;

    //userfaultfd stuffs
    struct uffdio_api ufFd_api;
    struct uffdio_register ufFd_register;
  
    page_size = PAGE_SIZE;
    noPages = no_of_pages;
    memorySize = noPages * page_size;

    ufFd = sys_userfaultfd(O_CLOEXEC| O_NONBLOCK);
    if(ufFd == -1){
	    return -1;
    }

    //UFFDIO_API ioctl
    ufFd_api.api = UFFD_API;
    ufFd_api.features = 0;
    if(sys_ioctl(ufFd, UFFDIO_API, &ufFd_api) == -1){
	    return -1;
    }
    
    addr = sys_mmap(desired_addr, memorySize, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0);
    if(addr == MAP_FAILED){
            return -1;
    }

    ufFd_register.range.start = (unsigned long long)addr;
    ufFd_register.range.len   = memorySize;
    ufFd_register.mode = UFFDIO_REGISTER_MODE_MISSING | UFFDIO_REGISTER_MODE_WP;
    if(sys_ioctl(ufFd, UFFDIO_REGISTER, &ufFd_register) == -1){
            return -1;
    }

    ufFd_register.range.start = (unsigned long long)addr;
    ufFd_register.range.len   = memorySize;
    ufFd_register.mode = UFFDIO_WRITEPROTECT_MODE_WP;
    if(sys_ioctl(ufFd, UFFDIO_WRITEPROTECT, &ufFd_register) == -1){
            return -1;
    }

    if(fds_send_fd(ufFd) < 0){
            return -1;
    }

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
  
        case PARASITE_CMD_SET_MADVISE_NO_NEED:
                return set_madvise((*(uint64_t *)args), PAGE_SIZE, MADV_DONTNEED);
                break;

	default:
		break;
	}

	return 0;
}	
