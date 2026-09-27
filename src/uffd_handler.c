#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <poll.h>
#include <sys/types.h>
#include <stdio.h>
#include <linux/userfaultfd.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/ptrace.h>

#include "../inc/ptrace.h"
#include "../inc/log.h"
#include "../inc/uffd_handler.h"
#include "../inc/compel_handler.h"
#include "../inc/uffd_wp_compat.h"

#define log_info(args...)

#define REMOTE_ATTEST 1

// Helloworld main function address
#ifdef HELLOWORLD
#define MAIN 0x43fd70
#elif FILEENCRYPT	
#define MAIN 0x40a790
#elif SWITCHLESS
#define MAIN 0x443d00
#elif DEBUGMALLOC
#define MAIN 0x43c0e0
#elif LOGCALLBACK
#define MAIN 0x43f0d0
#elif APKMAN
#define MAIN 0x43e980
#elif DATASEALING
#define MAIN 0x407b80
#elif PLUGGABLEALLOCATOR
#define MAIN 0x43e8b0
#elif MICROBENCH
#define MAIN 0x43e8b0
#elif VIRTUAL_ASSISTANT
#define MAIN 0x1d595
#elif TRUST_FL
#define MAIN 0x27b0
#elif REMOTE_ATTEST
#define MAIN 0x2eda
#endif


#define NO_NEW_PAGEFAULT            0xFF
#define NEW_PAGEFAULT_READ          0x00
#define NEW_PAGEFAULT_WRITE         UFFD_PAGEFAULT_FLAG_WRITE
#define PAGEFAULT_WRITE_PROTECTION  (UFFD_PAGEFAULT_FLAG_WRITE | UFFD_PAGEFAULT_FLAG_WP)

#define errExit(msg) do{ perror(msg); exit(EXIT_FAILURE);}while(0)

pid_t victimPid = -1;

 /**
  * @brief It handles the pagefaults that are caused by a write operation and
  *        make the page write unprotected and take a snapshot of the page in the next instruction,
  *        then makes the page write protected again.
  *
  * @param uffd
  * @param msg
  * @param victim_pid
  * @param page
  * @return int
  */
static int handle_wprotect_pagefaults(long uffd, struct uffd_msg msg, hares_child *tracee, int i)
{
	struct uffdio_writeprotect uffdio_wp;
	int ret = 0;

	uffdio_wp.range.start = msg.arg.pagefault.address;
	uffdio_wp.range.len = sysconf(_SC_PAGE_SIZE);
	uffdio_wp.mode = 0;
	if (ioctl(uffd, UFFDIO_WRITEPROTECT, &uffdio_wp) == -1){
		log_error("UFFDIO_WRITEPROTECT failed\n");
		goto fail_handle_wprotect_pagefaults;
	}

	return 0;

fail_handle_wprotect_pagefaults:
	return -1;
}


int disable_wprotect(long uffd, address_spaces *spaces, int i)
{
	struct uffdio_writeprotect uffdio_wp;
	int ret = 0;

	uffdio_wp.range.start = spaces->space[i].address;
	uffdio_wp.range.len = spaces->space[i].size * sysconf(_SC_PAGE_SIZE);
	uffdio_wp.mode = 0;
	
	if (ioctl(uffd, UFFDIO_WRITEPROTECT, &uffdio_wp) == -1){
		log_error("UFFDIO_WRITEPROTECT failed\n");
		goto fail_handle_wprotect_pagefaults;
	}

	return 0;

fail_handle_wprotect_pagefaults:
	return -1;
}

int enable_wprotect(long uffd, address_spaces *spaces, int i)
{
	struct uffdio_writeprotect uffdio_wp;
	int ret = 0;

	uffdio_wp.range.start = spaces->space[i].address;
	uffdio_wp.range.len = spaces->space[i].size * sysconf(_SC_PAGE_SIZE);
	uffdio_wp.mode = UFFDIO_WRITEPROTECT_MODE_WP;
	
	if (ioctl(uffd, UFFDIO_WRITEPROTECT, &uffdio_wp) == -1){
		log_error("UFFDIO_WRITEPROTECT failed\n");
		goto fail_handle_wprotect_pagefaults;
	}

	return 0;

fail_handle_wprotect_pagefaults:
	return -1;
}

/**
 * @brief Handles new read & write pagefaults
 *
 * @param uffd
 * @param msg
 * @param page
 * @param sk
 * @return uint8_t
 */
static uint8_t handle_rw_pagefault(long uffd, struct uffd_msg msg, char *page, msi_handler *msi, int sk)
{
	struct uffdio_copy uffdio_copy;
	uint8_t new_pagefault_type = NO_NEW_PAGEFAULT;

	//New pagefault due to read
	if(msg.event == UFFD_EVENT_PAGEFAULT &&
	  (msg.arg.pagefault.flags == NEW_PAGEFAULT_READ))
	{
		log_info("new read protection fault");
		memset(page, '0', PAGE_SIZE);
		new_pagefault_type = NEW_PAGEFAULT_READ;
	}

	//New pagefault due to write
	else if(msg.event == UFFD_EVENT_PAGEFAULT &&
		   (msg.arg.pagefault.flags == NEW_PAGEFAULT_WRITE))
	{
		log_info("new write protection fault");
		new_pagefault_type = NEW_PAGEFAULT_WRITE;
		memset(page, '0', PAGE_SIZE);
	}

	//Second write page fault
	else if(msg.event == UFFD_EVENT_PAGEFAULT &&
		   (msg.arg.pagefault.flags == PAGEFAULT_WRITE_PROTECTION))
	{
		log_info("old write protection fault");
		new_pagefault_type = PAGEFAULT_WRITE_PROTECTION;
	}

	if((new_pagefault_type == NEW_PAGEFAULT_READ) ||                                        \
	   (new_pagefault_type == NEW_PAGEFAULT_WRITE)){
		uffdio_copy.src = (unsigned long) page;
		uffdio_copy.dst = (unsigned long) msg.arg.pagefault.address &
			~(sysconf(_SC_PAGE_SIZE)- 1);
		uffdio_copy.len = sysconf(_SC_PAGE_SIZE);
		uffdio_copy.mode = UFFDIO_COPY_MODE_WP;
		uffdio_copy.copy = 0;
		if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1)
			errExit("ioctl-UFFDIO_COPY");
	}

	log_info("exiting handle_rw_pagefault");
	return new_pagefault_type;
}

/**
 * @brief Fault handler thread
 *
 * @param arg
 *
 * @return
 */
void *fault_handler_thread(void *arg)
{
	static struct uffd_msg msg;   /* Data read from userfaultfd */
	uffd_thread_args* handler_arg = (struct uffd_thread_args*)arg;
	hares_child *tracee = handler_arg->child;
	uffd_t *uffd;                    /* userfaultfd file descriptor */
	int no_uffd;
	char *page = NULL;
	struct uffdio_copy uffdio_copy;
	ssize_t nread;
	int ret = 0;

	address_spaces *faulting_spaces = handler_arg->faulting_spaces;
	empty_address_space(faulting_spaces);
	victimPid = tracee->c_pid;

	uffd = tracee->uffd;
	no_uffd = tracee->uffd_no;
	page = mmap(NULL, sysconf(_SC_PAGESIZE),                                                \
							  PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0);
	if(page == MAP_FAILED){
		errExit("Memory map failed");
	}

	struct pollfd *pollfd = malloc(sizeof(struct pollfd) * no_uffd);
	for (;;) {
		int nready;
		for(int i = 0; i < no_uffd; i++){
			pollfd[i].fd = uffd[i].fd;
			pollfd[i].events = POLLIN;
		}

		nready = poll(pollfd, no_uffd, -1);
		if (nready == -1){
			while(1);
			errExit("poll");
		}
			
		for(int i = 0; i < no_uffd; i++){

			if(pollfd[i].revents & POLLIN){

				log_info("polling id is %d", i);
				nread = read(uffd[i].fd, &msg, sizeof(msg));
				if (nread == 0) {
					log_error("EOF on userfaultfd!");
					exit(EXIT_FAILURE);
				}

				if (nread == -1)
					errExit("read");

				if (msg.event != UFFD_EVENT_PAGEFAULT) {
					log_error("Unexpected event on userfaultfd %d", msg.event);
					exit(EXIT_FAILURE);
				}

				log_debug("UFFD_EVENT_PAGEFAULT event: ");
				log_debug("flags = %llx; ", msg.arg.pagefault.flags);
				log_debug("address = %llx", msg.arg.pagefault.address);

				//Check if we need to handle new page-faults
				uint8_t pagefault_type = handle_rw_pagefault(uffd[i].fd,                   \
									     msg,                                              \
									     page,                                             \
									     handler_arg->msi,                                 \
									     handler_arg->sock_fd);
				if(pagefault_type == NEW_PAGEFAULT_READ || pagefault_type == NEW_PAGEFAULT_WRITE){
					log_info("New pagefault type is %d", pagefault_type);
					log_info("Handled new pagefault");
				}

				if(pagefault_type == NEW_PAGEFAULT_WRITE ||                                  \
				   pagefault_type == PAGEFAULT_WRITE_PROTECTION){

					//Filling up the faulting address
					log_info("Found a faulting address space %lx", msg.arg.pagefault.address);
					faulting_spaces->size += 1;
					faulting_spaces->space = realloc(faulting_spaces->space,                 \
									 sizeof(address_space) *                                 \
									 faulting_spaces->size);
					faulting_spaces->space[faulting_spaces->size - 1].address =              \
									 msg.arg.pagefault.address;
					faulting_spaces->space[faulting_spaces->size - 1].size = 1;              \
					faulting_spaces->space[faulting_spaces->size - 1].type =                 \
                                                                         tracee->uffd[i].type;
					faulting_spaces->nr_pages += 1;

					if(handle_wprotect_pagefaults(uffd[i].fd, msg, tracee, i)){
						log_error("Erros in handling write-protect pagefaults");
					}
				}
			}
		}
	}
}

int start_uffd_thread_handler(uffd_thread_handler *uffd_hdl){
	int rc = 0;

	if(uffd_hdl == NULL){
		log_error("uffd handle is NULL");
		goto out_fail;
	}

	rc = pthread_create(&uffd_hdl->thread, NULL,                                     \
						fault_handler_thread,                                        \
						(void*) &uffd_hdl->args);
	if (rc != 0) {
		log_error("Could not create a uffd handler thread");
		goto out_fail;
	}

out_fail:
	return rc;
}

int stop_uffd_thread_handler(uffd_thread_handler *uffd_hdl){
	int rc = 0;

	rc = pthread_cancel(uffd_hdl->thread);
	if(rc != 0){
		log_error("Could not stop the uffd handler thread");
		goto out_fail;
	}

out_fail:
	return rc;

}

int register_uffd(hares_child *child, address_spaces *spaces){
	int ret = 0;

	for(int i = 0; i < spaces->size; i++){
		child->uffd[i].fd = -1;
		child->uffd[i].address = 0x0;
		child->uffd[i].type = STACK;
	}

	int uffd_no = 0;
	for(int i = 0; i < spaces->size; i++){
#ifdef HELLOWORLD
		if(spaces->space[i].address != 0x7ffff7efa000 &&                                \
		   spaces->space[i].type != FILE_BACKED){
#elif FILEENCRYPT
		if(spaces->space[i].address != 0x7ffff72ee000 &&                                \
		   spaces->space[i].type != FILE_BACKED){
#elif SWITCHLESS
		if(spaces->space[i].address != 0x7ffff75b4000 &&                                \
		   spaces->space[i].type != FILE_BACKED){
#elif DEBUGMALLOC
		if(spaces->space[i].address != 0x7ffff7a9d000 &&                                \
		   spaces->space[i].type != FILE_BACKED){
#elif LOGCALLBACK
		if(spaces->space[i].address != 0x7ffff7a9e000 &&                                \
		   spaces->space[i].address != 0x7ffff7a9d000 &&								  \
		   spaces->space[i].type != FILE_BACKED){
#elif APKMAN
		if(spaces->space[i].address != 0x7ffff7a9d000 &&                                \
		   spaces->space[i].type != FILE_BACKED){
#elif DATASEALING
		if(spaces->space[i].address != 0x7ffff7a9d000 &&                                \
		   spaces->space[i].type != FILE_BACKED){
#elif PLUGGABLEALLOCATOR
		if(spaces->space[i].address != 0x7ffff7a9d000 &&                                \
		   spaces->space[i].type != FILE_BACKED){
#elif MICROBENCH
		if(spaces->space[i].address != 0x7ffff7a9d000 &&                                \
		   spaces->space[i].type != FILE_BACKED){
#elif VIRTUAL_ASSISTANT
		if(spaces->space[i].address != 0x7ffff7a9d000 &&                                \
		   spaces->space[i].type != FILE_BACKED){
#elif REMOTE_ATTEST
		if(spaces->space[i].address != 0x7ffff7a9d000 &&                                \
		   spaces->space[i].type != FILE_BACKED){
#endif
			// for(unsigned long j = 0; j < child->spaces.space[i].size; j++){
				child->uffd[i].address = spaces->space[i].address;
				child->uffd[i].type = spaces->space[i].type;
				log_info("Registering for the address 0x%lx", spaces->space[i].address);
				ret = compel_steal_uffd(child,                                                \
						        &child->uffd[i].fd,                                     \
							    spaces->space[i].address,         \
						        spaces->space[i].size);
				log_info("Registered uffd %d for the address 0x%lx", child->uffd[i].fd, \
						        spaces->space[i].address);
				//uffd_no++;
			// }
		}

	}
	
	return 0;
}

int deregister_uffd(hares_child *child, address_spaces *spaces){
	int ret = 0;
	int uffd_no = 0;
	for(int i = 0; i < spaces->size; i++){
#ifdef HELLOWORLD
		if((spaces->space[i].address != 0x7ffff7efa000) &&                              \
			(child->uffd[i].fd != -1) && (spaces->space[i].type != FILE_BACKED)){
#elif FILEENCRYPT
		if((spaces->space[i].address != 0x7ffff72ee000) &&                              \
			(child->uffd[i].fd != -1) && (spaces->space[i].type != FILE_BACKED)){
#elif SWITCHLESS
		if((spaces->space[i].address != 0x7ffff75b4000) &&                            	\
			(child->uffd[i].fd != -1) && spaces->space[i].type != FILE_BACKED){
#elif DEBUGMALLOC
		if((spaces->space[i].address != 0x7ffff7a9d000) &&                            	\
			(child->uffd[i].fd != -1) && spaces->space[i].type != FILE_BACKED){
#elif LOGCALLBACK
		if((spaces->space[i].address != 0x7ffff7a9e000) &&                            	\
			(spaces->space[i].address != 0x7ffff7a9d000) &&								\
			(child->uffd[i].fd != -1) && spaces->space[i].type != FILE_BACKED){
#elif APKMAN
		if(spaces->space[i].address != 0x7ffff7a9d000 &&                                \
		   spaces->space[i].type != FILE_BACKED){
#elif DATASEALING
		if(spaces->space[i].address != 0x7ffff7a9d000 &&                                \
		   spaces->space[i].type != FILE_BACKED){
#elif PLUGGABLEALLOCATOR
		if(spaces->space[i].address != 0x7ffff7a9d000 &&                                \
		   spaces->space[i].type != FILE_BACKED){
#elif MICROBENCH
		if(spaces->space[i].address != 0x7ffff7a9d000 &&                                \
		   spaces->space[i].type != FILE_BACKED){
#elif VIRTUAL_ASSISTANT
		if(spaces->space[i].address != 0x7ffff7a9d000 &&                                \
		   spaces->space[i].type != FILE_BACKED){
#elif REMOTE_ATTEST
		if(spaces->space[i].address != 0x7ffff7a9d000 &&                                \
		   spaces->space[i].type != FILE_BACKED){
#endif
			//for(unsigned long j = 0; j < child->spaces.space[i].size; j++){
				ret = compel_remove_uffd(child,                                                 \
							child->uffd[i].fd,                                            		\
							spaces->space[i].address,               							\
							spaces->space[i].size);
				log_info("Unregistered uffd %d for the address 0x%lx with size %d",             \
									    child->uffd[i].fd,                               	 	\
									    spaces->space[i].address,   							\
									    spaces->space[i].size);
			//}
		}
	}
	return 0;
}
