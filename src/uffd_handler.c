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

#define NO_NEW_PAGEFAULT 			0xFF
#define NEW_PAGEFAULT_READ  		0x00
#define NEW_PAGEFAULT_WRITE 		UFFD_PAGEFAULT_FLAG_WRITE
#define PAGEFAULT_WRITE_PROTECTION 	(UFFD_PAGEFAULT_FLAG_WRITE | UFFD_PAGEFAULT_FLAG_WP) 

#define errExit(msg) do{ perror(msg); exit(EXIT_FAILURE);}while(0)

pid_t victimPid = -1;

/**
  * @brief It peeks the page using ptrace
  * 
  * @param victim_pid 
  * @param address 
  * @param page 
  * @return int 
  */
static int retrieve_victim_page_postwrite(pid_t victim_pid, __u64 address, char *page){
   	int err;

   	err = get_child_data(victim_pid, page, (void*)address, (sysconf(_SC_PAGE_SIZE)));
   	if(err)
   	    return err;


    // for(int i = 0; i < sysconf(_SC_PAGE_SIZE); i += 8){
    //     fprintf(stderr, "The stolen value from %p is ", address + i);
    //     fprintf(stderr, "%c ", *((char*)(page+i)));
    //     fprintf(stderr, "%c ", *((char*)(page+i+1)));
    //     fprintf(stderr, "%c ", *((char*)(page+i+2)));
    //     fprintf(stderr, "%c ", *((char*)(page+i+3)));
    //     fprintf(stderr, "%c ", *((char*)(page+i+4)));
    //     fprintf(stderr, "%c ", *((char*)(page+i+5)));
    //     fprintf(stderr, "%c ", *((char*)(page+i+6)));
    //     fprintf(stderr, "%c\n", *((char*)(page+i+7)));
    // }

	return 0;
}

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
static int handle_wprotect_pagefaults(long uffd, struct uffd_msg msg, popsgx_child *tracee, char *page, int i)
{
	struct uffdio_writeprotect uffdio_wp;
	int ret = 0;

    pthread_mutex_lock(&tracee->mutex);
	ret = ptrace(PTRACE_ATTACH, tracee->c_pid, NULL, NULL);
	log_info("return value is %d %d", ret, errno);
	wait(NULL);

	log_info("--");
	uffdio_wp.range.start = tracee->spaces.space[i].address;
 	uffdio_wp.range.len = sysconf(_SC_PAGE_SIZE) * tracee->spaces.space[i].size;
 	uffdio_wp.mode = 0;
 	if (ioctl(uffd, UFFDIO_WRITEPROTECT, &uffdio_wp) == -1){
		log_error("UFFDIO_WRITEPROTECT failed\n");
		goto fail_handle_wprotect_pagefaults;
	} 

	log_info("xxxxxxx");
	//ret = ptrace(PTRACE_SINGLESTEP, tracee->c_pid, NULL, NULL);
	//wait(NULL);
	
	if(retrieve_victim_page_postwrite(tracee->c_pid, msg.arg.pagefault.address, page))
	{
		log_error("retrieve_victim_page_postwrite failed\n");
		goto fail_handle_wprotect_pagefaults; 
	}

	
	log_info("Setting the Write Protection of the page");
	// uffdio_wp.mode = UFFDIO_WRITEPROTECT_MODE_WP;
 	// if (ioctl(uffd, UFFDIO_WRITEPROTECT, &uffdio_wp) == -1)
	// { 
   	// 	log_error("ioctl-UFFDIO_WRITEPROTECT");
	// 	goto fail_handle_wprotect_pagefaults;
	// }

	ptrace(PTRACE_DETACH, tracee->c_pid, NULL, NULL);
	//wait(NULL);
	pthread_mutex_unlock(&tracee->mutex);
	
	return 0;

fail_handle_wprotect_pagefaults:
	ptrace(PTRACE_DETACH, tracee->c_pid, NULL, NULL);
    pthread_mutex_unlock(&tracee->mutex);
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
		//msi_request_page(msi, sk, page, (void*)msg.arg.pagefault.address, msg.arg.pagefault.flags);
        memset(page, '0', PAGE_SIZE);
		new_pagefault_type = NEW_PAGEFAULT_READ;
		//get_child_data(victimPid, page, msg.arg.pagefault.address, 4096);
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

	if((new_pagefault_type == NEW_PAGEFAULT_READ) || (new_pagefault_type == NEW_PAGEFAULT_WRITE)){
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
void *
fault_handler_thread(void *arg)
{
	static struct uffd_msg msg;   /* Data read from userfaultfd */
	uffd_thread_args* handler_arg = (struct uffd_thread_args*)arg;
	popsgx_child *tracee = handler_arg->child;
    int *uffd;                    /* userfaultfd file descriptor */
	int no_uffd;
	char *page = NULL;
	struct uffdio_copy uffdio_copy;
	ssize_t nread;
	int ret = 0;

	victimPid = tracee->c_pid;

	uffd = tracee->uffd;
	no_uffd = tracee->uffd_no;
	page = mmap(NULL, sysconf(_SC_PAGESIZE), PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0);
    if(page == MAP_FAILED){
        errExit("Memory map failed");
    }

	struct pollfd *pollfd = malloc(sizeof(struct pollfd) * no_uffd);
	for (;;) {
		int nready;
		for(int i = 0; i < no_uffd; i++){
			pollfd[i].fd = uffd[i];
			pollfd[i].events = POLLIN;
		}
		nready = poll(pollfd, no_uffd, -1);
		if (nready == -1)
			errExit("poll");

		for(int i = 0; i < no_uffd; i++){
			if(i == 3)
				continue;

			if(pollfd[i].revents & POLLIN){
				
				log_info("polling id is %d", i);
				nread = read(uffd[i], &msg, sizeof(msg));
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

				log_info("UFFD_EVENT_PAGEFAULT event: ");
				log_info("flags = %llx; ", msg.arg.pagefault.flags);
				log_info("address = %llx", msg.arg.pagefault.address);

				//Check if we need to handle new page-faults
				uint8_t pagefault_type = handle_rw_pagefault(uffd[i], msg, page, handler_arg->msi, handler_arg->sock_fd);
				if(pagefault_type != NO_NEW_PAGEFAULT){
					log_info("New pagefault type is %d", pagefault_type);
					log_info("Handled new pagefault");
				}

				if(pagefault_type == NEW_PAGEFAULT_WRITE || pagefault_type == PAGEFAULT_WRITE_PROTECTION){
					log_info("entry!!");
					void *t = malloc(sysconf(_SC_PAGE_SIZE));
					log_info("entrys!!");
					if(handle_wprotect_pagefaults(uffd[i], msg, tracee, t, i)){
						log_error("Erros in handling write-protect pagefaults");
					}
					log_info("entryx!!");
					free(t);

					int state;
					state =  compel_stop_task(tracee->c_pid);
    				if(ret < 0){
        				log_error("Could not stop the victim for compel infection");
    				}

					log_info("post compel stop task");

					ret = compel_remove_uffd(tracee, uffd[i], tracee->spaces.space[i].address, tracee->spaces.space[i].size);
					if(ret){
						log_error("failed to remove the uffd for the range 0x%lx", tracee->spaces.space[i].address);
					}

					compel_resume_task(tracee->c_pid, state, state);
					log_info("exiting compel_resume_task");
					
					// log_info("%d", handler_arg->msi->_can_request);
					// log_info("%d", handler_arg->sock_fd);
					// log_info("%p", msg.arg.pagefault.address);
					// log_info("%c ", *((char*)(t)));
					//msi_handle_write_command(handler_arg->msi ,handler_arg->sock_fd, msg.arg.pagefault.address, t, sysconf(_SC_PAGE_SIZE));

					//log_info("[%p]PAGEFAULT", (void *)msg.arg.pagefault.address);
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

    rc = pthread_create(&uffd_hdl->thread, NULL, fault_handler_thread, (void*) &uffd_hdl->args);
    if (rc != 0) {
		log_error("Could not create a dsm bus handler thread");
        goto out_fail;
	}

out_fail:
    return rc;
}