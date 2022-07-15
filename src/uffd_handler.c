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

#define NO_NEW_PAGEFAULT 			0xFF
#define NEW_PAGEFAULT_READ  		0x00
#define NEW_PAGEFAULT_WRITE 		0x01 // UFFD_PAGEFAULT_FLAG_WRITE
#define PAGEFAULT_WRITE_PROTECTION 	0x03 // UFFD_PAGEFAULT_FLAG_WRITE | UFFDIO_REGISTER_MODE_WP 

#define errExit(msg) do{ perror(msg); exit(EXIT_FAILURE);}while(0)

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

   	log_debug("The stolen value from %p is %c", address, *((char*)(page+0xf)));
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
static int handle_wprotect_pagefaults(long uffd, struct uffd_msg msg, popsgx_child *tracee, char *page)
{
	struct uffdio_writeprotect uffdio_wp;
	int ret = 0;

    pthread_mutex_lock(&tracee->mutex);
	ptrace(PTRACE_ATTACH, tracee->c_pid, NULL, NULL);
	wait(NULL);

	uffdio_wp.range.start = msg.arg.pagefault.address;
 	uffdio_wp.range.len = sysconf(_SC_PAGE_SIZE);
 	uffdio_wp.mode = 0;
 	if (ioctl(uffd, UFFDIO_WRITEPROTECT, &uffdio_wp) == -1){
		log_error("UFFDIO_WRITEPROTECT failed\n");
		goto fail_handle_wprotect_pagefaults;
	} 

	ptrace(PTRACE_SINGLESTEP, tracee->c_pid, NULL, NULL);
	wait(NULL);

	if(retrieve_victim_page_postwrite(tracee->c_pid, msg.arg.pagefault.address, page))
	{
		log_error("retrieve_victim_page_postwrite failed\n");
		goto fail_handle_wprotect_pagefaults; 
	}

	log_debug("Setting the Write Protection of the page");
	uffdio_wp.mode = UFFDIO_WRITEPROTECT_MODE_WP;
 	if (ioctl(uffd, UFFDIO_WRITEPROTECT, &uffdio_wp) == -1)
	{ 
   		log_error("ioctl-UFFDIO_WRITEPROTECT");
		goto fail_handle_wprotect_pagefaults;
	}

	ptrace(PTRACE_DETACH, tracee->c_pid, NULL, NULL);
	pthread_mutex_unlock(&tracee->mutex);
	return 0;

fail_handle_wprotect_pagefaults:
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
		msi_request_page(msi, sk, page,
			 (void*)msg.arg.pagefault.address,
			 msg.arg.pagefault.flags);
		
		new_pagefault_type = NEW_PAGEFAULT_READ;
	}
	//New pagefault due to write
	else if(msg.event == UFFD_EVENT_PAGEFAULT && 
		   (msg.arg.pagefault.flags == NEW_PAGEFAULT_WRITE))
	{
		new_pagefault_type = NEW_PAGEFAULT_WRITE;
	}

	//Second write page fault
	else if(msg.event == UFFD_EVENT_PAGEFAULT && 
		   (msg.arg.pagefault.flags == PAGEFAULT_WRITE_PROTECTION))
	{
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
    long uffd;                    /* userfaultfd file descriptor */
	char *page = NULL;
	struct uffdio_copy uffdio_copy;
	ssize_t nread;

	uffd = tracee->uffd;

	page = mmap(NULL, sysconf(_SC_PAGESIZE), PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0);
    if(page == MAP_FAILED){
        errExit("Memory map failed");
    }

	for (;;) {
		struct pollfd pollfd;
		int nready;
		pollfd.fd = uffd;
		pollfd.events = POLLIN;
		nready = poll(&pollfd, 1, -1);
		if (nready == -1)
			errExit("poll");

		nread = read(uffd, &msg, sizeof(msg));
		if (nread == 0) {
			log_error("EOF on userfaultfd!");
			exit(EXIT_FAILURE);
		}

		if (nread == -1)
			errExit("read");

		if (msg.event != UFFD_EVENT_PAGEFAULT) {
			log_error("Unexpected event on userfaultfd");
			exit(EXIT_FAILURE);
		}

		log_debug("    UFFD_EVENT_PAGEFAULT event: ");
		log_debug("flags = %llx; ", msg.arg.pagefault.flags);
		log_debug("address = %llx", msg.arg.pagefault.address);

		//Check if we need to handle new page-faults
		uint8_t pagefault_type = handle_rw_pagefault(uffd, msg, page, handler_arg->msi, handler_arg->sock_fd);
		if(pagefault_type != NO_NEW_PAGEFAULT){
			log_debug("New pagefault type is %d", pagefault_type);
			log_debug("Handled new pagefault");
		}

		if(pagefault_type == NEW_PAGEFAULT_WRITE || pagefault_type == PAGEFAULT_WRITE_PROTECTION){
			volatile void *t = alloca(sysconf(_SC_PAGE_SIZE));
			if(handle_wprotect_pagefaults(uffd, msg, tracee, t)){
				log_error("Erros in handling write-protect pagefaults");
			}

			msi_handle_write_command(handler_arg->msi ,handler_arg->sock_fd, msg.arg.pagefault.address, t, sysconf(_SC_PAGE_SIZE));

			log_debug("[%p]PAGEFAULT", (void *)msg.arg.pagefault.address);
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