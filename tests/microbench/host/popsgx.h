/* ==========================================
 *	 PopSGX library.
 *	 author Carlos Bilbao 😎
 *	 bilbao [at] vt [dot] edu
 * ==========================================
*/
#pragma once
#ifndef __POPSGX_H_
#define __POPSGX_H_

#include <linux/userfaultfd.h>
#include <linux/limits.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <stdarg.h>
#include <pthread.h>
#include <poll.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>

#define errExit(msg) do { perror(msg); exit(EXIT_FAILURE); \
	} while (0)

/* Set this flag to get information of the ecall/ocall flow */
static int verbose_pop_sgx = 1;

static char *arg_file = "child_request";
static int client_pid, my_socket;

static long unsigned int wait_for_ok(char *file_name, int return_val)
{
	FILE *file;
	char res[100];
	long unsigned int result;

	while (1) {
		file = fopen(file_name,"r");
	
		if (!file){
chill:      
			fclose(file);          	
			sleep((unsigned int)0.5);
			continue;
        }
     
		result = fscanf(file, "%s", res); 

		if (result == EOF) goto chill;

		if (!strcmp(res,"OK")){
			if (return_val && fscanf(file, "%ld", &result) == EOF){
				errExit("popsgx.h couldn't retrieve return value.\n");
			}
			fclose(file);
			break;
		}

		fclose(file);
	}

	return result;
}

/* ===================== USERFAULTFD STUFF ===================== */

/* Heap section information */

#define PROCMAPS_LINE_MAX_LENGTH (PATH_MAX + 100)

long uffd;          /* userfaultfd file descriptor */

long unsigned int heap_start_region;
long unsigned int heap_end_region;
long unsigned int heap_length;

static void __register_socket(void)
{
	FILE *dsm_file = fopen(arg_file,"w");
	int ret;

	if (!dsm_file){
	      errExit("Could not open dsm file");
	}

	/* File the parent reads:

	   +--------------------+
	   | "socket"           |
	   ----------------------
	*/
	
	fprintf(dsm_file,"socket\n");
	fclose(dsm_file);

	if ((ret = kill(client_pid,SIGUSR1)) < 0){
		errExit("kill failed");	
	}

	my_socket = wait_for_ok(arg_file,1);
}

static char * __request_dsm_page(long unsigned int heap_addr)
{
	FILE *dsm_file = fopen(arg_file,"w");
	int ret;
	char *page;

	if (!dsm_file){
	      errExit("Could not open dsm file");
	}

	/* File the parent reads:

	   +--------------------+
	   | "page_fault"       |
	   ----------------------
	   | faulty_address     |
	   ----------------------
	*/

	fprintf(dsm_file,"page_fault\n");
	fprintf(dsm_file,"%lx\n",heap_addr);
	fclose(dsm_file);

	if ((ret = kill(client_pid,SIGUSR1)) < 0){
		errExit("kill failed");	
	}

	ret = wait_for_ok(arg_file,0);

	/* Now copy data from socket... */
	page = malloc(sysconf(_SC_PAGE_SIZE));

	errno = 0;
	if (recv(my_socket, page, sysconf(_SC_PAGE_SIZE),0) != sysconf(_SC_PAGE_SIZE)){
		/* Was just the page not as big? */
		if (errno != 0){
			errExit("could not read page data with socket");
		}
	}

	return page;
}

/*
 	Parsing logic of /proc/pid/maps,
 	from https://github.com/ouadev/proc_maps_parser/blob/master/pmparser.c
*/
static void __split_line(char *buf,char *addr_1,char *addr_2,
			      char *perm,char *offset,char *device,char *inode,char *pathname)
{
	int orig = 0, i =0;

	while (buf[i]!='-'){
		addr_1[i-orig] =buf[i];
		i++;
	}

	addr_1[i] ='\0';
	i++;
	orig = i;
	
	while (buf[i]!='\t' && buf[i]!=' '){
		addr_2[i-orig] =buf[i];
		i++;
	}
	addr_2[i-orig] ='\0';

	while (buf[i] =='\t' || buf[i] ==' ') i++;
	
	orig = i;
	
	while (buf[i]!='\t' && buf[i]!=' '){
		perm[i-orig] =buf[i];
		i++;
	}
	perm[i-orig] ='\0';

	while (buf[i] =='\t' || buf[i] ==' ') i++;
	
	orig = i;
	
	while (buf[i]!='\t' && buf[i]!=' '){
		offset[i-orig] =buf[i];
		i++;
	}
	
	offset[i-orig] ='\0';

	while (buf[i] =='\t' || buf[i] ==' ') i++;
	
	orig = i;
	
	while (buf[i]!='\t' && buf[i]!=' '){
		device[i-orig] =buf[i];
		i++;
	}
	
	device[i-orig] ='\0';

	while (buf[i] =='\t' || buf[i] ==' ') i++;
	
	orig = i;
	
	while (buf[i]!='\t' && buf[i]!=' '){
		inode[i-orig] =buf[i];
		i++;
	}

	inode[i-orig] ='\0';
	pathname[0] ='\0';
	
	while (buf[i] =='\t' || buf[i] ==' ')
		i++;
	
	orig = i;
	
	while (buf[i]!='\t' && buf[i]!=' ' && buf[i]!='\n'){
		pathname[i-orig] =buf[i];
		i++;
	}
	pathname[i-orig] ='\0';
}

static void initialize_heap_info(void)
{
	int found = 0;
	char addr_1[20],addr_2[20], perm[8], offset[20], dev[10],inode[30],pathname[80];
	char buf[PROCMAPS_LINE_MAX_LENGTH], name[128];
	FILE *maps_fd;

	snprintf(name,sizeof(name),"/proc/%d/maps",getpid());
	
	if ((maps_fd = fopen(name, "r")) == NULL){
		errExit("Opening proc/maps/pid failed");
	}

	while (!found && !feof(maps_fd)){

		if (fgets(buf,PROCMAPS_LINE_MAX_LENGTH,maps_fd) == NULL){
			errExit("fgets failed");
		}

		__split_line(buf,addr_1,addr_2,perm,offset,dev,inode,pathname);

		if (strstr(pathname,"[heap]") != NULL){
			sscanf(addr_1,"%lx",&heap_start_region);
			sscanf(addr_2,"%lx",&heap_end_region);
			heap_length = (heap_end_region - heap_start_region) * 16;
			found = 1;
		}
	}

	fclose(maps_fd);

	if (!found){
		errExit("Could not find heap address\n");
	}
}

static void *fault_handler_thread(void *arg)
{
	static struct uffd_msg msg;   /* Data read from userfaultfd */
	struct uffdio_copy uffdio_copy;
	ssize_t nread;
	char *page = NULL;
	long unsigned int fault_addr;

	/* Endless loop for handling incoming events on userfaultfd fd*/
	for (;;) {
		struct pollfd pollfd;
		int nready;
		pollfd.fd = uffd;
		pollfd.events = POLLIN;
		
		/*
		  Use poll() to wait for the userfaultfd file to be ready to
		  perform I/O operations. poll() works in a similar fashion as
		  select().
		*/
		nready = poll(&pollfd, 1, -1);

		if (nready == -1)
			errExit("poll");

		/* Read the next message in the uffd file */
		nread = read(uffd, &msg, sizeof(msg));

		if (nread == 0) {
			errExit("EOF on userfaultfd!");
		}

		if (nread == -1)
			errExit("read");

		/* We're only interested in page fault event messages */
		if (msg.event != UFFD_EVENT_PAGEFAULT) {
			errExit("Unexpected event on userfaultfd");
		}

		fault_addr = (unsigned long) msg.arg.pagefault.address;

		if (verbose_pop_sgx){
			//fprintf(stderr,"[0x%lx] PAGEFAULT\n",fault_addr);
		}

		if (fault_addr > heap_end_region || fault_addr < heap_start_region
			 || fault_addr + sysconf(_SC_PAGE_SIZE) - 1 > heap_end_region){
				fprintf(stderr, "Faulty address out of heap bounds [0x%lx-0x%lx]",
					heap_start_region,heap_end_region);
				exit(EXIT_FAILURE);
		}
		
		/* DSM logic -- Delegate on parent to obtain page and perform sync logic */
		page = __request_dsm_page((long unsigned int )msg.arg.pagefault.address);

		uffdio_copy.src  = (unsigned long) page;
		uffdio_copy.dst  = fault_addr;
		uffdio_copy.len  = sysconf(_SC_PAGE_SIZE);
		uffdio_copy.mode = 0;
		uffdio_copy.copy = 0;

		/* Take care of the page fault by copying a page of data into
		   the faulting region. We copy our address space that will
		   have the new page stored now. 
		*/
		if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1)
			errExit("ioctl-UFFDIO_COPY");
	}
}

static long __create_uffd(void)
{
	int pthread_ret;  /* ID of the thread that handles page faults */
	struct uffdio_api uffdio_api;
	struct uffdio_register uffdio_register;
	pthread_t thr_handler;

	/*
	* There is no glibc wrapper for this system call, that creates a new
	* object to delegate user-space page-fault handling. Once created,
	* we will be able to read from it to receive notifications. *
	*/
	if ((uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK)) == -1) {
		errExit("could not create userfaultfd descriptor\n");
	}
	
	/*
	* After creating the userfaultfd object, we need to enable it using
   * the UFFDIO_API ioctl() syscall. It is a handshake between kernel
   * and user space to determine things like the API and available features.
   */
	uffdio_api.api = UFFD_API;
	uffdio_api.features = 0;
	
	if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1)
		errExit("ioctl-UFFDIO_API");

	/*
	* After a succesful kernel/user handshake, the application registers the
	* memory addresses. When a page fault occurs, if it is in that memory range
   * it will be forwarded up to the thread, that can handle it.
	*/
	uffdio_register.range.start = heap_start_region;
	uffdio_register.range.len   = heap_length;
	uffdio_register.mode        = UFFDIO_REGISTER_MODE_MISSING;

	if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1)
		errExit("ioctl-UFFDIO_REGISTER");

	/* Create a thread, that will start by calling the fault handler function */
	pthread_ret = pthread_create(&thr_handler, NULL, &fault_handler_thread, NULL);

	if (pthread_ret != 0) {
		errno = pthread_ret;
		errExit("pthread_create for heap uffd");
	}

	pthread_detach(thr_handler);
}

static void __update_dsm_parent(void)
{
	FILE *dsm_file;
	long unsigned int ret;

	dsm_file = fopen(arg_file,"w");

	if (!dsm_file){
	      errExit("Could not open dsm file");
	}

	/* File the parent reads:

	   +--------------------+
	   | "uffd"             |
	   ----------------------
	   | heap_start_region  |
	   ----------------------
	   | heap_length        |
	   ----------------------
	*/

	fprintf(dsm_file,"uffd\n");
	fprintf(dsm_file,"%lx\n",heap_start_region);
	fprintf(dsm_file,"%ld\n",heap_length);
	fclose(dsm_file); 

	if ((ret = kill(client_pid,SIGUSR1)) < 0){
		errExit("kill failed");	
	}

	ret = wait_for_ok(arg_file,0);
}

static void __prepare_uffd(void)
{
	initialize_heap_info(); 

	/* Make parent update DSM information */
	__update_dsm_parent();

	/* Create uffd and thread handler for the heap region */
	__create_uffd();
}

/* ===================== Forward e/ocalls ===================== */

static int __signal_popsgx(char *arg, int num_args, long int *args)
{
	int ret,i=0, result = -1;   
	FILE *args_file;

	args_file = fopen(arg_file,"w");

	if (!args_file){
	      errExit("Could not open args file");
	}

	/* File the parent reads:

	   +--------------+
	   | func name    |
	   ----------------
	   | num_args     |
	   ----------------
	   | arguments    |
	   ----------------        
	*/

	fprintf(args_file,"%s\n",arg);
	fprintf(args_file,"%d\n",num_args);

	/* Write arguments into the file */
	for (;i < num_args; ++i){
		fprintf(args_file,"%ld\n",args[i]);
	}

	fclose(args_file);

	if ((ret = kill(client_pid,SIGUSR1)) < 0){
		errExit("kill failed");	
	}

	/* Wait for the signal to be handled and get the return value */
	result = wait_for_ok(arg_file,1);

	return result;
}

static int popsgx_ecall(char *func, int args_num, ...)
{
	va_list valist;
	long int args[args_num];
	int i = 0;

	/* Get parameters for the function */
	va_start(valist,args_num);

	for (; i < args_num; ++i){
		args[i] = va_arg(valist,long int);
	}
	
	va_end(valist);

	return __signal_popsgx(func, args_num, args);
}

/*
   args should be the file name for the binary (argv[0]).
   Returns 1 if everything went well 
*/
static int init_popsgx(char *args)
{        
	FILE *pop_file;
	char *name;        
	int ret;

	/* Avoid getting killed when signaling parent */
	signal(SIGUSR1, SIG_IGN);

	if (!args){
	   fprintf(stderr, "Args not provided\n");
	   return -1;
	}

	/* Obtain socket to read page info */
	__register_socket();

	/* Prepare uffd heap, page fault handler and DSM */
	__prepare_uffd();

	/* Obtain the client's (parent) PID */
	client_pid = getppid();

	return 1;
}

#endif /*  __POPSGX_H_ */
