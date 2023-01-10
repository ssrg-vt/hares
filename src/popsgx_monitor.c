#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <signal.h>

#include "../inc/ptrace.h"
#include "../inc/log.h"
#include "../inc/popsgx_monitor.h"
#include "../inc/compel_handler.h"
#include "../inc/dsm_handler.h"
#include "../inc/uffd_handler.h"
#include "../inc/msi_handler.h"
#include "../inc/vmscan_util.h"

#define log_info(args...) 

extern char* __progname;

// Required number of arguments for the application
#define OPT_MANDATORY_COUNT 3

// Starting address for the buffer 
#define BUFFER_ADDRESS 0x10000

#define FILEENCRYPT 1

// Helloworld main function address
#ifdef HELLOWORLD
#define MAIN 0x43fd70
#elif FILEENCRYPT
#define MAIN 0x40a790
#elif SWITCHLESS
#define MAIN 0x444cf0
#endif


/**
 * @brief Printing the help message
 * 
 */
static void usage(void)
{
    log_info("\n"
             "usage: %s [-m mode | -v victim | -r remote-node-ip | -p remote-node-port | -t host-port              \
                        | -s shared_mem | -n no_pages]"
             "\n"
             "options:\n"
             "\t-m mode of the popsgx_monitor application either server or client\n"
             "\t-v victim process to serve page-faults & ditributed-memory-sharing\n"
             "\t-r remote node's ip-address for dsm\n"
             "\t-p remote node's port-number for dsm\n"
             "\t-t host's port-number\n"
             "\t-s address of the memory region to be shared\n"
             "\t-n number of pages to be shared\n"
             "\t-h help"
             "\n",
             __progname);
    exit(EXIT_SUCCESS);
}

/**
 * @brief This function is only to be used to stop the child at main
 *   
 * 
 * @param cpid 
 * @param addr 
 */
static void wait_child_main(pid_t cpid, unsigned long addr)
{
    int wait_status;
    wait(&wait_status);
    if (WIFSTOPPED(wait_status))
    {
        log_info("Child got a signal: %s\n", strsignal(WSTOPSIG(wait_status)));
    }
    else
    {
        log_error("wait");
        EXIT_FAILURE;
    }

    //Set a breakpoint to stop at the main function
    long main_data = set_breakpoint(cpid,  addr);
    ptrace(PTRACE_CONT, cpid, NULL, NULL);
    wait(&wait_status);
    clear_breakpoint(cpid, addr, main_data);
    ptrace(PTRACE_DETACH, cpid, NULL, NULL);
}

/**
 * @brief Execute the tracee application 
 * 
 * @param tracee 
 * @return int 
 */
static int execute_tracee_app(popsgx_child *tracee){
    int ret = 0;
    pid_t tracee_pid;

    tracee_pid = fork();
    if(tracee_pid < 0){
        log_error("Forking failed with error %s", strerror(errno));
        return -1;
    }else if(tracee_pid == 0){
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0)
        {
            log_error("ptrace");
            return;
        }

#ifdef HELLOWORLD
        char *user_args[] = {"host/helloworldhost", "./enclave/helloworldenc.signed",       \
                             "--simulate", NULL};
#elif FILEENCRYPT
        char *user_args[] = {"./host/file-encryptorhost", "testfile",  "./enclave/file-encryptorenc.signed",       \
                             "--simulate", NULL};
#elif SWITCHLESS
        char *user_args[] = {"host/switchlesshost", "./enclave/switchlessenc.signed",       \
                             "--simulate", NULL};
#elif PLUGGABLEALLOCATOR
        char *user_args[] = {"./host/allocator_demo_host", "./enclave/enclave_default.signed",  "./enclave/enclave_custom.signed",   \
                             "--simulate", NULL};
#endif

        execve(user_args[0], user_args, NULL);
        // Should not execute the below line
        log_error("Failed on execl of the tracee with error %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    tracee->c_pid = tracee_pid;

    log_info("Successfully forked the tracee as a child process %d", tracee_pid);
    return ret;
}

/**
 * @brief Set the breakpoints in the tracee application
 * 
 * @param child_pid 
 * @param trc 
 */
static void place_breakpoints(pid_t child_pid, tracepoints *trc){
    for(int i = 0; i < trc->size; i++){
        log_info("Setting breakpoints at 0x%lx", trc->breakpoints[i]);
        trc->old_instructions[i] = set_breakpoint(child_pid, trc->breakpoints[i]);
    }
}

/**
 * @brief Creating buffer for storing the memory of the application
 * 
 * @param msi 
 * @param buffer_addr 
 * @param no_pages 
 * @return int 
 */
int initialize_msi_page(msi_handler *msi, uint64_t buffer_addr, int no_pages){
    int ret = 0;

    //creating a buffer
    mmap(buffer_addr, no_pages * 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    memset(buffer_addr, 0, no_pages * 4096);

    ret = create_msi_pages(msi, buffer_addr, no_pages);
    if(ret){
        log_error("Couldn't create msi pages");
    }

    msi->popsgx_buffer_addr = BUFFER_ADDRESS;

    return ret;
}

int main(int argc, char *argv[]){
    int ret = 0;
    int opt, opt_counter = 0;
    char *mode = NULL;
    popsgx_app monitor_app;

    memset(&monitor_app, 0, sizeof(popsgx_app));
    monitor_app.buffer = BUFFER_ADDRESS;
    
    /*
     *  Parse the arguments
     */
    struct option long_opt[] =
    {
        {       "mode", required_argument, NULL, 'm'},
        {  "remote_ip", required_argument, NULL, 'r'},
        {"remote_port", required_argument, NULL, 'p'},
        {  "host_port", required_argument, NULL, 't'},
        {         NULL,                 0, NULL,  0 }
    };
    
    while((opt = getopt_long(argc, argv, "hr:p:t:m:", long_opt, NULL)) != -1){
        switch (opt)
        {
        case 'r':
            monitor_app.dsm.remote_ip = strdup(optarg);
            break;
        
        case 'p':
            monitor_app.dsm.remote_port = atoi(optarg);
            break;

        case 't':
            monitor_app.dsm.host_port = atoi(optarg);
            break;

        case 'm':
            mode = strdup(optarg);
            log_info("mode : %s", mode);
            if(!strcmp("server", mode)){
                monitor_app.mode = SERVER;
            }else if(!strcmp("client", mode)){
                monitor_app.mode = CLIENT;
            }else{
                usage();
            }
            break;

        case 'h':
        default:
            usage();
            break;
        }
        opt_counter++;
    }

    log_info("opt_counter %d", opt_counter);
    if (optind < argc || opt_counter < OPT_MANDATORY_COUNT)
	{
		usage();
	}

    //Execute and Wait for the child at main instruction
    ret = execute_tracee_app(&monitor_app.dsm.child);
    if(ret){
        log_error("failed to execute the tracee app");
        goto out_fail; 
    }
    wait_child_main(monitor_app.dsm.child.c_pid, MAIN);

    
    //This gets resumed when we steal uffd
    ret =  compel_stop_task(monitor_app.dsm.child.c_pid);
    if(ret < 0){
        log_error("Could not stop the victim for compel infection");
        goto out_stop_fail;
    }

    //uint64_t heap_pages = 0x4de000;
    // uint64_t heap_pages = 0x4de000;
    // ret = compel_correct_heap_offset(&monitor_app.dsm.child, heap_pages);
    // if(ret){
    //     log_error("compel_correct_heap_offset failed");
    // }
    
    
    //Needed the child process id in the msi
    monitor_app.dsm.msi.child = monitor_app.dsm.child;
    ret = create_msi_pages(&monitor_app.dsm.msi, 0, 0);
    if(ret){
        log_error("Failed to start msi");
        goto out_dsm_fail;
    }

    //Establishing connection to the remote node!!
    ret = dsm_main(&monitor_app.dsm, monitor_app.mode);
    if(ret){
        log_error("Failed to start dsm");
        goto out_dsm_fail;
    }
    
    //Grabbing the heap address
    get_virtual_address_frame_by_name(monitor_app.dsm.child.c_pid, &monitor_app.dsm.child.heap_start_address, &monitor_app.dsm.child.heap_end_address, "[heap]");

    //setting up the breakpoints
    monitor_app.dsm.child.trpoints.size = 40;
    monitor_app.dsm.child.trpoints.breakpoints = malloc(sizeof(unsigned long int) *                                  \
                                                        monitor_app.dsm.child.trpoints.size);
    monitor_app.dsm.child.trpoints.old_instructions = malloc(sizeof(unsigned long int) *                             \
                                                             monitor_app.dsm.child.trpoints.size);
    
    

#ifdef HELLOWORLD

    //Hello world
    monitor_app.dsm.child.trpoints.breakpoints[0] = 0x43fff6;
    monitor_app.dsm.child.trpoints.breakpoints[1] = 0x43fffb;
    monitor_app.dsm.child.trpoints.breakpoints[2] = 0x4400e6;
    monitor_app.dsm.child.trpoints.breakpoints[3] = 0x4400eb;
    monitor_app.dsm.child.trpoints.breakpoints[4] = 0x440278;
    monitor_app.dsm.child.trpoints.breakpoints[5] = 0x44027d;
    #define LIMIT 5

#elif FILEENCRYPT
    //file encryption
    monitor_app.dsm.child.trpoints.breakpoints[0] = 0x40aaef;
    monitor_app.dsm.child.trpoints.breakpoints[1] = 0x40aaf4;
    monitor_app.dsm.child.trpoints.breakpoints[2] = 0x4090ff;
    monitor_app.dsm.child.trpoints.breakpoints[3] = 0x409104;
    monitor_app.dsm.child.trpoints.breakpoints[4] = 0x409807;
    monitor_app.dsm.child.trpoints.breakpoints[5] = 0x40980c;
    monitor_app.dsm.child.trpoints.breakpoints[6] = 0x40a1aa;
    monitor_app.dsm.child.trpoints.breakpoints[7] = 0x40a1af;
    monitor_app.dsm.child.trpoints.breakpoints[8] = 0x40a65f;
    monitor_app.dsm.child.trpoints.breakpoints[9] = 0x40a664;

    monitor_app.dsm.child.trpoints.breakpoints[10] = 0x4090ff;
    monitor_app.dsm.child.trpoints.breakpoints[11] = 0x409104;
    monitor_app.dsm.child.trpoints.breakpoints[12] = 0x40a65f;
    monitor_app.dsm.child.trpoints.breakpoints[13] = 0x40a664;
    monitor_app.dsm.child.trpoints.breakpoints[14] = 0x40b982;
    monitor_app.dsm.child.trpoints.breakpoints[15] = 0x40b987;
    #define LIMIT 15

#elif SWITCHLESS
    monitor_app.dsm.child.trpoints.breakpoints[0] = 0x444f5c;
    monitor_app.dsm.child.trpoints.breakpoints[1] = 0x444f61;
    monitor_app.dsm.child.trpoints.breakpoints[2] = 0x445064;
    monitor_app.dsm.child.trpoints.breakpoints[3] = 0x445069;
    monitor_app.dsm.child.trpoints.breakpoints[4] = 0x445241;
    monitor_app.dsm.child.trpoints.breakpoints[5] = 0x445246;
    monitor_app.dsm.child.trpoints.breakpoints[6] = 0x44544a;
    monitor_app.dsm.child.trpoints.breakpoints[7] = 0x44544f;
    monitor_app.dsm.child.trpoints.breakpoints[8] = 0x4456ae;
    monitor_app.dsm.child.trpoints.breakpoints[9] = 0x4456b3;
    monitor_app.dsm.child.trpoints.breakpoints[10] = 0x4458b4;
    monitor_app.dsm.child.trpoints.breakpoints[11] = 0x4458b9;
    #define LIMIT 11

#elif PLUGGABLEALLOCATOR
    monitor_app.dsm.child.trpoints.breakpoints[0] = 0x43c5b6;
    monitor_app.dsm.child.trpoints.breakpoints[1] = 0x43c5bb;
    monitor_app.dsm.child.trpoints.breakpoints[2] = 0x43d920;
    monitor_app.dsm.child.trpoints.breakpoints[3] = 0x43d925;
    monitor_app.dsm.child.trpoints.breakpoints[4] = 0x446d4c;
    monitor_app.dsm.child.trpoints.breakpoints[5] = 0x446d4c;
    monitor_app.dsm.child.trpoints.breakpoints[6] = 0x446d52;
    #define LIMIT 6
#endif

    if(monitor_app.mode == SERVER){
        for(int i = 0; i <= LIMIT ; i = i + 2){
            monitor_app.dsm.child.trpoints.old_instructions[i] = set_breakpoint(monitor_app.dsm.child.c_pid,    \
                                                                      monitor_app.dsm.child.trpoints.breakpoints[i]);
        }

        int i = 0;
        unsigned long ret_address;

        while(1){
            int as[100];
            struct user_regs_struct regs;
            int index = -1;
            int delta = 0;

            // ret = scan_address_space(monitor_app.dsm.child, &monitor_app.dsm.child.spaces);
            // if(ret < 0){
            //     log_error("Could not scan the address space for read write permissions");
            //     goto out_stop_fail;
            // }else{
            //     log_info("Overall size of the rw pages are %ld", ret);
            // }

            // //uffd logic
            // monitor_app.dsm.child.uffd = realloc( monitor_app.dsm.child.uffd, sizeof(int) * monitor_app.dsm.child.spaces.size);
            // monitor_app.dsm.child.uffd_no = monitor_app.dsm.child.spaces.size;
            
            // //Registering for uffd
            // ret = register_uffd(&monitor_app.dsm.child);

            // address_spaces uffd_faulted_spaces;
            // monitor_app.uffd_hdl.args.child = &monitor_app.dsm.child;
            // monitor_app.uffd_hdl.args.msi = &monitor_app.dsm.msi;
            // monitor_app.uffd_hdl.args.sock_fd = monitor_app.dsm.socket_fd;
            // monitor_app.uffd_hdl.args.faulting_spaces = &uffd_faulted_spaces;
            // ret = start_uffd_thread_handler(&monitor_app.uffd_hdl);
            // if(ret){
            //     log_error("failed to start uffd thread");
            //     goto out_uffd_thread_fail;
            // }

            ptrace(PTRACE_CONT, monitor_app.dsm.child.c_pid, NULL, NULL);
            wait(&ret);

            if(WIFEXITED(ret)){
                log_info("Child process got exited");
                break;
            }
            
            // //closing the uffd logic
            // ret = stop_uffd_thread_handler(&monitor_app.uffd_hdl);
            // if(ret){
            //     log_error("failed to stop uffd thread");
            //     goto out_uffd_thread_fail;
            // }
            
            // //Deregistering for uffd
            // ret = deregister_uffd(&monitor_app.dsm.child);

            get_regs_args(monitor_app.dsm.child.c_pid, &regs, &as);

            for(int i = 0; i <= LIMIT; i++){
                if((regs.rip - 1) ==  monitor_app.dsm.child.trpoints.breakpoints[i]){
                    index = i;
                    break; 
                }
            }

            if(index == -1){
                break;
            }
            
            log_info("The instruction pointer 0x%x", regs.rip);

            clear_breakpoint(monitor_app.dsm.child.c_pid,                                                           \
                             monitor_app.dsm.child.trpoints.breakpoints[index],                                     \
                             monitor_app.dsm.child.trpoints.old_instructions[index]);
            
            monitor_app.dsm.child.trpoints.old_instructions[index] = set_breakpoint(monitor_app.dsm.child.c_pid,    \
                                                                 monitor_app.dsm.child.trpoints.breakpoints[index]);

            ret = scan_address_space(monitor_app.dsm.child, &monitor_app.dsm.child.spaces);
            if(ret < 0){
                log_error("Could not scan the address space for read write permissions");
                goto out_stop_fail;
            }else{
                log_info("Overall size of the rw pages are %ld", ret);
            }

            address_spaces delta_spaces;
            delta = find_vma_delta(&monitor_app.dsm.child.spaces , &delta_spaces);

            //Starting the idc communication!!
            msi_request_remote_execute(&monitor_app.dsm.msi, monitor_app.dsm.socket_fd, monitor_app.dsm.child.trpoints.breakpoints[index+1]);

            //Grabbing and sending the child process delta vma to remote
            msi_handle_send_vma(&monitor_app.dsm.msi, monitor_app.dsm.socket_fd, delta_spaces, 1);

            //Grabbing and sending the child process vma to remote
            msi_handle_send_vma(&monitor_app.dsm.msi, monitor_app.dsm.socket_fd, monitor_app.dsm.child.spaces, 0);

            //Grabbing and sending the child process registers to remote
            msi_handle_send_regs(&monitor_app.dsm.msi, monitor_app.dsm.socket_fd, &monitor_app.dsm.msi.regs);

            msi_handle_remote_execution(&monitor_app.dsm.msi, monitor_app.dsm.socket_fd, &ret_address);

            //Receive and update the child process delta vma
            msi_handle_rec_vma(&monitor_app.dsm.msi, monitor_app.dsm.socket_fd, 1);

            //Receive and update child process vma
            msi_handle_rec_vma(&monitor_app.dsm.msi, monitor_app.dsm.socket_fd, 0);

            //Receive and update child process regs
            msi_handle_rec_regs(&monitor_app.dsm.msi, monitor_app.dsm.socket_fd, &monitor_app.dsm.msi.regs);

            log_info("The instruction pointer 0x%x", monitor_app.dsm.msi.regs.rip);
        }

    }else{

        struct user_regs_struct usr_reg;
        int i = 1;
        uint64_t address;
        unsigned long old_instructions;
        int delta = 0;

        while(1){
            //Read for request from clients!!
            msi_handle_remote_execution(&monitor_app.dsm.msi, monitor_app.dsm.socket_fd, &address);

            //Receive and update the child process delta vma
            msi_handle_rec_vma(&monitor_app.dsm.msi, monitor_app.dsm.socket_fd, 1);

            //Receive and update child process vma
            msi_handle_rec_vma(&monitor_app.dsm.msi, monitor_app.dsm.socket_fd, 0);

            //Receive and update child process regs
            msi_handle_rec_regs(&monitor_app.dsm.msi, monitor_app.dsm.socket_fd, &monitor_app.dsm.msi.regs);
            
            ret = scan_address_space(monitor_app.dsm.child, &monitor_app.dsm.child.spaces);
            if(ret < 0){
                log_error("Could not scan the address space for read write permissions");
                goto out_stop_fail;
            }else{
                log_info("Overall size of the rw pages are %ld", ret);
            }

            address_spaces delta_spaces;
            delta = find_vma_delta(&monitor_app.dsm.child.spaces , &delta_spaces);

            log_info("Setting the breakpoint at %p", address);
            old_instructions = set_breakpoint(monitor_app.dsm.child.c_pid, (unsigned long)address);
            ptrace(PTRACE_CONT, monitor_app.dsm.child.c_pid, NULL, NULL);
            wait(&ret);
            
            clear_breakpoint(monitor_app.dsm.child.c_pid, address, old_instructions);
            log_info("Application hit the breakpoint %p", address);

            ret = scan_address_space(monitor_app.dsm.child, &monitor_app.dsm.child.spaces);
            if(ret < 0){
                log_error("Could not scan the address space for read write permissions");
                goto out_stop_fail;
            }else{
                log_info("Overall size of the rw pages are %ld", ret);
            }

            delta = find_vma_delta(&monitor_app.dsm.child.spaces , &delta_spaces);

            log_info("Starting the idc communication!!");
            msi_request_remote_execute(&monitor_app.dsm.msi, monitor_app.dsm.socket_fd, 0x00);

            //Grabbing and sending the child process delta vma to remote
            msi_handle_send_vma(&monitor_app.dsm.msi, monitor_app.dsm.socket_fd, delta_spaces, 1);

            //Grabbing and sending the child process vma to remote
            msi_handle_send_vma(&monitor_app.dsm.msi, monitor_app.dsm.socket_fd, monitor_app.dsm.child.spaces, 0);

            //Grabbing and sending the child process registers to remote
            msi_handle_send_regs(&monitor_app.dsm.msi, monitor_app.dsm.socket_fd, &monitor_app.dsm.msi.regs);
        }
    }

    return 0;

out_uffd_thread_fail:
out_dsm_fail:
out_msi_fail:
out_stop_fail:
out_fail:
    //Implement killing the tracee process
    return ret;
}