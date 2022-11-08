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

extern char* __progname;

// Required number of arguments for the application
#define OPT_MANDATORY_COUNT 3

// Starting address for the buffer 
#define BUFFER_ADDRESS 0x10000

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
        char *user_args[] = {"./host/file-encryptorhost", "testfile",  "./enclave/file-encryptorenc.signed",       \
                             "--simulate", NULL};
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
 * @brief Read the number of read-write address space
 * 
 * @param fp 
 * @return int 
 */
static int cnt_rw_address_space(FILE *fp){
    int read_write_addr_cnt = 0;
    char line[128];

    if(!fp)
        return -1;

    while(fgets(line, sizeof(line), fp)){
        char * token = strtok(line, " ");
        int i = 0;
        while(token != NULL){
            //extract the rw-p word from the maps line
            if(i == 1){
                if(strchr(token, 'w') != NULL){
                    //count the number of lines containing the word w in rwxp
                    read_write_addr_cnt++;
                }
                break;
            }
            token = strtok(NULL, " ");
            i++;
        }
    }

    return read_write_addr_cnt;
}

/**
 * @brief Scan and retrieve the address space information of the spaces
 * containing read and write permissions!!
 * 
 * @param child_pid 
 * @return int 
 */
static int scan_address_space(pid_t child_pid, address_spaces *spaces){
    int ret = 0;
    char file_name[50];
    char line[128];
    FILE *fp;
    int read_write_addr_cnt = 0;

    ret = snprintf(file_name, 50, "/proc/%d/maps", child_pid);
    if(ret < 0){
        log_error("failed in finding the maps file for the process %d", child_pid);
        goto get_frame_fail;
    }

    fp = fopen(file_name, "r");
    if(!fp){
        ret = errno;
        goto get_frame_fail;
    }

    read_write_addr_cnt = cnt_rw_address_space(fp);
    if(read_write_addr_cnt == -1){
        log_error("failed in reading the number of rw address spaces");
        ret = read_write_addr_cnt;
        goto get_frame_fail;
    }else{
        fseek(fp, 0, SEEK_SET);
    }
    log_info("There are %d address spaces with read-write permissions", read_write_addr_cnt);

    spaces->space = malloc(sizeof(address_space) * read_write_addr_cnt);
    spaces->size = read_write_addr_cnt;

    ret = 0;
    int iter = 0;
    while(fgets(line, sizeof(line), fp)){
        char * token = strtok(line, " ");
        int i = 0;
        while(token != NULL){
            //extract the rw-p word from the maps line
            if(i == 1){
                if(strchr(token, 'w') != NULL){
                    unsigned long end_address;
                    char *ptr;
                    spaces->space[iter].address =  strtoul(line, &ptr, 16);
                    end_address = strtoul(ptr+1, NULL, 16);
                    spaces->space[iter].size =  (end_address - spaces->space[iter].address)/4096;
                    ret += spaces->space[iter].size;
                    log_info("Found rw address at 0x%lx with a size %ld",                               \
                              spaces->space[iter].address, spaces->space[iter].size);
                    iter++;
                }
                break;
            }
            token = strtok(NULL, " ");
            i++;
        }
    }

    fclose(fp);

    spaces->nr_pages = ret;

    get_frame_fail:
        return ret;
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

    ret = execute_tracee_app(&monitor_app.dsm.child);
    if(ret){
        log_error("failed to execute the tracee app");
        goto out_fail; 
    }

    //Stop the tracee process as soon as possible
    kill(monitor_app.dsm.child.c_pid, SIGSTOP);
    ret =  compel_stop_task(monitor_app.dsm.child.c_pid);
    if(ret < 0){
        log_error("Could not stop the victim for compel infection");
        goto out_stop_fail;
    }

    //setting up the breakpoints
    monitor_app.dsm.child.trpoints.size = 1;
    monitor_app.dsm.child.trpoints.breakpoints = malloc(sizeof(unsigned long) *                         \
                                                        monitor_app.dsm.child.trpoints.size);
    monitor_app.dsm.child.trpoints.old_instructions = malloc(sizeof(long) *                             \
                                                             monitor_app.dsm.child.trpoints.size);
    monitor_app.dsm.child.trpoints.breakpoints[0] = 0x40aaef;
    //monitor_app.dsm.child.trpoints.breakpoints[1] = 0x40aaf4;
    place_breakpoints(monitor_app.dsm.child.c_pid, &monitor_app.dsm.child.trpoints);
    
    ptrace(PTRACE_CONT, monitor_app.dsm.child.c_pid, NULL, NULL);
    wait(&ret);
    log_info("Application hit a breakpoint");
    
    ret = scan_address_space(monitor_app.dsm.child.c_pid, &monitor_app.dsm.child.spaces);
    if(ret < 0){
        log_error("Could not scan the address space for read write permissions");
        goto out_stop_fail;
    }else{
        log_info("Overall size of the rw pages are %ld", ret);
    }

    //Registering for uffd 
    monitor_app.dsm.child.uffd = malloc(sizeof(int) * monitor_app.dsm.child.spaces.size);
    monitor_app.dsm.child.uffd_no = monitor_app.dsm.child.spaces.size;
    for(int i = 0; i < monitor_app.dsm.child.spaces.size; i++){
        log_info("Registering for the address 0x%lx", monitor_app.dsm.child.spaces.space[i].address);
        if(i != 3){
            ret = compel_steal_uffd(&monitor_app.dsm.child,                                       \
                                    &monitor_app.dsm.child.uffd[i],                               \
                                    monitor_app.dsm.child.spaces.space[i].address,                \   
                                    monitor_app.dsm.child.spaces.space[i].size);                  \

            log_info("Registered uffd %d for the address 0x%lx", monitor_app.dsm.child.uffd[i],   \
                      monitor_app.dsm.child.spaces.space[i].address);
        }
    }

    ret = initialize_msi_page(&monitor_app.dsm.msi,                         \
                              monitor_app.buffer,                           \
                              monitor_app.dsm.child.spaces.nr_pages);
    if(ret){
        log_error("Could not initialize msi page");
        goto out_msi_fail;
    }

    ret = dsm_main(&monitor_app.dsm, monitor_app.mode);
    if(ret){
        log_error("Failed to start dsm");
        goto out_dsm_fail;
    }

    monitor_app.uffd_hdl.args.child = &monitor_app.dsm.child;
    monitor_app.uffd_hdl.args.msi = &monitor_app.dsm.msi;
    monitor_app.uffd_hdl.args.sock_fd = monitor_app.dsm.socket_fd;
    ret = start_uffd_thread_handler(&monitor_app.uffd_hdl);
    if(ret){
        log_error("failed to start uffd thread");
        goto out_uffd_thread_fail;
    }

    if(monitor_app.mode == SERVER){
        clear_breakpoint(monitor_app.dsm.child.c_pid, monitor_app.dsm.child.trpoints.breakpoints[0],    \
                            monitor_app.dsm.child.trpoints.old_instructions[0]);
        ptrace(PTRACE_CONT, monitor_app.dsm.child.c_pid, NULL, NULL);
        //wait(&ret);
        //log_info("Client hit a breakpoint %p\n", monitor_app.dsm.child.trpoints.breakpoints[0]);
    }
    while(1);

    return 0;

out_uffd_thread_fail:
out_dsm_fail:
out_msi_fail:
out_stop_fail:
out_fail:
    //Implement killing the tracee process
    return ret;
}