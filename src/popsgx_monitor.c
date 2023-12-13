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

#include <cjson/cJSON.h>

#define log_info(args...) 

extern char* __progname;

// Required number of arguments for the application
#define OPT_MANDATORY_COUNT 4

// Starting address for the buffer 
#define BUFFER_ADDRESS 0x10000

// Helloworld main function address 
#ifdef HELLOWORLD
#define MAIN 0x43ed80
#elif SWITCHLESS
#define MAIN 0x443d00
#elif DEBUGMALLOC
#define MAIN 0x43ed80
#elif LOGCALLBACK
#define MAIN 0x441d70
#elif APKMAN
#define MAIN 0x43e980
#elif DATASEALING
#define MAIN 0x407b80
#elif PLUGGABLEALLOCATOR
#define MAIN 0x43e8b0
#elif  MICROBENCH
#define MAIN 0x43d9a0
#elif VIRTUAL_ASSISTANT
#define MAIN 0x1d595
#elif TRUST_FL
#define CODE_OFFSET 0x555555554000
#define MAIN CODE_OFFSET + 0x27c0
#elif SQLITE
#define CODE_OFFSET 0x555555554000
#define MAIN CODE_OFFSET + 0x2580
#elif SQLITEB
#define CODE_OFFSET 0x555555554000
#define MAIN CODE_OFFSET + 0x2860
#elif SGX_SSL
#define CODE_OFFSET 0x555555554000
#define MAIN CODE_OFFSET + 0x344d
#elif PORPOISE_H20
#define CODE_OFFSET 0x555555554000
#define MAIN CODE_OFFSET + 0x550d
#elif SGX_DNET
#define CODE_OFFSET 0x555555554000
#define MAIN CODE_OFFSET + 0x3e30
#elif PLINIUS
#define CODE_OFFSET 0x555555554000
#define MAIN CODE_OFFSET + 0x4b4a
#elif REMOTE_ATTEST
#define CODE_OFFSET 0x555555554000
#define MAIN CODE_OFFSET + 0x2eda
#endif

address_spaces uffd_stat_snapshot;

popsgx_app monitor_app;

#ifdef PROFILE
unsigned long no_cmpl_inj = 0;
unsigned long no_ptrace_calls = 0;
unsigned long no_prr_calls = 0;
unsigned long no_pg_trans = 0;
unsigned long sync_messages = 0;
unsigned long no_migrations = 0;
#endif

/**
 * @brief Printing the help message
 * 
 */
static void usage(void)
{
    log_info("\n"
             "usage: %s [-m mode | -c confi_file | -r remote-node-ip | -p remote-node-port | -t host-port ]"
             "\n"
             "options:\n"
             "\t-m mode of the popsgx_monitor application [server|cient]\n"
             "\t-r remote node's ip-address for dsm\n"
             "\t-p remote node's port-number for dsm\n"
             "\t-t host's port-number\n"
             "\t-c configuration file\n"
             "\t-h help"
             "\n",
             __progname);
    exit(EXIT_SUCCESS);
}

/*
 * @brief This is a signal handler for the process
 *
 */
void signal_handler(int signo){
    if(signo == SIGTERM || signo == SIGINT){
        close(monitor_app.dsm.socket_fd);
	exit(0);
    }
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
    long ret = 0;
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

    ptrace(PTRACE_SETOPTIONS, cpid, NULL, PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT | PTRACE_O_TRACECLONE);

    //Set a breakpoint to stop at the main function
    long main_data = set_breakpoint(cpid,  addr);
    
    ret = ptrace(PTRACE_CONT, cpid, NULL, NULL);
    
    wait(&wait_status);

    clear_breakpoint(cpid, addr, main_data);

    ret = ptrace(PTRACE_DETACH, cpid, NULL, NULL);
}

/**
 * @brief Execute the tracee application 
 * 
 * @param tracee 
 * @return int 
 */
static int execute_tracee_app(popsgx_child *tracee, char **user_args){
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
            return -1;
        }

#ifdef HELLOWORLD
        char *user_args[] = {"host/helloworld_host", "./enclave/enclave.signed",       \
                             NULL};
#elif FILEENCRYPT
        char *user_args[] = {"./host/file-encryptorhost", "testfile",  "./enclave/file-encryptorenc.signed", \
                             NULL};
#elif SWITCHLESS
        char *user_args[] = {"host/switchlesshost", "./enclave/switchlessenc.signed",       \
                              NULL};
#elif PLUGGABLEALLOCATOR
        char *user_args[] = {"./host/allocator_demo_host", "./enclave/enclave_default.signed",  "./enclave/enclave_custom.signed",   \
                             "--simulate", NULL};
#elif DEBUGMALLOC
        char *user_args[] = {"./host/debugmallochost", "./enclave/debugmallocenc.signed",   \
                             NULL};
#elif LOGCALLBACK
        char *user_args[] = {"host/log_callbackhost", "./enclave/log_callbackenc.signed",   \
                             NULL};
#elif APKMAN
        char *user_args[] = {"host/sqlite_host", "./enclave/enclave.signed",   \
                             NULL};

#elif DATASEALING
        char *user_args[] = {"host/host", "./enclave_a_v1/enclave.signed",   \
                             "enclave_a_v2/enclave.signed", "enclave_b/enclave.signed", NULL};
#elif MICROBENCH
        char *user_args[] = {"host/microbenchhost", "./enclave/microbenchenc.signed", NULL};

#elif VIRTUAL_ASSISTANT
        char *user_args[] = {"./host/build/virtual_assistant", "./virtualenc.signed", NULL};

#elif TRUST_FL 
        char *user_args[] = {"./trust_fl", NULL};

#elif SQLITE
        char *user_args[] = {"./app", "test.db", NULL};

#elif SQLITEB
        char *user_args[] = {"./app", "--benchmarks=overwrite", "--num=1", NULL};

#elif SGX_SSL
        char *user_args[] = {"./app", NULL};

#elif PORPOISE_H20
        char *user_args[] = {"./h2o", "--version", NULL};

#elif SGX_DNET
        char *user_args[] = {"./app", NULL};

#elif PLINIUS
        char *user_args[] = {"./plinius", NULL};

#elif REMOTE_ATTEST
	char *user_args[] = {"./app", NULL};

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


/**
 * @brief Parse the configuration file in Json Format
 * 
 * @param json_file_path configuration file
 * @param args argument for the client application
*/
static int parse_json_config(const char *json_file_path, client_args *args, tracepoints *trc_points, uintptr_t *main_address){
    // Open the JSON file for reading
    FILE *file = fopen(json_file_path, "r");
    if (!file) {
        perror("Error opening JSON file");
        return 1;
    }

    // Read the JSON data from the file
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    char *json_data = (char *)malloc(file_size + 1);
    if (!json_data) {
        perror("Memory allocation error");
        fclose(file);
        return 1;
    }

    fread(json_data, 1, file_size, file);
    json_data[file_size] = '\0';
    fclose(file);

    // Parse the JSON data
    cJSON *root = cJSON_Parse(json_data);

    if (root == NULL) {
        perror("Error parsing JSON data.\n");
        free(json_data);
        return 1;
    }

    // Access the user_args and breakpoints arrays
    cJSON *userArgsArray = cJSON_GetObjectItem(root, "user_args");
    cJSON *breakpointsArray = cJSON_GetObjectItem(root, "breakpoints");
    cJSON *mainAddressItem = cJSON_GetObjectItem(root, "main_address");

    if(userArgsArray != NULL && args != NULL){
        args->num_args = cJSON_GetArraySize(userArgsArray);
        args->user_args = (char**)malloc(sizeof(char*) * args->num_args);
        if (args->user_args == NULL) {
                perror("Memory allocation error");
                return 1;
        }
    }else{
        perror("user_args not given!!");
        return 1;
    }

    if (mainAddressItem != NULL && cJSON_IsString(mainAddressItem)) {
       *main_address = (uintptr_t)strtoull(mainAddressItem->valuestring, NULL, 16);
    }else{
       perror("main_address not given!!");
       return 1;
    }

    if(breakpointsArray != NULL && trc_points != NULL){
        trc_points->size = cJSON_GetArraySize(breakpointsArray);
        trc_points->breakpoints = malloc(sizeof(unsigned long int) *                                                      \
                                                        cJSON_GetArraySize(breakpointsArray));
        if(trc_points->breakpoints == NULL){
            perror("Memory allocation error");
            return 1;
        }
        trc_points->old_instructions = malloc(sizeof(unsigned long int) *                                                 \
                                                        cJSON_GetArraySize(breakpointsArray));
        if(trc_points->old_instructions == NULL){
            perror("Memory allocation error");
            return 1;
        }
    }else{
        perror("breakpointsArray not given!!");
        return 1;
    }

    if (userArgsArray != NULL && breakpointsArray != NULL) {
        // Iterate through the user_args array
        for (int i = 0; i < cJSON_GetArraySize(userArgsArray); i++) {
            cJSON *item = cJSON_GetArrayItem(userArgsArray, i);
            if (cJSON_IsString(item)) {
                args->user_args[i] = strdup(item->valuestring);
                if (args->user_args[i] == NULL) {
                        perror("Memory allocation error");
                        return 1;
                }
            }
        }

        // Iterate through the breakpoints array
        for (int i = 0; i < cJSON_GetArraySize(breakpointsArray); i++) {
            cJSON *item = cJSON_GetArrayItem(breakpointsArray, i);
            if (cJSON_IsString(item)) {
	        char *endptr;
                trc_points->breakpoints[i] = strtol(item->valuestring, &endptr, 16);
                trc_points->old_instructions[i] = strtol(item->valuestring, &endptr, 16);
		if (*endptr != '\0') {
        		perror("Conversion error: Invalid characters found.\n");
    		} else {
        		log_info("Integer value: %lx\n", trc_points->breakpoints[i]);
    		}
            }
        }
    } else {
        perror("Error accessing JSON arrays.\n");
    }

    // Free memory
    free(json_data);
    cJSON_Delete(root);

    return 0;
}

int main(int argc, char *argv[]){
    int ret = 0;
    int opt, opt_counter = 0;
    char *mode = NULL;
    const char* config_file_path = NULL;
    client_args uargs;
    uintptr_t main_address;

    memset(&monitor_app, 0, sizeof(popsgx_app));
    monitor_app.buffer = BUFFER_ADDRESS;

    printf("Testing\n");
    /*
     *  Parse the arguments
     */
    struct option long_opt[] =
    {
        {       "mode", required_argument, NULL, 'm'},
        {  "remote_ip", required_argument, NULL, 'r'},
        {"remote_port", required_argument, NULL, 'p'},
        {  "host_port", required_argument, NULL, 't'},
        {"config_file", required_argument, NULL, 'c'},
        {         NULL,                 0, NULL,  0 }
    };
    
    while((opt = getopt_long(argc, argv, "hr:p:t:m:c:", long_opt, NULL)) != -1){
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
        
        case 'c':
            config_file_path = optarg;
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

    //Parse the Json config file
    ret = parse_json_config(config_file_path, &uargs, &monitor_app.dsm.child.trpoints, &main_address);
    if(ret){
        log_error("failed to parse the config file");
        return EXIT_FAILURE;
    }

    //Execute and Wait for the child at main instruction
    ret = execute_tracee_app(&monitor_app.dsm.child, uargs.user_args);
    if(ret){
        log_error("failed to execute the tracee app");
        goto out_fail; 
    }

    wait_child_main(monitor_app.dsm.child.c_pid, main_address);

    //This gets resumed when we steal uffd
#ifdef PROFILE
    no_ptrace_calls += 1;
#endif

    ret =  compel_stop_task(monitor_app.dsm.child.c_pid);
    if(ret < 0){
        log_error("Could not stop the victim for compel infection");
        goto out_stop_fail;
    }
    
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
    
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);

    log_info("Connection established!!");
    
    //Grabbing the heap address
    get_virtual_address_frame_by_name(monitor_app.dsm.child.c_pid, &monitor_app.dsm.child.heap_start_address, &monitor_app.dsm.child.heap_end_address, "[heap]");


#ifdef HELLOWORLD
    //Hello world
    monitor_app.dsm.child.trpoints.breakpoints[0] = 0x43eef2;
    monitor_app.dsm.child.trpoints.breakpoints[1] = 0x43eef7;
    monitor_app.dsm.child.trpoints.breakpoints[2] = 0x43efd0;
    monitor_app.dsm.child.trpoints.breakpoints[3] = 0x43efd5;
    monitor_app.dsm.child.trpoints.breakpoints[4] = 0x43f10d;
    monitor_app.dsm.child.trpoints.breakpoints[5] = 0x43f112;
    #define LIMIT 5

#elif SWITCHLESS
    monitor_app.dsm.child.trpoints.breakpoints[0]  = 0x443f6c;
    monitor_app.dsm.child.trpoints.breakpoints[1]  = 0x443f71;
    monitor_app.dsm.child.trpoints.breakpoints[2]  = 0x444074;
    monitor_app.dsm.child.trpoints.breakpoints[3]  = 0x444079;
    monitor_app.dsm.child.trpoints.breakpoints[4]  = 0x444251;
    monitor_app.dsm.child.trpoints.breakpoints[5]  = 0x444256;
    monitor_app.dsm.child.trpoints.breakpoints[6]  = 0x444453;
    monitor_app.dsm.child.trpoints.breakpoints[7]  = 0x444458;
    monitor_app.dsm.child.trpoints.breakpoints[8]  = 0x4446ab;
    monitor_app.dsm.child.trpoints.breakpoints[9]  = 0x4446b0;
    monitor_app.dsm.child.trpoints.breakpoints[10] = 0x4448b1;
    monitor_app.dsm.child.trpoints.breakpoints[11] = 0x4448b6;
    #define LIMIT 11

#elif PLUGGABLEALLOCATOR
    monitor_app.dsm.child.trpoints.breakpoints[0] = 0x43f236;
    monitor_app.dsm.child.trpoints.breakpoints[1] = 0x43f23b;
    monitor_app.dsm.child.trpoints.breakpoints[2] = 0x440840;
    monitor_app.dsm.child.trpoints.breakpoints[3] = 0x440845;
    monitor_app.dsm.child.trpoints.breakpoints[4] = 0x43f964;
    monitor_app.dsm.child.trpoints.breakpoints[5] = 0x43f969;
    #define LIMIT 5

#elif LOGCALLBACK
    monitor_app.dsm.child.trpoints.breakpoints[0] = 0x441f9f;
    monitor_app.dsm.child.trpoints.breakpoints[1] = 0x441fa4;
    monitor_app.dsm.child.trpoints.breakpoints[2] = 0x4420ba;
    monitor_app.dsm.child.trpoints.breakpoints[3] = 0x4420bf;
    monitor_app.dsm.child.trpoints.breakpoints[4] = 0x44208c;
    monitor_app.dsm.child.trpoints.breakpoints[5] = 0x442091;
    monitor_app.dsm.child.trpoints.breakpoints[6] = 0x44224e;
    monitor_app.dsm.child.trpoints.breakpoints[7] = 0x442253;
    #define LIMIT 7

#elif DEBUGMALLOC
    monitor_app.dsm.child.trpoints.breakpoints[0] = 0x43eef2;
    monitor_app.dsm.child.trpoints.breakpoints[1] = 0x43eef7;
    monitor_app.dsm.child.trpoints.breakpoints[2] = 0x43efd0;
    monitor_app.dsm.child.trpoints.breakpoints[3] = 0x43efd5;
    monitor_app.dsm.child.trpoints.breakpoints[4] = 0x43f10d;
    monitor_app.dsm.child.trpoints.breakpoints[5] = 0x43f112;
    #define LIMIT 5

#elif APKMAN
    monitor_app.dsm.child.trpoints.breakpoints[0] = 0x43eaf9;
    monitor_app.dsm.child.trpoints.breakpoints[1] = 0x43eafe;
    monitor_app.dsm.child.trpoints.breakpoints[2] = 0x43ebda;
    monitor_app.dsm.child.trpoints.breakpoints[3] = 0x43ebdf;
    monitor_app.dsm.child.trpoints.breakpoints[4] = 0x43ed17;
    monitor_app.dsm.child.trpoints.breakpoints[5] = 0x43ed1c;
    #define LIMIT 5

#elif DATASEALING
    monitor_app.dsm.child.trpoints.breakpoints[0] = 0x40632b;
    monitor_app.dsm.child.trpoints.breakpoints[1] = 0x406330;
    monitor_app.dsm.child.trpoints.breakpoints[2] = 0x406ecd;
    monitor_app.dsm.child.trpoints.breakpoints[3] = 0x406ed2;
    monitor_app.dsm.child.trpoints.breakpoints[4] = 0x406614;
    monitor_app.dsm.child.trpoints.breakpoints[5] = 0x406619;
    monitor_app.dsm.child.trpoints.breakpoints[6] = 0x40854b;
    monitor_app.dsm.child.trpoints.breakpoints[7] = 0x408550;
    monitor_app.dsm.child.trpoints.breakpoints[8] = 0x4085c4;
    monitor_app.dsm.child.trpoints.breakpoints[9] = 0x4085c9;
    monitor_app.dsm.child.trpoints.breakpoints[10] = 0x40863d;
    monitor_app.dsm.child.trpoints.breakpoints[11] = 0x408642;
    #define LIMIT 11

#elif MICROBENCH
    monitor_app.dsm.child.trpoints.breakpoints[0] = 0x43daa3;
    monitor_app.dsm.child.trpoints.breakpoints[1] = 0x43daa8;
    monitor_app.dsm.child.trpoints.breakpoints[2] = 0x43dcb9;
    monitor_app.dsm.child.trpoints.breakpoints[3] = 0x43dcbe;
    monitor_app.dsm.child.trpoints.breakpoints[4] = 0x43de2d;
    monitor_app.dsm.child.trpoints.breakpoints[5] = 0x43de32;
    #define LIMIT 5

#elif VIRTUAL_ASSISTANT
    monitor_app.dsm.child.trpoints.breakpoints[0] = 0x1c937;
    monitor_app.dsm.child.trpoints.breakpoints[1] = 0x1c93c;
    monitor_app.dsm.child.trpoints.breakpoints[2] = 0x1caa5;
    monitor_app.dsm.child.trpoints.breakpoints[3] = 0x1caaa;
    monitor_app.dsm.child.trpoints.breakpoints[4] = 0x1cb3b;
    monitor_app.dsm.child.trpoints.breakpoints[5] = 0x1cb40;
    #define LIMIT 5

#elif TRUST_FL
    //sgx_create_enclave
    monitor_app.dsm.child.trpoints.breakpoints[0] = CODE_OFFSET + 0x2cee;
    monitor_app.dsm.child.trpoints.breakpoints[1] = CODE_OFFSET + 0x2cf3;
    //call ecall_get_seed
    monitor_app.dsm.child.trpoints.breakpoints[2] = CODE_OFFSET + 0x2dd8;
    monitor_app.dsm.child.trpoints.breakpoints[3] = CODE_OFFSET + 0x2ddd;
    //call ecall_init
    monitor_app.dsm.child.trpoints.breakpoints[4] = CODE_OFFSET + 0x2d70;
    monitor_app.dsm.child.trpoints.breakpoints[5] = CODE_OFFSET + 0x2d9c;
    //call ecall_data_process
    monitor_app.dsm.child.trpoints.breakpoints[6] = CODE_OFFSET + 0x3793;
    monitor_app.dsm.child.trpoints.breakpoints[7] = CODE_OFFSET + 0x3798;
    //call ecall_param_preprocess
    monitor_app.dsm.child.trpoints.breakpoints[8] = CODE_OFFSET + 0x3d77;
    monitor_app.dsm.child.trpoints.breakpoints[9] = CODE_OFFSET + 0x3d86;
    //call ecall_ml_vgg16
    monitor_app.dsm.child.trpoints.breakpoints[10] = CODE_OFFSET + 0x2810;
    monitor_app.dsm.child.trpoints.breakpoints[11] = CODE_OFFSET + 0x2815;
    //sgx_destroy_enclave
    monitor_app.dsm.child.trpoints.breakpoints[12] = CODE_OFFSET + 0x2828;
    monitor_app.dsm.child.trpoints.breakpoints[13] = CODE_OFFSET + 0x282d;
    #define LIMIT 13

#elif SQLITE
    //sgx_create_enclave
    monitor_app.dsm.child.trpoints.breakpoints[0] = CODE_OFFSET + 0x25fb;
    monitor_app.dsm.child.trpoints.breakpoints[1] = CODE_OFFSET + 0x2600;
    //opendb
    monitor_app.dsm.child.trpoints.breakpoints[2] = CODE_OFFSET + 0x2634;
    monitor_app.dsm.child.trpoints.breakpoints[3] = CODE_OFFSET + 0x2639;

    //execute_sql
    monitor_app.dsm.child.trpoints.breakpoints[4] = CODE_OFFSET + 0x26eb;
    monitor_app.dsm.child.trpoints.breakpoints[5] = CODE_OFFSET + 0x26f0;

    //close_db
    monitor_app.dsm.child.trpoints.breakpoints[6] = CODE_OFFSET + 0x2767;
    monitor_app.dsm.child.trpoints.breakpoints[7] = CODE_OFFSET + 0x276c;
    //destroy
    monitor_app.dsm.child.trpoints.breakpoints[8] = CODE_OFFSET + 0x2775;
    monitor_app.dsm.child.trpoints.breakpoints[9] = CODE_OFFSET + 0x277a;
    #define LIMIT 9

 #elif SQLITEB
    //sgx_create_enclave
    monitor_app.dsm.child.trpoints.breakpoints[0] = CODE_OFFSET + 0x292a;
    monitor_app.dsm.child.trpoints.breakpoints[1] = CODE_OFFSET + 0x292f;
    
    //ecall_sqlite3_prepare_v21
    monitor_app.dsm.child.trpoints.breakpoints[2] = CODE_OFFSET + 0x4d18;
    monitor_app.dsm.child.trpoints.breakpoints[3] = CODE_OFFSET + 0x4d1d;
    
    //ecall_sqlite3_prepare_v22
    monitor_app.dsm.child.trpoints.breakpoints[4] = CODE_OFFSET + 0x4d2e;
    monitor_app.dsm.child.trpoints.breakpoints[5] = CODE_OFFSET + 0x4d33;

    monitor_app.dsm.child.trpoints.breakpoints[6] = CODE_OFFSET + 0x50a5;
    monitor_app.dsm.child.trpoints.breakpoints[7] = CODE_OFFSET + 0x50aa;
    
    //ecall_sqlite3_prepare_v23
    monitor_app.dsm.child.trpoints.breakpoints[8] = CODE_OFFSET + 0x4d44;
    monitor_app.dsm.child.trpoints.breakpoints[9] = CODE_OFFSET + 0x4d49;
    
    monitor_app.dsm.child.trpoints.breakpoints[10] = CODE_OFFSET + 0x50bd;
    monitor_app.dsm.child.trpoints.breakpoints[11] = CODE_OFFSET + 0x50c2;

    //ecall_sqlite3_prepare_v24
    monitor_app.dsm.child.trpoints.breakpoints[12] = CODE_OFFSET + 0x50d7;
    monitor_app.dsm.child.trpoints.breakpoints[13] = CODE_OFFSET + 0x50dc;
    
    //ecall_sqlite3_step2 
    monitor_app.dsm.child.trpoints.breakpoints[14] = CODE_OFFSET + 0x4f8c;
    monitor_app.dsm.child.trpoints.breakpoints[15] = CODE_OFFSET + 0x4f91;
    
    monitor_app.dsm.child.trpoints.breakpoints[16] = CODE_OFFSET + 0x52ab;
    monitor_app.dsm.child.trpoints.breakpoints[17] = CODE_OFFSET + 0x52b0;

    //ecall_sqlite3_step3
    monitor_app.dsm.child.trpoints.breakpoints[18] = CODE_OFFSET + 0x4eef;
    monitor_app.dsm.child.trpoints.breakpoints[19] = CODE_OFFSET + 0x4ef4;
    
    monitor_app.dsm.child.trpoints.breakpoints[20] = CODE_OFFSET + 0x52e7;
    monitor_app.dsm.child.trpoints.breakpoints[21] = CODE_OFFSET + 0x52ec;

    //ecall_sqlite3_step1
    monitor_app.dsm.child.trpoints.breakpoints[22] = CODE_OFFSET + 0x4e66;
    monitor_app.dsm.child.trpoints.breakpoints[23] = CODE_OFFSET + 0x4e6b;

    //ecall_sqlite3_step4
    monitor_app.dsm.child.trpoints.breakpoints[24] = CODE_OFFSET + 0x519a;
    monitor_app.dsm.child.trpoints.breakpoints[25] = CODE_OFFSET + 0x519f;

    //ecall_sqlite3_clear_bindings1
    monitor_app.dsm.child.trpoints.breakpoints[26] = CODE_OFFSET + 0x4e72;
    monitor_app.dsm.child.trpoints.breakpoints[27] = CODE_OFFSET + 0x4e77;

    //ecall_sqlite3_clear_bindings4
    monitor_app.dsm.child.trpoints.breakpoints[28] = CODE_OFFSET + 0x51ad;
    monitor_app.dsm.child.trpoints.breakpoints[29] = CODE_OFFSET + 0x51b2;

    //ecall_wal_checkpoint_v2
    monitor_app.dsm.child.trpoints.breakpoints[30] = CODE_OFFSET + 0x5922;
    monitor_app.dsm.child.trpoints.breakpoints[31] = CODE_OFFSET + 0x5927;

    //ecall_sqlite3_finalize1
    monitor_app.dsm.child.trpoints.breakpoints[32] = CODE_OFFSET + 0x4f24;
    monitor_app.dsm.child.trpoints.breakpoints[33] = CODE_OFFSET + 0x4f29;

    //ecall_sqlite3_finalize2
    monitor_app.dsm.child.trpoints.breakpoints[34] = CODE_OFFSET + 0x4f3a;
    monitor_app.dsm.child.trpoints.breakpoints[35] = CODE_OFFSET + 0x4f3f;
    
    monitor_app.dsm.child.trpoints.breakpoints[36] = CODE_OFFSET + 0x522c;
    monitor_app.dsm.child.trpoints.breakpoints[37] = CODE_OFFSET + 0x5231;

    //ecall_sqlite3_finalize3
    monitor_app.dsm.child.trpoints.breakpoints[38] = CODE_OFFSET + 0x4f50;
    monitor_app.dsm.child.trpoints.breakpoints[39] = CODE_OFFSET + 0x4f55;
    
    monitor_app.dsm.child.trpoints.breakpoints[40] = CODE_OFFSET + 0x5246;
    monitor_app.dsm.child.trpoints.breakpoints[41] = CODE_OFFSET + 0x524b;

    //ecall_sqlite3_finalize4
    monitor_app.dsm.child.trpoints.breakpoints[42] = CODE_OFFSET + 0x5212;
    monitor_app.dsm.child.trpoints.breakpoints[43] = CODE_OFFSET + 0x5217;

    //ecall_sqlite3_reset3
    monitor_app.dsm.child.trpoints.breakpoints[44] = CODE_OFFSET + 0x4efb;
    monitor_app.dsm.child.trpoints.breakpoints[45] = CODE_OFFSET + 0x4f00;
    
    monitor_app.dsm.child.trpoints.breakpoints[46] = CODE_OFFSET + 0x52f7;
    monitor_app.dsm.child.trpoints.breakpoints[47] = CODE_OFFSET + 0x52fc;

    //ecall_sqlite3_reset4
    monitor_app.dsm.child.trpoints.breakpoints[48] = CODE_OFFSET + 0x51c5;
    monitor_app.dsm.child.trpoints.breakpoints[48] = CODE_OFFSET + 0x51ca;

    //ecall_sqlite3_reset1
    monitor_app.dsm.child.trpoints.breakpoints[50] = CODE_OFFSET + 0x4e86;
    monitor_app.dsm.child.trpoints.breakpoints[51] = CODE_OFFSET + 0x4e8b;

    //ecall_sqlite3_reset2
    monitor_app.dsm.child.trpoints.breakpoints[52] = CODE_OFFSET + 0x4fa1;
    monitor_app.dsm.child.trpoints.breakpoints[53] = CODE_OFFSET + 0x4fa6;
    
    monitor_app.dsm.child.trpoints.breakpoints[54] = CODE_OFFSET + 0x52c6;
    monitor_app.dsm.child.trpoints.breakpoints[55] = CODE_OFFSET + 0x52cb;

    //ecall_sqlite3_bind_blob1
    monitor_app.dsm.child.trpoints.breakpoints[56] = CODE_OFFSET + 0x4ded;
    monitor_app.dsm.child.trpoints.breakpoints[57] = CODE_OFFSET + 0x4df2;
    
    monitor_app.dsm.child.trpoints.breakpoints[58] = CODE_OFFSET + 0x4e0c;
    monitor_app.dsm.child.trpoints.breakpoints[59] = CODE_OFFSET + 0x4e11;

    //ecall_sqlite3_bind_blob4
    monitor_app.dsm.child.trpoints.breakpoints[60] = CODE_OFFSET + 0x5172;
    monitor_app.dsm.child.trpoints.breakpoints[61] = CODE_OFFSET + 0x5177;

    //ecall_opendb
    monitor_app.dsm.child.trpoints.breakpoints[62] = CODE_OFFSET + 0x4acc;
    monitor_app.dsm.child.trpoints.breakpoints[63] = CODE_OFFSET + 0x4ad1;

    //ecall_execute_sql
    monitor_app.dsm.child.trpoints.breakpoints[64] = CODE_OFFSET + 0x4b12;
    monitor_app.dsm.child.trpoints.breakpoints[65] = CODE_OFFSET + 0x4b17;
    
    monitor_app.dsm.child.trpoints.breakpoints[66] = CODE_OFFSET + 0x4b6b;
    monitor_app.dsm.child.trpoints.breakpoints[67] = CODE_OFFSET + 0x4b70;
    
    monitor_app.dsm.child.trpoints.breakpoints[68] = CODE_OFFSET + 0x4b87;
    monitor_app.dsm.child.trpoints.breakpoints[69] = CODE_OFFSET + 0x4b8c;
    
    monitor_app.dsm.child.trpoints.breakpoints[70] = CODE_OFFSET + 0x4c1a;
    monitor_app.dsm.child.trpoints.breakpoints[71] = CODE_OFFSET + 0x4c1f;
    
    monitor_app.dsm.child.trpoints.breakpoints[72] = CODE_OFFSET + 0x4c37;
    monitor_app.dsm.child.trpoints.breakpoints[73] = CODE_OFFSET + 0x4c3c;
    
    monitor_app.dsm.child.trpoints.breakpoints[74] = CODE_OFFSET + 0x4c4e;
    monitor_app.dsm.child.trpoints.breakpoints[75] = CODE_OFFSET + 0x4c53;
    
    monitor_app.dsm.child.trpoints.breakpoints[76] = CODE_OFFSET + 0x4d04;
    monitor_app.dsm.child.trpoints.breakpoints[77] = CODE_OFFSET + 0x4d09;
    
    //ecall_closedb
    monitor_app.dsm.child.trpoints.breakpoints[78] = CODE_OFFSET + 0x4cbd;
    monitor_app.dsm.child.trpoints.breakpoints[79] = CODE_OFFSET + 0x4cc2;
    
    monitor_app.dsm.child.trpoints.breakpoints[80] = CODE_OFFSET + 0x4a3f;
    monitor_app.dsm.child.trpoints.breakpoints[81] = CODE_OFFSET + 0x4a44;

    //sgx_destroy_enclave
    monitor_app.dsm.child.trpoints.breakpoints[82] = CODE_OFFSET + 0x2a8c;
    monitor_app.dsm.child.trpoints.breakpoints[83] = CODE_OFFSET + 0x2a91;

    #define LIMIT 83

#elif SGX_SSL
    //sgx_create_enclave
    monitor_app.dsm.child.trpoints.breakpoints[0] = CODE_OFFSET + 0x3460;
    monitor_app.dsm.child.trpoints.breakpoints[1] = CODE_OFFSET + 0x3465;
    
    //ecall_start_tls_client
    monitor_app.dsm.child.trpoints.breakpoints[2] = CODE_OFFSET + 0x3491;
    monitor_app.dsm.child.trpoints.breakpoints[3] = CODE_OFFSET + 0x3496;
    
    //SGX_DESTROY_ENCLAVE
    monitor_app.dsm.child.trpoints.breakpoints[4] = CODE_OFFSET + 0x34a3;
    monitor_app.dsm.child.trpoints.breakpoints[5] = CODE_OFFSET + 0x34a8;

    #define LIMIT 5

#elif PORPOISE_H20
    //sgx_create_enclave
    monitor_app.dsm.child.trpoints.breakpoints[0] = CODE_OFFSET + 0x5350;
    monitor_app.dsm.child.trpoints.breakpoints[1] = CODE_OFFSET + 0x5355;

    //ecall_init_transfer
    monitor_app.dsm.child.trpoints.breakpoints[2] = CODE_OFFSET + 0x53af;
    monitor_app.dsm.child.trpoints.breakpoints[3] = CODE_OFFSET + 0x53b4;
    
    //ecall_shim_main
    monitor_app.dsm.child.trpoints.breakpoints[4] = CODE_OFFSET + 0x5585;
    monitor_app.dsm.child.trpoints.breakpoints[5] = CODE_OFFSET + 0x558a;
    
    //ecall_sig_handler
    monitor_app.dsm.child.trpoints.breakpoints[6] = CODE_OFFSET + 0x15e4;
    monitor_app.dsm.child.trpoints.breakpoints[7] = CODE_OFFSET + 0x162e;

    //ecall_start_routine
    monitor_app.dsm.child.trpoints.breakpoints[8] = CODE_OFFSET + 0x54d8;
    monitor_app.dsm.child.trpoints.breakpoints[9] = CODE_OFFSET + 0x54dd;

    //ecall_destroy_enclave
    monitor_app.dsm.child.trpoints.breakpoints[10] = CODE_OFFSET + 0x5440;
    monitor_app.dsm.child.trpoints.breakpoints[11] = CODE_OFFSET + 0x5445;

    #define LIMIT 11

#elif SGX_DNET
    //sgx_create_enclave
    monitor_app.dsm.child.trpoints.breakpoints[0] = CODE_OFFSET + 0x4642;
    monitor_app.dsm.child.trpoints.breakpoints[1] = CODE_OFFSET + 0x4647;

    //sgx_ecall_trainer
    monitor_app.dsm.child.trpoints.breakpoints[2] = CODE_OFFSET + 0x4812;
    monitor_app.dsm.child.trpoints.breakpoints[3] = CODE_OFFSET + 0x4817;

    //sgx_ecall_tester
    monitor_app.dsm.child.trpoints.breakpoints[4] = CODE_OFFSET + 0x4a5a;
    monitor_app.dsm.child.trpoints.breakpoints[5] = CODE_OFFSET + 0x4a5f;

    //sgx_ecall_classify
    monitor_app.dsm.child.trpoints.breakpoints[6] = CODE_OFFSET + 0x45d5;
    monitor_app.dsm.child.trpoints.breakpoints[7] = CODE_OFFSET + 0x45da;

    //sgx_destroy_enclave
    monitor_app.dsm.child.trpoints.breakpoints[8] = CODE_OFFSET + 0x3e54;
    monitor_app.dsm.child.trpoints.breakpoints[9] = CODE_OFFSET + 0x3e59;

    #define LIMIT 9

#elif PLINIUS
    //sgx_create_enclave
    monitor_app.dsm.child.trpoints.breakpoints[0] = CODE_OFFSET + 0x4b24;
    monitor_app.dsm.child.trpoints.breakpoints[1] = CODE_OFFSET + 0x4b29;

    //rom_init()
    monitor_app.dsm.child.trpoints.breakpoints[18] = CODE_OFFSET + 0x4b9c;
    monitor_app.dsm.child.trpoints.breakpoints[19] = CODE_OFFSET + 0x4ba1;

    //ecall_init
    monitor_app.dsm.child.trpoints.breakpoints[2] = CODE_OFFSET + 0x4be3;
    monitor_app.dsm.child.trpoints.breakpoints[3] = CODE_OFFSET + 0x4be8;

    //ecall_nvram_worker not called
    monitor_app.dsm.child.trpoints.breakpoints[4] = CODE_OFFSET + 0x414a;
    monitor_app.dsm.child.trpoints.breakpoints[5] = CODE_OFFSET + 0x41b8;

    //empty_ecall not called
    monitor_app.dsm.child.trpoints.breakpoints[6] = CODE_OFFSET + 0x41b9;
    monitor_app.dsm.child.trpoints.breakpoints[7] = CODE_OFFSET + 0x41e9;

    //ecall_trainer
    monitor_app.dsm.child.trpoints.breakpoints[8] = CODE_OFFSET + 0x483e;
    monitor_app.dsm.child.trpoints.breakpoints[9] = CODE_OFFSET + 0x4843;

    //ecall_tester
    monitor_app.dsm.child.trpoints.breakpoints[10] = CODE_OFFSET + 0x49c8;
    monitor_app.dsm.child.trpoints.breakpoints[11] = CODE_OFFSET + 0x49cd;

    //ecall_classify not called
    monitor_app.dsm.child.trpoints.breakpoints[12] = CODE_OFFSET + 0x42f0;
    monitor_app.dsm.child.trpoints.breakpoints[13] = CODE_OFFSET + 0x436d;
    
    //ecall_set_data not called
    monitor_app.dsm.child.trpoints.breakpoints[14] = CODE_OFFSET + 0x436e;
    monitor_app.dsm.child.trpoints.breakpoints[15] = CODE_OFFSET + 0x43bb;
    
    //destroy_enclave
    monitor_app.dsm.child.trpoints.breakpoints[16] = CODE_OFFSET + 0x4d36;
    monitor_app.dsm.child.trpoints.breakpoints[17] = CODE_OFFSET + 0x5d3b;

    #define LIMIT 19

#elif REMOTE_ATTEST
    //sgx_create_enclave
    monitor_app.dsm.child.trpoints.breakpoints[0] = CODE_OFFSET + 0x34aa;
    monitor_app.dsm.child.trpoints.breakpoints[1] = CODE_OFFSET + 0x34af;

    //enclave_init_ra
    monitor_app.dsm.child.trpoints.breakpoints[2] = CODE_OFFSET + 0x352f;
    monitor_app.dsm.child.trpoints.breakpoints[3] = CODE_OFFSET + 0x3534;

    //enclave_close_ra
    monitor_app.dsm.child.trpoints.breakpoints[4] = CODE_OFFSET + 0x42fb;
    monitor_app.dsm.child.trpoints.breakpoints[5] = CODE_OFFSET + 0x4300;

    //verify_att_result_mac
    monitor_app.dsm.child.trpoints.breakpoints[6] = CODE_OFFSET + 0x4138;
    monitor_app.dsm.child.trpoints.breakpoints[7] = CODE_OFFSET + 0x413d;

    //put secret data
    monitor_app.dsm.child.trpoints.breakpoints[8] = CODE_OFFSET + 0x4299;
    monitor_app.dsm.child.trpoints.breakpoints[9] = CODE_OFFSET + 0x422e;

    //destroy enclave 
    monitor_app.dsm.child.trpoints.breakpoints[10] = CODE_OFFSET + 0x437d;
    monitor_app.dsm.child.trpoints.breakpoints[11] = CODE_OFFSET + 0x4382;

    //sgx_get_extended_epid_group_id
    monitor_app.dsm.child.trpoints.breakpoints[12] = CODE_OFFSET + 0x3264;
    monitor_app.dsm.child.trpoints.breakpoints[13] = CODE_OFFSET + 0x3269;
    
    //sgx_select_att_key_id
    monitor_app.dsm.child.trpoints.breakpoints[14] = CODE_OFFSET + 0x341f;
    monitor_app.dsm.child.trpoints.breakpoints[15] = CODE_OFFSET + 0x3424;
    
    //sgx_ra_get_msg1_ex
    monitor_app.dsm.child.trpoints.breakpoints[16] = CODE_OFFSET + 0x363d;
    monitor_app.dsm.child.trpoints.breakpoints[17] = CODE_OFFSET + 0x3642;
    
    //sgx_ra_proc_msg2_ex
    monitor_app.dsm.child.trpoints.breakpoints[18] = CODE_OFFSET + 0x3ce0;
    monitor_app.dsm.child.trpoints.breakpoints[19] = CODE_OFFSET + 0x3ce5;

    #define LIMIT 19

#endif
    if(monitor_app.mode == CLIENT){
        for(int i = 0; i < monitor_app.dsm.child.trpoints.size; i = i + 2){
            log_info("The values of breakpoints: %lx\n", monitor_app.dsm.child.trpoints.breakpoints[i]);
            monitor_app.dsm.child.trpoints.old_instructions[i] = set_breakpoint(monitor_app.dsm.child.c_pid,    \
                                                                      monitor_app.dsm.child.trpoints.breakpoints[i]);
        }

        int i = 0;
        unsigned long ret_address;
        int iter = 0;
        
        while(1){
            int as[100];
            struct user_regs_struct regs;
            int index = -1;
            int delta = 0;
            static bool should_change_uffd = true;
            static address_spaces uffd_faulted_spaces = {NULL, -1, -1};

            empty_address_space(&uffd_faulted_spaces);
            //Logic block for uffd registration
            ret = scan_address_space(&monitor_app.dsm.child, &monitor_app.dsm.child.spaces);
            if(ret < 0){
                log_error("Could not scan the address space for read write permissions");
                goto out_stop_fail;
            }else{
                log_info("Overall size of the rw pages are %ld", ret);
            }

            address_spaces new_spaces;
            if(iter){
                delta = find_new_vma_delta(&monitor_app.dsm.child.spaces , &new_spaces);

                if(new_spaces.size && should_change_uffd == false){
                    //closing the uffd logic
                    ret = stop_uffd_thread_handler(&monitor_app.uffd_hdl);
                    if(ret){
                        log_error("failed to stop uffd thread");
                        goto out_uffd_thread_fail;
                    }
                    //Deregistering for uffd
                    ret = deregister_uffd(&monitor_app.dsm.child, &uffd_stat_snapshot);

                    should_change_uffd = true;
                }
            }

            
            if(!iter){
                // log_error("1");
                //uffd logic
                monitor_app.dsm.child.uffd = realloc( monitor_app.dsm.child.uffd, sizeof(uffd_t) * monitor_app.dsm.child.spaces.size);
                monitor_app.dsm.child.uffd_no = monitor_app.dsm.child.spaces.size;
                //Registering for uffd
                ret = register_uffd(&monitor_app.dsm.child, &monitor_app.dsm.child.spaces);

                monitor_app.uffd_hdl.args.child = &monitor_app.dsm.child;
                monitor_app.uffd_hdl.args.msi = &monitor_app.dsm.msi;
                monitor_app.uffd_hdl.args.sock_fd = monitor_app.dsm.socket_fd;
                monitor_app.uffd_hdl.args.faulting_spaces = &uffd_faulted_spaces;
                ret = start_uffd_thread_handler(&monitor_app.uffd_hdl);
                if(ret){
                    log_error("failed to start uffd thread");
                    goto out_uffd_thread_fail;
                }
            }else{
                if(should_change_uffd){
                    copy_vm_stat_address_space(&uffd_stat_snapshot);
                    //uffd logic
                    monitor_app.dsm.child.uffd = realloc( monitor_app.dsm.child.uffd, sizeof(uffd_t) * uffd_stat_snapshot.size);
                    monitor_app.dsm.child.uffd_no = uffd_stat_snapshot.size;
                    //Registering for uffd
                    ret = register_uffd(&monitor_app.dsm.child, &uffd_stat_snapshot);

                    monitor_app.uffd_hdl.args.child = &monitor_app.dsm.child;
                    monitor_app.uffd_hdl.args.msi = &monitor_app.dsm.msi;
                    monitor_app.uffd_hdl.args.sock_fd = monitor_app.dsm.socket_fd;
                    monitor_app.uffd_hdl.args.faulting_spaces = &uffd_faulted_spaces;
                    ret = start_uffd_thread_handler(&monitor_app.uffd_hdl);
                    if(ret){
                        log_error("failed to start uffd thread");
                        goto out_uffd_thread_fail;
                    }
                }else{
                    for(int i = 0; i < uffd_stat_snapshot.size; i++){
                        if(monitor_app.dsm.child.uffd[i].fd != -1){
                            enable_wprotect(monitor_app.dsm.child.uffd[i].fd, &uffd_stat_snapshot, i);
                        }
                    }
                    should_change_uffd = false;
                }
            }
            

            // Ending part of uffd registration logic
            ptrace(PTRACE_CONT, monitor_app.dsm.child.c_pid, NULL, NULL);
            wait(&ret);

            if(WIFEXITED(ret)){
                log_info("Child process got exited");
                break;
            }
            
            get_regs_args(monitor_app.dsm.child.c_pid, &regs, &as);
            log_info("stopping at the instruction pointer 0x%lx", regs.rip);

            for(int i = 0; i < monitor_app.dsm.child.trpoints.size; i++){
                if((regs.rip - 1) ==  monitor_app.dsm.child.trpoints.breakpoints[i]){
                    index = i;
                    log_info("Found the address %p at index %d\n", regs.rip, index);
                    break; 
                }
            }

            if(index == -1){
                log_info("Finished child execution");
                break;
            }
            
            if(!iter){
                // log_error("2");
                //closing the uffd logic
                ret = stop_uffd_thread_handler(&monitor_app.uffd_hdl);
                if(ret){
                    log_error("failed to stop uffd thread");
                    goto out_uffd_thread_fail;
                }
                //Deregistering for uffd
                ret = deregister_uffd(&monitor_app.dsm.child, &monitor_app.dsm.child.spaces);
            }


            clear_breakpoint(monitor_app.dsm.child.c_pid,                                                           \
                             monitor_app.dsm.child.trpoints.breakpoints[index],                                     \
                             monitor_app.dsm.child.trpoints.old_instructions[index]);
            
            monitor_app.dsm.child.trpoints.old_instructions[index] = set_breakpoint(monitor_app.dsm.child.c_pid,    \
                                                                 monitor_app.dsm.child.trpoints.breakpoints[index]);

            ret = scan_address_space(&monitor_app.dsm.child, &monitor_app.dsm.child.spaces);
            if(ret < 0){
                log_error("Could not scan the address space for read write permissions");
                goto out_stop_fail;
            }else{
                log_info("Overall size of the rw pages are %ld", ret);
            }

            delta = find_new_vma_delta(&monitor_app.dsm.child.spaces , &new_spaces);
            
            log_info("First new space");
            for(int i = 0; i < new_spaces.size; i++){
                if(new_spaces.space[i].address >= 0x7ffff7949000 && new_spaces.space[i].address < 0x7ffff7a0f000)
                    log_info("The address is %lx with a size %d", new_spaces.space[i].address, new_spaces.space[i].size);
            }

            if(iter){
                if(new_spaces.size){
                    // log_error("7");
                    // log_error("Found new space 2!!");
                    //closing the uffd logic
                    ret = stop_uffd_thread_handler(&monitor_app.uffd_hdl);
                    if(ret){
                        log_error("failed to stop uffd thread");
                        goto out_uffd_thread_fail;
                    }
                    //Deregistering for uffd
                    ret = deregister_uffd(&monitor_app.dsm.child, &uffd_stat_snapshot);

                    should_change_uffd = true;
                }else{
                    // log_error("4");
                    for(int i = 0; i < uffd_stat_snapshot.size; i++){
                        if(monitor_app.dsm.child.uffd[i].fd != -1){
                            disable_wprotect(monitor_app.dsm.child.uffd[i].fd, &uffd_stat_snapshot, i);
                        }
                    }
                    should_change_uffd = false;
                }
            }

            //Starting the idc communication!!
            msi_request_remote_execute(&monitor_app.dsm.msi, monitor_app.dsm.socket_fd, monitor_app.dsm.child.trpoints.breakpoints[index+1]);

            //Grabbing and sending the child process delta vma to remote
            msi_handle_send_vma(&monitor_app.dsm.msi, monitor_app.dsm.socket_fd, new_spaces, 1);
            

            delta = accumulate_diff_between_vma(monitor_app.uffd_hdl.args.faulting_spaces, &new_spaces);
            delta = accumulate_diff_between_vma_with_type(&monitor_app.dsm.child.spaces, &new_spaces, FILE_BACKED);
            
	    /*
	    if(!iter){
	    	delta = accumulate_diff_between_vma_with_type(&monitor_app.dsm.child.spaces, &new_spaces, HEAP);
            	delta = accumulate_diff_between_vma_with_type(&monitor_app.dsm.child.spaces, &new_spaces, STACK);
	    }
	    */

	    iter++;

            log_info("Final new space");
            for(int i = 0; i < new_spaces.size; i++){
                if(new_spaces.space[i].address >= 0x7ffff7949000 && new_spaces.space[i].address < 0x7ffff7a0f000)
                    log_info("The address is %lx with a size %d with type %d", new_spaces.space[i].address, new_spaces.space[i].size, new_spaces.space[i].type);
            }

            log_info("Starting the idc communication to remote!!");
            //Grabbing and sending the child process vma to remote
            msi_handle_send_vma(&monitor_app.dsm.msi, monitor_app.dsm.socket_fd, new_spaces, 0);

            //Grabbing and sending the child process registers to remote
            msi_handle_send_regs(&monitor_app.dsm.msi, monitor_app.dsm.socket_fd, &monitor_app.dsm.msi.regs);

            log_info("Waiting to receive the idc communication from remote!!");

            msi_handle_remote_execution(&monitor_app.dsm.msi, monitor_app.dsm.socket_fd, &ret_address);

            //Receive and update the child process delta vma
            msi_handle_rec_vma(&monitor_app.dsm.msi, monitor_app.dsm.socket_fd, 1);

            log_info("Receiving the idc communication from remote!!");

            //Receive and update child process vma
            msi_handle_rec_vma(&monitor_app.dsm.msi, monitor_app.dsm.socket_fd, 0);

            //Receive and update child process regs
            msi_handle_rec_regs(&monitor_app.dsm.msi, monitor_app.dsm.socket_fd, &monitor_app.dsm.msi.regs);

            log_info("The instruction pointer received from remote node is 0x%lx", monitor_app.dsm.msi.regs.rip);
	    no_migrations += 2;
        }

#ifdef PROFILE
	    printf("no_compl_inj %ld \n", no_cmpl_inj);
	    printf("no_ptrace_calls %ld \n", no_ptrace_calls);
	    printf("no_prr_calls %ld \n", no_prr_calls);
	    printf("no_pg_trans %ld \n", no_pg_trans);
	    printf("sync_messages %ld \n", sync_messages);
	    printf("no_migrations %ld \n", no_migrations);
#endif
    
    }else{

        struct user_regs_struct usr_reg;
        int iter = 0;
        uint64_t address;
        unsigned long old_instructions;
        int delta = 0;

        while(1){
            static address_spaces uffd_faulted_spaces = {NULL, -1, -1};
            static bool should_change_uffd = true;
            
            empty_address_space(&uffd_faulted_spaces);

            log_info("Waiting to receive the idc communication from remote!!");

            //Read for request from clients!!
            msi_handle_remote_execution(&monitor_app.dsm.msi, monitor_app.dsm.socket_fd, &address);

            //Receive and update the child process delta vma
            msi_handle_rec_vma(&monitor_app.dsm.msi, monitor_app.dsm.socket_fd, 1);
            
            log_info("Receiving the idc communication from client!!");

            //Receive and update child process vma
            msi_handle_rec_vma(&monitor_app.dsm.msi, monitor_app.dsm.socket_fd, 0);

            //Receive and update child process regs
            msi_handle_rec_regs(&monitor_app.dsm.msi, monitor_app.dsm.socket_fd, &monitor_app.dsm.msi.regs);
            
            ret = scan_address_space(&monitor_app.dsm.child, &monitor_app.dsm.child.spaces);
            if(ret < 0){
                log_error("Could not scan the address space for read write permissions");
                goto out_stop_fail;
            }else{
                log_info("Overall size of the rw pages are %ld", ret);
            }

            // log_info("11child space:");
            // for(int i = 0; i < monitor_app.dsm.child.spaces.size; i++){
            //     log_info("The address is %lx with a size %d", monitor_app.dsm.child.spaces.space[i].address, monitor_app.dsm.child.spaces.space[i].size);
            // }


            address_spaces new_spaces, tmp_spaces;
            delta = find_new_vma_delta(&monitor_app.dsm.child.spaces , &new_spaces);
            
            if(new_spaces.size && should_change_uffd == false){
                    // log_error("6");
                    // log_error("Found new space which was false before!!");
                    //closing the uffd logic
                    ret = stop_uffd_thread_handler(&monitor_app.uffd_hdl);
                    if(ret){
                        log_error("failed to stop uffd thread");
                        goto out_uffd_thread_fail;
                    }
                    //Deregistering for uffd
                    ret = deregister_uffd(&monitor_app.dsm.child, &uffd_stat_snapshot);

                    should_change_uffd = true;
            }

            if(should_change_uffd){
                copy_vm_stat_address_space(&uffd_stat_snapshot);
                // Logic block for uffd registration
                //uffd logic
                monitor_app.dsm.child.uffd = realloc( monitor_app.dsm.child.uffd, sizeof(uffd_t) * monitor_app.dsm.child.spaces.size);
                monitor_app.dsm.child.uffd_no = monitor_app.dsm.child.spaces.size;

                //Registering for uffd
                ret = register_uffd(&monitor_app.dsm.child, &monitor_app.dsm.child.spaces);


                monitor_app.uffd_hdl.args.child = &monitor_app.dsm.child;
                monitor_app.uffd_hdl.args.msi = &monitor_app.dsm.msi;
                monitor_app.uffd_hdl.args.sock_fd = monitor_app.dsm.socket_fd;
                monitor_app.uffd_hdl.args.faulting_spaces = &uffd_faulted_spaces;
                ret = start_uffd_thread_handler(&monitor_app.uffd_hdl);
                if(ret){
                    log_error("failed to start uffd thread");
                    goto out_uffd_thread_fail;
                }
                // Ending part of uffd registration logic
            }else{
                for(int i = 0; i < uffd_stat_snapshot.size; i++){
                    if(monitor_app.dsm.child.uffd[i].fd != -1){
                        enable_wprotect(monitor_app.dsm.child.uffd[i].fd, &uffd_stat_snapshot, i);
                    }
                }
                should_change_uffd = false;
            }

            log_info("Setting the breakpoint at %p", address);
            old_instructions = set_breakpoint(monitor_app.dsm.child.c_pid, (unsigned long)address);
            ptrace(PTRACE_CONT, monitor_app.dsm.child.c_pid, NULL, NULL);
            wait(&ret);
            
            clear_breakpoint(monitor_app.dsm.child.c_pid, address, old_instructions);
            log_info("stopping at the instruction pointer %p", address);

            ret = scan_address_space(&monitor_app.dsm.child, &monitor_app.dsm.child.spaces);
            if(ret < 0){
                log_error("Could not scan the address space for read write permissions");
                goto out_stop_fail;
            }else{
                log_info("Overall size of the rw pages are %ld", ret);
            }

            delta = find_new_vma_delta(&monitor_app.dsm.child.spaces , &new_spaces);

            log_info("First new space:");
            for(int i = 0; i < new_spaces.size; i++){
                if(new_spaces.space[i].address >= 0x7ffff7949000 && new_spaces.space[i].address < 0x7ffff7a0f000)
                    log_info("The address is %lx with a size %d", new_spaces.space[i].address, new_spaces.space[i].size);
            }

            if(new_spaces.size){
                //closing the uffd logic
                ret = stop_uffd_thread_handler(&monitor_app.uffd_hdl);
                if(ret){
                    log_error("failed to stop uffd thread");
                    goto out_uffd_thread_fail;
                }
                //Deregistering for uffd
                ret = deregister_uffd(&monitor_app.dsm.child, &uffd_stat_snapshot);
                should_change_uffd = true;
            }else{
                // log_error("4");
                for(int i = 0; i < uffd_stat_snapshot.size; i++){
                    if(monitor_app.dsm.child.uffd[i].fd != -1){
                        disable_wprotect(monitor_app.dsm.child.uffd[i].fd, &uffd_stat_snapshot, i);
                    }
                }
                should_change_uffd = false;
            }

            log_info("Starting the idc communication to client!!");
            msi_request_remote_execute(&monitor_app.dsm.msi, monitor_app.dsm.socket_fd, 0x00);

            //Grabbing and sending the child process delta vma to remote
            msi_handle_send_vma(&monitor_app.dsm.msi, monitor_app.dsm.socket_fd, new_spaces, 1);

            delta = accumulate_diff_between_vma(monitor_app.uffd_hdl.args.faulting_spaces, &new_spaces);
            delta = accumulate_diff_between_vma_with_type(&monitor_app.dsm.child.spaces, &new_spaces, FILE_BACKED);
            //delta = accumulate_diff_between_vma_with_type(&monitor_app.dsm.child.spaces, &new_spaces, STACK);
            

            log_info("Final new space:");
            for(int i = 0; i < new_spaces.size; i++){
                if(new_spaces.space[i].address >= 0x7ffff7949000 && new_spaces.space[i].address < 0x7ffff7a0f000)
                    log_info("The address is %lx with a size %d", new_spaces.space[i].address, new_spaces.space[i].size);
            }

            //Grabbing and sending the child process vma to remote
            msi_handle_send_vma(&monitor_app.dsm.msi, monitor_app.dsm.socket_fd, new_spaces, 0);
               
            //Grabbing and sending the child process registers to remote
            msi_handle_send_regs(&monitor_app.dsm.msi, monitor_app.dsm.socket_fd, &monitor_app.dsm.msi.regs);

#ifdef PROFILE
	    printf("no_compl_inj %ld \n", no_cmpl_inj);
	    printf("no_ptrace_calls %ld \n", no_ptrace_calls);
	    printf("no_prr_calls %ld \n", no_prr_calls);
	    printf("no_pg_trans %ld \n", no_pg_trans);
	    printf("sync_messages %ld \n", sync_messages);
	    printf("no_migrations %ld \n", no_migrations);
#endif
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
