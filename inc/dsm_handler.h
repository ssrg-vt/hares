#ifndef __DSM_MONITOR_H__
#define __DSM_MONITOR_H__

#include "../inc/msi_handler.h"
#include "../inc/dsm_bus_handler.h"

/* --------------------------------------------------------------------
 * Structures & Required Datatypes
 * -------------------------------------------------------------------*/
enum app_mode{
    SERVER = 0,
    CLIENT
};

typedef struct child_tracepoints_t{
    unsigned long int *breakpoints;
    int size;
    //same size as breakpoints
    long *old_instructions;
}tracepoints;

typedef struct child_address_space_t{
    unsigned long address;
    long size;
}address_space;

typedef struct child_address_spaces_t{
    address_space *space;
    int size;
    long nr_pages;
}address_spaces;

typedef struct popsgx_child_app_t{
    pid_t c_pid;
    int   c_argc;
    char  *c_argv;
    char  *c_path; 
    int   *uffd;
    int uffd_no;
    pthread_mutex_t mutex;
    tracepoints trpoints;
    address_spaces spaces; 
} popsgx_child;

typedef struct dsm_handler_t{
    char *remote_ip;
    int remote_port;
    int host_port;
    int socket_fd;
    popsgx_child child;
    dsm_bus_handler dsm_bus;
    msi_handler msi;
}dsm_handler;

/* --------------------------------------------------------------------
 * Public functions
 * -------------------------------------------------------------------*/
int dsm_main(dsm_handler *mdsm, int mode);
int convert_childAddress_popAddress(uint64_t caddr, uint64_t *poff);

#endif