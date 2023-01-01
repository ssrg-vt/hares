#ifndef __CHILD_HANDLER_H__
#define __CHILD_HANDLER_H__


typedef struct child_tracepoints_t{
    unsigned long int *breakpoints;
    int size;
    //same size as breakpoints
    unsigned long int *old_instructions;
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
    address_spaces delta_spaces; 
} popsgx_child;

#endif
