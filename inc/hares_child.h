#ifndef __CHILD_HANDLER_H__
#define __CHILD_HANDLER_H__

typedef enum address_type_t{
    STACK = 0,
    HEAP,
    FILE_BACKED,
    ANONYMOUS
}address_type;

typedef struct child_tracepoints_t{
    unsigned long int *breakpoints;
    int size;
    //same size as breakpoints
    unsigned long int *old_instructions;
}tracepoints;

typedef struct child_address_space_t{
    unsigned long address;
    long size;
    address_type type;
}address_space;

typedef struct child_address_spaces_t{
    address_space *space;
    int size;
    long nr_pages;
}address_spaces;

typedef struct uffd_t{
    unsigned long address;
    int fd;
    address_type type;
}uffd_t;

typedef struct hares_child_app_t{
    pid_t c_pid;
    int   c_argc;
    char  *c_argv;
    char  *c_path; 
    uffd_t  *uffd;
    int uffd_no;
    pthread_mutex_t mutex;
    tracepoints trpoints;
    address_spaces spaces;
    address_spaces delta_spaces;
    unsigned long heap_start_address;
    unsigned long heap_end_address;  
} hares_child;

#endif
