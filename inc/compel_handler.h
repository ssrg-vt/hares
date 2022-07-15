#ifndef __COMPEL_HANDLER_H__
#define __COMPEL_HANDLER_H__

#include <compel/log.h>
#include <compel/infect-rpc.h>
#include <compel/infect-util.h>
#include <pthread.h>

#include "parasite.h"
#include "../inc/popsgx_monitor.h"

/* --------------------------------------------------------------------
 * MACROS
 * -------------------------------------------------------------------*/
#define PARASITE_CMD_GET_STDIN_FD         PARASITE_USER_CMDS
#define PARASITE_CMD_GET_STDOUT_FD        PARASITE_USER_CMDS + 1
#define PARASITE_CMD_GET_STDERR_FD        PARASITE_USER_CMDS + 2
#define PARASITE_CMD_GET_STDUFLT_FD       PARASITE_USER_CMDS + 3
#define PARASITE_CMD_SET_MADVISE_NO_NEED  PARASITE_USER_CMDS + 4

/* --------------------------------------------------------------------
 * Structures & Required Datatypes
 * -------------------------------------------------------------------*/
typedef enum compel_fd_t{
    PARASITE_STDIN_FD = PARASITE_CMD_GET_STDIN_FD,
    PARASITE_STDOUT_FD,
    PARASITE_STDERR_FD,
    PARASITE_STDUFLT_FD
}compel_fd;

typedef struct compel_handler_t{
    struct parasite_ctl *ctl;
    int state;
    pid_t pid;
}compel_handler;

/* --------------------------------------------------------------------
 * Public Functions
 * -------------------------------------------------------------------*/
int compel_steal_fd(popsgx_child *tracee, compel_fd fd_type, int *fd);
int compel_steal_uffd(popsgx_child *tracee, int *fd, void* addr, int no_pages);
int compel_do_madvise(popsgx_child *process, void *addr);

#endif