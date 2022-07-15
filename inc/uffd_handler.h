#ifndef __USERFAULT_HANDLER_H__
#define __USERFAULT_HANDLER_H__
#include <stdint.h>
#include <pthread.h>

#include "../inc/dsm_handler.h"
#include "../inc/msi_handler.h"

typedef struct uffd_thread_args_t{
    int sock_fd;
    popsgx_child *child;
    msi_handler *msi;
}uffd_thread_args;

typedef struct uffd_thread_handler_t{
    pthread_t thread;
    uffd_thread_args args;
}uffd_thread_handler;

int start_uffd_thread_handler(uffd_thread_handler *uffd_hdl);
#endif