#ifndef __HARES_MONITOR_H__
#define __HARES_MONITOR_H__

#include <pthread.h>
#include <sys/types.h>

#include "../inc/dsm_handler.h"
#include "../inc/uffd_handler.h"

/* --------------------------------------------------------------------
 * Structures & Required Datatypes
 * -------------------------------------------------------------------*/
typedef struct hares_app_t{
    enum app_mode mode;
    dsm_handler dsm;
    uffd_thread_handler uffd_hdl;
    uint64_t buffer;
}hares_app;

typedef struct client_args{
    char **user_args;
    int num_args;
}client_args;

#endif