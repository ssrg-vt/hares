#ifndef __POPSGX_MONITOR_H__
#define __POPSGX_MONITOR_H__

#include <pthread.h>
#include <sys/types.h>

#include "../inc/dsm_handler.h"
#include "../inc/uffd_handler.h"

/* --------------------------------------------------------------------
 * Structures & Required Datatypes
 * -------------------------------------------------------------------*/
typedef struct popsgx_app_t{
    enum app_mode mode;
    dsm_handler dsm;
    uffd_thread_handler uffd_hdl;
}popsgx_app;

#endif