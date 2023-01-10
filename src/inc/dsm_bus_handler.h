#ifndef __DSM_BUS_HANDLER_H__
#define __DSM_BUS_HANDLER_H__

#include <pthread.h>

#include "../inc/msi_handler.h"

/* --------------------------------------------------------------------
 * Structures & Required Datatypes
 * -------------------------------------------------------------------*/
typedef struct dsm_bus_thread_args_t{
    msi_handler *msi;
    int dsm_sock;
}dsm_bus_args;

typedef struct dsm_bus_handler_t{
    pthread_t thread;
    dsm_bus_args args;
    msi_handler *msi;
}dsm_bus_handler;

/* --------------------------------------------------------------------
 * Public functions
 * -------------------------------------------------------------------*/
int start_dsm_bus_handler(dsm_bus_handler *dsm_bus_hdl);

#endif