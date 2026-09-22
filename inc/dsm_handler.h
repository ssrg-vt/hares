#ifndef __DSM_MONITOR_H__
#define __DSM_MONITOR_H__



#include "../inc/dsm_bus_handler.h"
#include "../inc/hares_child.h"
#include "../inc/msi_handler.h"

/* --------------------------------------------------------------------
 * Structures & Required Datatypes
 * -------------------------------------------------------------------*/
enum app_mode{
    SERVER = 0,
    CLIENT
};

typedef struct dsm_handler_t{
    char *remote_ip;
    int remote_port;
    int host_port;
    int socket_fd;
    hares_child child;
    dsm_bus_handler dsm_bus;
    msi_handler msi;
}dsm_handler;

/* --------------------------------------------------------------------
 * Public functions
 * -------------------------------------------------------------------*/
int dsm_main(dsm_handler *mdsm, int mode);
int convert_childAddress_popAddress(uint64_t caddr, uint64_t *poff);

#endif
