#include <sys/socket.h>
#include <linux/types.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <stdbool.h>

#include "../inc/log.h"
#include "../inc/messages.h"
#include "../inc/dsm_bus_handler.h"

/* --------------------------------------------------------------------
 * Local functions
 * -------------------------------------------------------------------*/

/**
 * @brief callback function for cleaning up the dsm bus handler
 * 
 * @param arg 
 */
void bus_thread_cleanup_handler(void* arg)
{
	/* Close out the sockets so we don't have loose ends */
	int sk = *(int*)arg;
	/* Ensure it's not stdin/out/err */
	log_debug("Cleanup handler called: %d", sk);
	if (sk >= 2)
		close(sk);
}

/**
 * @brief Thread function for the dsm bus handler
 * 
 * @param arg 
 * @return void* 
 */
void* bus_thread_handler(void* arg){
    int rd = 0;
    struct msi_message msg;
    dsm_bus_args *bargs = (dsm_bus_args*) arg;
	int sock_fd = bargs->dsm_sock;
	msi_handler *msi = bargs->msi;

    /* In case of thread cancellation, execute this handler */
	pthread_cleanup_push(bus_thread_cleanup_handler, arg);

    /* Main Event Loop for the bus*/
	for(;;) {
		rd = read(sock_fd, &msg, sizeof(msg));
		if (rd < 0)
			log_error("Read Error");
		switch(msg.message_type){
			case DISCONNECT:
				close(sock_fd);
				return NULL;
			case INVALID_STATE_READ:
				log_debug("INVALID_STATE_READ_MSG_RECEIVED");
				msi_handle_page_request(msi, sock_fd, &msg);
			break;
			case INVALIDATE:
				log_debug("INVALIDATE_RECEIVED");
				msi_handle_page_invalidate(msi, sock_fd, &msg);
			break;
			case PAGE_REPLY:
				log_debug("PAGE_REPLY_RECEIVED");
			    msi_handle_page_reply(msi, sock_fd, &msg);
			break;
			case INVALIDATE_ACK:
				printf("INVALIDATE_ACK_RECEIVED\n");
			break;
			default:
				log_error("Unhandled bus request, %d",
				       msg.message_type);
			break;
		}
	}

    /* Cleanup pop 0 argument means we don't execute the handler in normal
	 * exit, which is true since we will never exit here anyway*/
	pthread_cleanup_pop(0);
	return NULL;
}

/* --------------------------------------------------------------------
 * Public functions
 * -------------------------------------------------------------------*/

/**
 * @brief Helper function for creating the dsm bus handler thread
 * 
 * @param dsm_bus_hdl 
 * @return int 
 */
int start_dsm_bus_handler(dsm_bus_handler *dsm_bus_hdl){
    int rc = 0;

    if(dsm_bus_hdl == NULL){
		log_error("dsm bus handle is NULL");
		goto out_fail;
    }

    rc = pthread_create(&dsm_bus_hdl->thread, NULL, bus_thread_handler, (void*) &dsm_bus_hdl->args);
    if (rc != 0) {
		log_error("Could not create a dsm bus handler thread");
        goto out_fail;
	}

out_fail:
    return rc;
}