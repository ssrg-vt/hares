#ifndef __MSI_HANDLER_H__
#define __MSI_HANDLER_H__

#include <pthread.h>
#include "../inc/pages.h"

/* --------------------------------------------------------------------
 * Structures & Required Datatypes
 * -------------------------------------------------------------------*/
typedef struct msi_handler_t{
    bool is_initialized;
    int wait_for_reply;
    pthread_mutex_t mutex;
    pthread_cond_t page_reply_cond;
    popsgx_page_buffer buffer;
    char tmp_buffer[4096];
}msi_handler;

/* --------------------------------------------------------------------
 * Public functions
 * -------------------------------------------------------------------*/
int create_msi_pages(msi_handler *msi, uint64_t popsgx_address, int no_pages);
int msi_handle_page_invalidate(msi_handler *msi, int sk, struct msi_message *in_msg);
int msi_request_page(msi_handler *msi, int sk, char* page, void* fault_addr, unsigned int rw);
int msi_handle_page_request(msi_handler *msi ,int sk, struct msi_message *in_msg);
void msi_handle_page_reply(msi_handler *msi, int sk, struct msi_message *in_msg);
int msi_handle_write_command(msi_handler *msi, int sk, void *addr, void *data, size_t data_size);
#endif