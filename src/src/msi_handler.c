#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <stdbool.h>

#include "../inc/messages.h"
#include "../inc/pages.h"
#include "../inc/log.h"
#include "../inc/msi_handler.h"
#include "../inc/dsm_handler.h"
#include "../inc/compel_handler.h"

#define log_info(args...) 

extern popsgx_child *victim;
/* --------------------------------------------------------------------
 * Public Functions defintions
 * -------------------------------------------------------------------*/
int msi_request_page(msi_handler *msi, int sk, char* page, void* fault_addr, unsigned int rw)
{
    int ret;
    struct msi_message msg;
    uint64_t poff;
    uint64_t paddr;
 
    ret = convert_childAddress_popAddress((uint64_t)fault_addr, &poff);
    if(ret){
        log_error("Could not convert the victim address to popsgx buffer address");
        goto msi_request_page_fail;
    }

    paddr = (msi->popsgx_buffer_addr + (poff * sysconf(_SC_PAGE_SIZE)));
    log_info("paddr is %p", paddr);

    pthread_mutex_lock(&msi->mutex);

    popsgx_page *page_to_transition = find_page(&msi->buffer, (void *)paddr);
    if(!page_to_transition){
        ret = -1;
        log_error("Could not find the relevant page with address %p", paddr);
        goto msi_request_page_fail;
    }

    pthread_mutex_lock(&page_to_transition->mutex);

    msg.message_type = INVALID_STATE_READ;
    msg.payload.request_page.address = (uint64_t) paddr;
    msg.payload.request_page.size = PAGE_SIZE;
   
    ret = write(sk, &msg, sizeof(msg));
    if(ret <=0)
        goto msi_request_write_fail;
    
    memset(&msi->tmp_buffer, 0, PAGE_SIZE);
    msi->wait_for_reply = 1;
    while(msi->wait_for_reply == 1){
        pthread_cond_wait(&msi->page_reply_cond, &msi->mutex);
    }

    memcpy(page, &msi->tmp_buffer, PAGE_SIZE);
    page_to_transition->tag = SHARED;

msi_request_write_fail:
    pthread_mutex_unlock(&msi->mutex);
msi_request_page_fail:
    pthread_mutex_unlock(&page_to_transition->mutex);
    return ret;
}

int msi_request_proc_reg(msi_handler *msi, int sk,  struct user_regs_struct *regs){
    int ret;
    struct msi_message msg;
    pthread_mutex_lock(&msi->mutex);

    msg.message_type = REMOTE_REGS;

    ret = write(sk, &msg, sizeof(msg));
    if(ret <= 0)
        goto msi_request_proc_reg_fail;
    
    memset(&msi->regs, 0, sizeof(struct user_regs_struct));
     msi->wait_for_reply = 1;
    while(msi->wait_for_reply == 1){
        pthread_cond_wait(&msi->page_reply_cond, &msi->mutex);
    }

    memcpy(regs, &msi->regs, sizeof(struct user_regs_struct));

msi_request_proc_reg_fail:
    pthread_mutex_unlock(&msi->mutex);
    return ret;
}

int msi_handle_reg_request(msi_handler *msi, int sk){
    int ret;
    struct msi_message msg_out;

    msg_out.message_type = REMOTE_REGS_REPLY;
    memcpy(&msg_out.payload.regs_message, &msi->regs, sizeof(struct user_regs_struct));

    log_debug("Hello xip: %p", msg_out.payload.regs_message.regs.rip);
    pthread_mutex_lock(&msi->mutex);
    ret = write(sk, &msg_out, sizeof(msg_out));
    if(ret <= 0){
        goto msi_handle_reg_request_fail;
    }

msi_handle_reg_request_fail:
    pthread_mutex_unlock(&msi->mutex);
    return ret;
}

int msi_handle_page_request(msi_handler *msi ,int sk, struct msi_message *in_msg){
    int ret;
    struct msi_message msg_out;

    popsgx_page *page_to_transition = find_page(&msi->buffer, (void*)in_msg->payload.request_page.address);
    if(!page_to_transition){
        log_error("Could not find the relevant page with address %p", in_msg->payload.request_page.address);
        ret = -1;
        goto msi_page_request_fail;
    }

    msg_out.message_type = PAGE_REPLY;

    /*If I'm invalid too, then I'll give you an empty page */
    if(page_to_transition->tag == INVALID){
        memset(msg_out.payload.page_data, '0', PAGE_SIZE);
    }else{
        /* Else I'll give you my local memory storage, won't trigger
		 * pagefault since it's already been edited anyway */
        memcpy(msg_out.payload.page_data, page_to_transition->popsgx_address, PAGE_SIZE);
    }

    pthread_mutex_lock(&page_to_transition->mutex);
    ret = write(sk, &msg_out, sizeof(msg_out));
    if(ret <= 0){
        goto msi_page_write_fail;
    }

    page_to_transition->tag = SHARED;

msi_page_write_fail:
    pthread_mutex_unlock(&page_to_transition->mutex);
msi_page_request_fail:
    return ret;
}

int msi_handle_page_invalidate(msi_handler *msi, int sk, struct msi_message *in_msg){
    int ret = 0;
    struct msi_message msg;

    log_info("msi_handle_page_invalidate");
    log_info("page address requested was %x", in_msg->payload.request_page.address);
    popsgx_page *page_to_transition = find_page(&msi->buffer, (void*)in_msg->payload.request_page.address);
    if(!page_to_transition){
        log_error("Could not find the relevant page with address %p", in_msg->payload.request_page.address);
        ret = -1;
        goto msi_handle_page_fail;
    }

    pthread_mutex_lock(&page_to_transition->mutex);
    page_to_transition->tag = INVALID;

    log_debug("msi_handle_page_invalidate");
    if (ret = madvise(page_to_transition->popsgx_address, PAGE_SIZE, MADV_DONTNEED)){
		log_error("fail to madvise");
        goto msi_post_lock_fail;
	}

    // ret = compel_do_madvise(victim, page_to_transition->popsgx_address);
    // if(ret){
    //     log_error("Setting madvise on victim failed");
    //     goto msi_post_lock_fail;
    // }

    msg.message_type = INVALIDATE_ACK;
    ret = write(sk, &msg, sizeof(msg));
    if(ret <= 0){
        log_error("Could not invalidate the page");
    }   

    log_debug("msi_handle_page_invalidate");
msi_post_lock_fail:
    pthread_mutex_unlock(&page_to_transition->mutex);
msi_handle_page_fail:
    return ret;
}

void msi_handle_page_reply(msi_handler *msi, int sk, struct msi_message *in_msg){
    pthread_mutex_lock(&msi->mutex);
    memcpy(&msi->tmp_buffer, in_msg->payload.page_data, PAGE_SIZE);

    msi->wait_for_reply = 0;
    pthread_cond_signal(&msi->page_reply_cond);
    pthread_mutex_unlock(&msi->mutex);
}

void msi_handle_regs_reply(msi_handler *msi, int sk, struct msi_message *in_msg){
    pthread_mutex_lock(&msi->mutex);
    memcpy(&msi->regs, &in_msg->payload.regs_message.regs, sizeof(struct user_regs_struct));
    log_debug("hello from in xip: %lx", in_msg->payload.regs_message.regs.rip);
    log_debug("hello from in msi regs: %lx", msi->regs.rip);
    msi->wait_for_reply = 0;
    pthread_cond_signal(&msi->page_reply_cond);
    pthread_mutex_unlock(&msi->mutex);
}

void msi_request_remote_execute(msi_handler *msi, int sk, uint64_t ret_addr){
    int ret = 0;
    struct msi_message msg;
    pthread_mutex_lock(&msi->mutex);
    msg.message_type = REMOTE_EXECUTE;
    msg.payload.remote_request_message.instr_address = ret_addr;
    ret = write(sk, &msg, sizeof(msg));
    if(ret <= 0){
        log_error("Bad write in MSI");
    }
    pthread_mutex_unlock(&msi->mutex);
}

void msi_handle_remote_execution(msi_handler *msi, int sk, uint64_t *ret_addr){
    int ret = 0;
    struct msi_message remote_msg;

    ret = read(sk, &remote_msg, sizeof(remote_msg));
    while(!remote_msg.message_type == REMOTE_EXECUTE){
        continue;
    }

    *ret_addr = remote_msg.payload.remote_request_message.instr_address;

    log_info("The instruction address received is %p", remote_msg.payload.remote_request_message.instr_address);
    // pthread_mutex_lock(&msi->mutex);
    // msi->_can_request = true;
    // pthread_mutex_unlock(&msi->mutex);
}

int msi_handle_write_command(msi_handler *msi, int sk, void *addr, void *data, size_t data_size){
    char write_buffer[100] = {0};
	unsigned long page_num = 0;
	struct msi_message msg;
	int ret;
    uint64_t poff;
    uint64_t paddr;

    //log_info("msi_handle_write_command");
    ret = convert_childAddress_popAddress((uint64_t)addr, &poff);
    if(ret){
        log_error("Could not convert the victim address to popsgx buffer address");
        goto msi_handle_write_fail;
    }

    paddr = (msi->popsgx_buffer_addr + (poff * sysconf(_SC_PAGE_SIZE)));
    //log_info("paddr is %p", paddr);

    popsgx_page *page_to_transition = find_page(&msi->buffer, (void*)paddr);
    if(!page_to_transition){
        log_error("Could not find the relevant page with address %p", paddr);
        ret = -1;
        goto msi_handle_write_fail;
    }

    if(page_to_transition){
        memcpy(page_to_transition->popsgx_address, data, data_size);
        page_to_transition->tag = MODIFIED;
        msg.message_type = INVALIDATE;
        msg.payload.invalidate_page.address = (uint64_t)paddr;
        ret = write(sk, &msg, sizeof(msg));
        if(ret <= 0){
            log_error("Bad write in MSI");
        }
    }

msi_handle_write_fail:
    return ret;
}

int msi_handle_rec_vma(msi_handler *msi, int sk, bool is_delta){
    int ret = 0;
    struct msi_message vma_from_remote_msg;
    
    pthread_mutex_lock(&msi->mutex);

    ret = read(sk, &vma_from_remote_msg, sizeof(vma_from_remote_msg));
    enum msi_message_type to_recieve_cmd = VMA_FROM_REMOTE;
    if(vma_from_remote_msg.message_type == to_recieve_cmd){
        log_info("recieved the vma_from_remote");
        struct vma_header vma_hdr = vma_from_remote_msg.payload.vma_header_message;
        log_info("vma: %d", vma_hdr.no_vma);

        vma_from_remote_msg.message_type = VMA_FROM_REMOTE_ACK;
        vma_from_remote_msg.payload.vma_header_message.no_vma = vma_hdr.no_vma;
        ret = write(sk, &vma_from_remote_msg, sizeof(vma_from_remote_msg));
        if(ret <= 0){
            log_error("Bad write in MSI");
        }

        log_info("sent the vma_from_remote_ack");

        for(int i = 0; i < vma_hdr.no_vma; i++){
            struct msi_message vma_buffer_header_msg;
            ret = read(sk, &vma_buffer_header_msg, sizeof(vma_buffer_header_msg));
            if(vma_buffer_header_msg.message_type == VMA_BUFFER_HEADER){
                log_info("recieved the vma_buffer_header");
                log_info("vma address is %lx with size is %d", vma_buffer_header_msg.payload.vma_buffer_message.vma_address, \
                                                               vma_buffer_header_msg.payload.vma_buffer_message.size);
                
                //if(vma_buffer_header_msg.payload.vma_buffer_message.vma_address == 0x7ffff42b7000) continue;

                vma_buffer_header_msg.message_type = VMA_BUFFER_HEADER_ACK;
                ret = write(sk, &vma_buffer_header_msg, sizeof(vma_buffer_header_msg));
                if(ret <= 0){
                    log_error("Bad write in MSI");
                }
                log_info("sent the vma_buffer_header_ack");

                uint64_t vma_addr = vma_buffer_header_msg.payload.vma_buffer_message.vma_address;
                uint64_t pages = vma_buffer_header_msg.payload.vma_buffer_message.size;
                address_type type = (address_type)vma_buffer_header_msg.payload.vma_buffer_message.type;

                char *vma_buffer = malloc(sizeof(char) * (sysconf(_SC_PAGE_SIZE)) * pages);

                //Reading pages in a vma
                for(int j = 0; j < pages; j++){
                    struct msi_message vma_buffer_msg;
                    ret = read(sk, &vma_buffer_msg, sizeof(vma_buffer_msg));
                    if(vma_buffer_msg.message_type == VMA_BUFFER){
                        log_info("recieved the page %d", j + 1);   
                        memcpy(&vma_buffer[j*4096], vma_buffer_msg.payload.page_data, PAGE_SIZE);
                    }else{
                        log_error("Couldn't receive VMA_BUFFER");
                        goto vma_buffer_fail;
                    }

                    vma_buffer_msg.message_type = VMA_BUFFER_ACK;
                    vma_buffer_msg.payload.page_data[0] = i;
                    ret = write(sk, &vma_buffer_msg, sizeof(vma_buffer_msg));
                    if(ret <= 0){
                        log_error("Bad write in MSI");
                    }
                    log_info("sent the vma_buffer_ack");
                }

               
                if(!is_delta){
                    //Now paste it onto the child process
                    if(type == HEAP){
                        if(msi->child.heap_end_address != (vma_addr + (pages * 4096))){
                            uint64_t heap_pages = vma_addr + (pages * 4096);
                            ret = compel_correct_heap_offset(&msi->child, heap_pages);
                            if(ret){
                                log_error("compel_correct_heap_offset failed");
                            }
                            log_info("Corrected heap offset");
                        }
                    }

                    pthread_mutex_lock(&msi->child.mutex);
                    ret = update_child_data(msi->child.c_pid, (void*)vma_addr, vma_buffer, (sysconf(_SC_PAGE_SIZE)) * pages);
                    pthread_mutex_unlock(&msi->child.mutex);
                }
                else{
                    if(type == HEAP){
                        log_info("Correcting heap offset");
                        uint64_t heap_pages = vma_addr + (pages * 4096);
                        ret = compel_correct_heap_offset(&msi->child, heap_pages);
                        if(ret){
                            log_error("compel_correct_heap_offset failed");
                        }
                        log_info("Corrected heap offset");
                    }else if(type == FILE_BACKED || type == ANONYMOUS){
                        log_info("Creating a new vma to sync with remote");
                        ret = compel_create_new_map(&msi->child, vma_addr, pages);
                        if(ret){
                            log_error("compel_create_new_map failed");
                        }   
                        log_info("Created a new vma");
                    }
                }
                
                free(vma_buffer);

            }else{
                log_error("Couldn't receive VMA_BUFFER_HEADER, read %d", vma_buffer_header_msg.message_type);
                goto msi_handle_rec_vma_fail;
            }
        }
    }

    struct msi_message trans_ack;
    trans_ack.message_type = VMA_TRANS_ACK;
    ret = write(sk, &trans_ack, sizeof(trans_ack));
    if(ret <= 0){
        log_error("Bad write in MSI");
    }
    log_info("sent the vma_trans_ack");

vma_buffer_fail:
msi_handle_rec_vma_fail:
msi_handle_rec_vma_out:
    pthread_mutex_unlock(&msi->mutex);
    return 0;
}

int msi_handle_rec_regs(msi_handler *msi, int sk, struct user_regs_struct *reg){
    int ret;
    struct msi_message msg;
    
    msg.message_type = REMOTE_REGS_REPLY;

    pthread_mutex_lock(&msi->mutex);

    ret = read(sk, &msg, sizeof(msg));
    if(msg.message_type == REMOTE_REGS){
        log_info("received the remote_regs");
        memcpy(reg, &msg.payload.regs_message, sizeof(struct user_regs_struct));

        ptrace(PTRACE_SETREGS, msi->child.c_pid, NULL, reg);

        msg.message_type = REMOTE_REGS_REPLY;
        ret = write(sk, &msg, sizeof(msg));
        if(ret <= 0){
            log_error("Bad write in MSI");
        }
        log_info("sent the remote_regs_reply acknowledgement");

    }else{
        log_error("Couldn't recieve REMOTE_REGS");
        goto msi_handle_rec_reg;
    }

    pthread_mutex_unlock(&msi->mutex);
    return 0;

msi_handle_rec_reg:
    pthread_mutex_unlock(&msi->mutex);
    return -1;
}

int msi_handle_send_regs(msi_handler *msi, int sk, struct user_regs_struct *reg){
    int ret;
    int as[100];
    struct msi_message reg_to_remote;

    pthread_mutex_lock(&msi->child.mutex);
    get_regs_args(msi->child.c_pid, reg, &as);
    pthread_mutex_unlock(&msi->child.mutex);

    reg_to_remote.message_type = REMOTE_REGS;
    memcpy(&reg_to_remote.payload.regs_message, reg, sizeof(struct user_regs_struct));
    
    pthread_mutex_lock(&msi->mutex);
    ret = write(sk, &reg_to_remote, sizeof(reg_to_remote));
    if(ret <= 0){
        goto msi_handle_reg_request_fail;
    }

    ret = read(sk, &reg_to_remote, sizeof(reg_to_remote));
    if(reg_to_remote.message_type == REMOTE_REGS_REPLY){
        log_info("received  remote_regs_reply");
    }else{
        log_error("Couldn't recieve REMOTE_REGS_REPLY");
        goto msi_handle_reg_request_fail;
    }

    pthread_mutex_unlock(&msi->mutex);
    return 0;

msi_handle_reg_request_fail:
    pthread_mutex_unlock(&msi->mutex);
    return ret;

}

int msi_handle_send_vma(msi_handler *msi, int sk, address_spaces vmas, bool is_delta){
    struct msi_message vma_from_remote_msg;
    int ret = 0;

    vma_from_remote_msg.message_type = VMA_FROM_REMOTE;
    vma_from_remote_msg.payload.vma_header_message.no_vma = vmas.size;

    pthread_mutex_lock(&msi->mutex);

    log_info("Wrote VMA_FROM_REMOTE");

    ret = write(sk, &vma_from_remote_msg, sizeof(vma_from_remote_msg));
    if(ret <= 0){
        log_error("Bad write in MSI");
    }

    ret = read(sk, &vma_from_remote_msg, sizeof(vma_from_remote_msg));
    if(vma_from_remote_msg.message_type == VMA_FROM_REMOTE_ACK && vma_from_remote_msg.payload.vma_header_message.no_vma == vmas.size){
        log_info("Received VMA_FROM_REMOTE_ACK");
    }else{
        log_error("Failed in receiving VMA_FROM_REMOTE_ACK");
    }

    log_info("VMAs are as follows");
    for(int i = 0; i < vmas.size; i++){
        struct msi_message vma_buffer_header_msg;
        //log_info("%lx", vmas.space[i].address);

        //Writing Buffer Header
        log_info("Sending VMA_BUFFER_HEADER");
        vma_buffer_header_msg.message_type = VMA_BUFFER_HEADER;
        vma_buffer_header_msg.payload.vma_buffer_message.vma_address = vmas.space[i].address;
        vma_buffer_header_msg.payload.vma_buffer_message.size = vmas.space[i].size;
        vma_buffer_header_msg.payload.vma_buffer_message.type = (int)vmas.space[i].type;
        ret = write(sk, &vma_buffer_header_msg, sizeof(vma_buffer_header_msg));
        if(ret <= 0){
            log_error("Bad write in MSI");
        }

        // if(vmas.space[i].address == 0x7ffff42b7000) continue;
        
        ret = read(sk, &vma_buffer_header_msg, sizeof(vma_buffer_header_msg));
        if(vma_buffer_header_msg.message_type == VMA_BUFFER_HEADER_ACK){
            log_info("recieved the vma_buffer_header ack");
        }else{
            log_error("Couldn't receive VMA_BUFFER_ACK");
            goto vma_buffer_fail;
        }
        

        //Reading vmas from the process space
        log_info("Reading vmas from the process");
        pthread_mutex_lock(&msi->child.mutex);
        
        char *vma_buffer = (char*)malloc((sysconf(_SC_PAGE_SIZE)) * vmas.space[i].size);
        log_info("Getting data from the child process");
        get_child_data(msi->child.c_pid, vma_buffer, (void*)vmas.space[i].address, (sysconf(_SC_PAGE_SIZE)) * vmas.space[i].size);
        pthread_mutex_unlock(&msi->child.mutex);

        for(int j = 0; j < vmas.space[i].size; j++){
            struct msi_message vma_buffer_msg;
            log_info("sending the page %d for the vma %lx", j + 1, vmas.space[i].address);
            vma_buffer_msg.message_type = VMA_BUFFER;
            memset(&vma_buffer_msg.payload.page_data, 0, PAGE_SIZE);
            memcpy(vma_buffer_msg.payload.page_data, &vma_buffer[j*4096], PAGE_SIZE);
            
            ret = write(sk, &vma_buffer_msg, sizeof(vma_buffer_msg));
            if(ret <= 0){
                log_error("Error in sending the vma page buffer");
                goto vma_buffer_fail;
            }

            ret = read(sk, &vma_buffer_msg, sizeof(vma_buffer_msg));
            if(vma_buffer_msg.message_type == VMA_BUFFER_ACK){
                log_info("recieved the page %d ack", j+1);
            }else{
                log_error("Couldn't receive VMA_BUFFER_ACK");
                goto vma_buffer_fail;
            };
        }

        free(vma_buffer);
    }

    ret = read(sk, &vma_from_remote_msg, sizeof(vma_from_remote_msg));
    if(vma_from_remote_msg.message_type == VMA_TRANS_ACK){
        log_info("Received VMA_TRANS_ACK");
    }else{
        log_error("Failed in receiving VMA_TRANS_ACK");
    }

vma_buffer_fail:
out_send:
    pthread_mutex_unlock(&msi->mutex);
}

int create_msi_pages(msi_handler *msi, uint64_t popsgx_address, int no_pages){
    int rc = 0;

    if(msi == NULL){
        log_error("msi handle is NULL");
        rc = -1;
        goto out_fail;
    }

    // rc = create_pages(&msi->buffer, popsgx_address, no_pages);
    // if(rc){
    //     log_error("Could not create enough pages for the msi");
    //     goto out_fail;
    // }

    
    pthread_mutex_init(&msi->mutex, NULL);
    msi->is_initialized = true;


out_fail:
    return rc;
}