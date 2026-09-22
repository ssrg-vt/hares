#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>

#include "../inc/pages.h"
#include "../inc/log.h"

static void __initialize_page(hares_page* pg){
    pthread_mutex_init(&pg->mutex, NULL);
    pg->tag = INVALID;
    pg->hares_address = NULL;
    pg->in_use = false;
}

static int __initialize_pages(hares_page** pages, int no_pages){
    int ret = 0;

    *pages = (hares_page*)malloc(no_pages * (sizeof(hares_page)));
    if(pages == NULL){
        log_error("Couldn't create enough pages, it failed with error %s", strerror(errno));
        ret = -1;
        goto initialize_pages_fail;
    }

    log_debug("Successfully initialized %d pages", no_pages);

    for(int iter = 0; iter < no_pages; iter++){
        __initialize_page((*pages)+iter);
    }

initialize_pages_fail:
    return ret;
}

static void __destroy_page(hares_page* pg){
    pthread_mutex_destroy(&pg->mutex);
}

static void __destroy_pages(hares_page **pages, int no_pages){

    for(int iter = 0; iter < no_pages; iter++){
        __destroy_page((*pages)+iter);
    }

    free(*pages);
}

static void __map_address_to_haresAddress(hares_page** pages, uint64_t mmap_addr, int no_pages){
    hares_page *buffer_pages = *pages;
    uint64_t page_addr = mmap_addr;
    for(int i = 0; i < no_pages; i++, page_addr+=PAGE_SIZE){
        buffer_pages[i].hares_address = (void*)page_addr;
    }
}

hares_page* find_page(hares_page_buffer *buffer, void* fault_address){
    hares_page *pg = NULL;
    hares_page *buffer_pages = buffer->pages;
    uint64_t addr_val = (uint64_t)fault_address;

    for(int iter = 0; iter < buffer->no_pages; iter++){
        //log_info("The page address is %lx", buffer_pages[iter].hares_address);
        if((uint64_t)buffer_pages[iter].hares_address + PAGE_SIZE > addr_val){
            pg = &buffer_pages[iter];
            break;
        }
    }

    log_debug("The page address is %p", pg->hares_address);
    return pg;
}

int create_pages(hares_page_buffer *buffer, uint64_t hares_address, int no_pages){
    int rc = 0;

    if(buffer == NULL){
        log_error("The page handle is NULL");
        rc = -1;
        goto out_fail;
    }

    buffer->no_pages = no_pages;
    rc = __initialize_pages(&buffer->pages, no_pages);
    if(rc){
        log_error("Couldn't initialize pages");
        rc = -1;
        goto out_fail;
    }

    __map_address_to_haresAddress(&buffer->pages, hares_address, no_pages);

out_fail:
    return rc;
}