#ifndef __POPSGX_PAGES_H__
#define __POPSGX_PAGES_H__
#include <unistd.h>
#include <stdbool.h>
#include <pthread.h>
#include <stdint.h>

/* --------------------------------------------------------------------
 * Macros
 * -------------------------------------------------------------------*/
#define PAGE_SIZE sysconf(_SC_PAGE_SIZE)

/* --------------------------------------------------------------------
 * Structures & Required Datatypes
 * -------------------------------------------------------------------*/
enum page_tag{
    INVALID = 0,
    MODIFIED,
    SHARED,
    NUM_TAGS
};

typedef struct popsgx_page_t{
    bool in_use;
    enum page_tag tag;
    pthread_mutex_t mutex;
    void *popsgx_address;
}popsgx_page;

typedef struct popsgx_page_buffer_t{
    int no_pages;
    popsgx_page *pages;
}popsgx_page_buffer;

/* --------------------------------------------------------------------
 * Public Functions
 * -------------------------------------------------------------------*/
int create_pages(popsgx_page_buffer *buffer, uint64_t popsgx_address, int no_pages);
popsgx_page* find_page(popsgx_page_buffer *buffer, void* fault_address);

#endif
