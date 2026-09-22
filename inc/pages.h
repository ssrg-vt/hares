#ifndef __HARES_PAGES_H__
#define __HARES_PAGES_H__
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

typedef struct hares_page_t{
    bool in_use;
    enum page_tag tag;
    pthread_mutex_t mutex;
    void *hares_address;
}hares_page;

typedef struct hares_page_buffer_t{
    int no_pages;
    hares_page *pages;
}hares_page_buffer;

/* --------------------------------------------------------------------
 * Public Functions
 * -------------------------------------------------------------------*/
int create_pages(hares_page_buffer *buffer, uint64_t hares_address, int no_pages);
hares_page* find_page(hares_page_buffer *buffer, void* fault_address);

#endif
