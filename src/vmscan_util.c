#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>

#include "../inc/log.h"
#include "../inc/popsgx_child.h"

address_spaces empty_vm_stat_snapshot = {NULL, -1, -1};
static address_spaces vm_stat_snapshot = {NULL, -1, -1};

void _empty_address_space(address_spaces* addr){
    addr->space = (address_space*)realloc(addr->space, 0);
    addr->size = 0;
    addr->nr_pages = 0;
}


/**
 * @brief This function copies the src onto the dest. furthermore,
 *        also note that the destination will be zero initialized 
 *        before being copied from src
 * 
 * @param dest 
 * @param src 
 */
void _copy_address_spaces(address_spaces* dest, address_spaces *src){
    
    _empty_address_space(dest);

    dest->space = malloc(sizeof(address_space) * src->size);
    dest->size = src->size;
    dest->nr_pages = src->nr_pages;
    for(int i = 0; i < dest->size; i++){
        dest->space[i].address = src->space[i].address;
        dest->space[i].size = src->space[i].size;
    }
}

/**
 * @brief This function finds and adds the new vma onto the argument
 *        delta vma. The delta vma will be emptied before updating
 * 
 * @param curr_vma 
 * @param delta_vma 
 * @return int 
 */

int _add_new_or_extended_vma(address_spaces* curr_vma, address_spaces* delta_vma){
    int count = 0;

    _empty_address_space(delta_vma);

    //Counting the vma address space that got extended
    for(int i = 0; i < curr_vma->size; i++){
        bool match_found = false;
        
        for(int j = 0; j < vm_stat_snapshot.size; j++){
            if(curr_vma->space[i].address == vm_stat_snapshot.space[j].address){
                if(curr_vma->space[i].size == vm_stat_snapshot.space[j].size){
                    
                    log_debug("curr_vma->space[i].address : %p                          \
                               vm_stat_snapshot.space[j].address : %p",                 \
                                curr_vma->space[i].address,                             \
                                vm_stat_snapshot.space[j].address);

                    log_debug("curr_vma->space[i].size : %p                             \
                               vm_stat_snapshot.space[j].size : %p",                    \
                                curr_vma->space[i].size,                                \
                                vm_stat_snapshot.space[j].size);
                    
                    //Setting the space as NULL since matched
                    match_found = true;
                    break;
                }
            }
        }

        if(!match_found){
            count++;

            //Updating the address space of delta_vma
            delta_vma->space = realloc(delta_vma->space,                                \
                                       sizeof(address_space) * count);
            delta_vma->space[count - 1].address = curr_vma->space[i].address;
            delta_vma->space[count - 1].size = curr_vma->space[i].size;

            delta_vma->size++;
            delta_vma->nr_pages += curr_vma->space[i].size;
        }

    }

    log_info("New or extended VMA count : %d", count);
    return count;
}

int _find_vma_delta(address_spaces* curr_vma, address_spaces* delta_vma){
    int ret = 0;

    ret = _add_new_or_extended_vma(curr_vma, delta_vma);
    if(ret){
        // If the curr_vma has been updated copy it into vm
        _copy_address_spaces(&vm_stat_snapshot, curr_vma);
    }

    return ret;
}



int find_vma_delta(address_spaces* curr_vma, address_spaces* delta_vma){
    int ret = 0;
    
    *delta_vma = (address_spaces){NULL, 0, 0};

    if(vm_stat_snapshot.space    == empty_vm_stat_snapshot.space     &&                 \
       vm_stat_snapshot.nr_pages == empty_vm_stat_snapshot.nr_pages  &&                 \
       vm_stat_snapshot.size     == empty_vm_stat_snapshot.size)
    {
        _copy_address_spaces(&vm_stat_snapshot, curr_vma);
        _copy_address_spaces(delta_vma, curr_vma);
        
        goto find_vma_delta_exit;
    }

    ret = _find_vma_delta(curr_vma, delta_vma);
    if(ret){
        log_info("delta vma size : %d", delta_vma->size);
        log_info("delta vma pages : %ld", delta_vma->nr_pages);
        for(int i = 0; i < ret; i++){
            log_info("delta vma space address : %lx size : %ld",                        \
                        delta_vma->space[i].address, delta_vma->space[i].size);
        }
    }

find_vma_delta_exit:
    return ret;
}