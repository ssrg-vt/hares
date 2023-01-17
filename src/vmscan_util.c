#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <pthread.h>

#include "../inc/log.h"
#include "../inc/popsgx_child.h"

#define log_info(args...) 

address_spaces empty_vm_stat_snapshot = {NULL, -1, -1};
static address_spaces vm_stat_snapshot = {NULL, -1, -1};

void _empty_address_space(address_spaces* addr){
    addr->space = (address_space*)realloc(addr->space, 0);
    addr->size = 0;
    addr->nr_pages = 0;
}

void empty_address_space(address_spaces* addr){
    
    if(addr == NULL)
        return;

    _empty_address_space(addr);
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
        dest->space[i].type = src->space[i].type;
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
                if((curr_vma->space[i].size == vm_stat_snapshot.space[j].size))  
                {
                    
                    log_info("curr_vma->space[i].address : %p                           \
                               vm_stat_snapshot.space[j].address : %p",                 \
                                curr_vma->space[i].address,                             \
                                vm_stat_snapshot.space[j].address);

                    log_info("curr_vma->space[i].size : %p                              \
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
            delta_vma->space[count - 1].type = curr_vma->space[i].type;

            delta_vma->size++;
            delta_vma->nr_pages += curr_vma->space[i].size;
        }
    }

    log_info("New or extended VMA count : %d", count);
    return count;
}

int _find_new_vma_delta(address_spaces* curr_vma, address_spaces* delta_vma){
    int ret = 0;

    ret = _add_new_or_extended_vma(curr_vma, delta_vma);
    if(ret){
        // If the curr_vma has been updated copy it into vm
        _copy_address_spaces(&vm_stat_snapshot, curr_vma);
    }

    return ret;
}


int find_new_vma_delta(address_spaces* curr_vma, address_spaces* delta_vma){
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

    ret = _find_new_vma_delta(curr_vma, delta_vma);
    if(ret){
        log_info("delta vma size : %d", delta_vma->size);
        log_info("delta vma pages : %ld", delta_vma->nr_pages);
        for(int i = 0; i < ret; i++){
            log_info("delta vma space address : %lx size : %ld type : %d",                        \
                        delta_vma->space[i].address, delta_vma->space[i].size, delta_vma->space[i].type);
        }
    }

find_vma_delta_exit:
    return ret;
}

int accumulate_diff_between_vma(address_spaces* src_vma, address_spaces* dest_vma){
    int ret = 0;
    address_spaces temp = {NULL, 0, 0};

    for(int i = 0; i < src_vma->size; i++){
        bool match_found = false;

        for(int j = 0; j < dest_vma->size; j++){
            if(dest_vma->space[i].address >= src_vma->space[i].address &&  \
               dest_vma->space[i].address < (src_vma->space[i].address + src_vma->space[i].size)){
                match_found = true;
                break;
            }
        }

        if(!match_found){
            temp.space = (address_space*)realloc(temp.space, sizeof(address_space) * (temp.size + 1));
            temp.space[temp.size].address = src_vma->space[i].address;
            temp.space[temp.size].size = src_vma->space[i].size;
            temp.space[temp.size].type = src_vma->space[i].type;
            temp.size += 1;
            temp.nr_pages += src_vma->space[i].size;
        }
    }

    //accumulating the difference vma
    for(int i = 0; i < temp.size; i++){
        int size = dest_vma->size;
        dest_vma->space = (address_space*) realloc(dest_vma->space, sizeof(address_space) * (size + 1));
        dest_vma->space[size].address = temp.space[i].address;
        dest_vma->space[size].size = temp.space[i].size;
        dest_vma->space[size].type = temp.space[i].type;

        dest_vma->size += 1;
        dest_vma->nr_pages += 1;
        ret++;
    }

    return ret;
}

int accumulate_diff_between_vma_with_type(address_spaces* src_vma, address_spaces* dest_vma, address_type type){
    int ret = 0;
    address_spaces temp = {NULL, 0, 0};

    for(int i = 0; i < src_vma->size; i++){
        bool match_found = false;

        for(int j = 0; j < dest_vma->size; j++){
            if(dest_vma->space[i].address >= src_vma->space[i].address &&  \
               dest_vma->space[i].address < (src_vma->space[i].address + src_vma->space[i].size)){
                match_found = true;
                break;
            }
        }

        if(!match_found && src_vma->space[i].type == type){
            temp.space = (address_space*)realloc(temp.space, sizeof(address_space) * (temp.size + 1));
            temp.space[temp.size].address = src_vma->space[i].address;
            temp.space[temp.size].size = src_vma->space[i].size;
            temp.space[temp.size].type = src_vma->space[i].type;
            temp.size += 1;
            temp.nr_pages += 1;
        }
    }

    //accumulating the difference vma
    for(int i = 0; i < temp.size; i++){
        int size = dest_vma->size;
        dest_vma->space = (address_space*) realloc(dest_vma->space, sizeof(address_space) * (size + 1));
        dest_vma->space[size].address = temp.space[i].address;
        dest_vma->space[size].size = temp.space[i].size;
        dest_vma->space[size].type = temp.space[i].type;

        dest_vma->size += 1;
        dest_vma->nr_pages += 1;
        ret++;
    }

    return ret;
}

/**
 * @brief Read the number of read-write address space
 * 
 * @param fp 
 * @return int 
 */
static int cnt_rw_address_space(FILE *fp){
    int read_write_addr_cnt = 0;
    char line[128];

    if(!fp)
        return -1;

    while(fgets(line, sizeof(line), fp)){
        char * token = strtok(line, " ");
        int i = 0;
        while(token != NULL){
            //extract the rw-p word from the maps line
            if(i == 1){
                if(strchr(token, 'w') != NULL && strchr(token, 'p') != NULL){
                    //count the number of lines containing the word w in rwxp
                    read_write_addr_cnt++;
                }
                break;
            }
            token = strtok(NULL, " ");
            i++;
        }
    }

    return read_write_addr_cnt;
}

/**
 * @brief Scan and retrieve the address space information of the spaces
 * containing read and write permissions!!
 * 
 * @param child_pid 
 * @return int 
 */
int scan_address_space(popsgx_child *child, address_spaces *spaces){
    int ret = 0;
    char file_name[50];
    char line[128];
    FILE *fp;
    pid_t child_pid = child->c_pid;
    int read_write_addr_cnt = 0;

    ret = snprintf(file_name, 50, "/proc/%d/maps", child_pid);
    if(ret < 0){
        log_error("failed in finding the maps file for the process %d", child_pid);
        goto get_frame_fail;
    }

    fp = fopen(file_name, "r");
    if(!fp){
        ret = errno;
        goto get_frame_fail;
    }

    read_write_addr_cnt = cnt_rw_address_space(fp);
    if(read_write_addr_cnt == -1){
        log_error("failed in reading the number of rw address spaces");
        ret = read_write_addr_cnt;
        goto get_frame_fail;
    }else{
        fseek(fp, 0, SEEK_SET);
    }
    log_info("There are %d address spaces with read-write permissions", read_write_addr_cnt);

    free(spaces->space);
    spaces->space = malloc(sizeof(address_space) * read_write_addr_cnt);
    spaces->size = read_write_addr_cnt;

    ret = 0;
    int iter = 0;
    while(fgets(line, sizeof(line), fp)){
        //log_info("%s", line);
        bool is_set = false;
        char * token = strtok(line, " ");
        int i = 0;
        while(token != NULL){
            //extract the rw-p word from the maps line
            if(i == 1){
                if(strchr(token, 'w') != NULL && strchr(token, 'p') != NULL){
                    unsigned long end_address;
                    char *ptr;
                    spaces->space[iter].address =  strtoul(line, &ptr, 16);
                    end_address = strtoul(ptr+1, NULL, 16);
                    spaces->space[iter].size =  (end_address - spaces->space[iter].address)/4096;
                    log_info("the start addr : %lx end addr : %lx", spaces->space[iter].address, end_address);
                    ret += spaces->space[iter].size;
                    is_set = true;
                }
                //break;
            }

            if(is_set)
                if(i == 5){
                    if(strstr(token, "[heap]") != NULL){
                        spaces->space[iter].type = HEAP;
                        //while(1);
                    }else if(strstr(token, "[stack]") != NULL){
                        spaces->space[iter].type = STACK;
                    }else if(strlen(token) == 1){
                        //String length of anonymous mapping would always be 1
                        spaces->space[iter].type = ANONYMOUS;
                    }else{
                        spaces->space[iter].type = FILE_BACKED;
                    }
                    log_info("Found rw address at 0x%lx with a size %ld and type %d",                                   \
                              spaces->space[iter].address, spaces->space[iter].size, spaces->space[iter].type);
                    iter++;
                    break;
                }
                
            token = strtok(NULL, " ");
            i++;
        }
    }

    fclose(fp);

    spaces->nr_pages = ret;

    get_frame_fail:
        return ret;
}

/**
 * @brief Get the stack frame address
 * 
 * @param tracee_pid 
 * @param stack_start_address 
 * @return int (size of the stack frame)
 */
int get_virtual_address_frame_by_name(pid_t tracee_pid, unsigned long *start_address, unsigned long *end_address, char *frame){
    int ret = 0;
    char *sret;
    FILE *fp;
    char file_name[50];
    char line[128];
    unsigned long stack_end_address;

    ret = snprintf(file_name, 50, "/proc/%d/maps", tracee_pid);
    if(ret < 0){
        log_error("failed in finding the maps file for the process %d", tracee_pid);
        goto get_stack_frame_fail;
    }

    fp = fopen(file_name, "r");
    if(!fp)
        goto get_stack_frame_fail;
    
    while(fgets(line, sizeof(line), fp)){
        sret = strstr(line, frame);
        if(sret){
            char *ptr;
            *start_address = strtoul(line, &ptr, 16);            
            stack_end_address = strtoul(ptr+1, NULL, 16);
            log_info("The starting address of the pid %d %s : %lx", tracee_pid, frame, *start_address);
            log_info("The ending address of the pid %d %s : %lx", tracee_pid, frame, stack_end_address);
            ret = stack_end_address - *start_address;
            *end_address = stack_end_address;
            break;
        }
    }

    if(!sret){
        log_debug("Could not find the stack frame in the tracee proc map");
        ret = -1;
    }
    
    fclose(fp);

get_stack_frame_fail:
    return ret;
}