#ifndef __VMSCAN_UTIL_H__
#define __VMSCAN_UTIL_H__

int find_vma_delta(address_spaces* curr_vma, address_spaces* delta_vma);
int scan_address_space(pid_t child_pid, address_spaces *spaces);
#endif