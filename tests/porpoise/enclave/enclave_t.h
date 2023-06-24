#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _syscall_arg_t
#define _syscall_arg_t
typedef struct syscall_arg_t {
	int busy;
	long int* arg0;
	long int* arg1;
	long int* arg2;
	long int* arg3;
	long int* arg4;
	long int* arg5;
	long int* arg6;
	long int* arg7;
	long int* arg8;
	long int* err_no;
} syscall_arg_t;
#endif

int ecall_init_transfer(struct syscall_arg_t* syscall_arg_table, void* buf7);
int ecall_shim_main(int argc, char** argv);
void ecall_sig_handler(int signum);
void ecall_start_routine(void* arg);
int ecall_empty(void);
int ecall_perf_ocall(int count);

sgx_status_t SGX_CDECL ocall_syscall(int syscall_table_index);
sgx_status_t SGX_CDECL ocall_print_string(char* str);
sgx_status_t SGX_CDECL ocall_empty(int* retval);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
