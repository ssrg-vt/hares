#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */


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

#ifndef OCALL_SYSCALL_DEFINED__
#define OCALL_SYSCALL_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_syscall, (int syscall_table_index));
#endif
#ifndef OCALL_PRINT_STRING_DEFINED__
#define OCALL_PRINT_STRING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (char* str));
#endif
#ifndef OCALL_EMPTY_DEFINED__
#define OCALL_EMPTY_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_empty, (void));
#endif

sgx_status_t ecall_init_transfer(sgx_enclave_id_t eid, int* retval, struct syscall_arg_t* syscall_arg_table, void* buf7);
sgx_status_t ecall_shim_main(sgx_enclave_id_t eid, int* retval, int argc, char** argv);
sgx_status_t ecall_sig_handler(sgx_enclave_id_t eid, int signum);
sgx_status_t ecall_start_routine(sgx_enclave_id_t eid, void* arg);
sgx_status_t ecall_empty(sgx_enclave_id_t eid, int* retval);
sgx_status_t ecall_perf_ocall(sgx_enclave_id_t eid, int* retval, int count);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
