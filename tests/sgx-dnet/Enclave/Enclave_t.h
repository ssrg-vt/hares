#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "dnet_types.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void empty_ecall(void);
void ecall_trainer(list* sections, data* training_data, int pmem);
void ecall_tester(list* sections, data* test_data, int pmem);
void ecall_classify(list* sections, list* labels, image* im);

sgx_status_t SGX_CDECL ocall_open_file(const char* filename, flag oflag);
sgx_status_t SGX_CDECL ocall_close_file(void);
sgx_status_t SGX_CDECL ocall_fread(void* ptr, size_t size, size_t nmemb);
sgx_status_t SGX_CDECL ocall_fwrite(void* ptr, size_t size, size_t nmemb);
sgx_status_t SGX_CDECL ocall_print_string(const char* str);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);
sgx_status_t SGX_CDECL ocall_free_sec(section* sec);
sgx_status_t SGX_CDECL ocall_free_list(list* list);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
