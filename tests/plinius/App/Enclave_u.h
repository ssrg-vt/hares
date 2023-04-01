#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "dnet_types.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_OPEN_FILE_DEFINED__
#define OCALL_OPEN_FILE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_open_file, (const char* filename, flag oflag));
#endif
#ifndef OCALL_CLOSE_FILE_DEFINED__
#define OCALL_CLOSE_FILE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_close_file, (void));
#endif
#ifndef OCALL_FREAD_DEFINED__
#define OCALL_FREAD_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fread, (void* ptr, size_t size, size_t nmemb));
#endif
#ifndef OCALL_FWRITE_DEFINED__
#define OCALL_FWRITE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fwrite, (void* ptr, size_t size, size_t nmemb));
#endif
#ifndef MY_OCALL_CLOSE_DEFINED__
#define MY_OCALL_CLOSE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, my_ocall_close, (void));
#endif
#ifndef OCALL_READ_DISK_CHUNK_DEFINED__
#define OCALL_READ_DISK_CHUNK_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_read_disk_chunk, (void));
#endif
#ifndef OCALL_PRINT_STRING_DEFINED__
#define OCALL_PRINT_STRING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
#endif
#ifndef OCALL_START_CLOCK_DEFINED__
#define OCALL_START_CLOCK_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_start_clock, (void));
#endif
#ifndef OCALL_STOP_CLOCK_DEFINED__
#define OCALL_STOP_CLOCK_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_stop_clock, (void));
#endif
#ifndef OCALL_ADD_LOSS_DEFINED__
#define OCALL_ADD_LOSS_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_add_loss, (void));
#endif
#ifndef SGX_OC_CPUIDEX_DEFINED__
#define SGX_OC_CPUIDEX_DEFINED__
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
#endif
#ifndef SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
#endif
#ifndef SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
#endif
#ifndef SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
#endif
#ifndef SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));
#endif
#ifndef OCALL_FREE_SEC_DEFINED__
#define OCALL_FREE_SEC_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_free_sec, (section* sec));
#endif
#ifndef OCALL_FREE_LIST_DEFINED__
#define OCALL_FREE_LIST_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_free_list, (list* list));
#endif

sgx_status_t ecall_init(sgx_enclave_id_t eid, void* per_out, uint8_t* addr);
sgx_status_t ecall_nvram_worker(sgx_enclave_id_t eid, int val, size_t tid);
sgx_status_t empty_ecall(sgx_enclave_id_t eid);
sgx_status_t ecall_trainer(sgx_enclave_id_t eid, list* sections, data* training_data, int pmem, comm_info* o_point);
sgx_status_t ecall_tester(sgx_enclave_id_t eid, list* sections, data* test_data, int pmem);
sgx_status_t ecall_classify(sgx_enclave_id_t eid, list* sections, list* labels, image* im);
sgx_status_t ecall_set_data(sgx_enclave_id_t eid, data* data);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
