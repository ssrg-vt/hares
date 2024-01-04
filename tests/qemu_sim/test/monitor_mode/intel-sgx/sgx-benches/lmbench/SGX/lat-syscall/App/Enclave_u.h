#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "common_types.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_PRINT_STRING_DEFINED__
#define OCALL_PRINT_STRING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
#endif
#ifndef OCALL_GETTIMEOFDAY_DEFINED__
#define OCALL_GETTIMEOFDAY_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_gettimeofday, (struct mytimeval* tv));
#endif
#ifndef OCALL_DO_GETPPID_DEFINED__
#define OCALL_DO_GETPPID_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_do_getppid, (iter_t iterations, void* cookie, size_t clen));
#endif
#ifndef OCALL_DO_WRITE_DEFINED__
#define OCALL_DO_WRITE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_do_write, (iter_t iterations, void* cookie, size_t clen));
#endif
#ifndef OCALL_DO_READ_DEFINED__
#define OCALL_DO_READ_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_do_read, (iter_t iterations, void* cookie, size_t clen));
#endif
#ifndef OCALL_DO_STAT_DEFINED__
#define OCALL_DO_STAT_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_do_stat, (iter_t iterations, void* cookie, size_t clen));
#endif
#ifndef OCALL_DO_FSTAT_DEFINED__
#define OCALL_DO_FSTAT_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_do_fstat, (iter_t iterations, void* cookie, size_t clen));
#endif
#ifndef OCALL_DO_OPENCLOSE_DEFINED__
#define OCALL_DO_OPENCLOSE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_do_openclose, (iter_t iterations, void* cookie, size_t clen));
#endif

sgx_status_t ecall_print_string(sgx_enclave_id_t eid, const char* str);
sgx_status_t ecall_send_params(sgx_enclave_id_t eid, int parallel, int warmup, int repetitions, char* benchmark, size_t blen, struct _state cookie);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
