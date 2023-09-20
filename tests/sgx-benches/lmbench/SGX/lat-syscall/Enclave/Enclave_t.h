#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "common_types.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void ecall_print_string(const char* str);
void ecall_send_params(int parallel, int warmup, int repetitions, char* benchmark, size_t blen, struct _state cookie);

sgx_status_t SGX_CDECL ocall_print_string(const char* str);
sgx_status_t SGX_CDECL ocall_gettimeofday(struct mytimeval* tv);
sgx_status_t SGX_CDECL ocall_do_getppid(iter_t iterations, void* cookie, size_t clen);
sgx_status_t SGX_CDECL ocall_do_write(iter_t iterations, void* cookie, size_t clen);
sgx_status_t SGX_CDECL ocall_do_read(iter_t iterations, void* cookie, size_t clen);
sgx_status_t SGX_CDECL ocall_do_stat(iter_t iterations, void* cookie, size_t clen);
sgx_status_t SGX_CDECL ocall_do_fstat(iter_t iterations, void* cookie, size_t clen);
sgx_status_t SGX_CDECL ocall_do_openclose(iter_t iterations, void* cookie, size_t clen);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
