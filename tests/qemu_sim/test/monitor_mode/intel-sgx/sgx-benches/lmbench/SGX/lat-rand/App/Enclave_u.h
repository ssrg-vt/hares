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

sgx_status_t ecall_print_string(sgx_enclave_id_t eid, const char* str);
sgx_status_t ecall_send_params(sgx_enclave_id_t eid, int parallel, int warmup, int repetitions);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
