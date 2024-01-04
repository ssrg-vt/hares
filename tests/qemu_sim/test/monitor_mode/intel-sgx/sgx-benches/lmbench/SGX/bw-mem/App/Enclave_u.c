#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_send_params_t {
	int ms_parallel;
	int ms_warmup;
	int ms_repetitions;
	char* ms_benchmark;
	size_t ms_blen;
	state_t ms_cookie;
} ms_ecall_send_params_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_ocall_gettimeofday_t {
	struct mytimeval* ms_tv;
} ms_ocall_gettimeofday_t;

static sgx_status_t SGX_CDECL Enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_gettimeofday(void* pms)
{
	ms_ocall_gettimeofday_t* ms = SGX_CAST(ms_ocall_gettimeofday_t*, pms);
	ocall_gettimeofday(ms->ms_tv);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[2];
} ocall_table_Enclave = {
	2,
	{
		(void*)Enclave_ocall_print_string,
		(void*)Enclave_ocall_gettimeofday,
	}
};
sgx_status_t ecall_send_params(sgx_enclave_id_t eid, int parallel, int warmup, int repetitions, char* benchmark, size_t blen, state_t cookie)
{
	sgx_status_t status;
	ms_ecall_send_params_t ms;
	ms.ms_parallel = parallel;
	ms.ms_warmup = warmup;
	ms.ms_repetitions = repetitions;
	ms.ms_benchmark = benchmark;
	ms.ms_blen = blen;
	ms.ms_cookie = cookie;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	return status;
}

