#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_print_string_t {
	const char* ms_str;
} ms_ecall_print_string_t;

typedef struct ms_ecall_send_params_t {
	int ms_parallel;
	int ms_warmup;
	int ms_repetitions;
	char* ms_benchmark;
	size_t ms_blen;
	struct _state ms_cookie;
} ms_ecall_send_params_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_ocall_gettimeofday_t {
	struct mytimeval* ms_tv;
} ms_ocall_gettimeofday_t;

typedef struct ms_ocall_do_getppid_t {
	iter_t ms_iterations;
	void* ms_cookie;
	size_t ms_clen;
} ms_ocall_do_getppid_t;

typedef struct ms_ocall_do_write_t {
	iter_t ms_iterations;
	void* ms_cookie;
	size_t ms_clen;
} ms_ocall_do_write_t;

typedef struct ms_ocall_do_read_t {
	iter_t ms_iterations;
	void* ms_cookie;
	size_t ms_clen;
} ms_ocall_do_read_t;

typedef struct ms_ocall_do_stat_t {
	iter_t ms_iterations;
	void* ms_cookie;
	size_t ms_clen;
} ms_ocall_do_stat_t;

typedef struct ms_ocall_do_fstat_t {
	iter_t ms_iterations;
	void* ms_cookie;
	size_t ms_clen;
} ms_ocall_do_fstat_t;

typedef struct ms_ocall_do_openclose_t {
	iter_t ms_iterations;
	void* ms_cookie;
	size_t ms_clen;
} ms_ocall_do_openclose_t;

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

static sgx_status_t SGX_CDECL Enclave_ocall_do_getppid(void* pms)
{
	ms_ocall_do_getppid_t* ms = SGX_CAST(ms_ocall_do_getppid_t*, pms);
	ocall_do_getppid(ms->ms_iterations, ms->ms_cookie, ms->ms_clen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_do_write(void* pms)
{
	ms_ocall_do_write_t* ms = SGX_CAST(ms_ocall_do_write_t*, pms);
	ocall_do_write(ms->ms_iterations, ms->ms_cookie, ms->ms_clen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_do_read(void* pms)
{
	ms_ocall_do_read_t* ms = SGX_CAST(ms_ocall_do_read_t*, pms);
	ocall_do_read(ms->ms_iterations, ms->ms_cookie, ms->ms_clen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_do_stat(void* pms)
{
	ms_ocall_do_stat_t* ms = SGX_CAST(ms_ocall_do_stat_t*, pms);
	ocall_do_stat(ms->ms_iterations, ms->ms_cookie, ms->ms_clen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_do_fstat(void* pms)
{
	ms_ocall_do_fstat_t* ms = SGX_CAST(ms_ocall_do_fstat_t*, pms);
	ocall_do_fstat(ms->ms_iterations, ms->ms_cookie, ms->ms_clen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_do_openclose(void* pms)
{
	ms_ocall_do_openclose_t* ms = SGX_CAST(ms_ocall_do_openclose_t*, pms);
	ocall_do_openclose(ms->ms_iterations, ms->ms_cookie, ms->ms_clen);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[8];
} ocall_table_Enclave = {
	8,
	{
		(void*)Enclave_ocall_print_string,
		(void*)Enclave_ocall_gettimeofday,
		(void*)Enclave_ocall_do_getppid,
		(void*)Enclave_ocall_do_write,
		(void*)Enclave_ocall_do_read,
		(void*)Enclave_ocall_do_stat,
		(void*)Enclave_ocall_do_fstat,
		(void*)Enclave_ocall_do_openclose,
	}
};
sgx_status_t ecall_print_string(sgx_enclave_id_t eid, const char* str)
{
	sgx_status_t status;
	ms_ecall_print_string_t ms;
	ms.ms_str = str;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_send_params(sgx_enclave_id_t eid, int parallel, int warmup, int repetitions, char* benchmark, size_t blen, struct _state cookie)
{
	sgx_status_t status;
	ms_ecall_send_params_t ms;
	ms.ms_parallel = parallel;
	ms.ms_warmup = warmup;
	ms.ms_repetitions = repetitions;
	ms.ms_benchmark = benchmark;
	ms.ms_blen = blen;
	ms.ms_cookie = cookie;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	return status;
}

