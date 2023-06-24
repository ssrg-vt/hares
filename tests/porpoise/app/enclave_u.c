#include "enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_init_transfer_t {
	int ms_retval;
	struct syscall_arg_t* ms_syscall_arg_table;
	void* ms_buf7;
} ms_ecall_init_transfer_t;

typedef struct ms_ecall_shim_main_t {
	int ms_retval;
	int ms_argc;
	char** ms_argv;
} ms_ecall_shim_main_t;

typedef struct ms_ecall_sig_handler_t {
	int ms_signum;
} ms_ecall_sig_handler_t;

typedef struct ms_ecall_start_routine_t {
	void* ms_arg;
} ms_ecall_start_routine_t;

typedef struct ms_ecall_empty_t {
	int ms_retval;
} ms_ecall_empty_t;

typedef struct ms_ecall_perf_ocall_t {
	int ms_retval;
	int ms_count;
} ms_ecall_perf_ocall_t;

typedef struct ms_ocall_syscall_t {
	int ms_syscall_table_index;
} ms_ocall_syscall_t;

typedef struct ms_ocall_print_string_t {
	char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_ocall_empty_t {
	int ms_retval;
} ms_ocall_empty_t;

static sgx_status_t SGX_CDECL enclave_ocall_syscall(void* pms)
{
	ms_ocall_syscall_t* ms = SGX_CAST(ms_ocall_syscall_t*, pms);
	ocall_syscall(ms->ms_syscall_table_index);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_empty(void* pms)
{
	ms_ocall_empty_t* ms = SGX_CAST(ms_ocall_empty_t*, pms);
	ms->ms_retval = ocall_empty();

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[3];
} ocall_table_enclave = {
	3,
	{
		(void*)enclave_ocall_syscall,
		(void*)enclave_ocall_print_string,
		(void*)enclave_ocall_empty,
	}
};
sgx_status_t ecall_init_transfer(sgx_enclave_id_t eid, int* retval, struct syscall_arg_t* syscall_arg_table, void* buf7)
{
	sgx_status_t status;
	ms_ecall_init_transfer_t ms;
	ms.ms_syscall_arg_table = syscall_arg_table;
	ms.ms_buf7 = buf7;
	status = sgx_ecall(eid, 0, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_shim_main(sgx_enclave_id_t eid, int* retval, int argc, char** argv)
{
	sgx_status_t status;
	ms_ecall_shim_main_t ms;
	ms.ms_argc = argc;
	ms.ms_argv = argv;
	status = sgx_ecall(eid, 1, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_sig_handler(sgx_enclave_id_t eid, int signum)
{
	sgx_status_t status;
	ms_ecall_sig_handler_t ms;
	ms.ms_signum = signum;
	status = sgx_ecall(eid, 2, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_start_routine(sgx_enclave_id_t eid, void* arg)
{
	sgx_status_t status;
	ms_ecall_start_routine_t ms;
	ms.ms_arg = arg;
	status = sgx_ecall(eid, 3, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_empty(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_ecall_empty_t ms;
	status = sgx_ecall(eid, 4, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_perf_ocall(sgx_enclave_id_t eid, int* retval, int count)
{
	sgx_status_t status;
	ms_ecall_perf_ocall_t ms;
	ms.ms_count = count;
	status = sgx_ecall(eid, 5, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

