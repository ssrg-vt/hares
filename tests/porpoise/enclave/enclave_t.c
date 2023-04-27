#include "enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

static sgx_status_t SGX_CDECL sgx_ecall_init_transfer(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_init_transfer_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_init_transfer_t* ms = SGX_CAST(ms_ecall_init_transfer_t*, pms);
	ms_ecall_init_transfer_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_init_transfer_t), ms, sizeof(ms_ecall_init_transfer_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	struct syscall_arg_t* _tmp_syscall_arg_table = __in_ms.ms_syscall_arg_table;
	void* _tmp_buf7 = __in_ms.ms_buf7;
	int _in_retval;


	_in_retval = ecall_init_transfer(_tmp_syscall_arg_table, _tmp_buf7);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_shim_main(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_shim_main_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_shim_main_t* ms = SGX_CAST(ms_ecall_shim_main_t*, pms);
	ms_ecall_shim_main_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_shim_main_t), ms, sizeof(ms_ecall_shim_main_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	char** _tmp_argv = __in_ms.ms_argv;
	int _in_retval;


	_in_retval = ecall_shim_main(__in_ms.ms_argc, _tmp_argv);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_sig_handler(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_sig_handler_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_sig_handler_t* ms = SGX_CAST(ms_ecall_sig_handler_t*, pms);
	ms_ecall_sig_handler_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_sig_handler_t), ms, sizeof(ms_ecall_sig_handler_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;


	ecall_sig_handler(__in_ms.ms_signum);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_start_routine(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_start_routine_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_start_routine_t* ms = SGX_CAST(ms_ecall_start_routine_t*, pms);
	ms_ecall_start_routine_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_start_routine_t), ms, sizeof(ms_ecall_start_routine_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_arg = __in_ms.ms_arg;


	ecall_start_routine(_tmp_arg);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_empty(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_empty_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_empty_t* ms = SGX_CAST(ms_ecall_empty_t*, pms);
	ms_ecall_empty_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_empty_t), ms, sizeof(ms_ecall_empty_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	int _in_retval;


	_in_retval = ecall_empty();
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_perf_ocall(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_perf_ocall_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_perf_ocall_t* ms = SGX_CAST(ms_ecall_perf_ocall_t*, pms);
	ms_ecall_perf_ocall_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_perf_ocall_t), ms, sizeof(ms_ecall_perf_ocall_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	int _in_retval;


	_in_retval = ecall_perf_ocall(__in_ms.ms_count);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[6];
} g_ecall_table = {
	6,
	{
		{(void*)(uintptr_t)sgx_ecall_init_transfer, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_shim_main, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_sig_handler, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_start_routine, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_empty, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_perf_ocall, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[3][6];
} g_dyn_entry_table = {
	3,
	{
		{0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_syscall(int syscall_table_index)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_syscall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_syscall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_syscall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_syscall_t));
	ocalloc_size -= sizeof(ms_ocall_syscall_t);

	if (memcpy_verw_s(&ms->ms_syscall_table_index, sizeof(ms->ms_syscall_table_index), &syscall_table_index, sizeof(syscall_table_index))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_print_string(char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));
	ocalloc_size -= sizeof(ms_ocall_print_string_t);

	if (str != NULL) {
		if (memcpy_verw_s(&ms->ms_str, sizeof(char*), &__tmp, sizeof(char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}

	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_empty(int* retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_empty_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_empty_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_empty_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_empty_t));
	ocalloc_size -= sizeof(ms_ocall_empty_t);

	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

