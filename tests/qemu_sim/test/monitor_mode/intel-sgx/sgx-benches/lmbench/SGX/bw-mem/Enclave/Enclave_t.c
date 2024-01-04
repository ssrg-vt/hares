#include "Enclave_t.h"

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

static sgx_status_t SGX_CDECL sgx_ecall_send_params(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_send_params_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_send_params_t* ms = SGX_CAST(ms_ecall_send_params_t*, pms);
	ms_ecall_send_params_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_send_params_t), ms, sizeof(ms_ecall_send_params_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_benchmark = __in_ms.ms_benchmark;
	size_t _tmp_blen = __in_ms.ms_blen;
	size_t _len_benchmark = _tmp_blen;
	char* _in_benchmark = NULL;

	CHECK_UNIQUE_POINTER(_tmp_benchmark, _len_benchmark);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_benchmark != NULL && _len_benchmark != 0) {
		if ( _len_benchmark % sizeof(*_tmp_benchmark) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_benchmark = (char*)malloc(_len_benchmark);
		if (_in_benchmark == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_benchmark, _len_benchmark, _tmp_benchmark, _len_benchmark)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	ecall_send_params(__in_ms.ms_parallel, __in_ms.ms_warmup, __in_ms.ms_repetitions, _in_benchmark, _tmp_blen, __in_ms.ms_cookie);

err:
	if (_in_benchmark) free(_in_benchmark);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[1];
} g_ecall_table = {
	1,
	{
		{(void*)(uintptr_t)sgx_ecall_send_params, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[2][1];
} g_dyn_entry_table = {
	2,
	{
		{0, },
		{0, },
	}
};


sgx_status_t SGX_CDECL ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = 256;

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
		if (memcpy_verw_s(&ms->ms_str, sizeof(const char*), &__tmp, sizeof(const char*))) {
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

	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_gettimeofday(struct mytimeval* tv)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_tv = sizeof(struct mytimeval);

	ms_ocall_gettimeofday_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_gettimeofday_t);
	void *__tmp = NULL;

	void *__tmp_tv = NULL;

	CHECK_ENCLAVE_POINTER(tv, _len_tv);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (tv != NULL) ? _len_tv : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_gettimeofday_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_gettimeofday_t));
	ocalloc_size -= sizeof(ms_ocall_gettimeofday_t);

	if (tv != NULL) {
		if (memcpy_verw_s(&ms->ms_tv, sizeof(struct mytimeval*), &__tmp, sizeof(struct mytimeval*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_tv = __tmp;
		memset_verw(__tmp_tv, 0, _len_tv);
		__tmp = (void *)((size_t)__tmp + _len_tv);
		ocalloc_size -= _len_tv;
	} else {
		ms->ms_tv = NULL;
	}

	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (tv) {
			if (memcpy_s((void*)tv, _len_tv, __tmp_tv, _len_tv)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

