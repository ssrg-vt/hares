#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_trainer_t {
	list* ms_sections;
	data* ms_training_data;
	int ms_pmem;
} ms_ecall_trainer_t;

typedef struct ms_ecall_tester_t {
	list* ms_sections;
	data* ms_test_data;
	int ms_pmem;
} ms_ecall_tester_t;

typedef struct ms_ecall_classify_t {
	list* ms_sections;
	list* ms_labels;
	image* ms_im;
} ms_ecall_classify_t;

typedef struct ms_ocall_open_file_t {
	const char* ms_filename;
	flag ms_oflag;
} ms_ocall_open_file_t;

typedef struct ms_ocall_fread_t {
	void* ms_ptr;
	size_t ms_size;
	size_t ms_nmemb;
} ms_ocall_fread_t;

typedef struct ms_ocall_fwrite_t {
	void* ms_ptr;
	size_t ms_size;
	size_t ms_nmemb;
} ms_ocall_fwrite_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

typedef struct ms_ocall_free_sec_t {
	section* ms_sec;
} ms_ocall_free_sec_t;

typedef struct ms_ocall_free_list_t {
	list* ms_list;
} ms_ocall_free_list_t;

static sgx_status_t SGX_CDECL Enclave_ocall_open_file(void* pms)
{
	ms_ocall_open_file_t* ms = SGX_CAST(ms_ocall_open_file_t*, pms);
	ocall_open_file(ms->ms_filename, ms->ms_oflag);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_close_file(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_close_file();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_fread(void* pms)
{
	ms_ocall_fread_t* ms = SGX_CAST(ms_ocall_fread_t*, pms);
	ocall_fread(ms->ms_ptr, ms->ms_size, ms->ms_nmemb);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_fwrite(void* pms)
{
	ms_ocall_fwrite_t* ms = SGX_CAST(ms_ocall_fwrite_t*, pms);
	ocall_fwrite(ms->ms_ptr, ms->ms_size, ms->ms_nmemb);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_free_sec(void* pms)
{
	ms_ocall_free_sec_t* ms = SGX_CAST(ms_ocall_free_sec_t*, pms);
	ocall_free_sec(ms->ms_sec);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_free_list(void* pms)
{
	ms_ocall_free_list_t* ms = SGX_CAST(ms_ocall_free_list_t*, pms);
	ocall_free_list(ms->ms_list);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[12];
} ocall_table_Enclave = {
	12,
	{
		(void*)Enclave_ocall_open_file,
		(void*)Enclave_ocall_close_file,
		(void*)Enclave_ocall_fread,
		(void*)Enclave_ocall_fwrite,
		(void*)Enclave_ocall_print_string,
		(void*)Enclave_sgx_oc_cpuidex,
		(void*)Enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)Enclave_sgx_thread_set_multiple_untrusted_events_ocall,
		(void*)Enclave_ocall_free_sec,
		(void*)Enclave_ocall_free_list,
	}
};
sgx_status_t empty_ecall(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_trainer(sgx_enclave_id_t eid, list* sections, data* training_data, int pmem)
{
	sgx_status_t status;
	ms_ecall_trainer_t ms;
	ms.ms_sections = sections;
	ms.ms_training_data = training_data;
	ms.ms_pmem = pmem;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_tester(sgx_enclave_id_t eid, list* sections, data* test_data, int pmem)
{
	sgx_status_t status;
	ms_ecall_tester_t ms;
	ms.ms_sections = sections;
	ms.ms_test_data = test_data;
	ms.ms_pmem = pmem;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_classify(sgx_enclave_id_t eid, list* sections, list* labels, image* im)
{
	sgx_status_t status;
	ms_ecall_classify_t ms;
	ms.ms_sections = sections;
	ms.ms_labels = labels;
	ms.ms_im = im;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	return status;
}

