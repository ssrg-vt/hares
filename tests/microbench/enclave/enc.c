// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <stdio.h>
#include <assert.h>

#include "microbench_t.h"

void ecall_5(int a1, int a2, int a3, int a4, int a5){usleep(500000);}

void ecall_10(int a1, int a2, int a3, int a4, int a5, int a6, int a7, 
	     int a8, int a9,int a10){}

void ecall_15(int a1, int a2, int a3, int a4, int a5, int a6, int a7, 
	      int a8, int a9,int a10,int a11,int a12, int a13, int a14, int a15){}

void ecall_20(int a1, int a2, int a3, int a4, int a5, int a6, int a7, 
	      int a8, int a9, int a10,int a11,int a12, int a13, int a14, int a15,
	      int a16, int a17, int a18, int a19, int a20){}

void ecall(void)
{
        printf("Inside enclave call\n");
	// Empty call...
}
