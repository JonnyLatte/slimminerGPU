#ifndef __GPU_H__
#define __GPU_H__

#include <stdbool.h>
#include <stdio.h>
#include <CL/cl.h>


typedef struct {
	cl_kernel kernel_scanhash;

	cl_mem mem_block;
	cl_mem mem_halfstate;
	cl_mem mem_output;
	cl_mem mem_result;

	uint32_t *results_hash;
	
	size_t local;

} GPU_WORKER;

int initOpenCL(int prefered_platform, int prefered_device, int work_size);
int initGPU_WORKER(GPU_WORKER *gpu);

int scanhash_dcrypt_gpu(GPU_WORKER *gpu,int thr_id, uint32_t *pdata,
                    unsigned char *digest, const uint32_t *ptarget,
                    uint32_t max_nonce, unsigned long *hashes_done, int num_iter,unsigned long *hashes_skipped);

#endif
