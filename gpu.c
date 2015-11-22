#include "gpu.h"
#include "miner.h"

#include <string.h>
#include <stdlib.h> 
#include <stdio.h>

#include "dcrypt.h"


const char * CL_ERR_STR(cl_int err)
{
	#define CASE_ERR(E) case E : return #E;

	switch (err)
	{
		CASE_ERR(CL_SUCCESS)                                 
		CASE_ERR(CL_DEVICE_NOT_FOUND)                        
		CASE_ERR(CL_DEVICE_NOT_AVAILABLE)                     
		CASE_ERR(CL_COMPILER_NOT_AVAILABLE)                   
		CASE_ERR(CL_MEM_OBJECT_ALLOCATION_FAILURE)            
		CASE_ERR(CL_OUT_OF_RESOURCES)                         
		CASE_ERR(CL_OUT_OF_HOST_MEMORY)                       
		CASE_ERR(CL_PROFILING_INFO_NOT_AVAILABLE)             
		CASE_ERR(CL_MEM_COPY_OVERLAP)                         
		CASE_ERR(CL_IMAGE_FORMAT_MISMATCH)                    
		CASE_ERR(CL_IMAGE_FORMAT_NOT_SUPPORTED)              
		CASE_ERR(CL_BUILD_PROGRAM_FAILURE)                    
		CASE_ERR(CL_MAP_FAILURE)                              
		CASE_ERR(CL_MISALIGNED_SUB_BUFFER_OFFSET)            
		CASE_ERR(CL_EXEC_STATUS_ERROR_FOR_EVENTS_IN_WAIT_LIST) 
		CASE_ERR(CL_COMPILE_PROGRAM_FAILURE)                 
		CASE_ERR(CL_LINKER_NOT_AVAILABLE)                    
		CASE_ERR(CL_LINK_PROGRAM_FAILURE)                     
		CASE_ERR(CL_DEVICE_PARTITION_FAILED)                  
		CASE_ERR(CL_KERNEL_ARG_INFO_NOT_AVAILABLE)            
		CASE_ERR(CL_INVALID_VALUE)                           
		CASE_ERR(CL_INVALID_DEVICE_TYPE)                      
		CASE_ERR(CL_INVALID_PLATFORM)                         
		CASE_ERR(CL_INVALID_DEVICE)                          
		CASE_ERR(CL_INVALID_CONTEXT)                          
		CASE_ERR(CL_INVALID_QUEUE_PROPERTIES)                 
		CASE_ERR(CL_INVALID_COMMAND_QUEUE)                    
		CASE_ERR(CL_INVALID_HOST_PTR)                         
		CASE_ERR(CL_INVALID_MEM_OBJECT)                       
		CASE_ERR(CL_INVALID_IMAGE_FORMAT_DESCRIPTOR)          
		CASE_ERR(CL_INVALID_IMAGE_SIZE)         
		CASE_ERR(CL_INVALID_SAMPLER)                      
		CASE_ERR(CL_INVALID_BINARY)                        
		CASE_ERR(CL_INVALID_BUILD_OPTIONS)                    
		CASE_ERR(CL_INVALID_PROGRAM)                   
		CASE_ERR(CL_INVALID_PROGRAM_EXECUTABLE)               
		CASE_ERR(CL_INVALID_KERNEL_NAME)              
		CASE_ERR(CL_INVALID_KERNEL_DEFINITION)                
		CASE_ERR(CL_INVALID_KERNEL)               
		CASE_ERR(CL_INVALID_ARG_INDEX)                        
		CASE_ERR(CL_INVALID_ARG_VALUE)                       
		CASE_ERR(CL_INVALID_ARG_SIZE)                       
		CASE_ERR(CL_INVALID_KERNEL_ARGS)                      
		CASE_ERR(CL_INVALID_WORK_DIMENSION)                   
		CASE_ERR(CL_INVALID_WORK_GROUP_SIZE)                  
		CASE_ERR(CL_INVALID_WORK_ITEM_SIZE)                   
		CASE_ERR(CL_INVALID_GLOBAL_OFFSET)                    
		CASE_ERR(CL_INVALID_EVENT_WAIT_LIST)                  
		CASE_ERR(CL_INVALID_EVENT)                            
		CASE_ERR(CL_INVALID_OPERATION)                        
		CASE_ERR(CL_INVALID_GL_OBJECT)                        
		CASE_ERR(CL_INVALID_BUFFER_SIZE)                      
		CASE_ERR(CL_INVALID_MIP_LEVEL)                        
		CASE_ERR(CL_INVALID_GLOBAL_WORK_SIZE)                 
		CASE_ERR(CL_INVALID_PROPERTY)                         
		CASE_ERR(CL_INVALID_IMAGE_DESCRIPTOR)                 
		CASE_ERR(CL_INVALID_COMPILER_OPTIONS)                 
		CASE_ERR(CL_INVALID_LINKER_OPTIONS)                   
		CASE_ERR(CL_INVALID_DEVICE_PARTITION_COUNT)   
	}	       
}

char *file_contents(const char *filename, size_t *length)
{
    FILE *f = fopen(filename, "r");
    void *buffer;

    if (!f) {
        //fprintf(stderr, "Unable to open %s for reading\n", filename);
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    *length = ftell(f);
    fseek(f, 0, SEEK_SET);

    buffer = malloc(*length+1);
    *length = fread(buffer, 1, *length, f);
    fclose(f);
    ((char*)buffer)[*length] = '\0';

    return (char*)buffer;
}


cl_device_id g_device;
cl_context g_context;		
cl_command_queue g_commandQueue;
cl_program g_program;

int g_output_size;

int initOpenCL(int prefered_platform, int prefered_device, int work_size)
{
	cl_platform_id *  platforms = 0;
	cl_device_id * deviceIds = 0;

	int platform_count;

	cl_int err = clGetPlatformIDs(0, NULL, &platform_count);

	if(err != CL_SUCCESS)
	{
		applog(LOG_INFO, "Error: %s\n",CL_ERR_STR(err));
		return 1;
	}

	if(prefered_platform >= platform_count)
	{
		applog(LOG_INFO, "Prefered platform out of range");
		return 1;
	}

	platforms = malloc(sizeof(cl_platform_id)*platform_count);

	if(platforms == NULL)
	{
		applog(LOG_INFO, "Error allocating memory for platforms");
		return 1;
	}

	err = clGetPlatformIDs (platform_count,platforms, NULL);
	
	if(err != CL_SUCCESS)
	{
		applog(LOG_INFO, "Error: %s\n",CL_ERR_STR(err));
		return 1;
	}

	cl_uint deviceIdCount = 0;
	err = clGetDeviceIDs (platforms[prefered_platform], CL_DEVICE_TYPE_ALL, 0, NULL,&deviceIdCount);

	if(err != CL_SUCCESS)
	{
		applog(LOG_INFO, "Error: %s\n",CL_ERR_STR(err));
		return 1;
	}

	if(prefered_device >= deviceIdCount)
	{
		free(platforms);
		applog(LOG_INFO, "Prefered device out of range");
		return 1;
	}

	deviceIds = malloc(sizeof(cl_device_id)*deviceIdCount);

	if(deviceIds == NULL)
	{
		applog(LOG_INFO, "Error allocating memory for deviceIds");
		return 1;
	}
	
	err = clGetDeviceIDs(platforms[prefered_platform], CL_DEVICE_TYPE_ALL,deviceIdCount,deviceIds, NULL);

	if(err != CL_SUCCESS)
	{
		applog(LOG_INFO, "Error: %s\n",CL_ERR_STR(err));
		return 1;
	}

	g_device = deviceIds[prefered_device];

	free(platforms);
	free(deviceIds);

	g_context = clCreateContext(0, 1, &g_device, NULL, NULL, &err);

	//if(gpu->threadIndex == 0) applog(LOG_INFO,"create context: %s",CL_ERR_STR(err));

	if(!g_context || err != CL_SUCCESS)
	{
		applog(LOG_INFO, "Error: %s\n",CL_ERR_STR(err));
		return 1;
	}

	g_commandQueue = clCreateCommandQueue(g_context, g_device, 0, &err);

	if(!g_commandQueue || err != CL_SUCCESS)
	{
		applog(LOG_INFO, "Error: %s\n",CL_ERR_STR(err));
		return 1;
	}
 
	size_t size;
	char * src = file_contents("dcrypt.cl",&size);

	if(src == NULL)
	{
		applog(LOG_INFO, "dcrypt.cl not found");
		return 1;
	}

	g_program = clCreateProgramWithSource(g_context, 1, (const char **)&src, &size, &err);

	g_output_size = work_size;

	char *CompilerOptions = (char *)calloc(1, 256);
	//sprintf(CompilerOptions, "-D WORK_SIZE=%d -D OUTPUT_SIZE=%d ", work_size, g_output_size);

	err = clBuildProgram(g_program, 0, NULL, CompilerOptions, NULL, NULL);
	
	if(!g_program || err != CL_SUCCESS)
	{

		applog(LOG_INFO, "Error: %s\n",CL_ERR_STR(err));

		size_t len;
	    char buffer[2048];
	    applog(LOG_INFO, "Error: Failed to build program executable!");
	    clGetProgramBuildInfo(g_program, g_device, CL_PROGRAM_BUILD_LOG, sizeof(buffer), buffer, &len);
	    applog(LOG_INFO, "%s\n", buffer);
		

		return 1;
	}

	return 0;
}

int initGPU_WORKER(GPU_WORKER *gpu)
{
	cl_int err;

	gpu->kernel_scanhash = clCreateKernel(g_program, "scanhash", &err);

	if(err != CL_SUCCESS)
	{
		applog(LOG_INFO, "Error: scanhash %s\n",CL_ERR_STR(err));
		return 1;
	}

    gpu->mem_block     = clCreateBuffer(g_context, CL_MEM_READ_ONLY, 80, NULL, NULL);
    gpu->mem_halfstate = clCreateBuffer(g_context, CL_MEM_READ_ONLY, 32, NULL, NULL);
	gpu->mem_output    = clCreateBuffer(g_context, CL_MEM_READ_WRITE, 4+4+4+32, NULL, NULL);
	

	gpu->results_hash = (uint32_t *)malloc(4+4+4+32); 



	if(!gpu->results_hash)
	{
		applog(LOG_INFO,"failed to allocate memory for gpu output");
	    exit(1);
	}

	clGetKernelWorkGroupInfo(gpu->kernel_scanhash, g_device, CL_KERNEL_WORK_GROUP_SIZE, sizeof(&gpu->local), &gpu->local, NULL);

    err  = clSetKernelArg(gpu->kernel_scanhash, 0, sizeof(cl_mem), &gpu->mem_block);
 	err |= clSetKernelArg(gpu->kernel_scanhash, 1, sizeof(cl_mem), & gpu->mem_halfstate);
    err |= clSetKernelArg(gpu->kernel_scanhash, 2, sizeof(cl_mem), &gpu->mem_output);

	if (err != CL_SUCCESS)
	{
		applog(LOG_INFO,"Error:clSetKernelArg");
		exit(1);
	}

	return 0;
}

void sha256half(char *msg,unsigned char hash[SHA256_DIGEST_LENGTH])
{
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, msg, 64);
	memcpy(hash,&sha256,32);
}

int scanhash_dcrypt_gpu(GPU_WORKER *gpu,int thr_id, uint32_t *pdata,
                    unsigned char *digest, const uint32_t *ptarget,
                    uint32_t max_nonce, unsigned long *hashes_done, int num_iter,unsigned long *hashes_skipped)
{
  uint32_t block[20], *hash;
  uint32_t nNonce = pdata[19];
  const uint32_t Htarg = ptarget[7]; //the last element in the target is the first 32 bits of the target
  int i;
  bool completed;

  *hashes_skipped = 0;	
  *hashes_done = 0;
  //copy the block (first 80 bytes of pdata) into block
  memcpy(block, pdata, 80);

  cl_int err = 0;
  uint32_t global;

  SHA256_CTX	halfstate,fullstate;
  SHA256_Init(&halfstate);
  SHA256_Update(&halfstate,&block,64);

	clSetKernelArg(gpu->kernel_scanhash, 3, sizeof(uint32_t), &Htarg);
 
	do
	{
	   uint32_t range = max_nonce-nNonce;
	   uint32_t first_nonce =  nNonce+1;
	   //applog(LOG_INFO, "nonce %d max nonce %d range %d",nNonce, max_nonce,range); 

		global = (range > opt_work_size)? opt_work_size : range;

		block[19] = first_nonce ;
		nNonce += global;

		memset(gpu->results_hash,0,32+4*3);

		err  = clEnqueueWriteBuffer(g_commandQueue, gpu->mem_block    , CL_TRUE, 0, 80, block     , 0, NULL, NULL);
		err |= clEnqueueWriteBuffer(g_commandQueue, gpu->mem_halfstate, CL_TRUE, 0, 32, &halfstate, 0, NULL, NULL);
		err |= clEnqueueWriteBuffer(g_commandQueue, gpu->mem_output , CL_TRUE, 0, 12, gpu->results_hash, 0, NULL, NULL);


		if (err != CL_SUCCESS)
		{
			applog(LOG_INFO,"Error: Failed to write to source array!");
			exit(1);
		}

		err = clEnqueueNDRangeKernel(g_commandQueue, gpu->kernel_scanhash, 1, NULL, (const size_t *)&global,(const size_t *)&gpu->local, 0, NULL, NULL);

		if(work_restart[thr_id].restart) break;

		if (err)
		{
			applog(LOG_INFO,"Error: Failed to execute kernel! global=%d",global);
			exit(1);
		}

		clFinish(g_commandQueue);	

	 	err   = clEnqueueReadBuffer(g_commandQueue, gpu->mem_output, 1, 0, 8+32, gpu->results_hash, 0, NULL, 0);
		
		*hashes_skipped += global;
		*hashes_done += gpu->results_hash[0];
	
		if(err)
		{
			applog(LOG_INFO,"Error: Failed to read output from kernel");
			exit(1);
		}

		if(gpu->results_hash[1])
		{
			uint32_t* hash_result = (uint32_t*)(gpu->results_hash+3);
			
			if(hash_result[7] <= Htarg && fulltest(hash_result, ptarget)) 
			{
				block[19] = gpu->results_hash[2];
			
				//uint32_t hash2[8];

				//dcrypt((u8int*)block, 80, NULL, hash2);

				//sha256_to_str((u8int *)block,80,str,hash2);
				//digest_to_string(hash2, str);

				applog(LOG_INFO, "GPU: hash found");
			
				//applog(LOG_DEBUG,
				//		"\n%08x%08x%08x%08x%08x%08x%08x%08x \n%08x%08x%08x%08x%08x%08x%08x%08x",
				//		hash_result[7],  hash_result[6],  hash_result[5],  hash_result[4],  hash_result[3], hash_result[2],  hash_result[1],  hash_result[0],  
				//		hash2[7], hash2[6], hash2[5], hash2[4], hash2[3],hash2[2], hash2[1], hash2[0]);

				pdata[19] = block[19];
				return 1;
			}
			else applog(LOG_INFO, "GPU: error");
		}
	}
	while (nNonce < max_nonce && !work_restart[thr_id].restart);

	if(nNonce > max_nonce) nNonce = max_nonce;

	pdata[19] = nNonce;
	return 0;
}

