#define SHA256_LEN 64

#define ror(x,n) ((x >> n) | (x << (32-n)))
#define Ch(x,y,z) bitselect(z, y, x)
#define Maj(x,y,z) bitselect(x, y, z ^ x)

#define Sigma0(x) ((ror(x,2))  ^ (ror(x,13)) ^ (ror(x,22)))
#define Sigma1(x) ((ror(x,6))  ^ (ror(x,11)) ^ (ror(x,25)))
#define sigma0(x) ((ror(x,7))  ^ (ror(x,18)) ^(x>>3))
#define sigma1(x) ((ror(x,17)) ^ (ror(x,19)) ^(x>>10))

#define SWAP32(n)       as_uint(as_uchar4(n).s3210) 

__constant uint k[] = {
   0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
   0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
   0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
   0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
   0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
   0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
   0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
   0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
};

#define hash0 (uint8)(0x6a09e667U, 0xbb67ae85U,	0x3c6ef372U, 0xa54ff53aU, 0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U)

#define a state.s0	
#define b state.s1	
#define c state.s2	
#define d state.s3	
#define e state.s4	
#define f state.s5	
#define g state.s6	
#define h state.s7

#define TRANSFORM(H) \
state = H;\
for (int i = 16; i < 64; i++) {\
	w[i] = w[i-16] + sigma0(w[i-15]) + w[i-7] + sigma1(w[i-2]); \
}\
for (int i = 0; i < 64; i++) {\
	uint t1 = h + Sigma1(e) + Ch(e,f,g) + k[i] + w[i];\
	uint t2 = Sigma0(a) + Maj(a,b,c);\
	h = g; g = f; f = e; e = d+t1; d = c; c = b; b = a; a = t1+t2;\
} \
H += state;

#define TRANSFORMW(H,W) ((uint16*)w)[0] = W; TRANSFORM(H)
#define HASHSWAPENDIAN(H) H = (uint8)(SWAP32(H.s0), SWAP32(H.s1), SWAP32(H.s2), SWAP32(H.s3),SWAP32(H.s4), SWAP32(H.s5), SWAP32(H.s6), SWAP32(H.s7));
#define INIT(H) H = hash0;

#define SETWSWAPENDIAN(DATA)\
	((uint16*)w)[0] = DATA;\
	for(int i = 0; i < 64; i++)\
	{\
		w[i] = SWAP32(w[i]);\
	}

#define TRANSFORMWS(H,DATA) SETWSWAPENDIAN(DATA); TRANSFORM(H)

__constant uchar hex_digits[] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};

#define DIGEST2STR(S,H) \
for(int i = 0; i < 32; i ++)\
{\
	S[i*2  ] = hex_digits[(((uchar*)&H)[i] & 0xf0)>> 4]; \
	S[i*2+1] = hex_digits[((uchar*)&H)[i] & 0x0f];\
}

#define DIGEST2SKIPLIST(A,H) \
for(int i = 0; i < 32; i ++)\
{\
	A[i*2  ] = (((uchar*)&H)[i] & 0xf0)>> 4; \
	A[i*2+1] = ((uchar*)&H)[i] & 0x0f;\
}


__kernel void init_internal_hashes(__global uint8* ctx,__global uchar * temp_arrays)                                   
{  
	uint w[64];
	uint8 state,hash; 

	uchar tmp_array[SHA256_LEN],temp_value;
	*((uint16*) tmp_array) = 0xffffffff;

	for(uint x1 = 0; x1 < 16; x1++)
	{
		INIT(hash)
		TRANSFORMWS(hash,*((uint16*)tmp_array))
		TRANSFORMW(hash,(uint16)(0x00800000U | hex_digits[x1] << 24, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 520U)) 

		HASHSWAPENDIAN(hash)
		DIGEST2STR(tmp_array,hash)

     }

	
	return;
}




__kernel void scanhash(__global const uint* data,__global const uint* halfstate,  __global uint* output, uint target)                                   
{  
	uint global_index = get_global_id(0);                                          
	uint nonce = global_index+data[19];

	uint w[64];
	uint8 state,hash_first,hash_temp,hash_res; 
	uint index,steps,count;
	uchar tmp_array[SHA256_LEN],skip_list[SHA256_LEN];
	uint16 buffer[16];

	//INIT(hash_first )
	//TRANSFORMWS(hash_first,((__global uint16*)data)[0])
	hash_first = (uint8)(halfstate[0],halfstate[1],halfstate[2],halfstate[3],halfstate[4],halfstate[5],halfstate[6],halfstate[7]);
	TRANSFORMW(hash_first,(uint16)(SWAP32(data[16]), SWAP32(data[17]), SWAP32(data[18]), SWAP32(nonce),0x80000000U, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 640U))
	HASHSWAPENDIAN(hash_first)
	DIGEST2SKIPLIST(skip_list,hash_first)

	for(steps = 0, index = 0; index < SHA256_LEN-1; steps++)
	{
		index += skip_list[index]+1;
	}

	if(index != SHA256_LEN - 1 || steps > 16) return;
 
	count = 0;
	index = 0;
	*((uint16*)tmp_array) = 0xffffffff;		

 	do
	{
		index += skip_list[index]+1;
	
		INIT(hash_temp)
		TRANSFORMWS(hash_temp,*((uint16*)tmp_array))
		TRANSFORMW(hash_temp,(uint16)(0x00800000U | hex_digits[skip_list[index]] << 24, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 520U)) 
		HASHSWAPENDIAN(hash_temp)
		DIGEST2STR(tmp_array,hash_temp)

		buffer[count] = *((uint16*)tmp_array);
		
		count++;
	}
	while(index != SHA256_LEN - 1);

	if(hex_digits[skip_list[index]] != tmp_array[SHA256_LEN - 1]) return;

	INIT(hash_res)
	for(int i = 0; i < count; i++)
	{
		TRANSFORMWS(hash_res,buffer[i])
	}
	TRANSFORMWS(hash_res,((__global uint16*)data)[0])
	TRANSFORMW(hash_res,(uint16)(SWAP32(data[16]), SWAP32(data[17]), SWAP32(data[18]), SWAP32(nonce),0x80000000U, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 640U + 512U * count)) 
	HASHSWAPENDIAN(hash_res)

	atomic_inc(&output[0]); //hashes done
	if (hash_res.s7 <= target) 
	{	
		int p = atomic_inc(&output[1]); 
		if(p > 0) return;	
		output[2] = nonce;	// share found
		for(int i = 0; i < 8; i++)
		{
			output[3+i] = ((uint*)&hash_res)[i];
		}
	}
}



