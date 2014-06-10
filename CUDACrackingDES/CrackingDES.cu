#include "Arrays.cuh"
#include "CrackingDES.cuh"

inline void gpuAssert(cudaError_t code, char *file, int line)
{
	if (code != cudaSuccess) 
	{
		fprintf(stderr,"GPUassert: %s %s %d\n", cudaGetErrorString(code), file, line);
		exit(code);
	}
}

struct result
{
	bool isCracked;
	int keyNumber;
};

void encipherTextCPU(short * message, short * key, short * cipherMessage)
{
	short C[SHIFTSLEN+1][BLOCKSLEN];
	short D[SHIFTSLEN+1][BLOCKSLEN];
	short L[IPMSGCOUNT+1][MSGBITLEN/2];
	short R[IPMSGCOUNT+1][MSGBITLEN/2];
	short expandedR[EXTENDEDLEN];
	short sboxes[SBOXCOUNT][SBOXSIZE];
	short keys[KEYCOUNT][PC2LEN];

	for(int i = 0; i < BLOCKSLEN; i++)
	{
		C[0][i] = key[PC1[i]-1];
		D[0][i] = key[PC1[BLOCKSLEN + i]-1];
	}
	for(int i = 1; i < SHIFTSLEN+1; i++)
	{
		for(int j = 0; j < BLOCKSLEN - leftShifts[i]; j++)
		{
			C[i][j] = C[i-1][j + leftShifts[i]];
			D[i][j] = D[i-1][j + leftShifts[i]];
		}
		for(int j = 0; j < leftShifts[i]; j++)
		{
			C[i][j + BLOCKSLEN - leftShifts[i]] = C[i-1][j];
			D[i][j + BLOCKSLEN - leftShifts[i]] = D[i-1][j];
		}
		for(int j = 0; j < PC2LEN; j++)
		{
			if(PC2[j] - 1 < BLOCKSLEN)
				keys[i-1][j] = C[i][PC2[j]-1];
			else
				keys[i-1][j] = D[i][PC2[j]-BLOCKSLEN-1];
		}
	}

	for(int i = 0; i < MSGBITLEN/2; i++)
	{
		L[0][i] = message[IP[i]-1];
		R[0][i] = message[IP[MSGBITLEN/2 + i]-1];
	}

	for(int i = 1; i < IPMSGCOUNT+1; i++)
	{
		for(int j = 0; j < EXTENDEDLEN; j++)
			expandedR[j] = R[i-1][selectionTable[j] - 1] ^ keys[i-1][j];
		for(int j = 0; j < SBOXCOUNT; j++)
		{
			short row = 2 * expandedR[j*SBLOCKSIZE] + expandedR[j*SBLOCKSIZE + 5];
			short column = 8 * expandedR[j*SBLOCKSIZE + 1] 
			+ 4 * expandedR[j*SBLOCKSIZE + 2] + 2 * expandedR[j*SBLOCKSIZE + 3]
			+ expandedR[j*SBLOCKSIZE + 4];
			short sValue = S[j][row*SCOLUMNS + column];
			short mask = 1;
			for(int k = 0; k < SBOXSIZE; k++)
				sboxes[j][SBOXSIZE - k -1] = (sValue & (mask << k)) >> k;
		}
					for(int j = 0; j < MSGBITLEN/2; j++)
		{
			L[i][j] = R[i-1][j];
			R[i][j] = (L[i-1][j] + sboxes[(P[j]-1) / SBOXSIZE][(P[j]-1) % SBOXSIZE]) % 2;
		}
	}
	for(int i = 0; i < MSGBITLEN; i++)
	{
		if(reverseIP[i] < MSGBITLEN/2)
			cipherMessage[i] = R[16][reverseIP[i] - 1];
		else
			cipherMessage[i] = L[16][reverseIP[i] - 1 - MSGBITLEN/2];
	}
}

__device__ void encipherTextGPU(short * message, short * key, short * cipherMessage, bool * result)
{
	short C[SHIFTSLEN+1][BLOCKSLEN];
	short D[SHIFTSLEN+1][BLOCKSLEN];
	short L[IPMSGCOUNT+1][MSGBITLEN/2];
	short R[IPMSGCOUNT+1][MSGBITLEN/2];
	short expandedR[EXTENDEDLEN];
	short sboxes[SBOXCOUNT][SBOXSIZE];
	short keys[KEYCOUNT][PC2LEN];

	for(int i = 0; i < BLOCKSLEN; i++)
	{
		C[0][i] = key[d_PC1[i]-1];
		D[0][i] = key[d_PC1[BLOCKSLEN + i]-1];
	}
	for(int i = 1; i < SHIFTSLEN+1; i++)
	{
		for(int j = 0; j < BLOCKSLEN - d_leftShifts[i]; j++)
		{
			C[i][j] = C[i-1][j + d_leftShifts[i]];
			D[i][j] = D[i-1][j + d_leftShifts[i]];
		}
		for(int j = 0; j < d_leftShifts[i]; j++)
		{
			C[i][j + BLOCKSLEN - d_leftShifts[i]] = C[i-1][j];
			D[i][j + BLOCKSLEN - d_leftShifts[i]] = D[i-1][j];
		}
		for(int j = 0; j < PC2LEN; j++)
		{
			if(d_PC2[j] - 1 < BLOCKSLEN)
				keys[i-1][j] = C[i][d_PC2[j]-1];
			else
				keys[i-1][j] = D[i][d_PC2[j]-BLOCKSLEN-1];
		}
	}
	for(int i = 0; i < MSGBITLEN/2; i++)
	{
		L[0][i] = message[d_IP[i]-1];
		R[0][i] = message[d_IP[MSGBITLEN/2 + i]-1];
	}
	for(int i = 1; i < IPMSGCOUNT+1; i++)
	{
		for(int j = 0; j < EXTENDEDLEN; j++)
			expandedR[j] = R[i-1][d_selectionTable[j] - 1] ^ keys[i-1][j];
		for(int j = 0; j < SBOXCOUNT; j++)
		{
			short row = 2 * expandedR[j*SBLOCKSIZE] + expandedR[j*SBLOCKSIZE + 5];
			short column = 8 * expandedR[j*SBLOCKSIZE + 1] 
			+ 4 * expandedR[j*SBLOCKSIZE + 2] + 2 * expandedR[j*SBLOCKSIZE + 3]
			+ expandedR[j*SBLOCKSIZE + 4];
			short sValue = d_S[j][row*SCOLUMNS + column];
			short mask = 1;
		for(int k = 0; k < SBOXSIZE; k++)
				sboxes[j][SBOXSIZE - k -1] = (sValue & (mask << k)) >> k;
		}

		for(int j = 0; j < MSGBITLEN/2; j++)
		{
			L[i][j] = R[i-1][j];
			R[i][j] = (L[i-1][j] + sboxes[(d_P[j]-1) / SBOXSIZE][(d_P[j]-1) % SBOXSIZE]) % 2;
		}
	}
	*result = true;
	for(int i = 0; i < MSGBITLEN; i++)
	{
		if(d_reverseIP[i] < MSGBITLEN/2)
		{
			if(R[16][d_reverseIP[i] - 1] != cipherMessage[i])
			{
				*result = false;
				break;
			}
		}
		else if(L[16][d_reverseIP[i] - 1 - MSGBITLEN/2] != cipherMessage[i])
		{
			*result = false;
			break;
		}
	}
	if(*result)
		return;
}

__host__ __device__ void convertSignToBitArray(char sign, short * resultArray)
{
	//memset(resultArray, 0 ,SIGN_SIZE);
	char mask = 1;
	for(int i = 0; i < SIGN_SIZE; i++)
	 resultArray[i] = (sign & (mask << i)) >> i;
}

__host__ __device__ void convertTextToBitArray(char * text, int length, short * resultArray)
{
	//memset(resultArray, 0 ,length);
	for(int i = 0; i < MAX_TEXT_LEN; i++)
	{
		if(i < length)
			convertSignToBitArray(text[i],resultArray + i*SIGN_SIZE);
		else
			convertSignToBitArray('a',resultArray + i*SIGN_SIZE);
	}
}

__host__ __device__ void generatePermutation(int combination, int signsCount, int length, char * resultArray)
{
	//memset(resultArray, 0 ,length);
	for(int i = 0; i < length; i++)
	{
		int res = combination % signsCount;
		/*switch(res)
		{
		case 0:
			resultArray[i] = 'a';
			break;
		case 1:
			resultArray[i] = 'b';
			break;
		case 2:
			resultArray[i] = 'c';
			break;
		}*/
		resultArray[i] = 'a' + res;
		combination /= signsCount;
	}
}

__global__ void CrackingDESKernel(short * _cipherText, short * _plainText, int signsCount, int threadsCount, int keyLength, struct result * result)
{
	__shared__ short cipherText[MSGBITLEN];
	__shared__ short plainText[MSGBITLEN];
	
	int position = blockIdx.x*BLOCKSIZE + threadIdx.x;
	//for(int i = 0; i < signsCount; i++)
	//{
		if(position < MSGBITLEN)
		{
			cipherText[position] = _cipherText[position];
			plainText[position] = _plainText[position];
		}
		//convertSignToBitArray('a' + i ,plainText + MSGBITLEN - SIGN_SIZE - 1);
		__syncthreads();

		if(position >= threadsCount)
			return;
		char * code = new char[MSGLEN];
		short * key = new short[MSGBITLEN];
		bool * res = new bool[1];
		generatePermutation(position, signsCount, MSGLEN, code);
		char sign;
		convertTextToBitArray(code,keyLength,key);
		encipherTextGPU(plainText, key, cipherText, res);
		delete[] code;
		delete[] key;
		if(*res)
		{
			result->isCracked = true;
			result->keyNumber = position;
		}
	//}
		//__syncthreads();
	return;
}
void ERR(char *msg)
{
	fprintf(stderr,"Error: %s\n", msg);
	exit(1);
}

int main()
{
	char * plainText = new char[MSGLEN+1];
	char * key = new char[MSGLEN+1];
	short * plainBitText = new short[MSGBITLEN];
	short * cipherBitText = new short[MSGBITLEN];
	short * keyBit = new short[MSGBITLEN];
	cudaEvent_t timerStart, timerStop;
	float timer;

	short * d_cipherText, * d_plainText;

	int signsCount = 0;
	printf("Enter the alphabet size.\n");
	scanf("%d", &signsCount);

	printf("Enter the plain text.\n");
	scanf("%s", plainText);
	convertTextToBitArray(plainText,8,plainBitText);

	printf("Enter the key text.\n");
	scanf("%s", key); 
	int keyLength = strlen(key);

	convertTextToBitArray(key,keyLength,keyBit);

	encipherTextCPU(plainBitText, keyBit, cipherBitText);

	printf("Cipher text generated from given text and key, now lets try to crack it.\n");

	if(cudaMalloc((void**) &d_cipherText, sizeof(short)*MSGBITLEN) != cudaSuccess)
		ERR("cudaMalloc");
	if(cudaMemcpy(d_cipherText, cipherBitText, sizeof(short)*MSGBITLEN, cudaMemcpyHostToDevice) != cudaSuccess)
		ERR("cudaMemcpy");

	if(cudaMalloc((void**) &d_plainText, sizeof(short)*MSGBITLEN) != cudaSuccess)
		ERR("cudaMalloc");

	long messageCombination = 0;
	char * code = new char[MSGLEN];

	int threadsCount = 1;
	for(int i = 0; i < keyLength; i++)
		threadsCount *= signsCount;
	int blocksCount = threadsCount / BLOCKSIZE + 1;

	struct result * result = new struct result;
	result->isCracked = false;
	result->keyNumber = -1;
	struct result * d_result;
	if(cudaMalloc((void**) &d_result, sizeof(struct result)) != cudaSuccess)
		ERR("cudaMalloc");
	if(cudaMemcpy(d_result, result, sizeof(struct result), cudaMemcpyHostToDevice) != cudaSuccess)
		ERR("cudaMemcpy");

	long long textsCount = 1;
	for(int i = 0; i < MSGLEN; i++)
		textsCount *= signsCount;

	cudaEventCreate(&timerStart, 0);
	cudaEventCreate(&timerStop, 0);

	cudaEventRecord(timerStart, 0);
	while(messageCombination < textsCount)
	{
		printf("Cracking iteration %d of %d\n",messageCombination, textsCount);
		generatePermutation(messageCombination++, 3, 8, code);
		convertTextToBitArray(code,8,plainBitText);
		if(cudaMemcpy(d_plainText, plainBitText, sizeof(short)*MSGBITLEN, cudaMemcpyHostToDevice) != cudaSuccess)
			ERR("cudaMemcpy");

		CrackingDESKernel<<<blocksCount,BLOCKSIZE>>>(d_cipherText, d_plainText, signsCount, threadsCount, keyLength, d_result);
		gpuErrchk(cudaPeekAtLastError());
		if(cudaDeviceSynchronize() != cudaSuccess)
			ERR("cudaDeviceSynchronize");
		if(cudaMemcpy(result, d_result, sizeof(struct result), cudaMemcpyDeviceToHost) != cudaSuccess)
			ERR("cudaMemcpy");
		if(result->isCracked)
		{
			printf("MESSAGE CRACKED\n");
			printf("MSG: ");
			for(int i=0; i < MSGLEN; i++)
				printf("%c",code[i]);
			printf("\n");
			generatePermutation(result->keyNumber, signsCount, MSGLEN, code);
			printf("KEY: ");
			for(int i=0; i < keyLength; i++)
				printf("%c",code[i]);
			printf("\n");
			break;
		}
	}

	if(cudaEventRecord(timerStop, 0) != cudaSuccess)
		ERR("cudaEventRecord");

	if(cudaEventSynchronize(timerStop) != cudaSuccess)
		ERR("cudaEventSynchronize");

	if(cudaDeviceSynchronize() != cudaSuccess)
		ERR("cudaDeviceSynchronize");

	cudaEventElapsedTime(&timer, timerStart, timerStop);

	printf("\n");

	printf("Done! T = %f ms\n", timer);

	cudaEventDestroy(timerStart);
	cudaEventDestroy(timerStop);

	if(cudaFree(d_cipherText) != cudaSuccess)
			ERR("cudaFree");
	if(cudaFree(d_plainText) != cudaSuccess)
			ERR("cudaFree");

	delete[] plainText;
	delete[] key;
	delete[] plainBitText;
	delete[] cipherBitText;
	delete[] keyBit;
}