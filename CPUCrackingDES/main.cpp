#include <iostream>

using namespace std;

#define KEYLEN 64
#define PC1LEN 56
#define PC2LEN 48
#define SHIFTSLEN 16
#define BLOCKSLEN PC1LEN/2
#define KEYCOUNT 16
#define MSGLEN 64
#define IPMSGCOUNT 16
#define EXTENDEDLEN 48
#define SBOXCOUNT 8
#define SBOXSIZE 4
#define SBLOCKSIZE 6
#define SCOLUMNS 16
#define SROWS 4

#define SHORTMSGLEN 12 
#define MAX_TEXT_LEN 8
#define SIGN_SIZE 8

void convertSignToBitArray(char sign, short * resultArray)
{
	memset(resultArray, 0 ,SIGN_SIZE);
	char mask = 1;
	for(int i = 0; i < SIGN_SIZE; i++)
	 resultArray[i] = (sign & (mask << i)) >> i;
}

void convertTextToBitArray(char * text, int length, short * resultArray)
{
	memset(resultArray, 0 ,length);
	for(int i = 0; i < MAX_TEXT_LEN; i++)
	{
		if(i < length)
			convertSignToBitArray(text[i],resultArray + i*SIGN_SIZE);
		else
			convertSignToBitArray('a',resultArray + i*SIGN_SIZE);
	}
}

void generatePermutation(int combination, int signsCount, int length, char * resultArray)
{
	memset(resultArray, 0 ,length);
	for(int i = 0; i < length; i++)
	{
		int res = combination % signsCount;
		switch(res)
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
		}
		combination /= signsCount;
	}
}

int main()
{
	short PC1[] = {
              57,   49,    41,   33,    25,    17,    9,
               1,   58,    50,   42,    34,    26,   18,
              10,    2,    59,   51,    43,    35,   27,
              19,   11,     3,   60,    52,    44,   36,
              63,   55,    47,   39,    31,    23,   15,
               7,   62,    54,   46,    38,    30,   22,
              14,    6,    61,   53,    45,    37,   29,
              21,   13,     5,   28,    20,    12,    4
	};
	short PC2[] = {
                 14,    17,   11,    24,     1,    5,
                  3,    28,   15,     6,    21,   10,
                 23,    19,   12,     4,    26,    8,
                 16,     7,   27,    20,    13,    2,
                 41,    52,   31,    37,    47,   55,
                 30,    40,   51,    45,    33,   48,
                 44,    49,   39,    56,    34,   53,
                 46,    42,   50,    36,    29,   32,
	};
	short selectionTable[] = {
                 32,     1,    2,     3,     4,    5,
                  4,     5,    6,     7,     8,    9,
                  8,     9,   10,    11,    12,   13,
                 12,    13,   14,    15,    16,   17,
                 16,    17,   18,    19,    20,   21,
                 20,    21,   22,    23,    24,   25,
                 24,    25,   26,    27,    28,   29,
                 28,    29,   30,    31,    32,    1
	};

	short S[SBOXCOUNT][SROWS*SCOLUMNS] = {
		{
			14,   4,  13,   1,   2,  15,  11,   8,   3,  10,   6,  12,   5,   9,   0,   7,
			 0,  15,   7,   4,  14,   2,  13,   1,  10,   6,  12,  11,   9,   5,   3,   8,
			 4,   1,  14,   8,  13,   6,   2,  11,  15,  12,   9,   7,   3,  10,   5,   0,
			15,  12,   8,   2,   4,   9,   1,   7,   5,  11,   3,  14,  10,   0,   6,  13
		},
		{
			15,   1,   8,  14,   6,  11,   3,   4,   9,   7,   2,  13,  12,   0,   5,  10,
			 3,  13,   4,   7,  15,   2,   8,  14,  12,   0,   1,  10,   6,   9,  11,   5,
			 0,  14,   7,  11,  10,   4,  13,   1,   5,   8,  12,   6,   9,   3,   2,  15,
			13,   8,  10,   1,   3,  15,   4,   2,  11,   6,   7,  12,   0,   5,  14,  9
		},
		{                     
			10,   0,   9,  14,   6,   3,  15,   5,   1,  13,  12,   7,  11,   4,   2,   8,
			13,   7,   0,   9,   3,   4,   6,  10,   2,   8,   5,  14,  12,  11,  15,   1,
			13,   6,   4,   9,   8,  15,   3,   0,  11,   1,   2,  12,   5,  10,  14,   7,
		     1,  10,  13,   0,   6,   9,   8,   7,   4,  15,  14,   3,  11,   5,   2,  12
		},
		{
			 7,  13,  14,   3,   0,   6,   9,  10,   1,   2,   8,   5,  11,  12,   4,  15,
		    13,   8,  11,   5,   6,  15,   0,   3,   4,   7,   2,  12,   1,  10,  14,   9,
		    10,   6,   9,   0,  12,  11,   7,  13,  15,   1,   3,  14,   5,   2,   8,   4,
		     3,  15,   0,   6,  10,   1,  13,   8,   9,   4,   5,  11,  12,   7,   2,  14
		},
		{
		     2,  12,   4,   1,   7,  10,  11,   6,   8,   5,   3,  15,  13,   0,  14,   9,
		    14,  11,   2,  12,   4,   7,  13,   1,   5,   0,  15,  10,   3,   9,   8,   6,
		     4,   2,   1,  11,  10,  13,   7,   8,  15,   9,  12,   5,   6,   3,   0,  14,
		    11,   8,  12,   7,   1,  14,   2,  13,   6,  15,   0,   9,  10,   4,   5,   3
		},
		{
		    12,   1,  10,  15,   9,   2,   6,   8,   0,  13,   3,   4,  14,   7,   5,  11,
		    10,  15,   4,   2,   7,  12,   9,   5,   6,   1,  13,  14,   0,  11,   3,   8,
			 9,  14,  15,   5,   2,   8,  12,   3,   7,   0,   4,  10,   1,  13,  11,   6,
			 4,   3,   2,  12,   9,   5,  15,  10,  11,  14,   1,   7,   6,   0,   8,  13
		},
		{
			 4,  11,   2,  14,  15,   0,   8,  13,   3,  12,   9,   7,   5,  10,   6,   1,
		    13,   0,  11,   7,   4,   9,   1,  10,  14,   3,   5,  12,   2,  15,   8,   6,
			 1,   4,  11,  13,  12,   3,   7,  14,  10,  15,   6,   8,   0,   5,   9,   2,
			 6,  11,  13,   8,   1,   4,  10,   7,   9,   5,   0,  15,  14,   2,   3,  12
		},
		{
		    13,   2,   8,   4,   6,  15,  11,   1,  10,   9,   3,  14,   5,   0,  12,   7,
			 1,  15,  13,   8,  10,   3,   7,   4,  12,   5,   6,  11,   0,  14,   9,   2,
			 7,  11,   4,   1,   9,  12,  14,   2,   0,   6,  10,  13,  15,   3,   5,   8,
			 2,   1,  14,   7,   4,  10,   8,  13,  15,  12,   9,   0,   3,   5,   6,  11
		}
	};

	short C[SHIFTSLEN+1][BLOCKSLEN];
	short D[SHIFTSLEN+1][BLOCKSLEN];

	short leftShifts[] = {0, 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};
	short keys[KEYCOUNT][PC2LEN];

	short IP[] = {
		58,    50,    42,    34,    26,    18,    10,     2,
		60,    52,    44,    36,    28,    20,    12,     4,
		62,    54,    46,    38,    30,    22,    14,     6,
		64,    56,    48,    40,    32,    24,    16,     8,
		57,    49,    41,    33,    25,    17,     9,     1,
		59,    51,    43,    35,    27,    19,    11,     3,
		61,    53,    45,    37,    29,    21,    13,     5,
		63,    55,    47,    39,    31,    23,    15,     7
	};

	short P[] = {
		16,     7,    20,    21,
		29,    12,    28,    17,
		1,    15,    23,    26,
		5,    18,    31,    10,
		2,     8,    24,    14,
		32,    27,     3,     9,
		19,    13,    30,     6,
		22,    11,     4,    25
	};

	short L[IPMSGCOUNT+1][MSGLEN/2];
	short R[IPMSGCOUNT+1][MSGLEN/2];

	short reverseIP[] = {
		40,     8,    48,    16,    56,    24,    64,    32,
		39,     7,    47,    15,    55,    23,    63,    31,
		38,     6,    46,    14,    54,    22,    62,    30,
		37,     5,    45,    13,    53,    21,    61,    29,
		36,     4,    44,    12,    52,    20,    60,    28,
		35,     3,    43,    11,    51,    19,    59,    27,
		34,     2,    42,    10,    50,    18,    58,    26,
		33,     1,    41,     9,    49,    17,    57,    25
	};

	short finalMessage[MSGLEN];

	short * message = new short[MSGLEN];
	short * key = new short[KEYLEN];
	short * cipherMessage = new short[MSGLEN];
	convertTextToBitArray("aabbccbb",8,message);
	convertTextToBitArray("bac",3,key);

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

	for(int i = 0; i < MSGLEN/2; i++)
	{
		L[0][i] = message[IP[i]-1];
		R[0][i] = message[IP[MSGLEN/2 + i]-1];
	}

	short expandedR[EXTENDEDLEN];
	short sboxes[SBOXCOUNT][SBOXSIZE];
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
					for(int j = 0; j < MSGLEN/2; j++)
		{
			L[i][j] = R[i-1][j];
			R[i][j] = (L[i-1][j] + sboxes[(P[j]-1) / SBOXSIZE][(P[j]-1) % SBOXSIZE]) % 2;
		}
	}
	for(int i = 0; i < MSGLEN; i++)
	{
		if(reverseIP[i] < MSGLEN/2)
			cipherMessage[i] = R[16][reverseIP[i] - 1];
		else
			cipherMessage[i] = L[16][reverseIP[i] - 1 - MSGLEN/2];
	}



	long messageCombination = 0;
	long keyCombination = 0;
	char * code = new char[8];
	while(messageCombination < 6561)
	{
		generatePermutation(messageCombination++, 3, 8, code);
		convertTextToBitArray(code,8,message);

		keyCombination = 0;
		while(keyCombination < 27)
		{
			generatePermutation(keyCombination++, 3, 8, code);
			convertTextToBitArray(code,3,key);
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

			for(int i = 0; i < MSGLEN/2; i++)
			{
				L[0][i] = message[IP[i]-1];
				R[0][i] = message[IP[MSGLEN/2 + i]-1];
			}

			short expandedR[EXTENDEDLEN];
			short sboxes[SBOXCOUNT][SBOXSIZE];
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

				for(int j = 0; j < MSGLEN/2; j++)
				{
					L[i][j] = R[i-1][j];
					R[i][j] = (L[i-1][j] + sboxes[(P[j]-1) / SBOXSIZE][(P[j]-1) % SBOXSIZE]) % 2;
				}
			}
			bool cracked = true;
			for(int i = 0; i < MSGLEN; i++)
			{
				if(reverseIP[i] < MSGLEN/2)
					finalMessage[i] = R[16][reverseIP[i] - 1];
				else
					finalMessage[i] = L[16][reverseIP[i] - 1 - MSGLEN/2];
				if(finalMessage[i] != cipherMessage[i])
				{
					cracked = false;
					cout << "EQUAL: "<< i << " FROM " << MSGLEN << endl;
					break;
				}
			}
			if(cracked)
			{
				cout << "CRACKED"<< endl;
				for(int i = 0; i < MSGLEN; i++)
				{
					cout << finalMessage[i];
				}
				cout << endl;
				free(message);
				free(code);
				free(cipherMessage);
				free(key);
				return 0;
			}
		}
	}
	free(message);
	free(code);
	free(cipherMessage);
	free(key);
	return 0;
}