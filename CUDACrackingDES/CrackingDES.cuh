#include <iostream>

using namespace std;

#define KEYLEN 64
#define PC1LEN 56
#define PC2LEN 48
#define SHIFTSLEN 16
#define BLOCKSLEN PC1LEN/2
#define KEYCOUNT 16
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

#define gpuErrchk(ans) { gpuAssert((ans), __FILE__, __LINE__); }
#define MSGLEN 8
#define MSGBITLEN 64
#define BLOCKSIZE 512
#define MAXBLOCKCOUNT 128