#ifndef __RC6__H
#define __RC6__H

#define RC6_KEY_SIZE		128 				// bits
#define RC6_KEY_CHARS		RC6_KEY_SIZE / 8    // bytes
#define RC6_BLOCK_SIZE 		16					// bytes

#define ROUND				20
#define ROUNDKEYS			2 * ROUND + 4

#define ROL(x, y) 			(((x) >> ((ULONG)(y))) | ((x) << (32 - (ULONG)(y))))
#define ROR(x, y) 			(((x) << ((ULONG)(y))) | ((x) >> (32 - (ULONG)(y))))
#define MAX(x, y) 			( ((x)>(y))?(x):(y) )

#if BIG_ENDIAN == 1
#define BSWAP(x) 			(((ROR(x,8) & 0xFF00FF00) | (ROL(x,8) & 0x00FF00FF)))
#else
#define BSWAP(x) 			(x)
#endif

//////////////////////////////////////
//  GLOBALS
//////////////////////////////////////

typedef ULONG rc6_key[44];
typedef UCHAR RC6_KEY[RC6_KEY_CHARS], *PRC6_KEY;
typedef ULONG RC6_CBC_VECTOR[RC6_BLOCK_SIZE/sizeof(long)];


static PRC6_KEY g_rc6_key = "551C2016B00B5F00\0";

typedef struct
{
	rc6_key 		skey;
	RC6_CBC_VECTOR  vector;
} RC6CONTEXT, *HRC6;

//////////////////////////////////////
// FUNCTIONS
//////////////////////////////////////

VOID __stdcall RC6_KeySetup(
		HRC6 		hAlgorithm,
		PUCHAR 		key
	);

VOID __stdcall RC6_Encrypt(
		HRC6		hAlgorithm,
		PULONG		In,
		PULONG		Out
	);

VOID __stdcall RC6_Decrypt(
		HRC6 		hAlgorithm,
		PULONG 		In,
		PULONG 		Out
	);

NTSTATUS RC6_EncryptDecryptBuffer(
		 PCHAR		InBuf,
		 ULONG		InSize,
		 PCHAR*		pOutBuf,
		 PULONG		pOutSize,
		 PRC6_KEY	pRc6Key,
		 BOOL		bEncrypt
	);


#endif 