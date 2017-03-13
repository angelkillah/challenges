#include "main.h"
#include "rc4.h"

static __inline VOID swap_bytes(PUCHAR a, PUCHAR b)
{
	UCHAR tmp;
	tmp = *a;
	*a = *b;
	*b = tmp;
}

VOID RC4_Init(PRC4_STATE pState, 
			  PUCHAR pKey, 
			  ULONG keylen)
{
	ULONG j;
	ULONG i;
	
	for(i=0; i<256; i++)
		pState->perm[i] = (UCHAR)i;
	pState->index1 = 0;
	pState->index2 = 0;
	
	for(j = 0, /*(UCHAR)*/i = 0; i<256; i++)
	{
		j = (j + pState->perm[i] + pKey[i % keylen]) % 256;
		swap_bytes(&pState->perm[i], &pState->perm[j]);
	}
}

VOID RC4_EncryptDecryptBuffer(PRC4_STATE pState,
							  PUCHAR pInBuf,
							  PUCHAR pOutBuf,
							  ULONG buflen)
{
	ULONG i;
	UCHAR j;
	
	for(i=0; i<buflen; i++)
	{
		pState->index1++;
		pState->index2 += pState->perm[pState->index1];
		
		swap_bytes(&pState->perm[pState->index1], &pState->perm[pState->index2]);
		
		j = pState->perm[pState->index1] + pState->perm[pState->index2];
		pOutBuf[i] = pInBuf[i] ^ pState->perm[j];
	}				
}
