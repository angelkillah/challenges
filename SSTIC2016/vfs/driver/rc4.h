#ifndef __RC4__H
#define __RC4__H

#define RC4_KEY_SIZE	16  // in bytes

typedef struct _RC4_STATE {
		UCHAR	perm[256];
		UCHAR	index1;
		UCHAR	index2;
} RC4_STATE, *PRC4_STATE;

VOID RC4_Init(PRC4_STATE pState, 
			  PUCHAR pKey, 
			  ULONG keylen);

VOID RC4_EncryptDecryptBuffer(
			  PRC4_STATE pState,
			  PUCHAR pInBuf,
			  PUCHAR pOutBuf,
			  ULONG buflen);

#endif