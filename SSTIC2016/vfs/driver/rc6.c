#include "main.h"
#include "rc6.h"

VOID __stdcall RC6_KeySetup(
		HRC6 hAlgorithm,
		UCHAR *key
		)
{
	ULONG L[64], S[50], A, B, i, j, v, s, t, l;

	/* copy the key into the L array */
	for(A = i = j = 0; i < RC6_KEY_CHARS;)
	{
		A = (A << 8) | ((ULONG) (key[i++] & 255));
		if(!(i & 3))
		{
			L[j++] = BSWAP(A);
			A = 0;
		}
	}

	/* setup the S array */
	t = ROUNDKEYS;			/* fixed at 20 rounds */
	S[0] = 0xB7E15163UL;
	for(i = 1; i < t; i++)
		S[i] = S[i - 1] + 0x9E3779B9UL;

	/* mix buffer */
	s = 3 * MAX(t, j);
	l = j;
	for (A = B = i = j = v = 0; v < s; v++)
	{
		A = S[i] = ROL(S[i] + A + B, 3);
		B = L[j] = ROL(L[j] + A + B, (A + B));
		i = (i + 1) % t;
		j = (j + 1) % l;
	}

	/* copy to key */
	for(i = 0; i < t; i++)
	{
		hAlgorithm->skey[i] = S[i];
	}

	hAlgorithm->vector[0] = 0;
	hAlgorithm->vector[1] = 0;
	hAlgorithm->vector[2] = 0;
	hAlgorithm->vector[3] = 0;
}

VOID __stdcall RC6_Encrypt(
		HRC6		hAlgorithm,
		ULONG*		In,
		ULONG*		Out
	)
{
	ULONG a,b,c,d,t,u;
	LONG r;

	a = In[0];
	b = In[1];
	c = In[2];
	d = In[3];

	a ^= hAlgorithm->vector[0];
	b ^= hAlgorithm->vector[1];
	c ^= hAlgorithm->vector[2];
	d ^= hAlgorithm->vector[3];

	b += hAlgorithm->skey[0];
	d += hAlgorithm->skey[1];
	for(r = 0; r < ROUND; r++)
	{
		t = (b * (b + b + 1));
		t = ROL(t, 5);
		u = (d * (d + d + 1));
		u = ROL(u, 5);
		a = ROL(a ^ t, u) + hAlgorithm->skey[r + r + 2];
		c = ROL(c ^ u, t) + hAlgorithm->skey[r + r + 3];
		t = a;
		a = b;
		b = c;
		c = d;
		d = t;
	}
	a += hAlgorithm->skey[42];
	c += hAlgorithm->skey[43];

	Out[0] = a;
	Out[1] = b;
	Out[2] = c;
	Out[3] = d;

	hAlgorithm->vector[0] = a;
	hAlgorithm->vector[1] = b;
	hAlgorithm->vector[2] = c;
	hAlgorithm->vector[3] = d;
}

VOID __stdcall RC6_Decrypt(
		HRC6 hAlgorithm,
		ULONG *In,
		ULONG *Out
	)
{
	ULONG a,b,c,d,t,u;
	LONG r;
	RC6_CBC_VECTOR vector;

	a = In[0];
	b = In[1];
	c = In[2];
	d = In[3];

	vector[0] = a;
	vector[1] = b;
	vector[2] = c;
	vector[3] = d;

	a -= hAlgorithm->skey[42];
	c -= hAlgorithm->skey[43];
	for(r = ROUND - 1; r >= 0; r--)
	{
		t = d;
		d = c;
		c = b;
		b = a;
		a = t;
		t = (b * (b + b + 1));
		t = ROL(t, 5);
		u = (d * (d + d + 1));
		u = ROL(u, 5);
		c = ROR(c - hAlgorithm->skey[r + r + 3], t) ^ u;
		a = ROR(a - hAlgorithm->skey[r + r + 2], u) ^ t;
	}
	b -= hAlgorithm->skey[0];
	d -= hAlgorithm->skey[1];

	a ^= hAlgorithm->vector[0];
	b ^= hAlgorithm->vector[1];
	c ^= hAlgorithm->vector[2];
	d ^= hAlgorithm->vector[3];
	
	hAlgorithm->vector[0] = vector[0];
	hAlgorithm->vector[1] = vector[1];
	hAlgorithm->vector[2] = vector[2];
	hAlgorithm->vector[3] = vector[3];

	Out[0] = a;
	Out[1] = b;
	Out[2] = c;
	Out[3] = d;
}

NTSTATUS RC6_EncryptDecryptBuffer(
		 PCHAR		InBuf,
		 ULONG		InSize,
		 PCHAR*		pOutBuf,
		 PULONG		pOutSize,
		 PRC6_KEY	pRc6Key,
		 BOOL		bEncrypt
		)
{
	ULONG 	OutSize;
	PCHAR	OutBuf = NULL, NewBuf = NULL;
	ULONG 	i, InBlocks;
	RC6CONTEXT CryptCtx;
	NTSTATUS Status = STATUS_NO_MEMORY;

	if(bEncrypt)
	{
		OutSize = (InSize + (RC6_BLOCK_SIZE - 1)) & (~(RC6_BLOCK_SIZE - 1));
		if (InSize < OutSize)
		{
			NewBuf = PoolAlloc(OutSize);
			if(NewBuf)
			{
				RtlZeroMemory(NewBuf, OutSize);
				RtlCopyMemory(NewBuf, InBuf, InSize);
			}
			else
				return Status;
			
			InBuf = NewBuf;
		}
	}
	else
		OutSize = (InSize & (~(RC6_BLOCK_SIZE - 1)));

	if((InBuf) && (OutBuf = PoolAlloc(OutSize)))
	{
		RC6_KeySetup(&CryptCtx, pRc6Key);
		InBlocks = OutSize / RC6_BLOCK_SIZE;
		*pOutBuf = OutBuf;
		*pOutSize = OutSize;

		for(i=0; i<InBlocks; i++)
		{
			if(bEncrypt)
				RC6_Encrypt(&CryptCtx, (PULONG)InBuf, (PULONG)OutBuf);
			else
				RC6_Decrypt(&CryptCtx, (PULONG)InBuf, (PULONG)OutBuf);

			InBuf += RC6_BLOCK_SIZE;
			OutBuf += RC6_BLOCK_SIZE;
		}
		Status = STATUS_SUCCESS;
	}
	if(NewBuf)
		PoolFree(NewBuf);
	
	return Status;
}