#include "main.h"
#include "rc6.h"
#include "disk.h"
#include "rc4.h"
#include "comm.h"
#include "linked_list.h"
#include "vfs.h"


NTSTATUS VFS_Update_DiskInfo()
{
	PCHAR pSector;
	NTSTATUS status = STATUS_SUCCESS;
	
	pSector = PoolAlloc(512);
	if(pSector == NULL)
		return STATUS_NO_MEMORY;
	
	status = DISK_ReadWriteSector(1, offset_diskinfo, READ, pSector);
	if(!NT_SUCCESS(status))
		return status;

	RtlCopyMemory(pSector, pDiskInfo, (sizeof(DWORD)*2) + sizeof(LONGLONG)*4);
	status = DISK_ReadWriteSector(1, offset_diskinfo, WRITE, pSector);
	if(!NT_SUCCESS(status))
		return status;

	PoolFree(pSector);	
	
	return status;
}

NTSTATUS VFS_Store_DiskInfo()
{
	NTSTATUS status;
	BYTE DiskInfo[116] = {0};
	
	if(pDiskInfo->total_freespace <= 116)
		return STATUS_NO_MEMORY;
	
	RtlCopyMemory(DiskInfo, &pDiskInfo->magic, sizeof(DWORD));
	RtlCopyMemory(DiskInfo+4, &pDiskInfo->total_freespace, sizeof(LONGLONG));
	RtlCopyMemory(DiskInfo+12, &pDiskInfo->total_usedspace, sizeof(LONGLONG));
	RtlCopyMemory(DiskInfo+20, &pDiskInfo->total_space, sizeof(LONGLONG));
	RtlCopyMemory(DiskInfo+28, &pDiskInfo->current_disk_offset, sizeof(LONGLONG));
	RtlCopyMemory(DiskInfo+36, &pDiskInfo->current_offset_in_sector, sizeof(ULONG));
	RtlCopyMemory(DiskInfo+40, &pDiskInfo->magic2, sizeof(DWORD));
	if(NT_SUCCESS(status = DISK_WriteData(44, DiskInfo)))
	{
		pDiskInfo->total_usedspace += 44;
		pDiskInfo->total_freespace -= 44;
	}
	return status;
}

NTSTATUS VFS_StoreData()
{
	NTSTATUS status;
	ULONG blob_size;
	PBYTE pBlob;
	PCHAR pEncrypted = NULL, pDecrypted;
	ULONG i = 0;//, j = 0;
	ULONG encSize, decSize;
	MFT mft;
	
	// get linked list data size
	blob_size = Get_LinkedList_Size();
	pBlob = PoolAlloc(blob_size);
	if(blob_size == 0 || pBlob == NULL)
		return STATUS_NO_MEMORY;
	
	Fill_Blob_with_Data(pBlob);
	Dbg("Before encryption with rc6 : \n");
	for(i=0; i<20; i++)
		Dbg("%02x", pBlob[i]);
	
	
	if(!NT_SUCCESS(status = RC6_EncryptDecryptBuffer(pBlob, blob_size, &pEncrypted, &encSize, (PRC6_KEY)g_rc6_key, TRUE)))
		return status;
	
	Dbg("[+] Files Containers encrypted with RC6, total size : %d\n", encSize);
	Dbg("after encryption with rc6 : \n")
	for(i=0; i<20; i++)
		Dbg("%02x", pEncrypted[i] & 0xff);
	Dbg("jusqu'à :\n");
	for(i=encSize; i>encSize-20; i--)
		Dbg("%02x", pEncrypted[i] & 0xff);
	mft.nb_of_files = nb_entries;
	RtlCopyMemory(mft.rc6_key, g_rc6_key, RC6_KEY_CHARS);
	Dbg("Writing MFT...")
	if(!NT_SUCCESS(status = DISK_WriteData(sizeof(DWORD) + RC6_KEY_CHARS, (PBYTE)&mft)))
		return status;
	Dbg("[+] MFT correctly stored\n");
	pDiskInfo->total_usedspace += sizeof(DWORD) + RC6_KEY_CHARS;
	pDiskInfo->total_freespace -= sizeof(DWORD) + RC6_KEY_CHARS;
	
	Dbg("freespace : %llu\n", pDiskInfo->total_freespace);
	Dbg("Writing blob...\n")
	if(!NT_SUCCESS(status = DISK_WriteData(encSize, pEncrypted)))
		return status;
	
	Dbg("Blob correctly stored\n");
	pDiskInfo->total_usedspace += encSize;
	pDiskInfo->total_freespace -= encSize;
	
	Dbg("test rc6 decryption\n");
	if(!NT_SUCCESS(status = RC6_EncryptDecryptBuffer(pEncrypted, encSize, &pDecrypted, &decSize, (PRC6_KEY)g_rc6_key, FALSE)))
		return status;
	Dbg("dump of the first 20 bytes : \n");
	for(i=0; i<20; i++)
		Dbg("%02x", pDecrypted[i]);
	
	Dbg("Updating DiskInfo...");
	return VFS_Update_DiskInfo();
}