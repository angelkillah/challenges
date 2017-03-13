#include "main.h"
#include "comm.h"
#include "rc4.h"
#include "linked_list.h"

PCONTAINER_ENTRY AllocateContainerEntry(PSHARED_BUFFER pSharedBuffer, PUCHAR rc4_key)
{
	PCONTAINER_ENTRY pContainerEntry = NULL;
	FILE_DATA filedata = {0};
	
	pContainerEntry = PoolAlloc(sizeof(CONTAINER_ENTRY));
	filedata = PoolAlloc(pSharedBuffer->raw_data_len);
	if(pContainerEntry == NULL || pSharedBuffer == NULL)
	{
		Dbg(__FUNCTION__ ": failed !\n"); 
		return NULL;
	}
	
	pContainerEntry->raw_data_len = pSharedBuffer->raw_data_len;
	RtlCopyMemory(pContainerEntry->rc4_key, rc4_key, RC4_KEY_SIZE);
	RtlCopyMemory(pContainerEntry->checksum, pSharedBuffer->checksum, MD5_CHECKSUM_SIZE);
	RtlCopyMemory(filedata, pSharedBuffer->data, pSharedBuffer->raw_data_len);
	pContainerEntry->data = filedata;
	pContainerEntry->entry_size = sizeof(ULONG) + RC4_KEY_SIZE + MD5_CHECKSUM_SIZE + pSharedBuffer->raw_data_len;
	
	return pContainerEntry;
}

ULONG Get_LinkedList_Size()
{
	PLIST_ENTRY pListEntry = NULL;
	PCONTAINER_ENTRY pCurContainerEntry = NULL;
	ULONG i=0;

	if(pContainerListHead != NULL)
	{
		if(IsListEmpty(pContainerListHead))
		{
			Dbg("The list is empty\n");
		}
		else
		{		
			pListEntry = pContainerListHead->Flink;
			Dbg("Walk through the container list\n");
			do
			{
				pCurContainerEntry = (PCONTAINER_ENTRY)CONTAINING_RECORD(pListEntry, CONTAINER_ENTRY, entry);
				i += pCurContainerEntry->entry_size;
				pListEntry = pListEntry->Flink;   
			}
			while(pListEntry != pContainerListHead);
		}
	}
	return i;
}

NTSTATUS AddContainerToList(PSHARED_BUFFER pSharedBuffer, PUCHAR rc4_key)
{    
	PCONTAINER_ENTRY pNewEntry = NULL;

	if(pContainerListHead == NULL)
	{
		Dbg("pSharedBuffer->len : %d\n", pSharedBuffer->raw_data_len);
		pNewEntry = AllocateContainerEntry(pSharedBuffer, rc4_key);
		if(pNewEntry == NULL)
		{
			Dbg(__FUNCTION__ ": failed !\n");
			return STATUS_NO_MEMORY;
		}
		InitializeListHead(&pNewEntry->entry);            
		pContainerListHead = &pNewEntry->entry;
	}

	pNewEntry = AllocateContainerEntry(pSharedBuffer, rc4_key);
	if(pNewEntry == NULL)
	{
		Dbg(__FUNCTION__ ": failed !\n");
		return STATUS_NO_MEMORY;
	}    
	InsertHeadList(pContainerListHead, &pNewEntry->entry);        
	return STATUS_SUCCESS;
}

VOID FreeList(VOID)
{
	PLIST_ENTRY pListEntry = NULL; 
	PLIST_ENTRY pNextEntry = NULL;
	PCONTAINER_ENTRY pCurContainerEntry = NULL;
	
	if(pContainerListHead != NULL)
	{
		if(!IsListEmpty(pContainerListHead))
		{
			pListEntry = pContainerListHead->Flink;
			do
			{
				pCurContainerEntry = (PCONTAINER_ENTRY)CONTAINING_RECORD(pListEntry, CONTAINER_ENTRY, entry);
				pNextEntry = pListEntry->Flink;
				ExFreePool(pCurContainerEntry);
				pListEntry = pNextEntry;
			}
			while(pListEntry != pContainerListHead);
			pContainerListHead = NULL;
		}

	}
}

VOID Fill_Blob_with_Data(PBYTE pData)
{
	PLIST_ENTRY pListEntry = NULL;
	PCONTAINER_ENTRY pCurContainerEntry = NULL;
	ULONG i=0;

	if(pContainerListHead != NULL)
	{
		if(IsListEmpty(pContainerListHead))
		{
			Dbg("The list is empty\n");
		}
		else
		{		
			pListEntry = pContainerListHead->Flink;
			Dbg("Walk through the container list\n");
			do
			{
				pCurContainerEntry = (PCONTAINER_ENTRY)CONTAINING_RECORD(pListEntry, CONTAINER_ENTRY, entry);
				RtlCopyMemory(pData, &(pCurContainerEntry->raw_data_len), sizeof(ULONG));
				RtlCopyMemory(pData+sizeof(ULONG), pCurContainerEntry->rc4_key, RC4_KEY_SIZE);
				RtlCopyMemory(pData+sizeof(ULONG)+MD5_CHECKSUM_SIZE, pCurContainerEntry->checksum, MD5_CHECKSUM_SIZE);
				RtlCopyMemory(pData+sizeof(ULONG)+MD5_CHECKSUM_SIZE+RC4_KEY_SIZE, pCurContainerEntry->data, pCurContainerEntry->raw_data_len);
				pData = pData+sizeof(ULONG)+MD5_CHECKSUM_SIZE+RC4_KEY_SIZE+pCurContainerEntry->raw_data_len;
				pListEntry = pListEntry->Flink;   
			}
			while(pListEntry != pContainerListHead);
		}
	}	
}

VOID Dbg_WalkList(VOID)
{
	PLIST_ENTRY pListEntry = NULL;
	PCONTAINER_ENTRY pCurContainerEntry = NULL;
	ULONG i=0;

	if(pContainerListHead != NULL)
	{
		if(IsListEmpty(pContainerListHead))
		{
			Dbg("The list is empty\n");
		}
		else
		{		
			pListEntry = pContainerListHead->Flink;
			Dbg("Walk through the container list\n");
			do
			{
				pCurContainerEntry = (PCONTAINER_ENTRY)CONTAINING_RECORD(pListEntry, CONTAINER_ENTRY, entry);
				Dbg("datalen : %d\n", pCurContainerEntry->raw_data_len);
				Dbg("checksum : \n");
				for(i=0; i<MD5_CHECKSUM_SIZE; i++)
					Dbg("%02x", pCurContainerEntry->checksum[i]);
				Dbg("data : \n");
				for(i=0; i<pCurContainerEntry->raw_data_len; i++)
					Dbg("%x", pCurContainerEntry->data[i]);
				pListEntry = pListEntry->Flink;   
			}
			while(pListEntry != pContainerListHead);
		}
	}
}
