#ifndef __LINKED_LIST_H
#define __LINKED_LIST_H

#define FILE_DATA	PBYTE

/////////////////////////////////////////////////////////////////////////////
// STRUCTS
/////////////////////////////////////////////////////////////////////////////

// container linked list
typedef struct _CONTAINER_ENTRY
{
    LIST_ENTRY 	entry;
	ULONG 		entry_size;
    ULONG 		raw_data_len;
	BYTE		rc4_key[RC4_KEY_SIZE];
	BYTE		checksum[MD5_CHECKSUM_SIZE];
	FILE_DATA	data;
} CONTAINER_ENTRY, *PCONTAINER_ENTRY;



/////////////////////////////////////////////////////////////////////////////
// GLOBALS
/////////////////////////////////////////////////////////////////////////////

// files container list
PLIST_ENTRY pContainerListHead;
ULONG 		nb_entries;


/////////////////////////////////////////////////////////////////////////////
// FUNCTIONS
/////////////////////////////////////////////////////////////////////////////

PCONTAINER_ENTRY AllocateContainerEntry(PSHARED_BUFFER, PUCHAR);
NTSTATUS AddContainerToList(PSHARED_BUFFER, PUCHAR);
VOID FreeList(VOID);
VOID Dbg_WalkList(VOID);
ULONG Get_LinkedList_Size();
VOID Fill_Blob_with_Data(PBYTE);

#endif
