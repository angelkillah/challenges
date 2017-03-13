#ifndef __VFS_H
#define __VFS_H


typedef struct _MFT {
	DWORD			nb_of_files;
	BYTE			rc6_key[RC6_KEY_CHARS];
} MFT, *PMFT;

//////////////////////////////////////
// FUNCTIONS
//////////////////////////////////////
				  
NTSTATUS VFS_Store_DiskInfo();				  
NTSTATUS VFS_StoreData();
NTSTATUS VFS_Update_DiskInfo();
#endif

