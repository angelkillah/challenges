#ifndef __MAIN__H
#define __MAIN__H

#include <fltkernel.h>
#include <ntddk.h>
#include <ntstrsafe.h>
#include <windef.h>

//#define DEBUG
#ifdef DEBUG
	#define Dbg(fmt, ...) \
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, fmt, __VA_ARGS__);
#else
	#define Dbg(fmt, ...)
#endif

#define DEVICE_NAME					L"\\Device\\drvSSTIC"

#define TAG_NAME					'vFs'
#define PoolAlloc(x)				ExAllocatePoolWithTag(NonPagedPool, x, TAG_NAME)		
#define PoolFree(x)					ExFreePoolWithTag(x, TAG_NAME)

#define READ 	0
#define WRITE	1

DWORD g_pid;
ULONG g_seed;

//////////////////////////////////////
// FUNCTIONS
//////////////////////////////////////

NTSTATUS DriverEntry(__in PDRIVER_OBJECT pDriverObject,
					 __in PUNICODE_STRING pRegistryPath);

DRIVER_UNLOAD Unload;

#endif 