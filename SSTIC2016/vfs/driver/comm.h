#ifndef __IOCTL_HANDLERS__H
#define __IOCTL_HANDLERS__H

#define MAX_SIZE_FILE			2097152  // 2mb
#define MAX_PATH_SIZE			50
#define	MD5_CHECKSUM_SIZE		16
#define DISKPATH_FORMAT 		L"\\DosDevices\\%c:"
#define IOCTL_VOLUME_BASE		((ULONG) 'V')
#define ABSOLUTE(wait) 			(wait)
#define RELATIVE(wait) 			(-(wait))
#define NANOSECONDS(nanos) \
								(((signed __int64)(nanos)) / 100L)
#define MICROSECONDS(micros) \
								(((signed __int64)(micros)) * NANOSECONDS(1000L))
#define MILLISECONDS(milli) \
								(((signed __int64)(milli)) * MICROSECONDS(1000L))
#define SECONDS(seconds) \
								(((signed __int64)(seconds)) * MILLISECONDS(1000L))

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG 			NextEntryOffset;
	ULONG			NumberOfThreads;
	LARGE_INTEGER	Reserved[3];
	LARGE_INTEGER	CreateTime;
	LARGE_INTEGER	UserTime;
	LARGE_INTEGER	KernelTime;
	UNICODE_STRING	ImageName;
	KPRIORITY		BasePriority;
	HANDLE			ProcessId;
	HANDLE			InheritedFromProcessId;
	ULONG			HandleCount;
	ULONG			Reserved2[2];
	ULONG			PrivatePageCount;
	VM_COUNTERS		VirtualMemoryCounters;
	IO_COUNTERS		IoCounters;
	PVOID			Threads[0];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

typedef struct _SHARED_BUFFER {
	HANDLE			event_driver_ready_to_recv_file;
	HANDLE			event_user_file_sent;
	HANDLE			event_driver_memory_full;
	HANDLE			event_user_all_files_sent;
	DWORD			raw_data_len;
	BYTE			checksum[MD5_CHECKSUM_SIZE];
	BYTE 			data[MAX_SIZE_FILE];
} SHARED_BUFFER, *PSHARED_BUFFER;

typedef struct _THREAD_ARGS {
	DWORD			dwPid;
	CHAR			cDiskLetter;
} THREAD_ARGS;


typedef NTSTATUS(*ZWQUERYSYSTEMINFORMATION)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(*ZWQUERYINFORMATIONPROCESS)(HANDLE, ULONG, PVOID, ULONG, PULONG);

ZWQUERYSYSTEMINFORMATION ZwQuerySystemInformation;
ZWQUERYINFORMATIONPROCESS ZwQueryInformationProcess;

SHARED_BUFFER s_SharedBuffer;
PMDL pMdl;
PVOID addrMdl;
BOOL bFinish;
		
//////////////////////////////////////
// FUNCTIONS
//////////////////////////////////////

NTSTATUS Comm_InitUserlandThread(PWCHAR);
NTSTATUS Comm_WaitUserlandNotif(THREAD_ARGS*);
NTSTATUS Comm_InitMDL();
NTSTATUS Comm_AccessMdl(PVOID);
VOID Comm_MapBufferInUserSpace();
VOID wrap_MDL_SetEvent();
VOID wrap_MDL_SetFinishEvent();
VOID wrap_MDL_WaitEvent();
VOID wrap_MDL_ResetUserEvent();
VOID wrap_MDL_ResetEvent();
VOID wrap_MDL_WaitFinishEvent();
VOID wrap_MDL_DumpStructure();


#endif 
