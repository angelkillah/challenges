#include "main.h"
#include "comm.h"
#include "disk.h"
#include "rc6.h"
#include "vfs.h"
 
NTSTATUS DISK_ReadWriteSector(__in DWORD dwSectorsToRead,
							  __in LONGLONG lStartingOffset,
							  __in BOOL bWrite,
							  __out PCHAR pData)
{
	NTSTATUS status;
	IO_STATUS_BLOCK iosb;
	KEVENT event;
	LARGE_INTEGER lDiskOffset = {0};
	PIRP pIrp = NULL;
	ULONG ulMajorFunction;
	
	if(!pDevObj || !pData || !dwSectorsToRead || !pObjFile)
	{
		Dbg(__FUNCTION__ "\t l35\n");
		return STATUS_NO_MEMORY;
	}
	KeInitializeEvent(&event, NotificationEvent, FALSE);
	lDiskOffset.QuadPart = lStartingOffset; 
	
	ulMajorFunction = (bWrite == FALSE ? IRP_MJ_READ : IRP_MJ_WRITE);
	pIrp = IoBuildSynchronousFsdRequest(ulMajorFunction, pDevObj, pData, dwSectorsToRead*512, &lDiskOffset, &event, &iosb);
	if(!pIrp)
	{
	Dbg(__FUNCTION__ "\t l45\n");
		return STATUS_NO_MEMORY;
	}
	
	IoGetNextIrpStackLocation(pIrp)->FileObject = pObjFile; 
	status = IoCallDriver(pDevObj, pIrp);
	if(status == STATUS_PENDING)
	{
		KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
		status = iosb.Status;
	}
	if(!NT_SUCCESS(status))
	{
		Dbg(__FUNCTION__ "\t status : %x l57\n", status);
		return STATUS_NO_MEMORY;
	}
	return STATUS_SUCCESS;
}

ULONG DISK_GetCurrentFreeBlock()
{
	ULONG i;
	for(i=1; i<=pDiskInfo->nb_of_partitions; i++)
	{
		if(pDiskInfo->current_disk_offset < pDiskInfo->begin_offset[i])
			return i;
	}
	return 0;
}


NTSTATUS DISK_WriteData(__in ULONG ulDataSize,
						__in PBYTE pData)
{
	NTSTATUS status;
	KEVENT event;
	LARGE_INTEGER lDiskOffset = {0};
	IO_STATUS_BLOCK iosb;
	ULONG nb_sectors_to_write = 0;
	ULONG nb_bytes_to_write = 0;
	ULONG nb_free_sectors;
	ULONG i, j=0;
	ULONG current_block;
	ULONG available_space_in_sector = 0;
	PCHAR pCurrentSector = NULL;
	PIRP pIrp = NULL;
	PBYTE pTmp = NULL;
	
	if(!pDevObj || !pDiskInfo || !pData)
		return STATUS_UNSUCCESSFUL;
	
	pCurrentSector = PoolAlloc(512);
	if(pCurrentSector == NULL || (ulDataSize >= pDiskInfo->total_freespace))
	{
		Dbg(__FUNCTION__ "\t l100\n");
		return STATUS_NO_MEMORY;
	}
	nb_bytes_to_write = ulDataSize;

	while(nb_bytes_to_write)
	{
		Dbg("[!] nb_bytes_to_write : %d\n", nb_bytes_to_write);
		if(pDiskInfo->current_offset_in_sector > 0)
		{
			Dbg("There is space available in the current sector, let's fill it\n");
			available_space_in_sector = 512 - pDiskInfo->current_offset_in_sector;
			status = DISK_ReadWriteSector(1, pDiskInfo->current_disk_offset, READ, pCurrentSector);
			if(!NT_SUCCESS(status))
				return status;
			Dbg("space available in the sector : %lx\n", available_space_in_sector);
			if(nb_bytes_to_write >= available_space_in_sector)
			{
				Dbg("data to write >= sector size left")
				RtlCopyMemory(pCurrentSector+pDiskInfo->current_offset_in_sector, pData+(ulDataSize-nb_bytes_to_write), available_space_in_sector);
				nb_bytes_to_write -= available_space_in_sector;   
				current_block = DISK_GetCurrentFreeBlock();
				Dbg("current_block : %lx\n", current_block);
				status = DISK_ReadWriteSector(1, pDiskInfo->current_disk_offset, WRITE, pCurrentSector);
				if(!NT_SUCCESS(status))
					return status;
				if((pDiskInfo->current_disk_offset+512) >= pDiskInfo->begin_offset[current_block])
				{
					pDiskInfo->current_disk_offset = pDiskInfo->end_offset[current_block];
					Dbg("jump @ %I64x\n", pDiskInfo->current_disk_offset);
				}
				else
					pDiskInfo->current_disk_offset += 512;
				pDiskInfo->current_offset_in_sector = 0;
			}
			else
			{
				Dbg("data to write < sector size left\n");
				RtlCopyMemory(pCurrentSector+pDiskInfo->current_offset_in_sector, pData+(ulDataSize-nb_bytes_to_write), nb_bytes_to_write);
				status = DISK_ReadWriteSector(1, pDiskInfo->current_disk_offset, WRITE, pCurrentSector);
				if(!NT_SUCCESS(status))
					return status;
				pDiskInfo->current_offset_in_sector += nb_bytes_to_write;
				nb_bytes_to_write = 0;	
			}
			Dbg("writing success. current_disk_offset = %I64x, current_offset_in_sector = %I64x\n", pDiskInfo->current_disk_offset, pDiskInfo->current_offset_in_sector);
		}
		// there is no space left in the current sector
		else
		{
			Dbg("there is no space available in the current sector\n");
			// how many sectors are available to write in the curent block? we need to handle the case where there is less than one sector to write
			current_block = DISK_GetCurrentFreeBlock();
			nb_free_sectors = (ULONG)(pDiskInfo->begin_offset[current_block] - pDiskInfo->current_disk_offset)/512;
			if(((nb_bytes_to_write/512)+1) <= nb_free_sectors)
			{
				Dbg("there is space to write in the current block\n");
				if(nb_bytes_to_write/512 > 0)
				{
					status = DISK_ReadWriteSector(nb_bytes_to_write/512, pDiskInfo->current_disk_offset, WRITE, pData+(ulDataSize-nb_bytes_to_write));
					if(!NT_SUCCESS(status))
						return status;
					pDiskInfo->current_disk_offset += ((nb_bytes_to_write/512)*512);
					pDiskInfo->current_offset_in_sector = 0;
					Dbg("writing success. current_disk_offset = %I64x, current_offset_in_sector = %I64x\n", pDiskInfo->current_disk_offset, pDiskInfo->current_offset_in_sector);
					nb_bytes_to_write %= 512;
					if(nb_bytes_to_write)
					{
						Dbg("there is %d bytes left to write\n", nb_bytes_to_write);
						status = DISK_ReadWriteSector(1, pDiskInfo->current_disk_offset, WRITE, pData+(ulDataSize-nb_bytes_to_write));
						if(!NT_SUCCESS(status))
							return status;
						pDiskInfo->current_offset_in_sector = nb_bytes_to_write;
						nb_bytes_to_write = 0;
						Dbg("writing success. current_disk_offset = %I64x, current_offset_in_sector = %I64x\n", pDiskInfo->current_disk_offset, pDiskInfo->current_offset_in_sector);
					}
				}
				// data to write less than sector size ?
				else if((nb_bytes_to_write/512) == 0)
				{
					Dbg("data to write less than a sector size\n")
					pTmp = PoolAlloc(512);
					RtlZeroMemory(pTmp, 512);
					RtlCopyMemory(pTmp, pData+(ulDataSize-nb_bytes_to_write), nb_bytes_to_write);
					status = DISK_ReadWriteSector(1, pDiskInfo->current_disk_offset, WRITE, pTmp);
					if(!NT_SUCCESS(status))
						return status;
					Dbg("writing success.\n");
					PoolFree(pTmp);
					pDiskInfo->current_offset_in_sector += nb_bytes_to_write;
					nb_bytes_to_write = 0;
				}
			}
			// we write in every bloc sectors and we go to the end of the partition
			else
			{
				status = DISK_ReadWriteSector(nb_free_sectors, pDiskInfo->current_disk_offset, WRITE, pData+(ulDataSize-nb_bytes_to_write));
				if(!NT_SUCCESS(status))
					return status;
				current_block = DISK_GetCurrentFreeBlock();
				Dbg("current_block : %lx\n", current_block);
				i=0;
				Dbg("end_offset[current_block] : %I64x\nbegin_offset[current_block+1] : %I64x\n", pDiskInfo->end_offset[current_block], pDiskInfo->begin_offset[current_block+1]);
				while(pDiskInfo->end_offset[current_block+i] == pDiskInfo->begin_offset[current_block+i+1])
					i++;
				pDiskInfo->current_disk_offset = pDiskInfo->end_offset[current_block+i];
				pDiskInfo->current_offset_in_sector = 0;
				nb_bytes_to_write -= (nb_free_sectors*512);
			}
			Dbg("writing success. current_disk_offset = %I64x, current_offset_in_sector = %I64x\n", pDiskInfo->current_disk_offset, pDiskInfo->current_offset_in_sector);
		}
	}
	PoolFree(pCurrentSector);
	return STATUS_SUCCESS;
}

BOOL DISK_IsSectorEmpty(__in LONGLONG lOffset)
{
	LARGE_INTEGER lDiskOffset = {0};
	BYTE buf2[512] = {0};
	PBYTE buf = NULL;
	
	buf = PoolAlloc(512);
	if(!buf)
	{
		Dbg(__FUNCTION__ "\t l223\n");
		return STATUS_NO_MEMORY;
	}
	lDiskOffset.QuadPart = lOffset;
	DISK_ReadWriteSector(1, lDiskOffset.QuadPart, READ, buf);
	if(RtlEqualMemory(buf, buf2, 512))
	{
		PoolFree(buf);
		return TRUE;
	}
	PoolFree(buf);
	return FALSE;
}

// if vfs exists : returns the structure read from the diskExtents
// otherwise, returns the first sector available to write
NTSTATUS DISK_GetFirstFreeSector(__out PBOOL bDoesVFSExist)
{
	NTSTATUS status;
	LARGE_INTEGER lDiskOffset = {0};
	LONGLONG i = 1;
	
	while(TRUE)
	{
		lDiskOffset.QuadPart = 512*i;
		if(DISK_IsSectorEmpty(lDiskOffset.QuadPart))
		{	
			Dbg(__FUNCTION__ ":\tfree space @ offset : %llu\n", lDiskOffset.QuadPart);
			pDiskInfo->current_disk_offset = lDiskOffset.QuadPart;
			return STATUS_SUCCESS;
		}
		i++;
	}
}	
	

NTSTATUS DISK_GetDiskNumber(__in  PWCHAR diskpath, 
						   __out PDWORD DiskNumber)
{
	NTSTATUS status;
	HANDLE hFile;
	UNICODE_STRING usDiskPath;
	OBJECT_ATTRIBUTES objAttr;
	VOLUME_DISK_EXTENTS diskExtents;
	DWORD dwSize;
	IO_STATUS_BLOCK iosb = {0};
		
	RtlInitUnicodeString(&usDiskPath, (PCWSTR)diskpath);
	InitializeObjectAttributes(&objAttr, &usDiskPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	
	status = ZwCreateFile(&hFile, FILE_READ_DATA, &objAttr, &iosb, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE, NULL, 0);
	if(!NT_SUCCESS(status))
	{
		ZwClose(hFile);
		return status;
	}
	
	status = ZwDeviceIoControlFile(hFile, NULL, NULL, NULL, &iosb, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, NULL, 0, (PVOID)&diskExtents, sizeof(diskExtents));  
	if(!NT_SUCCESS(status))
	{
		ZwClose(hFile);
		return status;
	}
	
	*DiskNumber = diskExtents.Extents[0].DiskNumber;
	
	ZwClose(hFile);
	return status;
}

NTSTATUS DISK_GetDiskDeviceObject(__in PWCHAR pDrivePath)
{
	NTSTATUS status;
	HANDLE hFile;
	UNICODE_STRING usDiskPath;
	OBJECT_ATTRIBUTES objAttr;
	DWORD dwDiskNumber;
	WCHAR diskpath[20];
	IO_STATUS_BLOCK iosb = {0};
	
	status = DISK_GetDiskNumber(pDrivePath, &dwDiskNumber);
	if(!NT_SUCCESS(status))
		return status;
	
	if(!NT_SUCCESS(RtlStringCchPrintfW(diskpath, 20, L"\\??\\PhysicalDrive%d", dwDiskNumber)))
		return STATUS_INVALID_PARAMETER;

	RtlInitUnicodeString(&usDiskPath, diskpath);
	InitializeObjectAttributes(&objAttr, &usDiskPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
		
	status = ZwCreateFile(&hFile, FILE_READ_DATA | FILE_WRITE_DATA, &objAttr, &iosb, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_NON_DIRECTORY_FILE, NULL, 0);
	if(!NT_SUCCESS(status))
	{
		ZwClose(hFile);
		return status;
	}
	
	status = ObReferenceObjectByHandle(hFile, FILE_READ_DATA, NULL, KernelMode, &pObjFile, NULL);
	if(!NT_SUCCESS(status))
	{
		ZwClose(hFile);
		return status;
	}
	
	pDevObj = IoGetRelatedDeviceObject(pObjFile);
	ZwClose(hFile);
	return status;
}

NTSTATUS DISK_GetDiskTotalSize()
{
	NTSTATUS status;
	KEVENT event;
	PIRP pIrp = NULL;
	DISK_GEOMETRY_EX lDiskSize;
	IO_STATUS_BLOCK iosb = {0};
	
	KeInitializeEvent(&event, NotificationEvent, FALSE);
	pIrp = IoBuildDeviceIoControlRequest(IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, 
										 pDevObj, 
										 NULL, 
										 0, 
										 &lDiskSize, 
										 sizeof(DISK_GEOMETRY_EX), 
										 FALSE, 
										 &event, 
										 &iosb);
	if(pIrp)
	{
		IoGetNextIrpStackLocation(pIrp)->FileObject = pObjFile;
		status = IoCallDriver(pDevObj, pIrp);
		if(status == STATUS_PENDING)
		{
			KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
			status = iosb.Status;
		}
		pDiskInfo->total_space = lDiskSize.DiskSize.QuadPart;
	}
	else
	{
		Dbg(__FUNCTION__ "\t 363\n");
		return STATUS_NO_MEMORY;
	}
	return status;
}

DWORD DISK_GetPartitionsNumber(__in DRIVE_LAYOUT_INFORMATION_EX *pDriveLayout)
{
	DWORD i;
	DWORD cPartitions = 0;
	for(i=0; i<pDriveLayout->PartitionCount; i++)
	{
		if(pDriveLayout->PartitionEntry[i].PartitionStyle == 0) // PARTITION_STYLE_MBR
		{
			if(pDriveLayout->PartitionEntry[i].Mbr.PartitionType != 0) // PARTITION_ENTRY_UNUSED  
				cPartitions++;
		}
	}
	return cPartitions;
}

NTSTATUS DISK_CollectDriveInfo(__in PWCHAR pDrivePath)
{
	NTSTATUS ntStatus, status;
	IO_STATUS_BLOCK iosb = {0};
	PIRP pIrp = NULL;
	KEVENT event;
	DRIVE_LAYOUT_INFORMATION_EX* pDriveLayout = NULL;
	BOOL bDoesVFSExist = FALSE;
	ULONG i = 0, j = 1;
	LONGLONG totalsize = 0;
	
	pDiskInfo = (DISK_INFO*)PoolAlloc(sizeof(DISK_INFO));
	if(pDiskInfo == NULL)
		return STATUS_NO_MEMORY;
	RtlZeroMemory(pDiskInfo, sizeof(DISK_INFO));
	
	status = DISK_GetDiskDeviceObject(pDrivePath);
	if(!NT_SUCCESS(status))
		return status;
	
	KeInitializeEvent(&event, NotificationEvent, FALSE);
	status = STATUS_BUFFER_TOO_SMALL;
	while(status == STATUS_BUFFER_TOO_SMALL || ntStatus == STATUS_BUFFER_TOO_SMALL)
	{
		i++;
		iosb.Status = STATUS_SUCCESS;
		if(pDriveLayout)
			PoolFree(pDriveLayout);
		pDriveLayout = (DRIVE_LAYOUT_INFORMATION_EX*)PoolAlloc(sizeof(DRIVE_LAYOUT_INFORMATION_EX)*i);
		if(pDriveLayout == NULL)
			return STATUS_NO_MEMORY;
		
		pIrp = IoBuildDeviceIoControlRequest(IOCTL_DISK_GET_DRIVE_LAYOUT_EX, 
											 pDevObj, 
											 NULL, 
											 0, 
											 pDriveLayout, 
											 sizeof(DRIVE_LAYOUT_INFORMATION_EX)*i, 
											 0, 
											 &event, 
											 &iosb);
		if(pIrp == NULL)
		{
			if(pDriveLayout)
				PoolFree(pDriveLayout);
			ObDereferenceObject(pObjFile);
			return STATUS_INVALID_PARAMETER;
		}
		IoGetNextIrpStackLocation(pIrp)->FileObject = pObjFile;
		ntStatus = IoCallDriver(pDevObj, pIrp);
		if(ntStatus == STATUS_BUFFER_TOO_SMALL)
		{}
		else if(ntStatus == STATUS_PENDING)
		{
			KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
			status = iosb.Status;
			KeResetEvent(&event);
		}
		else
			break;
		
	}

	if(!NT_SUCCESS(DISK_GetDiskTotalSize()))
		return status;
	
	pDiskInfo->magic = 0xC1C1C1C1;
	pDiskInfo->magic2 = 0xC1C1C1C1;
	pDiskInfo->nb_of_partitions = DISK_GetPartitionsNumber(pDriveLayout);
	pDiskInfo->current_offset_in_sector = 0;
	
	for(i=0; i<pDriveLayout->PartitionCount; i++)
	{
		if(pDriveLayout->PartitionEntry[i].PartitionStyle == 0) // PARTITION_STYLE_MBR
		{
			Dbg("PartitionType : %x\n", pDriveLayout->PartitionEntry[i].Mbr.PartitionType);
			if(pDriveLayout->PartitionEntry[i].Mbr.PartitionType != 0) // PARTITION_ENTRY_UNUSED  
			{
				Dbg("Starting offset : %I64x, PartitionLength : %I64x\n", pDriveLayout->PartitionEntry[i].StartingOffset, pDriveLayout->PartitionEntry[i].PartitionLength);
				pDiskInfo->begin_offset[j] = pDriveLayout->PartitionEntry[i].StartingOffset.QuadPart;
				pDiskInfo->end_offset[j] = pDriveLayout->PartitionEntry[i].StartingOffset.QuadPart + pDriveLayout->PartitionEntry[i].PartitionLength.QuadPart;
				Dbg("Begin offset : %I64x, EndOffset : %I64x\n", pDiskInfo->begin_offset[j], pDiskInfo->end_offset[j]);
			}
		}
		j++;
	}
	
	status = DISK_GetFirstFreeSector(&bDoesVFSExist);
	if(!NT_SUCCESS(status))
		return status;
	
	if(!bDoesVFSExist)
	{
		pDiskInfo->begin_offset[0] = 0;
		pDiskInfo->end_offset[0] = pDiskInfo->current_disk_offset;
	}
	else
	{
		Dbg("[+] VFS found\n")
		return VFS_ALREADY_EXISTS;
	}
	
	// save the diskinfo offset
	offset_diskinfo = pDiskInfo->current_disk_offset;
	
	Dbg("nb_of_partitions : %d\n", pDiskInfo->nb_of_partitions);
	for(i=0; i<=pDiskInfo->nb_of_partitions; i++)
	{
		if(i==pDiskInfo->nb_of_partitions)
			totalsize += (pDiskInfo->total_space-pDiskInfo->end_offset[i]);
		else
			totalsize += (pDiskInfo->begin_offset[i+1]-pDiskInfo->end_offset[i]);
	}
	
	pDiskInfo->total_freespace = totalsize;
	Dbg("Total Size : %llu\n", pDiskInfo->total_space);
	Dbg("Total Free Size : %llu\n", totalsize);
	
	PoolFree(pDriveLayout);
	return status;
}

/*
NTSTATUS store_file(PCHAR pEncrypted, ULONG EncSize, PWCHAR FileName)
{
	NTSTATUS ntStatus;
	UNICODE_STRING usFileName;
	IO_STATUS_BLOCK iosb;
	OBJECT_ATTRIBUTES objAttr;
	HANDLE hFile;

	RtlInitUnicodeString(&usFileName, FileName); 
	InitializeObjectAttributes(&objAttr, &usFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	Dbg("Before ZwCreateFile\n");

	ntStatus = ZwCreateFile(&hFile, GENERIC_WRITE, &objAttr, &iosb, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_SUPERSEDE, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	if(!NT_SUCCESS(ntStatus))
		return STATUS_INVALID_PARAMETER;

	Dbg("new file created\n");

	ntStatus = ZwWriteFile(hFile, NULL, NULL, NULL, &iosb, pEncrypted, EncSize, NULL, NULL);
	if(!NT_SUCCESS(ntStatus))
		return STATUS_INVALID_PARAMETER;

	Dbg("file written\n");

	ntStatus = ZwClose(hFile);
	if(!NT_SUCCESS(ntStatus))
		return STATUS_INVALID_PARAMETER;

	return STATUS_SUCCESS;
}*/