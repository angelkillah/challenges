#ifndef __DISK__H
#define __DISK__H

#define IOCTL_DISK_GET_DRIVE_LAYOUT_EX \
			CTL_CODE (FILE_DEVICE_DISK, 0x14, METHOD_BUFFERED, FILE_ANY_ACCESS)
			
#define IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS \
			CTL_CODE (IOCTL_VOLUME_BASE, 0, METHOD_BUFFERED, FILE_ANY_ACCESS)
			
#define IOCTL_DISK_GET_DRIVE_GEOMETRY_EX \
			CTL_CODE (FILE_DEVICE_DISK, 0x28, METHOD_BUFFERED, FILE_ANY_ACCESS)
			
#define VFS_ALREADY_EXISTS		0x5513

#pragma pack(push)
#pragma pack(1)
typedef struct _DISK_INFO {
	DWORD			magic;
	DWORD			nb_of_partitions;
	LONGLONG		total_freespace;
	LONGLONG		total_usedspace;
	LONGLONG		total_space;
	LONGLONG	 	current_disk_offset;
	ULONG			current_offset_in_sector;
	LONGLONG		begin_offset[5];
	LONGLONG		end_offset[5];
	DWORD			magic2;
} DISK_INFO, *PDISK_INFO;
#pragma pack(pop)

typedef struct _DISK_EXTENT {
	DWORD			DiskNumber;
	LARGE_INTEGER	StartingOffset;
	LARGE_INTEGER	ExtentLength;
} DISK_EXTENT, *PDISK_EXTENT;

typedef struct _VOLUME_DISK_EXTENTS {
	DWORD		NumberOfDiskExtents;
	DISK_EXTENT	Extents[ANYSIZE_ARRAY];
} VOLUME_DISK_EXTENTS, *PVOLUME_DISK_EXTENTS;

typedef struct _PARTITION_INFORMATION_GPT {
	GUID		PartitionType;
	GUID		PartitionId;
	ULONG64		Attributes;
	WCHAR		Name[36];
} PARTITION_INFORMATION_GPT, *PPARTITION_INFORMATION_GPT;	

typedef struct _PARTITION_INFORMATION_MBR {
	UCHAR		PartitionType;
	BOOLEAN		BootIndicator;
	BOOLEAN		RecognizedPartition;
	ULONG		HiddenSectors;
} PARTITION_INFORMATION_MBR, *PPARTITION_INFORMATION_MBR;			
			
typedef enum _PARTITION_STYLE {
	PARTITION_STYLE_MBR = 0,
	PARTITION_STYLE_GPT = 1,
	PARTITION_STYLE_RAW = 2
} PARTITION_STYLE;
			
typedef struct _DRIVE_LAYOUT_INFORMATION_MBR {
	ULONG	Signature;
} DRIVE_LAYOUT_INFORMATION_MBR, *PDRIVE_LAYOUT_INFORMATION_MBR;
			
typedef struct _DRIVE_LAYOUT_INFORMATION_GPT {
	GUID			DiskId;
	LARGE_INTEGER	StartingUsableOffset;
	LARGE_INTEGER	UsableLength;
	ULONG			MaxPartitionCount;
} DRIVE_LAYOUT_INFORMATION_GPT, *PDRIVE_LAYOUT_INFORMATION_GPT;
			
			
typedef struct _PARTITION_INFORMATION_EX {
	PARTITION_STYLE		PartitionStyle;
	LARGE_INTEGER		StartingOffset;
	LARGE_INTEGER		PartitionLength;
	ULONG				PartitionNumber;
	BOOLEAN				RewritePartition;
	union {
		PARTITION_INFORMATION_MBR	Mbr;
		PARTITION_INFORMATION_GPT	Gpt;
	};
} PARTITION_INFORMATION_EX, *PPARTITION_INFORMATION_EX;	
			
typedef struct _DRIVE_LAYOUT_INFORMATION_EX {
	ULONG	PartitionStyle;
	ULONG	PartitionCount;
	union {
		DRIVE_LAYOUT_INFORMATION_MBR Mbr;
		DRIVE_LAYOUT_INFORMATION_GPT Gpt;
	};
	PARTITION_INFORMATION_EX PartitionEntry[1];
} DRIVE_LAYOUT_INFORMATION_EX, *PDRIVE_LAYOUT_INFORMATION_EX;


typedef struct _DISK_GEOMETRY {
	LARGE_INTEGER	Cylinders;
	DWORD			MediaType;
	DWORD			TracksPerCylinder;
	DWORD			SectorsPerTrack;
	DWORD			BytesPerSector;
} DISK_GEOMETRY;

typedef struct _DISK_GEOMETRY_EX {
	DISK_GEOMETRY Geometry;
	LARGE_INTEGER DiskSize;
	BYTE		  Data[1];
} DISK_GEOMETRY_EX;

//////////////////////////////////////
//  GLOBALS
//////////////////////////////////////

PFILE_OBJECT pObjFile;
PDEVICE_OBJECT pDevObj;
PDISK_INFO pDiskInfo;
LONGLONG offset_diskinfo;


//////////////////////////////////////
// FUNCTIONS
//////////////////////////////////////

NTSTATUS DISK_CollectDriveInfo(__in PWCHAR pDrivePath);

NTSTATUS DISK_GetDiskNumber(__in  PWCHAR pDrivePath, 
						   __out PDWORD dwDiskNumber);
						   
NTSTATUS DISK_GetDiskTotalSize();
						   
NTSTATUS DISK_GetDiskDeviceObject(__in PWCHAR pDrivePath);
								 
DWORD DISK_GetPartitionsNumber(__in DRIVE_LAYOUT_INFORMATION_EX *pDriveLayout);	

NTSTATUS DISK_GetFirstFreeSector(__out PBOOL bDoesVFSExist);		

NTSTATUS DISK_WriteData(__in ULONG ulDataSize,
						__in PBYTE pData);	

NTSTATUS DISK_WipeVFS();		

NTSTATUS DISK_ReadWriteSector(__in DWORD dwSectorsToRead,
							  __in LONGLONG lStartingOffset,
							  __in BOOL bWrite,
							  __out PCHAR pData);	
						 
BOOL DISK_IsSectorEmpty(__in LONGLONG lOffset);		

ULONG DISK_GetCurrentFreeBlock();						
								 
NTSTATUS store_file(PCHAR pEncrypted, ULONG EncSize, PWCHAR FileName);
								 

#endif