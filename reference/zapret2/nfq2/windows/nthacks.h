#pragma once

#include <winternl.h>

#define DIRECTORY_QUERY                 (0x0001)
#define DIRECTORY_TRAVERSE              (0x0002)
#define DIRECTORY_CREATE_OBJECT         (0x0004)
#define DIRECTORY_CREATE_SUBDIRECTORY   (0x0008)
#define DIRECTORY_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0xF)

typedef struct _PROCESS_SESSION_INFORMATION {
    ULONG SessionId;
} PROCESS_SESSION_INFORMATION, *PPROCESS_SESSION_INFORMATION;

typedef struct _OBJECT_DIRECTORY_INFORMATION {
	UNICODE_STRING Name;
	UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, *POBJECT_DIRECTORY_INFORMATION;

#ifdef __cplusplus
extern "C"
{
#endif
	NTSTATUS NTAPI NtOpenDirectoryObject(
		_Out_ PHANDLE            DirectoryHandle,
		_In_  ACCESS_MASK        DesiredAccess,
		_In_  POBJECT_ATTRIBUTES ObjectAttributes
	);
	NTSTATUS NTAPI NtQueryDirectoryObject(
		_In_      HANDLE  DirectoryHandle,
		_Out_opt_ PVOID   Buffer,
		_In_      ULONG   Length,
		_In_      BOOLEAN ReturnSingleEntry,
		_In_      BOOLEAN RestartScan,
		_Inout_   PULONG  Context,
		_Out_opt_ PULONG  ReturnLength
	);
#ifdef __cplusplus
};
#endif
