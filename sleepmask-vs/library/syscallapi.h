#pragma once
#include "beacon_gate.h"
#include "sleepmask.h"
#include "winternl.h"
#include "../debug.h"

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

// Required structs.
typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation,
    MemoryWorkingSetInformation,
    MemoryMappedFilenameInformation,
    MemoryRegionInformation,
    MemoryWorkingSetExInformation,
    MemorySharedCommitInformation,
    MemoryImageInformation,
    MemoryRegionInformationEx,
    MemoryPrivilegedBasicInformation,
    MemoryEnclaveImageInformation,
    MemoryBasicInformationCapped
} MEMORY_INFORMATION_CLASS, * PMEMORY_INFORMATION_CLASS;

typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT, * PSECTION_INHERIT;

typedef struct _PS_ATTRIBUTE {
    ULONG  Attribute;
    SIZE_T Size;
    union
    {
        ULONG Value;
        PVOID ValuePtr;
    } u1;
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST {
    SIZE_T       TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

// Sys call API dispatcher routine. 
void SysCallDispatcher(PBEACON_INFO info, PFUNCTION_CALL functionCall);

// Sys call API wrappers.
void NtAllocateVirtualMemoryWrapper(PFUNCTION_CALL functionCall);
void NtProtectVirtualMemoryWrapper(PFUNCTION_CALL functionCall);
void NtFreeVirtualMemoryWrapper(PFUNCTION_CALL functionCall);
void NtGetContextThreadWrapper(PFUNCTION_CALL functionCall);
void NtSetContextThreadWrapper(PFUNCTION_CALL functionCall);
void NtResumeThreadWrapper(PFUNCTION_CALL functionCall);
void NtCreateThreadExWrapper(PFUNCTION_CALL functionCall);
void NtOpenProcessWrapper(PFUNCTION_CALL functionCall);
void NtOpenThreadWrapper(PFUNCTION_CALL functionCall);
void NtCloseWrapper(PFUNCTION_CALL functionCall);
void NtCreateSectionWrapper(PFUNCTION_CALL functionCall);
void NtMapViewOfSectionWrapper(PFUNCTION_CALL functionCall);
void NtUnmapViewOfSectionWrapper(PFUNCTION_CALL functionCall);
void NtQueryVirtualMemoryWrapper(PFUNCTION_CALL functionCal);
void NtDuplicateObjectWrapper(PFUNCTION_CALL functionCall);
void NtReadProcessMemoryWrapper(PFUNCTION_CALL functionCall);
void NtWriteProcessMemoryWrapper(PFUNCTION_CALL functionCall);

/**
* Sys call API function definitions
* 
* Note: These are extern as they are implemented in the specific technique .cpp code.
*/
extern NTSTATUS _NtProtectVirtualMemory(IN HANDLE ProcessHandle, IN OUT PVOID* BaseAddress, IN OUT PSIZE_T NumberOfBytesToProtect, IN ULONG NewAccessProtection, OUT PULONG OldAccessProtection);
extern NTSTATUS _NtAllocateVirtualMemory(IN HANDLE ProcessHandle, IN OUT PVOID* BaseAddress, IN ULONG_PTR ZeroBits, IN OUT PSIZE_T RegionSize, IN ULONG AllocationType, IN ULONG Protect);
extern NTSTATUS _NtFreeVirtualMemory(IN HANDLE ProcessHandle, IN OUT PVOID* BaseAddress, IN OUT PSIZE_T RegionSize, IN ULONG FreeType);
extern NTSTATUS _NtGetContextThread(IN HANDLE ThreadHandle, IN OUT PCONTEXT ThreadContext);
extern NTSTATUS _NtSetContextThread(IN HANDLE ThreadHandle, IN PCONTEXT ThreadContext);
extern NTSTATUS _NtResumeThread(IN HANDLE ThreadHandle, IN OUT PULONG PreviousSuspendCount OPTIONAL);
extern NTSTATUS _NtCreateThreadEx(OUT PHANDLE ThreadHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL, IN HANDLE ProcessHandle, IN PVOID StartRoutine, IN PVOID Argument OPTIONAL, IN ULONG CreateFlags, IN SIZE_T ZeroBits, IN SIZE_T StackSize, IN SIZE_T MaximumStackSize, IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL);
extern NTSTATUS _NtOpenProcess(OUT PHANDLE ProcessHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes, IN CLIENT_ID* ClientId);
extern NTSTATUS _NtOpenThread(OUT PHANDLE ProcessHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes, IN CLIENT_ID* ClientId);
extern NTSTATUS _NtClose(IN HANDLE Handle);
extern NTSTATUS _NtCreateSection(OUT PHANDLE SectionHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL, IN PLARGE_INTEGER MaximumSize OPTIONAL, IN ULONG SectionPageProtection, IN ULONG AllocationAttributes, IN HANDLE FileHandle OPTIONAL);
extern NTSTATUS _NtMapViewOfSection(IN HANDLE SectionHandle, IN HANDLE ProcessHandle, IN OUT PVOID BaseAddress, IN ULONG ZeroBits, IN SIZE_T CommitSize, IN OUT PLARGE_INTEGER SectionOffset OPTIONAL, IN OUT PSIZE_T ViewSize, IN SECTION_INHERIT InheritDisposition, IN ULONG AllocationType, IN ULONG Win32Protect);
extern NTSTATUS _NtUnmapViewOfSection(IN HANDLE ProcessHandle, IN PVOID BaseAddress);
extern NTSTATUS _NtQueryVirtualMemory(IN HANDLE ProcessHandle, IN PVOID BaseAddress, IN MEMORY_INFORMATION_CLASS MemoryInformationClass, OUT PVOID MemoryInformation, IN SIZE_T MemoryInformationLength, OUT PSIZE_T ReturnLength OPTIONAL);
extern NTSTATUS _NtDuplicateObject(IN HANDLE SourceProcessHandle, IN HANDLE SourceHandle, IN HANDLE TargetProcessHandle OPTIONAL, OUT PHANDLE TargetHandle OPTIONAL, IN ACCESS_MASK DesiredAccess, IN ULONG HandleAttributes, IN ULONG Options);
extern NTSTATUS _NtReadVirtualMemory(IN HANDLE ProcessHandle, IN PVOID BaseAddress, OUT PVOID Buffer, IN SIZE_T NumberOfBytesToRead, OUT PSIZE_T NumberOfBytesRead OPTIONAL);
extern NTSTATUS _NtWriteVirtualMemory(IN HANDLE ProcessHandle, IN PVOID BaseAddress, IN PVOID Buffer, IN SIZE_T NumberOfBytesToWrite, OUT PSIZE_T NumberOfBytesWritten OPTIONAL);
