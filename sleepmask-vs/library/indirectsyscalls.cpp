#include <windows.h>
#include "..\sleepmask-vs.h"
#include "..\library\syscallapi.h"
#include "..\library\indirectsyscalls.h"
#include "winternl.h"

// Ptr to global sys call information.
extern PBEACON_SYSCALLS gSysCallInfo;

// Scoped vars used for jmp target and sys number.
PVOID currentJmpAddr = NULL;
DWORD currentSysNum = 0;
#ifdef _WIN32
PVOID originalEdi = 0;
#endif

// Memory management APIs.
NTSTATUS _NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect) {
    PrepareSyscall(gSysCallInfo->syscalls.ntAllocateVirtualMemory.sysnum, gSysCallInfo->syscalls.ntAllocateVirtualMemory.jmpAddr);
    return DoSyscall(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

NTSTATUS _NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection) {
    PrepareSyscall(gSysCallInfo->syscalls.ntProtectVirtualMemory.sysnum, gSysCallInfo->syscalls.ntProtectVirtualMemory.jmpAddr);
    return DoSyscall(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
}

NTSTATUS _NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType) {
    PrepareSyscall(gSysCallInfo->syscalls.ntFreeVirtualMemory.sysnum, gSysCallInfo->syscalls.ntFreeVirtualMemory.jmpAddr);
    return DoSyscall(ProcessHandle, BaseAddress, RegionSize, FreeType);
}

NTSTATUS _NtQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength) {
    PrepareSyscall(gSysCallInfo->syscalls.ntQueryVirtualMemory.sysnum, gSysCallInfo->syscalls.ntQueryVirtualMemory.jmpAddr);
    return  DoSyscall(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);
}

NTSTATUS _NtCreateSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle) {
    PrepareSyscall(gSysCallInfo->syscalls.ntCreateSection.sysnum, gSysCallInfo->syscalls.ntCreateSection.jmpAddr);
    return DoSyscall(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle);
}

NTSTATUS _NtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID BaseAddress, ULONG ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect) {
    PrepareSyscall(gSysCallInfo->syscalls.ntMapViewOfSection.sysnum, gSysCallInfo->syscalls.ntMapViewOfSection.jmpAddr);
    return DoSyscall(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect);
}

NTSTATUS _NtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress) {
    PrepareSyscall(gSysCallInfo->syscalls.ntUnmapViewOfSection.sysnum, gSysCallInfo->syscalls.ntUnmapViewOfSection.jmpAddr);
    return DoSyscall(ProcessHandle, BaseAddress);
}

NTSTATUS _NtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead) {
    PrepareSyscall(gSysCallInfo->syscalls.ntReadVirtualMemory.sysnum, gSysCallInfo->syscalls.ntReadVirtualMemory.jmpAddr);
    return  DoSyscall(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead);
}

NTSTATUS _NtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten) {
    PrepareSyscall(gSysCallInfo->syscalls.ntWriteVirtualMemory.sysnum, gSysCallInfo->syscalls.ntWriteVirtualMemory.jmpAddr);
    return DoSyscall(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
}

// Thread APIs.
NTSTATUS _NtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PPS_ATTRIBUTE_LIST AttributeList) {
    PrepareSyscall(gSysCallInfo->syscalls.ntCreateThreadEx.sysnum, gSysCallInfo->syscalls.ntCreateThreadEx.jmpAddr);
    return DoSyscall(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
}

NTSTATUS _NtGetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext) {
    PrepareSyscall(gSysCallInfo->syscalls.ntGetContextThread.sysnum, gSysCallInfo->syscalls.ntGetContextThread.jmpAddr);
    return DoSyscall(ThreadHandle, ThreadContext);
}

NTSTATUS _NtSetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext) {
    PrepareSyscall(gSysCallInfo->syscalls.ntSetContextThread.sysnum, gSysCallInfo->syscalls.ntSetContextThread.jmpAddr);
    return DoSyscall(ThreadHandle, ThreadContext);
}

NTSTATUS _NtResumeThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount) {
    PrepareSyscall(gSysCallInfo->syscalls.ntResumeThread.sysnum, gSysCallInfo->syscalls.ntResumeThread.jmpAddr);
    return DoSyscall(ThreadHandle, PreviousSuspendCount);
}

// Handle APIs.
NTSTATUS _NtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, CLIENT_ID* ClientId) {
    PrepareSyscall(gSysCallInfo->syscalls.ntOpenProcess.sysnum, gSysCallInfo->syscalls.ntOpenProcess.jmpAddr);
    return DoSyscall(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

NTSTATUS _NtOpenThread(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, CLIENT_ID* ClientId) {
    PrepareSyscall(gSysCallInfo->syscalls.ntOpenThread.sysnum, gSysCallInfo->syscalls.ntOpenThread.jmpAddr);
    return DoSyscall(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

NTSTATUS _NtClose(HANDLE Handle) {
    PrepareSyscall(gSysCallInfo->syscalls.ntClose.sysnum, gSysCallInfo->syscalls.ntClose.jmpAddr);
    return DoSyscall(Handle);
}

NTSTATUS _NtDuplicateObject(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options) {
    PrepareSyscall(gSysCallInfo->syscalls.ntDuplicateObject.sysnum, gSysCallInfo->syscalls.ntDuplicateObject.jmpAddr);
    return DoSyscall(SourceProcessHandle, SourceHandle, TargetProcessHandle, TargetHandle, DesiredAccess, HandleAttributes, Options);
}

/**
* Sets the globals currentJmpAddr/SysNum to target sys call.
*
* Note: This is inspired by RecycledGate:
* https://github.com/thefLink/RecycledGate/blob/main/Sample/Main.c#L95-L96
* however, it uses C instead of ASM to avoid the compiler
* overwriting the r10/r11 registers between calls.
*
* @param DWORD sysNum for current sys call.
* @param PVOID addr target jump address for sys call.
*/
void PrepareSyscall(DWORD sysNum, PVOID addr) {
    currentJmpAddr = addr;
    currentSysNum = sysNum;
}

/**
* x64 ASM stub for RecylcedGate.
*
* Note: This is x64 only and based on https://github.com/thefLink/RecycledGate.
*
* @param (...) means this asm stub can be called with a variable number of args.
* @return NTSTATUS.
*/
#ifdef _WIN64
// This attribute ensures the compiler generates code without prolog / epilog code.
__attribute__((naked))
NTSTATUS DoRecycledGateSyscallx64(...) {
    __asm {
        push [currentJmpAddr]
        xor rax, rax
        mov r10, rcx
        mov eax, [currentSysNum]
        ret
    }
}

/**
* x64 ASM stub for indirect sys call gate.
*
* @param (...) means this asm stub can be called with a variable number of args.
* @return NTSTATUS.
*/
__attribute__((naked))
NTSTATUS DoIndirectSyscallx64(...) {
    __asm {
        mov r11, currentJmpAddr
        mov eax, currentSysNum
        mov r10, rcx
        jmp r11
    }
}

/**
* x86 ASM stub for indirect sys call gate.
*
* Note: See the following for more info on WOW64 KiFastSystemCall: https://cloud.google.com/blog/topics/threat-intelligence/wow64-subsystem-internals-and-hooking-techniques/
*
* @param (...) means this asm stub can be called with a variable number of args.
* @return NTSTATUS.
*/
#elif _WIN32
__attribute__((naked))
NTSTATUS DoIndirectSyscallx86(...) {
    __asm {
        mov edx, esp             // Move esp into edx, which is modified later based on x86 Native vs WOW64
        mov originalEdi, edi     // Back up original value of non-volatile register edi

        mov eax, fs : [192]      // Determine if this is X86 Native or WOW64 (192 == 0xC0)
        test eax, eax
        je is_native

    is_wow64:                    // WOW64: Win7 WOW64 requires workarounds, which work on Win10 and Win11 as well.
        add edx, 4               // Workaround Win7 Wow64 expects edx to point at 1st arg
        xor ecx, ecx             // Workaround Win7 WoW64 expects ecx to be 0
        jmp do_syscall

    is_native:                   // Native X86, Note this path also works for Win10 and Win11 however it will use is_wow64 path.
        sub edx, 4               // Subtract 4 from edx for native

    do_syscall:                  // Workarounds have been applied and ready to make syscall.
        mov eax, currentSysNum
        mov edi, currentJmpAddr
        call edi                 // Call the syscall function

        mov edi, originalEdi     // Restore edi
        ret
    }
}
#endif
