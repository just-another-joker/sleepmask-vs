#include <windows.h>

// Include bof-vs header files.
#include "beacon.h"
#include "helpers.h"
#include "sleepmask.h"

// Include sleepmask-vs specific header files.
#include "..\debug.h"

#if ENABLE_LOGGING || _DEBUG
void dlog(const char* fmt, ...) {
    char buff[512];
    va_list va;
    va_start(va, fmt);
    vsprintf_s(buff, 512, fmt, va);
    va_end(va);
    OutputDebugStringA(buff);
}

/**
* A helper function to display the contents of the SLEEPMASK_INFO structure.
* 
* @param info A pointer to a SLEEPMASK_INFO structure.
*/
void PrintSleepMaskInfo(PBEACON_INFO info) {
    DLOGF("SLEEPMASK: Version: %X\n", info->version);
    DLOGF("SLEEPMASK: Sleepmask: %p\n", info->sleep_mask_ptr);
    DLOGF("SLEEPMASK: Sleepmask Text Size: %x\n", info->sleep_mask_text_size);
    DLOGF("SLEEPMASK: Sleepmask Total Size: %x\n", info->sleep_mask_total_size);
    DLOGF("SLEEPMASK: Beacon: %p\n", info->beacon_ptr);
    DLOGF("SLEEPMASK: Heap Records: %p\n", info->heap_records);
    DLOGF("SLEEPMASK: Mask Key: %p\n", &info->mask[0]);
    DLOGF("SLEEPMASK: Allocated Memory: %p\n", &info->allocatedMemory);

    return;
}

/**
* A helper function to display the contents of a ALLOCATED_MEMORY_REGION structure.
*
* @param memoryRegion A pointer to a ALLOCATED_MEMORY_REGION structure.
*/
void PrintAllocatedMemoryRegion(PALLOCATED_MEMORY_REGION memoryRegion) {
    DLOGF("SLEEPMASK: Allocated Memory Region\n");
    DLOGF("SLEEPMASK: \tBaseAddress: %p\n", memoryRegion->AllocationBase);
    DLOGF("SLEEPMASK: \tRegionSize: %lu\n", memoryRegion->RegionSize);
    DLOGF("SLEEPMASK: \tType: %x\n", memoryRegion->Type);
    DLOGF("SLEEPMASK: \tPurpose: %x\n", memoryRegion->Purpose);

    for (int i = 0; i < sizeof(memoryRegion->Sections) / sizeof(ALLOCATED_MEMORY_SECTION); ++i) {
        if (memoryRegion->Sections[i].Label == LABEL_EMPTY || memoryRegion->Sections[i].BaseAddress == NULL) {
            continue;
        }
        DLOGF("SLEEPMASK: \tSection[%d]\n", i);
        DLOGF("SLEEPMASK: \t\tLabel: %lu\n", memoryRegion->Sections[i].Label);
        DLOGF("SLEEPMASK: \t\tBaseAddress: %p\n", memoryRegion->Sections[i].BaseAddress);
        DLOGF("SLEEPMASK: \t\tVirtualSize: %lu\n", memoryRegion->Sections[i].VirtualSize);
        DLOGF("SLEEPMASK: \t\tCurrenProtection: %x\n", memoryRegion->Sections[i].CurrentProtect);
        DLOGF("SLEEPMASK: \t\tPreviousProtect: %x\n", memoryRegion->Sections[i].PreviousProtect);
        DLOGF("SLEEPMASK: \t\tMaskSection: %s\n", memoryRegion->Sections[i].MaskSection ? "TRUE" : "FALSE");
    }

    DLOGF("SLEEPMASK: \tCleanup Information:\n");
    DLOGF("SLEEPMASK: \t\tCleanup: %s\n", memoryRegion->CleanupInformation.Cleanup ? "TRUE" : "FALSE");
    if (memoryRegion->CleanupInformation.AllocationMethod == METHOD_HEAPALLOC) {
        DLOGF("SLEEPMASK: \t\tAllocationMethod: METHOD_HEAPALLOC\n");
        DLOGF("SLEEPMASK: \t\tAdditionalCleanupInformation: HeapHandle: %p\n", memoryRegion->CleanupInformation.AdditionalCleanupInformation.HeapAllocInfo.HeapHandle);
    }
    else if (memoryRegion->CleanupInformation.AllocationMethod == METHOD_MODULESTOMP) {
        DLOGF("SLEEPMASK: \t\tAllocationMethod: METHOD_MODULESTOMP\n");
        DLOGF("SLEEPMASK: \t\tAdditionalCleanupInformation: ModuleHandle: %p\n", memoryRegion->CleanupInformation.AdditionalCleanupInformation.ModuleStompInfo.ModuleHandle);
    }
    else {
        if (memoryRegion->CleanupInformation.AllocationMethod == METHOD_VIRTUALALLOC) {
            DLOGF("SLEEPMASK: \t\tAllocationMethod: METHOD_VIRTUALALLOC\n");
        }
        else if (memoryRegion->CleanupInformation.AllocationMethod == METHOD_NTMAPVIEW) {
            DLOGF("SLEEPMASK: \t\tAllocationMethod: METHOD_NTMAPVIEW\n");
        }
        else if (memoryRegion->CleanupInformation.AllocationMethod == METHOD_UNKNOWN) {
            DLOGF("SLEEPMASK: \t\tAllocationMethod: METHOD_UNKNOWN\n");
        }
        else {
            DLOGF("SLEEPMASK: \t\tAllocationMethod: METHOD_USER_DEFINED (%d)\n", memoryRegion->CleanupInformation.AllocationMethod);
        }
        DLOGF("SLEEPMASK: \t\tAdditionalCleanupInformation: NONE\n");
    }

    return;
}

/**
* A helper function to display the contents of a FUNCTION_CALL structure.
*
* @param entry A pointer to a FUNCTION_CALL structure.
*/
void PrintBeaconGateInfo(PFUNCTION_CALL functionCall) {
    DLOGF("Calling %s\n", winApiArray[functionCall->function]);
    for (int i = 0; i < functionCall->numOfArgs; i++) {
        DLOGF("Arg %d: 0x%p\n", i, (PVOID)functionCall->args[i]);
    }
}

/**
* A helper function to display the contents of a SYSCALL_API_ENTRY structure.
*
* @param name A pointer to a char* containing (human readable) target function name.
* @param entry A pointer to a SYSCALL_API_ENTRY structure.
*/
void DumpApiEntry(const char* name, PSYSCALL_API_ENTRY entry) {
    DLOGF("    %41s: fnAddr: %p jmpAddr : %p sysnum : %lu\n", name, entry->fnAddr, entry->jmpAddr, entry->sysnum);
}

/**
* A helper function to display the contents of a RTL_API structure.
*
* @param name A pointer to a char* containing (human readable) target function name.
* @param entry A pointer to current entry.
*/
void DumpRtlEntry(const char* name, PVOID entry) {
    DLOGF("    %41s: fnAddr: %p\n", name, entry);
}

/**
* A helper function to display the contents of a BEACON_SYSCALLS structure.
*
* @param entry A pointer to a BEACON_SYSCALLS structure.
*/
void PrintSyscallInfo(PBEACON_SYSCALLS info) {
    if (info == NULL) {
        return;
    }

    DLOG("SLEEPMASK: Printing Syscall Info:\n");
    DumpApiEntry("ntAllocateVirtualMemory", &info->syscalls.ntAllocateVirtualMemory);
    DumpApiEntry("ntProtectVirtualMemory", &info->syscalls.ntProtectVirtualMemory);
    DumpApiEntry("ntFreeVirtualMemory", &info->syscalls.ntFreeVirtualMemory);
    DumpApiEntry("ntGetContextThread", &info->syscalls.ntGetContextThread);
    DumpApiEntry("ntSetContextThread", &info->syscalls.ntSetContextThread);
    DumpApiEntry("ntResumeThread", &info->syscalls.ntResumeThread);
    DumpApiEntry("ntCreateThreadEx", &info->syscalls.ntCreateThreadEx);
    DumpApiEntry("ntOpenProcess", &info->syscalls.ntOpenProcess);
    DumpApiEntry("ntOpenThread", &info->syscalls.ntOpenThread);
    DumpApiEntry("ntClose", &info->syscalls.ntClose);
    DumpApiEntry("ntCreateSection", &info->syscalls.ntCreateSection);
    DumpApiEntry("ntMapViewOfSection", &info->syscalls.ntMapViewOfSection);
    DumpApiEntry("ntUnmapViewOfSection", &info->syscalls.ntUnmapViewOfSection);
    DumpApiEntry("ntQueryVirtualMemory", &info->syscalls.ntQueryVirtualMemory);
    DumpApiEntry("ntDuplicateObject", &info->syscalls.ntDuplicateObject);
    DumpApiEntry("ntReadVirtualMemory", &info->syscalls.ntReadVirtualMemory);
    DumpApiEntry("ntWriteVirtualMemory", &info->syscalls.ntWriteVirtualMemory);
    DumpApiEntry("ntReadFile", &info->syscalls.ntReadFile);
    DumpApiEntry("ntWriteFile", &info->syscalls.ntWriteFile);
    DumpApiEntry("ntCreateFile", &info->syscalls.ntCreateFile);
    DumpApiEntry("ntQueueApcThread", &info->syscalls.ntQueueApcThread);
    DumpApiEntry("ntCreateProcess", &info->syscalls.ntCreateProcess);
    DumpApiEntry("ntOpenProcessToken", &info->syscalls.ntOpenProcessToken);
    DumpApiEntry("ntTestAlert", &info->syscalls.ntTestAlert);
    DumpApiEntry("ntSuspendProcess", &info->syscalls.ntSuspendProcess);
    DumpApiEntry("ntResumeProcess", &info->syscalls.ntResumeProcess);
    DumpApiEntry("ntQuerySystemInformation", &info->syscalls.ntQuerySystemInformation);
    DumpApiEntry("ntQueryDirectoryFile", &info->syscalls.ntQueryDirectoryFile);
    DumpApiEntry("ntSetInformationProcess", &info->syscalls.ntSetInformationProcess);
    DumpApiEntry("ntSetInformationThread", &info->syscalls.ntSetInformationThread);
    DumpApiEntry("ntQueryInformationProcess", &info->syscalls.ntQueryInformationProcess);
    DumpApiEntry("ntQueryInformationThread", &info->syscalls.ntQueryInformationThread);
    DumpApiEntry("ntOpenSection", &info->syscalls.ntOpenSection);
    DumpApiEntry("ntAdjustPrivilegesToken", &info->syscalls.ntAdjustPrivilegesToken);
    DumpApiEntry("ntDeviceIoControlFile", &info->syscalls.ntDeviceIoControlFile);
    DumpApiEntry("ntWaitForMultipleObjects", &info->syscalls.ntWaitForMultipleObjects);

    DLOG("\nSLEEPMASK: Printing Run Time Library Functions:\n");
    DumpRtlEntry("rtlDosPathNameToNtPathNameUWithStatusAddr", info->rtls.rtlDosPathNameToNtPathNameUWithStatusAddr);
    DumpRtlEntry("rtlFreeHeapAddr", info->rtls.rtlFreeHeapAddr);
    DumpRtlEntry("rtlGetProcessHeapAddr", info->rtls.rtlGetProcessHeapAddr);
}
#endif
