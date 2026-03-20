#include <windows.h>
#include "..\library\retaddrspoofing.h"
#include "..\sleepmask-vs.h"
#include "..\base\helpers.h"
#include "..\debug.h"

extern PRET_SPOOF_INFO gRetSpoofInfo;

/**
* Find a specific byte pattern (gadget) in a module's .text section.
*
* Note: We search the .text section to make sure the gadget is RX.
*
* @param moduleHandle A handle to the specified module.
* @param gadget The required hex gadget.
* @param gadgetLength The size of target gadget.
*
* Returns PVOID to gadget.
*/
PVOID FindGadget(char* moduleHandle, const char* gadget, size_t gadgetLength) {
    PVOID pGadget = NULL;
    PIMAGE_NT_HEADERS ntHeader = NULL;
    PIMAGE_SECTION_HEADER sectionHeader = NULL;
    DWORD numberOfSections = 0;

    // Sanity check incoming ptr.
    if (!moduleHandle) {
        goto Cleanup;
    }

    // Determine the location of the NT header.
    ntHeader = (PIMAGE_NT_HEADERS)(moduleHandle + ((PIMAGE_DOS_HEADER)moduleHandle)->e_lfanew);

    // Find the section header.
    sectionHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)&ntHeader->OptionalHeader + ntHeader->FileHeader.SizeOfOptionalHeader);

    // Iterate through all sections.
    numberOfSections = ntHeader->FileHeader.NumberOfSections;
    while (numberOfSections--) {
        // Find the .text section.
        if (_memcmp((char*)sectionHeader->Name, ".text", 5) == 0) {
            for (int i = 0; i < sectionHeader->Misc.VirtualSize; i++) {
                char* location = (char*)moduleHandle + sectionHeader->VirtualAddress + i;
                if (_memcmp(location, gadget, gadgetLength) == 0) {
                    pGadget = (PVOID)location;
                    break;
                }
            }
            goto Cleanup;
        }
        // Get the VA of the next section.
        sectionHeader++;
    }

Cleanup:
    return pGadget;
}

/**
* Find the specified gadgets and store them for future use.
*
* @param A pointer to a GADGETS structure.
*
* @return BOOL indicating success.
*/
BOOL FindGadgets(PGADGETS gadgets)
{
    DFR_LOCAL(KERNEL32, GetModuleHandleA);

    PVOID wininetGadget = NULL;
    PVOID kernel32Gadget = NULL;
    BOOL bSuccess = FALSE;

#ifdef _WIN64
    DLOGF("SLEEPMASK: Searching for gadget in WinINet.dll...\n");
    wininetGadget = FindGadget((char*)GetModuleHandleA("wininet.dll"), "\xff\x23", 2); // jmp [rbx]
    if (!wininetGadget){
        DLOGF("SLEEPMASK: Failed to find gadget in WinINet\n");
        goto Cleanup;
    }

    DLOGF("SLEEPMASK: Searching for gadget in Kernel32.dll...\n");
    kernel32Gadget = FindGadget((char*)GetModuleHandleA("Kernel32.dll"), "\xff\x23", 2); // jmp [rbx]
    if (!kernel32Gadget) {
        DLOGF("SLEEPMASK: Failed to find gadget in Kernel32\n");
        goto Cleanup;
    }
#elif _WIN32
    DLOGF("SLEEPMASK: Searching for gadget in WinINet.dll...\n");
    wininetGadget = FindGadget((char*)GetModuleHandleA("wininet.dll"), "\xff\x23", 2); // jmp [ebx]
    if (!wininetGadget) {
        DLOGF("SLEEPMASK: Failed to find gadget in WinINet\n");
        goto Cleanup;
    }

    DLOGF("SLEEPMASK: Searching for gadget in Kernel32.dll...\n");
    kernel32Gadget = FindGadget((char*)GetModuleHandleA("Kernel32.dll"), "\xff\x23", 2); // jmp [ebx]
    if (!kernel32Gadget) {
        DLOGF("SLEEPMASK: Failed to find gadget in Kernel32\n");
        goto Cleanup;
    }
#endif
    gadgets->WinInet = wininetGadget;
    DLOGF("SLEEPMASK: Found gadget in WinInet.dll: 0x%p\n", wininetGadget);
    gadgets->Kernel32 = kernel32Gadget;
    DLOGF("SLEEPMASK: Found gadget in Kernel32.dll: 0x%p\n", kernel32Gadget);
    bSuccess = TRUE;

Cleanup:
    return bSuccess;
}

/**
*  Set the required gadget before ret address spoofing.
*
* Note: Here we ensure that a call to a function in WinINet will
* return to WinINet.dll and a call to a function in Kernel32 will
* return to Kernel32.dll.
*
* @param PFUNCTION_CALL A pointer to FUNCTION_CALL struct.
* @param PGADGETS A pointer to a GADGETS struct.
* @param PRET_SPOOF_INFO A pointer to a RET_SPOOF_INFO struct.
*/
void SetupFunctionCall(PFUNCTION_CALL functionCall, PGADGETS gadgets, PRET_SPOOF_INFO retSpoofInfo) {
    if (functionCall->function == INTERNETOPENA || functionCall->function == INTERNETCONNECTA) {
        retSpoofInfo->RopGadget = gadgets->WinInet;
        retSpoofInfo->TargetFunction = functionCall->functionPtr;
    }
    else {
        retSpoofInfo->RopGadget = gadgets->Kernel32;
        retSpoofInfo->TargetFunction = functionCall->functionPtr;
    }

    /**
    * Once we have the real target function stored in the RET_SPOOF_INFO struct
    * we can overwrite the original function ptr so everything is
    * routed through the default BeaconGate code.
    */
#ifdef _WIN64
    functionCall->functionPtr = (PVOID)&SpoofReturnAddressx64;
#elif _WIN32
    functionCall->functionPtr = (PVOID)&SpoofReturnAddressx86;
#endif
}

/**
*  A modified version of Namaszo's X64 Return Address Spoofer.
*
* Ref: https://www.unknowncheats.me/forum/anti-cheat-bypass/268039-x64-return-address-spoofing-source-explanation.html
* Ref: https://github.com/kyleavery/AceLdr

* @param (...) means this asm stub can be called with a variable number of args.
*
* Returns a ULONG_PTR with the result from the target function.
*/
#ifdef _WIN64
// This attribute ensures the compiler generates code without prolog / epilog code.
// Note: This attribute causes an intellisense error as it cannot parse the clang inline asm.
__attribute__((naked))
ULONG_PTR SpoofReturnAddressx64(...) {
    __asm {
        pop r11                   // Save the real return address to r11
        mov rax, gRetSpoofInfo    // Get ptr to global gRetSpoofInfo struct
        mov r10, [rax]            // Store the trampoline gadget in r10 (gRetSpoofInfo->RopGadget / +0)
        push r10                  // Push trampoline gadget to stack
        mov r10, [rax + 0x8]      // Save target function into r10 (gRetSpoofInfo->TargetFunction / +8)
        mov [rax + 0x18], r11     // Save the original return address to gRetSpoofInfo->OriginalRetAddress / +24
        mov [rax + 0x10], rbx     // Store the original value of rbx in gRetSpoofInfo->RestoreRegister
        
        lea rbx, [rip + 0x9]      // Load the effective address of our cleanup code (x64 allows rip relative addressing - sub rsp, 0x8)
        mov [rax], rbx            // Save ptr to clean up in gRetSpoofInfo->RopGadget / +0 (this will overwrite original gadget)
        mov  rbx, rax             // Set rbx to gRetSpoofInfo, the jmp [rbx] gadget will dereference and jump to cleanup code
        jmp r10                   // Execute the target function

        push [rbx + 0x18]         // Need to push original ret address to fix stack (gRetSpoofInfo->OriginalRetAddress / +24)
        mov rbx, [rbx + 0x10]     // Restore the original rbx value from gRetSpoofInfo->RestoreRegister / +16)
        ret
    }
}

/**
*  A *stdcall* x86 return address spoofer.
*
* Ref: https://github.com/danielkrupinski/x86RetSpoof
* Ref: https://medium.com/@fsx30/faking-your-return-address-through-gadget-and-rop-65cc6239599
*
* Note: WINAPIs are stdcall, hence this implementation assumes the target function will clean the stack.
* It will not work with other x86 calling conventions without modification.
*
* @param (...) means this asm stub can be called with a variable number of args.
*
* Returns a ULONG_PTR with the result from the target function.
*/
#elif _WIN32
__attribute__((naked))
ULONG_PTR SpoofReturnAddressx86(...) {
    __asm {
        mov eax, gRetSpoofInfo      // Get ptr to gRetSpoofInfo
        mov [eax], ebx              // Backup original ebx instruction to gRetSpoofInfo->OriginalEbx (+0)
        pop dword ptr [eax + 12]    // Save the original return address to gRetSpoofInfo->OriginalReturnAddress (+12)

        lea ebx, [Fixup]            // Load the address of the Fixup code into ebp
        mov [eax + 16], ebx         // Save the address of the Fixup code into gRetSpoofInfo->Fixup  (+16)
        lea ebx, [eax + 16]         // Load the address of gRetSpoofInfo->Fixup into ebx

        push dword ptr [eax + 4]    // Push gadget (jmp [ebx]) on to the stack from gRetSpoofInfo->RopGadget (+4)
        jmp [eax + 8]               // Execute the target function from gRetSpoofInfo->TargetFunction (+8)

    Fixup:                          // Callee will clean stack
        push [ebx - 4]              // Push the original return address back on to the stack from gRetSpoofInfo->OriginalReturnAddress (-4 offset from Fixup)
        mov ebx, [ebx - 16]         // Restore the original ebx instruction from gRetSpoofInfo->OriginalEbx (-16 offset from Fixup)
        ret                         // Return
    }
}
#endif
