#include <windows.h>
#include "base\helpers.h"

/**
 * For the debug build we want:
 *   a) Include the mock-up layer
 *   b) Undefine DECLSPEC_IMPORT since the mocked Beacon API
 *      is linked against the the debug build.
 */
#ifdef _DEBUG
#include "base\mock.h"
#undef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT
#endif

extern "C" {
#include "beacon.h"
#include "library/stdlib.cpp"
    DFR(KERNEL32, GetLastError);
    #define GetLastError KERNEL32$GetLastError

    DFR(KERNEL32, CreateProcessA);
    #define CreateProcessA KERNEL32$CreateProcessA

    DFR(KERNEL32, CreateMutexA);
    #define CreateMutexA KERNEL32$CreateMutexA

    DFR(KERNEL32, CreateRemoteThread);
    #define CreateRemoteThread KERNEL32$CreateRemoteThread

    DFR(KERNEL32, CreateThread);
    #define CreateThread KERNEL32$CreateThread

    DFR(KERNEL32, CreateFileMappingA);
    #define CreateFileMappingA KERNEL32$CreateFileMappingA

    DFR(KERNEL32, MapViewOfFile);
    #define MapViewOfFile KERNEL32$MapViewOfFile

    void go(char* args, int len) {
        /**
        * These are unit tests for Beacon's BOF System Call API.
        * You can enable `stage { beacon_gate { Core } };` in
        * your malleable C2 profile and use the following BOF
        * to test your custom call gate.
        * `inline-execute unit-test-bof.x64.o`
        *  For ref: https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/beacon-object-files_bof-c-api.htm
        */
        // Test 1: Local memory allocation tests.
        PVOID pMemoryTest1 = NULL;
        size_t retValue = 0;
        DWORD oldProtection = 0;
        MEMORY_BASIC_INFORMATION mbi;
        _memset(&mbi, 0, sizeof(mbi));

        // Test 2: Remote memory allocation tests.
        PVOID pMemoryTest2 = NULL;
        char cmdStr[] = "cmd.exe";
        HANDLE hProcess = INVALID_HANDLE_VALUE;
        char bufferIn[] = "Hello!";
        char bufferOut[10];
        DWORD threadId = 0;
        LPVOID exitProcPtr = NULL;

        STARTUPINFOA si;
        _memset(&si, 0, sizeof(si));
        PROCESS_INFORMATION pi;
        _memset(&pi, 0, sizeof(pi));

        // Test 3: Thread tests.
        HANDLE hThread = INVALID_HANDLE_VALUE;
        LPVOID loadLib = NULL;
        LPVOID exitThreadPtr = NULL;
        LPVOID rtlUserThread = NULL;
        DWORD suspendCount = 0;
        CONTEXT ctx;
        _memset(&ctx, 0, sizeof(ctx));

        // Test 4 : File mapping Tests.
        HANDLE hFile = INVALID_HANDLE_VALUE;
        PVOID pFileAddress = NULL;

        // Test 5: Duplicate handle test.
        HANDLE hMutex, hMutexDup = INVALID_HANDLE_VALUE;

        /**
        * Test 1. Allocate some memory locally with masking enabled.
        */
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Running BeaconGate unit tests....");
        BeaconPrintf(CALLBACK_OUTPUT, "=====================================");
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Test 1: Memory APIs Local");
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Testing BeaconVirtualAlloc (local) ");
        pMemoryTest1 = BeaconVirtualAlloc(NULL, 8, MEM_COMMIT, PAGE_READWRITE);
        if (pMemoryTest1 == NULL) {
            BeaconPrintf(CALLBACK_OUTPUT, "Test Failed Virtual Alloc: 0x%p", pMemoryTest1);
            BeaconPrintf(CALLBACK_ERROR, "Error: %i", GetLastError());
            return;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "Allocated local memory at: 0x%p", pMemoryTest1);

        // Query the newly allocated memory.
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Testing BeaconVirtualQuery (local) ");
        BeaconPrintf(CALLBACK_OUTPUT, "PRE CALL: mbi.BaseAddress: 0x%p", mbi.BaseAddress);
        BeaconPrintf(CALLBACK_OUTPUT, "PRE CALL: mbi.AllocationProtect: %d", mbi.AllocationProtect);
        BeaconPrintf(CALLBACK_OUTPUT, "PRE CALL: mbi.Protect: %d", mbi.Protect);
        retValue = BeaconVirtualQuery(pMemoryTest1, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
        if (retValue == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "Test Failed Virtual Query: %d", retValue);
            BeaconPrintf(CALLBACK_ERROR, "Error: %i", GetLastError());
            return;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "BeaconVirtualQuery ret value: %d", retValue);
        BeaconPrintf(CALLBACK_OUTPUT, "POST CALL: mbi.BaseAddress: 0x%p", mbi.BaseAddress);
        BeaconPrintf(CALLBACK_OUTPUT, "POST CALL: mbi.AllocationProtect: %d", mbi.AllocationProtect);
        BeaconPrintf(CALLBACK_OUTPUT, "POST CALL: mbi.Protect: %d", mbi.Protect);

        // Change the protection.
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Testing BeaconVirtualProtect (local) ");
        BeaconPrintf(CALLBACK_OUTPUT, "BeaconVirtualProtect PRE old protection value: %d", oldProtection);
        retValue = BeaconVirtualProtect(pMemoryTest1, 8, PAGE_READONLY, &oldProtection);
        if (retValue == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "Test Failed Virtual Protect: %d", retValue);
            BeaconPrintf(CALLBACK_ERROR, "Error: %i", GetLastError());
            return;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "BeaconVirtualProtect ret value: %d", retValue);
        if (oldProtection != PAGE_READWRITE) {
            BeaconPrintf(CALLBACK_OUTPUT, "Test Failed Virtual Protect: %d", retValue);
            BeaconPrintf(CALLBACK_ERROR, "Error: %i", GetLastError());
            return;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "BeaconVirtualProtect POST old protection value: %d", oldProtection);

        // Check again.
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Testing BeaconVirtualQuery (local) again: ");
        retValue = BeaconVirtualQuery(pMemoryTest1, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
        if (retValue == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "Test Failed Virtual Query: %d", retValue);
            BeaconPrintf(CALLBACK_ERROR, "Error: %i", GetLastError());
            return;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "BeaconVirtualQuery ret value: %d", retValue);
        if (mbi.Protect != PAGE_READONLY) {
            BeaconPrintf(CALLBACK_OUTPUT, "Test Failed Virtual Query: %d", retValue);
            BeaconPrintf(CALLBACK_ERROR, "Error: %i", GetLastError());
            return;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "mbi.Protect: %d", mbi.Protect);

        // Free the memory.
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Testing BeaconVirtualFree");
        retValue = BeaconVirtualFree(pMemoryTest1, 8, MEM_DECOMMIT);
        if (retValue == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "Test Failed Virtual Free: %d", retValue);
            BeaconPrintf(CALLBACK_ERROR, "Error: %i", GetLastError());
            return;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "BeaconVirtualFree ret value: %d", retValue);

        /**
        * Test 2. Allocate/write/read remote memory.
        */
        // Create a process.
        BeaconPrintf(CALLBACK_OUTPUT, "=====================================");
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Test 2: Memory APIs Remote");
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Creating a dummy cmd.exe process...");
        retValue = CreateProcessA(NULL,   // No module name (use command line)
            cmdStr,                       // Command line
            NULL,                         // Process handle not inheritable
            NULL,                         // Thread handle not inheritable
            FALSE,                        // Set handle inheritance to FALSE
            0,                            // No creation flags
            NULL,                         // Use parent's environment block
            NULL,                         // Use parent's starting directory
            &si,                          // Pointer to STARTUPINFO structure
            &pi);                         // Pointer to PROCESS_INFORMATION structure
        if (retValue == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "Test failed to create a process: %d", retValue);
            BeaconPrintf(CALLBACK_ERROR, "Error: %i", GetLastError());
            return;
        }

        // Close handle returned in PROCESS_INFO.
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Testing BeaconCloseHandle");
        retValue = BeaconCloseHandle(pi.hProcess);
        if (retValue == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "Test Failed Close Handle: %d", retValue);
            BeaconPrintf(CALLBACK_ERROR, "Error: %i", GetLastError());
            return;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "Close Handle ret value: %d", retValue);

        // Open a new handle to process via pid.
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Testing BeaconOpenProcess");
        hProcess = BeaconOpenProcess(PROCESS_ALL_ACCESS, FALSE, pi.dwProcessId);
        if (hProcess == NULL) {
            BeaconPrintf(CALLBACK_OUTPUT, "Test Failed OpenProcess");
            BeaconPrintf(CALLBACK_ERROR, "Error: %i", GetLastError());
            return;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "OpenProcess handle value: 0x%p", hProcess);

        // Alloc remote memory in spawned dummy process and assert we successfully allocated memory.
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Testing BeaconVirtualAllocEx");
        pMemoryTest2 = BeaconVirtualAllocEx(hProcess, NULL, 8, MEM_COMMIT, PAGE_READWRITE);
        if (pMemoryTest2 == NULL) {
            BeaconPrintf(CALLBACK_OUTPUT, "Test Failed Virtual Alloc remote: %p", pMemoryTest2);
            BeaconPrintf(CALLBACK_ERROR, "Error: %i", GetLastError());
            return;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "Allocated remote memory at: 0x%p", pMemoryTest2);

        // Write memory.
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Testing BeaconWriteProcessMemory");
        BeaconPrintf(CALLBACK_OUTPUT, "Buffer to be written to remote process: %s", bufferIn);
        retValue = BeaconWriteProcessMemory(hProcess, pMemoryTest2, &bufferIn, sizeof(bufferIn), NULL);
        if (retValue == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "Test Failed write process memory: %d", retValue);
            BeaconPrintf(CALLBACK_ERROR, "Error: %i", GetLastError());
            return;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "BeaconWriteProcessMemory ret value: %d", retValue);

        // Read remote memory.
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Testing BeaconReadProcessMemory");
        retValue = BeaconReadProcessMemory(hProcess, pMemoryTest2, bufferOut, sizeof(bufferOut), NULL);
        if (retValue == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "Test Failed read process memory: %d", retValue);
            BeaconPrintf(CALLBACK_ERROR, "Error: %i", GetLastError());
            return;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "BeaconReadProcessMemory ret value: %d", retValue);
        BeaconPrintf(CALLBACK_OUTPUT, "BeaconReadProcessMemory buffer: %s", bufferOut);

        // Change perms for remote memory.
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Testing BeaconVirtualProtectEx");
        retValue = BeaconVirtualProtectEx(hProcess, pMemoryTest2, 8, PAGE_READONLY, &oldProtection);
        if (retValue == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "Test Failed virtual protect: %d", retValue);
            BeaconPrintf(CALLBACK_ERROR, "Error: %i", GetLastError());
            return;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "BeaconVirtualProtect ret value: %d", retValue);

        // Create Remote Thread to terminate process.
        BeaconPrintf(CALLBACK_OUTPUT, "[+] CreateRemoteThread to terminate process...");
        exitProcPtr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "ExitProcess");
        hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)exitProcPtr, NULL, 0, &threadId);
        if (hThread == NULL) {
            BeaconPrintf(CALLBACK_OUTPUT, "CreateRemoteThread failed");
            BeaconPrintf(CALLBACK_ERROR, "Error: %i", GetLastError());
            return;
        }

        /**
        * Test 3: Thread tests.
        */
        // Spawn local thread.
        BeaconPrintf(CALLBACK_OUTPUT, "=====================================");
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Test 3: Thread API tests");
        hThread = NULL;
        threadId = 0;
        loadLib = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Creating local suspended thread...");
        hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)loadLib, NULL, CREATE_SUSPENDED, &threadId);
        if (hThread == NULL) {
            BeaconPrintf(CALLBACK_OUTPUT, "CreateThread failed");
            BeaconPrintf(CALLBACK_ERROR, "Error: %i", GetLastError());
            return;
        }

        // Close returned handle.
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Testing BeaconCloseHandle");
        retValue = BeaconCloseHandle(hThread);
        if (retValue == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "Closing thread handle failed: %d", retValue);
            BeaconPrintf(CALLBACK_ERROR, "Error: %i", GetLastError());
            return;
        }

        // Open thread by tid.
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Testing BeaconOpenThread");
        hThread = NULL;
        hThread = BeaconOpenThread(THREAD_ALL_ACCESS, FALSE, threadId);
        if (hThread == NULL) {
            BeaconPrintf(CALLBACK_OUTPUT, "Opening thread failed");
            BeaconPrintf(CALLBACK_ERROR, "Error: %i", GetLastError());
            return;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "BeaconOpenThread handle value: 0x%p", hThread);

        // Get thread context.
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Testing BeaconGetThreadContext");
#ifdef _WIN64
        BeaconPrintf(CALLBACK_OUTPUT, "Ctx.rip pre: 0x%p", ctx.Rip);
#elif _WIN32
        BeaconPrintf(CALLBACK_OUTPUT, "Ctx.eip pre: 0x%p", ctx.Eip);
#endif
        ctx.ContextFlags = CONTEXT_CONTROL;
        retValue = BeaconGetThreadContext(hThread, &ctx);
        if (retValue == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "GetThreadContext failed: %d", retValue);
            BeaconPrintf(CALLBACK_ERROR, "Error: %i", GetLastError());
            return;
        }
        rtlUserThread = (LPVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlUserThreadStart");
#ifdef _WIN64
        if (ctx.Rip != (DWORD64)rtlUserThread) {
#elif _WIN32
        if (ctx.Eip != (DWORD)rtlUserThread) {
#endif
            BeaconPrintf(CALLBACK_OUTPUT, "GetThreadContext failed: %d", retValue);
            BeaconPrintf(CALLBACK_ERROR, "Error: %i", GetLastError());
            return;
        }
#ifdef _WIN64
        BeaconPrintf(CALLBACK_OUTPUT, "Ctx.rip post: 0x%p", ctx.Rip);
#elif _WIN32
        BeaconPrintf(CALLBACK_OUTPUT, "Ctx.eip post: 0x%p", ctx.Eip);
#endif

        // Set thread context.
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Testing BeaconSetThreadContext");
        exitThreadPtr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "ExitThread");
#ifdef _WIN64
        ctx.Rip = (DWORD64)exitThreadPtr;
        ctx.Rcx = 0;
#elif _WIN32
        ctx.Eip = (DWORD)exitThreadPtr;
        ctx.Ecx = 0;
#endif
        ctx.ContextFlags = CONTEXT_CONTROL;
        retValue = BeaconSetThreadContext(hThread, &ctx);
        if (retValue == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "Setting Thread Context failed: %d", retValue);
            BeaconPrintf(CALLBACK_ERROR, "Error: %i", GetLastError());
            return;
        }

        // Resume thread.
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Testing BeaconResumeThread");
        suspendCount = BeaconResumeThread(hThread);
        if (suspendCount == -1) {
            BeaconPrintf(CALLBACK_OUTPUT, "Resuming Thread failed: %d", suspendCount);
            BeaconPrintf(CALLBACK_ERROR, "Error: %i", GetLastError());
            return;
        }

        /**
        * Test 4: Create File Mapping tests.
        */

        // Create a new file mapping.
        BeaconPrintf(CALLBACK_OUTPUT, "=====================================");
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Test 4: File Mapping APIs");
        BeaconPrintf(CALLBACK_OUTPUT, "[+] CreateFileMapping...");
        hFile = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, 1000, NULL);
        if (hFile == NULL) {
            BeaconPrintf(CALLBACK_OUTPUT, "CreateFileMapping failed");
            BeaconPrintf(CALLBACK_ERROR, "Error: %i", GetLastError());
            return;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "CreateFileMapping handle value: 0x%p", hFile);

        // Map it.
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Mapping view of file...");
        pFileAddress = MapViewOfFile(hFile, FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE, 0, 0, 0);
        if (pFileAddress == NULL) {
            BeaconPrintf(CALLBACK_OUTPUT, "Mapping view of file failed: %p", pFileAddress);
            BeaconPrintf(CALLBACK_ERROR, "Error: %i", GetLastError());
            return;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "MapViewOfFile ptr: 0x%p", pFileAddress);

        // Unmap file mapping.
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Testing BeaconUnmapViewOfFile");
        retValue = BeaconUnmapViewOfFile(pFileAddress);
        if (retValue == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "Unmap view of file failed: %d", retValue);
            BeaconPrintf(CALLBACK_ERROR, "Error: %i", GetLastError());
            return;
        }

        /**
        * Test 5: Duplicate Handle tests.
        */
        BeaconPrintf(CALLBACK_OUTPUT, "=====================================");
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Test 5: Duplicating a handle");
        hMutex = CreateMutex(NULL, FALSE, NULL);
        retValue = BeaconDuplicateHandle((HANDLE)-1, hMutex, (HANDLE)-1, &hMutexDup, 0, FALSE, DUPLICATE_SAME_ACCESS);
        if (retValue == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "Duplicate Handle failed: %d", retValue);
            BeaconPrintf(CALLBACK_ERROR, "Error: %i", GetLastError());
            return;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "BeaconDuplicateHandle succeeded: %d", retValue);
        BeaconPrintf(CALLBACK_OUTPUT, "Duplicated Handle: 0x%p", hMutexDup);

        // If we got here, everything passed.
        BeaconPrintf(CALLBACK_OUTPUT, "[+] ALL TESTS PASSED");
        return;
    }
}

// Define a main function for the bebug build
#if defined(_DEBUG) && !defined(_GTEST)

int main(int argc, char* argv[]) {
    // Run BOF's entrypoint
    // To pack arguments for the bof use e.g.: bof::runMocked<int, short, const char*>(go, 6502, 42, "foobar");
    bof::runMocked<>(go);
    return 0;
}

/**
* The Googletest framework is currently not compatible with clang.
* Therefore Sleepmask-vs does not provide support for unit tests.
*/
#elif defined(_GTEST)
#endif
