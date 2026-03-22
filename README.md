# Threadpool Sleepmask

This repository adds `threadpool-sleepmask`, an advanced sleepmask variant to [sleepmask-vs](https://github.com/Cobalt-Strike/sleepmask-vs).
It combines Thread Pool Timer sleep obfuscation with Draugr stack spoofing and
Ekko-style self-masking to produce a beacon and sleepmask with low-observability, bypassing
[pe-sieve](https://github.com/hasherezade/pe-sieve) while sleeping.

---

### Cloning the repo:

Sleepmask-VS includes BOF-VS as a submodule to simplify maintenance and development. Therefore, `git clone` will not download all of the files required to compile the project. `git submodule init` and `git submodule update` are also required to initialize the repository and fetch BOF-VS.

Alternatively, `git clone --recurse-submodules <sleepmask-vs>` will instruct Git to initialize and fetch BOF-VS as part of cloning Sleepmask-VS.

Note: If you download Sleepmask-VS as a zip, you will need to do the following to correctly configure the submodule dependency:
```
extract zip
git init
rm -r bof-vs
git submodule add https://github.com/cobalt-strike/bof-vs
```

### How it works

During a sleep cycle the sleepmask encrypts **both** the beacon memory regions
(sections + heap records) **and** its own `.text` section. Because the sleepmask
code itself is encrypted and marked `PAGE_READWRITE`, tools like pe-sieve that
scan for executable shellcode or in-memory PE anomalies find nothing recognizable
in the process — the implant is completely masked at rest.

The implementation chains seven `NtContinue`-driven timer callbacks on a dedicated
timer thread (`WT_EXECUTEINTIMERTHREAD`), each resuming a pre-built `CONTEXT` that
drives the next step:

| Step | Function | Purpose |
|------|----------|---------|
| 0 | `WaitForSingleObjectEx` | Gate — blocks until the main thread signals `EvntStart` |
| 1 | `VirtualProtect` | Mark sleepmask `.text` as `PAGE_READWRITE` |
| 2 | `SystemFunction032` | RC4-encrypt sleepmask code (advapi32) |
| 3 | `WaitForSingleObjectEx` | **The actual sleep** — waits on `NtCurrentProcess` for the requested duration |
| 4 | `SystemFunction032` | RC4-decrypt sleepmask code |
| 5 | `VirtualProtect` | Restore sleepmask `.text` to `PAGE_EXECUTE_READ` |
| 6 | `SetEvent` | Signal `EvntEnd` — wake the main thread |

Key design details:

* **Race-condition-free context capture** — `RtlCaptureContext` runs as a timer
  callback on the timer thread itself. The main thread waits on `EvntTimer` until
  the capture is complete before building the NtContinue chain.
* **Atomic chain trigger** — `NtSignalAndWaitForSingleObject` atomically signals
  `EvntStart` (unblocking step 0) and waits on `EvntEnd` (blocking until step 6).
  This call is routed through **Draugr stack spoofing** so the main thread's call
  stack appears clean while blocked in the kernel wait.
* **CFG compatibility** — Timer callback targets (`NtContinue`, `RtlCaptureContext`,
  `SetEvent`) are registered as valid CFG indirect call targets via
  `SetProcessValidCallTargets` on CFG-enabled processes.
* **Clean timer dispatch flow** — NtContinue target functions return naturally to
  the timer dispatch code (no `NtTestAlert` trampolining), preserving the thread
  pool's internal bookkeeping.
* **Blocking cleanup** — `RtlDeleteTimerQueueEx(INVALID_HANDLE_VALUE)` ensures
  the timer thread has fully terminated before queue structures are freed.
* **Graceful fallback** — If `advapi32.dll` or any required function pointer
  cannot be resolved, the sleepmask falls back to a basic `TpAllocTimer` sleep
  that still masks/unmasks beacon memory.

For all non-sleep API calls intercepted by BeaconGate (e.g. network I/O, handle
operations), Draugr stack spoofing is applied so every proxied call has a
synthetic call stack resembling `BaseThreadInitThunk → RtlUserThreadStart`.

### Cross-Compiling with CMake (Linux)

As an alternative to building on Windows with Visual Studio, Sleepmask-VS can
be cross-compiled on Linux using Clang and the MinGW-w64 toolchain. This
produces the same COFF `.o` files that the Windows build generates.

**Prerequisites:**
* `clang` (tested with 18.x)
* MinGW-w64 headers (`x86_64-w64-mingw32` and `i686-w64-mingw32`)
* `cmake` (3.20+)
* `python3` (for `boflint`)

**Building:**
```bash
# Initialize submodules (if not already done)
git submodule update --init

# Build x64 release objects
cmake -B build-x64 -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-win-x64.cmake
cmake --build build-x64

# Build x86 release objects
cmake -B build-x86 -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-win-x86.cmake
cmake --build build-x86
```

Output files are placed in `x64/Release/*.x64.o` and `Release/*.x86.o`,
matching the layout expected by `sleepmask.cna`. The `boflint` linter runs
automatically on each `.o` file as a post-build step.

To use Sleepmask-VS:
1. Enable the Sleepmask (`stage.sleep_mask "true";`)
2. Enable required BeaconGate functions (`stage.beacon_gate { ... }`)
3. Compile Sleepmask-VS
4. Load `sleepmask.cna` in the Script Manager. This will create a new menu item called Sleepmask
5. Select the required Sleepmask from the drop down menu item
6. Save the configuration
7. Export a Beacon

### pe-sieve evasion

[pe-sieve](https://github.com/hasherezade/pe-sieve) scans a target process for
in-memory implant indicators: injected/replaced PEs, executable shellcode regions,
hooks, and other anomalies. During sleep, the threadpool-sleepmask defeats this
by:

1. Encrypting the beacon's PE sections and heap records (RC4)
2. Encrypting its own executable `.text` section (RC4 via `SystemFunction032`)
3. Changing its own memory protection to `PAGE_READWRITE` (non-executable)

With the implant's code encrypted and non-executable, pe-sieve's shellcode and
PE-image scanners find no actionable artifacts. When the sleep expires, the
timer chain decrypts and restores everything before the beacon resumes execution.

## Sleepmask-VS

In addition to `threadpool-sleepmask`, this repository contains sleepmask examples built on top of the Beacon 
Object File Visual Studio template ([BOF-VS](https://github.com/Cobalt-Strike/bof-vs)).
Sleepmask-VS is intended to function as a library, however, to support development efforts,
we have included the examples described below.

**Note**: This repository assumes familiarity with BOF-VS. The BOF-VS project README contains
information about the Dynamic Function Resolution (DFR) macros and helper functions used
throughout this project.

## Other Sleepmask Variants

* `draugr-sleepmask` — BeaconGate example using return address spoofing and a
  spoofed stack frame to create a legitimate-looking call stack
  ([Draugr](https://github.com/NtDallas/Draugr))
* `retaddrspoofing-sleepmask` — BeaconGate example that spoofs the return
  address of proxied WinAPIs
* `indirectsyscalls-sleepmask` — BeaconGate example using indirect syscalls
  for proxied WinAPIs
* `default-sleepmask` — Minimal baseline sleepmask

For more information about the template used by this repository, see the original [sleepmask-vs](https://github.com/Cobalt-Strike/sleepmask-vs).

### Acknowledgments

* [MalDev Academy](https://maldevacademy.com/) — The `threadpool-sleepmask` self-masking
  implementation is based on MalDev Academy's race-condition-free Ekko sleep obfuscation
  technique, which captures the thread context on the timer thread itself and uses
  `NtSignalAndWaitForSingleObject` for atomic chain synchronization.
