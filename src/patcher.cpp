#include "patcher.h"
#include "scanner.h"
#include "hook.h"
#include "ue_types.h"
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <cwchar>

extern void LogMsg(const char* fmt, ...);

// ===================================================================
// Helper: resolve an FName to a narrow string  (reuses one FString)
// ===================================================================

static FString g_fstr = { nullptr, 0, 0 };

static const wchar_t* NameToString(FNameToStringFn fn, uintptr_t namePtr) {
    g_fstr.Num = 0;
    fn((const void*)namePtr, &g_fstr);
    return g_fstr.Data;
}

static bool NameEqualsA(FNameToStringFn fn, uintptr_t namePtr, const char* target) {
    const wchar_t* ws = NameToString(fn, namePtr);
    if (!ws) return false;
    size_t tlen = strlen(target);
    for (size_t i = 0; i < tlen; ++i) {
        if (ws[i] != (wchar_t)(unsigned char)target[i]) return false;
    }
    return ws[tlen] == L'\0';
}

static void WideToNarrow(const wchar_t* ws, char* out, size_t maxLen) {
    if (!ws) { out[0] = '\0'; return; }
    size_t i = 0;
    for (; ws[i] && i + 1 < maxLen; ++i)
        out[i] = (char)(ws[i] < 128 ? ws[i] : '?');
    out[i] = '\0';
}

// ===================================================================
// Object iteration helpers
// ===================================================================

static uintptr_t GetObject(uintptr_t objArrayBase, int32_t index) {
    auto** chunks = ReadAt<uintptr_t**>(objArrayBase, TObjOff::Objects);
    if (!chunks) return 0;

    int chunkIdx = index / TObjOff::ChunkSize;
    int itemIdx  = index % TObjOff::ChunkSize;

    uintptr_t chunk = (uintptr_t)chunks[chunkIdx];
    if (!chunk) return 0;

    uintptr_t item = chunk + (uintptr_t)itemIdx * ItemOff::Size;
    return ReadAt<uintptr_t>(item, ItemOff::Object);
}

// ===================================================================
// Globals for the hook detour
// ===================================================================

static ScanResults       g_scan = {};
static uintptr_t         g_objArrayBase = 0;
static InlineHook        g_postSaveHook = {};

// Signal subsystem instance + signal name (resolved at init time)
static void*             g_signalSubsystem = nullptr;
static FName             g_socketSignalName = { 0, 0 };
static bool              g_signalReady = false;

// INI fallback signal name
static char              g_iniSignalName[256] = "CrLogisticsSocketsSignal";

// ===================================================================
// Read fallback signal name from INI
// ===================================================================

extern char g_modDir[];

static void ReadSignalNameFromINI() {
    char path[MAX_PATH];
    snprintf(path, MAX_PATH, "%s\\socket_save_fix.ini", g_modDir);

    FILE* f = fopen(path, "r");
    if (!f) return;

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == ';' || line[0] == '\n' || line[0] == '\r')
            continue;

        char val[256];
        if (sscanf(line, "SocketSignalName=%255s", val) == 1) {
            strncpy(g_iniSignalName, val, sizeof(g_iniSignalName) - 1);
            g_iniSignalName[sizeof(g_iniSignalName) - 1] = '\0';
            LogMsg("  INI SocketSignalName = %s", g_iniSignalName);
        }
    }
    fclose(f);
}

// ===================================================================
// Find UObject by class name in GUObjectArray
// ===================================================================

static uintptr_t FindObjectByClassName(const char* className) {
    int32_t numElements = ReadAt<int32_t>(g_objArrayBase, TObjOff::NumElements);

    for (int32_t i = 0; i < numElements; ++i) {
        uintptr_t obj = GetObject(g_objArrayBase, i);
        if (!obj) continue;

        uintptr_t cls = ReadAt<uintptr_t>(obj, UObjOff::ClassPrivate);
        if (!cls) continue;

        if (NameEqualsA(g_scan.fnNameToString, cls + UObjOff::NamePrivate, className))
            return obj;
    }
    return 0;
}

// ===================================================================
// Find an FName ComparisonIndex by string
//
// Walk GUObjectArray looking for any FName that matches the target
// string.  Returns the FName with its ComparisonIndex set.
// ===================================================================

static FName FindFNameByString(const char* target) {
    int32_t numElements = ReadAt<int32_t>(g_objArrayBase, TObjOff::NumElements);

    for (int32_t i = 0; i < numElements; ++i) {
        uintptr_t obj = GetObject(g_objArrayBase, i);
        if (!obj) continue;

        uintptr_t namePtr = obj + UObjOff::NamePrivate;
        if (NameEqualsA(g_scan.fnNameToString, namePtr, target)) {
            FName result;
            result.ComparisonIndex = ReadAt<uint32_t>(namePtr, 0);
            result.Number = ReadAt<uint32_t>(namePtr, 4);
            return result;
        }
    }

    return { 0, 0 };
}

// ===================================================================
// Discover signal name from CrLogisticsSocketsSignalProcessor CDO
//
// The processor's InitializeInternal accesses offset 0x288 which is
// where it stores the FName of the signal it subscribes to.
// ===================================================================

static constexpr size_t SIGNAL_PROCESSOR_SIGNAL_OFFSET = 0x288;

static bool DiscoverSignalName() {
    // Find the CDO (Class Default Object) for the signal processor
    int32_t numElements = ReadAt<int32_t>(g_objArrayBase, TObjOff::NumElements);
    uintptr_t processorClass = 0;
    uintptr_t processorCDO = 0;

    // First pass: find the class
    for (int32_t i = 0; i < numElements; ++i) {
        uintptr_t obj = GetObject(g_objArrayBase, i);
        if (!obj) continue;

        uintptr_t cls = ReadAt<uintptr_t>(obj, UObjOff::ClassPrivate);
        if (!cls) continue;

        if (NameEqualsA(g_scan.fnNameToString, cls + UObjOff::NamePrivate,
                        "CrLogisticsSocketsSignalProcessor")) {
            processorClass = cls;
            // The CDO's Outer is typically its package
            uintptr_t outer = ReadAt<uintptr_t>(obj, UObjOff::OuterPrivate);
            if (outer) {
                uintptr_t outerClass = ReadAt<uintptr_t>(outer, UObjOff::ClassPrivate);
                if (outerClass && NameEqualsA(g_scan.fnNameToString,
                                               outerClass + UObjOff::NamePrivate, "Package")) {
                    processorCDO = obj;
                    LogMsg("Found CrLogisticsSocketsSignalProcessor CDO at 0x%llX",
                           (unsigned long long)obj);
                    break;
                }
            }
            // If we can't verify it's a CDO, use the first instance anyway
            if (!processorCDO) {
                processorCDO = obj;
                LogMsg("Found CrLogisticsSocketsSignalProcessor instance at 0x%llX (may not be CDO)",
                       (unsigned long long)obj);
            }
        }
    }

    if (!processorCDO) {
        LogMsg("WARNING: CrLogisticsSocketsSignalProcessor not found in GUObjectArray");
        return false;
    }

    // Read the FName at CDO + 0x288
    FName signalFName;
    signalFName.ComparisonIndex = ReadAt<uint32_t>(processorCDO, SIGNAL_PROCESSOR_SIGNAL_OFFSET);
    signalFName.Number = ReadAt<uint32_t>(processorCDO, SIGNAL_PROCESSOR_SIGNAL_OFFSET + 4);

    // Resolve to string
    const wchar_t* ws = NameToString(g_scan.fnNameToString,
                                      processorCDO + SIGNAL_PROCESSOR_SIGNAL_OFFSET);
    if (ws && ws[0] != L'\0') {
        char nameBuf[256];
        WideToNarrow(ws, nameBuf, sizeof(nameBuf));
        LogMsg("Signal name from CDO+0x%zX: \"%s\" (CompIdx=0x%X, Num=%d)",
               SIGNAL_PROCESSOR_SIGNAL_OFFSET, nameBuf,
               signalFName.ComparisonIndex, signalFName.Number);

        g_socketSignalName = signalFName;
        return true;
    }

    LogMsg("WARNING: FName at CDO+0x%zX resolved to empty/null", SIGNAL_PROCESSOR_SIGNAL_OFFSET);
    return false;
}

// ===================================================================
// Find UMassSignalSubsystem instance
// ===================================================================

static bool FindSignalSubsystem() {
    int32_t numElements = ReadAt<int32_t>(g_objArrayBase, TObjOff::NumElements);

    for (int32_t i = 0; i < numElements; ++i) {
        uintptr_t obj = GetObject(g_objArrayBase, i);
        if (!obj) continue;

        uintptr_t cls = ReadAt<uintptr_t>(obj, UObjOff::ClassPrivate);
        if (!cls) continue;

        if (NameEqualsA(g_scan.fnNameToString, cls + UObjOff::NamePrivate,
                        "MassSignalSubsystem")) {
            g_signalSubsystem = (void*)obj;
            LogMsg("Found UMassSignalSubsystem at 0x%llX", (unsigned long long)obj);
            return true;
        }
    }

    LogMsg("WARNING: UMassSignalSubsystem not found");
    return false;
}

// ===================================================================
// Hook detour: OnPostSaveLoaded
//
// Called after the save subsystem finishes loading entity data.
// We signal all entities with the logistics sockets signal to trigger
// UCrLogisticsSocketsSignalProcessor::Execute, which properly rebuilds
// socket data from FCrLogisticsSocketsParams + FCrCustomConnectionData.
// ===================================================================

// Type for calling the original function via trampoline
using OnPostSaveLoadedFn = void (*)(void* thisPtr);

// ===================================================================
// Entity manager scanning
//
// UMassEntitySubsystem embeds an FMassEntityManager.  The manager has
// a flat sparse array of entity data where each slot stores:
//   - SerialNumber (int32)  — to validate FMassEntityHandle
//   - Archetype info
//
// In UE5 Mass Entity, the entity array is a TSparseArray.
// TSparseArray layout:
//   +0x00  TArray<ElementType> Data       (ptr, Num, Max)
//   +0x10  AllocationBitmap / FreeList
//
// We need to discover the offset of this array within UMassEntitySubsystem.
// Strategy: scan for a plausible TSparseArray (pointer followed by count)
// within the subsystem's memory, then validate entries.
//
// Each entity data element in UE5 Mass Entity is ~16-32 bytes containing:
//   - int32 SerialNumber (at element start or offset 0)
//   - FMassArchetypeHandle (pointer)
// ===================================================================

static constexpr int MAX_ENTITY_INDEX = 200000;

// Try to read the entity manager's entity data from the subsystem.
// Returns entity count, fills handles array (caller provides buffer).
// entitySubsystem = UMassEntitySubsystem* address
static int ReadEntityHandles(uintptr_t entitySubsystem,
                              FMassEntityHandle* outHandles, int maxHandles)
{
    // UMassEntitySubsystem inherits UWorldSubsystem : USubsystem : UObject (0x30 base)
    // Then has FMassEntityManager embedded.  The manager is a large struct.
    // We scan offsets 0x30..0x200 looking for what looks like a TSparseArray<FEntityData>.
    //
    // A valid TSparseArray has:
    //   +0x00  ptr to data  (valid heap address, non-null)
    //   +0x08  int32 Num    (positive, reasonable)
    //   +0x0C  int32 Max    (>= Num)

    LogMsg("  Scanning UMassEntitySubsystem (0x%llX) for entity array...",
           (unsigned long long)entitySubsystem);

    for (size_t off = 0x30; off < 0x400; off += 8) {
        uintptr_t arrayPtr = ReadAt<uintptr_t>(entitySubsystem, off);
        if (arrayPtr == 0 || arrayPtr < 0x10000) continue;

        int32_t num = ReadAt<int32_t>(entitySubsystem, off + 0x08);
        int32_t max = ReadAt<int32_t>(entitySubsystem, off + 0x0C);

        // Look for a plausible entity array: reasonable count, max >= num
        if (num < 100 || num > MAX_ENTITY_INDEX || max < num || max > MAX_ENTITY_INDEX * 2)
            continue;

        // Validate: check if the array contains plausible entity data
        // Each element should start with a serial number (small positive int32)
        // followed by some pointer (archetype handle)
        // Try element sizes of 16, 24, 32 bytes

        for (int elemSize = 16; elemSize <= 32; elemSize += 8) {
            int validCount = 0;
            int sampleSize = (num < 20) ? num : 20;

            for (int i = 0; i < sampleSize; ++i) {
                uintptr_t elemAddr = arrayPtr + (uintptr_t)i * elemSize;
                int32_t serial = ReadAt<int32_t>(elemAddr, 0);
                uintptr_t archetype = ReadAt<uintptr_t>(elemAddr, 8);

                // Valid serial: small positive number (1..~1000 after fresh load)
                // Valid archetype: non-null pointer in a reasonable range
                if (serial > 0 && serial < 10000 &&
                    archetype > 0x10000 && archetype < 0x7FFFFFFFFFFF) {
                    validCount++;
                }
            }

            if (validCount >= sampleSize / 2) {
                LogMsg("  Found candidate entity array at subsys+0x%zX: "
                       "ptr=0x%llX, num=%d, max=%d, elemSize=%d (%d/%d valid samples)",
                       off, (unsigned long long)arrayPtr, num, max,
                       elemSize, validCount, sampleSize);

                // Read entity handles
                int count = 0;
                for (int i = 0; i < num && count < maxHandles; ++i) {
                    uintptr_t elemAddr = arrayPtr + (uintptr_t)i * elemSize;
                    int32_t serial = ReadAt<int32_t>(elemAddr, 0);

                    if (serial > 0) {  // slot is occupied (free slots have serial <= 0)
                        outHandles[count].Index = i;
                        outHandles[count].SerialNumber = serial;
                        count++;
                    }
                }

                LogMsg("  Extracted %d valid entity handles from %d slots", count, num);
                return count;
            }
        }
    }

    LogMsg("  WARNING: Could not find entity array in UMassEntitySubsystem");
    return 0;
}

static void __attribute__((ms_abi)) Detour_OnPostSaveLoaded(void* thisPtr) {
    LogMsg(">>> OnPostSaveLoaded hook entered (this=0x%llX)",
           (unsigned long long)(uintptr_t)thisPtr);

    // Call original first — let the save system finish its work
    auto origFn = (OnPostSaveLoadedFn)g_postSaveHook.trampoline;
    origFn(thisPtr);

    LogMsg("  Original OnPostSaveLoaded returned");

    // Re-discover subsystem if needed (it may not exist at patch time)
    if (!g_signalSubsystem) {
        FindSignalSubsystem();
    }

    // Retry signal name discovery if it failed at init
    if (!g_signalReady) {
        if (DiscoverSignalName()) {
            g_signalReady = true;
        } else {
            g_socketSignalName = FindFNameByString(g_iniSignalName);
            if (g_socketSignalName.ComparisonIndex != 0)
                g_signalReady = true;
        }
    }

    if (!g_signalReady || !g_signalSubsystem || !g_scan.fnSignalEntity) {
        LogMsg("  Signal system not ready (ready=%d, subsys=%p, fn=%p) — skipping",
               g_signalReady, g_signalSubsystem, (void*)g_scan.fnSignalEntity);
        return;
    }

    // Find UMassEntitySubsystem to iterate entity handles
    uintptr_t entitySubsystem = FindObjectByClassName("MassEntitySubsystem");
    if (!entitySubsystem) {
        LogMsg("  WARNING: MassEntitySubsystem not found — cannot signal entities");
        return;
    }

    // Read valid entity handles from the entity manager
    constexpr int HANDLE_BUF_SIZE = 100000;
    FMassEntityHandle* handles = (FMassEntityHandle*)VirtualAlloc(
        nullptr, HANDLE_BUF_SIZE * sizeof(FMassEntityHandle),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!handles) {
        LogMsg("  ERROR: Failed to allocate handle buffer");
        return;
    }

    int handleCount = ReadEntityHandles(entitySubsystem, handles, HANDLE_BUF_SIZE);

    if (handleCount > 0) {
        LogMsg("  Signaling %d entities with socket signal (CompIdx=0x%X)...",
               handleCount, g_socketSignalName.ComparisonIndex);

        for (int i = 0; i < handleCount; ++i) {
            g_scan.fnSignalEntity(g_signalSubsystem, g_socketSignalName, handles[i]);
        }

        LogMsg("  Socket signal sent to %d entities", handleCount);
    } else {
        LogMsg("  No entity handles found — signal skipped");
        LogMsg("  Dumping UMassEntitySubsystem memory for diagnostics:");

        // Dump first 256 bytes for manual analysis
        uint8_t* mem = (uint8_t*)entitySubsystem;
        for (int row = 0; row < 32; ++row) {
            int off = row * 16;
            LogMsg("    +0x%03X: %02X %02X %02X %02X %02X %02X %02X %02X "
                   "%02X %02X %02X %02X %02X %02X %02X %02X",
                   off,
                   mem[off+0],  mem[off+1],  mem[off+2],  mem[off+3],
                   mem[off+4],  mem[off+5],  mem[off+6],  mem[off+7],
                   mem[off+8],  mem[off+9],  mem[off+10], mem[off+11],
                   mem[off+12], mem[off+13], mem[off+14], mem[off+15]);
        }
    }

    VirtualFree(handles, 0, MEM_RELEASE);

    LogMsg("<<< OnPostSaveLoaded hook complete");
}

// ===================================================================
// ApplyPatch — main logic
// ===================================================================

bool ApplyPatch() {
    // ---- Step 1: Scan for engine symbols ----
    if (!ScanForEngineSymbols(g_scan)) {
        return false;
    }

    g_objArrayBase = g_scan.guObjectArray + GUObjOff::ObjObjects;

    // ---- Step 2: Validate required addresses ----
    if (!g_scan.fnOnPostSaveLoaded) {
        LogMsg("ERROR: OnPostSaveLoaded_RVA not configured in INI");
        LogMsg("Add to socket_save_fix.ini:");
        LogMsg("  OnPostSaveLoaded_RVA=0x764DC40");
        return false;
    }
    if (!g_scan.fnSignalEntity) {
        LogMsg("ERROR: SignalEntity_RVA not configured in INI");
        LogMsg("Add to socket_save_fix.ini:");
        LogMsg("  SignalEntity_RVA=0x65F1BB0");
        return false;
    }

    // ---- Step 3: Read INI fallback signal name ----
    ReadSignalNameFromINI();

    // ---- Step 4: Wait for UObject system to be populated ----
    LogMsg("Waiting for UObject system to populate...");
    DWORD startTime = GetTickCount();

    for (int attempt = 0; attempt < 1200; ++attempt) {
        int32_t numEl = ReadAt<int32_t>(g_objArrayBase, TObjOff::NumElements);
        if (numEl > 1000) {
            // System is populated enough
            DWORD elapsed = GetTickCount() - startTime;
            LogMsg("UObject system ready: %d objects (%lu ms)", numEl, elapsed);
            break;
        }
        if (attempt == 1199) {
            LogMsg("ERROR: Timed out waiting for UObject system");
            return false;
        }
        Sleep(100);
    }

    // ---- Step 5: Discover signal name from CDO ----
    LogMsg("Discovering signal name from CrLogisticsSocketsSignalProcessor CDO...");
    if (DiscoverSignalName()) {
        g_signalReady = true;
        LogMsg("Signal name discovered from CDO");
    } else {
        // Fall back to INI signal name — resolve via FName lookup
        LogMsg("Falling back to INI signal name: %s", g_iniSignalName);
        g_socketSignalName = FindFNameByString(g_iniSignalName);
        if (g_socketSignalName.ComparisonIndex != 0) {
            g_signalReady = true;
            LogMsg("Resolved INI signal name: CompIdx=0x%X",
                   g_socketSignalName.ComparisonIndex);
        } else {
            LogMsg("WARNING: Could not resolve signal name '%s' — will retry at hook time",
                   g_iniSignalName);
        }
    }

    // ---- Step 6: Find UMassSignalSubsystem ----
    FindSignalSubsystem();  // OK if not found yet — will retry in hook

    // ---- Step 7: Verify OnPostSaveLoaded prologue ----
    LogMsg("Verifying OnPostSaveLoaded prologue at 0x%llX...",
           (unsigned long long)g_scan.fnOnPostSaveLoaded);

    uint8_t* prologue = (uint8_t*)g_scan.fnOnPostSaveLoaded;
    // Expected: 40 53 48 83 EC 20 48 8B D9 E8 xx xx xx xx
    //           push rbx; sub rsp,0x20; mov rbx,rcx; call rel32
    bool prologueOK =
        prologue[0] == 0x40 && prologue[1] == 0x53 &&   // push rbx (REX)
        prologue[2] == 0x48 && prologue[3] == 0x83 &&   // sub rsp, 0x20
        prologue[4] == 0xEC && prologue[5] == 0x20 &&
        prologue[6] == 0x48 && prologue[7] == 0x8B &&   // mov rbx, rcx
        prologue[8] == 0xD9 &&
        prologue[9] == 0xE8;                             // call rel32

    if (!prologueOK) {
        LogMsg("ERROR: OnPostSaveLoaded prologue mismatch!");
        LogMsg("  Expected: 40 53 48 83 EC 20 48 8B D9 E8 xx xx xx xx");
        LogMsg("  Got:      %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
               prologue[0], prologue[1], prologue[2], prologue[3], prologue[4],
               prologue[5], prologue[6], prologue[7], prologue[8], prologue[9]);
        return false;
    }
    LogMsg("  Prologue verified: push rbx; sub rsp,20h; mov rbx,rcx; call rel32");

    // ---- Step 8: Install the hook ----
    // Steal exactly 14 bytes (the full prologue up to and including the call rel32)
    if (!InstallHook(g_postSaveHook, g_scan.fnOnPostSaveLoaded,
                     (void*)Detour_OnPostSaveLoaded, 14)) {
        LogMsg("ERROR: Failed to install OnPostSaveLoaded hook");
        return false;
    }

    LogMsg("OnPostSaveLoaded hook installed successfully");

    DWORD totalElapsed = GetTickCount() - startTime;
    LogMsg("Total setup time: %lu ms", totalElapsed);

    return true;
}
