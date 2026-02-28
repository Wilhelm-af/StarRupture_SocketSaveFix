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
// Globals
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

// Hierarchy patch state (for cleanup/restore)
static uintptr_t* g_newChain = nullptr;
static uintptr_t  g_socketsStruct = 0;
static uintptr_t* g_origChain = nullptr;
static int32_t    g_origDepth = 0;
static uintptr_t  g_origSuperStruct = 0;

// ===================================================================
// Diagnostic: dump hierarchy chain and struct info
// ===================================================================

static void DumpHierarchyChain(FNameToStringFn fn, const char* label, uintptr_t scriptStruct) {
    if (!scriptStruct) return;

    int32_t depth = ReadAt<int32_t>(scriptStruct, UStructOff::HierarchyDepth);
    uintptr_t* chain = ReadAt<uintptr_t*>(scriptStruct, UStructOff::InheritanceChain);

    LogMsg("  %s.HierarchyDepth   = %d", label, depth);
    LogMsg("  %s.InheritanceChain = 0x%llX", label, (unsigned long long)(uintptr_t)chain);

    if (chain && depth >= 0 && depth < 32) {
        for (int i = 0; i <= depth; ++i) {
            uintptr_t entry = chain[i];
            uintptr_t structPtr = entry - UStructOff::InheritanceChain;

            char nameBuf[256];
            const wchar_t* ws = NameToString(fn, structPtr + UObjOff::NamePrivate);
            WideToNarrow(ws, nameBuf, sizeof(nameBuf));

            LogMsg("    chain[%d] = 0x%llX -> struct 0x%llX (%s)%s",
                   i, (unsigned long long)entry,
                   (unsigned long long)structPtr, nameBuf,
                   (i == depth) ? " [SELF]" : "");
        }
    }
}

static void DumpStructInfo(FNameToStringFn fn, const char* label, uintptr_t scriptStruct) {
    if (!scriptStruct) return;

    char nameBuf[256];

    uintptr_t super = ReadAt<uintptr_t>(scriptStruct, UStructOff::SuperStruct);
    if (super) {
        const wchar_t* ws = NameToString(fn, super + UObjOff::NamePrivate);
        WideToNarrow(ws, nameBuf, sizeof(nameBuf));
    } else {
        strcpy(nameBuf, "(null)");
    }
    LogMsg("  %s.SuperStruct      = 0x%llX (%s)", label,
           (unsigned long long)super, nameBuf);

    DumpHierarchyChain(fn, label, scriptStruct);

    int32_t propsSize = ReadAt<int32_t>(scriptStruct, UStructOff::PropertiesSize);
    LogMsg("  %s.PropertiesSize   = %d (0x%X)", label, propsSize, propsSize);

    uint32_t flags = ReadAt<uint32_t>(scriptStruct, UScriptStructOff::StructFlags);
    LogMsg("  %s.StructFlags      = 0x%08X", label, flags);
}

// ===================================================================
// Find all three target UScriptStructs in one pass
// ===================================================================

struct TargetStructs {
    uintptr_t socketsFragment;   // FCrLogisticsSocketsFragment
    uintptr_t savableFragment;   // FCrMassSavableFragment
    uintptr_t massFragment;      // FMassFragment
    uintptr_t scriptStructClass; // UScriptStruct class pointer (cached)
};

static bool FindTargets(uintptr_t objArrayBase, FNameToStringFn fn, TargetStructs& t) {
    int32_t numElements = ReadAt<int32_t>(objArrayBase, TObjOff::NumElements);
    if (numElements <= 0) return false;

    // Phase 1: Find UScriptStruct class if not yet known
    if (!t.scriptStructClass) {
        constexpr int MAX_CLASSES = 512;
        uintptr_t checkedClasses[MAX_CLASSES];
        int numChecked = 0;

        for (int32_t i = 0; i < numElements; ++i) {
            uintptr_t obj = GetObject(objArrayBase, i);
            if (!obj) continue;

            uintptr_t cls = ReadAt<uintptr_t>(obj, UObjOff::ClassPrivate);
            if (!cls) continue;

            bool already = false;
            for (int c = 0; c < numChecked; ++c) {
                if (checkedClasses[c] == cls) { already = true; break; }
            }
            if (already) continue;
            if (numChecked < MAX_CLASSES) checkedClasses[numChecked++] = cls;

            if (NameEqualsA(fn, cls + UObjOff::NamePrivate, "ScriptStruct")) {
                t.scriptStructClass = cls;
                break;
            }
        }
        if (!t.scriptStructClass) return false;
    }

    // Phase 2: Find target structs by name
    int found = (t.socketsFragment ? 1 : 0) +
                (t.savableFragment ? 1 : 0) +
                (t.massFragment ? 1 : 0);

    for (int32_t i = 0; i < numElements && found < 3; ++i) {
        uintptr_t obj = GetObject(objArrayBase, i);
        if (!obj) continue;

        uintptr_t cls = ReadAt<uintptr_t>(obj, UObjOff::ClassPrivate);
        if (cls != t.scriptStructClass) continue;

        uintptr_t namePtr = obj + UObjOff::NamePrivate;

        if (!t.socketsFragment && NameEqualsA(fn, namePtr, "CrLogisticsSocketsFragment")) {
            t.socketsFragment = obj;
            found++;
        }
        else if (!t.savableFragment && NameEqualsA(fn, namePtr, "CrMassSavableFragment")) {
            t.savableFragment = obj;
            found++;
        }
        else if (!t.massFragment && NameEqualsA(fn, namePtr, "MassFragment")) {
            t.massFragment = obj;
            found++;
        }
    }

    return found == 3;
}

// ===================================================================
// PatchHierarchyChain — rebuild the precomputed IsChildOf array
//
// UE5 stores a flat ancestor array at UStruct+0x30 and depth at +0x38.
// IsChildOf(target) checks: this->chain[target->depth] == (target + 0x30)
//
// We insert FCrMassSavableFragment into FCrLogisticsSocketsFragment's chain
// so that the save system's IsChildOf check succeeds.
// ===================================================================

static bool PatchHierarchyChain(uintptr_t socketsStruct, uintptr_t savableStruct) {
    int32_t sockDepth = ReadAt<int32_t>(socketsStruct, UStructOff::HierarchyDepth);
    uintptr_t* sockChain = ReadAt<uintptr_t*>(socketsStruct, UStructOff::InheritanceChain);

    int32_t savDepth = ReadAt<int32_t>(savableStruct, UStructOff::HierarchyDepth);
    uintptr_t savIdentity = savableStruct + UStructOff::InheritanceChain;
    uintptr_t sockIdentity = socketsStruct + UStructOff::InheritanceChain;

    LogMsg("PatchHierarchyChain:");
    LogMsg("  sockets depth=%d, chain=0x%llX, identity=0x%llX",
           sockDepth, (unsigned long long)(uintptr_t)sockChain,
           (unsigned long long)sockIdentity);
    LogMsg("  savable depth=%d, identity=0x%llX",
           savDepth, (unsigned long long)savIdentity);

    if (!sockChain || sockDepth < 0 || sockDepth > 30) {
        LogMsg("ERROR: Invalid sockets hierarchy data");
        return false;
    }

    if (sockChain[sockDepth] != sockIdentity) {
        LogMsg("ERROR: chain[self_depth] (0x%llX) != self identity (0x%llX)",
               (unsigned long long)sockChain[sockDepth],
               (unsigned long long)sockIdentity);
        return false;
    }

    // Check if savable is already in the chain (patch already applied)
    if (savDepth <= sockDepth && sockChain[savDepth] == savIdentity) {
        LogMsg("Hierarchy chain already contains CrMassSavableFragment");
        return true;
    }

    // Build new chain: insert savable at index savDepth, shift rest up by 1
    int newSize = sockDepth + 2;
    LogMsg("Building new chain: %d -> %d entries", sockDepth + 1, newSize);

    g_newChain = (uintptr_t*)VirtualAlloc(
        nullptr, newSize * sizeof(uintptr_t),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!g_newChain) {
        LogMsg("ERROR: VirtualAlloc failed for new chain");
        return false;
    }

    for (int i = 0; i < savDepth; ++i) {
        g_newChain[i] = sockChain[i];
    }

    g_newChain[savDepth] = savIdentity;

    for (int i = savDepth; i <= sockDepth; ++i) {
        g_newChain[i + 1] = sockChain[i];
    }

    for (int i = 0; i < newSize; ++i) {
        LogMsg("  newChain[%d] = 0x%llX%s%s",
               i, (unsigned long long)g_newChain[i],
               (g_newChain[i] == savIdentity) ? " [SAVABLE]" : "",
               (g_newChain[i] == sockIdentity) ? " [SELF]" : "");
    }

    // Save originals for restoration on shutdown
    g_socketsStruct   = socketsStruct;
    g_origChain       = sockChain;
    g_origDepth       = sockDepth;
    g_origSuperStruct = ReadAt<uintptr_t>(socketsStruct, UStructOff::SuperStruct);

    // Apply the patch
    uintptr_t patchStart = socketsStruct + UStructOff::InheritanceChain;
    DWORD oldProtect;
    VirtualProtect((void*)patchStart, 0x18, PAGE_READWRITE, &oldProtect);

    WriteAt<uintptr_t*>(socketsStruct, UStructOff::InheritanceChain, g_newChain);
    WriteAt<int32_t>(socketsStruct, UStructOff::HierarchyDepth, sockDepth + 1);
    WriteAt<uintptr_t>(socketsStruct, UStructOff::SuperStruct, savableStruct);

    VirtualProtect((void*)patchStart, 0x18, oldProtect, &oldProtect);

    // Verify
    uintptr_t* verifyChain = ReadAt<uintptr_t*>(socketsStruct, UStructOff::InheritanceChain);
    int32_t verifyDepth = ReadAt<int32_t>(socketsStruct, UStructOff::HierarchyDepth);
    uintptr_t verifySuper = ReadAt<uintptr_t>(socketsStruct, UStructOff::SuperStruct);

    bool ok = (verifyChain == g_newChain) &&
              (verifyDepth == sockDepth + 1) &&
              (verifySuper == savableStruct);

    if (ok) {
        uintptr_t testEntry = g_newChain[savDepth];
        bool isChildOf = (savDepth <= verifyDepth) && (testEntry == savIdentity);
        LogMsg("  IsChildOf(CrMassSavableFragment) = %s", isChildOf ? "TRUE" : "FALSE");
    }

    return ok;
}

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
// Find UObject by class name in GUObjectArray (with class pointer cache)
// ===================================================================

struct ClassCacheEntry {
    const char* name;
    uintptr_t   classPtr;
};
static ClassCacheEntry g_classCache[8] = {};
static int             g_classCacheCount = 0;

static uintptr_t FindObjectByClassName(const char* className, bool skipCDO = false) {
    int32_t numElements = ReadAt<int32_t>(g_objArrayBase, TObjOff::NumElements);

    uintptr_t cachedClass = 0;
    for (int c = 0; c < g_classCacheCount; ++c) {
        if (strcmp(g_classCache[c].name, className) == 0) {
            cachedClass = g_classCache[c].classPtr;
            break;
        }
    }

    for (int32_t i = 0; i < numElements; ++i) {
        uintptr_t obj = GetObject(g_objArrayBase, i);
        if (!obj) continue;

        uintptr_t cls = ReadAt<uintptr_t>(obj, UObjOff::ClassPrivate);
        if (!cls) continue;

        if (cachedClass) {
            if (cls != cachedClass) continue;
        } else {
            if (!NameEqualsA(g_scan.fnNameToString, cls + UObjOff::NamePrivate, className))
                continue;
            if (g_classCacheCount < 8) {
                g_classCache[g_classCacheCount].name = className;
                g_classCache[g_classCacheCount].classPtr = cls;
                g_classCacheCount++;
            }
        }

        if (skipCDO) {
            uintptr_t outer = ReadAt<uintptr_t>(obj, UObjOff::OuterPrivate);
            if (outer) {
                uintptr_t outerClass = ReadAt<uintptr_t>(outer, UObjOff::ClassPrivate);
                if (outerClass && NameEqualsA(g_scan.fnNameToString,
                                               outerClass + UObjOff::NamePrivate, "Package"))
                    continue;
            }
        }

        return obj;
    }
    return 0;
}

// ===================================================================
// Find an FName ComparisonIndex by string
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
// ===================================================================

static constexpr size_t SIGNAL_PROCESSOR_SIGNAL_OFFSET = 0x288;

static bool DiscoverSignalName() {
    int32_t numElements = ReadAt<int32_t>(g_objArrayBase, TObjOff::NumElements);
    uintptr_t processorCDO = 0;

    for (int32_t i = 0; i < numElements; ++i) {
        uintptr_t obj = GetObject(g_objArrayBase, i);
        if (!obj) continue;

        uintptr_t cls = ReadAt<uintptr_t>(obj, UObjOff::ClassPrivate);
        if (!cls) continue;

        if (NameEqualsA(g_scan.fnNameToString, cls + UObjOff::NamePrivate,
                        "CrLogisticsSocketsSignalProcessor")) {
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

    FName signalFName;
    signalFName.ComparisonIndex = ReadAt<uint32_t>(processorCDO, SIGNAL_PROCESSOR_SIGNAL_OFFSET);
    signalFName.Number = ReadAt<uint32_t>(processorCDO, SIGNAL_PROCESSOR_SIGNAL_OFFSET + 4);

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

using OnPostSaveLoadedFn = void (*)(void* thisPtr);

// ===================================================================
// Entity manager scanning
// ===================================================================

static constexpr int MAX_ENTITY_INDEX = 200000;

static int ReadEntityHandles(uintptr_t entitySubsystem,
                              FMassEntityHandle* outHandles, int maxHandles)
{
    LogMsg("  Scanning UMassEntitySubsystem (0x%llX) for entity array...",
           (unsigned long long)entitySubsystem);

    for (size_t off = 0x30; off < 0x400; off += 8) {
        uintptr_t arrayPtr = ReadAt<uintptr_t>(entitySubsystem, off);
        if (arrayPtr == 0 || arrayPtr < 0x10000) continue;

        int32_t num = ReadAt<int32_t>(entitySubsystem, off + 0x08);
        int32_t max = ReadAt<int32_t>(entitySubsystem, off + 0x0C);

        if (num < 100 || num > MAX_ENTITY_INDEX || max < num || max > MAX_ENTITY_INDEX * 2)
            continue;

        for (int elemSize = 16; elemSize <= 32; elemSize += 8) {
            int validCount = 0;
            int sampleSize = (num < 20) ? num : 20;

            for (int i = 0; i < sampleSize; ++i) {
                uintptr_t elemAddr = arrayPtr + (uintptr_t)i * elemSize;
                int32_t serial = ReadAt<int32_t>(elemAddr, 0);
                uintptr_t archetype = ReadAt<uintptr_t>(elemAddr, 8);

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

                int count = 0;
                for (int i = 0; i < num && count < maxHandles; ++i) {
                    uintptr_t elemAddr = arrayPtr + (uintptr_t)i * elemSize;
                    int32_t serial = ReadAt<int32_t>(elemAddr, 0);

                    if (serial > 0) {
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
    }

    VirtualFree(handles, 0, MEM_RELEASE);

    LogMsg("<<< OnPostSaveLoaded hook complete");
}

// ===================================================================
// ApplyPatch — main logic
//
// Phase 1 (v1): Patch hierarchy chain so save system includes socket data
// Phase 2 (v2): Hook OnPostSaveLoaded to signal entities after load
// ===================================================================

bool ApplyPatch() {
    // ---- Step 1: Scan for engine symbols ----
    if (!ScanForEngineSymbols(g_scan)) {
        return false;
    }

    g_objArrayBase = g_scan.guObjectArray + GUObjOff::ObjObjects;

    // ---- Step 2: Validate v2 hook addresses ----
    if (!g_scan.fnOnPostSaveLoaded) {
        LogMsg("WARNING: OnPostSaveLoaded_RVA not configured — v2 signal hook disabled");
        LogMsg("Add to socket_save_fix.ini:");
        LogMsg("  OnPostSaveLoaded_RVA=0x764DC40");
    }
    if (!g_scan.fnSignalEntity) {
        LogMsg("WARNING: SignalEntity_RVA not configured — v2 signal hook disabled");
        LogMsg("Add to socket_save_fix.ini:");
        LogMsg("  SignalEntity_RVA=0x65F1BB0");
    }

    bool v2Possible = g_scan.fnOnPostSaveLoaded && g_scan.fnSignalEntity;

    // ---- Step 3: Read INI fallback signal name ----
    if (v2Possible) {
        ReadSignalNameFromINI();
    }

    // ---- Step 4: Poll for target UScriptStructs (v1 hierarchy patch) ----
    LogMsg("Polling for target UScriptStructs (100ms intervals, 120s timeout)...");

    TargetStructs targets = {};
    DWORD startTime = GetTickCount();

    for (int attempt = 0; attempt < 1200; ++attempt) {
        int32_t numEl = ReadAt<int32_t>(g_objArrayBase, TObjOff::NumElements);

        if (numEl > 0 && g_scan.fnNameToString) {
            uintptr_t firstObj = GetObject(g_objArrayBase, 0);
            if (firstObj) {
                const wchar_t* ws = NameToString(g_scan.fnNameToString,
                                                  firstObj + UObjOff::NamePrivate);
                if (ws && ws[0] != L'\0') {
                    if (FindTargets(g_objArrayBase, g_scan.fnNameToString, targets)) {
                        DWORD elapsed = GetTickCount() - startTime;
                        LogMsg("All targets found in %lu ms (attempt %d, %d objects)",
                               elapsed, attempt, numEl);
                        break;
                    }
                }
            }
        }

        if (attempt == 1199) {
            DWORD elapsed = GetTickCount() - startTime;
            LogMsg("ERROR: Timed out after %lu ms", elapsed);
            LogMsg("  Objects: %d, ScriptStructClass: 0x%llX",
                   ReadAt<int32_t>(g_objArrayBase, TObjOff::NumElements),
                   (unsigned long long)targets.scriptStructClass);
            LogMsg("  SocketsFragment: 0x%llX, SavableFragment: 0x%llX, MassFragment: 0x%llX",
                   (unsigned long long)targets.socketsFragment,
                   (unsigned long long)targets.savableFragment,
                   (unsigned long long)targets.massFragment);
            return false;
        }

        Sleep(100);
    }

    LogMsg("  CrLogisticsSocketsFragment at 0x%llX", (unsigned long long)targets.socketsFragment);
    LogMsg("  CrMassSavableFragment      at 0x%llX", (unsigned long long)targets.savableFragment);
    LogMsg("  MassFragment               at 0x%llX", (unsigned long long)targets.massFragment);

    // ---- Step 5: Pre-patch diagnostics ----
    LogMsg("=== Pre-patch diagnostics ===");
    DumpStructInfo(g_scan.fnNameToString, "CrLogisticsSocketsFragment", targets.socketsFragment);
    DumpStructInfo(g_scan.fnNameToString, "CrMassSavableFragment", targets.savableFragment);

    // ---- Step 6: Check if hierarchy patch already applied ----
    uintptr_t currentSuper = ReadAt<uintptr_t>(targets.socketsFragment, UStructOff::SuperStruct);
    char nameBuf[256];

    if (currentSuper == targets.savableFragment) {
        LogMsg("SuperStruct already points to CrMassSavableFragment — hierarchy patch already applied!");
    } else {
        if (currentSuper != targets.massFragment) {
            if (currentSuper) {
                const wchar_t* ws = NameToString(g_scan.fnNameToString,
                                                  currentSuper + UObjOff::NamePrivate);
                WideToNarrow(ws, nameBuf, sizeof(nameBuf));
            } else {
                strcpy(nameBuf, "(null)");
            }
            LogMsg("WARNING: Unexpected SuperStruct: 0x%llX (%s)",
                   (unsigned long long)currentSuper, nameBuf);
        }

        // ---- Step 7: Apply hierarchy chain patch (v1) ----
        LogMsg("=== Applying hierarchy chain patch (v1) ===");

        if (!PatchHierarchyChain(targets.socketsFragment, targets.savableFragment)) {
            LogMsg("ERROR: Hierarchy chain patch failed");
            return false;
        }

        // Verify
        uintptr_t newSuper = ReadAt<uintptr_t>(targets.socketsFragment, UStructOff::SuperStruct);
        if (newSuper != targets.savableFragment) {
            LogMsg("ERROR: SuperStruct verification failed");
            return false;
        }

        const wchar_t* ws = NameToString(g_scan.fnNameToString, newSuper + UObjOff::NamePrivate);
        WideToNarrow(ws, nameBuf, sizeof(nameBuf));
        LogMsg("VERIFIED: SuperStruct now -> %s (0x%llX)", nameBuf, (unsigned long long)newSuper);

        LogMsg("=== Post-patch diagnostics ===");
        DumpStructInfo(g_scan.fnNameToString, "CrLogisticsSocketsFragment", targets.socketsFragment);
    }

    // ---- Step 8: Install OnPostSaveLoaded hook (v2) ----
    if (!v2Possible) {
        LogMsg("v2 signal hook skipped (missing RVAs). Hierarchy patch (v1) applied.");
        DWORD totalElapsed = GetTickCount() - startTime;
        LogMsg("Total setup time: %lu ms", totalElapsed);
        return true;
    }

    LogMsg("=== Installing OnPostSaveLoaded hook (v2) ===");

    // Discover signal name from CDO
    LogMsg("Discovering signal name from CrLogisticsSocketsSignalProcessor CDO...");
    if (DiscoverSignalName()) {
        g_signalReady = true;
        LogMsg("Signal name discovered from CDO");
    } else {
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

    // Find UMassSignalSubsystem
    FindSignalSubsystem();  // OK if not found yet — will retry in hook

    // Verify OnPostSaveLoaded prologue
    LogMsg("Verifying OnPostSaveLoaded prologue at 0x%llX...",
           (unsigned long long)g_scan.fnOnPostSaveLoaded);

    uint8_t* prologue = (uint8_t*)g_scan.fnOnPostSaveLoaded;
    bool prologueOK =
        prologue[0] == 0x40 && prologue[1] == 0x53 &&
        prologue[2] == 0x48 && prologue[3] == 0x83 &&
        prologue[4] == 0xEC && prologue[5] == 0x20 &&
        prologue[6] == 0x48 && prologue[7] == 0x8B &&
        prologue[8] == 0xD9 &&
        prologue[9] == 0xE8;

    if (!prologueOK) {
        LogMsg("ERROR: OnPostSaveLoaded prologue mismatch!");
        LogMsg("  Expected: 40 53 48 83 EC 20 48 8B D9 E8 xx xx xx xx");
        LogMsg("  Got:      %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
               prologue[0], prologue[1], prologue[2], prologue[3], prologue[4],
               prologue[5], prologue[6], prologue[7], prologue[8], prologue[9]);
        LogMsg("v2 hook skipped — hierarchy patch (v1) is still active");
        DWORD totalElapsed = GetTickCount() - startTime;
        LogMsg("Total setup time: %lu ms", totalElapsed);
        return true;  // v1 patch still applied, partial success
    }
    LogMsg("  Prologue verified: push rbx; sub rsp,20h; mov rbx,rcx; call rel32");

    // Install the hook (steal 14 bytes)
    if (!InstallHook(g_postSaveHook, g_scan.fnOnPostSaveLoaded,
                     (void*)Detour_OnPostSaveLoaded, 14)) {
        LogMsg("ERROR: Failed to install OnPostSaveLoaded hook");
        LogMsg("v2 hook failed — hierarchy patch (v1) is still active");
        DWORD totalElapsed = GetTickCount() - startTime;
        LogMsg("Total setup time: %lu ms", totalElapsed);
        return true;  // v1 patch still applied, partial success
    }

    LogMsg("OnPostSaveLoaded hook installed successfully");

    DWORD totalElapsed = GetTickCount() - startTime;
    LogMsg("Total setup time: %lu ms", totalElapsed);
    LogMsg("=== v1 (hierarchy patch) + v2 (signal hook) both active ===");

    return true;
}

// ===================================================================
// CleanupPatch — restore hooks and hierarchy on DLL unload
// ===================================================================

void CleanupPatch() {
    // Restore inline hook
    if (g_postSaveHook.installed) {
        RemoveHook(g_postSaveHook);
    }

    // Restore original hierarchy chain
    if (g_socketsStruct != 0 && g_origChain != nullptr) {
        DWORD oldProtect;
        uintptr_t patchStart = g_socketsStruct + UStructOff::InheritanceChain;
        if (VirtualProtect((void*)patchStart, 0x18, PAGE_READWRITE, &oldProtect)) {
            WriteAt<uintptr_t*>(g_socketsStruct, UStructOff::InheritanceChain, g_origChain);
            WriteAt<int32_t>   (g_socketsStruct, UStructOff::HierarchyDepth,   g_origDepth);
            WriteAt<uintptr_t> (g_socketsStruct, UStructOff::SuperStruct,      g_origSuperStruct);
            VirtualProtect((void*)patchStart, 0x18, oldProtect, &oldProtect);
        }

        g_socketsStruct   = 0;
        g_origChain       = nullptr;
        g_origDepth       = 0;
        g_origSuperStruct = 0;
    }

    if (g_newChain) {
        VirtualFree(g_newChain, 0, MEM_RELEASE);
        g_newChain = nullptr;
    }
}
