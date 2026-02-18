#include "patcher.h"
#include "scanner.h"
#include "ue_types.h"
#include <windows.h>
#include <cstring>
#include <cwchar>

extern void LogMsg(const char* fmt, ...);

// ===================================================================
// Helper: resolve an FName to a narrow string  (reuses one FString)
// ===================================================================

static FString g_fstr = { nullptr, 0, 0 };

// Returns a pointer to a static wchar buffer.  NOT thread-safe.
static const wchar_t* NameToString(FNameToStringFn fn, uintptr_t namePtr) {
    g_fstr.Num = 0;
    fn((const void*)namePtr, &g_fstr);
    return g_fstr.Data;
}

// Compare FName result to an ASCII C-string
static bool NameEqualsA(FNameToStringFn fn, uintptr_t namePtr, const char* target) {
    const wchar_t* ws = NameToString(fn, namePtr);
    if (!ws) return false;
    size_t tlen = strlen(target);
    for (size_t i = 0; i < tlen; ++i) {
        if (ws[i] != (wchar_t)(unsigned char)target[i]) return false;
    }
    return ws[tlen] == L'\0';
}

// Convert wchar to narrow for logging (truncates non-ASCII)
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
            // Each entry is (ancestorStructPtr + 0x30), so subtract 0x30 to get the struct
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

    // SuperStruct
    uintptr_t super = ReadAt<uintptr_t>(scriptStruct, UStructOff::SuperStruct);
    if (super) {
        const wchar_t* ws = NameToString(fn, super + UObjOff::NamePrivate);
        WideToNarrow(ws, nameBuf, sizeof(nameBuf));
    } else {
        strcpy(nameBuf, "(null)");
    }
    LogMsg("  %s.SuperStruct      = 0x%llX (%s)", label,
           (unsigned long long)super, nameBuf);

    // Hierarchy chain
    DumpHierarchyChain(fn, label, scriptStruct);

    // PropertiesSize
    int32_t propsSize = ReadAt<int32_t>(scriptStruct, UStructOff::PropertiesSize);
    LogMsg("  %s.PropertiesSize   = %d (0x%X)", label, propsSize, propsSize);

    // StructFlags
    uint32_t flags = ReadAt<uint32_t>(scriptStruct, UScriptStructOff::StructFlags);
    LogMsg("  %s.StructFlags      = 0x%08X", label, flags);
}

// ===================================================================
// Find all three targets in one pass.  Returns true when all found.
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

static uintptr_t* g_newChain = nullptr;  // leaked intentionally (tiny, permanent)

static bool PatchHierarchyChain(uintptr_t socketsStruct, uintptr_t savableStruct) {
    // Read current chain info for sockets fragment
    int32_t sockDepth = ReadAt<int32_t>(socketsStruct, UStructOff::HierarchyDepth);
    uintptr_t* sockChain = ReadAt<uintptr_t*>(socketsStruct, UStructOff::InheritanceChain);

    // Read savable fragment's info
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

    // Verify the chain's self-entry is correct
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
    // Old chain: [root, ..., FMassFragment, socketsFragment]  (sockDepth+1 entries)
    // New chain: [root, ..., FMassFragment, savableFragment, socketsFragment]  (sockDepth+2 entries)
    int newSize = sockDepth + 2;
    LogMsg("Building new chain: %d -> %d entries", sockDepth + 1, newSize);

    // Allocate permanent memory for the new chain
    g_newChain = (uintptr_t*)VirtualAlloc(
        nullptr, newSize * sizeof(uintptr_t),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!g_newChain) {
        LogMsg("ERROR: VirtualAlloc failed for new chain");
        return false;
    }

    // Copy entries before the insertion point
    for (int i = 0; i < savDepth; ++i) {
        g_newChain[i] = sockChain[i];
    }

    // Insert savable fragment's identity at its depth
    g_newChain[savDepth] = savIdentity;

    // Copy remaining entries (shifted by 1), including self
    for (int i = savDepth; i <= sockDepth; ++i) {
        g_newChain[i + 1] = sockChain[i];
    }

    // Log the new chain
    for (int i = 0; i < newSize; ++i) {
        LogMsg("  newChain[%d] = 0x%llX%s%s",
               i, (unsigned long long)g_newChain[i],
               (g_newChain[i] == savIdentity) ? " [SAVABLE]" : "",
               (g_newChain[i] == sockIdentity) ? " [SELF]" : "");
    }

    // Apply the patch: update chain pointer, depth, and SuperStruct
    uintptr_t patchStart = socketsStruct + UStructOff::InheritanceChain;
    // Unprotect the entire region from +0x30 to +0x48 (InheritanceChain + HierarchyDepth + SuperStruct)
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
        // Test the IsChildOf logic ourselves
        uintptr_t testEntry = g_newChain[savDepth];
        bool isChildOf = (savDepth <= verifyDepth) && (testEntry == savIdentity);
        LogMsg("  IsChildOf(CrMassSavableFragment) = %s", isChildOf ? "TRUE" : "FALSE");
    }

    return ok;
}

// ===================================================================
// ApplyPatch — main logic
// ===================================================================

bool ApplyPatch() {
    // ---- Step 1: Scan for engine symbols ----
    ScanResults scan;
    if (!ScanForEngineSymbols(scan)) {
        return false;
    }

    uintptr_t objArrayBase = scan.guObjectArray + GUObjOff::ObjObjects;

    // ---- Step 2: Aggressively poll for target structs ----
    LogMsg("Polling for target UScriptStructs (100ms intervals, 120s timeout)...");

    TargetStructs targets = {};
    DWORD startTime = GetTickCount();

    for (int attempt = 0; attempt < 1200; ++attempt) {
        int32_t numEl = ReadAt<int32_t>(objArrayBase, TObjOff::NumElements);

        if (numEl > 0 && scan.fnNameToString) {
            uintptr_t firstObj = GetObject(objArrayBase, 0);
            if (firstObj) {
                const wchar_t* ws = NameToString(scan.fnNameToString, firstObj + UObjOff::NamePrivate);
                if (ws && ws[0] != L'\0') {
                    if (FindTargets(objArrayBase, scan.fnNameToString, targets)) {
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
                   ReadAt<int32_t>(objArrayBase, TObjOff::NumElements),
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

    // ---- Step 3: Diagnostics — dump struct info BEFORE patch ----
    LogMsg("=== Pre-patch diagnostics ===");
    DumpStructInfo(scan.fnNameToString, "CrLogisticsSocketsFragment", targets.socketsFragment);
    DumpStructInfo(scan.fnNameToString, "CrMassSavableFragment", targets.savableFragment);

    // Also dump a known-working savable fragment for reference
    uintptr_t agentFragment = 0;
    {
        int32_t numEl = ReadAt<int32_t>(objArrayBase, TObjOff::NumElements);
        for (int32_t i = 0; i < numEl; ++i) {
            uintptr_t obj = GetObject(objArrayBase, i);
            if (!obj) continue;
            uintptr_t cls = ReadAt<uintptr_t>(obj, UObjOff::ClassPrivate);
            if (cls != targets.scriptStructClass) continue;
            if (NameEqualsA(scan.fnNameToString, obj + UObjOff::NamePrivate, "CrLogisticsAgentFragment")) {
                agentFragment = obj;
                break;
            }
        }
    }
    if (agentFragment) {
        LogMsg("=== Reference: known savable fragment ===");
        DumpStructInfo(scan.fnNameToString, "CrLogisticsAgentFragment", agentFragment);
    }

    // ---- Step 4: Check if patch already applied ----
    uintptr_t currentSuper = ReadAt<uintptr_t>(targets.socketsFragment, UStructOff::SuperStruct);
    char nameBuf[256];

    if (currentSuper == targets.savableFragment) {
        LogMsg("SuperStruct already points to CrMassSavableFragment — patch already applied!");
        return true;
    }

    if (currentSuper != targets.massFragment) {
        if (currentSuper) {
            const wchar_t* ws = NameToString(scan.fnNameToString, currentSuper + UObjOff::NamePrivate);
            WideToNarrow(ws, nameBuf, sizeof(nameBuf));
        } else {
            strcpy(nameBuf, "(null)");
        }
        LogMsg("WARNING: Unexpected SuperStruct: 0x%llX (%s)",
               (unsigned long long)currentSuper, nameBuf);
    }

    // ---- Step 5: Patch hierarchy chain + SuperStruct ----
    LogMsg("=== Applying hierarchy chain patch ===");

    if (!PatchHierarchyChain(targets.socketsFragment, targets.savableFragment)) {
        LogMsg("ERROR: Hierarchy chain patch failed");
        return false;
    }

    // ---- Step 6: Verify ----
    uintptr_t newSuper = ReadAt<uintptr_t>(targets.socketsFragment, UStructOff::SuperStruct);
    if (newSuper != targets.savableFragment) {
        LogMsg("ERROR: SuperStruct verification failed");
        return false;
    }

    const wchar_t* ws = NameToString(scan.fnNameToString, newSuper + UObjOff::NamePrivate);
    WideToNarrow(ws, nameBuf, sizeof(nameBuf));
    LogMsg("VERIFIED: SuperStruct now -> %s (0x%llX)", nameBuf, (unsigned long long)newSuper);

    // ---- Step 7: Post-patch diagnostics ----
    LogMsg("=== Post-patch diagnostics ===");
    DumpStructInfo(scan.fnNameToString, "CrLogisticsSocketsFragment", targets.socketsFragment);

    DWORD totalElapsed = GetTickCount() - startTime;
    LogMsg("Total patch time: %lu ms", totalElapsed);

    return true;
}
