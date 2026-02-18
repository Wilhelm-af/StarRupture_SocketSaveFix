#include "scanner.h"
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>

extern void LogMsg(const char* fmt, ...);
extern char g_modDir[];

// ===================================================================
// Helpers
// ===================================================================

static uintptr_t g_moduleBase = 0;
static size_t    g_moduleSize = 0;

static bool GetMainModule(uintptr_t& base, size_t& imageSize) {
    base = (uintptr_t)GetModuleHandleA(nullptr);
    if (!base) return false;

    auto* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

    auto* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    imageSize = nt->OptionalHeader.SizeOfImage;
    return true;
}

// ---------------------------------------------------------------------------
// Pattern scanner  — format: "48 8B 05 ?? ?? ?? ?? 48"
// ---------------------------------------------------------------------------

struct ParsedPattern {
    uint8_t bytes[128];
    bool    check[128];
    size_t  len;
};

static bool ParsePattern(const char* patStr, ParsedPattern& pp) {
    pp.len = 0;
    const char* p = patStr;
    while (*p && pp.len < 128) {
        while (*p == ' ') p++;
        if (!*p) break;
        if (p[0] == '?' && p[1] == '?') {
            pp.bytes[pp.len] = 0;
            pp.check[pp.len] = false;
            pp.len++;
            p += 2;
        } else {
            char hex[3] = { p[0], p[1], 0 };
            pp.bytes[pp.len] = (uint8_t)strtoul(hex, nullptr, 16);
            pp.check[pp.len] = true;
            pp.len++;
            p += 2;
        }
    }
    return pp.len > 0;
}

// Find first match starting from 'startOffset' within the image
static uintptr_t FindPatternFrom(uintptr_t base, size_t size,
                                 const ParsedPattern& pp, size_t startOffset = 0)
{
    const uint8_t* mem = (const uint8_t*)base;
    for (size_t i = startOffset; i + pp.len <= size; ++i) {
        bool match = true;
        for (size_t j = 0; j < pp.len; ++j) {
            if (pp.check[j] && mem[i + j] != pp.bytes[j]) {
                match = false;
                break;
            }
        }
        if (match) return base + i;
    }
    return 0;
}

static uintptr_t FindPattern(uintptr_t base, size_t size, const char* patStr) {
    ParsedPattern pp;
    if (!ParsePattern(patStr, pp)) return 0;
    return FindPatternFrom(base, size, pp);
}

// Resolve RIP-relative displacement
static uintptr_t ResolveRIP(uintptr_t instrAddr, int dispOff, int instrLen) {
    int32_t disp = *(int32_t*)(instrAddr + dispOff);
    return instrAddr + instrLen + disp;
}

// ===================================================================
// GUObjectArray validation
// ===================================================================

static bool ValidateGUObjectArray(uintptr_t candidate) {
    // Must point past the module base (GUObjectArray is in .data/.bss,
    // which sits after .text in the virtual address space)
    if (candidate < g_moduleBase)
        return false;

    // At early startup the array may not be populated yet — that's OK.
    // We only reject clearly invalid addresses (outside any reasonable range).
    // The .data section for a 240MB exe is typically within +0x20000000 of base.
    if (candidate >= g_moduleBase + g_moduleSize + 0x20000000)
        return false;

    // If the array IS populated, do a sanity check
    uintptr_t objArrayBase = candidate + GUObjOff::ObjObjects;
    int32_t numElements  = ReadAt<int32_t>(objArrayBase, TObjOff::NumElements);
    int32_t numChunks    = ReadAt<int32_t>(objArrayBase, TObjOff::NumChunks);

    if (numElements > 0) {
        // Array is populated — validate consistency
        if (numElements > 10000000 || numChunks <= 0 || numChunks > 500)
            return false;

        uintptr_t objectsPtr = ReadAt<uintptr_t>(objArrayBase, TObjOff::Objects);
        if (objectsPtr == 0) return false;
    }
    // If numElements == 0, accept the address — patcher will poll until populated

    return true;
}

// ===================================================================
// Fallback: read addresses from socket_save_fix.ini
//
// Supports both absolute addresses and RVAs:
//   GUObjectArray=0x14E137A30       (absolute)
//   GUObjectArray_RVA=0xE137A30     (added to module base)
//   FNameToString=0x1414B13A0       (absolute)
//   FNameToString_RVA=0x14B13A0     (added to module base)
// ===================================================================
static bool ReadFallbackConfig(ScanResults& out) {
    char path[MAX_PATH];
    snprintf(path, MAX_PATH, "%s\\socket_save_fix.ini", g_modDir);

    FILE* f = fopen(path, "r");
    if (!f) return false;

    LogMsg("Reading fallback config: %s", path);
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == ';' || line[0] == '\n' || line[0] == '\r')
            continue;

        unsigned long long val;

        // GUObjectArray absolute
        if (sscanf(line, "GUObjectArray=0x%llx", &val) == 1) {
            out.guObjectArray = (uintptr_t)val;
            LogMsg("  GUObjectArray = 0x%llX (absolute)", val);
        }
        // GUObjectArray RVA
        if (sscanf(line, "GUObjectArray_RVA=0x%llx", &val) == 1) {
            out.guObjectArray = g_moduleBase + (uintptr_t)val;
            LogMsg("  GUObjectArray = 0x%llX (base + RVA 0x%llX)",
                   (unsigned long long)out.guObjectArray, val);
        }
        // FNameToString absolute
        if (sscanf(line, "FNameToString=0x%llx", &val) == 1) {
            out.fnNameToString = (FNameToStringFn)(uintptr_t)val;
            LogMsg("  FNameToString = 0x%llX (absolute)", val);
        }
        // FNameToString RVA
        if (sscanf(line, "FNameToString_RVA=0x%llx", &val) == 1) {
            out.fnNameToString = (FNameToStringFn)(g_moduleBase + (uintptr_t)val);
            LogMsg("  FNameToString = 0x%llX (base + RVA 0x%llX)",
                   (unsigned long long)(g_moduleBase + val), val);
        }
    }
    fclose(f);
    return out.guObjectArray != 0 && out.fnNameToString != nullptr;
}

// ===================================================================
// GUObjectArray patterns
// ===================================================================

struct GUAPattern {
    const char* name;
    const char* aob;
    int  dispOff;       // offset of disp32 within the matched bytes
    int  instrLen;      // total length of the instruction containing the disp
    int  adjust;        // post-resolve adjustment to reach GUObjectArray base
};

static const GUAPattern guaPatterns[] = {
    // Pattern A: Function prologue with lea rcx,[GUObjectArray] after INT3 padding
    //   CC CC 48 83 EC 28 48 8D 0D [disp] E8 [disp] 48 8D 0D
    // Found in game at RVA 0xDF7510 — very specific due to INT3+sub+lea+call+lea combo
    { "GUA-A (INT3+sub28+lea+call+lea)",
      "CC CC 48 83 EC 28 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 0D",
      8, 13, 0 },

    // Pattern B: 48 8B D3 48 8D 0D [GUObjectArray] 48 83 C4 20 5B E9
    //   mov rdx,rbx ; lea rcx,[GUObjectArray] ; add rsp,20h ; pop rbx ; jmp (tail call)
    // Found at RVA 0x1686D91
    { "GUA-B (mov rdx+lea+epilogue+jmp tail call)",
      "48 8B D3 48 8D 0D ?? ?? ?? ?? 48 83 C4 20 5B E9",
      5, 10, 0 },

    // Pattern C: 48 8B D3 48 8D 0D [GUObjectArray] E8
    //   mov rdx,rbx ; lea rcx,[GUObjectArray] ; call
    // More generic but still specific due to the mov+lea+call triplet
    { "GUA-C (mov rdx,rbx + lea rcx + call)",
      "48 8B D3 48 8D 0D ?? ?? ?? ?? E8",
      5, 10, 0 },

    // Pattern D: Original chunked access pattern
    //   mov rax,[rip+ObjObjects.Objects] ; mov rcx,[rax+rcx*8] ; lea rax,[rcx+rdx*8]
    { "GUA-D (chunked access: 48 8B 05 + 48 8B 0C C8 + 48 8D 04 D1)",
      "48 8B 05 ?? ?? ?? ?? 48 8B 0C C8 48 8D 04 D1",
      3, 7, -0x10 },
};

// ===================================================================
// FName::ToString patterns
// ===================================================================

struct FNTPattern {
    const char* name;
    const char* aob;
};

static const FNTPattern fntPatterns[] = {
    // Pattern A: Exact match for this game's UE5 build
    //   Save rbx[+10h], rsi[+18h], push rdi, sub rsp 20h,
    //   cmp byte [rip+??],0 (name pool init check), mov rdi,rdx, mov ebx,[rcx]
    // This is the actual prologue from PDB-verified FName::ToString(FString&) const
    { "FNT-A (save rbx/rsi + sub20 + global flag check + mov ebx,[rcx])",
      "48 89 5C 24 10 48 89 74 24 18 57 48 83 EC 20 80 3D ?? ?? ?? ?? 00 48 8B FA 8B 19 48 8B F1" },

    // Pattern B: Slightly shorter version (without the final mov rsi,rcx)
    { "FNT-B (save rbx/rsi + sub20 + global flag check + mov edi,rdx)",
      "48 89 5C 24 10 48 89 74 24 18 57 48 83 EC 20 80 3D ?? ?? ?? ?? 00 48 8B FA 8B 19" },

    // Pattern C: Even shorter — just prologue + global flag check
    { "FNT-C (save rbx/rsi + sub20 + cmp byte [rip+??],0)",
      "48 89 5C 24 10 48 89 74 24 18 57 48 83 EC 20 80 3D ?? ?? ?? ?? 00" },

    // Pattern D: Older UE5 builds without the global flag check (checks Number directly)
    { "FNT-D (save rbx + push rdi + sub30 + cmp [rcx+4],0)",
      "48 89 5C 24 ?? 57 48 83 EC 30 83 79 04 00" },

    // Pattern E: Another older variant
    { "FNT-E (3 reg saves + sub20 + cmp [rcx+4],0)",
      "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC 20 83 79 04 00" },
};

// ===================================================================
// ScanForEngineSymbols
// ===================================================================

bool ScanForEngineSymbols(ScanResults& out) {
    out.guObjectArray  = 0;
    out.fnNameToString = nullptr;

    if (!GetMainModule(g_moduleBase, g_moduleSize)) {
        LogMsg("ERROR: Cannot get main module info");
        return false;
    }
    LogMsg("Main module: base=0x%llX  size=0x%llX (%llu MB)",
           (unsigned long long)g_moduleBase,
           (unsigned long long)g_moduleSize,
           (unsigned long long)(g_moduleSize / (1024 * 1024)));

    // ---- Try INI config first (fast, safe, no memory scanning) ----
    if (ReadFallbackConfig(out)) {
        LogMsg("Loaded addresses from INI — skipping AOB scan");
    } else {
        // ---- AOB scan fallback ----
        LogMsg("No INI config found, falling back to AOB scan...");

        LogMsg("Scanning for GUObjectArray...");
        for (const auto& pat : guaPatterns) {
            ParsedPattern pp;
            if (!ParsePattern(pat.aob, pp)) continue;

            size_t searchOffset = 0;
            int attempts = 0;
            while (attempts < 50) {
                uintptr_t match = FindPatternFrom(g_moduleBase, g_moduleSize, pp, searchOffset);
                if (!match) break;

                uintptr_t resolved = ResolveRIP(match, pat.dispOff, pat.instrLen);
                uintptr_t candidate = resolved + pat.adjust;
                attempts++;

                if (ValidateGUObjectArray(candidate)) {
                    out.guObjectArray = candidate;
                    LogMsg("  FOUND via %s (attempt %d) at 0x%llX",
                           pat.name, attempts, (unsigned long long)candidate);
                    break;
                }
                searchOffset = (match - g_moduleBase) + 1;
            }
            if (out.guObjectArray) break;
            LogMsg("  %s: %s", pat.name,
                   attempts > 0 ? "matched but validation failed" : "no match");
        }

        LogMsg("Scanning for FName::ToString...");
        for (const auto& pat : fntPatterns) {
            uintptr_t match = FindPattern(g_moduleBase, g_moduleSize, pat.aob);
            if (match) {
                out.fnNameToString = (FNameToStringFn)match;
                LogMsg("  FOUND via %s at 0x%llX", pat.name, (unsigned long long)match);
                break;
            }
            LogMsg("  %s: no match", pat.name);
        }

        if (!out.guObjectArray || !out.fnNameToString) {
            LogMsg("=========================================================");
            LogMsg("ERROR: Could not locate required engine symbols.");
            LogMsg("Create  socket_save_fix.ini  next to the DLL:");
            LogMsg("  GUObjectArray_RVA=0xE137A30");
            LogMsg("  FNameToString_RVA=0x14B13A0");
            LogMsg("=========================================================");
            return false;
        }
    }

    // ---- Log current state ----
    if (out.guObjectArray) {
        uintptr_t objArrayBase = out.guObjectArray + GUObjOff::ObjObjects;
        int32_t numElements = ReadAt<int32_t>(objArrayBase, TObjOff::NumElements);
        int32_t numChunks   = ReadAt<int32_t>(objArrayBase, TObjOff::NumChunks);
        LogMsg("GUObjectArray state: NumElements=%d  NumChunks=%d %s",
               numElements, numChunks,
               numElements == 0 ? "(not yet populated — patcher will poll)" : "(populated)");
    }

    return out.guObjectArray != 0 && out.fnNameToString != nullptr;
}
