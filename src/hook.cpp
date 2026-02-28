#include "hook.h"
#include <windows.h>
#include <cstring>

extern void LogMsg(const char* fmt, ...);

// ---------------------------------------------------------------------------
// Trampoline layout (variable size):
//
//   [stolen bytes, with E8 fixups]     stealSize bytes
//   FF 25 00 00 00 00                  6 bytes  (jmp [rip+0])
//   <absolute 8-byte address>          8 bytes  (target + stealSize)
//
// Total = stealSize + 14
// ---------------------------------------------------------------------------

// 14-byte absolute jmp sequence for x64:
//   FF 25 00 00 00 00   jmp [rip+0]
//   <8-byte address>
static constexpr size_t ABS_JMP_SIZE = 14;

bool InstallHook(InlineHook& hook, uintptr_t target, void* detour, size_t stealSize) {
    if (stealSize < ABS_JMP_SIZE) {
        LogMsg("ERROR: stealSize %zu < %zu minimum", stealSize, ABS_JMP_SIZE);
        return false;
    }

    hook.target    = target;
    hook.detour    = detour;
    hook.stealSize = stealSize;
    hook.installed = false;

    // --- Allocate trampoline (RWX) ---
    size_t trampolineSize = stealSize + ABS_JMP_SIZE;
    hook.trampoline = VirtualAlloc(nullptr, trampolineSize,
                                   MEM_COMMIT | MEM_RESERVE,
                                   PAGE_EXECUTE_READWRITE);
    if (!hook.trampoline) {
        LogMsg("ERROR: VirtualAlloc for trampoline failed (err=%lu)", GetLastError());
        return false;
    }

    // --- Copy stolen bytes to trampoline ---
    memcpy(hook.origBytes, (void*)target, stealSize);
    memcpy(hook.trampoline, (void*)target, stealSize);

    // --- Fix up E8 (call rel32) instructions in the stolen region ---
    // E8 is 5 bytes: opcode + 4-byte signed displacement
    uint8_t* tramp = (uint8_t*)hook.trampoline;
    for (size_t i = 0; i + 5 <= stealSize; ) {
        if (tramp[i] == 0xE8) {
            // Original absolute target = target + i + 5 + old_disp
            int32_t oldDisp;
            memcpy(&oldDisp, tramp + i + 1, 4);
            uintptr_t callTarget = target + i + 5 + (int64_t)oldDisp;

            // New displacement from trampoline location
            uintptr_t newCallSite = (uintptr_t)(tramp + i);
            int64_t newDisp64 = (int64_t)callTarget - (int64_t)(newCallSite + 5);

            // Check if it fits in int32
            if (newDisp64 < INT32_MIN || newDisp64 > INT32_MAX) {
                LogMsg("WARNING: E8 fixup at offset %zu: displacement 0x%llX out of int32 range",
                       i, (unsigned long long)newDisp64);
                // This can happen if trampoline is allocated far from the original code.
                // Fall through — the call will crash, but we log it.
            }

            int32_t newDisp = (int32_t)newDisp64;
            memcpy(tramp + i + 1, &newDisp, 4);

            LogMsg("  E8 fixup at stolen+%zu: old_disp=0x%08X new_disp=0x%08X target=0x%llX",
                   i, (uint32_t)oldDisp, (uint32_t)newDisp,
                   (unsigned long long)callTarget);

            i += 5;
        } else {
            i++;
        }
    }

    // --- Append absolute jmp back to (target + stealSize) ---
    uint8_t* jmpBack = tramp + stealSize;
    jmpBack[0] = 0xFF;
    jmpBack[1] = 0x25;
    jmpBack[2] = 0x00;
    jmpBack[3] = 0x00;
    jmpBack[4] = 0x00;
    jmpBack[5] = 0x00;
    uintptr_t returnAddr = target + stealSize;
    memcpy(jmpBack + 6, &returnAddr, 8);

    // --- Write absolute jmp to detour at the original target ---
    DWORD oldProtect;
    if (!VirtualProtect((void*)target, stealSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        LogMsg("ERROR: VirtualProtect failed (err=%lu)", GetLastError());
        VirtualFree(hook.trampoline, 0, MEM_RELEASE);
        hook.trampoline = nullptr;
        return false;
    }

    uint8_t* dst = (uint8_t*)target;
    dst[0] = 0xFF;
    dst[1] = 0x25;
    dst[2] = 0x00;
    dst[3] = 0x00;
    dst[4] = 0x00;
    dst[5] = 0x00;
    uintptr_t detourAddr = (uintptr_t)detour;
    memcpy(dst + 6, &detourAddr, 8);

    // NOP any remaining stolen bytes beyond the 14-byte jmp
    for (size_t i = ABS_JMP_SIZE; i < stealSize; ++i)
        dst[i] = 0x90;

    VirtualProtect((void*)target, stealSize, oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), (void*)target, stealSize);

    hook.installed = true;

    LogMsg("Hook installed: target=0x%llX -> detour=0x%llX, trampoline=0x%llX, steal=%zu",
           (unsigned long long)target,
           (unsigned long long)(uintptr_t)detour,
           (unsigned long long)(uintptr_t)hook.trampoline,
           stealSize);

    return true;
}

void RemoveHook(InlineHook& hook) {
    if (!hook.installed) return;

    DWORD oldProtect;
    VirtualProtect((void*)hook.target, hook.stealSize, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy((void*)hook.target, hook.origBytes, hook.stealSize);
    VirtualProtect((void*)hook.target, hook.stealSize, oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), (void*)hook.target, hook.stealSize);

    hook.installed = false;
    LogMsg("Hook removed: target=0x%llX", (unsigned long long)hook.target);
}
