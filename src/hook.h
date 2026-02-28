#pragma once
#include <cstdint>
#include <cstddef>

// ---------------------------------------------------------------------------
// x64 inline hook — steals bytes from a function prologue, replaces with
// an absolute jmp to the detour.  A trampoline preserves the stolen bytes
// so the original function can still be called.
// ---------------------------------------------------------------------------

struct InlineHook {
    uintptr_t target;           // address of the function to hook
    void*     detour;           // address of the detour function
    void*     trampoline;       // allocated executable memory: stolen bytes + jmp back
    uint8_t   origBytes[32];    // backup of stolen bytes (for unhook)
    size_t    stealSize;        // number of bytes stolen (>= 14)
    bool      installed;
};

// Install an inline hook.  stealSize must be >= 14 and must land on an
// instruction boundary.  If the stolen region contains an E8 (call rel32)
// instruction, its displacement is automatically fixed up in the trampoline.
bool InstallHook(InlineHook& hook, uintptr_t target, void* detour, size_t stealSize);

// Remove the hook by restoring original bytes.
void RemoveHook(InlineHook& hook);
