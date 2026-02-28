#pragma once
#include <cstdint>
#include "ue_types.h"

struct ScanResults {
    uintptr_t       guObjectArray;      // Base of GUObjectArray
    FNameToStringFn fnNameToString;     // FName::ToString function pointer
    uintptr_t       fnOnPostSaveLoaded; // UCrMassSaveSubsystem::OnPostSaveLoaded address
    SignalEntityFn  fnSignalEntity;     // UMassSignalSubsystem::SignalEntity function pointer
};

// Scan the main game module for GUObjectArray and FName::ToString.
// Falls back to socket_save_fix.ini if AOB patterns fail.
bool ScanForEngineSymbols(ScanResults& out);
