#pragma once

// Install an inline hook on UCrMassSaveSubsystem::OnPostSaveLoaded.
// When save data is loaded, the hook triggers socket re-initialization
// via UMassSignalSubsystem::SignalEntity to rebuild logistics socket
// connections that were lost during save/load.
bool ApplyPatch();

// Remove hooks and free trampoline memory.
// Called on DLL_PROCESS_DETACH for clean unload.
void CleanupPatch();
