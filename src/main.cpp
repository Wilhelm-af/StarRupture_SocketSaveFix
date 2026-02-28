#include <windows.h>
#include <cstdio>
#include <cstdarg>
#include <cstring>

extern bool ApplyPatch();
extern void CleanupPatch();

// ===================================================================
// Globals shared with other modules
// ===================================================================

static FILE* g_log    = nullptr;
char         g_modDir[MAX_PATH] = {};

// ===================================================================
// Logging
// ===================================================================

void LogMsg(const char* fmt, ...) {
    if (!g_log) return;

    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(g_log, "[%02d:%02d:%02d.%03d] ",
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    va_list ap;
    va_start(ap, fmt);
    vfprintf(g_log, fmt, ap);
    va_end(ap);

    fprintf(g_log, "\n");
    fflush(g_log);
}

// ===================================================================
// Background patch thread
// ===================================================================

static DWORD WINAPI PatchThread(LPVOID param) {
    // Build paths relative to our DLL location
    char dllPath[MAX_PATH];
    GetModuleFileNameA((HMODULE)param, dllPath, MAX_PATH);

    // Extract directory
    char* lastSep = nullptr;
    for (char* p = dllPath; *p; ++p)
        if (*p == '\\' || *p == '/') lastSep = p;

    if (lastSep) {
        size_t dirLen = (size_t)(lastSep - dllPath);
        memcpy(g_modDir, dllPath, dirLen);
        g_modDir[dirLen] = '\0';
        strcpy(lastSep + 1, "socket_save_fix.log");
    } else {
        strcpy(g_modDir, ".");
        strcpy(dllPath, "socket_save_fix.log");
    }

    g_log = fopen(dllPath, "w");
    if (!g_log) return 1;

    LogMsg("=== SocketSaveFix v2.0 ===");
    LogMsg("DLL dir: %s", g_modDir);
    LogMsg("Log:     %s", dllPath);

    // Wait for the exe module to be fully mapped, then install hooks.
    // The UObject system needs to be populated before we can resolve symbols.
    LogMsg("Starting initialization...");

    bool ok = ApplyPatch();

    LogMsg("=== %s ===", ok ? "SUCCESS" : "FAILED");
    fclose(g_log);
    g_log = nullptr;
    return ok ? 0 : 1;
}

// ===================================================================
// DLL entry point
// ===================================================================

extern "C" BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        CreateThread(nullptr, 0, PatchThread, (LPVOID)hinstDLL, 0, nullptr);
    }
    else if (fdwReason == DLL_PROCESS_DETACH && lpReserved == nullptr) {
        // Explicit unload (FreeLibrary) — restore hooks to prevent crashes
        // during engine teardown.  Skip if lpReserved != nullptr (process exit).
        CleanupPatch();
    }
    return TRUE;
}
