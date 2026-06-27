#ifndef INJECTION_H
#define INJECTION_H

#include <windows.h>
#include <string>
#include <vector>

namespace injection {
    // ===== PROCESS MANAGEMENT =====

    // Find process by name
    DWORD FindProcessByName(const std::wstring& processName);

    // Notepad-specific functions
    DWORD FindNotepadPID();
    bool CreateAndInjectIntoNotepad(const char* dllPath);

    // Privilege and admin functions
    bool IsProcessAdmin(DWORD pid);
    bool IsCurrentProcessAdmin();
    bool EnableDebugPrivilege();

    // ===== CORE INJECTION FUNCTIONS =====

    // Main injection function
    bool PerformInjection(DWORD targetPid, const char* dllPath);

    // High-level injection functions
    void InjectDLLIntoNotepad(const char* dllPath);
    void InjectDLLIntoSvchost(const char* dllPath);

    // DLL loading and management
    void LoadDLLFromSystem32(const char* dllName, const char* funcName = "Main");

    // ===== PROVIDER-SPECIFIC FUNCTIONS =====

    // Provider injection functions
    void tz();
    void tzx();
    void ghost();
    void keyser();
    void goath();
    void macho();

    // ===== UTILITY FUNCTIONS =====

    // File and path utilities
    std::string GetSystem32Path();
    bool FileExists(const std::string& path);

    // Process utilities
    void WaitForProcessExit(DWORD pid, DWORD timeoutMs = 30000);
    void KillProcessByName(const std::wstring& processName);

    // DLL utilities
    HMODULE LoadDLLIntoCurrentProcess(const std::string& dllPath);
    bool ExecuteDLLFunction(const std::string& dllPath, const std::string& functionName);

    // ===== CONFIGURATION =====

    // Target process configuration
    struct TargetProcess {
        std::string name;
        std::wstring executableName;
        bool requiresAdmin = false;
        bool allowMultiple = false;
        bool autoCreateIfMissing = false;
    };

    std::vector<TargetProcess> GetDefaultTargets();
    TargetProcess GetTargetByName(const std::string& name);

    // ===== INJECTION CONTROLS =====

    bool PrepareForInjection();
    void CleanupAfterInjection();
    bool ValidateTargetProcess(DWORD pid, const std::string& expectedName = "");

} // namespace injection

#endif // INJECTION_H