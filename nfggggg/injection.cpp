#include "injection.h"
#include "protection.h"
#include <tlhelp32.h>
#include <psapi.h>
#include <thread>
#include <chrono>
#include <algorithm>
#include <shlwapi.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shlwapi.lib")

namespace injection {

    // ===== PROCESS MANAGEMENT =====

    DWORD FindProcessByName(const std::wstring& processName) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        DWORD pid = 0;

        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe;
            pe.dwSize = sizeof(PROCESSENTRY32W);

            if (Process32FirstW(hSnapshot, &pe)) {
                do {
                    if (_wcsicmp(pe.szExeFile, processName.c_str()) == 0) {
                        pid = pe.th32ProcessID;
                        break;
                    }
                } while (Process32NextW(hSnapshot, &pe));
            }
            CloseHandle(hSnapshot);
        }
        return pid;
    }

    DWORD FindNotepadPID() {
        return FindProcessByName(L"notepad.exe");
    }

    bool IsProcessAdmin(DWORD pid) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!hProcess) return false;

        HANDLE hToken = NULL;
        bool isAdmin = false;

        if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
            TOKEN_ELEVATION elevation;
            DWORD size = sizeof(TOKEN_ELEVATION);

            if (GetTokenInformation(hToken, TokenElevation, &elevation, size, &size)) {
                isAdmin = (elevation.TokenIsElevated != 0);
            }
            CloseHandle(hToken);
        }

        CloseHandle(hProcess);
        return isAdmin;
    }

    bool IsCurrentProcessAdmin() {
        BOOL isAdmin = FALSE;
        HANDLE hToken = NULL;

        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            TOKEN_ELEVATION elevation;
            DWORD size = sizeof(TOKEN_ELEVATION);

            if (GetTokenInformation(hToken, TokenElevation, &elevation, size, &size)) {
                isAdmin = elevation.TokenIsElevated;
            }
            CloseHandle(hToken);
        }
        return isAdmin != FALSE;
    }

    bool EnableDebugPrivilege() {
        HANDLE hToken;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
            return false;
        }

        TOKEN_PRIVILEGES tp;
        LUID luid;

        if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
            CloseHandle(hToken);
            return false;
        }

        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
            CloseHandle(hToken);
            return false;
        }

        CloseHandle(hToken);
        return true;
    }

    // ===== CORE INJECTION FUNCTIONS =====

    __declspec(noinline) bool PerformInjection(DWORD targetPid, const char* dllPath) {
        bool success = false;
        DWORD exitCode = 0;
        try {
            EnableDebugPrivilege();

            HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
            if (!hProcess) {
                hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
                    PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                    FALSE, targetPid);
            }

            if (hProcess) {
                size_t pathSize = strlen(dllPath) + 1;
                LPVOID pRemoteMem = VirtualAllocEx(hProcess, NULL, (DWORD)pathSize,
                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

                if (pRemoteMem) {
                    SIZE_T bytesWritten;
                    if (WriteProcessMemory(hProcess, pRemoteMem, dllPath, pathSize, &bytesWritten) &&
                        bytesWritten == pathSize) {

                        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
                        if (hKernel32) {
                            FARPROC pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryA");
                            HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                (LPTHREAD_START_ROUTINE)pLoadLibrary, pRemoteMem, 0, NULL);

                            if (hThread) {
                                WaitForSingleObject(hThread, 1000);
                                GetExitCodeThread(hThread, &exitCode);
                                CloseHandle(hThread);
                                success = true;
                            }
                        }
                    }
                    VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
                }
                CloseHandle(hProcess);
            }
        } catch (...) {}
        return success && (exitCode != 0);
    }

    // ===== FIXED: Create hidden notepad that doesn't reopen =====

    bool CreateAndInjectIntoNotepad(const char* dllPath) {
        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi = { 0 };

        // KEY FIX: Create notepad with a dummy file argument
        // This prevents the "reopen" behavior
        std::string commandLine = "C:\\Windows\\System32\\notepad.exe C:\\Windows\\System32\\drivers\\etc\\hosts";

        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;

        // Create notepad suspended and hidden
        if (!CreateProcessA(NULL,
            (LPSTR)commandLine.c_str(),
            NULL, NULL, FALSE,
            CREATE_SUSPENDED | CREATE_NO_WINDOW,
            NULL, NULL, &si, &pi)) {
            return false;
        }

        // Wait for process to initialize
        Sleep(200);

        bool success = PerformInjection(pi.dwProcessId, dllPath);

        if (success) {
            ResumeThread(pi.hThread);

            // Force hide window after resume
            for (int i = 0; i < 10; i++) {
                HWND hWnd = NULL;
                EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
                    DWORD pid;
                    GetWindowThreadProcessId(hwnd, &pid);
                    if (pid == *(DWORD*)lParam) {
                        *(HWND*)lParam = hwnd;
                        return FALSE;
                    }
                    return TRUE;
                    }, (LPARAM)&pi.dwProcessId);

                if (hWnd) {
                    ShowWindow(hWnd, SW_HIDE);
                    SetWindowPos(hWnd, 0, 0, 0, 0, 0, SWP_HIDEWINDOW | SWP_NOZORDER | SWP_NOMOVE | SWP_NOSIZE);
                    break;
                }
                Sleep(50);
            }
        }

        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);

        return success;
    }

    void InjectDLLIntoNotepad(const char* dllPath) {
        if (!FileExists(dllPath)) {
            return;
        }

        // Try injection up to 2 times
        bool success = false;
        for (int attempt = 0; attempt < 2 && !success; attempt++) {
            success = CreateAndInjectIntoNotepad(dllPath);

            if (!success && attempt == 0) {
                // Kill any existing notepad before retry
                DWORD existingPid = FindNotepadPID();
                if (existingPid != 0) {
                    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, existingPid);
                    if (hProcess) {
                        TerminateProcess(hProcess, 0);
                        CloseHandle(hProcess);
                        Sleep(200);
                    }
                }
            }
        }

        if (!success) {
            SendDiscordAlert("INJECTION FAILED", dllPath);
        }
    }

    void InjectDLLIntoSvchost(const char* dllPath) {
        InjectDLLIntoNotepad(dllPath);
    }

    // ===== PROVIDER-SPECIFIC FUNCTIONS =====

    void tz() {
        std::string dllPath = GetSystem32Path() + "\\tz_provider.dll";
        if (FileExists(dllPath)) {
            InjectDLLIntoNotepad(dllPath.c_str());
        }
    }

    void tzx() {
        std::string dllPath = GetSystem32Path() + "\\tzx_provider.dll";
        if (FileExists(dllPath)) {
            InjectDLLIntoNotepad(dllPath.c_str());
        }
    }

    void ghost() {
        std::string dllPath = GetSystem32Path() + "\\ghost_provider.dll";
        if (FileExists(dllPath)) {
            InjectDLLIntoNotepad(dllPath.c_str());
        }
    }

    void keyser() {
        std::string dllPath = GetSystem32Path() + "\\keyser_provider.dll";
        if (FileExists(dllPath)) {
            InjectDLLIntoNotepad(dllPath.c_str());
        }
    }

    void goath() {
        std::string dllPath = GetSystem32Path() + "\\goath_provider.dll";
        if (FileExists(dllPath)) {
            InjectDLLIntoNotepad(dllPath.c_str());
        }
    }

    void macho() {
        std::string dllPath = GetSystem32Path() + "\\macho_provider.dll";
        if (FileExists(dllPath)) {
            InjectDLLIntoNotepad(dllPath.c_str());
        }
    }

    // ===== UTILITY FUNCTIONS =====

    std::string GetSystem32Path() {
        char system32Path[MAX_PATH];
        GetSystemDirectoryA(system32Path, MAX_PATH);
        return std::string(system32Path);
    }

    bool FileExists(const std::string& path) {
        return GetFileAttributesA(path.c_str()) != INVALID_FILE_ATTRIBUTES;
    }

    void WaitForProcessExit(DWORD pid, DWORD timeoutMs) {
        HANDLE hProcess = OpenProcess(SYNCHRONIZE, FALSE, pid);
        if (hProcess) {
            WaitForSingleObject(hProcess, timeoutMs);
            CloseHandle(hProcess);
        }
    }

    void KillProcessByName(const std::wstring& processName) {
        DWORD pid = FindProcessByName(processName);
        if (pid > 0) {
            HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
            if (hProcess) {
                TerminateProcess(hProcess, 0);
                CloseHandle(hProcess);
            }
        }
    }

    HMODULE LoadDLLIntoCurrentProcess(const std::string& dllPath) {
        if (!FileExists(dllPath)) {
            return nullptr;
        }
        return LoadLibraryA(dllPath.c_str());
    }

    bool ExecuteDLLFunction(const std::string& dllPath, const std::string& functionName) {
        HMODULE hDll = LoadDLLIntoCurrentProcess(dllPath);
        if (!hDll) {
            return false;
        }

        FARPROC func = GetProcAddress(hDll, functionName.c_str());
        if (!func) {
            FreeLibrary(hDll);
            return false;
        }

        typedef void (*DllFunction)();
        DllFunction dllFunc = (DllFunction)func;
        dllFunc();

        return true;
    }

    // ===== CONFIGURATION =====

    std::vector<TargetProcess> GetDefaultTargets() {
        std::vector<TargetProcess> targets;

        targets.push_back({
            "notepad",
            L"notepad.exe",
            false,
            true,
            true
            });

        targets.push_back({
            "svchost",
            L"svchost.exe",
            true,
            false,
            false
            });

        targets.push_back({
            "explorer",
            L"explorer.exe",
            false,
            false,
            false
            });

        return targets;
    }

    TargetProcess GetTargetByName(const std::string& name) {
        auto targets = GetDefaultTargets();
        for (const auto& target : targets) {
            if (target.name == name) {
                return target;
            }
        }
        return TargetProcess();
    }

    // ===== INJECTION CONTROLS =====

    bool PrepareForInjection() {
        if (!EnableDebugPrivilege()) {
            return false;
        }

        return true;
    }

    void CleanupAfterInjection() {
    }

    bool ValidateTargetProcess(DWORD pid, const std::string& expectedName) {
        if (pid == 0) return false;

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!hProcess) return false;

        WCHAR exePath[MAX_PATH];
        DWORD pathSize = MAX_PATH;
        if (QueryFullProcessImageNameW(hProcess, 0, exePath, &pathSize)) {
            std::wstring fullPath(exePath);
            std::wstring exeName = fullPath.substr(fullPath.find_last_of(L"\\/") + 1);

            if (!expectedName.empty()) {
                std::wstring expectedWide(expectedName.begin(), expectedName.end());
                return _wcsicmp(exeName.c_str(), expectedWide.c_str()) == 0;
            }
        }

        CloseHandle(hProcess);
        return true;
    }

    // ===== DLL LOADING FUNCTION =====

    void LoadDLLFromSystem32(const char* dllName, const char* funcName) {
        std::string dllPath = GetSystem32Path() + "\\" + dllName;

        if (!FileExists(dllPath)) {
            return;
        }

        bool isCleaning = (strcmp(dllName, "cleaning.dll") == 0);
        bool isDestruct = (strcmp(dllName, "dih.dll") == 0 || strstr(dllName, "destruct") != NULL);

        if (isCleaning) {
            ExecuteDLLFunction(dllPath, funcName);
        }
        else {
            // Use the fixed notepad injection method
            InjectDLLIntoNotepad(dllPath.c_str());

            if (isDestruct) {
                std::thread([]() {
                    Sleep(3000); // Give time for destruction
                    }).detach();
            }
        }
    }

} // namespace injection