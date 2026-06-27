#pragma once
#include <windows.h>
#include <tlhelp32.h>

// Dynamic API loading to hide imports from static analysis
// All sensitive Windows APIs are loaded at runtime instead of linked statically

namespace DynamicAPI {

    // ===== KERNEL32.DLL =====

    // Process/Thread APIs
    typedef HANDLE(WINAPI* pCreateRemoteThread)(
        HANDLE hProcess,
        LPSECURITY_ATTRIBUTES lpThreadAttributes,
        SIZE_T dwStackSize,
        LPTHREAD_START_ROUTINE lpStartAddress,
        LPVOID lpParameter,
        DWORD dwCreationFlags,
        LPDWORD lpThreadId
    );

    typedef LPVOID(WINAPI* pVirtualAllocEx)(
        HANDLE hProcess,
        LPVOID lpAddress,
        SIZE_T dwSize,
        DWORD flAllocationType,
        DWORD flProtect
    );

    typedef BOOL(WINAPI* pWriteProcessMemory)(
        HANDLE hProcess,
        LPVOID lpBaseAddress,
        LPCVOID lpBuffer,
        SIZE_T nSize,
        SIZE_T* lpNumberOfBytesWritten
    );

    typedef BOOL(WINAPI* pVirtualProtect)(
        LPVOID lpAddress,
        SIZE_T dwSize,
        DWORD flNewProtect,
        PDWORD lpflOldProtect
    );

    typedef HANDLE(WINAPI* pCreateToolhelp32Snapshot)(
        DWORD dwFlags,
        DWORD th32ProcessID
    );

    typedef BOOL(WINAPI* pModule32FirstW)(
        HANDLE hSnapshot,
        LPMODULEENTRY32W lpme
    );

    typedef BOOL(WINAPI* pModule32NextW)(
        HANDLE hSnapshot,
        LPMODULEENTRY32W lpme
    );

    // ===== NTDLL.DLL =====

    typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
        HANDLE ProcessHandle,
        DWORD ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength,
        PULONG ReturnLength
    );

    // Global function pointers
    extern pCreateRemoteThread fnCreateRemoteThread;
    extern pVirtualAllocEx fnVirtualAllocEx;
    extern pWriteProcessMemory fnWriteProcessMemory;
    extern pVirtualProtect fnVirtualProtect;
    extern pCreateToolhelp32Snapshot fnCreateToolhelp32Snapshot;
    extern pModule32FirstW fnModule32FirstW;
    extern pModule32NextW fnModule32NextW;
    extern pNtQueryInformationProcess fnNtQueryInformationProcess;

    // Initialize all dynamic APIs (call once at startup)
    bool InitializeAPIs();

    // Check if APIs are loaded
    bool AreAPIsLoaded();
}
