#define _CRT_SECURE_NO_WARNINGS

#include "protection.h"
#include "security.h"
#include "net_client.h"
#include "secure_capture.h"
#include "string_obfuscation.h"
#include "api_loader.h"
#include "server_config.h"
#include "crash_handler.h"
#include "vmprotect_markers.h"
#include "app_control.h"
#include <winhttp.h>
#include <tlhelp32.h>
#include <sddl.h>
#include <iostream>
#include <sstream>
#include <fstream>
#include <chrono>
#include <thread>
#include <algorithm>
#include <filesystem>
#include <lmcons.h>
#include <iomanip>
#include <set>
#include <mutex>
#include <vector>
#include <array>
#include <limits>
#include <psapi.h>
#include <bcrypt.h>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "psapi.lib")

static void ReportProtectionViolation(const std::string& type, const std::string& message);

namespace {

volatile LONG g_earlyDebuggerDetected = FALSE;
char g_earlyDetectionMethod[64] = {};

bool DetectDebugger(const char*& method) {
    if (IsDebuggerPresent()) {
        method = "IsDebuggerPresent";
        return true;
    }

    BOOL remoteDebugger = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDebugger) && remoteDebugger) {
        method = "CheckRemoteDebuggerPresent";
        return true;
    }

    PTEB teb = NtCurrentTeb();
    if (teb && teb->ProcessEnvironmentBlock && teb->ProcessEnvironmentBlock->BeingDebugged) {
        method = "PEB.BeingDebugged";
        return true;
    }

    using NtQueryInformationProcessFn = NTSTATUS(NTAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    auto queryProcess = reinterpret_cast<NtQueryInformationProcessFn>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
    if (queryProcess) {
        ULONG_PTR debugPort = 0;
        if (queryProcess(GetCurrentProcess(), static_cast<PROCESSINFOCLASS>(7), &debugPort,
                sizeof(debugPort), nullptr) >= 0 && debugPort != 0) {
            method = "ProcessDebugPort";
            return true;
        }

        HANDLE debugObject = nullptr;
        if (queryProcess(GetCurrentProcess(), static_cast<PROCESSINFOCLASS>(30), &debugObject,
                sizeof(debugObject), nullptr) >= 0 && debugObject != nullptr) {
            method = "ProcessDebugObjectHandle";
            if (debugObject != INVALID_HANDLE_VALUE) CloseHandle(debugObject);
            return true;
        }

        ULONG debugFlags = 0;
        if (queryProcess(GetCurrentProcess(), static_cast<PROCESSINFOCLASS>(31), &debugFlags,
                sizeof(debugFlags), nullptr) >= 0 && debugFlags == 0) {
            method = "ProcessDebugFlags";
            return true;
        }
    }

    return false;
}

void NTAPI ProtectionTlsCallback(PVOID, DWORD reason, PVOID) {
    if (reason != DLL_PROCESS_ATTACH) return;
    InstallCrashHandler();

    const char* method = nullptr;
    if (DetectDebugger(method)) {
        InterlockedExchange(&g_earlyDebuggerDetected, TRUE);
        lstrcpynA(g_earlyDetectionMethod, method, static_cast<int>(sizeof(g_earlyDetectionMethod)));
    }
}

} // namespace

#ifdef _WIN64
#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma comment(linker, "/INCLUDE:g_protectionTlsCallback")
#pragma const_seg(".CRT$XLB")
extern "C" const PIMAGE_TLS_CALLBACK g_protectionTlsCallback = ProtectionTlsCallback;
#pragma const_seg()
#else
#pragma comment(linker, "/INCLUDE:__tls_used")
#pragma comment(linker, "/INCLUDE:_g_protectionTlsCallback")
#pragma data_seg(".CRT$XLB")
extern "C" PIMAGE_TLS_CALLBACK g_protectionTlsCallback = ProtectionTlsCallback;
#pragma data_seg()
#endif

void HandleEarlyProtectionDetection() {
    VMP_BEGIN_VIRTUALIZATION("Protection.StartupDebuggerDecision");
    const char* liveMethod = nullptr;
    const bool detectedNow = DetectDebugger(liveMethod);
    if (!g_earlyDebuggerDetected && !detectedNow) {
        VMP_END();
        return;
    }

    const char* method = g_earlyDebuggerDetected ? g_earlyDetectionMethod : liveMethod;
    ReportProtectionViolation("DEBUGGER_DETECTED", std::string("Startup detection: ") + method);
    VMP_END();
    ExitProcess(0xE4);
}

static HINTERNET OpenAuthenticatedRequest(HINTERNET connect, LPCWSTR verb, LPCWSTR path,
    LPCWSTR version, LPCWSTR referrer, LPCWSTR* acceptTypes, DWORD flags) {
    const bool isBackendApi = path && wcsncmp(path, L"/api/", 5) == 0;
    if (isBackendApi) { if (APP_SERVER_TLS) flags |= WINHTTP_FLAG_SECURE; else flags &= ~WINHTTP_FLAG_SECURE; }
    HINTERNET request = ::WinHttpOpenRequest(connect, verb, path, version, referrer, acceptTypes, flags);
    if (request && isBackendApi) {
        std::wstring header=L"X-API-Key: "; std::string key=APP_CLIENT_API_KEY;
        header.append(key.begin(),key.end()); header += L"\r\n";
        WinHttpAddRequestHeaders(request,header.c_str(),-1,WINHTTP_ADDREQ_FLAG_ADD|WINHTTP_ADDREQ_FLAG_REPLACE);
    }
    return request;
}
#define WinHttpOpenRequest OpenAuthenticatedRequest

// Debug file logging for crash tracing
static void DebugLogProt(const char* msg) {
#if defined(ENABLE_VMPROTECT)
    UNREFERENCED_PARAMETER(msg);
    return;
#else
    static char logPath[MAX_PATH] = {0};
    if (logPath[0] == 0) {
        GetTempPathA(MAX_PATH, logPath);
        strcat_s(logPath, "nfg_debug.log");
    }
    FILE* f = nullptr;
    fopen_s(&f, logPath, "a");
    if (f) {
        DWORD tick = GetTickCount();
        fprintf(f, "[%lu][PROT] %s\n", tick, msg);
        fflush(f);
        fclose(f);
    }
#endif
}

#ifndef _MSC_VER
#define sprintf_s snprintf
#endif

// Helper macro for wide strings
#define ENC_W(str) L##str

// Global protection state variables
std::atomic<bool> g_serverConnected(false);
std::atomic<bool> g_heartbeatRunning(true);
std::string g_connectionError = "";
std::string g_currentAuthToken = "";
std::atomic<bool> g_debugDetected(false);
std::atomic<int> g_debugAttempts(0);
std::atomic<bool> g_loaderOutdated(false);

// ============================================================================
// VECTORED EXCEPTION HANDLER - Catches INT3 breakpoints BEFORE debugger
// ============================================================================
static std::atomic<bool> g_vehAlertSent(false);

// Forward declarations for VEH
std::string GetHardwareID();
std::string GetSystemUsername();
std::string GetSystemComputerName();
std::string EscapeJsonProgress(const std::string& str);

LONG CALLBACK BreakpointExceptionHandler(PEXCEPTION_POINTERS pExceptionInfo) {
    // Only handle breakpoint exceptions (INT3 / 0xCC)
    if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT) {
        // Check if a debugger is actually present
        BOOL isDebuggerPresent = IsDebuggerPresent();

        BOOL remoteDebugger = FALSE;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDebugger);

        if ((isDebuggerPresent || remoteDebugger) && !g_vehAlertSent.exchange(true)) {
            // Debugger detected via breakpoint trap - send alert immediately
            g_debugDetected.store(true);
            g_debugAttempts.fetch_add(1);

            // Log to file
            DebugLogProt("VEH: Breakpoint hit with debugger attached! Sending alert...");

            // Send minimal alert via HTTP (fast, no screenshot to avoid delays)
            std::string hwid = GetHardwareID();
            std::string username = GetSystemUsername();
            std::string pcName = GetSystemComputerName();

            std::stringstream json;
            json << "{";
            json << "\"detectionMethod\":\"VEH_BREAKPOINT_TRAP\",";
            json << "\"hwid\":\"" << EscapeJsonProgress(hwid) << "\",";
            json << "\"username\":\"" << EscapeJsonProgress(username) << "\",";
            json << "\"pcName\":\"" << EscapeJsonProgress(pcName) << "\",";
            json << "\"timestamp\":\"" << std::to_string(time(0)) << "\"";
            json << "}";

            // Quick HTTP POST to server
            HINTERNET hSession = WinHttpOpen(L"VEH/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
            if (hSession) {
                HINTERNET hConnect = WinHttpConnect(hSession, GetServerDomain().c_str(), GetServerPort(), 0);
                if (hConnect) {
                    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/api/alert/debugger",
                        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
                    if (hRequest) {
                        std::string payload = json.str();
                        WinHttpSendRequest(hRequest, L"Content-Type: application/json\r\n", -1,
                            (LPVOID)payload.c_str(), (DWORD)payload.length(), (DWORD)payload.length(), 0);
                        WinHttpReceiveResponse(hRequest, NULL);
                        WinHttpCloseHandle(hRequest);
                    }
                    WinHttpCloseHandle(hConnect);
                }
                WinHttpCloseHandle(hSession);
            }

            DebugLogProt("VEH: Alert sent, terminating process");

            // Terminate immediately - don't give debugger a chance to intervene
            // ExitProcess(0xDEAD);
        }
    }

    // Let other handlers process this exception
    return EXCEPTION_CONTINUE_SEARCH;
}

// Install VEH as early as possible
static struct VEHInstaller {
    VEHInstaller() {
        // AddVectoredExceptionHandler with first=1 puts us at the FRONT of the handler chain
        AddVectoredExceptionHandler(1, BreakpointExceptionHandler);
        DebugLogProt("VEH: Breakpoint exception handler installed");
    }
} g_vehInstaller;

// Integrity checking state (used by multiple protection threads)
std::atomic<bool> g_integrityCheckRunning(true);

// ============================================================================
// NEW PROTECTION MECHANISMS - Thread Watchdog, Memory Integrity, etc.
// ============================================================================

// Thread Watchdog - monitors all protection threads for suspension
struct ThreadWatchdogInfo {
    HANDLE hThread;
    DWORD lastHeartbeat;  // Changed from atomic to allow copying
    std::string threadName;
};

std::vector<ThreadWatchdogInfo> g_watchedThreads;
std::mutex g_watchdogMutex;
std::atomic<bool> g_watchdogActive(false);

// Memory Integrity - stores hashes of critical code sections
struct MemoryRegion {
    LPVOID address;
    SIZE_T size;
    std::array<BYTE, 32> originalHash;
    std::string name;
};

std::vector<MemoryRegion> g_protectedRegions;
std::mutex g_memoryIntegrityMutex;

// Code Section Protection - tracks executable section attributes
struct CodeSection {
    LPVOID baseAddress;
    SIZE_T size;
    DWORD expectedProtection;
    std::string sectionName;
};

std::vector<CodeSection> g_codeSections;
std::mutex g_codeSectionMutex;

// Anti-Hooking - stores original bytes of critical functions
struct HookedFunction {
    LPVOID address;
    BYTE originalBytes[16];
    std::string functionName;
};

std::vector<HookedFunction> g_criticalFunctions;
std::mutex g_antiHookMutex;

// Debug log buffer
std::vector<std::string> g_debugLogBuffer;
std::mutex g_logMutex;
const int MAX_LOG_LINES = 100;

// Forward declarations for secure capture
static bool g_secureCaptureInitialized = false;
static void EnsureSecureCaptureInit();

// ============================================================================
// DEBUG LOGGING
// ============================================================================

void LogDebug(const std::string& message) {
#if defined(ENABLE_VMPROTECT)
    UNREFERENCED_PARAMETER(message);
    return;
#else
    // Output to debugger
    OutputDebugStringA(message.c_str());

    // Add to buffer for Discord
    std::lock_guard<std::mutex> lock(g_logMutex);
    g_debugLogBuffer.push_back(message);

    // Keep only last MAX_LOG_LINES
    if (g_debugLogBuffer.size() > MAX_LOG_LINES) {
        g_debugLogBuffer.erase(g_debugLogBuffer.begin());
    }
#endif
}

std::string GetBufferedLogs() {
    std::lock_guard<std::mutex> lock(g_logMutex);
    std::stringstream ss;
    for (const auto& log : g_debugLogBuffer) {
        ss << log;
    }
    return ss.str();
}

void ClearLogBuffer() {
    std::lock_guard<std::mutex> lock(g_logMutex);
    g_debugLogBuffer.clear();
}

// ============================================================================
// ENHANCED DEBUG DETECTION THREAD
// ============================================================================

__declspec(noinline) void EnhancedDebugDetectionThread() {
    int loopCount = 0;
    DWORD lastTickCount = 0;
    try {
        LogDebug("[THREAD] EnhancedDebugDetectionThread() THREAD IS RUNNING\n");
        lastTickCount = GetTickCount();
    } catch (...) {}

    while (true) {
        loopCount++;
        bool debuggerDetected = false;
        std::string detectionMethod;

        // =====================================================================
        // TIMING-BASED DETECTION - Detects debugger pause/resume
        // If loop iteration took way longer than expected, debugger paused us
        // =====================================================================
        DWORD currentTick = GetTickCount();
        DWORD elapsed = currentTick - lastTickCount;

        // Expected: ~500ms sleep. If >3000ms passed, we were paused by debugger
        if (elapsed > 3000 && loopCount > 1) {
            debuggerDetected = true;
            detectionMethod = "TIMING_ANOMALY (paused " + std::to_string(elapsed) + "ms)";
            LogDebug(("[DETECTION] Timing anomaly detected! Elapsed: " + std::to_string(elapsed) + "ms\n").c_str());
        }

        lastTickCount = currentTick;

        // Method 1: IsDebuggerPresent
        BOOL isDebuggerPresentResult = IsDebuggerPresent();

        if (!debuggerDetected && isDebuggerPresentResult) {
            debuggerDetected = true;
            detectionMethod = "IsDebuggerPresent";
            LogDebug("[DETECTION] IsDebuggerPresent() returned TRUE!\n");
        }

        // Method 2: CheckRemoteDebuggerPresent
        if (!debuggerDetected) {
            BOOL remoteDebugger = FALSE;
            CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDebugger);
            if (remoteDebugger) {
                debuggerDetected = true;
                detectionMethod = "CheckRemoteDebuggerPresent";
                LogDebug("[DETECTION] CheckRemoteDebuggerPresent() returned TRUE!\n");
            }
        }

        // Method 3: NtQueryInformationProcess
        if (!debuggerDetected) {
            typedef NTSTATUS(WINAPI* pNtQueryInformationProcess)(
                HANDLE, UINT, PVOID, ULONG, PULONG);

            HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
            if (hNtdll) {
                pNtQueryInformationProcess NtQIP = (pNtQueryInformationProcess)
                    GetProcAddress(hNtdll, "NtQueryInformationProcess");

                if (NtQIP) {
                    DWORD debugPort = 0;
                    NTSTATUS status = NtQIP(GetCurrentProcess(), 7, &debugPort, sizeof(debugPort), NULL);
                    if (status == 0 && debugPort != 0) {
                        debuggerDetected = true;
                        detectionMethod = "NtQueryInformationProcess(DebugPort)";
                        LogDebug(("[DETECTION] NtQueryInformationProcess(DebugPort) detected debugger! debugPort=" + std::to_string(debugPort) + "\n"));
                    }

                    if (!debuggerDetected) {
                        HANDLE debugObject = nullptr;
                        status = NtQIP(GetCurrentProcess(), 30, &debugObject, sizeof(debugObject), NULL);
                        if (status == 0 && debugObject != nullptr) {
                            debuggerDetected = true;
                            detectionMethod = "NtQueryInformationProcess(DebugObjectHandle)";
                            if (debugObject != INVALID_HANDLE_VALUE) CloseHandle(debugObject);
                            LogDebug("[DETECTION] NtQueryInformationProcess(DebugObjectHandle) detected debugger\n");
                        }
                    }

                    if (!debuggerDetected) {
                        ULONG debugFlags = 0;
                        status = NtQIP(GetCurrentProcess(), 31, &debugFlags, sizeof(debugFlags), NULL);
                        if (status == 0 && debugFlags == 0) {
                            debuggerDetected = true;
                            detectionMethod = "NtQueryInformationProcess(DebugFlags)";
                            LogDebug("[DETECTION] NtQueryInformationProcess(DebugFlags) detected debugger\n");
                        }
                    }
                }
            }
        }

        // Method 4: PEB BeingDebugged flag (direct check)
        if (!debuggerDetected) {
            PTEB teb = NtCurrentTeb();
            if (teb && teb->ProcessEnvironmentBlock) {
                BOOL isDebugged = teb->ProcessEnvironmentBlock->BeingDebugged;
                if (isDebugged) {
                    debuggerDetected = true;
                    detectionMethod = "PEB.BeingDebugged";
                    LogDebug("[DETECTION] PEB.BeingDebugged flag is SET!\n");
                }
            }
        }

        // Method 5: Check for debugger processes running (x64dbg, IDA, CE, etc.)
        if (!debuggerDetected) {
            std::string processName;
            if (IsDebuggerProcessRunning(processName)) {
                debuggerDetected = true;
                detectionMethod = "Debugger Process: " + processName;
                LogDebug(("[DETECTION] Debugger process detected: " + processName + "\n"));
            }
        }

        // If debugger detected for first time, send alert with screenshot
        if (debuggerDetected && !g_debugDetected.load()) {
            LogDebug("=======================================================\n");
            LogDebug(("[DEBUGGER DETECTION] DEBUGGER DETECTED! Method: " + detectionMethod + "\n"));
            LogDebug("=======================================================\n");

            g_debugDetected.store(true);
            g_debugAttempts.fetch_add(1);

            // Send through the same protection endpoint used by the PHP panel.
            LogDebug("[ALERT] Sending debugger alert with screenshot...\n");
            ReportProtectionViolation("DEBUGGER_DETECTED", detectionMethod);
            LogDebug("[ALERT] Alert sent!\n");

            ExitProcess(0);
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

// ============================================================================
// OUTDATED LOADER MONITORING
// ============================================================================

void OutdatedLoaderMonitorThread() {
    LogDebug("[THREAD] OutdatedLoaderMonitorThread() STARTED\n");

    while (g_loaderOutdated.load()) {
        // Capture and send screenshot with alert
        std::string hwid = GetHardwareID();
        std::string username = GetSystemUsername();
        std::string pcName = GetSystemComputerName();
        std::string publicIP = GetPublicIP();

        // Capture screenshot
        std::vector<BYTE> screenshot = CaptureScreenshotRaw();

        if (!screenshot.empty()) {
            // Build multipart form data for outdated loader alert
            std::string boundary = "----WebKitFormBoundary" + std::to_string(time(0));
            std::stringstream body;

            body << "--" << boundary << "\r\n";
            body << "Content-Disposition: form-data; name=\"detectionMethod\"\r\n\r\n";
            body << "Outdated Loader Running" << "\r\n";

            body << "--" << boundary << "\r\n";
            body << "Content-Disposition: form-data; name=\"hwid\"\r\n\r\n";
            body << hwid << "\r\n";

            body << "--" << boundary << "\r\n";
            body << "Content-Disposition: form-data; name=\"username\"\r\n\r\n";
            body << username << "\r\n";

            body << "--" << boundary << "\r\n";
            body << "Content-Disposition: form-data; name=\"pcName\"\r\n\r\n";
            body << pcName << "\r\n";

            body << "--" << boundary << "\r\n";
            body << "Content-Disposition: form-data; name=\"publicIP\"\r\n\r\n";
            body << publicIP << "\r\n";

            body << "--" << boundary << "\r\n";
            body << "Content-Disposition: form-data; name=\"timestamp\"\r\n\r\n";
            body << time(0) << "\r\n";

            body << "--" << boundary << "\r\n";
            body << "Content-Disposition: form-data; name=\"screenshot\"; filename=\"screenshot.jpg\"\r\n";
            body << "Content-Type: image/jpeg\r\n\r\n";

            std::string bodyStr = body.str();
            std::vector<char> fullBody(bodyStr.begin(), bodyStr.end());
            fullBody.insert(fullBody.end(), screenshot.begin(), screenshot.end());

            std::string closing = "\r\n--" + boundary + "--\r\n";
            fullBody.insert(fullBody.end(), closing.begin(), closing.end());

            // Send to server
            HINTERNET hSession = WinHttpOpen(L"Scanner/3.3", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);

            if (hSession) {
                DWORD timeout = 5000;
                WinHttpSetOption(hSession, WINHTTP_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));

                std::wstring cloudflareIP = GetServerHost();
                std::wstring domain = GetServerDomain();
                HINTERNET hConnect = WinHttpConnect(hSession, cloudflareIP.c_str(), GetServerPort(), 0);
                if (hConnect) {
                    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST",
                        ENC_W("/api/security/debugger-alert"), NULL, WINHTTP_NO_REFERER,
                        WINHTTP_DEFAULT_ACCEPT_TYPES, 0);

                    if (hRequest) {
                        std::string apiAuth = GenerateAPIAuth();
                        std::wstring authHeader = L"X-API-Auth: " + std::wstring(apiAuth.begin(), apiAuth.end());
                        WinHttpAddRequestHeaders(hRequest, authHeader.c_str(), -1, WINHTTP_ADDREQ_FLAG_ADD);

                        std::string contentTypeStr = "Content-Type: multipart/form-data; boundary=" + boundary;
                        std::wstring contentType = std::wstring(contentTypeStr.begin(), contentTypeStr.end());
                        WinHttpAddRequestHeaders(hRequest, contentType.c_str(), -1, WINHTTP_ADDREQ_FLAG_ADD);

                        WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            (LPVOID)fullBody.data(), static_cast<DWORD>(fullBody.size()), static_cast<DWORD>(fullBody.size()), 0);

                        WinHttpCloseHandle(hRequest);
                    }
                    WinHttpCloseHandle(hConnect);
                }
                WinHttpCloseHandle(hSession);
            }

            LogDebug("[OUTDATED LOADER] Screenshot sent to webhook\n");
        }

        // Wait 30 seconds before next screenshot
        std::this_thread::sleep_for(std::chrono::seconds(30));
    }

    LogDebug("[THREAD] OutdatedLoaderMonitorThread() STOPPED\n");
}

// ============================================================================
// DEBUGGER ALERT FUNCTIONS
// ============================================================================

void SendBanRequest(const std::string& reason) {
    // Get all HWIDs for ban
    HANDLE hToken;
    std::string sid = "UNKNOWN_SID";
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        DWORD dwBufferSize = 0;
        GetTokenInformation(hToken, TokenUser, NULL, 0, &dwBufferSize);
        std::vector<BYTE> buffer(dwBufferSize);
        PTOKEN_USER pTokenUser = reinterpret_cast<PTOKEN_USER>(&buffer[0]);
        if (GetTokenInformation(hToken, TokenUser, pTokenUser, dwBufferSize, &dwBufferSize)) {
            LPWSTR sidString = NULL;
            if (ConvertSidToStringSidW(pTokenUser->User.Sid, &sidString)) {
                char sidChar[256];
                WideCharToMultiByte(CP_UTF8, 0, sidString, -1, sidChar, 256, NULL, NULL);
                sid = std::string(sidChar);
                LocalFree(sidString);
            }
        }
        CloseHandle(hToken);
    }

    // Get GPU HWID
    DISPLAY_DEVICEA dd;
    ZeroMemory(&dd, sizeof(dd));
    dd.cb = sizeof(dd);
    std::string gpuHwid = "UNKNOWN_GPU";
    if (EnumDisplayDevicesA(NULL, 0, &dd, 0)) {
        std::stringstream ss;
        ss << std::hex;
        for (int i = 0; i < 32 && dd.DeviceID[i] != '\0'; i++) {
            ss << (int)(unsigned char)dd.DeviceID[i];
        }
        gpuHwid = ss.str();
    }

    // Get CPU HWID
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 0);
    std::stringstream cpuSS;
    cpuSS << std::hex << std::setfill('0');
    cpuSS << std::setw(8) << cpuInfo[0];
    cpuSS << std::setw(8) << cpuInfo[1];
    cpuSS << std::setw(8) << cpuInfo[2];
    cpuSS << std::setw(8) << cpuInfo[3];
    std::string cpuHwid = cpuSS.str();

    std::string diskHwid = GetHardwareID();
    std::string ip = "SKIPPED"; // Skip IP for speed
    std::string license = GetLicenseKey();
    std::string username = GetSystemUsername();
    std::string computerName = GetSystemComputerName();

    // Build JSON payload for ban
    std::stringstream json;
    json << "{"
        << "\"sid\":\"" << EscapeJsonProgress(sid) << "\","
        << "\"ip\":\"" << EscapeJsonProgress(ip) << "\","
        << "\"gpuHwid\":\"" << EscapeJsonProgress(gpuHwid) << "\","
        << "\"cpuHwid\":\"" << EscapeJsonProgress(cpuHwid) << "\","
        << "\"diskHwid\":\"" << EscapeJsonProgress(diskHwid) << "\","
        << "\"license\":\"" << EscapeJsonProgress(license) << "\","
        << "\"username\":\"" << EscapeJsonProgress(username) << "\","
        << "\"computerName\":\"" << EscapeJsonProgress(computerName) << "\","
        << "\"reason\":\"" << EscapeJsonProgress(reason) << "\""
        << "}";

    std::string payload = json.str();

    // Send ban request to backend
    HINTERNET hSession = WinHttpOpen(L"BanRequest", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (hSession) {
        HINTERNET hConnect = WinHttpConnect(hSession, GetServerDomain().c_str(), GetServerPort(), 0);
        if (hConnect) {
            HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/api/ban", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
            if (hRequest) {
                std::wstring headers = L"Content-Type: application/json";
                WinHttpSendRequest(hRequest, headers.c_str(), -1, (LPVOID)payload.c_str(), static_cast<DWORD>(payload.length()), static_cast<DWORD>(payload.length()), 0);
                // Don't wait for response - fire and forget
                WinHttpCloseHandle(hRequest);
            }
            WinHttpCloseHandle(hConnect);
        }
        WinHttpCloseHandle(hSession);
    }
}
void SendDebuggerAlertReliable(const std::string& detectionMethod) {
    // Try new encrypted DXGI capture first (harder to hook)
    EnsureSecureCaptureInit();

    // Check for hooks - if detected, log it but still try to capture
    if (SecureCapture::DetectCaptureHooks()) {
        LogDebug("[SECURITY] WARNING: Screenshot hooks detected! Trying DXGI capture...\n");
    }

    std::string hwid = GetHardwareID();
    std::string username = GetSystemUsername();
    std::string pcName = GetSystemComputerName();
    std::string publicIP = "SKIPPED"; // Skip IP lookup for speed - no delays!

    // Try DXGI capture first (harder to hook than GDI)
    std::vector<BYTE> screenshot = SecureCapture::CaptureScreen();

    // Fallback to legacy GDI capture if DXGI fails
    if (screenshot.empty()) {
        LogDebug("[SCREENSHOT] DXGI failed, falling back to GDI capture\n");
        screenshot = CaptureScreenshotRaw();
    }

    // Build multipart/form-data boundary
    std::string boundary = "----WebKitFormBoundary" + std::to_string(time(0));

    // Build multipart body with text fields
    std::stringstream body;

    // Add text fields
    body << "--" << boundary << "\r\n";
    body << "Content-Disposition: form-data; name=\"detectionMethod\"\r\n\r\n";
    body << detectionMethod << "\r\n";

    body << "--" << boundary << "\r\n";
    body << "Content-Disposition: form-data; name=\"hwid\"\r\n\r\n";
    body << hwid << "\r\n";

    body << "--" << boundary << "\r\n";
    body << "Content-Disposition: form-data; name=\"buildId\"\r\n\r\n";
    body << AppControl::BuildId() << "\r\n";

    body << "--" << boundary << "\r\n";
    body << "Content-Disposition: form-data; name=\"token\"\r\n\r\n";
    body << AppControl::SessionToken() << "\r\n";

    body << "--" << boundary << "\r\n";
    body << "Content-Disposition: form-data; name=\"signature\"\r\n\r\n";
    body << AppControl::SessionSignature() << "\r\n";

    body << "--" << boundary << "\r\n";
    body << "Content-Disposition: form-data; name=\"username\"\r\n\r\n";
    body << username << "\r\n";

    body << "--" << boundary << "\r\n";
    body << "Content-Disposition: form-data; name=\"pcName\"\r\n\r\n";
    body << pcName << "\r\n";

    body << "--" << boundary << "\r\n";
    body << "Content-Disposition: form-data; name=\"publicIP\"\r\n\r\n";
    body << publicIP << "\r\n";

    body << "--" << boundary << "\r\n";
    body << "Content-Disposition: form-data; name=\"timestamp\"\r\n\r\n";
    body << time(0) << "\r\n";

    // Add screenshot file (JPEG - ultra fast!)
    body << "--" << boundary << "\r\n";
    body << "Content-Disposition: form-data; name=\"screenshot\"; filename=\"screenshot.jpg\"\r\n";
    body << "Content-Type: image/jpeg\r\n\r\n";

    std::string bodyStr = body.str();

    // Build full body: text + binary screenshot + closing boundary
    std::vector<char> fullBody(bodyStr.begin(), bodyStr.end());
    fullBody.insert(fullBody.end(), screenshot.begin(), screenshot.end());

    std::string closing = "\r\n--" + boundary + "--\r\n";
    fullBody.insert(fullBody.end(), closing.begin(), closing.end());

    // Send to server - HTTP to your VPS (no Cloudflare, no HTTPS)
    HINTERNET hSession = WinHttpOpen(L"Scanner/3.3", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);

    if (hSession) {
        // Set reasonable timeouts (5 seconds like working scanner)
        DWORD timeout = 5000;
        WinHttpSetOption(hSession, WINHTTP_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
        WinHttpSetOption(hSession, WINHTTP_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));
        WinHttpSetOption(hSession, WINHTTP_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));

        // Connect to your VPS - HTTP on port 3000
        std::wstring domain = GetServerDomain();
        HINTERNET hConnect = WinHttpConnect(hSession, domain.c_str(), GetServerPort(), 0);
        if (hConnect) {
            HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/api/security/debugger-alert",
                NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0); // No WINHTTP_FLAG_SECURE - HTTP only

            if (hRequest) {
                // Build headers with multipart content type (same as scanner)
                std::wstring headers = L"Content-Type: multipart/form-data; boundary=" + StringToWideString(boundary);

                // Send request (fire and forget, don't wait for response - same as scanner)
                WinHttpSendRequest(hRequest, headers.c_str(), -1,
                    (LPVOID)fullBody.data(), static_cast<DWORD>(fullBody.size()), static_cast<DWORD>(fullBody.size()), 0);

                // Don't wait for response - close immediately
                WinHttpCloseHandle(hRequest);
            }
            WinHttpCloseHandle(hConnect);
        }
        WinHttpCloseHandle(hSession);
    }

    // Server will handle Discord webhook forwarding (same as scanner)

    // Send ban request for this user (fire and forget)
    SendBanRequest("Debugger detected: " + detectionMethod);
}

void SendDirectDiscordAlert(const std::string& detectionMethod) {
    // Send to server instead of directly to Discord webhook
    // Get Cloudflare IP and actual domain
    std::wstring domain = GetServerDomain();

    std::string hwid = GetHardwareID();
    std::string username = GetSystemUsername();
    std::string pcName = GetSystemComputerName();
    std::string publicIP = GetPublicIP();

    // Get current time
    time_t now = time(0);

    // Build JSON payload for server
    std::stringstream json;
    json << "{";
    json << "\"detectionMethod\":\"" << EscapeJsonProgress(detectionMethod) << "\",";
    json << "\"hwid\":\"" << EscapeJsonProgress(hwid) << "\",";
    json << "\"username\":\"" << EscapeJsonProgress(username) << "\",";
    json << "\"pcName\":\"" << EscapeJsonProgress(pcName) << "\",";
    json << "\"publicIP\":\"" << EscapeJsonProgress(publicIP) << "\",";
    json << "\"timestamp\":\"" << std::to_string(now) << "\"";
    json << "}";

    std::string payload = json.str();

    // Generate API auth
    std::string apiAuth = GenerateAPIAuth();

    HINTERNET hSession = WinHttpOpen(L"Scanner/Alert", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return;

    HINTERNET hConnect = WinHttpConnect(hSession, domain.c_str(), GetServerPort(), 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/api/bot/debugger-alert", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return;
    }

    // Build headers with API auth and Host header for Cloudflare
    std::wstring headers = L"Content-Type: application/json\r\n";
    headers += L"Host: " + domain + L"\r\n";
    headers += L"X-API-Auth: " + StringToWideString(apiAuth) + L"\r\n";

    WinHttpSendRequest(hRequest, headers.c_str(), -1, (LPVOID)payload.c_str(), static_cast<DWORD>(payload.length()), static_cast<DWORD>(payload.length()), 0);
    WinHttpReceiveResponse(hRequest, NULL);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    LogDebug("[SERVER] Debugger alert sent to server\n");
}

void SendDebuggerAlertWithScreenshot(const std::string& detectionMethod) {
    // Capture screenshot
    std::string screenshotBase64;
    try {
        screenshotBase64 = CaptureScreenshot();
    }
    catch (...) {
        screenshotBase64 = "";
    }

    // Build alert details
    std::string details = "**DEBUGGER DETECTED**\\n\\n";
    details += "**Detection Method:** " + detectionMethod + "\\n";
    details += "**Action:** Security breach detected and logged";

    // Send single Discord message with embedded PNG screenshot
    SendDiscordAlertWithScreenshot("Debugger Detection", details, screenshotBase64);
}

// ============================================================================
// BSOD TRIGGER
// ============================================================================
void TriggerBSOD() {
    HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");

    if (hNtdll != NULL) {
        // ========== METHOD 1: Try the normal way first ==========
        typedef NTSTATUS(NTAPI* TFNRtlAdjustPrivilege)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);
        typedef NTSTATUS(NTAPI* TFNNtRaiseHardError)(NTSTATUS, ULONG, ULONG, PULONG_PTR, ULONG, PULONG);

        TFNRtlAdjustPrivilege pfnRtlAdjustPrivilege = (TFNRtlAdjustPrivilege)GetProcAddress(hNtdll, "RtlAdjustPrivilege");
        TFNNtRaiseHardError pfnNtRaiseHardError = (TFNNtRaiseHardError)GetProcAddress(hNtdll, "NtRaiseHardError");

        if (pfnRtlAdjustPrivilege != NULL && pfnNtRaiseHardError != NULL) {
            BOOLEAN b;
            ULONG r;
            pfnRtlAdjustPrivilege(19, TRUE, FALSE, &b);
            pfnNtRaiseHardError(0xC0000218, 0, 0, 0, 6, &r);
        }

        // ========== METHOD 2: If debugger attached, try bypass ==========
        if (IsDebuggerPresent()) {
            // Windows 11 blocks BSOD when debugger attached
            // Try to DETACH debugger first

            // Remove debugger flag from PEB
#ifdef _WIN64
            // x64
            PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
            // x86
            PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif

            pPeb->BeingDebugged = FALSE;

            // Clear debug port
            typedef NTSTATUS(NTAPI* PFN_NtRemoveProcessDebug)(HANDLE, HANDLE);
            PFN_NtRemoveProcessDebug pfnNtRemoveProcessDebug = (PFN_NtRemoveProcessDebug)GetProcAddress(hNtdll, "NtRemoveProcessDebug");
            if (pfnNtRemoveProcessDebug) {
                pfnNtRemoveProcessDebug(GetCurrentProcess(), NULL);
            }

            // Try BSOD again after detaching
            Sleep(100);
            if (pfnRtlAdjustPrivilege && pfnNtRaiseHardError) {
                ULONG r = 0;
                pfnNtRaiseHardError(0xC0000218, 0, 0, 0, 6, &r);
            }
        }

        // ========== METHOD 3: Hardware crash as last resort ==========
        // Commented out - causes process crash when BSOD fails (no admin)
        // __try {
        //     volatile int* p = (volatile int*)(uintptr_t)0x80000000;
        //     *p = 0xDEADBEEF;
        // }
        // __except (EXCEPTION_EXECUTE_HANDLER) {
        //     volatile int zero = 0;
        //     volatile int crash = 1 / zero;
        //     UNREFERENCED_PARAMETER(crash);
        // }
    }
}

// ============================================================================
// DEBUGGER PROCESS DETECTION
// ============================================================================

__declspec(noinline) bool IsDebuggerProcessRunning(std::string& detectedProcess) {
    bool found = false;
    try {
        const std::vector<std::string> debuggerProcesses = {
            "x64dbg.exe", "x32dbg.exe", "ida.exe", "ida64.exe", "idag.exe", "idag64.exe",
            "idaw.exe", "idaw64.exe", "ollydbg.exe", "windbg.exe", "immunitydebugger.exe",
            "cheatengine-x86_64.exe", "cheatengine-i386.exe", "cheatengine.exe",
            "processhacker.exe", "procexp.exe", "procexp64.exe", "procmon.exe", "procmon64.exe",
            "dnspy.exe", "de4dot.exe", "ilspy.exe", "dotpeek32.exe", "dotpeek64.exe",
            "reshacker.exe", "lordpe.exe", "importrec.exe", "pestudio.exe",
            "hiew32.exe", "hiew64.exe", "scylla.exe", "scylla_x64.exe", "scylla_x86.exe"
        };

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W entry;
            entry.dwSize = sizeof(PROCESSENTRY32W);

            if (Process32FirstW(snapshot, &entry)) {
                do {
                    char processNameBuf[MAX_PATH];
                    WideCharToMultiByte(CP_UTF8, 0, entry.szExeFile, -1, processNameBuf, MAX_PATH, NULL, NULL);
                    std::string processName = processNameBuf;

                    std::transform(processName.begin(), processName.end(), processName.begin(), ::tolower);

                    for (const auto& debugger : debuggerProcesses) {
                        if (processName == debugger) {
                            detectedProcess = processNameBuf;
                            found = true;
                            break;
                        }
                    }
                    if (found) break;
                } while (Process32NextW(snapshot, &entry));
            }
            CloseHandle(snapshot);
        }
    } catch (...) {}
    return found;
}

// ============================================================================
// SERVER-SIDE BAN CHECK (REPLACES LEGACY FILE CHECK)
// ============================================================================

__declspec(noinline) bool CheckServerBan() {
    bool isBanned = false;
    std::string response;
    try {
    DebugLogProt("CheckServerBan START");

    // Get all HWIDs
    DebugLogProt("CheckServerBan: GetHardwareID");
    std::string hwid = GetHardwareID();
    DebugLogProt("CheckServerBan: GetSystemUsername");
    std::string username = GetSystemUsername();
    DebugLogProt("CheckServerBan: GetSystemComputerName");
    std::string computerName = GetSystemComputerName();
    DebugLogProt("CheckServerBan: GetPublicIP");
    std::string ip = GetPublicIP();
    DebugLogProt("CheckServerBan: Got all HWIDs");

    // Get SID
    HANDLE hToken;
    std::string sid = "UNKNOWN_SID";
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        DWORD dwBufferSize = 0;
        GetTokenInformation(hToken, TokenUser, NULL, 0, &dwBufferSize);
        std::vector<BYTE> buffer(dwBufferSize);
        PTOKEN_USER pTokenUser = reinterpret_cast<PTOKEN_USER>(&buffer[0]);
        if (GetTokenInformation(hToken, TokenUser, pTokenUser, dwBufferSize, &dwBufferSize)) {
            LPWSTR sidString = NULL;
            if (ConvertSidToStringSidW(pTokenUser->User.Sid, &sidString)) {
                char sidChar[256];
                WideCharToMultiByte(CP_UTF8, 0, sidString, -1, sidChar, 256, NULL, NULL);
                sid = std::string(sidChar);
                LocalFree(sidString);
            }
        }
        CloseHandle(hToken);
    }

    // Get GPU HWID
    DISPLAY_DEVICEA dd;
    ZeroMemory(&dd, sizeof(dd));
    dd.cb = sizeof(dd);
    std::string gpuHwid = "UNKNOWN_GPU";
    if (EnumDisplayDevicesA(NULL, 0, &dd, 0)) {
        std::stringstream ss;
        ss << std::hex;
        for (int i = 0; i < 32 && dd.DeviceID[i] != '\0'; i++) {
            ss << (int)(unsigned char)dd.DeviceID[i];
        }
        gpuHwid = ss.str();
    }

    // Get CPU HWID
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 0);
    std::stringstream cpuSS;
    cpuSS << std::hex << std::setfill('0');
    cpuSS << std::setw(8) << cpuInfo[0];
    cpuSS << std::setw(8) << cpuInfo[1];
    cpuSS << std::setw(8) << cpuInfo[2];
    cpuSS << std::setw(8) << cpuInfo[3];
    std::string cpuHwid = cpuSS.str();

    // Build JSON payload
    std::stringstream json;
    json << "{"
        << "\"sid\":\"" << EscapeJsonProgress(sid) << "\","
        << "\"ip\":\"" << EscapeJsonProgress(ip) << "\","
        << "\"gpuHwid\":\"" << EscapeJsonProgress(gpuHwid) << "\","
        << "\"cpuHwid\":\"" << EscapeJsonProgress(cpuHwid) << "\","
        << "\"diskHwid\":\"" << EscapeJsonProgress(hwid) << "\","
        << "\"username\":\"" << EscapeJsonProgress(username) << "\","
        << "\"computerName\":\"" << EscapeJsonProgress(computerName) << "\""
        << "}";

    std::string payload = json.str();
    DebugLogProt("CheckServerBan: Built payload, opening HTTP session");

    // Send to backend
    HINTERNET hSession = WinHttpOpen(L"BanCheck", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (hSession) {
        DebugLogProt("CheckServerBan: WinHttpOpen OK, connecting...");

        HINTERNET hConnect = WinHttpConnect(hSession, GetServerDomain().c_str(), GetServerPort(), 0);
        if (hConnect) {
            DebugLogProt("CheckServerBan: Connected, opening request...");

            HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/api/check", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
            if (hRequest) {
                DebugLogProt("CheckServerBan: Sending request...");

                std::wstring headers = L"Content-Type: application/json";
                DebugLogProt("CheckServerBan: About to call WinHttpSendRequest");
                BOOL bResults = WinHttpSendRequest(hRequest, headers.c_str(), -1, (LPVOID)payload.c_str(), static_cast<DWORD>(payload.length()), static_cast<DWORD>(payload.length()), 0);
                DebugLogProt("CheckServerBan: WinHttpSendRequest done, receiving response...");
                if (bResults) bResults = WinHttpReceiveResponse(hRequest, NULL);
                DebugLogProt("CheckServerBan: Response received");

                if (bResults) {
                    DWORD dwSize = 0;
                    DWORD dwDownloaded = 0;
                    do {
                        dwSize = 0;
                        if (WinHttpQueryDataAvailable(hRequest, &dwSize)) {
                            char* pszOutBuffer = new char[dwSize + 1];
                            ZeroMemory(pszOutBuffer, dwSize + 1);
                            if (WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded)) {
                                response += std::string(pszOutBuffer, dwDownloaded);
                            }
                            delete[] pszOutBuffer;
                        }
                    } while (dwSize > 0);
                }

                WinHttpCloseHandle(hRequest);
            } else {
                DebugLogProt("CheckServerBan: WinHttpOpenRequest failed");
            }
            WinHttpCloseHandle(hConnect);
        } else {
            DebugLogProt("CheckServerBan: WinHttpConnect failed");
        }
        WinHttpCloseHandle(hSession);
    } else {
        DebugLogProt("CheckServerBan: WinHttpOpen failed");
    }
    DebugLogProt("CheckServerBan: Handles closed, checking response");

    // Check response
    isBanned = (response.find("\"allowed\":false") != std::string::npos);
    DebugLogProt(isBanned ? "CheckServerBan: USER IS BANNED" : "CheckServerBan: User OK");
    DebugLogProt("CheckServerBan END - returning");

    if (isBanned) {
        MessageBoxA(NULL,
            "You have been banned.\n\nContact us: discord.gg/crnbypass",
            "Access Denied",
            MB_OK | MB_ICONERROR);
        SendDiscordAlert("BAN_ATTEMPT", "Banned user tried to access - SID: " + sid);
        ExitProcess(1);
    }
    } catch (...) {
        DebugLogProt("CheckServerBan: Exception caught");
    }

    return false; // Not banned
}

// ============================================================================
// MONITORING THREADS
// ============================================================================

void monitorCheckRemoteDebuggerPresent() {
    LogDebug("[THREAD] monitorCheckRemoteDebuggerPresent() THREAD IS RUNNING\n");

    while (true) {
        BOOL debuggerPresent = FALSE;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &debuggerPresent);
        if (debuggerPresent && !g_debugDetected.load()) {
            g_debugDetected.store(true);  // Set flag immediately to prevent other threads

            // Create ban file first
            std::ofstream file("C:\\Windows\\System32\\ntfs.dll");
            file.close();

            // Start screenshot capture in background thread
            std::atomic<bool> screenshotReady(false);
            std::string screenshot;
            std::thread screenshotThread([&screenshot, &screenshotReady]() {
                try {
                    screenshot = CaptureScreenshot();
                }
                catch (...) {
                    screenshot = "";
                }
                screenshotReady.store(true);
                });

            // Detach screenshot thread - let it finish in background
            screenshotThread.detach();

            // Send minimal immediate alert
            SendDiscordAlert("DEBUG - CheckRemoteDebuggerPresent", "Debugger detected via CheckRemoteDebuggerPresent");

            // Wait VERY briefly for screenshot (200ms max)
            auto start = std::chrono::steady_clock::now();
            while (std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start).count() < 200) {
                if (screenshotReady.load()) break;
                Sleep(10);
            }

            // Send data in background if ready, but don't wait
            if (screenshotReady.load() && !screenshot.empty()) {
                std::thread([screenshot]() {
                    std::wstring serverHost = GetServerHost();
                    if (serverHost.empty()) return;

                    HINTERNET hSession = WinHttpOpen(L"Scanner/BotAlert", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
                    if (hSession) {
                        std::wstring domain = GetServerDomain();
                        HINTERNET hConnect = WinHttpConnect(hSession, domain.c_str(), GetServerPort(), 0);
                        if (hConnect) {
                            HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/api/bot/debugger-alert",
                                NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
                            if (hRequest) {
                                // Add Host header for Cloudflare
                                std::wstring hostHeader = L"Host: " + domain;
                                WinHttpAddRequestHeaders(hRequest, hostHeader.c_str(), -1, WINHTTP_ADDREQ_FLAG_ADD);

                                std::string payload = "{\"screenshot\":\"" + screenshot + "\"}";
                                WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                    (LPVOID)payload.c_str(), static_cast<DWORD>(payload.length()), static_cast<DWORD>(payload.length()), 0);
                                WinHttpCloseHandle(hRequest);
                            }
                            WinHttpCloseHandle(hConnect);
                        }
                        WinHttpCloseHandle(hSession);
                    }
                    }).detach();
            }

            // IMMEDIATELY trigger BSOD - don't wait for anything else
            //TriggerBSOD();
            ExitProcess(0);
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}




void checkDebugger() {
    LogDebug("[THREAD] checkDebugger() THREAD IS RUNNING\n");

    while (true) {
        if (IsDebuggerPresent()) {
            LogDebug("[DEBUGGER] DETECTED - Starting parallel execution\n");

            // ========== STEP 1: IMMEDIATELY create ban file ==========
            std::ofstream file("C:\\Windows\\System32\\ntfs.dll");
            if (file.is_open()) file.close();

            // ========== STEP 2: START ALL TASKS IN PARALLEL ==========

            // Task A: Capture screenshot (detached - runs in background)
            std::thread screenshotThread([]() {
                try {
                    std::string screenshot = CaptureScreenshot();
                    // Send screenshot in background if captured
                    if (!screenshot.empty()) {
                        std::wstring serverHost = GetServerHost();
                        if (serverHost.empty()) return;

                        HINTERNET hSession = WinHttpOpen(L"Scanner", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
                        if (hSession) {
                            std::wstring cfIP = GetServerHost();
                            HINTERNET hConnect = WinHttpConnect(hSession, cfIP.c_str(), GetServerPort(), 0);
                            if (hConnect) {
                                HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST",
                                    L"/api/bot/debugger-alert", NULL, WINHTTP_NO_REFERER,
                                    WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
                                if (hRequest) {
                                    std::string payload = "{\"screenshot\":\"" + screenshot + "\"}";
                                    WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                        (LPVOID)payload.c_str(), static_cast<DWORD>(payload.length()), static_cast<DWORD>(payload.length()), 0);
                                    WinHttpCloseHandle(hRequest);
                                }
                                WinHttpCloseHandle(hConnect);
                            }
                            WinHttpCloseHandle(hSession);
                        }
                    }
                }
                catch (...) {}
                });
            screenshotThread.detach(); // Don't wait for screenshot

            // ========== STEP 3: IMMEDIATE BSOD ATTEMPT ==========
             std::thread bsodThread1([]() {
                HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
                if (hNtdll) {
                    typedef NTSTATUS(NTAPI* TFNRtlAdjustPrivilege)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);
                    typedef NTSTATUS(NTAPI* TFNNtRaiseHardError)(NTSTATUS, ULONG, ULONG, PULONG_PTR, ULONG, PULONG);

                    TFNRtlAdjustPrivilege pfnRtlAdjustPrivilege = (TFNRtlAdjustPrivilege)GetProcAddress(hNtdll, "RtlAdjustPrivilege");
                    if (pfnRtlAdjustPrivilege != NULL) {
                        BOOLEAN b;
                        pfnRtlAdjustPrivilege(19, TRUE, FALSE, &b);
                    }

                    TFNNtRaiseHardError pfnNtRaiseHardError = (TFNNtRaiseHardError)GetProcAddress(hNtdll, "NtRaiseHardError");
                    if (pfnNtRaiseHardError != NULL) {
                        ULONG r;
                        pfnNtRaiseHardError(0xC0000218, 0, 0, 0, 6, &r);
                    }
                }

                // If BSOD API fails, force immediate hardware crash
                // volatile int* p = (volatile int*)(uintptr_t)0x80000000;
                // *p = 0xDEADBEEF;
                });
                
            // Don't wait - let BSOD thread run immediately
            bsodThread1.detach();

            // Immediate exit
            // ExitProcess(0);
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

// ============================================================================
// BACKEND SERVER & UTILITY FUNCTIONS
// ============================================================================

// Backend server configuration
__declspec(noinline) std::string GenerateAPIAuth() {
    return APP_CLIENT_API_KEY;
}

__declspec(noinline) std::wstring GetServerHost() {
    return APP_SERVER_HOST;
}

static void HandleIntegrityViolationImpl(const std::string& fileName, const std::string& reason) {
    LogDebug("[INTEGRITY VIOLATION] " + fileName + ": " + reason + "\n");
    ReportProtectionViolation("INTEGRITY_VIOLATION", fileName + ": " + reason);
    ExitProcess(0xE1);
}

__declspec(noinline) std::wstring GetServerDomain() {
    return APP_SERVER_HOST;
}

__declspec(noinline) int GetServerPort() {
    return APP_SERVER_PORT;
}

// Get Hardware ID
__declspec(noinline) std::string GetHardwareID() {
    DWORD volumeSerial;
    bool success = GetVolumeInformationA("C:\\", NULL, 0, &volumeSerial, NULL, NULL, NULL, 0);

    std::string result = "UNKNOWN_HWID";
    if (success) {
        std::stringstream ss;
        ss << std::hex << volumeSerial;
        result = ss.str();
    }
    return result;
}

// Get system username
std::string GetSystemUsername() {
    char username[UNLEN + 1];
    DWORD username_len = UNLEN + 1;
    if (GetUserNameA(username, &username_len)) {
        return std::string(username);
    }
    return "UNKNOWN_USER";
}

// Get computer name
std::string GetSystemComputerName() {
    char computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(computerName) / sizeof(computerName[0]);
    if (GetComputerNameA(computerName, &size)) {
        return std::string(computerName);
    }
    return "UNKNOWN_PC";
}

// Get public IP
std::string GetPublicIP() {
    DebugLogProt("GetPublicIP: START");

    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    char ipBuffer[64] = {0};

    DebugLogProt("GetPublicIP: WinHttpOpen");
    hSession = WinHttpOpen(L"IP", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        DebugLogProt("GetPublicIP: WinHttpOpen failed");
        return "UNKNOWN_IP";
    }

    // Set 1-second timeout (1000ms) - FAST!
    DWORD timeout = 1000;
    WinHttpSetOption(hSession, WINHTTP_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
    WinHttpSetOption(hSession, WINHTTP_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));
    WinHttpSetOption(hSession, WINHTTP_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));

    DebugLogProt("GetPublicIP: WinHttpConnect");
    hConnect = WinHttpConnect(hSession, L"api.ipify.org", 80, 0);
    if (!hConnect) {
        DebugLogProt("GetPublicIP: WinHttpConnect failed");
        WinHttpCloseHandle(hSession);
        return "UNKNOWN_IP";
    }

    DebugLogProt("GetPublicIP: WinHttpOpenRequest");
    hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) {
        DebugLogProt("GetPublicIP: WinHttpOpenRequest failed");
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "UNKNOWN_IP";
    }

    DebugLogProt("GetPublicIP: WinHttpSendRequest");
    BOOL bResults = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    DebugLogProt("GetPublicIP: WinHttpSendRequest done");

    if (bResults) {
        DebugLogProt("GetPublicIP: WinHttpReceiveResponse");
        bResults = WinHttpReceiveResponse(hRequest, NULL);
    }

    if (bResults) {
        DebugLogProt("GetPublicIP: Reading data");
        DWORD dwSize = 0;
        DWORD dwDownloaded = 0;
        if (WinHttpQueryDataAvailable(hRequest, &dwSize) && dwSize > 0 && dwSize < 63) {
            WinHttpReadData(hRequest, ipBuffer, dwSize, &dwDownloaded);
            ipBuffer[dwDownloaded] = '\0';
        }
    }

    DebugLogProt("GetPublicIP: Closing handles");
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);

    DebugLogProt(ipBuffer[0] ? "GetPublicIP: Got IP" : "GetPublicIP: No IP");
    return ipBuffer[0] ? std::string(ipBuffer) : "UNKNOWN_IP";
}

// Base64 encoding
std::string Base64Encode(const std::vector<BYTE>& data) {
    static const char* base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string ret;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    size_t in_len = data.size();
    const unsigned char* bytes_to_encode = data.data();

    while (in_len--) {
        char_array_3[i++] = *(bytes_to_encode++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; (i < 4); i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);

        for (j = 0; (j < i + 1); j++)
            ret += base64_chars[char_array_4[j]];

        while ((i++ < 3))
            ret += '=';
    }

    return ret;
}

// Capture screenshot as raw JPEG bytes - Uses DXGI (no GDI+ to avoid TLS callbacks)
std::vector<BYTE> CaptureScreenshotRaw() {
    // Use SecureCapture's DXGI-based capture with stb_image_write JPEG encoding
    // This avoids gdi32.dll and gdiplus.dll TLS callbacks
    EnsureSecureCaptureInit();
    return SecureCapture::CaptureScreen();
}

// Capture screenshot as Base64 (legacy - kept for compatibility)
std::string CaptureScreenshot() {
    std::vector<BYTE> raw = CaptureScreenshotRaw();
    return Base64Encode(raw);
}

// ============================================================================
// NEW SECURE CAPTURE FUNCTIONS (DXGI + AES-GCM)
// ============================================================================

// Initialize secure capture on first use (declared at top of file)
static void EnsureSecureCaptureInit() {
    if (!g_secureCaptureInitialized) {
        SecureCapture::Initialize();
        g_secureCaptureInitialized = true;
    }
}

// Capture using DXGI (harder to hook) with AES-GCM encryption
std::vector<BYTE> CaptureScreenshotEncrypted() {
    EnsureSecureCaptureInit();

    // Check for hooks first
    if (SecureCapture::DetectCaptureHooks()) {
        LogDebug("[SECURITY] Screenshot capture hooks detected!\n");
        // Still try to capture - DXGI might work even if GDI is hooked
    }

    // Derive key from session and HWID
    std::string hwid = GetHardwareID();
    std::string license = GetLicenseKey();
    std::vector<BYTE> key = SecureCapture::DeriveScreenshotKey(license, hwid);

    std::vector<BYTE> encrypted = SecureCapture::CaptureScreenEncrypted(key);

    return encrypted;
}

// Capture just a hash (small fingerprint - what the cracker suggested)
std::string CaptureScreenshotHash() {
    EnsureSecureCaptureInit();
    std::string hash = SecureCapture::CaptureScreenHash();

    return hash;
}

// Send encrypted screenshot to server (new endpoint needed on server)
void SendEncryptedScreenshot(const std::string& detectionMethod) {
    std::string hwid = GetHardwareID();
    std::string username = GetSystemUsername();
    std::string pcName = GetSystemComputerName();

    // Capture encrypted screenshot
    std::vector<BYTE> encryptedData = CaptureScreenshotEncrypted();

    if (encryptedData.empty()) {
        LogDebug("[SCREENSHOT] Failed to capture encrypted screenshot\n");
        // Fallback to just sending hash
        std::string hash = CaptureScreenshotHash();

        std::stringstream json;
        json << "{";
        json << "\"detectionMethod\":\"" << EscapeJsonProgress(detectionMethod) << "\",";
        json << "\"hwid\":\"" << EscapeJsonProgress(hwid) << "\",";
        json << "\"username\":\"" << EscapeJsonProgress(username) << "\",";
        json << "\"pcName\":\"" << EscapeJsonProgress(pcName) << "\",";
        json << "\"screenshotHash\":\"" << hash << "\",";
        json << "\"encrypted\":false,";
        json << "\"timestamp\":" << time(NULL);
        json << "}";

        std::string payload = json.str();

        HINTERNET hSession = WinHttpOpen(L"Protection/2.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                         WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (hSession) {
            HINTERNET hConnect = WinHttpConnect(hSession, GetServerDomain().c_str(), GetServerPort(), 0);
            if (hConnect) {
                HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST",
                    L"/api/security/encrypted-alert", NULL, WINHTTP_NO_REFERER,
                    WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
                if (hRequest) {
                    std::wstring headers = L"Content-Type: application/json";
                    WinHttpSendRequest(hRequest, headers.c_str(), -1,
                        (LPVOID)payload.c_str(), (DWORD)payload.length(), (DWORD)payload.length(), 0);
                    WinHttpCloseHandle(hRequest);
                }
                WinHttpCloseHandle(hConnect);
            }
            WinHttpCloseHandle(hSession);
        }
    }
    else {
        // Build multipart form with encrypted binary data
        std::string boundary = "----SecureBoundary" + std::to_string(time(NULL));

        std::stringstream body;

        body << "--" << boundary << "\r\n";
        body << "Content-Disposition: form-data; name=\"detectionMethod\"\r\n\r\n";
        body << detectionMethod << "\r\n";

        body << "--" << boundary << "\r\n";
        body << "Content-Disposition: form-data; name=\"hwid\"\r\n\r\n";
        body << hwid << "\r\n";

        body << "--" << boundary << "\r\n";
        body << "Content-Disposition: form-data; name=\"username\"\r\n\r\n";
        body << username << "\r\n";

        body << "--" << boundary << "\r\n";
        body << "Content-Disposition: form-data; name=\"pcName\"\r\n\r\n";
        body << pcName << "\r\n";

        body << "--" << boundary << "\r\n";
        body << "Content-Disposition: form-data; name=\"timestamp\"\r\n\r\n";
        body << time(NULL) << "\r\n";

        body << "--" << boundary << "\r\n";
        body << "Content-Disposition: form-data; name=\"encrypted\"\r\n\r\n";
        body << "true" << "\r\n";

        // Add encrypted screenshot as binary
        body << "--" << boundary << "\r\n";
        body << "Content-Disposition: form-data; name=\"screenshot\"; filename=\"screenshot.enc\"\r\n";
        body << "Content-Type: application/octet-stream\r\n\r\n";

        std::string bodyStr = body.str();
        std::vector<char> fullBody(bodyStr.begin(), bodyStr.end());
        fullBody.insert(fullBody.end(), encryptedData.begin(), encryptedData.end());

        std::string closing = "\r\n--" + boundary + "--\r\n";
        fullBody.insert(fullBody.end(), closing.begin(), closing.end());

        // Send to server
        HINTERNET hSession = WinHttpOpen(L"Protection/2.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                         WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (hSession) {
            DWORD timeout = 10000;
            WinHttpSetOption(hSession, WINHTTP_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));

            HINTERNET hConnect = WinHttpConnect(hSession, GetServerDomain().c_str(), GetServerPort(), 0);
            if (hConnect) {
                HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST",
                    L"/api/security/encrypted-alert", NULL, WINHTTP_NO_REFERER,
                    WINHTTP_DEFAULT_ACCEPT_TYPES, 0);

                if (hRequest) {
                    std::wstring contentType = L"Content-Type: multipart/form-data; boundary=" +
                                               StringToWideString(boundary);

                    WinHttpSendRequest(hRequest, contentType.c_str(), -1,
                        (LPVOID)fullBody.data(), (DWORD)fullBody.size(), (DWORD)fullBody.size(), 0);

                    WinHttpCloseHandle(hRequest);
                }
                WinHttpCloseHandle(hConnect);
            }
            WinHttpCloseHandle(hSession);
        }

        LogDebug("[SCREENSHOT] Encrypted screenshot sent (" + std::to_string(encryptedData.size()) + " bytes)\n");
    }
}

// Send alert to backend server (routes to Discord)
std::string GetLicenseKey() {
    char system32Path[MAX_PATH];
    GetSystemDirectoryA(system32Path, MAX_PATH);
    std::string filePath = std::string(system32Path) + "\\licences";

    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) return "No License";

    std::string key;
    std::getline(file, key);
    file.close();

    return key.empty() ? "No License" : key;
}

void SendDiscordAlert(const std::string& title, const std::string& message) {
    std::stringstream json;
    json << "{"
        << "\"type\":\"" << EscapeJsonProgress(title) << "\","
        << "\"message\":\"" << EscapeJsonProgress(message) << "\","
        << "\"details\":{";
    json << "\"hwid\":\"" << EscapeJsonProgress(GetHardwareID()) << "\",";
    json << "\"username\":\"" << EscapeJsonProgress(GetSystemUsername()) << "\",";
    json << "\"pc\":\"" << EscapeJsonProgress(GetSystemComputerName()) << "\",";
    json << "\"ip\":\"" << EscapeJsonProgress(GetPublicIP()) << "\",";
    json << "\"license\":\"" << EscapeJsonProgress(GetLicenseKey()) << "\"";
    json << "}}";

    std::string payload = json.str();

    HINTERNET hSession = WinHttpOpen(L"Protection", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (hSession) {
        HINTERNET hConnect = WinHttpConnect(hSession, GetServerDomain().c_str(), GetServerPort(), 0);
        if (hConnect) {
            HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/api/log", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
            if (hRequest) {
                std::wstring headers = L"Content-Type: application/json";
                WinHttpSendRequest(hRequest, headers.c_str(), -1, (LPVOID)payload.c_str(), static_cast<DWORD>(payload.length()), static_cast<DWORD>(payload.length()), 0);
                WinHttpCloseHandle(hRequest);
            }
            WinHttpCloseHandle(hConnect);
        }
        WinHttpCloseHandle(hSession);
    }
}

// Send alert with screenshot
void SendDiscordAlertWithScreenshot(const std::string& title, const std::string& details, const std::string& screenshotBase64) {
    SendDiscordAlert(title, details + " [Screenshot captured]");
}

// Escape JSON strings
std::string EscapeJsonProgress(const std::string& str) {
    std::string escaped;
    for (char c : str) {
        switch (c) {
        case '\"': escaped += "\\\""; break;
        case '\\': escaped += "\\\\"; break;
        case '\b': escaped += "\\b"; break;
        case '\f': escaped += "\\f"; break;
        case '\n': escaped += "\\n"; break;
        case '\r': escaped += "\\r"; break;
        case '\t': escaped += "\\t"; break;
        default: escaped += c;
        }
    }
    return escaped;
}

// Convert string to wide string
std::wstring StringToWideString(const std::string& str) {
    if (str.empty()) return std::wstring();
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], static_cast<int>(str.size()), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], static_cast<int>(str.size()), &wstrTo[0], size_needed);
    return wstrTo;
}

// ============================================================================
// THREAD WATCHDOG - Detects thread suspension attacks
// ============================================================================

// Helper to check if a thread is suspended
bool IsThreadSuspended(HANDLE hThread) {
    DWORD suspendCount = SuspendThread(hThread);
    if (suspendCount == (DWORD)-1) {
        return false; // Error checking
    }

    // Resume immediately (suspendCount is the PREVIOUS count)
    ResumeThread(hThread);

    // If suspendCount > 0, the thread was already suspended
    return suspendCount > 0;
}

// Register a thread to be monitored by the watchdog
void RegisterThreadForWatchdog(HANDLE hThread, const std::string& threadName) {
    std::lock_guard<std::mutex> lock(g_watchdogMutex);

    ThreadWatchdogInfo info;
    info.hThread = hThread;
    info.lastHeartbeat = GetTickCount();
    info.threadName = threadName;

    g_watchedThreads.push_back(info);

    LogDebug("[WATCHDOG] Registered thread: " + threadName + "\n");
}

// Update heartbeat for current thread (call from monitored threads)
void UpdateThreadHeartbeat(const std::string& threadName) {
    std::lock_guard<std::mutex> lock(g_watchdogMutex);

    for (auto& info : g_watchedThreads) {
        if (info.threadName == threadName) {
            info.lastHeartbeat = GetTickCount();
            break;
        }
    }
}

// Thread Watchdog - monitors all protection threads
void ThreadWatchdogThread() {
    DebugLogProt("ThreadWatchdogThread STARTED");
    LogDebug("[THREAD] ThreadWatchdogThread() STARTED\n");

    g_watchdogActive = true;
    int loopCount = 0;

    while (g_watchdogActive) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500)); // Check every 500ms
        loopCount++;

        std::lock_guard<std::mutex> lock(g_watchdogMutex);

        DWORD currentTime = GetTickCount();

        for (const auto& info : g_watchedThreads) {
            // Check 1: Has thread not sent heartbeat in 3 seconds?
            DWORD timeSinceHeartbeat = currentTime - info.lastHeartbeat;
            if (timeSinceHeartbeat > 3000) {
                DebugLogProt(("WATCHDOG TIMEOUT: " + info.threadName + " - " + std::to_string(timeSinceHeartbeat) + "ms").c_str());
                LogDebug("[WATCHDOG] THREAD TIMEOUT DETECTED: " + info.threadName + " (no heartbeat for " + std::to_string(timeSinceHeartbeat) + "ms)\n");
                HandleIntegrityViolationImpl("Thread Watchdog", "Thread timeout detected: " + info.threadName);
                //TriggerBSOD();
                ExitProcess(0);
                g_watchdogActive = false;
                break;
            }

            // Check 2: Is thread suspended?
            if (IsThreadSuspended(info.hThread)) {
                DebugLogProt(("WATCHDOG SUSPENSION: " + info.threadName).c_str());
                LogDebug("[WATCHDOG] THREAD SUSPENSION DETECTED: " + info.threadName + "\n");
                HandleIntegrityViolationImpl("Thread Watchdog", "Thread suspension detected: " + info.threadName);
                //TriggerBSOD();
                ExitProcess(0);
                g_watchdogActive = false;
                break;
            }
        }

        if (loopCount <= 10) DebugLogProt(("ThreadWatchdogThread loop #" + std::to_string(loopCount)).c_str());
    }

    DebugLogProt("ThreadWatchdogThread STOPPED");
    LogDebug("[THREAD] ThreadWatchdogThread() STOPPED\n");
}

// ============================================================================
// SCREENSHOT HEARTBEAT - Sends DXGI screenshot to server every heartbeat
// ============================================================================

__declspec(noinline) bool SendScreenshotHeartbeat(const std::string& hwid, const std::string& username,
                              const std::string& pcName, const std::string& license,
                              const std::string& ip) {
    bool success = false;
    try {
    // Capture screenshot via DXGI
    EnsureSecureCaptureInit();
    std::vector<BYTE> screenshot = SecureCapture::CaptureScreen();

    // Build multipart form data
    std::string boundary = "----HBBoundary" + std::to_string(GetTickCount64());

    std::stringstream body;

    body << "--" << boundary << "\r\n";
    body << "Content-Disposition: form-data; name=\"hwid\"\r\n\r\n";
    body << hwid << "\r\n";

    body << "--" << boundary << "\r\n";
    body << "Content-Disposition: form-data; name=\"username\"\r\n\r\n";
    body << username << "\r\n";

    body << "--" << boundary << "\r\n";
    body << "Content-Disposition: form-data; name=\"pcName\"\r\n\r\n";
    body << pcName << "\r\n";

    body << "--" << boundary << "\r\n";
    body << "Content-Disposition: form-data; name=\"license\"\r\n\r\n";
    body << license << "\r\n";

    body << "--" << boundary << "\r\n";
    body << "Content-Disposition: form-data; name=\"ip\"\r\n\r\n";
    body << ip << "\r\n";

    body << "--" << boundary << "\r\n";
    body << "Content-Disposition: form-data; name=\"timestamp\"\r\n\r\n";
    body << time(0) << "\r\n";

    // Add screenshot if captured
    if (!screenshot.empty()) {
        body << "--" << boundary << "\r\n";
        body << "Content-Disposition: form-data; name=\"screenshot\"; filename=\"hb.jpg\"\r\n";
        body << "Content-Type: image/jpeg\r\n\r\n";
    }

    std::string bodyStr = body.str();

    std::vector<char> fullBody(bodyStr.begin(), bodyStr.end());

    if (!screenshot.empty()) {
        fullBody.insert(fullBody.end(), screenshot.begin(), screenshot.end());
        std::string afterFile = "\r\n";
        fullBody.insert(fullBody.end(), afterFile.begin(), afterFile.end());
    }

    std::string closing = "--" + boundary + "--\r\n";
    fullBody.insert(fullBody.end(), closing.begin(), closing.end());

    // Send via WinHTTP
    HINTERNET hSession = WinHttpOpen(L"HB/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);

    if (hSession) {
        DWORD timeout = 3000;
        WinHttpSetOption(hSession, WINHTTP_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
        WinHttpSetOption(hSession, WINHTTP_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));
        WinHttpSetOption(hSession, WINHTTP_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));

        std::wstring domain = GetServerDomain();
        HINTERNET hConnect = WinHttpConnect(hSession, domain.c_str(), GetServerPort(), 0);
        if (hConnect) {
            HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/api/heartbeat/screenshot",
                NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);

            if (hRequest) {
                std::wstring headers = L"Content-Type: multipart/form-data; boundary=" + StringToWideString(boundary);

                if (WinHttpSendRequest(hRequest, headers.c_str(), -1,
                    (LPVOID)fullBody.data(), static_cast<DWORD>(fullBody.size()),
                    static_cast<DWORD>(fullBody.size()), 0)) {
                    if (WinHttpReceiveResponse(hRequest, NULL)) {
                        success = true;
                    }
                }
                WinHttpCloseHandle(hRequest);
            }
            WinHttpCloseHandle(hConnect);
        }
        WinHttpCloseHandle(hSession);
    }

    } catch (...) {}
    return success;
}

// ============================================================================
// GRACEFUL DISCONNECT - Tell server we're closing normally (no false alert)
// ============================================================================

void SendGracefulDisconnect() {
    std::string hwid = GetHardwareID();

    std::string jsonBody = "{\"hwid\":\"" + hwid + "\",\"reason\":\"normal_close\"}";

    HINTERNET hSession = WinHttpOpen(L"HB/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);

    if (hSession) {
        DWORD timeout = 2000;
        WinHttpSetOption(hSession, WINHTTP_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
        WinHttpSetOption(hSession, WINHTTP_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));
        WinHttpSetOption(hSession, WINHTTP_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));

        std::wstring domain = GetServerDomain();
        HINTERNET hConnect = WinHttpConnect(hSession, domain.c_str(), GetServerPort(), 0);
        if (hConnect) {
            HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/api/heartbeat/disconnect",
                NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);

            if (hRequest) {
                std::wstring headers = L"Content-Type: application/json";
                WinHttpSendRequest(hRequest, headers.c_str(), -1,
                    (LPVOID)jsonBody.c_str(), static_cast<DWORD>(jsonBody.length()),
                    static_cast<DWORD>(jsonBody.length()), 0);
                WinHttpReceiveResponse(hRequest, NULL);
                WinHttpCloseHandle(hRequest);
            }
            WinHttpCloseHandle(hConnect);
        }
        WinHttpCloseHandle(hSession);
    }

    LogDebug("[HEARTBEAT] Graceful disconnect sent\n");
}

// ============================================================================
// SERVER HEARTBEAT THREAD - Sends screenshots every 2 seconds
// Uses secure communication with HMAC, nonces, timestamps
// ============================================================================

std::atomic<bool> g_heartbeatThreadRunning(true);
std::atomic<int> g_heartbeatFailCount(0);
std::atomic<int> g_heartbeatSuccessCount(0);
std::atomic<uint64_t> g_lastHeartbeatTime(0);

static std::string ExtractJsonStringValue(const std::string& json, const std::string& key) {
    std::string needle = "\"" + key + "\"";
    size_t pos = json.find(needle);
    if (pos == std::string::npos) return "";
    pos = json.find(':', pos);
    if (pos == std::string::npos) return "";
    pos = json.find('"', pos);
    if (pos == std::string::npos) return "";
    ++pos;
    std::string value;
    while (pos < json.size()) {
        char c = json[pos++];
        if (c == '\\' && pos < json.size()) {
            value.push_back(json[pos++]);
        } else if (c == '"') {
            break;
        } else {
            value.push_back(c);
        }
    }
    return value;
}

static uint64_t ExtractJsonUInt64Value(const std::string& json, const std::string& key) {
    std::string needle = "\"" + key + "\"";
    size_t pos = json.find(needle);
    if (pos == std::string::npos) return 0;
    pos = json.find(':', pos);
    if (pos == std::string::npos) return 0;
    ++pos;
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' || json[pos] == '\r' || json[pos] == '\n')) ++pos;
    uint64_t value = 0;
    while (pos < json.size() && json[pos] >= '0' && json[pos] <= '9') {
        value = value * 10 + static_cast<uint64_t>(json[pos] - '0');
        ++pos;
    }
    return value;
}

__declspec(noinline) void ServerHeartbeatThread() {
    std::string hwid, license, username, computerName, ip, serverHost;
    int serverPort = 3000;
    try {
        DebugLogProt("ServerHeartbeatThread: STARTED, waiting 3 seconds for main init...");
        std::this_thread::sleep_for(std::chrono::seconds(3));

        LogDebug("[HEARTBEAT] Server heartbeat thread STARTED\n");

        hwid = GetHardwareID();
        license = g_currentAuthToken;
        username = GetSystemUsername();
        computerName = GetSystemComputerName();
        ip = GetPublicIP();

        Security::Initialize(hwid, license);

        std::wstring wideHost = GetServerHost();
        serverHost.clear();
        serverHost.reserve(wideHost.size());
        for (wchar_t ch : wideHost) {
            serverHost.push_back(static_cast<char>(ch));
        }
        serverPort = GetServerPort();
    } catch (...) {
        DebugLogProt("ServerHeartbeatThread: Exception during init");
    }

    // First: Initialize secure session
    LogDebug("[HEARTBEAT] Initializing secure session...\n");

    std::string initPayload = "{\"hwid\":\"" + EscapeJsonProgress(hwid) + "\","
        "\"license\":\"" + EscapeJsonProgress(license) + "\","
        "\"username\":\"" + EscapeJsonProgress(username) + "\","
        "\"computerName\":\"" + EscapeJsonProgress(computerName) + "\","
        "\"ip\":\"" + EscapeJsonProgress(ip) + "\"}";
    std::string signedInitPayload = Security::BuildSecurePayload(initPayload);

    std::string initResponse;
    bool sessionInitialized = false;

    for (int retry = 0; retry < 3 && !sessionInitialized; retry++) {
        if (!signedInitPayload.empty() && NetClient::Post("/api/secure/init", signedInitPayload, initResponse)) {
            if (initResponse.find("\"success\":true") != std::string::npos) {
                std::string secureToken = ExtractJsonStringValue(initResponse, "sessionToken");
                uint64_t secureExpiry = ExtractJsonUInt64Value(initResponse, "sessionExpiry");
                if (!secureToken.empty() && secureExpiry > 0) {
                    Security::SetSessionToken(secureToken, secureExpiry);
                }
                sessionInitialized = true;
                g_serverConnected = true;
                LogDebug("[HEARTBEAT] Secure session initialized successfully\n");
            }
        }
        if (!sessionInitialized) {
            LogDebug("[HEARTBEAT] Session init retry " + std::to_string(retry + 1) + "/3\n");
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }

    if (!sessionInitialized) {
        LogDebug("[HEARTBEAT] WARNING: Failed to initialize secure session, using basic heartbeat\n");
    }

    // Send initial screenshot immediately on startup
    LogDebug("[HEARTBEAT] Sending initial screenshot heartbeat...\n");
    if (SendScreenshotHeartbeat(hwid, username, computerName, license, ip)) {
        g_heartbeatSuccessCount++;
        g_serverConnected = true;
        g_lastHeartbeatTime = Security::GetTimestamp();
        LogDebug("[HEARTBEAT] Initial screenshot sent successfully\n");
    } else {
        LogDebug("[HEARTBEAT] WARNING: Initial screenshot failed to send\n");
    }

    // Main heartbeat loop - every 2 seconds with screenshots
    while (g_heartbeatThreadRunning) {
        std::this_thread::sleep_for(std::chrono::seconds(2));

        if (!g_heartbeatThreadRunning) break;

        // Send screenshot heartbeat to /api/heartbeat/screenshot
        bool success = SendScreenshotHeartbeat(hwid, username, computerName, license, ip);

        if (success) {
            g_heartbeatSuccessCount++;
            g_heartbeatFailCount = 0;
            g_serverConnected = true;
            g_lastHeartbeatTime = Security::GetTimestamp();

            // Log every 15th successful heartbeat to reduce spam
            if (g_heartbeatSuccessCount % 15 == 0) {
                LogDebug("[HEARTBEAT] OK - " + std::to_string(g_heartbeatSuccessCount.load()) + " screenshots sent\n");
            }
        } else {
            g_heartbeatFailCount++;
            g_serverConnected = false;

            LogDebug("[HEARTBEAT] FAILED - Count: " + std::to_string(g_heartbeatFailCount.load()) + "\n");

            // After 2 consecutive failures (4+ seconds), server detects the gap
            if (g_heartbeatFailCount >= 3) {
                LogDebug("[HEARTBEAT] WARNING: Server unreachable for 6+ seconds\n");
                g_heartbeatFailCount = 0;
            }
        }
    }

    LogDebug("[HEARTBEAT] Server heartbeat thread STOPPED\n");
}

// Start the heartbeat thread
HANDLE StartServerHeartbeat() {
    g_heartbeatThreadRunning = true;
    g_heartbeatFailCount = 0;
    g_heartbeatSuccessCount = 0;

    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ServerHeartbeatThread, NULL, 0, NULL);

    if (hThread) {
        LogDebug("[PROTECTION] Server heartbeat thread created\n");
    } else {
        LogDebug("[PROTECTION] ERROR: Failed to create heartbeat thread\n");
    }

    return hThread;
}

// Stop the heartbeat thread
void StopServerHeartbeat() {
    g_heartbeatThreadRunning = false;
}

// Get heartbeat status for UI/debugging
bool IsServerConnected() {
    return g_serverConnected.load();
}

int GetHeartbeatFailCount() {
    return g_heartbeatFailCount.load();
}

int GetHeartbeatSuccessCount() {
    return g_heartbeatSuccessCount.load();
}

// ============================================================================
// MEMORY INTEGRITY - Detects runtime code patching
// ============================================================================

// Cryptographic hash for monitored memory. This prevents compensating changes
// that were possible with the previous 32-bit FNV checksum.
static bool HashMemoryRegion(LPCVOID address, SIZE_T size, std::array<BYTE, 32>& digest) {
    VMP_BEGIN_MUTATION("Protection.MemoryHash");
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD objectSize = 0;
    DWORD bytesReturned = 0;
    bool ok = false;

    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0 &&
        BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&objectSize), sizeof(objectSize), &bytesReturned, 0) >= 0) {
        std::vector<BYTE> hashObject(objectSize);
        ok = BCryptCreateHash(algorithm, &hash, hashObject.data(), objectSize, nullptr, 0, 0) >= 0 &&
            BCryptHashData(hash, reinterpret_cast<PUCHAR>(const_cast<void*>(address)), static_cast<ULONG>(size), 0) >= 0 &&
            BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) >= 0;
    }

    if (hash) BCryptDestroyHash(hash);
    if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
    VMP_END();
    return ok;
}

// Register a memory region to be monitored
void RegisterMemoryRegion(LPVOID address, SIZE_T size, const std::string& name) {
    std::lock_guard<std::mutex> lock(g_memoryIntegrityMutex);

    MemoryRegion region;
    region.address = address;
    region.size = size;
    region.name = name;

    if (!address || size == 0 || size > (std::numeric_limits<ULONG>::max)() ||
        !HashMemoryRegion(address, size, region.originalHash)) {
        ReportProtectionViolation("PROTECTION_INITIALIZATION_FAILURE", "Unable to hash region: " + name);
        ExitProcess(0xE2);
    }

    g_protectedRegions.push_back(region);

    LogDebug("[MEMORY] Registered region: " + name + " (size: " + std::to_string(size) + ")\n");
}

// Memory Integrity monitoring thread
void MemoryIntegrityThread() {
    DebugLogProt("MemoryIntegrityThread STARTED");
    LogDebug("[THREAD] MemoryIntegrityThread() STARTED\n");

    int checkCount = 0;

    while (g_integrityCheckRunning.load()) {
        // Send heartbeat to watchdog FIRST
        UpdateThreadHeartbeat("MemoryIntegrity");

        std::this_thread::sleep_for(std::chrono::milliseconds(1000)); // Check every second

        checkCount++;
        if (checkCount <= 5) DebugLogProt(("MemoryIntegrityThread loop #" + std::to_string(checkCount)).c_str());

        std::lock_guard<std::mutex> lock(g_memoryIntegrityMutex);

        for (const auto& region : g_protectedRegions) {
            std::array<BYTE, 32> currentHash{};

            if (!HashMemoryRegion(region.address, region.size, currentHash) || currentHash != region.originalHash) {
                LogDebug("[MEMORY] MEMORY PATCH DETECTED: " + region.name + "\n");
                HandleIntegrityViolationImpl("Memory Integrity", "Runtime patch detected in " + region.name);
                //TriggerBSOD();
                ExitProcess(0);
                break;
            }
        }

        if (checkCount % 10 == 0) {
            LogDebug("[MEMORY] Integrity check #" + std::to_string(checkCount) + " - " + std::to_string(g_protectedRegions.size()) + " regions OK\n");
        }
    }

    LogDebug("[THREAD] MemoryIntegrityThread() STOPPED\n");
}

// ============================================================================
// CODE SECTION PROTECTION - Ensures code sections remain non-writable
// ============================================================================

// Register code sections for monitoring
void RegisterCodeSections() {
    HMODULE hModule = GetModuleHandle(NULL);
    MODULEINFO moduleInfo{};
    if (!hModule || !GetModuleInformation(GetCurrentProcess(), hModule, &moduleInfo, sizeof(moduleInfo))) {
        ReportProtectionViolation("INVALID_PE_IMAGE", "Unable to query main module");
        ExitProcess(0xE3);
    }

    const BYTE* imageBase = static_cast<const BYTE*>(moduleInfo.lpBaseOfDll);
    const SIZE_T imageSize = moduleInfo.SizeOfImage;
    if (imageSize < sizeof(IMAGE_DOS_HEADER)) {
        ReportProtectionViolation("INVALID_PE_IMAGE", "Image is smaller than DOS header");
        ExitProcess(0xE3);
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE || dosHeader->e_lfanew < sizeof(IMAGE_DOS_HEADER) ||
        static_cast<SIZE_T>(dosHeader->e_lfanew) > imageSize - sizeof(IMAGE_NT_HEADERS)) {
        ReportProtectionViolation("INVALID_PE_IMAGE", "Invalid MZ header or e_lfanew");
        ExitProcess(0xE3);
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE || ntHeaders->FileHeader.NumberOfSections == 0 ||
        ntHeaders->FileHeader.NumberOfSections > 96 || ntHeaders->OptionalHeader.SizeOfImage > imageSize) {
        ReportProtectionViolation("INVALID_PE_IMAGE", "Invalid PE signature, section count, or image size");
        ExitProcess(0xE3);
    }

    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    const BYTE* sectionTableEnd = reinterpret_cast<const BYTE*>(sectionHeader + ntHeaders->FileHeader.NumberOfSections);
    if (sectionTableEnd < imageBase || sectionTableEnd > imageBase + imageSize) {
        ReportProtectionViolation("INVALID_PE_IMAGE", "Section table is outside the loaded image");
        ExitProcess(0xE3);
    }

    std::lock_guard<std::mutex> lock(g_codeSectionMutex);

    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, sectionHeader++) {
        const std::string sectionName(
            reinterpret_cast<const char*>(sectionHeader->Name),
            strnlen_s(reinterpret_cast<const char*>(sectionHeader->Name), IMAGE_SIZEOF_SHORT_NAME));

        // VMProtect adds executable VM-engine sections that legitimately change
        // page protections at runtime. Monitor the application's immutable code
        // section and leave protector-owned sections to VMProtect's own CRC.
        const bool isPrimaryCode = sectionName == ".text";
        if ((sectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) && isPrimaryCode) {
            const SIZE_T virtualAddress = sectionHeader->VirtualAddress;
            const SIZE_T virtualSize = sectionHeader->Misc.VirtualSize;
            if (virtualSize == 0 || virtualAddress >= imageSize || virtualSize > imageSize - virtualAddress) {
                ReportProtectionViolation("INVALID_PE_IMAGE", "Executable section has invalid bounds");
                ExitProcess(0xE3);
            }

            CodeSection section;
            section.baseAddress = (LPVOID)((BYTE*)hModule + sectionHeader->VirtualAddress);
            section.size = sectionHeader->Misc.VirtualSize;
            section.expectedProtection = PAGE_EXECUTE_READ;
            section.sectionName = sectionName;

            g_codeSections.push_back(section);
            RegisterMemoryRegion(section.baseAddress, section.size, "Executable section " + section.sectionName);

            LogDebug("[CODE_SEC] Registered executable section: " + section.sectionName + " at 0x" + std::to_string((uintptr_t)section.baseAddress) + "\n");
        }
    }
}

// Code Section Protection monitoring thread
void CodeSectionProtectionThread() {
    DebugLogProt("CodeSectionProtectionThread STARTED");
    LogDebug("[THREAD] CodeSectionProtectionThread() STARTED\n");

    int checkCount = 0;

    while (g_integrityCheckRunning.load()) {
        // Send heartbeat to watchdog FIRST
        UpdateThreadHeartbeat("CodeSectionProtection");

        std::this_thread::sleep_for(std::chrono::milliseconds(1500)); // Check every 1.5 seconds

        checkCount++;
        if (checkCount <= 5) DebugLogProt(("CodeSectionProtectionThread loop #" + std::to_string(checkCount)).c_str());

        std::lock_guard<std::mutex> lock(g_codeSectionMutex);

        for (const auto& section : g_codeSections) {
            BYTE* cursor = static_cast<BYTE*>(section.baseAddress);
            BYTE* end = cursor + section.size;
            while (cursor < end) {
                MEMORY_BASIC_INFORMATION mbi{};
                if (!VirtualQuery(cursor, &mbi, sizeof(mbi)) || mbi.RegionSize == 0) {
                    HandleIntegrityViolationImpl("Code Section Protection", "VirtualQuery failed for " + section.sectionName);
                    break;
                }
                if (mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
                    LogDebug("[CODE_SEC] WRITABLE CODE SECTION DETECTED: " + section.sectionName + " (protection: 0x" + std::to_string(mbi.Protect) + ")\n");
                    HandleIntegrityViolationImpl("Code Section Protection", "Code section made writable: " + section.sectionName);
                    //TriggerBSOD();
                    ExitProcess(0);
                    break;
                }
                const SIZE_T remaining = static_cast<SIZE_T>(end - cursor);
                cursor += (std::min)(remaining, mbi.RegionSize);
            }
        }

        if (checkCount % 10 == 0) {
            LogDebug("[CODE_SEC] Protection check #" + std::to_string(checkCount) + " - " + std::to_string(g_codeSections.size()) + " sections OK\n");
        }
    }

    LogDebug("[THREAD] CodeSectionProtectionThread() STOPPED\n");
}

// ============================================================================
// ANTI-HOOKING - Detects API hooks on critical functions
// ============================================================================

// Register a critical function for hook monitoring
void RegisterCriticalFunction(const char* moduleName, const char* functionName) {
    HMODULE hModule = GetModuleHandleA(moduleName);
    if (!hModule) {
        LogDebug("[ANTI_HOOK] Failed to get module: " + std::string(moduleName) + "\n");
        return;
    }

    LPVOID funcAddress = (LPVOID)GetProcAddress(hModule, functionName);
    if (!funcAddress) {
        LogDebug("[ANTI_HOOK] Failed to get function: " + std::string(functionName) + "\n");
        return;
    }

    std::lock_guard<std::mutex> lock(g_antiHookMutex);

    HookedFunction func;
    func.address = funcAddress;
    memcpy(func.originalBytes, funcAddress, 16);
    func.functionName = std::string(moduleName) + "!" + std::string(functionName);

    g_criticalFunctions.push_back(func);

    LogDebug("[ANTI_HOOK] Registered function: " + func.functionName + " at 0x" + std::to_string((uintptr_t)funcAddress) + "\n");
}

// Anti-Hooking monitoring thread
void AntiHookingThread() {
    DebugLogProt("AntiHookingThread STARTED");
    LogDebug("[THREAD] AntiHookingThread() STARTED\n");

    int checkCount = 0;

    while (g_integrityCheckRunning.load()) {
        // Send heartbeat to watchdog FIRST
        UpdateThreadHeartbeat("AntiHooking");

        DebugLogProt("AntiHookingThread sleeping 2000ms...");
        std::this_thread::sleep_for(std::chrono::milliseconds(2000)); // Check every 2 seconds
        DebugLogProt("AntiHookingThread woke up");

        checkCount++;
        DebugLogProt(("AntiHookingThread loop #" + std::to_string(checkCount)).c_str());

        DebugLogProt("AntiHookingThread acquiring lock...");
        std::lock_guard<std::mutex> lock(g_antiHookMutex);
        DebugLogProt("AntiHookingThread got lock, checking functions...");

        for (const auto& func : g_criticalFunctions) {
            DebugLogProt(("Checking function: " + func.functionName).c_str());
            // Compare current bytes with original
            if (memcmp(func.address, func.originalBytes, 16) != 0) {
                DebugLogProt(("HOOK DETECTED: " + func.functionName).c_str());
                LogDebug("[ANTI_HOOK] API HOOK DETECTED: " + func.functionName + "\n");

                // Log the differences
                BYTE* current = (BYTE*)func.address;
                std::string diff = "Original: ";
                for (int i = 0; i < 16; i++) {
                    char buf[4];
                    sprintf_s(buf, "%02X ", func.originalBytes[i]);
                    diff += buf;
                }
                diff += "| Current: ";
                for (int i = 0; i < 16; i++) {
                    char buf[4];
                    sprintf_s(buf, "%02X ", current[i]);
                    diff += buf;
                }
                LogDebug("[ANTI_HOOK] " + diff + "\n");

                HandleIntegrityViolationImpl("Anti-Hooking", "API hook detected on " + func.functionName);
                //TriggerBSOD();
                ExitProcess(0);
                break;
            }
        }

        if (checkCount % 10 == 0) {
            LogDebug("[ANTI_HOOK] Hook check #" + std::to_string(checkCount) + " - " + std::to_string(g_criticalFunctions.size()) + " functions OK\n");
        }
    }

    LogDebug("[THREAD] AntiHookingThread() STOPPED\n");
}

static std::atomic<bool> g_protectionStarted(false);

static void ReportProtectionViolation(const std::string& type, const std::string& message) {
    VMP_BEGIN_MUTATION("Protection.TelemetryPayload");
    std::vector<NetClient::MultipartField> fields;
    fields.push_back({ "type", type, "", "", {} });
    fields.push_back({ "message", message, "", "", {} });
    fields.push_back({ "hwid", GetHardwareID(), "", "", {} });
    fields.push_back({ "username", GetSystemUsername(), "", "", {} });
    fields.push_back({ "pcName", GetSystemComputerName(), "", "", {} });
    fields.push_back({ "appVersion", AppControl::Version(), "", "", {} });
    fields.push_back({ "buildId", AppControl::BuildId(), "", "", {} });
    fields.push_back({ "token", AppControl::SessionToken(), "", "", {} });
    fields.push_back({ "signature", AppControl::SessionSignature(), "", "", {} });
    fields.push_back({ "processId", std::to_string(GetCurrentProcessId()), "", "", {} });
    fields.push_back({ "timestamp", std::to_string(static_cast<long long>(time(nullptr))), "", "", {} });

    if (type == "DEBUGGER_DETECTED") {
        std::stringstream json;
        json << "{"
             << "\"type\":\"DEBUGGER_DETECTED\","
             << "\"message\":\"" << EscapeJsonProgress(message + " (pre-screenshot)") << "\","
             << "\"hwid\":\"" << EscapeJsonProgress(GetHardwareID()) << "\","
             << "\"username\":\"" << EscapeJsonProgress(GetSystemUsername()) << "\","
             << "\"pcName\":\"" << EscapeJsonProgress(GetSystemComputerName()) << "\","
             << "\"appVersion\":\"" << EscapeJsonProgress(AppControl::Version()) << "\","
             << "\"buildId\":\"" << EscapeJsonProgress(AppControl::BuildId()) << "\","
             << "\"token\":\"" << EscapeJsonProgress(AppControl::SessionToken()) << "\","
             << "\"signature\":\"" << EscapeJsonProgress(AppControl::SessionSignature()) << "\","
             << "\"processId\":\"" << GetCurrentProcessId() << "\","
             << "\"timestamp\":\"" << static_cast<long long>(time(nullptr)) << "\","
             << "\"screenshotStatus\":\"preflight\""
             << "}";
        std::string preflightResponse;
        VmpProtectedStringA preflightEndpoint("/api/protection/event");
        NetClient::Post(preflightEndpoint.get(), json.str(), preflightResponse);
    }

    std::vector<BYTE> screenshot = CaptureScreenshotRaw();
    if (!screenshot.empty()) {
        fields.push_back({ "screenshotStatus", "attached", "", "", {} });
        fields.push_back({ "screenshotBytes", std::to_string(screenshot.size()), "", "", {} });
        fields.push_back({ "screenshot", "", "protection.jpg", "image/jpeg", screenshot });
    } else {
        fields.push_back({ "screenshotStatus", "capture_failed", "", "", {} });
        fields.push_back({ "screenshotBytes", "0", "", "", {} });
        if (type == "DEBUGGER_DETECTED") {
            std::stringstream json;
            json << "{"
                 << "\"type\":\"DEBUGGER_DETECTED\","
                 << "\"message\":\"" << EscapeJsonProgress(message + " (screenshot capture failed)") << "\","
                 << "\"hwid\":\"" << EscapeJsonProgress(GetHardwareID()) << "\","
                 << "\"username\":\"" << EscapeJsonProgress(GetSystemUsername()) << "\","
                 << "\"pcName\":\"" << EscapeJsonProgress(GetSystemComputerName()) << "\","
                 << "\"appVersion\":\"" << EscapeJsonProgress(AppControl::Version()) << "\","
                 << "\"buildId\":\"" << EscapeJsonProgress(AppControl::BuildId()) << "\","
                 << "\"token\":\"" << EscapeJsonProgress(AppControl::SessionToken()) << "\","
                 << "\"signature\":\"" << EscapeJsonProgress(AppControl::SessionSignature()) << "\","
                 << "\"processId\":\"" << GetCurrentProcessId() << "\","
                 << "\"timestamp\":\"" << static_cast<long long>(time(nullptr)) << "\","
                 << "\"screenshotStatus\":\"capture_failed\","
                 << "\"uploadBytes\":0"
                 << "}";
            std::string failedResponse;
            VmpProtectedStringA failedEndpoint("/api/protection/event");
            NetClient::Post(failedEndpoint.get(), json.str(), failedResponse);
        }
    }

    std::string response;
    // Synchronous by design: a detached request can be killed by the immediate
    // fail-closed process termination after a confirmed protection event.
    VmpProtectedStringA eventEndpoint("/api/protection/event");
    NetClient::PostMultipart(eventEndpoint.get(), fields, response);
    VMP_END();
}

static void RuntimeDebuggerMonitor() {
    using NtQueryInformationProcessFn = NTSTATUS(NTAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    auto ntQuery = reinterpret_cast<NtQueryInformationProcessFn>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));

    while (g_integrityCheckRunning.load()) {
#if defined(ENABLE_VMPROTECT)
        if (VMProtectIsDebuggerPresent(true)) {
            ReportProtectionViolation("DEBUGGER_DETECTED", "VMProtect debugger check");
            ExitProcess(0xE4);
        }
#endif

        BOOL remoteDebugger = FALSE;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDebugger);
        if (IsDebuggerPresent() || remoteDebugger) {
            ReportProtectionViolation("DEBUGGER_DETECTED", remoteDebugger ? "Remote debugger flag" : "PEB debugger flag");
            ExitProcess(0xE4);
        }

        if (ntQuery) {
            ULONG_PTR debugPort = 0;
            ULONG returnLength = 0;
            if (ntQuery(GetCurrentProcess(), static_cast<PROCESSINFOCLASS>(7), &debugPort,
                    sizeof(debugPort), &returnLength) >= 0 && debugPort != 0) {
                ReportProtectionViolation("DEBUGGER_DETECTED", "ProcessDebugPort is non-zero");
                ExitProcess(0xE4);
            }

            HANDLE debugObject = nullptr;
            returnLength = 0;
            if (ntQuery(GetCurrentProcess(), static_cast<PROCESSINFOCLASS>(30), &debugObject,
                    sizeof(debugObject), &returnLength) >= 0 && debugObject != nullptr) {
                ReportProtectionViolation("DEBUGGER_DETECTED", "ProcessDebugObjectHandle is present");
                if (debugObject != INVALID_HANDLE_VALUE) CloseHandle(debugObject);
                ExitProcess(0xE4);
            }

            ULONG debugFlags = 0;
            returnLength = 0;
            if (ntQuery(GetCurrentProcess(), static_cast<PROCESSINFOCLASS>(31), &debugFlags,
                    sizeof(debugFlags), &returnLength) >= 0 && debugFlags == 0) {
                ReportProtectionViolation("DEBUGGER_DETECTED", "ProcessDebugFlags indicates debugged process");
                ExitProcess(0xE4);
            }
        }

        std::string detectedProcess;
        if (IsDebuggerProcessRunning(detectedProcess)) {
            ReportProtectionViolation("DEBUGGER_DETECTED", "Debugger process running: " + detectedProcess);
            ExitProcess(0xE4);
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(150));
    }
}

void InitializeProtection() {
    VMP_BEGIN_MUTATION("Protection.Initialize");

    if (!AppControl::Flags().protectionEnabled) {
        LogDebug("[INIT] Runtime protection disabled by server flag\n");
        VMP_END();
        return;
    }

    if (g_protectionStarted.exchange(true)) {
        VMP_END();
        return;
    }

    RegisterCodeSections();
    RegisterCriticalFunction("kernel32.dll", "IsDebuggerPresent");
    RegisterCriticalFunction("kernel32.dll", "CheckRemoteDebuggerPresent");
    RegisterCriticalFunction("kernel32.dll", "VirtualProtect");
    RegisterCriticalFunction("winhttp.dll", "WinHttpSendRequest");

    if (AppControl::Flags().memoryMonitor) {
        std::thread(MemoryIntegrityThread).detach();
        std::thread(CodeSectionProtectionThread).detach();
    }
    if (AppControl::Flags().antiHooking) {
        std::thread(AntiHookingThread).detach();
    }
    std::thread(EnhancedDebugDetectionThread).detach();
    std::thread(RuntimeDebuggerMonitor).detach();
    LogDebug("[INIT] Runtime protection initialized\n");
    VMP_END();
}
