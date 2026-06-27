#ifndef PROTECTION_H
#define PROTECTION_H

#include <windows.h>
#include <winternl.h>
#include <string>
#include <vector>
#include <atomic>
#include <mutex>
#include <set>
#include <tlhelp32.h>

// Secure screenshot capture (DXGI + AES-GCM)
#include "secure_capture.h"

// Backend server functions (implemented in protection.cpp)
std::string GenerateAPIAuth();
std::wstring GetServerHost();
std::wstring GetServerDomain();
int GetServerPort();
std::string GetHardwareID();
std::string GetSystemUsername();
std::string GetSystemComputerName();
std::string GetPublicIP();
std::string GetLicenseKey();
std::vector<BYTE> CaptureScreenshotRaw();
std::string CaptureScreenshot();
std::vector<BYTE> CaptureScreenshotEncrypted(); // New: DXGI + AES-GCM encrypted
std::string CaptureScreenshotHash();            // New: Perceptual hash only (small)
void SendDiscordAlert(const std::string& title, const std::string& message);
void SendDiscordAlertWithScreenshot(const std::string& title, const std::string& details, const std::string& screenshotBase64);
void SendEncryptedScreenshot(const std::string& detectionMethod); // New: Sends encrypted screenshot
std::string EscapeJsonProgress(const std::string& str);
std::wstring StringToWideString(const std::string& str);

// Global protection state variables
extern std::atomic<bool> g_serverConnected;
extern std::atomic<bool> g_heartbeatRunning;
extern std::string g_connectionError;
extern std::string g_currentAuthToken;
extern std::atomic<bool> g_debugDetected;
extern std::atomic<int> g_debugAttempts;
extern std::atomic<bool> g_loaderOutdated;

// Debug logging
extern std::vector<std::string> g_debugLogBuffer;
extern std::mutex g_logMutex;
extern const int MAX_LOG_LINES;

void LogDebug(const std::string& message);
std::string GetBufferedLogs();
void ClearLogBuffer();

// Protection threads
void ServerHeartbeatThread();
void EnhancedDebugDetectionThread();
void OutdatedLoaderMonitorThread();

// Alert functions
void SendDebuggerAlertReliable(const std::string& detectionMethod);
void SendDirectDiscordAlert(const std::string& detectionMethod);
void SendDebuggerAlertWithScreenshot(const std::string& detectionMethod);

// Detection functions
bool IsDebuggerProcessRunning(std::string& detectedProcess);
void TriggerBSOD();

// Server-side ban check
bool CheckServerBan();

// Monitoring threads
void monitorCheckRemoteDebuggerPresent();
void checkDebugger();

// ============================================================================
// SERVER HEARTBEAT - Screenshot heartbeat every 2 seconds
// ============================================================================
bool SendScreenshotHeartbeat(const std::string& hwid, const std::string& username,
                              const std::string& pcName, const std::string& license,
                              const std::string& ip);
HANDLE StartServerHeartbeat();
void StopServerHeartbeat();
void SendGracefulDisconnect();
bool IsServerConnected();
int GetHeartbeatFailCount();
int GetHeartbeatSuccessCount();

// Global integrity state
extern std::atomic<bool> g_integrityCheckRunning;

// ============================================================================
// NEW PROTECTION MECHANISMS - Thread Watchdog, Memory Integrity, etc.
// ============================================================================

// Thread Watchdog - Detects thread suspension attacks
void RegisterThreadForWatchdog(HANDLE hThread, const std::string& threadName);
void UpdateThreadHeartbeat(const std::string& threadName);
void ThreadWatchdogThread();
extern std::atomic<bool> g_watchdogActive;

// Memory Integrity - Detects runtime code patching
void RegisterMemoryRegion(LPVOID address, SIZE_T size, const std::string& name);
void MemoryIntegrityThread();

// Code Section Protection - Ensures code sections remain non-writable
void RegisterCodeSections();
void CodeSectionProtectionThread();

// Anti-Hooking - Detects API hooks on critical functions
void RegisterCriticalFunction(const char* moduleName, const char* functionName);
void AntiHookingThread();

void InitializeProtection();
void HandleEarlyProtectionDetection();

#endif // PROTECTION_H
