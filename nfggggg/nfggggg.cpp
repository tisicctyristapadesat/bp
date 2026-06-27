#include <windows.h>
#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")
#include <iostream>
#include <string>
#include <sstream>
#include <fstream>
#include <chrono>
#include <thread>
#include <algorithm>
#include <cmath>
#include <urlmon.h>
#include <shellapi.h>
#include <shlobj.h>
#include <taskschd.h>
#include <set>
#include <mutex>
#include <vector>

#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "taskschd.lib")

#include <dwmapi.h>
#include <objbase.h>
#pragma comment(lib, "dwmapi.lib")

#ifndef WDA_EXCLUDEFROMCAPTURE
#define WDA_EXCLUDEFROMCAPTURE 0x00000011
#endif
#ifndef WDA_NONE
#define WDA_NONE 0x00000000
#endif

// Using NetClient for secure backend communication
#include "net_client.h"
#include "server_config.h"
#define IMGUI_DEFINE_MATH_OPERATORS
#include "imgui.h"
#include "imgui_internal.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"

#include <d3d11.h>
#pragma comment(lib, "d3d11.lib")

// DirectX 11 globals
static ID3D11Device*            g_pd3dDevice = nullptr;
static ID3D11DeviceContext*     g_pd3dDeviceContext = nullptr;
static IDXGISwapChain*          g_pSwapChain = nullptr;
static ID3D11RenderTargetView*  g_mainRenderTargetView = nullptr;

// Forward declarations for DirectX
bool CreateDeviceD3D(HWND hWnd);
void CleanupDeviceD3D();
void CreateRenderTarget();
void CleanupRenderTarget();
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

// Forward declare message handler from imgui_impl_win32.cpp
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

#include "hwid.h"
#include "protection.h"
#include "injections.h"
#include "injection.h"
#include "api_loader.h"
#include "vmprotect_markers.h"
#include "app_control.h"
#include "security.h"

// ===== DEBUG FILE LOGGING (thread-safe with SRWLOCK) =====
static SRWLOCK g_debugLogLock = SRWLOCK_INIT;
static volatile LONG g_debugLogInitialized = 0;
static char g_debugLogPath[MAX_PATH] = {0};

void DebugLog(const char* msg) {
#if defined(ENABLE_VMPROTECT)
    UNREFERENCED_PARAMETER(msg);
    return;
#else
    // Thread-safe one-time initialization
    if (InterlockedCompareExchange(&g_debugLogInitialized, 0, 0) == 0) {
        AcquireSRWLockExclusive(&g_debugLogLock);
        if (g_debugLogInitialized == 0) {
            GetTempPathA(MAX_PATH, g_debugLogPath);
            strcat_s(g_debugLogPath, "nfg_debug.log");
            // Clear old log
            HANDLE hFile = CreateFileA(g_debugLogPath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hFile != INVALID_HANDLE_VALUE) {
                const char header[] = "=== DEBUG LOG START ===\n";
                DWORD written = 0;
                WriteFile(hFile, header, sizeof(header) - 1, &written, NULL);
                CloseHandle(hFile);
            }
            InterlockedExchange(&g_debugLogInitialized, 1);
        }
        ReleaseSRWLockExclusive(&g_debugLogLock);
    }

    // Thread-safe file write using Win32 (no CRT FILE operations)
    AcquireSRWLockExclusive(&g_debugLogLock);
    HANDLE hFile = CreateFileA(g_debugLogPath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
        OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        SetFilePointer(hFile, 0, NULL, FILE_END);
        char buf[1024];
        DWORD tick = GetTickCount();
        int len = wsprintfA(buf, "[%lu] %s\n", tick, msg);
        DWORD written = 0;
        WriteFile(hFile, buf, (DWORD)len, &written, NULL);
        CloseHandle(hFile);
    }
    ReleaseSRWLockExclusive(&g_debugLogLock);
#endif
}

// ===== GLOBAL UI VARIABLES =====
static bool g_isProcessing = false;
char g_statusMessage[256] = "Ready";
float g_progressValue = 0.0f;
static float g_animTime = 0.0f;
static bool g_showBypassPopup = false;
static bool g_bypassPopupJustOpened = false;
static bool g_showSettingsPopup = false;
static int g_selectedProvider = 0;
static volatile LONG g_providerVisible[7] = { 0, 0, 0, 0, 0, 0, 0 };
static volatile LONG g_featureRefreshInFlight = 0;
static ULONGLONG g_lastFeatureRefresh = 0;
static bool g_isDragging = false;
static ImVec2 g_dragOffset;
static bool g_streamproofEnabled = true;
static int g_currentTab = 0;
static ImVec4 g_accentColor = ImVec4(0.300f, 0.535f, 0.790f, 1.0f);
static float g_pickerHue = 0.58f;
static float g_pickerWhite = 0.10f;
static float g_pickerBlack = 0.16f;
bool g_showSpinner = false;
static char g_spinnerMessage[256] = "";
static char g_spinnerDetail[256] = "";
static bool g_spinnerFinished = false;
static bool g_spinnerSuccess = false;
static ULONGLONG g_spinnerStartedAt = 0;
static ULONGLONG g_spinnerFinishedAt = 0;

// Loading screen variables
static bool g_showLoadingScreen = false;
static bool g_updateComplete = false;

// Custom auth / session variables
static bool g_isLoggedIn = false;
static bool g_tosAccepted = false;
static char g_licenseKey[256] = "";
static char g_authMessage[256] = "";
static float g_authMessageTime = 0.0f;
static bool g_authMessageShow = false;
static std::string g_licenseExpiry = "0";
static std::string g_licenseSubscription = "Standard";
static std::string g_licenseUsername = "member";

// Phone feature variables
static bool g_showPhonePopup = false;
static bool g_phoneDownloading = false;
static float g_phoneProgress = 0.0f;
static std::string g_phoneMessage = "";
static std::string g_localIP = "Loading...";

static std::atomic<bool> g_connectionMonitorStarted(false);

static void StartConnectionMonitor() {
    if (g_connectionMonitorStarted.exchange(true)) return;
    std::thread([]() {
        while (g_connectionMonitorStarted.load()) {
            std::string response;
            bool ok = NetClient::Post("/api/test", "{}", response) && response.find("\"status\":\"ok\"") != std::string::npos;
            g_serverConnected.store(ok);
            for (int i=0;i<50&&g_connectionMonitorStarted.load();++i) Sleep(100);
        }
    }).detach();
}

static bool FeatureResponseContains(const std::string& json, const char* name) {
    std::string needle = "\"" + std::string(name) + "\"";
    return json.find(needle) != std::string::npos;
}

static void RefreshServerFeaturesAsync() {
    if (InterlockedCompareExchange(&g_featureRefreshInFlight, 1, 0) != 0) return;
    g_lastFeatureRefresh = GetTickCount64();
    std::thread([]() {
        std::string response;
        if (NetClient::ExternalGet(FEATURE_SERVER_HOST, FEATURE_SERVER_PORT, FEATURE_API_PATH, response, 2000, FEATURE_API_KEY, FEATURE_SERVER_TLS != 0)) {
            const char* names[] = { "TZ", "TZX", "CRN External", "Keyser", "Ghost", "Macho", "South" };
            for (int i = 0; i < 7; ++i) {
                InterlockedExchange(&g_providerVisible[i], FeatureResponseContains(response, names[i]) ? 1 : 0);
            }
        }
        InterlockedExchange(&g_featureRefreshInFlight, 0);
    }).detach();
}

struct USBDriveInfo {
    char driveLetter;
    std::string volumeName;
};

std::vector<USBDriveInfo> GetPluggedUSBDrives() {
    std::vector<USBDriveInfo> usbDrives;
    DWORD drives = GetLogicalDrives();

    for (char letter = 'A'; letter <= 'Z'; ++letter) {
        if (!(drives & (1 << (letter - 'A'))))
            continue;

        char rootPath[] = { letter, ':', '\\', '\0' };

        UINT driveType = GetDriveTypeA(rootPath);
        if (driveType != DRIVE_REMOVABLE)
            continue;

        USBDriveInfo info;
        info.driveLetter = letter;

        char volumeName[MAX_PATH] = {};
        char fileSystem[MAX_PATH] = {};
        DWORD serialNumber = 0, maxComponentLen = 0, fileSystemFlags = 0;

        if (GetVolumeInformationA(
            rootPath,
            volumeName,
            MAX_PATH,
            &serialNumber,
            &maxComponentLen,
            &fileSystemFlags,
            fileSystem,
            MAX_PATH))
        {
            info.volumeName = volumeName[0] ? volumeName : "USB Drive";
        }
        else {
            info.volumeName = "USB Drive";
        }

        usbDrives.push_back(info);
    }

    return usbDrives;
}

bool CheckAndAlertUSBDrives() {
    auto usbDrives = GetPluggedUSBDrives();
    bool anyStillPlugged = false;

    for (const auto& usb : usbDrives) {
        std::string message =
            "Please unplug \"" + usb.volumeName + "\" from your computer.";

        MessageBoxA(
            nullptr,
            message.c_str(),
            "USB Alert",
            MB_OK | MB_ICONWARNING | MB_TOPMOST | MB_SETFOREGROUND
        );

        char rootPath[] = { usb.driveLetter, ':', '\\', '\0' };
        if (GetDriveTypeA(rootPath) == DRIVE_REMOVABLE) {
            anyStillPlugged = true;
        }
    }

    return anyStillPlugged;
}

// ===== FORWARD DECLARATIONS =====
void SetupImGuiStyle();
void ShowAuthMessage(const char* message, float duration = 3.0f);
void AttemptLogin();
void DrawTermsOfServiceWindow(HWND hwnd, bool& done);
void DownloadAndUpdateDLLs();
bool AnimatedButton(const char* label, const ImVec2& size, bool primary = true);
void DrawSpinner(const char* label, float radius, float thickness, const ImVec4& color);
float PulseAnimation(float speed = 2.0f, float min = 0.7f, float max = 1.0f);
std::string GetLicenseExpiryText();
void DrawBackgroundParticles(ImDrawList* draw_list, ImVec2 size);
void DrawAnimatedBorder(ImDrawList* draw_list, ImVec2 pos, ImVec2 size, float rounding, const ImVec4& color);
void DrawCardShadow(ImDrawList* draw_list, ImVec2 pos, ImVec2 size, float rounding);
void DrawCornerAccents(ImDrawList* draw_list, ImVec2 pos, ImVec2 size, float cornerSize);

// ===== STREAMPROOF =====
void SetStreamproof(HWND hwnd, BOOL enable) {
    if (enable) {
        SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE);
        LONG ex = GetWindowLongW(hwnd, GWL_EXSTYLE);
        ex |= WS_EX_TOOLWINDOW;
        ex &= ~WS_EX_APPWINDOW;
        SetWindowLongW(hwnd, GWL_EXSTYLE, ex);
        ITaskbarList* pTaskbar = nullptr;
        if (SUCCEEDED(CoCreateInstance(CLSID_TaskbarList, nullptr, CLSCTX_INPROC_SERVER, IID_ITaskbarList, reinterpret_cast<void**>(&pTaskbar)))) {
            pTaskbar->DeleteTab(hwnd);
            pTaskbar->Release();
        }
    } else {
        SetWindowDisplayAffinity(hwnd, WDA_NONE);
        LONG ex = GetWindowLongW(hwnd, GWL_EXSTYLE);
        ex &= ~WS_EX_TOOLWINDOW;
        ex |= WS_EX_APPWINDOW;
        SetWindowLongW(hwnd, GWL_EXSTYLE, ex);
        ITaskbarList* pTaskbar = nullptr;
        if (SUCCEEDED(CoCreateInstance(CLSID_TaskbarList, nullptr, CLSCTX_INPROC_SERVER, IID_ITaskbarList, reinterpret_cast<void**>(&pTaskbar)))) {
            pTaskbar->AddTab(hwnd);
            pTaskbar->Release();
        }
    }
}

// ===== INJECTION HANDLER FUNCTIONS =====
void ExecuteProviderInjection(int provider);
void ExecuteDLLInjection(const char* dllName);

// ===== PHONE FUNCTIONS =====
void DownloadPhoneApp() {
    // Start immediately - show spinner overlay (like cleaning/destruct)
    g_phoneDownloading = true;
    g_phoneProgress = 0.0f;
    g_showSpinner = true;  // This shows the full-screen spinner overlay
    lstrcpynA(g_spinnerMessage, "Starting server!", sizeof(g_spinnerMessage));

    std::thread([]() {
        // Step 1: Starting server message (immediately) - WITH EXCLAMATION MARK
        lstrcpynA(g_spinnerMessage, "Starting server!", sizeof(g_spinnerMessage));
        Sleep(1000);
        g_phoneProgress = 0.2f;

        // Step 2: Download the exe
        lstrcpynA(g_spinnerMessage, "Downloading phone app!", sizeof(g_spinnerMessage));

        char tempPath[MAX_PATH];
        GetTempPathA(MAX_PATH, tempPath);
        std::string tempFile = std::string(tempPath) + "ilovepibbles.tmp";

        if (!NetClient::DownloadFile("/ilovepibbles.tmp", tempFile)) {
            lstrcpynA(g_spinnerMessage, "Download failed!", sizeof(g_spinnerMessage));
            Sleep(2000);
            g_phoneDownloading = false;
            g_showSpinner = false;
            return;
        }

        Sleep(1000);
        g_phoneProgress = 0.6f;
        lstrcpynA(g_spinnerMessage, "Starting server!", sizeof(g_spinnerMessage));

        // Step 3: Execute the downloaded file via cmd
        std::string cmdCommand = "cmd.exe /c start \"\" \"" + tempFile + "\"";
        system(cmdCommand.c_str());

        Sleep(2000);
        g_phoneProgress = 1.0f;
        lstrcpynA(g_spinnerMessage, "Complete!", sizeof(g_spinnerMessage));

        // Get local IP for message
        g_localIP = NetClient::GetLocalIPAddress();
        std::string message = "✓ Phone access server running!\n\nAccess from phone:\nhttp://" + g_localIP + ":8000";

        MessageBoxA(NULL, message.c_str(), "Phone Access", MB_OK | MB_ICONINFORMATION);

        Sleep(1000);
        g_phoneDownloading = false;
        g_showSpinner = false;
        }).detach();
}

std::string GetJsonValue(const std::string& json, const std::string& key) {
    size_t pos = json.find("\"" + key + "\"");
    if (pos == std::string::npos) return "";

    pos = json.find(":", pos);
    if (pos == std::string::npos) return "";

    pos++;
    while (pos < json.length() && (json[pos] == ' ' || json[pos] == '\t')) pos++;

    if (json[pos] == '\"') {
        pos++;
        size_t end = json.find("\"", pos);
        if (end == std::string::npos) return "";
        return json.substr(pos, end - pos);
    }
    else {
        size_t end = json.find_first_of(",}]", pos);
        if (end == std::string::npos) return "";
        std::string value = json.substr(pos, end - pos);
        size_t start = value.find_first_not_of(" \t\r\n");
        size_t finish = value.find_last_not_of(" \t\r\n");
        if (start == std::string::npos) return "";
        return value.substr(start, finish - start + 1);
    }
}

// ===== DPAPI-PROTECTED LICENSE PERSISTENCE =====
static std::string GetLegacyLicenseFilePath() {
    char system32Path[MAX_PATH];
    GetSystemDirectoryA(system32Path, MAX_PATH);
    return std::string(system32Path) + "\\" + "licences";
}

bool SaveLicenseKey(const std::string& key) {
    if(key.empty()||key.size()>512)return false;
    DATA_BLOB input{(DWORD)key.size(),(BYTE*)key.data()},encrypted{};
    const char entropyText[]="CRN.Loader.License.v1";DATA_BLOB entropy{(DWORD)sizeof(entropyText)-1,(BYTE*)entropyText};
    if(!CryptProtectData(&input,L"CRN Loader License",&entropy,nullptr,nullptr,CRYPTPROTECT_UI_FORBIDDEN,&encrypted))return false;
    HKEY registryKey=nullptr;bool ok=false;
    if(RegCreateKeyExW(HKEY_CURRENT_USER,L"Software\\CRN\\Loader",0,nullptr,0,KEY_SET_VALUE,nullptr,&registryKey,nullptr)==ERROR_SUCCESS){
        ok=RegSetValueExW(registryKey,L"License",0,REG_BINARY,encrypted.pbData,encrypted.cbData)==ERROR_SUCCESS;
        std::string mac=Security::HMAC_SHA256(std::string(APP_HMAC_SALT),key+"|"+AppControl::BuildId()+"|CRN.Loader.License.v2");
        if(ok)RegSetValueExA(registryKey,"LicenseMac",0,REG_SZ,(const BYTE*)mac.c_str(),(DWORD)mac.size()+1);
        RegCloseKey(registryKey);
    }
    if(encrypted.pbData){SecureZeroMemory(encrypted.pbData,encrypted.cbData);LocalFree(encrypted.pbData);}return ok;
}

bool LoadLicenseKey(std::string& key) {
    key.clear();HKEY registryKey=nullptr;DWORD type=0,size=0;
    RegOpenKeyExW(HKEY_CURRENT_USER,L"Software\\CRN\\Loader",0,KEY_QUERY_VALUE,&registryKey);
    if(registryKey){
        if(RegQueryValueExW(registryKey,L"License",nullptr,&type,nullptr,&size)==ERROR_SUCCESS&&type==REG_BINARY&&size>0&&size<4096){
            std::vector<BYTE> data(size);if(RegQueryValueExW(registryKey,L"License",nullptr,&type,data.data(),&size)==ERROR_SUCCESS){
                DATA_BLOB encrypted{size,data.data()},plain{};const char entropyText[]="CRN.Loader.License.v1";DATA_BLOB entropy{(DWORD)sizeof(entropyText)-1,(BYTE*)entropyText};
                if(CryptUnprotectData(&encrypted,nullptr,&entropy,nullptr,nullptr,CRYPTPROTECT_UI_FORBIDDEN,&plain)&&plain.cbData>0&&plain.cbData<=512){
                    key.assign((char*)plain.pbData,plain.cbData);
                    DWORD macType=0,macSize=0;std::string storedMac;
                    if(RegQueryValueExA(registryKey,"LicenseMac",nullptr,&macType,nullptr,&macSize)==ERROR_SUCCESS&&macType==REG_SZ&&macSize>0&&macSize<256){
                        storedMac.resize(macSize);RegQueryValueExA(registryKey,"LicenseMac",nullptr,&macType,(BYTE*)storedMac.data(),&macSize);
                        if(!storedMac.empty()&&storedMac.back()=='\0')storedMac.pop_back();
                        std::string expected=Security::HMAC_SHA256(std::string(APP_HMAC_SALT),key+"|"+AppControl::BuildId()+"|CRN.Loader.License.v2");
                        if(storedMac!=expected){AppControl::ReportCanaryTrigger("SIGNED_LOCAL_CONFIG","Saved license MAC mismatch");key.clear();}
                    }else if(!key.empty()){
                        SaveLicenseKey(key);
                    }
                    SecureZeroMemory(plain.pbData,plain.cbData);LocalFree(plain.pbData);
                }
                SecureZeroMemory(data.data(),data.size());
            }
        }RegCloseKey(registryKey);
    }
    if(!key.empty())return true;
    std::ifstream legacy(GetLegacyLicenseFilePath(),std::ios::binary);if(!legacy.is_open())return false;std::getline(legacy,key);legacy.close();
    if(key.empty())return false;if(SaveLicenseKey(key))DeleteFileA(GetLegacyLicenseFilePath().c_str());return true;
}

static bool DeleteSavedLicense(){
    HKEY key=nullptr;LONG result=RegOpenKeyExW(HKEY_CURRENT_USER,L"Software\\CRN\\Loader",0,KEY_SET_VALUE,&key);
    if(result==ERROR_SUCCESS){result=RegDeleteValueW(key,L"License");RegDeleteValueA(key,"LicenseMac");RegCloseKey(key);}DeleteFileA(GetLegacyLicenseFilePath().c_str());
    return result==ERROR_SUCCESS||result==ERROR_FILE_NOT_FOUND;
}

// ===== DLL DOWNLOAD FUNCTION =====
void DownloadAndUpdateDLLs() {
    AppControl::RefreshFeatureFlags();
    if (AppControl::DownloadsDisabled()) {
        lstrcpynA(g_statusMessage, AppControl::KillReason().c_str(), sizeof(g_statusMessage));
        g_updateComplete = true;
        g_showSpinner = false;
        g_showLoadingScreen = false;
        return;
    }
    g_showSpinner = true;
    lstrcpynA(g_spinnerMessage, "Checking for updates!", sizeof(g_spinnerMessage));

    std::thread([]() {
        Sleep(1500);

        std::string sys32 = injection::GetSystem32Path() + "\\";

        std::string cleaningUrl = "/api/download/cleaning.dll";
        std::string cleaningPath = sys32 + "cleaning.dll";

        DeleteFileA(cleaningPath.c_str());

        if (!NetClient::DownloadFile(cleaningUrl.c_str(), cleaningPath)) {
            lstrcpynA(g_statusMessage, "Update skipped: backend unavailable", sizeof(g_statusMessage));
            g_showSpinner = false;
            g_showLoadingScreen = false;
            return;
        }

        Sleep(1000);

        std::string destructionUrl = "/api/download/dih.dll";
        std::string dihPath = sys32 + "dih.dll";

        DeleteFileA(dihPath.c_str());

        if (!NetClient::DownloadFile(destructionUrl.c_str(), dihPath)) {
            lstrcpynA(g_statusMessage, "Update skipped: backend unavailable", sizeof(g_statusMessage));
            g_showSpinner = false;
            g_showLoadingScreen = false;
            return;
        }

        Sleep(1000);

        if (!injection::FileExists(cleaningPath) || !injection::FileExists(dihPath)) {
            lstrcpynA(g_statusMessage, "Update skipped: files unavailable", sizeof(g_statusMessage));
            g_showSpinner = false;
            g_showLoadingScreen = false;
            return;
        }

        Sleep(1500);

        g_updateComplete = true;
        g_showSpinner = false;
        g_showLoadingScreen = false;
        }).detach();
}

// ===== INJECTION HANDLER FUNCTIONS IMPLEMENTATION =====
void ExecuteProviderInjection(int provider) {
    AppControl::RefreshFeatureFlags();
    if (AppControl::ModulesDisabled()) {
        ShowAuthMessage(AppControl::KillReason().c_str());
        return;
    }
    g_isProcessing = true;
    g_showSpinner = true;
    g_spinnerFinished = false;
    g_spinnerSuccess = false;
    g_spinnerStartedAt = GetTickCount64();
    g_spinnerFinishedAt = 0;
    lstrcpynA(g_spinnerMessage, "Injecting", sizeof(g_spinnerMessage));
    lstrcpynA(g_spinnerDetail, "Preparing provider...", sizeof(g_spinnerDetail));
    lstrcpynA(g_statusMessage, "Starting provider...", sizeof(g_statusMessage));
    g_progressValue = 0.1f;

    std::thread([provider]() {
        bool ok = true;
        try {
            lstrcpynA(g_spinnerDetail, "Running selected bypass...", sizeof(g_spinnerDetail));
            g_progressValue = 0.55f;

            switch (provider) {
            case 0: inject::tz(); break;
            case 1: inject::tzx(); break;
            case 2: inject::ghost(); break;
            case 3: inject::keyser(); break;
            case 4: inject::goath(); break;
            case 5: inject::macho(); break;
            default:
                ok = false;
                lstrcpynA(g_statusMessage, "Invalid provider selected", sizeof(g_statusMessage));
                lstrcpynA(g_spinnerDetail, "Invalid provider selected.", sizeof(g_spinnerDetail));
                break;
            }
        }
        catch (...) {
            ok = false;
            lstrcpynA(g_statusMessage, "Injection failed", sizeof(g_statusMessage));
            lstrcpynA(g_spinnerDetail, "Something went wrong while injecting.", sizeof(g_spinnerDetail));
        }

        if (ok) {
            lstrcpynA(g_statusMessage, "Injection completed", sizeof(g_statusMessage));
            lstrcpynA(g_spinnerMessage, "Finished", sizeof(g_spinnerMessage));
            lstrcpynA(g_spinnerDetail, "Provider finished successfully.", sizeof(g_spinnerDetail));
            g_progressValue = 1.0f;
        }
        else {
            lstrcpynA(g_spinnerMessage, "Error", sizeof(g_spinnerMessage));
            g_progressValue = 1.0f;
        }

        g_spinnerSuccess = ok;
        g_spinnerFinished = true;
        g_spinnerFinishedAt = GetTickCount64();
        g_isProcessing = false;
        }).detach();
}

void ExecuteDLLInjection(const char* dllName) {
    AppControl::RefreshFeatureFlags();
    if (AppControl::ModulesDisabled()) {
        ShowAuthMessage(AppControl::KillReason().c_str());
        return;
    }
    g_isProcessing = true;
    g_showSpinner = true;
    g_spinnerFinished = false;
    g_spinnerSuccess = false;
    g_spinnerStartedAt = GetTickCount64();
    g_spinnerFinishedAt = 0;

    bool isDestruct = (strcmp(dllName, "dih.dll") == 0);
    bool isCleaning = (strcmp(dllName, "cleaning.dll") == 0);

    if (isCleaning) {
        lstrcpynA(g_spinnerMessage, "Cleaning", sizeof(g_spinnerMessage));
        lstrcpynA(g_spinnerDetail, "Preparing clean-up module...", sizeof(g_spinnerDetail));
        wsprintfA(g_statusMessage, "Injecting %s into self...", dllName);
    }
    else if (isDestruct) {
        lstrcpynA(g_spinnerMessage, "Destructing", sizeof(g_spinnerMessage));
        lstrcpynA(g_spinnerDetail, "Preparing self destruct module...", sizeof(g_spinnerDetail));
        wsprintfA(g_statusMessage, "Injecting %s into Notepad...", dllName);
    }
    else {
        lstrcpynA(g_spinnerMessage, "Injecting", sizeof(g_spinnerMessage));
        lstrcpynA(g_spinnerDetail, "Preparing module...", sizeof(g_spinnerDetail));
        wsprintfA(g_statusMessage, "Injecting %s into Notepad...", dllName);
    }

    g_progressValue = 0.2f;

    std::thread([dllName, isDestruct, isCleaning]() {
        bool ok = true;
        try {
            Sleep(300);
            lstrcpynA(g_spinnerDetail, "Loading module...", sizeof(g_spinnerDetail));
            g_progressValue = 0.55f;

            injection::LoadDLLFromSystem32(dllName, "Main");

            if (isDestruct) {
                lstrcpynA(g_spinnerDetail, "Waiting for cleanup to finish...", sizeof(g_spinnerDetail));
                for (int i = 0; i < 300; i++) {
                    DWORD notepadPid = injection::FindNotepadPID();
                    if (notepadPid == 0) {
                        break;
                    }
                    Sleep(1000);
                }
            }
        }
        catch (...) {
            ok = false;
            lstrcpynA(g_statusMessage, "Module failed", sizeof(g_statusMessage));
            lstrcpynA(g_spinnerDetail, "Something went wrong while loading the module.", sizeof(g_spinnerDetail));
        }

        if (ok) {
            wsprintfA(g_statusMessage, "%s completed!", dllName);
            lstrcpynA(g_spinnerMessage, "Finished", sizeof(g_spinnerMessage));
            lstrcpynA(g_spinnerDetail, "Operation completed successfully.", sizeof(g_spinnerDetail));
        }
        else {
            lstrcpynA(g_spinnerMessage, "Error", sizeof(g_spinnerMessage));
        }
        g_progressValue = 1.0f;
        g_spinnerSuccess = ok;
        g_spinnerFinished = true;
        g_spinnerFinishedAt = GetTickCount64();
        g_isProcessing = false;
        }).detach();
}

// ===== CUSTOM AUTH PLACEHOLDER =====
__declspec(noinline) void AttemptLogin() {
    AppControl::RefreshFeatureFlags();
    if (AppControl::AuthDisabled()) {
        ShowAuthMessage(AppControl::KillReason().c_str());
        return;
    }
    std::string key;
    bool keyEmpty = true;
    bool busy = false;
    try {
        key = std::string(g_licenseKey);
        keyEmpty = key.empty();
        busy = g_isProcessing;
    } catch (...) {}

    if (keyEmpty) {
        ShowAuthMessage("Please enter a license key");
        return;
    }

    if (busy) return;

    g_isProcessing = true;
    g_showSpinner = true;
    lstrcpynA(g_spinnerMessage, "Authenticating", sizeof(g_spinnerMessage));
    lstrcpynA(g_spinnerDetail, "Verifying your license with the server...", sizeof(g_spinnerDetail));

    std::thread([key]() {
        VMP_BEGIN_VIRTUALIZATION("Auth.ServerDecision");
        std::string escaped;
        escaped.reserve(key.size());
        for(char c:key){if(c=='"'||c=='\\')escaped.push_back('\\');if((unsigned char)c>=0x20)escaped.push_back(c);}
        std::string response;
        VmpProtectedStringA loginEndpoint("/api/auth/custom-login");
        VmpProtectedStringA licensePrefix("{\"licenseKey\":\"");
        VmpProtectedStringA successMarker("\"success\":true");
        std::string payload = std::string(licensePrefix.get()) + escaped + "\","
            + AppControl::CommonIdentityJsonFields()
            + ",\"machineUser\":\"" + EscapeJsonProgress(GetSystemUsername()) + "\"}";
        bool connected=NetClient::Post(loginEndpoint.get(),payload,response);
        bool accepted=connected&&response.find(successMarker.get())!=std::string::npos;
        if(accepted){
            VmpProtectedStringA usernameField("username");
            VmpProtectedStringA subscriptionField("subscription");
            VmpProtectedStringA expiryField("expiry");
            VmpProtectedStringA tokenField("token");
            VmpProtectedStringA sessionSignatureField("sessionSignature");
            std::string username=GetJsonValue(response,usernameField.get());
            std::string subscription=GetJsonValue(response,subscriptionField.get());
            std::string expiry=GetJsonValue(response,expiryField.get());
            std::string sessionToken=GetJsonValue(response,tokenField.get());
            std::string sessionSignature=GetJsonValue(response,sessionSignatureField.get());
            g_licenseUsername=username.empty()?"member":username;
            g_licenseSubscription=subscription.empty()?"Standard":subscription;
            g_licenseExpiry=expiry.empty()?"0":expiry;
            g_currentAuthToken=key;
            AppControl::SetSessionBinding(sessionToken,sessionSignature);
            InitializeProtection();
            AppControl::SendSessionHeartbeat();
            g_isLoggedIn=true;
            g_serverConnected.store(true);
            SaveLicenseKey(key);
            StartConnectionMonitor();
            lstrcpynA(g_spinnerDetail,"Server connected. Opening dashboard...",sizeof(g_spinnerDetail));
            ShowAuthMessage("Server connected");
        }else{
            g_serverConnected.store(false);
            VmpProtectedStringA messageField("message");
            std::string message=GetJsonValue(response,messageField.get());
            lstrcpynA(g_spinnerDetail,"Authentication failed.",sizeof(g_spinnerDetail));
            ShowAuthMessage(message.empty()?"Server connection or license failed":message.c_str());
        }
        g_showSpinner = false;
        g_isProcessing = false;
        VMP_END();
        }).detach();
}

// ===== UI HELPER FUNCTIONS =====
void ShowAuthMessage(const char* message, float duration) {
    lstrcpynA(g_authMessage, message, sizeof(g_authMessage));
    g_authMessageTime = duration;
    g_authMessageShow = true;
}

bool AnimatedButton(const char* label, const ImVec2& size, bool primary) {
    ImGuiWindow* window = ImGui::GetCurrentWindow();
    if (window->SkipItems) return false;

    ImVec2 pos = ImGui::GetCursorScreenPos();
    bool hovered = ImGui::IsMouseHoveringRect(pos, ImVec2(pos.x + size.x, pos.y + size.y));

    static float glowAnim = 0.0f;
    if (hovered) {
        glowAnim = ImMin(glowAnim + ImGui::GetIO().DeltaTime * 5.0f, 1.0f);
    }
    else {
        glowAnim = ImMax(glowAnim - ImGui::GetIO().DeltaTime * 3.5f, 0.0f);
    }

    if (glowAnim > 0.01f) {
        ImDrawList* draw_list = ImGui::GetWindowDrawList();
        float glowSize = 10.0f * glowAnim;
        ImVec4 glowColor = primary ? ImVec4(0.30f, 0.55f, 0.95f, 0.42f * glowAnim) : ImVec4(0.92f, 0.42f, 0.42f, 0.32f * glowAnim);

        for (int i = 0; i < 3; i++) {
            float offset = (i + 1) * (glowSize / 3.0f);
            float alpha = glowColor.w * (1.0f - (float)i / 3.0f);
            ImVec4 layerColor = ImVec4(glowColor.x, glowColor.y, glowColor.z, alpha);
            draw_list->AddRectFilled(
                ImVec2(pos.x - offset, pos.y - offset),
                ImVec2(pos.x + size.x + offset, pos.y + size.y + offset),
                ImGui::GetColorU32(layerColor),
                10.0f + offset
            );
        }
    }

    return ImGui::Button(label, size);
}

void DrawTermsOfServiceWindow(HWND hwnd, bool& done) {
    ImGuiIO& io = ImGui::GetIO();
    ImDrawList* drawList = ImGui::GetWindowDrawList();
    drawList->AddRectFilled(ImVec2(0, 0), io.DisplaySize, ImGui::GetColorU32(ImVec4(0.010f, 0.011f, 0.015f, 1.0f)));

    const float panelW = 620.0f;
    const float panelH = 374.0f;
    const ImVec2 panelPos((io.DisplaySize.x - panelW) * 0.5f, (io.DisplaySize.y - panelH) * 0.5f);
    const ImVec2 panelSize(panelW, panelH);

    DrawCardShadow(drawList, panelPos, panelSize, 8.0f);
    drawList->AddRectFilled(panelPos, panelPos + panelSize, ImGui::GetColorU32(ImVec4(0.038f, 0.041f, 0.052f, 1.0f)), 8.0f);
    drawList->AddRect(panelPos, panelPos + panelSize, ImGui::GetColorU32(ImVec4(0.145f, 0.158f, 0.192f, 1.0f)), 8.0f);
    drawList->AddLine(panelPos + ImVec2(26.0f, 72.0f), panelPos + ImVec2(panelW - 26.0f, 72.0f),
        ImGui::GetColorU32(ImVec4(0.135f, 0.148f, 0.180f, 1.0f)), 1.0f);

    ImGui::SetCursorScreenPos(panelPos);
    ImGui::BeginChild("TermsOfServiceGate", panelSize, false, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
    ImGui::InvisibleButton("##tos_drag", ImVec2(panelW, 34.0f));
    if (ImGui::IsItemActive()) {
        ReleaseCapture();
        SendMessage(hwnd, WM_NCLBUTTONDOWN, HTCAPTION, 0);
    }

    const char* eyebrow = "TERMS OF SERVICE";
    const float eyebrowW = ImGui::CalcTextSize(eyebrow).x;
    ImGui::SetCursorPos(ImVec2((panelW - eyebrowW) * 0.5f, 24.0f));
    ImGui::TextColored(g_accentColor, "%s", eyebrow);

    const char* title = "Review Before Continuing";
    ImGui::SetWindowFontScale(1.35f);
    const float titleW = ImGui::CalcTextSize(title).x;
    ImGui::SetCursorPos(ImVec2((panelW - titleW) * 0.5f, 46.0f));
    ImGui::TextColored(ImVec4(0.90f, 0.91f, 0.94f, 1.0f), "%s", title);
    ImGui::SetWindowFontScale(1.0f);

    const char* intro = "Accept the terms to unlock the login screen.";
    const float introW = ImGui::CalcTextSize(intro).x;
    ImGui::SetCursorPos(ImVec2((panelW - introW) * 0.5f, 84.0f));
    ImGui::TextColored(ImVec4(0.62f, 0.64f, 0.70f, 1.0f), "%s", intro);

    const ImVec2 termsPos(36.0f, 114.0f);
    const ImVec2 termsSize(panelW - 72.0f, 178.0f);
    const ImVec2 termsScreenPos = panelPos + termsPos;
    drawList->AddRectFilled(termsScreenPos, termsScreenPos + termsSize,
        ImGui::GetColorU32(ImVec4(0.026f, 0.028f, 0.036f, 1.0f)), 6.0f);
    drawList->AddRect(termsScreenPos, termsScreenPos + termsSize,
        ImGui::GetColorU32(ImVec4(0.105f, 0.116f, 0.145f, 1.0f)), 6.0f);

    ImGui::SetCursorPos(termsPos + ImVec2(18.0f, 14.0f));
    ImGui::PushTextWrapPos(termsPos.x + termsSize.x - 18.0f);

    const char* terms[] = {
        "Reverse engineering, decompilation, modification, or analysis of the software is prohibited.",
        "Unauthorized redistribution of the software is prohibited.",
        "Users are responsible for ensuring compliance with all applicable laws and regulations.",
        "The developers are not liable for any damages, data loss, account actions, or other consequences resulting from use of the software.",
        "The software is provided \"as is\" without warranties of any kind.",
        "Continued use of the software constitutes acceptance of all Terms of Service conditions."
    };

    for (const char* term : terms) {
        ImGui::TextColored(g_accentColor, "-");
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(0.72f, 0.74f, 0.80f, 1.0f), "%s", "");
        ImGui::SameLine();
        ImGui::TextWrapped("%s", term);
    }
    ImGui::PopTextWrapPos();

    const float buttonW = 172.0f;
    const float buttonH = 42.0f;
    const float buttonGap = 18.0f;
    const float buttonStartX = (panelW - buttonW * 2.0f - buttonGap) * 0.5f;
    ImGui::SetCursorPos(ImVec2(buttonStartX, panelH - 58.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 5.0f);
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.68f, 0.16f, 0.20f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.82f, 0.22f, 0.27f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.56f, 0.12f, 0.16f, 1.0f));
    if (AnimatedButton("DECLINE", ImVec2(buttonW, buttonH), false)) {
        done = true;
        PostQuitMessage(0);
    }
    ImGui::PopStyleColor(3);
    ImGui::SameLine(0.0f, buttonGap);
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.12f, 0.55f, 0.28f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.16f, 0.68f, 0.35f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.08f, 0.43f, 0.21f, 1.0f));
    if (AnimatedButton("ACCEPT", ImVec2(buttonW, buttonH), true)) {
        g_tosAccepted = true;
    }
    ImGui::PopStyleColor(3);
    ImGui::PopStyleVar();
    ImGui::EndChild();
}

void DrawSpinner(const char* label, float radius, float thickness, const ImVec4& color) {
    (void)label;
    (void)thickness;
    (void)color;
    ImGuiWindow* window = ImGui::GetCurrentWindow();
    if (window->SkipItems) return;

    ImGuiContext& g = *GImGui;
    const ImGuiStyle& style = g.Style;

    ImVec2 pos = window->DC.CursorPos;
    ImVec2 size(radius * 2.0f, (radius + style.FramePadding.y) * 2.0f);
    const ImRect bb(pos, ImVec2(pos.x + size.x, pos.y + size.y));
    ImGui::ItemSize(bb, style.FramePadding.y);

    ImDrawList* draw_list = window->DrawList;
    ImVec2 centre = ImVec2(pos.x + radius, pos.y + radius + style.FramePadding.y);

    // CSS-style double bounce: two overlapping discs, half a cycle apart.
    const float phase1 = fmodf(g_animTime, 2.0f) * 0.5f;
    const float phase2 = fmodf(phase1 + 0.5f, 1.0f);
    const float scale1 = 0.5f - 0.5f * cosf(phase1 * IM_PI * 2.0f);
    const float scale2 = 0.5f - 0.5f * cosf(phase2 * IM_PI * 2.0f);
    const ImU32 bounceColor = ImGui::GetColorU32(ImVec4(1.0f, 1.0f, 1.0f, 0.60f));

    if (scale1 > 0.001f)
        draw_list->AddCircleFilled(centre, radius * scale1, bounceColor, 64);
    if (scale2 > 0.001f)
        draw_list->AddCircleFilled(centre, radius * scale2, bounceColor, 64);
}

float PulseAnimation(float speed, float min, float max) {
    float t = sinf(g_animTime * speed) * 0.5f + 0.5f;
    return min + (max - min) * t;
}

std::string GetLicenseExpiryText() {
    if (g_licenseExpiry.empty() || g_licenseExpiry == "0") {
        return "Lifetime";
    }

    try {
        long long expiryTimestamp = std::stoll(g_licenseExpiry);
        auto now = std::chrono::system_clock::now();
        auto nowTimestamp = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
        long long diff = expiryTimestamp - nowTimestamp;

        if (diff <= 0) {
            return "Expired";
        }

        int days = (int)(diff / (60 * 60 * 24));
        if (days > 999) {
            return "Lifetime";
        }

        int hours = (int)((diff % (60 * 60 * 24)) / (60 * 60));
        int minutes = (int)((diff % (60 * 60)) / 60);

        char buffer[128];
        if (days > 0) {
            snprintf(buffer, sizeof(buffer), "%dd %dh %dm", days, hours, minutes);
        }
        else if (hours > 0) {
            snprintf(buffer, sizeof(buffer), "%dh %dm", hours, minutes);
        }
        else {
            snprintf(buffer, sizeof(buffer), "%dm", minutes);
        }

        return std::string(buffer);
    }
    catch (...) {
        return "Unknown";
    }
}

void DrawBackgroundParticles(ImDrawList* draw_list, ImVec2 size) {
    static const int particleCount = 30;
    for (int i = 0; i < particleCount; i++) {
        float offsetX = (i * 157) % 100 / 100.0f;
        float offsetY = (i * 251) % 100 / 100.0f;
        float speed = 0.08f + (i % 5) * 0.04f;

        float x = size.x * offsetX;
        float y = fmodf(offsetY * size.y + g_animTime * speed * 25.0f, size.y);

        float pulsePhase = (i % 10) * 0.628f;
        float alpha = (0.045f + 0.028f * sinf(g_animTime * 1.3f + pulsePhase));
        float particleSize = 1.2f + (i % 3) * 0.6f;

        ImVec4 particleColor = ImVec4(0.30f, 0.55f, 0.95f, alpha);
        draw_list->AddCircleFilled(ImVec2(x, y), particleSize, ImGui::GetColorU32(particleColor), 10);

        draw_list->AddCircle(ImVec2(x, y), particleSize + 2.5f,
            ImGui::GetColorU32(ImVec4(0.35f, 0.60f, 1.00f, alpha * 0.28f)), 10, 1.0f);
    }
}

void DrawAnimatedBorder(ImDrawList* draw_list, ImVec2 pos, ImVec2 size, float rounding, const ImVec4& color) {
    float glowIntensity = 0.5f + 0.5f * sinf(g_animTime * 3.0f);

    for (int i = 0; i < 3; i++) {
        float thickness = 1.5f + i * 0.5f;
        float alpha = color.w * glowIntensity * (1.0f - i * 0.3f);
        ImVec4 layerColor = ImVec4(color.x, color.y, color.z, alpha);

        draw_list->AddRect(
            ImVec2(pos.x - i, pos.y - i),
            ImVec2(pos.x + size.x + i, pos.y + size.y + i),
            ImGui::GetColorU32(layerColor),
            rounding + i,
            0,
            thickness
        );
    }
}

void DrawCardShadow(ImDrawList* draw_list, ImVec2 pos, ImVec2 size, float rounding) {
    for (int i = 5; i > 0; i--) {
        float offset = i * 3.5f;
        float alpha = 0.14f / (i * 0.75f);
        draw_list->AddRectFilled(
            ImVec2(pos.x - offset * 0.4f, pos.y + offset),
            ImVec2(pos.x + size.x + offset * 0.4f, pos.y + size.y + offset),
            ImGui::GetColorU32(ImVec4(0.0f, 0.01f, 0.04f, alpha)),
            rounding + 3.0f
        );
    }

    float glowAlpha = 0.10f + 0.05f * sinf(g_animTime * 1.6f);
    draw_list->AddRectFilled(
        ImVec2(pos.x + 25, pos.y - 1),
        ImVec2(pos.x + size.x - 25, pos.y + 2),
        ImGui::GetColorU32(ImVec4(0.30f, 0.55f, 0.95f, glowAlpha)),
        2.0f
    );
}

void DrawCornerAccents(ImDrawList* draw_list, ImVec2 pos, ImVec2 size, float cornerSize) {
    float accentPulse = 0.45f + 0.28f * sinf(g_animTime * 1.3f);
    ImU32 accentColor = ImGui::GetColorU32(ImVec4(0.30f, 0.55f, 0.95f, accentPulse));
    ImU32 glowColor = ImGui::GetColorU32(ImVec4(0.35f, 0.60f, 1.00f, accentPulse * 0.28f));

    float thickness = 2.0f;
    float length = cornerSize;
    float glowThickness = 4.5f;

    // Top-left corner
    draw_list->AddLine(ImVec2(pos.x, pos.y + length), ImVec2(pos.x, pos.y), glowColor, glowThickness);
    draw_list->AddLine(ImVec2(pos.x, pos.y), ImVec2(pos.x + length, pos.y), glowColor, glowThickness);
    draw_list->AddLine(ImVec2(pos.x, pos.y + length), ImVec2(pos.x, pos.y), accentColor, thickness);
    draw_list->AddLine(ImVec2(pos.x, pos.y), ImVec2(pos.x + length, pos.y), accentColor, thickness);

    // Top-right corner
    draw_list->AddLine(ImVec2(pos.x + size.x - length, pos.y), ImVec2(pos.x + size.x, pos.y), glowColor, glowThickness);
    draw_list->AddLine(ImVec2(pos.x + size.x, pos.y), ImVec2(pos.x + size.x, pos.y + length), glowColor, glowThickness);
    draw_list->AddLine(ImVec2(pos.x + size.x - length, pos.y), ImVec2(pos.x + size.x, pos.y), accentColor, thickness);
    draw_list->AddLine(ImVec2(pos.x + size.x, pos.y), ImVec2(pos.x + size.x, pos.y + length), accentColor, thickness);

    // Bottom-left corner
    draw_list->AddLine(ImVec2(pos.x, pos.y + size.y - length), ImVec2(pos.x, pos.y + size.y), glowColor, glowThickness);
    draw_list->AddLine(ImVec2(pos.x, pos.y + size.y), ImVec2(pos.x + length, pos.y + size.y), glowColor, glowThickness);
    draw_list->AddLine(ImVec2(pos.x, pos.y + size.y - length), ImVec2(pos.x, pos.y + size.y), accentColor, thickness);
    draw_list->AddLine(ImVec2(pos.x, pos.y + size.y), ImVec2(pos.x + length, pos.y + size.y), accentColor, thickness);

    // Bottom-right corner
    draw_list->AddLine(ImVec2(pos.x + size.x - length, pos.y + size.y), ImVec2(pos.x + size.x, pos.y + size.y), glowColor, glowThickness);
    draw_list->AddLine(ImVec2(pos.x + size.x, pos.y + size.y - length), ImVec2(pos.x + size.x, pos.y + size.y), glowColor, glowThickness);
    draw_list->AddLine(ImVec2(pos.x + size.x - length, pos.y + size.y), ImVec2(pos.x + size.x, pos.y + size.y), accentColor, thickness);
    draw_list->AddLine(ImVec2(pos.x + size.x, pos.y + size.y - length), ImVec2(pos.x + size.x, pos.y + size.y), accentColor, thickness);
}

void SetupImGuiStyle() {
    ImGuiStyle& style = ImGui::GetStyle();

    style.WindowRounding = 0.0f;
    style.ChildRounding = 3.0f;
    style.FrameRounding = 3.0f;
    style.PopupRounding = 4.0f;
    style.ScrollbarRounding = 3.0f;
    style.GrabRounding = 3.0f;
    style.TabRounding = 3.0f;

    style.WindowPadding = ImVec2(0, 0);
    style.FramePadding = ImVec2(10, 7);
    style.ItemSpacing = ImVec2(8, 5);
    style.ItemInnerSpacing = ImVec2(6, 4);
    style.FrameBorderSize = 0.0f;
    style.PopupBorderSize = 0.0f;
    style.WindowBorderSize = 0.0f;
    style.ChildBorderSize = 0.0f;

    ImVec4* colors = style.Colors;

    colors[ImGuiCol_WindowBg]        = ImVec4(0.043f, 0.047f, 0.063f, 1.0f);
    colors[ImGuiCol_ChildBg]         = ImVec4(0.0f, 0.0f, 0.0f, 0.0f);
    colors[ImGuiCol_PopupBg]         = ImVec4(0.055f, 0.059f, 0.078f, 0.98f);
    colors[ImGuiCol_Border]          = ImVec4(0.110f, 0.118f, 0.157f, 0.50f);
    colors[ImGuiCol_BorderShadow]    = ImVec4(0.0f, 0.0f, 0.0f, 0.0f);

    colors[ImGuiCol_Text]            = ImVec4(0.82f, 0.84f, 0.90f, 1.0f);
    colors[ImGuiCol_TextDisabled]    = ImVec4(0.35f, 0.37f, 0.44f, 1.0f);
    colors[ImGuiCol_TextSelectedBg]  = ImVec4(0.29f, 0.49f, 1.00f, 0.30f);

    colors[ImGuiCol_Button]          = ImVec4(0.071f, 0.075f, 0.098f, 1.0f);
    colors[ImGuiCol_ButtonHovered]   = ImVec4(0.098f, 0.106f, 0.137f, 1.0f);
    colors[ImGuiCol_ButtonActive]    = ImVec4(0.130f, 0.140f, 0.180f, 1.0f);

    colors[ImGuiCol_FrameBg]         = ImVec4(0.063f, 0.067f, 0.090f, 1.0f);
    colors[ImGuiCol_FrameBgHovered]  = ImVec4(0.082f, 0.090f, 0.118f, 1.0f);
    colors[ImGuiCol_FrameBgActive]   = ImVec4(0.110f, 0.118f, 0.157f, 1.0f);

    colors[ImGuiCol_Header]          = ImVec4(0.29f, 0.49f, 1.00f, 0.25f);
    colors[ImGuiCol_HeaderHovered]   = ImVec4(0.29f, 0.49f, 1.00f, 0.40f);
    colors[ImGuiCol_HeaderActive]    = ImVec4(0.29f, 0.49f, 1.00f, 0.55f);

    colors[ImGuiCol_CheckMark]       = ImVec4(0.29f, 0.49f, 1.00f, 1.0f);
    colors[ImGuiCol_SliderGrab]      = ImVec4(0.29f, 0.49f, 1.00f, 0.80f);
    colors[ImGuiCol_SliderGrabActive]= ImVec4(0.40f, 0.58f, 1.00f, 1.0f);

    colors[ImGuiCol_Separator]       = ImVec4(0.110f, 0.118f, 0.157f, 0.60f);
    colors[ImGuiCol_SeparatorHovered]= ImVec4(0.29f, 0.49f, 1.00f, 0.40f);
    colors[ImGuiCol_SeparatorActive] = ImVec4(0.29f, 0.49f, 1.00f, 0.70f);
}

// DirectX 11 helper functions
bool CreateDeviceD3D(HWND hWnd) {
    DXGI_SWAP_CHAIN_DESC sd;
    ZeroMemory(&sd, sizeof(sd));
    sd.BufferCount = 2;
    sd.BufferDesc.Width = 0;
    sd.BufferDesc.Height = 0;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hWnd;
    sd.SampleDesc.Count = 1;
    sd.SampleDesc.Quality = 0;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    UINT createDeviceFlags = 0;
    D3D_FEATURE_LEVEL featureLevel;
    const D3D_FEATURE_LEVEL featureLevelArray[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0 };
    HRESULT res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, createDeviceFlags,
        featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
    if (res != S_OK)
        return false;

    CreateRenderTarget();
    return true;
}

void CleanupDeviceD3D() {
    CleanupRenderTarget();
    if (g_pSwapChain) { g_pSwapChain->Release(); g_pSwapChain = nullptr; }
    if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = nullptr; }
    if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = nullptr; }
}

void CreateRenderTarget() {
    ID3D11Texture2D* pBackBuffer;
    g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    g_pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr, &g_mainRenderTargetView);
    pBackBuffer->Release();
}

void CleanupRenderTarget() {
    if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = nullptr; }
}

LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;

    switch (msg) {
    case WM_SIZE:
        if (g_pd3dDevice != nullptr && wParam != SIZE_MINIMIZED) {
            CleanupRenderTarget();
            g_pSwapChain->ResizeBuffers(0, (UINT)LOWORD(lParam), (UINT)HIWORD(lParam), DXGI_FORMAT_UNKNOWN, 0);
            CreateRenderTarget();
        }
        return 0;
    case WM_SYSCOMMAND:
        if ((wParam & 0xfff0) == SC_KEYMENU)
            return 0;
        break;
    case WM_HOTKEY:
        if (wParam == 1 || wParam == 2) {
            ::ShowWindow(hWnd, SW_RESTORE);
            ::ShowWindow(hWnd, SW_SHOW);
            ::SetForegroundWindow(hWnd);
            return 0;
        }
        break;
    case WM_KEYDOWN:
        if (wParam == VK_F12 || wParam == VK_F11) {
            ::ShowWindow(hWnd, SW_RESTORE);
            ::ShowWindow(hWnd, SW_SHOW);
            ::SetForegroundWindow(hWnd);
            return 0;
        }
        break;
    case WM_DESTROY:
        ::UnregisterHotKey(hWnd, 1);
        ::UnregisterHotKey(hWnd, 2);
        ::PostQuitMessage(0);
        return 0;
    }
    return ::DefWindowProcW(hWnd, msg, wParam, lParam);
}

// ===== WINDOWS ENTRY POINT =====
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // ===== DYNAMIC API LOADING =====
    // Initialize dynamic APIs to hide imports from static analysis
    if (!DynamicAPI::InitializeAPIs()) {
        MessageBoxA(NULL, "Failed to initialize system APIs", "Error", MB_ICONERROR);
        return 1;
    }

    // Filename, path, and EXE self-hash checks intentionally disabled.

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

    if (!isAdmin) {
        MessageBoxA(NULL,
            "This application requires Administrator privileges.\n\n"
            "Please right-click the file and select:\n"
            "\"Run as administrator\"",
            "Administrator Required",
            MB_OK | MB_ICONERROR);
        ExitProcess(1);
    }

    CoInitialize(nullptr);
    NetClient::Initialize();
    AppControl::Initialize();
    HandleEarlyProtectionDetection();
    InitializeProtection();

    // ===== USB DRIVE CHECK (async - don't block startup) =====
    std::thread([]() {
        while (true) {
            std::vector<USBDriveInfo> usbDrives = GetPluggedUSBDrives();
            if (usbDrives.empty()) break;
            std::string message = "Please unplug \"" + usbDrives[0].volumeName + "\" from your computer.";
            MessageBoxA(NULL, message.c_str(), "USB Alert", MB_OK | MB_ICONWARNING | MB_TOPMOST | MB_SETFOREGROUND);
            Sleep(500);
        }
    }).detach();

    // ===== GRAPHICS INITIALIZATION (DirectX 11 + Win32) =====
    WNDCLASSEXW wc = { sizeof(wc), CS_CLASSDC, WndProc, 0L, 0L, GetModuleHandle(nullptr), nullptr, nullptr, nullptr, nullptr, L"CRN_Window", nullptr };
    ::RegisterClassExW(&wc);

    // Create window without border (WS_POPUP)
    int windowWidth = 760;
    int windowHeight = 420;
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);
    int posX = (screenWidth - windowWidth) / 2;
    int posY = (screenHeight - windowHeight) / 2;

    HWND hwnd = ::CreateWindowW(wc.lpszClassName, L"CRN", WS_POPUP, posX, posY, windowWidth, windowHeight, nullptr, nullptr, wc.hInstance, nullptr);
    ::RegisterHotKey(hwnd, 1, 0, VK_F12);
    ::RegisterHotKey(hwnd, 2, 0, VK_F11);
    SetStreamproof(hwnd, TRUE);

    // Initialize DirectX
    if (!CreateDeviceD3D(hwnd)) {
        CleanupDeviceD3D();
        ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
        return 1;
    }

    ::ShowWindow(hwnd, SW_SHOWDEFAULT);
    ::UpdateWindow(hwnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.IniFilename = nullptr; // Disable imgui.ini file creation

    ImFontConfig fontConfig;
    fontConfig.OversampleH = 3;
    fontConfig.OversampleV = 3;
    fontConfig.PixelSnapH = false;
    fontConfig.RasterizerMultiply = 1.08f;

    ImFont* font = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\segoeuib.ttf", 15.5f, &fontConfig);
    if (!font) {
        font = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\arialbd.ttf", 15.5f, &fontConfig);
    }
    if (!font) {
        io.Fonts->AddFontDefault(&fontConfig);
    }

    SetupImGuiStyle();
    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    static bool g_autoLoginAttempted = false;

    // Get local IP on background thread (avoid blocking startup)
    DebugLog("Getting local IP (async)");
    std::thread([]() {
        g_localIP = NetClient::GetLocalIPAddress();
    }).detach();
    DebugLog("Entering main loop");

    // ===== MAIN LOOP =====
    bool done = false;
    static bool g_protectionInitialized = false;
    while (!done) {
        MSG msg;
        while (::PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
            ::TranslateMessage(&msg);
            ::DispatchMessage(&msg);
            if (msg.message == WM_QUIT)
                done = true;
        }
        if (done)
            break;

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();
        g_animTime += io.DeltaTime;

        // ===== FAST STARTUP SETUP (once, on first frame) =====
        if (!g_protectionInitialized) {
            g_protectionInitialized = true;
            g_updateComplete = true;
            g_showLoadingScreen = false;
            DebugLog("Startup UI checks complete; runtime protection is active");
        }

        if (g_tosAccepted && g_updateComplete && !g_autoLoginAttempted && !g_isLoggedIn) {
            g_autoLoginAttempted = true;
            std::string savedKey;
            if (LoadLicenseKey(savedKey)) {
                strncpy_s(g_licenseKey, savedKey.c_str(), sizeof(g_licenseKey) - 1);
                g_licenseKey[sizeof(g_licenseKey) - 1] = '\0';
                AttemptLogin();
            }
        }

        if (g_authMessageShow) {
            g_authMessageTime -= io.DeltaTime;
            if (g_authMessageTime <= 0.0f) {
                g_authMessageShow = false;
            }
        }

        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(io.DisplaySize);
        ImGui::Begin("Main", nullptr, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
            ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoBackground |
            ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

        if (!g_tosAccepted) {
            DrawTermsOfServiceWindow(hwnd, done);
        }
        else if (!g_isLoggedIn) {
            // ===== LOGIN SCREEN =====
            float loginCardW = 500.0f;
            float loginCardH = 300.0f;

            if (g_showLoadingScreen) {
                ImDrawList* fullBgDraw = ImGui::GetWindowDrawList();
                fullBgDraw->AddRectFilled(ImVec2(0, 0), io.DisplaySize, ImGui::GetColorU32(ImVec4(0.04f, 0.05f, 0.07f, 1.0f)));
                DrawBackgroundParticles(fullBgDraw, io.DisplaySize);

                float spinnerRadius = 32.0f;
                float contentHeight = spinnerRadius * 2 + 80.0f;
                float centerY = (io.DisplaySize.y - contentHeight) / 2;

                ImGui::SetCursorScreenPos(ImVec2((io.DisplaySize.x - spinnerRadius * 2) / 2, centerY));
                DrawSpinner("##loadspinner", spinnerRadius, 5.0f, ImVec4(0.20f, 0.40f, 0.80f, 1.0f));

                float msgPulse = PulseAnimation(2.0f, 0.85f, 1.0f);
                int dots = ((int)(g_animTime * 2.0f)) % 4;
                std::string loadText = "Initializing CRN Framework" + std::string(dots, '.');

                ImGui::SetWindowFontScale(1.3f);
                float textW = ImGui::CalcTextSize(loadText.c_str()).x;
                float textY = centerY + spinnerRadius * 2 + 35;
                ImGui::SetCursorScreenPos(ImVec2((io.DisplaySize.x - textW) / 2, textY));
                ImGui::TextColored(ImVec4(0.85f, 0.90f, 0.95f, msgPulse), "%s", loadText.c_str());

                ImGui::SetWindowFontScale(0.95f);
                const char* subText = "Securing connection...";
                float subW = ImGui::CalcTextSize(subText).x;
                ImGui::SetCursorScreenPos(ImVec2((io.DisplaySize.x - subW) / 2, textY + 32));
                ImGui::TextColored(ImVec4(0.45f, 0.50f, 0.60f, msgPulse * 0.8f), "%s", subText);
                ImGui::SetWindowFontScale(1.0f);
            }
            else {
                // Login uses the same shell and visual language as the dashboard.
                const float shellW=740.0f,shellH=400.0f,leftW=220.0f,railW=54.0f;
                ImGui::SetCursorPos(ImVec2(10,10));
                ImVec2 shellPos=ImGui::GetCursorScreenPos();
                ImDrawList* loginDraw=ImGui::GetWindowDrawList();
                loginDraw->AddRectFilled(shellPos,shellPos+ImVec2(shellW,shellH),ImGui::GetColorU32(ImVec4(0.012f,0.012f,0.016f,1.0f)));
                loginDraw->AddRect(shellPos,shellPos+ImVec2(shellW,shellH),ImGui::GetColorU32(ImVec4(0.075f,0.075f,0.085f,1.0f)));
                ImGui::BeginChild("LoginShell",ImVec2(shellW,shellH),false,ImGuiWindowFlags_NoScrollbar|ImGuiWindowFlags_NoScrollWithMouse);
                ImGui::InvisibleButton("##login_drag",ImVec2(shellW-48.0f,28.0f));
                if(ImGui::IsItemActive()){ReleaseCapture();SendMessage(hwnd,WM_NCLBUTTONDOWN,HTCAPTION,0);}

                // Left identity panel.
                ImVec2 leftPos=shellPos;
                loginDraw->AddRectFilled(leftPos,leftPos+ImVec2(leftW,shellH),ImGui::GetColorU32(ImVec4(0.045f,0.045f,0.052f,1.0f)));
                loginDraw->AddLine(leftPos+ImVec2(leftW,0),leftPos+ImVec2(leftW,shellH),ImGui::GetColorU32(ImVec4(0.070f,0.070f,0.082f,1.0f)));
                ImVec2 logo=leftPos+ImVec2(30,42);
                loginDraw->AddNgon(logo+ImVec2(12,12),13.0f,ImGui::GetColorU32(ImVec4(0.88f,0.89f,0.92f,1.0f)),6,3.0f);
                loginDraw->AddText(leftPos+ImVec2(68,40),ImGui::GetColorU32(ImVec4(0.82f,0.83f,0.87f,1.0f)),"CRN");
                loginDraw->AddText(leftPos+ImVec2(68,58),ImGui::GetColorU32(ImVec4(0.39f,0.40f,0.45f,1.0f)),"FiveM Bypass");
                loginDraw->AddText(leftPos+ImVec2(30,126),ImGui::GetColorU32(ImVec4(0.34f,0.35f,0.40f,1.0f)),"SERVER");
                ImVec2 status=leftPos+ImVec2(30,150);
                loginDraw->AddRectFilled(status,status+ImVec2(160,60),ImGui::GetColorU32(ImVec4(0.070f,0.072f,0.084f,1.0f)),5.0f);
                bool online=IsServerConnected();
                ImU32 stateColor=ImGui::GetColorU32(online?ImVec4(0.34f,0.78f,0.50f,1.0f):ImVec4(0.45f,0.47f,0.53f,1.0f));
                loginDraw->AddCircleFilled(status+ImVec2(17,22),4.0f,stateColor,12);
                loginDraw->AddText(status+ImVec2(30,12),ImGui::GetColorU32(ImVec4(0.78f,0.79f,0.84f,1.0f)),online?"Connected":"Awaiting login");
                std::string endpoint=NetClient::GetServerHost()+":"+std::to_string(NetClient::GetServerPort());
                loginDraw->AddText(status+ImVec2(16,37),ImGui::GetColorU32(ImVec4(0.42f,0.43f,0.48f,1.0f)),endpoint.c_str());
                loginDraw->AddText(leftPos+ImVec2(30,300),ImGui::GetColorU32(ImVec4(0.34f,0.35f,0.40f,1.0f)),"SECURE SESSION");
                loginDraw->AddText(leftPos+ImVec2(30,326),ImGui::GetColorU32(ImVec4(0.60f,0.61f,0.66f,1.0f)),"Encrypted transport");
                loginDraw->AddText(leftPos+ImVec2(30,348),ImGui::GetColorU32(ImVec4(0.42f,0.43f,0.48f,1.0f)),"License verified remotely");

                // Narrow rail from the dashboard shell.
                loginDraw->AddRectFilled(shellPos+ImVec2(leftW,0),shellPos+ImVec2(leftW+railW,shellH),ImGui::GetColorU32(ImVec4(0.014f,0.014f,0.018f,1.0f)));
                for(int i=0;i<3;++i){ImVec2 c=shellPos+ImVec2(leftW+railW*0.5f,166.0f+i*34.0f);ImU32 col=ImGui::GetColorU32(i==0?g_accentColor:ImVec4(0.28f,0.29f,0.34f,1.0f));loginDraw->AddCircle(c,6.0f,col,16,1.7f);if(i==0)loginDraw->AddCircleFilled(c,2.0f,col,10);}

                // Close control.
                ImVec2 closePos=shellPos+ImVec2(shellW-38,16);ImGui::SetCursorScreenPos(closePos);ImGui::InvisibleButton("##login_close",ImVec2(22,22));
                bool closeHover=ImGui::IsItemHovered();if(ImGui::IsItemClicked())done=true;
                ImU32 closeColor=ImGui::GetColorU32(closeHover?ImVec4(0.90f,0.34f,0.40f,1.0f):ImVec4(0.42f,0.43f,0.48f,1.0f));
                loginDraw->AddLine(closePos+ImVec2(5,5),closePos+ImVec2(17,17),closeColor,1.7f);loginDraw->AddLine(closePos+ImVec2(17,5),closePos+ImVec2(5,17),closeColor,1.7f);

                const float contentX=leftW+railW+40.0f;
                ImGui::SetCursorPos(ImVec2(contentX,58));
                ImGui::TextColored(g_accentColor,"LICENSE PORTAL");
                ImGui::SetWindowFontScale(1.55f);ImGui::SetCursorPos(ImVec2(contentX,88));ImGui::TextColored(ImVec4(0.88f,0.89f,0.92f,1.0f),"Welcome back");ImGui::SetWindowFontScale(1.0f);
                ImGui::SetCursorPos(ImVec2(contentX,126));ImGui::TextColored(ImVec4(0.43f,0.44f,0.49f,1.0f),"Connect your license to continue to the dashboard.");
                ImGui::SetCursorPos(ImVec2(contentX,174));ImGui::TextColored(ImVec4(0.55f,0.56f,0.61f,1.0f),"LICENSE KEY");
                ImGui::SetCursorPos(ImVec2(contentX,198));ImGui::PushItemWidth(shellW-contentX-40.0f);
                ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding,4.0f);ImGui::PushStyleVar(ImGuiStyleVar_FramePadding,ImVec2(13,11));
                ImGui::PushStyleColor(ImGuiCol_FrameBg,ImVec4(0.035f,0.036f,0.043f,1.0f));ImGui::PushStyleColor(ImGuiCol_FrameBgHovered,ImVec4(0.055f,0.057f,0.068f,1.0f));ImGui::PushStyleColor(ImGuiCol_FrameBgActive,ImVec4(0.060f,0.064f,0.078f,1.0f));
                bool enterPressed=ImGui::InputTextWithHint("##license_new","Enter your license key",g_licenseKey,sizeof(g_licenseKey),ImGuiInputTextFlags_Password|ImGuiInputTextFlags_EnterReturnsTrue);
                ImGui::PopStyleColor(3);ImGui::PopStyleVar(2);ImGui::PopItemWidth();
                ImGui::SetCursorPos(ImVec2(contentX,258));
                ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding,4.0f);
                if(AnimatedButton(g_isProcessing?"CONNECTING...":"CONNECT TO SERVER",ImVec2(shellW-contentX-40.0f,40.0f),true)||enterPressed)AttemptLogin();
                ImGui::PopStyleVar();
                ImGui::SetCursorPos(ImVec2(contentX,316));
                if(g_authMessageShow){bool good=strstr(g_authMessage,"connected")!=nullptr;ImGui::TextColored(good?ImVec4(0.34f,0.78f,0.50f,1.0f):ImVec4(0.86f,0.35f,0.40f,1.0f),"%s",g_authMessage);}else{ImGui::TextColored(ImVec4(0.38f,0.39f,0.44f,1.0f),"Your key is verified by the local server.");}
                ImGui::EndChild();

            }
        }
        else {
            // ===== MAIN SCREEN =====
            float cardW = 740.0f;
            float cardH = 400.0f;
            ImGui::SetCursorPos(ImVec2(10, 10));

            ImVec2 mainCardPos = ImGui::GetCursorScreenPos();
            ImDrawList* mainCardDrawList = ImGui::GetWindowDrawList();
            mainCardDrawList->AddRectFilled(mainCardPos, ImVec2(mainCardPos.x + cardW, mainCardPos.y + cardH),
                ImGui::GetColorU32(ImVec4(0.012f, 0.012f, 0.016f, 1.0f)), 0.0f);

            ImGui::BeginChild("Card", ImVec2(cardW, cardH), false, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

            ImDrawList* mainDrawList = ImGui::GetWindowDrawList();
            ImGui::InvisibleButton("##dragarea", ImVec2(cardW, 28));
            if (ImGui::IsItemActive()) {
                ReleaseCapture();
                SendMessage(hwnd, WM_NCLBUTTONDOWN, HTCAPTION, 0);
            }

            float leftW = 220.0f;
            float railW = 54.0f;
            float contentX = leftW + railW + 18.0f;
            float contentW = cardW - contentX - 16.0f;
            ImU32 textMain = ImGui::GetColorU32(ImVec4(0.78f, 0.79f, 0.84f, 1.0f));
            ImU32 textMuted = ImGui::GetColorU32(ImVec4(0.42f, 0.43f, 0.48f, 1.0f));
            ImU32 panelColor = ImGui::GetColorU32(ImVec4(0.044f, 0.044f, 0.052f, 1.0f));
            ImU32 panelHover = ImGui::GetColorU32(ImVec4(0.066f, 0.068f, 0.080f, 1.0f));
            ImVec4 accentHover = ImVec4(
                min(g_accentColor.x + 0.06f, 1.0f),
                min(g_accentColor.y + 0.06f, 1.0f),
                min(g_accentColor.z + 0.06f, 1.0f),
                1.0f);
            ImVec4 accentActive = ImVec4(
                max(g_accentColor.x - 0.05f, 0.0f),
                max(g_accentColor.y - 0.05f, 0.0f),
                max(g_accentColor.z - 0.05f, 0.0f),
                1.0f);
            ImU32 blueColor = ImGui::GetColorU32(g_accentColor);
            ImU32 blueHoverColor = ImGui::GetColorU32(accentHover);
            ImU32 blueActiveColor = ImGui::GetColorU32(accentActive);

            auto drawTile = [&](const char* id, const char* label, ImVec2 size, bool selected, bool enabled) -> bool {
                ImVec2 p = ImGui::GetCursorScreenPos();
                ImGui::InvisibleButton(id, size);
                bool hovered = enabled && ImGui::IsItemHovered();
                bool clicked = enabled && ImGui::IsItemClicked();
                ImDrawList* draw = ImGui::GetWindowDrawList();
                ImU32 bg = selected ? ImGui::GetColorU32(ImVec4(g_accentColor.x * 0.22f, g_accentColor.y * 0.26f, g_accentColor.z * 0.32f, 1.0f)) : (hovered ? panelHover : panelColor);
                draw->AddRectFilled(p, ImVec2(p.x + size.x, p.y + size.y), bg, 4.0f);
                if (selected) {
                    draw->AddRectFilled(p, ImVec2(p.x + 3.0f, p.y + size.y), blueColor, 4.0f);
                }
                draw->AddText(ImVec2(p.x + 12.0f, p.y + 12.0f), enabled ? textMain : textMuted, label);
                const char* mark = selected ? "v" : ">";
                ImVec2 markSize = ImGui::CalcTextSize(mark);
                draw->AddText(ImVec2(p.x + size.x - markSize.x - 14.0f, p.y + 12.0f),
                    selected ? blueColor : ImGui::GetColorU32(ImVec4(0.35f, 0.36f, 0.40f, 1.0f)), mark);
                return clicked;
            };

            auto drawTopButton = [&](const char* id, const char* label, ImVec2 size, bool active) -> bool {
                ImVec2 p = ImGui::GetCursorScreenPos();
                ImGui::InvisibleButton(id, size);
                ImDrawList* draw = ImGui::GetWindowDrawList();
                bool hovered = ImGui::IsItemHovered();
                bool clicked = ImGui::IsItemClicked();
                ImU32 bg = active ? panelColor : ImGui::GetColorU32(ImVec4(0.018f, 0.018f, 0.023f, 1.0f));
                if (hovered) bg = panelHover;
                draw->AddRectFilled(p, ImVec2(p.x + size.x, p.y + size.y), bg, 4.0f);
                draw->AddRect(p, ImVec2(p.x + size.x, p.y + size.y), ImGui::GetColorU32(ImVec4(0.075f, 0.075f, 0.085f, 1.0f)), 4.0f);
                ImVec2 iconCenter = ImVec2(p.x + 30.0f, p.y + size.y * 0.5f);
                ImU32 iconColor = active ? blueColor : textMuted;
                if (strcmp(label, "Bypass options") == 0) {
                    draw->AddCircle(iconCenter, 5.5f, iconColor, 14, 2.0f);
                    draw->AddCircleFilled(iconCenter, 2.0f, iconColor, 10);
                } else {
                    for (int k = 0; k < 8; ++k) {
                        float a = (float)k / 8.0f * IM_PI * 2.0f;
                        ImVec2 p1 = iconCenter + ImVec2(cosf(a) * 6.0f, sinf(a) * 6.0f);
                        ImVec2 p2 = iconCenter + ImVec2(cosf(a) * 4.2f, sinf(a) * 4.2f);
                        draw->AddLine(p1, p2, iconColor, 1.5f);
                    }
                    draw->AddCircle(iconCenter, 3.2f, iconColor, 12, 1.5f);
                }
                draw->AddText(ImVec2(p.x + 44.0f, p.y + 10.0f), active ? textMain : textMuted, label);
                return clicked;
            };

            ImGui::SetCursorPos(ImVec2(0, 0));
            ImGui::BeginChild("LeftPane", ImVec2(leftW, cardH), false, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
            ImDrawList* leftDraw = ImGui::GetWindowDrawList();
            ImVec2 leftPos = ImGui::GetCursorScreenPos();
            leftDraw->AddRectFilled(leftPos, ImVec2(leftPos.x + leftW, leftPos.y + cardH),
                ImGui::GetColorU32(ImVec4(0.045f, 0.045f, 0.052f, 1.0f)));
            leftDraw->AddLine(ImVec2(leftPos.x + leftW, leftPos.y), ImVec2(leftPos.x + leftW, leftPos.y + cardH),
                ImGui::GetColorU32(ImVec4(0.070f, 0.070f, 0.082f, 1.0f)));

            ImVec2 logo = ImVec2(leftPos.x + 18, leftPos.y + 28);
            leftDraw->AddNgon(logo + ImVec2(12, 12), 13.0f, ImGui::GetColorU32(ImVec4(0.88f, 0.89f, 0.92f, 1.0f)), 6, 3.0f);
            ImGui::SetCursorPos(ImVec2(56, 27));
            ImGui::TextColored(ImVec4(0.82f, 0.83f, 0.87f, 1.0f), "CRN");
            ImGui::SetCursorPos(ImVec2(56, 43));
            ImGui::TextColored(ImVec4(0.39f, 0.40f, 0.45f, 1.0f), "FiveM Bypass");

            ImVec2 statusPos = leftPos + ImVec2(18, 118);
            leftDraw->AddText(statusPos, ImGui::GetColorU32(ImVec4(0.34f, 0.35f, 0.40f, 1.0f)), "Session");
            leftDraw->AddRectFilled(statusPos + ImVec2(0, 24), statusPos + ImVec2(leftW - 36, 82),
                ImGui::GetColorU32(ImVec4(0.075f, 0.077f, 0.090f, 1.0f)), 5.0f);
            leftDraw->AddCircleFilled(statusPos + ImVec2(18, 53), 4.0f, ImGui::GetColorU32(ImVec4(0.34f, 0.78f, 0.50f, 1.0f)), 12);
            bool serverOnline=IsServerConnected();
            leftDraw->AddText(statusPos + ImVec2(32, 42), serverOnline?textMain:textMuted, serverOnline?"Connected":"Disconnected");
            std::string serverLabel=NetClient::GetServerHost()+":"+std::to_string(NetClient::GetServerPort());
            leftDraw->AddText(statusPos + ImVec2(32, 61), serverOnline?blueColor:textMuted, serverLabel.c_str());

            ImVec2 hintPos = leftPos + ImVec2(18, 230);
            leftDraw->AddText(hintPos, ImGui::GetColorU32(ImVec4(0.34f, 0.35f, 0.40f, 1.0f)), "Panel");
            leftDraw->AddRectFilled(hintPos + ImVec2(0, 24), hintPos + ImVec2(leftW - 36, 104),
                ImGui::GetColorU32(ImVec4(0.060f, 0.062f, 0.074f, 1.0f)), 5.0f);
            leftDraw->AddText(hintPos + ImVec2(14, 40), textMain, "Clean layout");
            leftDraw->AddText(hintPos + ImVec2(14, 62), textMuted, "Fast boot enabled");
            leftDraw->AddText(hintPos + ImVec2(14, 82), textMuted, "Custom auth slot");
            ImGui::EndChild();

            ImGui::SetCursorPos(ImVec2(leftW, 0));
            ImGui::BeginChild("IconRail", ImVec2(railW, cardH), false, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
            ImDrawList* railDraw = ImGui::GetWindowDrawList();
            ImVec2 railPos = ImGui::GetCursorScreenPos();
            railDraw->AddRectFilled(railPos, ImVec2(railPos.x + railW, railPos.y + cardH),
                ImGui::GetColorU32(ImVec4(0.014f, 0.014f, 0.018f, 1.0f)));
            for (int i = 0; i < 3; ++i) {
                ImVec2 center = railPos + ImVec2(railW * 0.5f, 188.0f + i * 27.0f);
                ImU32 icon = ImGui::GetColorU32(ImVec4(0.45f, 0.47f, 0.55f, 1.0f));
                if (i == 0) {
                    railDraw->AddCircle(center + ImVec2(-4, 0), 3.0f, icon, 12, 1.8f);
                    railDraw->AddCircle(center + ImVec2(4, 0), 3.0f, icon, 12, 1.8f);
                    railDraw->AddLine(center + ImVec2(-1, 0), center + ImVec2(1, 0), icon, 1.8f);
                    railDraw->AddLine(center + ImVec2(-8, -2), center + ImVec2(-10, -4), icon, 1.8f);
                    railDraw->AddLine(center + ImVec2(8, -2), center + ImVec2(10, -4), icon, 1.8f);
                } else if (i == 1) {
                    railDraw->AddCircle(center, 7.5f, icon, 24, 2.0f);
                    railDraw->AddLine(center + ImVec2(-6, 0), center + ImVec2(6, 0), icon, 1.5f);
                    railDraw->AddLine(center + ImVec2(0, -6), center + ImVec2(0, 6), icon, 1.5f);
                    railDraw->AddBezierCubic(center + ImVec2(-3, -7), center + ImVec2(-6, -2), center + ImVec2(-6, 2), center + ImVec2(-3, 7), icon, 1.2f);
                    railDraw->AddBezierCubic(center + ImVec2(3, -7), center + ImVec2(6, -2), center + ImVec2(6, 2), center + ImVec2(3, 7), icon, 1.2f);
                } else {
                    ImVec2 pts[3] = { center + ImVec2(-8, 6), center + ImVec2(9, -7), center + ImVec2(2, 9) };
                    railDraw->AddTriangleFilled(pts[0], pts[1], pts[2], icon);
                    railDraw->AddLine(center + ImVec2(1, 2), center + ImVec2(9, -7), ImGui::GetColorU32(ImVec4(0.20f, 0.21f, 0.25f, 1.0f)), 1.5f);
                }
            }
            ImGui::EndChild();

            ImGui::SetCursorPos(ImVec2(contentX, 24));
            ImGui::BeginChild("DashboardArea", ImVec2(contentW, cardH - 34), false, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
            ImGui::SetWindowFontScale(1.22f);
            ImGui::TextColored(ImVec4(0.78f, 0.79f, 0.84f, 1.0f), "Welcome back, %s!", g_licenseUsername.c_str());
            ImGui::SetWindowFontScale(1.0f);
            ImGui::TextColored(g_accentColor, "License expires: %s", GetLicenseExpiryText().c_str());

            ImGui::Dummy(ImVec2(0, 6));
            if (drawTopButton("##bypass_tab", "Bypass options", ImVec2((contentW - 8.0f) * 0.5f, 36.0f), true)) {
                g_showBypassPopup = true;
            }
            ImGui::SameLine(0, 8);
            if (drawTopButton("##settings_tab", "Settings", ImVec2((contentW - 8.0f) * 0.5f, 36.0f), false)) {
                g_showSettingsPopup = true;
            }

            ImGui::Dummy(ImVec2(0, 6));
            ImGui::TextColored(ImVec4(0.33f, 0.34f, 0.39f, 1.0f), "Subscription:");
            ImGui::SameLine();
            ImGui::TextColored(g_accentColor, "%s", g_licenseSubscription.c_str());
            ImGui::SameLine();
            ImGui::SetCursorPosX(contentW - 150.0f);
            ImGui::TextColored(ImVec4(0.49f, 0.50f, 0.55f, 1.0f), "Pick an option below");

            if (g_lastFeatureRefresh == 0 || GetTickCount64() - g_lastFeatureRefresh >= 3000ULL) {
                RefreshServerFeaturesAsync();
            }

            const char* providers[] = { "TZ", "TZX", "CRN External", "Keyser", "Ghost", "Macho", "South" };
            float gap = 8.0f;
            float optionW = (contentW - gap) * 0.5f;
            float optionH = 38.0f;
            int visibleIndex = 0;
            for (int i = 0; i < 7; ++i) {
                if (InterlockedCompareExchange(&g_providerVisible[i], 0, 0) == 0) {
                    if (g_selectedProvider == i) g_selectedProvider = -1;
                    continue;
                }
                if (visibleIndex % 2 == 1) ImGui::SameLine(0, gap);
                bool selected = g_selectedProvider == i;
                bool supported = true;
                std::string id = "##provider" + std::to_string(i);
                if (drawTile(id.c_str(), providers[i], ImVec2(optionW, optionH), selected, supported)) {
                    g_selectedProvider = i;
                }
                ++visibleIndex;
            }
            if (visibleIndex == 0) ImGui::TextColored(ImVec4(0.42f, 0.43f, 0.48f, 1.0f), "No features are currently enabled.");

            ImGui::Dummy(ImVec2(0, 8));
            bool canExecute = !g_isProcessing && g_selectedProvider >= 0 && g_selectedProvider < 6;
            ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 4.0f);
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.035f, 0.045f, 0.060f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_Button, canExecute ? g_accentColor : ImVec4(0.18f, 0.22f, 0.28f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, canExecute ? accentHover : ImVec4(0.18f, 0.22f, 0.28f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive, canExecute ? accentActive : ImVec4(0.18f, 0.22f, 0.28f, 1.0f));
            if (ImGui::Button("Inject", ImVec2(contentW, 38.0f)) && canExecute) {
                ExecuteProviderInjection(g_selectedProvider);
            }
            ImGui::PopStyleColor(4);
            ImGui::PopStyleVar();

            if (g_isProcessing || g_progressValue > 0.0f) {
                ImGui::Dummy(ImVec2(0, 4));
                ImGui::TextColored(ImVec4(0.30f, 0.50f, 0.74f, 1.0f), "%s", g_statusMessage);
            }
            ImGui::EndChild();
            ImGui::EndChild();

            // ===== PHONE POPUP - EXACTLY LIKE CLEANING/DESTRUCT =====
            if (g_showPhonePopup && !ImGui::IsPopupOpen("Phone")) {
                ImGui::OpenPopup("Phone");
            }

            float phoneCardW = 400.0f;  // Smaller like cleaning/destruct
            float phoneCardH = 180.0f;  // Smaller like cleaning/destruct
            ImGui::SetNextWindowSize(ImVec2(phoneCardW, phoneCardH), ImGuiCond_Always);
            ImGui::SetNextWindowPos(ImVec2(io.DisplaySize.x * 0.5f, io.DisplaySize.y * 0.5f), ImGuiCond_Always, ImVec2(0.5f, 0.5f));

            if (ImGui::BeginPopupModal("Phone", &g_showPhonePopup, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoBackground)) {
                ImGui::SetCursorPos(ImVec2(0, 0));
                ImDrawList* phoneDrawList = ImGui::GetWindowDrawList();
                ImVec2 phoneCardPos = ImGui::GetCursorScreenPos();

                // Card background (exactly like cleaning/destruct)
                phoneDrawList->AddRectFilled(phoneCardPos, ImVec2(phoneCardPos.x + phoneCardW, phoneCardPos.y + phoneCardH),
                    ImGui::GetColorU32(ImVec4(0.06f, 0.06f, 0.09f, 1.0f)), 12.0f);

                // Animated border (exactly like cleaning/destruct)
                DrawAnimatedBorder(phoneDrawList, phoneCardPos, ImVec2(phoneCardW, phoneCardH), 12.0f, ImVec4(0.30f, 0.55f, 0.95f, 0.4f));

                // Corner accents
                DrawCornerAccents(phoneDrawList, phoneCardPos, ImVec2(phoneCardW, phoneCardH), 20.0f);

                // Header - "PHONE ACCESS" (exactly like "CLEANING!" or "DESTRUCTING!")
                ImGui::SetCursorPos(ImVec2(phoneCardW / 2 - 70, 15));
                ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.35f, 0.60f, 1.00f, 1.0f));
                ImGui::SetWindowFontScale(1.6f);
                ImGui::Text("PHONE ACCESS");
                ImGui::SetWindowFontScale(1.0f);
                ImGui::PopStyleColor();

                // Close button (top-right) - SAME AS BYPASS POPUP
                ImGui::SetCursorPos(ImVec2(phoneCardW - 40, 10));
                ImVec2 closeBtnPos = ImGui::GetCursorScreenPos();
                bool closeHovered = ImGui::IsMouseHoveringRect(closeBtnPos, ImVec2(closeBtnPos.x + 28, closeBtnPos.y + 28));

                if (closeHovered) {
                    phoneDrawList->AddRectFilled(
                        closeBtnPos,
                        ImVec2(closeBtnPos.x + 28, closeBtnPos.y + 28),
                        ImGui::GetColorU32(ImVec4(0.85f, 0.30f, 0.35f, 1.0f)),
                        8.0f
                    );
                }

                const char* closeLabel = "X";
                float closeLabelWidth = ImGui::CalcTextSize(closeLabel).x;
                float closeLabelX = closeBtnPos.x + (28 - closeLabelWidth) / 2;
                float closeLabelY = closeBtnPos.y + (28 - ImGui::GetFontSize()) / 2;

                phoneDrawList->AddText(
                    ImVec2(closeLabelX, closeLabelY),
                    ImGui::GetColorU32(ImVec4(0.60f, 0.62f, 0.66f, 1.0f)),
                    closeLabel
                );

                if (closeHovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
                    g_showPhonePopup = false;
                    ImGui::CloseCurrentPopup();
                }

                // LOADING ANIMATION - EXACTLY LIKE CLEANING/DESTRUCT/INJECTING
                float centerX = phoneCardW / 2.0f;
                float centerY = phoneCardH / 2.0f + 10;

                // Spinner (same radius and thickness as cleaning/destruct)
                ImGui::SetCursorPos(ImVec2(centerX - 28, centerY - 40));
                DrawSpinner("##phonespinner", 28.0f, 4.5f, ImVec4(0.35f, 0.60f, 1.00f, 1.0f));

                // Animated message with dots (EXACT FORMAT AS CLEANING/DESTRUCT)
                float msgPulse = PulseAnimation(2.0f, 0.85f, 1.0f);
                int dots = ((int)(g_animTime * 2.0f)) % 4;
                std::string animatedMessage = g_phoneMessage + std::string(dots, '.');

                // Centered text with glow (same as cleaning/destruct)
                ImGui::SetCursorPos(ImVec2(centerX - ImGui::CalcTextSize(animatedMessage.c_str()).x / 2, centerY + 15));
                ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.94f, 0.95f, 0.97f, msgPulse));
                ImGui::SetWindowFontScale(1.3f);

                // Add glow behind text (same as cleaning/destruct)
                ImVec2 textPos = ImGui::GetCursorScreenPos();
                phoneDrawList->AddText(ImVec2(textPos.x + 1, textPos.y + 1),
                    ImGui::GetColorU32(ImVec4(0.30f, 0.55f, 0.95f, 0.5f * msgPulse)),
                    animatedMessage.c_str());

                ImGui::Text("%s", animatedMessage.c_str());
                ImGui::SetWindowFontScale(1.0f);
                ImGui::PopStyleColor();

                // Progress bar (thin, same as cleaning/destruct)
                ImGui::SetCursorPos(ImVec2(50, centerY + 50));
                ImVec2 progressBarPos = ImGui::GetCursorScreenPos();
                ImVec2 progressBarSize = ImVec2(phoneCardW - 100, 4);  // Thin like cleaning/destruct

                // Background
                phoneDrawList->AddRectFilled(
                    progressBarPos,
                    ImVec2(progressBarPos.x + progressBarSize.x, progressBarPos.y + progressBarSize.y),
                    ImGui::GetColorU32(ImVec4(0.10f, 0.11f, 0.14f, 1.0f)),
                    2.0f
                );

                // Progress fill
                float progressWidth = progressBarSize.x * g_phoneProgress;
                if (progressWidth > 0) {
                    phoneDrawList->AddRectFilled(
                        progressBarPos,
                        ImVec2(progressBarPos.x + progressWidth, progressBarPos.y + progressBarSize.y),
                        ImGui::GetColorU32(ImVec4(0.25f, 0.48f, 0.88f, 1.0f)),
                        2.0f
                    );
                }

                ImGui::Dummy(progressBarSize);

                // "Please wait" text (same as cleaning/destruct)
                const char* subText = "Please wait";
                float subW = ImGui::CalcTextSize(subText).x;
                ImGui::SetCursorPos(ImVec2((phoneCardW - subW) / 2, centerY + 65));
                ImGui::TextColored(ImVec4(0.50f, 0.52f, 0.58f, msgPulse * 0.7f), "%s", subText);

                // Close on Escape
                if (ImGui::IsKeyPressed(ImGuiKey_Escape)) {
                    g_showPhonePopup = false;
                    ImGui::CloseCurrentPopup();
                }

                ImGui::EndPopup();
            }

            // ===== BYPASS POPUP =====
            if (g_showBypassPopup && !ImGui::IsPopupOpen("Bypass")) {
                ImGui::OpenPopup("Bypass");
            }

            float bypassCardW = 500.0f;
            float bypassCardH = 245.0f;
            ImGui::SetNextWindowSize(ImVec2(bypassCardW, bypassCardH), ImGuiCond_Always);
            ImGui::SetNextWindowPos(ImVec2(io.DisplaySize.x * 0.5f, io.DisplaySize.y * 0.5f), ImGuiCond_Always, ImVec2(0.5f, 0.5f));

            if (ImGui::BeginPopupModal("Bypass", &g_showBypassPopup, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoBackground)) {
                ImDrawList* bypassCardDrawList = ImGui::GetWindowDrawList();
                ImVec2 bypassCardPos = ImGui::GetCursorScreenPos();
                bypassCardDrawList->AddRectFilled(bypassCardPos, ImVec2(bypassCardPos.x + bypassCardW, bypassCardPos.y + bypassCardH),
                    ImGui::GetColorU32(ImVec4(0.050f, 0.054f, 0.071f, 0.99f)), 6.0f);
                bypassCardDrawList->AddRect(bypassCardPos, ImVec2(bypassCardPos.x + bypassCardW, bypassCardPos.y + bypassCardH),
                    ImGui::GetColorU32(ImVec4(0.12f, 0.18f, 0.25f, 1.0f)), 6.0f);

                ImGui::SetCursorPos(ImVec2(bypassCardW - 36, 22));
                if (ImGui::InvisibleButton("##bypass_close", ImVec2(22, 22))) {
                    g_showBypassPopup = false;
                    ImGui::CloseCurrentPopup();
                }
                bypassCardDrawList->AddLine(bypassCardPos + ImVec2(bypassCardW - 30, 28), bypassCardPos + ImVec2(bypassCardW - 16, 42), textMuted, 1.8f);
                bypassCardDrawList->AddLine(bypassCardPos + ImVec2(bypassCardW - 16, 28), bypassCardPos + ImVec2(bypassCardW - 30, 42), textMuted, 1.8f);

                bypassCardDrawList->AddCircle(bypassCardPos + ImVec2(30, 31), 6.0f, blueColor, 14, 2.0f);
                bypassCardDrawList->AddText(ImGui::GetFont(), 17.0f, bypassCardPos + ImVec2(50, 21), textMain, "Bypass settings");
                bypassCardDrawList->AddText(ImGui::GetFont(), 14.0f, bypassCardPos + ImVec2(24, 58), textMuted, "Quick Actions");

                auto drawActionIcon = [&](ImDrawList* draw, ImVec2 c, const char* kind, ImU32 col) {
                    if (strcmp(kind, "browser") == 0) {
                        draw->AddCircle(c, 5.5f, col, 18, 1.7f);
                        draw->AddLine(c + ImVec2(-4.5f, 0), c + ImVec2(4.5f, 0), col, 1.2f);
                        draw->AddBezierCubic(c + ImVec2(-2.0f, -5.0f), c + ImVec2(-5.0f, -1.0f), c + ImVec2(-5.0f, 1.0f), c + ImVec2(-2.0f, 5.0f), col, 1.1f);
                        draw->AddBezierCubic(c + ImVec2(2.0f, -5.0f), c + ImVec2(5.0f, -1.0f), c + ImVec2(5.0f, 1.0f), c + ImVec2(2.0f, 5.0f), col, 1.1f);
                    } else if (strcmp(kind, "shield") == 0) {
                        ImVec2 pts[5] = { c + ImVec2(0, -7), c + ImVec2(6, -4), c + ImVec2(5, 3), c + ImVec2(0, 8), c + ImVec2(-5, 3) };
                        draw->AddPolyline(pts, 5, col, ImDrawFlags_Closed, 1.7f);
                        draw->AddLine(c + ImVec2(-2, 0), c + ImVec2(0, 3), col, 1.3f);
                        draw->AddLine(c + ImVec2(0, 3), c + ImVec2(4, -3), col, 1.3f);
                    } else if (strcmp(kind, "scan") == 0) {
                        draw->AddCircle(c + ImVec2(-1, -1), 5.0f, col, 18, 1.7f);
                        draw->AddLine(c + ImVec2(3, 3), c + ImVec2(8, 8), col, 1.7f);
                    } else if (strcmp(kind, "strings") == 0) {
                        draw->AddRect(c + ImVec2(-6, -6), c + ImVec2(6, 6), col, 2.0f, 0, 1.5f);
                        draw->AddLine(c + ImVec2(-3, -2), c + ImVec2(3, -2), col, 1.2f);
                        draw->AddLine(c + ImVec2(-3, 2), c + ImVec2(2, 2), col, 1.2f);
                    } else if (strcmp(kind, "clean") == 0) {
                        draw->PathArcTo(c, 5.5f, -2.5f, 1.7f, 18);
                        draw->PathStroke(col, 0, 1.8f);
                        ImVec2 pts[3] = { c + ImVec2(3, -6), c + ImVec2(8, -5), c + ImVec2(5, -1) };
                        draw->AddTriangleFilled(pts[0], pts[1], pts[2], col);
                    } else {
                        draw->AddCircle(c, 5.5f, col, 18, 1.7f);
                        draw->AddLine(c + ImVec2(-3, -3), c + ImVec2(3, 3), col, 1.5f);
                        draw->AddLine(c + ImVec2(3, -3), c + ImVec2(-3, 3), col, 1.5f);
                    }
                };

                auto quickButton = [&](int col, int row, const char* id, const char* label, const char* icon, bool accent) {
                    ImVec2 p = bypassCardPos + ImVec2(24.0f + col * 230.0f, 86.0f + row * 44.0f);
                    ImVec2 s = ImVec2(218.0f, 34.0f);
                    ImGui::SetCursorScreenPos(p);
                    ImGui::InvisibleButton(id, s);
                    bool hovered = ImGui::IsItemHovered();
                    bool clicked = ImGui::IsItemClicked();
                    ImU32 bg = accent ? blueColor :
                        (hovered ? ImGui::GetColorU32(ImVec4(0.090f, 0.120f, 0.165f, 1.0f)) : ImGui::GetColorU32(ImVec4(0.080f, 0.090f, 0.120f, 1.0f)));
                    ImU32 fg = accent ? ImGui::GetColorU32(ImVec4(0.08f, 0.07f, 0.10f, 1.0f)) : textMain;
                    bypassCardDrawList->AddRectFilled(p, ImVec2(p.x + s.x, p.y + s.y), bg, 4.0f);
                    ImVec2 textSize = ImGui::CalcTextSize(label);
                    float textX = p.x + (s.x - textSize.x) * 0.5f + 11.0f;
                    drawActionIcon(bypassCardDrawList, ImVec2(textX - 15.0f, p.y + 17.0f), icon, fg);
                    bypassCardDrawList->AddText(ImGui::GetFont(), 15.0f, ImVec2(textX, p.y + 9.0f), fg, label);
                    if (clicked) {
                        lstrcpynA(g_statusMessage, label, sizeof(g_statusMessage));
                    }
                };
                quickButton(0, 0, "##clean_browser", "Clean browser", "browser", false);
                quickButton(1, 0, "##clean_def", "Clean def history", "shield", false);
                quickButton(0, 1, "##manual_check", "Manual check", "scan", false);
                quickButton(1, 1, "##check_strings", "Check Strings", "strings", false);
                quickButton(0, 2, "##full_clean", "Full clean", "clean", true);
                quickButton(1, 2, "##self_destruct", "Self Destruct", "destruct", true);

                if (ImGui::IsKeyPressed(ImGuiKey_Escape)) {
                    g_showBypassPopup = false;
                    ImGui::CloseCurrentPopup();
                }

                ImGui::EndPopup();
            }

            if (g_showSettingsPopup && !ImGui::IsPopupOpen("Settings")) {
                ImGui::OpenPopup("Settings");
            }

            float settingsCardW = 500.0f;
            float settingsCardH = 394.0f;
            ImGui::SetNextWindowSize(ImVec2(settingsCardW, settingsCardH), ImGuiCond_Always);
            ImGui::SetNextWindowPos(ImVec2(io.DisplaySize.x * 0.5f, io.DisplaySize.y * 0.5f), ImGuiCond_Always, ImVec2(0.5f, 0.5f));

            if (ImGui::BeginPopupModal("Settings", &g_showSettingsPopup, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoBackground)) {
                ImDrawList* settingsDraw = ImGui::GetWindowDrawList();
                ImVec2 settingsPos = ImGui::GetCursorScreenPos();
                settingsDraw->AddRectFilled(settingsPos, ImVec2(settingsPos.x + settingsCardW, settingsPos.y + settingsCardH),
                    ImGui::GetColorU32(ImVec4(0.050f, 0.054f, 0.071f, 0.99f)), 6.0f);
                settingsDraw->AddRect(settingsPos, ImVec2(settingsPos.x + settingsCardW, settingsPos.y + settingsCardH),
                    ImGui::GetColorU32(ImVec4(0.12f, 0.18f, 0.25f, 1.0f)), 6.0f);

                ImGui::SetCursorPos(ImVec2(settingsCardW - 36, 22));
                if (ImGui::InvisibleButton("##settings_close", ImVec2(22, 22))) {
                    g_showSettingsPopup = false;
                    ImGui::CloseCurrentPopup();
                }
                settingsDraw->AddLine(settingsPos + ImVec2(settingsCardW - 30, 28), settingsPos + ImVec2(settingsCardW - 16, 42), textMuted, 1.8f);
                settingsDraw->AddLine(settingsPos + ImVec2(settingsCardW - 16, 28), settingsPos + ImVec2(settingsCardW - 30, 42), textMuted, 1.8f);

                settingsDraw->AddCircle(settingsPos + ImVec2(30, 31), 6.0f, blueColor, 14, 2.0f);
                settingsDraw->AddText(ImGui::GetFont(), 17.0f, settingsPos + ImVec2(50, 21), textMain, "Settings");
                settingsDraw->AddText(ImGui::GetFont(), 14.0f, settingsPos + ImVec2(24, 58), textMuted, "Menu Options");

                ImVec2 row = settingsPos + ImVec2(24, 86);
                ImVec2 rowSize = ImVec2(settingsCardW - 48, 42);
                settingsDraw->AddRectFilled(row, row + rowSize, ImGui::GetColorU32(ImVec4(0.080f, 0.090f, 0.120f, 1.0f)), 4.0f);
                settingsDraw->AddText(ImGui::GetFont(), 15.0f, row + ImVec2(16, 8), textMain, "Streamproof");
                settingsDraw->AddText(ImGui::GetFont(), 13.5f, row + ImVec2(16, 25), textMuted, g_streamproofEnabled ? "Hidden from recordings" : "Visible in recordings");

                ImVec2 togglePos = row + ImVec2(rowSize.x - 62, 10);
                ImVec2 toggleSize = ImVec2(46, 22);
                ImGui::SetCursorScreenPos(togglePos);
                if (ImGui::InvisibleButton("##streamproof_toggle", toggleSize)) {
                    g_streamproofEnabled = !g_streamproofEnabled;
                    SetStreamproof(hwnd, g_streamproofEnabled ? TRUE : FALSE);
                }
                settingsDraw->AddRectFilled(togglePos, togglePos + toggleSize,
                    g_streamproofEnabled ? blueColor : ImGui::GetColorU32(ImVec4(0.13f, 0.14f, 0.17f, 1.0f)), 11.0f);
                float knobX = g_streamproofEnabled ? togglePos.x + 26.0f : togglePos.x + 4.0f;
                settingsDraw->AddCircleFilled(ImVec2(knobX + 7.0f, togglePos.y + 11.0f), 7.5f, textMain, 16);

                settingsDraw->AddText(ImGui::GetFont(), 14.0f, settingsPos + ImVec2(24, 140), textMuted, "Accent color");
                ImVec2 pickerPanel = settingsPos + ImVec2(24, 160);
                ImVec2 pickerSize = ImVec2(settingsCardW - 48, 210);
                settingsDraw->AddRectFilled(pickerPanel, pickerPanel + pickerSize, ImGui::GetColorU32(ImVec4(0.080f, 0.090f, 0.120f, 1.0f)), 5.0f);

                ImVec2 wheelCenter = pickerPanel + ImVec2(105, 105);
                float wheelRadius = 82.0f;
                float wheelThickness = 15.0f;
                for (int i = 0; i < 128; ++i) {
                    float a0 = (float)i / 128.0f * IM_PI * 2.0f;
                    float a1 = (float)(i + 1) / 128.0f * IM_PI * 2.0f;
                    ImU32 hue = ImColor::HSV((float)i / 128.0f, 1.0f, 1.0f);
                    settingsDraw->PathLineTo(wheelCenter + ImVec2(cosf(a0) * wheelRadius, sinf(a0) * wheelRadius));
                    settingsDraw->PathLineTo(wheelCenter + ImVec2(cosf(a1) * wheelRadius, sinf(a1) * wheelRadius));
                    settingsDraw->PathStroke(hue, 0, wheelThickness);
                }
                settingsDraw->AddCircle(wheelCenter, wheelRadius + wheelThickness * 0.5f, ImGui::GetColorU32(ImVec4(0.18f, 0.22f, 0.31f, 1.0f)), 96, 1.0f);
                settingsDraw->AddCircle(wheelCenter, wheelRadius - wheelThickness * 0.5f, ImGui::GetColorU32(ImVec4(0.18f, 0.22f, 0.31f, 1.0f)), 96, 1.0f);

                ImVec2 huePoint = wheelCenter + ImVec2(0.0f, -53.0f);
                ImVec2 whitePoint = wheelCenter + ImVec2(-48.0f, 38.0f);
                ImVec2 blackPoint = wheelCenter + ImVec2(48.0f, 38.0f);
                ImVec4 pureHue = ImColor::HSV(g_pickerHue, 1.0f, 1.0f);
                auto trianglePoint = [&](float whiteWeight, float blackWeight) {
                    float hueWeight = 1.0f - whiteWeight - blackWeight;
                    return ImVec2(huePoint.x * hueWeight + whitePoint.x * whiteWeight + blackPoint.x * blackWeight,
                        huePoint.y * hueWeight + whitePoint.y * whiteWeight + blackPoint.y * blackWeight);
                };
                auto triangleColor = [&](float whiteWeight, float blackWeight) {
                    float hueWeight = 1.0f - whiteWeight - blackWeight;
                    return ImGui::GetColorU32(ImVec4(pureHue.x * hueWeight + whiteWeight,
                        pureHue.y * hueWeight + whiteWeight, pureHue.z * hueWeight + whiteWeight, 1.0f));
                };
                const int triangleSteps = 20;
                for (int w = 0; w < triangleSteps; ++w) {
                    for (int b = 0; b < triangleSteps - w; ++b) {
                        float w0 = (float)w / triangleSteps, b0 = (float)b / triangleSteps;
                        float w1 = (float)(w + 1) / triangleSteps, b1 = (float)(b + 1) / triangleSteps;
                        ImVec2 p0 = trianglePoint(w0, b0);
                        ImVec2 p1 = trianglePoint(w1, b0);
                        ImVec2 p2 = trianglePoint(w0, b1);
                        settingsDraw->AddTriangleFilled(p0, p1, p2, triangleColor(w0 + 1.0f / (3.0f * triangleSteps), b0 + 1.0f / (3.0f * triangleSteps)));
                        if (w + b < triangleSteps - 1) {
                            ImVec2 p3 = trianglePoint(w1, b1);
                            settingsDraw->AddTriangleFilled(p1, p3, p2, triangleColor(w1 - 1.0f / (3.0f * triangleSteps), b1 - 1.0f / (3.0f * triangleSteps)));
                        }
                    }
                }
                settingsDraw->AddTriangle(huePoint, whitePoint, blackPoint, ImGui::GetColorU32(ImVec4(0.82f, 0.85f, 0.92f, 0.9f)), 1.2f);

                float hueAngle = g_pickerHue * IM_PI * 2.0f;
                ImVec2 hueMarker = wheelCenter + ImVec2(cosf(hueAngle) * wheelRadius, sinf(hueAngle) * wheelRadius);
                settingsDraw->AddCircleFilled(hueMarker, 6.5f, textMain, 20);
                settingsDraw->AddCircleFilled(hueMarker, 3.5f, ImGui::GetColorU32(pureHue), 20);
                ImVec2 triangleMarker = trianglePoint(g_pickerWhite, g_pickerBlack);
                settingsDraw->AddCircle(triangleMarker, 6.0f, textMain, 20, 2.0f);
                settingsDraw->AddCircle(triangleMarker, 7.5f, ImGui::GetColorU32(ImVec4(0.03f, 0.04f, 0.06f, 0.8f)), 20, 1.0f);

                ImVec2 removePos = pickerPanel + ImVec2(246, 82);
                ImGui::SetCursorScreenPos(removePos);
                ImGui::InvisibleButton("##remove_credential", ImVec2(170, 42));
                bool removeHovered = ImGui::IsItemHovered();
                settingsDraw->AddRectFilled(removePos, removePos + ImVec2(170, 42),
                    ImGui::GetColorU32(removeHovered ? ImVec4(0.10f, 0.11f, 0.14f, 1.0f) : ImVec4(0.025f, 0.028f, 0.036f, 1.0f)), 6.0f);
                settingsDraw->AddRect(removePos, removePos + ImVec2(170, 42),
                    ImGui::GetColorU32(ImVec4(0.88f, 0.90f, 0.94f, 1.0f)), 6.0f, 0, 1.0f);
                ImVec2 removeTextSize = ImGui::CalcTextSize("Remove credential");
                settingsDraw->AddText(ImGui::GetFont(), 14.0f,
                    removePos + ImVec2((170.0f - removeTextSize.x) * 0.5f, 13.0f), textMain, "Remove credential");
                if (ImGui::IsItemClicked()) {
                    NetClient::PostAsync("/api/auth/logout", "{}");
                    DeleteSavedLicense();
                    SecureZeroMemory(g_licenseKey, sizeof(g_licenseKey));
                    if (!g_currentAuthToken.empty()) SecureZeroMemory(&g_currentAuthToken[0], g_currentAuthToken.size());
                    g_currentAuthToken.clear();
                    g_connectionMonitorStarted.store(false);
                    g_serverConnected.store(false);
                    g_isLoggedIn = false;
                    g_autoLoginAttempted = true;
                    g_showSettingsPopup = false;
                    ImGui::CloseCurrentPopup();
                    ShowAuthMessage("Saved credential removed");
                }

                ImGui::SetCursorScreenPos(wheelCenter - ImVec2(wheelRadius + 12.0f, wheelRadius + 12.0f));
                ImGui::InvisibleButton("##accent_picker", ImVec2((wheelRadius + 12.0f) * 2.0f, (wheelRadius + 12.0f) * 2.0f));
                if (ImGui::IsItemActive() || ImGui::IsItemClicked()) {
                    ImVec2 mouse = ImGui::GetIO().MousePos;
                    ImVec2 delta = mouse - wheelCenter;
                    float dist = sqrtf(delta.x * delta.x + delta.y * delta.y);
                    if (dist <= wheelRadius + wheelThickness && dist >= wheelRadius - wheelThickness) {
                        float angle = atan2f(delta.y, delta.x);
                        if (angle < 0.0f) angle += IM_PI * 2.0f;
                        g_pickerHue = angle / (IM_PI * 2.0f);
                    } else {
                        float denominator = (whitePoint.y - blackPoint.y) * (huePoint.x - blackPoint.x) + (blackPoint.x - whitePoint.x) * (huePoint.y - blackPoint.y);
                        float hueWeight = ((whitePoint.y - blackPoint.y) * (mouse.x - blackPoint.x) + (blackPoint.x - whitePoint.x) * (mouse.y - blackPoint.y)) / denominator;
                        float whiteWeight = ((blackPoint.y - huePoint.y) * (mouse.x - blackPoint.x) + (huePoint.x - blackPoint.x) * (mouse.y - blackPoint.y)) / denominator;
                        float blackWeight = 1.0f - hueWeight - whiteWeight;
                        if (hueWeight >= 0.0f && whiteWeight >= 0.0f && blackWeight >= 0.0f) {
                            g_pickerWhite = whiteWeight;
                            g_pickerBlack = blackWeight;
                        }
                    }
                    pureHue = ImColor::HSV(g_pickerHue, 1.0f, 1.0f);
                    float activeHueWeight = 1.0f - g_pickerWhite - g_pickerBlack;
                    g_accentColor = ImVec4(pureHue.x * activeHueWeight + g_pickerWhite,
                        pureHue.y * activeHueWeight + g_pickerWhite, pureHue.z * activeHueWeight + g_pickerWhite, 1.0f);
                    if (dist <= wheelRadius + wheelThickness || (g_pickerWhite >= 0.0f && g_pickerBlack >= 0.0f)) {
                        lstrcpynA(g_statusMessage, "Accent updated", sizeof(g_statusMessage));
                    }
                }

                if (ImGui::IsKeyPressed(ImGuiKey_Escape)) {
                    g_showSettingsPopup = false;
                    ImGui::CloseCurrentPopup();
                }

                ImGui::EndPopup();
            }

        } // end else (main screen)

        // Spinner overlay
        if (g_showSpinner) {
            if (g_spinnerFinished && g_spinnerFinishedAt > 0) {
                ULONGLONG doneFor = GetTickCount64() - g_spinnerFinishedAt;
                ULONGLONG holdTime = g_spinnerSuccess ? 1500ULL : 2400ULL;
                if (doneFor > holdTime) {
                    g_showSpinner = false;
                    g_progressValue = 0.0f;
                    if (g_spinnerSuccess) {
                        lstrcpynA(g_statusMessage, "Ready", sizeof(g_statusMessage));
                    }
                }
            }

            ImGui::SetNextWindowPos(ImVec2(0, 0));
            ImGui::SetNextWindowSize(io.DisplaySize);
            ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(0.025f, 0.026f, 0.030f, 1.0f));
            ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
            ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
            ImGui::Begin("##SpinnerOverlay", nullptr, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
                ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoInputs);

            ImDrawList* overlayDraw = ImGui::GetWindowDrawList();
            const float spinnerRadius = 28.0f;
            const ImVec2 spinnerPos = ImVec2(
                (io.DisplaySize.x - spinnerRadius * 2.0f) * 0.5f,
                io.DisplaySize.y * 0.5f - spinnerRadius - 20.0f);
            ImGui::SetCursorScreenPos(spinnerPos);
            DrawSpinner("##spinner", spinnerRadius, 0.0f, ImVec4(1, 1, 1, 1));

            const char* loadingText = g_spinnerMessage[0] ? g_spinnerMessage : "Working";
            const ImVec2 textSize = ImGui::CalcTextSize(loadingText);
            overlayDraw->AddText(
                ImGui::GetFont(), 17.0f,
                ImVec2((io.DisplaySize.x - textSize.x) * 0.5f, spinnerPos.y + spinnerRadius * 2.0f + 22.0f),
                ImGui::GetColorU32(ImVec4(0.94f, 0.95f, 0.97f, 1.0f)), loadingText);

            if(g_spinnerDetail[0]){
                const ImVec2 detailSize=ImGui::CalcTextSize(g_spinnerDetail);
                overlayDraw->AddText(ImGui::GetFont(),13.0f,
                    ImVec2((io.DisplaySize.x-detailSize.x)*0.5f,spinnerPos.y+spinnerRadius*2.0f+50.0f),
                    ImGui::GetColorU32(ImVec4(0.45f,0.47f,0.53f,1.0f)),g_spinnerDetail);
            }

            ImGui::End();
            ImGui::PopStyleVar(2);
            ImGui::PopStyleColor();
        }

        ImGui::End();

        // Rendering
        ImGui::Render();
        const float clear_color[4] = { 0.04f, 0.04f, 0.07f, 1.0f };
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear_color);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        g_pSwapChain->Present(1, 0); // VSync
    }

    // Tell server we're closing normally (prevents false "connection lost" alert)
    StopServerHeartbeat();
    g_connectionMonitorStarted.store(false);
    NetClient::Shutdown();
    SendGracefulDisconnect();
    CoUninitialize();

    // Cleanup
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    CleanupDeviceD3D();
    ::DestroyWindow(hwnd);
    ::UnregisterClassW(wc.lpszClassName, wc.hInstance);

    return 0;
}
