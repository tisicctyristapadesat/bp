#include "app_control.h"

#include "net_client.h"
#include "protection.h"
#include "security.h"
#include "vmprotect_markers.h"

#include <windows.h>
#include <atomic>
#include <cstring>
#include <mutex>
#include <sstream>
#include <thread>

#ifndef APP_VERSION
#define APP_VERSION "2.1.4"
#endif

#ifndef APP_BUILD_ID
#if defined(_WIN64)
#define APP_BUILD_ID "nfggggg-release-x64-2026-06-23"
#else
#define APP_BUILD_ID "nfggggg-release-win32-2026-06-23"
#endif
#endif

namespace {
std::mutex g_controlMutex;
AppControl::FeatureFlags g_flags;
std::string g_sessionToken;
std::string g_sessionSignature;
std::atomic<bool> g_initialized(false);

struct CanaryString {
    const char* id;
    volatile char* value;
    const char* expected;
};

volatile char g_canarySessionRefresh[] = "/api/auth/session/refresh";
volatile char g_canaryStableChannel[] = "updateChannel=stable";
volatile char g_canaryLicenseStatus[] = "licenseStatus=active";
volatile char g_canaryCacheManifest[] = "cdn/cache_manifest.json";
volatile char g_canaryGraceWindow[] = "auth.refresh_grace_seconds=45";
volatile char g_canaryIntegrityMode[] = "client.integrity.mode=balanced";
volatile char g_canarySubscriptionTier[] = "subscriptionTier=standard";
volatile char g_canaryLicenseVerify[] = "/api/auth/license/verify";
volatile char g_canaryPremiumToken[] = "premiumToken=eyJhbGciOiJIUzI1NiJ9.decoy";
volatile char g_canaryOfflineMode[] = "offlineModeAllowed=false";
volatile char g_canaryAdminOverride[] = "adminOverrideKey=disabled";
volatile char g_canaryDebugBypass[] = "debugBypass=0";

const char g_expectedSessionRefresh[] = "/api/auth/session/refresh";
const char g_expectedStableChannel[] = "updateChannel=stable";
const char g_expectedLicenseStatus[] = "licenseStatus=active";
const char g_expectedCacheManifest[] = "cdn/cache_manifest.json";
const char g_expectedGraceWindow[] = "auth.refresh_grace_seconds=45";
const char g_expectedIntegrityMode[] = "client.integrity.mode=balanced";
const char g_expectedSubscriptionTier[] = "subscriptionTier=standard";
const char g_expectedLicenseVerify[] = "/api/auth/license/verify";
const char g_expectedPremiumToken[] = "premiumToken=eyJhbGciOiJIUzI1NiJ9.decoy";
const char g_expectedOfflineMode[] = "offlineModeAllowed=false";
const char g_expectedAdminOverride[] = "adminOverrideKey=disabled";
const char g_expectedDebugBypass[] = "debugBypass=0";

CanaryString g_canaries[] = {
    { "AUTH_SESSION_REFRESH", g_canarySessionRefresh, g_expectedSessionRefresh },
    { "UPDATE_CHANNEL", g_canaryStableChannel, g_expectedStableChannel },
    { "LICENSE_STATUS", g_canaryLicenseStatus, g_expectedLicenseStatus },
    { "CACHE_MANIFEST", g_canaryCacheManifest, g_expectedCacheManifest },
    { "AUTH_GRACE_WINDOW", g_canaryGraceWindow, g_expectedGraceWindow },
    { "INTEGRITY_MODE", g_canaryIntegrityMode, g_expectedIntegrityMode },
    { "SUBSCRIPTION_TIER", g_canarySubscriptionTier, g_expectedSubscriptionTier },
    { "LICENSE_VERIFY_ENDPOINT", g_canaryLicenseVerify, g_expectedLicenseVerify },
    { "PREMIUM_TOKEN_DECOY", g_canaryPremiumToken, g_expectedPremiumToken },
    { "OFFLINE_MODE_DECOY", g_canaryOfflineMode, g_expectedOfflineMode },
    { "ADMIN_OVERRIDE_DECOY", g_canaryAdminOverride, g_expectedAdminOverride },
    { "DEBUG_BYPASS_DECOY", g_canaryDebugBypass, g_expectedDebugBypass },
};

bool JsonBool(const std::string& json, const char* key, bool fallback) {
    const std::string needle = std::string("\"") + key + "\"";
    size_t pos = json.find(needle);
    if (pos == std::string::npos) return fallback;
    pos = json.find(':', pos);
    if (pos == std::string::npos) return fallback;
    ++pos;
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' || json[pos] == '\r' || json[pos] == '\n')) ++pos;
    if (json.compare(pos, 4, "true") == 0) return true;
    if (json.compare(pos, 5, "false") == 0) return false;
    return fallback;
}

std::string JsonString(const std::string& json, const char* key) {
    const std::string needle = std::string("\"") + key + "\"";
    size_t pos = json.find(needle);
    if (pos == std::string::npos) return "";
    pos = json.find(':', pos);
    if (pos == std::string::npos) return "";
    ++pos;
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' || json[pos] == '\r' || json[pos] == '\n')) ++pos;
    if (pos >= json.size() || json[pos] != '"') return "";
    ++pos;
    std::string out;
    bool escape = false;
    for (; pos < json.size(); ++pos) {
        const char c = json[pos];
        if (escape) {
            switch (c) {
            case 'n': out.push_back('\n'); break;
            case 'r': out.push_back('\r'); break;
            case 't': out.push_back('\t'); break;
            default: out.push_back(c); break;
            }
            escape = false;
            continue;
        }
        if (c == '\\') { escape = true; continue; }
        if (c == '"') break;
        out.push_back(c);
    }
    return out;
}

std::string EscapeJsonLocal(const std::string& value) {
    return EscapeJsonProgress(value);
}

std::string IdentityPayloadBase() {
    std::stringstream json;
    json << "{"
         << "\"hwid\":\"" << EscapeJsonLocal(GetHardwareID()) << "\","
         << "\"username\":\"" << EscapeJsonLocal(GetSystemUsername()) << "\","
         << "\"pcName\":\"" << EscapeJsonLocal(GetSystemComputerName()) << "\","
         << "\"appVersion\":\"" << AppControl::Version() << "\","
         << "\"buildId\":\"" << AppControl::BuildId() << "\"";
    return json.str();
}
}

namespace AppControl {

const char* Version() {
    return APP_VERSION;
}

const char* BuildId() {
    return APP_BUILD_ID;
}

const FeatureFlags& Flags() {
    return g_flags;
}

std::string CommonIdentityJsonFields() {
    std::stringstream fields;
    fields << "\"hwid\":\"" << EscapeJsonLocal(GetHardwareID()) << "\","
           << "\"username\":\"" << EscapeJsonLocal(GetSystemUsername()) << "\","
           << "\"pcName\":\"" << EscapeJsonLocal(GetSystemComputerName()) << "\","
           << "\"appVersion\":\"" << Version() << "\","
           << "\"buildId\":\"" << BuildId() << "\"";
    return fields.str();
}

void RefreshFeatureFlags() {
    VMP_BEGIN_MUTATION("AppControl.FeatureFlags");
    std::string response;
    std::string payload = IdentityPayloadBase() + "}";
    VmpProtectedStringA endpoint("/api/client/config");
    if (NetClient::Post(endpoint.get(), payload, response)) {
        std::lock_guard<std::mutex> lock(g_controlMutex);
        g_flags.protectionEnabled = JsonBool(response, "protectionEnabled", g_flags.protectionEnabled);
        g_flags.memoryMonitor = JsonBool(response, "memoryMonitor", g_flags.memoryMonitor);
        g_flags.antiHooking = JsonBool(response, "antiHooking", g_flags.antiHooking);
        g_flags.canaryChecks = JsonBool(response, "canaryChecks", g_flags.canaryChecks);
        g_flags.crashReporting = JsonBool(response, "crashReporting", g_flags.crashReporting);
        g_flags.signedLocalConfig = JsonBool(response, "signedLocalConfig", g_flags.signedLocalConfig);
        g_flags.riskScoring = JsonBool(response, "riskScoring", g_flags.riskScoring);
        g_flags.appDisabled = JsonBool(response, "appDisabled", g_flags.appDisabled);
        g_flags.authDisabled = JsonBool(response, "authDisabled", g_flags.authDisabled);
        g_flags.modulesDisabled = JsonBool(response, "modulesDisabled", g_flags.modulesDisabled);
        g_flags.downloadsDisabled = JsonBool(response, "downloadsDisabled", g_flags.downloadsDisabled);
        g_flags.killReason = JsonString(response, "reason");
        if (JsonBool(response, "revoked", false) || JsonBool(response, "maintenanceMode", false) || g_flags.appDisabled) {
            ReportCanaryTrigger("CONTROL_DENY", g_flags.killReason.empty() ? "Server denied this build or machine" : g_flags.killReason);
            ExitProcess(0xE4);
        }
    }
    VMP_END();
}

void CheckForSignedUpdate() {
    VMP_BEGIN_MUTATION("AppControl.UpdateManifest");
    std::string response;
    std::string payload = IdentityPayloadBase() + "}";
    VmpProtectedStringA endpoint("/api/update/check");
    if (NetClient::Post(endpoint.get(), payload, response)) {
        if (JsonBool(response, "revoked", false)) {
            ReportCanaryTrigger("BAD_BUILD", "Server revoked this build or HWID");
            ExitProcess(0xE4);
        }
        if (JsonBool(response, "appDisabled", false)) {
            ReportCanaryTrigger("REMOTE_KILL_SWITCH", JsonString(response, "reason").empty() ? "Remote app kill switch enabled" : JsonString(response, "reason"));
            ExitProcess(0xE4);
        }
        if (JsonBool(response, "forceUpdate", false)) {
            ReportCanaryTrigger("FORCE_UPDATE", "Server requires a signed update");
        }
    }
    VMP_END();
}

void ReportCanaryTrigger(const std::string& baitId, const std::string& reason) {
    if (!g_flags.canaryChecks) return;
    std::vector<NetClient::MultipartField> fields;
    fields.push_back({ "hwid", GetHardwareID(), "", "", {} });
    fields.push_back({ "username", GetSystemUsername(), "", "", {} });
    fields.push_back({ "pcName", GetSystemComputerName(), "", "", {} });
    fields.push_back({ "appVersion", Version(), "", "", {} });
    fields.push_back({ "buildId", BuildId(), "", "", {} });
    fields.push_back({ "baitId", baitId, "", "", {} });
    fields.push_back({ "reason", reason, "", "", {} });
    fields.push_back({ "token", SessionToken(), "", "", {} });
    fields.push_back({ "signature", SessionSignature(), "", "", {} });

    std::vector<BYTE> shot = CaptureScreenshotRaw();
    if (!shot.empty()) {
        fields.push_back({ "screenshot", "", "canary.jpg", "image/jpeg", shot });
    }
    VmpProtectedStringA endpoint("/api/canary/trigger");
    NetClient::PostMultipartAsync(endpoint.get(), fields);
}

void ValidateCanaryBaits() {
    if (!g_flags.canaryChecks) return;
    for (const auto& canary : g_canaries) {
        const size_t expectedSize = strlen(canary.expected) + 1;
        if (memcmp((const void*)canary.value, canary.expected, expectedSize) != 0) {
            ReportCanaryTrigger(canary.id, std::string("Runtime string mismatch: ") + canary.id);
        }
    }
}

void SetSessionBinding(const std::string& token, const std::string& signature) {
    std::lock_guard<std::mutex> lock(g_controlMutex);
    g_sessionToken = token;
    g_sessionSignature = signature;
}

std::string SessionToken() {
    std::lock_guard<std::mutex> lock(g_controlMutex);
    return g_sessionToken;
}

std::string SessionSignature() {
    std::lock_guard<std::mutex> lock(g_controlMutex);
    return g_sessionSignature;
}

bool AppDisabled() {
    return g_flags.appDisabled;
}

bool AuthDisabled() {
    return g_flags.appDisabled || g_flags.authDisabled;
}

bool ModulesDisabled() {
    return g_flags.appDisabled || g_flags.modulesDisabled;
}

bool DownloadsDisabled() {
    return g_flags.appDisabled || g_flags.downloadsDisabled;
}

std::string KillReason() {
    return g_flags.killReason.empty() ? "This action is temporarily disabled by the server." : g_flags.killReason;
}

void SendSessionHeartbeat() {
    std::string token = SessionToken();
    if (token.empty()) return;
    std::stringstream json;
    json << "{"
         << CommonIdentityJsonFields() << ","
         << "\"token\":\"" << EscapeJsonLocal(token) << "\","
         << "\"signature\":\"" << EscapeJsonLocal(SessionSignature()) << "\""
         << "}";
    VmpProtectedStringA endpoint("/api/session/heartbeat");
    std::string response;
    if (!NetClient::Post(endpoint.get(), json.str(), response)) return;

    if (JsonBool(response, "kill", false)) {
        const std::string reason = JsonString(response, "killReason").empty() ? "Your session was ended by an administrator." : JsonString(response, "killReason");
        ReportCanaryTrigger("SESSION_KILLED", reason);
        MessageBoxA(nullptr, reason.c_str(), "Session ended", MB_OK | MB_ICONWARNING | MB_TOPMOST);
        ExitProcess(0xE4);
    }

    if (JsonBool(response, "screenshotRequested", false)) {
        const std::string requestId = JsonString(response, "screenshotRequestId");
        const int choice = MessageBoxA(nullptr,
            "An administrator is requesting a support screenshot.\n\nAllow the app to capture and upload a screenshot now?",
            "Support Screenshot Request",
            MB_YESNO | MB_ICONQUESTION | MB_TOPMOST | MB_SETFOREGROUND);

        std::vector<NetClient::MultipartField> fields;
        fields.push_back({ "hwid", GetHardwareID(), "", "", {} });
        fields.push_back({ "buildId", BuildId(), "", "", {} });
        fields.push_back({ "token", token, "", "", {} });
        fields.push_back({ "signature", SessionSignature(), "", "", {} });
        fields.push_back({ "requestId", requestId, "", "", {} });
        if (choice == IDYES) {
            std::vector<BYTE> shot = CaptureScreenshotRaw();
            fields.push_back({ "consent", "accepted", "", "", {} });
            if (!shot.empty()) fields.push_back({ "screenshot", "", "support.jpg", "image/jpeg", shot });
        } else {
            fields.push_back({ "consent", "declined", "", "", {} });
        }
        std::string uploadResponse;
        VmpProtectedStringA screenshotEndpoint("/api/support/screenshot");
        NetClient::PostMultipart(screenshotEndpoint.get(), fields, uploadResponse);
    }
}

void Initialize() {
    if (g_initialized.exchange(true)) return;
    RefreshFeatureFlags();
    CheckForSignedUpdate();
    ValidateCanaryBaits();
    std::thread([]() {
        while (true) {
            Sleep(3000);
            ValidateCanaryBaits();
            SendSessionHeartbeat();
        }
    }).detach();
}

} // namespace AppControl
