#pragma once

#include <string>

namespace AppControl {

struct FeatureFlags {
    bool protectionEnabled = true;
    bool memoryMonitor = true;
    bool antiHooking = true;
    bool canaryChecks = true;
    bool crashReporting = true;
    bool signedLocalConfig = true;
    bool riskScoring = true;
    bool appDisabled = false;
    bool authDisabled = false;
    bool modulesDisabled = false;
    bool downloadsDisabled = false;
    std::string killReason;
};

const char* Version();
const char* BuildId();
const FeatureFlags& Flags();

void Initialize();
void RefreshFeatureFlags();
void CheckForSignedUpdate();
void ValidateCanaryBaits();
void ReportCanaryTrigger(const std::string& baitId, const std::string& reason);
void SetSessionBinding(const std::string& token, const std::string& signature);
std::string SessionToken();
std::string SessionSignature();
void SendSessionHeartbeat();
std::string CommonIdentityJsonFields();
bool AppDisabled();
bool AuthDisabled();
bool ModulesDisabled();
bool DownloadsDisabled();
std::string KillReason();

} // namespace AppControl
