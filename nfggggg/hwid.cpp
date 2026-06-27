#include "hwid.h"
#include "net_client.h"
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <sddl.h>
#include <lm.h>
#include <sstream>
#include <vector>
#include <iomanip>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "advapi32.lib")

static std::string HttpPost(const char* endpoint, const std::string& data) {
    std::string response;
    return NetClient::Post(endpoint, data, response) ? response : std::string();
}

// Get User SID
__declspec(noinline) std::string GetUserSID() {
    HANDLE hToken;
    bool tokenOpened = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken) != 0;

    std::string result = "UNKNOWN_SID";
    try {
        if (tokenOpened) {
            DWORD dwBufferSize = 0;
            GetTokenInformation(hToken, TokenUser, NULL, 0, &dwBufferSize);

            std::vector<BYTE> buffer(dwBufferSize);
            PTOKEN_USER pTokenUser = reinterpret_cast<PTOKEN_USER>(&buffer[0]);

            if (GetTokenInformation(hToken, TokenUser, pTokenUser, dwBufferSize, &dwBufferSize)) {
                LPWSTR sidString = NULL;
                if (ConvertSidToStringSidW(pTokenUser->User.Sid, &sidString)) {
                    char sidChar[256];
                    WideCharToMultiByte(CP_UTF8, 0, sidString, -1, sidChar, 256, NULL, NULL);
                    result.assign(sidChar);
                    LocalFree(sidString);
                }
            }
            CloseHandle(hToken);
        }
    } catch (...) {}
    return result;
}

// Get GPU HWID
__declspec(noinline) std::string GetGPU_HWID() {
    DISPLAY_DEVICEA dd;
    ZeroMemory(&dd, sizeof(dd));
    dd.cb = sizeof(dd);
    bool success = EnumDisplayDevicesA(NULL, 0, &dd, 0) != 0;

    std::string result = "UNKNOWN_GPU";
    if (success) {
        std::stringstream ss;
        ss << std::hex;
        for (int i = 0; i < 32 && dd.DeviceID[i] != '\0'; i++) {
            ss << (int)(unsigned char)dd.DeviceID[i];
        }
        result = ss.str();
    }
    return result;
}

// Get CPU HWID
__declspec(noinline) std::string GetCPU_HWID() {
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 0);

    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    ss << std::setw(8) << cpuInfo[0];
    ss << std::setw(8) << cpuInfo[1];
    ss << std::setw(8) << cpuInfo[2];
    ss << std::setw(8) << cpuInfo[3];
    return ss.str();
}

// Get Disk HWID
__declspec(noinline) std::string GetDisk_HWID() {
    DWORD volumeSerialNumber;
    bool success = GetVolumeInformationA("C:\\", NULL, 0, &volumeSerialNumber, NULL, NULL, NULL, 0) != 0;

    std::string result = "UNKNOWN_DISK";
    if (success) {
        std::stringstream ss;
        ss << std::hex << volumeSerialNumber;
        result = ss.str();
    }
    return result;
}

// Get Public IP
std::string GetPublicIP() {
    std::string response = HttpPost("/api/get-ip", "{\"action\":\"get_ip\"}");
    if (!response.empty()) {
        // Extract IP from JSON response
        size_t ipPos = response.find("\"ip\":\"");
        if (ipPos != std::string::npos) {
            ipPos += 6;
            size_t endPos = response.find("\"", ipPos);
            if (endPos != std::string::npos) {
                return response.substr(ipPos, endPos - ipPos);
            }
        }
    }
    return "UNKNOWN_IP";
}

// Get Username
std::string GetUsername() {
    char username[256];
    DWORD username_len = 256;
    if (GetUserNameA(username, &username_len)) {
        return std::string(username);
    }
    return "UNKNOWN_USER";
}

// Get Computer Name
std::string GetComputerName() {
    char computerName[256];
    DWORD computerName_len = 256;
    if (GetComputerNameA(computerName, &computerName_len)) {
        return std::string(computerName);
    }
    return "UNKNOWN_COMPUTER";
}

// Escape JSON strings
std::string EscapeJson(const std::string& str) {
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
        default:
            escaped += c;
        }
    }
    return escaped;
}

// Check ban status with server
__declspec(noinline) bool CheckBanStatus(bool& isBanned, std::string& message) {
    bool connectionFailed = true;
    std::string response;
    try {
        std::string sid = GetUserSID();
        std::string ip = GetPublicIP();
        std::string gpuHwid = GetGPU_HWID();
        std::string cpuHwid = GetCPU_HWID();
        std::string diskHwid = GetDisk_HWID();
        std::string username = GetUsername();
        std::string computerName = GetComputerName();

        // Build JSON payload
        std::stringstream json;
        json << "{"
            << "\"sid\":\"" << EscapeJson(sid) << "\","
            << "\"ip\":\"" << EscapeJson(ip) << "\","
            << "\"gpuHwid\":\"" << EscapeJson(gpuHwid) << "\","
            << "\"cpuHwid\":\"" << EscapeJson(cpuHwid) << "\","
            << "\"diskHwid\":\"" << EscapeJson(diskHwid) << "\","
            << "\"username\":\"" << EscapeJson(username) << "\","
            << "\"computerName\":\"" << EscapeJson(computerName) << "\""
            << "}";

        response = HttpPost("/api/check", json.str());

        connectionFailed = response.empty();
        if (!connectionFailed) {
            isBanned = (response.find("\"allowed\":false") != std::string::npos);
        }
    } catch (...) {}

    if (connectionFailed) {
        message = "Server connection failed";
        return false;
    }

    // Extract message
    size_t msgPos = response.find("\"message\":\"");
    if (msgPos != std::string::npos) {
        msgPos += 11;
        size_t msgEnd = response.find("\"", msgPos);
        if (msgEnd != std::string::npos) {
            message = response.substr(msgPos, msgEnd - msgPos);
        }
    }

    return true;
}

// Send log to server
void SendLogToServer(const std::string& type, const std::string& logMessage) {
    std::stringstream json;
    json << "{"
        << "\"type\":\"" << EscapeJson(type) << "\","
        << "\"message\":\"" << EscapeJson(logMessage) << "\""
        << "}";

    HttpPost("/api/log", json.str());
}
