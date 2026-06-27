#pragma once
#include <string>
#include <vector>
#include <functional>
#include <windows.h>

// ============================================================================
// CENTRALIZED NETWORK CLIENT
// Replaces all WinHTTP, raw Winsock, and URLDownloadToFile calls
// Single point of contact for all backend communication
// ============================================================================

namespace NetClient {

    // Initialize the client (call once at startup)
    void Initialize();

    // Shutdown and cleanup
    void Shutdown();

    // --- Core POST (JSON) ---
    // Returns true on success, response body in 'response'
    bool Post(const char* endpoint, const std::string& json, std::string& response);

    // Fire-and-forget POST (alerts, bans, logs - don't wait for response)
    void PostAsync(const char* endpoint, const std::string& json);

    // --- Multipart POST (screenshots, file uploads) ---
    struct MultipartField {
        std::string name;
        std::string value;       // For text fields
        std::string filename;    // For file fields (empty = text field)
        std::string contentType; // For file fields
        std::vector<BYTE> data;  // For binary file data
    };

    bool PostMultipart(const char* endpoint,
                       const std::vector<MultipartField>& fields,
                       std::string& response);

    // Fire-and-forget multipart
    void PostMultipartAsync(const char* endpoint,
                            const std::vector<MultipartField>& fields);

    // --- File Download ---
    // Downloads to disk, returns true on success
    bool DownloadFile(const char* endpoint, const std::string& savePath);

    // --- External GET (for third-party APIs like ipify) ---
    bool ExternalGet(const wchar_t* host, int port, const wchar_t* path,
                     std::string& response, int timeoutMs = 3000,
                     const wchar_t* bearerToken = nullptr, bool useTls = false);

    // --- Connection Status ---
    bool IsConnected();

    // Get local IP address
    std::string GetLocalIPAddress();

    // --- Server Configuration ---
    std::string GetServerHost();
    int GetServerPort();
}
