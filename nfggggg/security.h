#pragma once
#include <windows.h>
#include <stdint.h>

// ============================================================================
// All functions use char* buffers, no STL, no exceptions
// ============================================================================

void Security_Initialize(const char* hwid, const char* license) noexcept;
void Security_SHA256_Raw(const BYTE* data, DWORD len, BYTE* out32) noexcept;
void Security_SHA256_Hex(const char* data, char* out, DWORD outLen) noexcept;
void Security_HMAC_SHA256(const char* key, const char* data, char* out, DWORD outLen) noexcept;
void Security_GenerateNonce(char* out, DWORD outLen) noexcept;
UINT64 Security_GetTimestamp() noexcept;
void Security_SignRequest(const char* payload, const char* nonce, UINT64 timestamp, char* out, DWORD outLen) noexcept;
void Security_BuildSecurePayload(const char* jsonData, char* out, DWORD outLen) noexcept;
BOOL Security_VerifyServerResponse(const char* response, const char* signature) noexcept;
void Security_SetSessionToken(const char* token, UINT64 expiry) noexcept;
void Security_GetSessionToken(char* out, DWORD outLen) noexcept;
BOOL Security_IsSessionValid() noexcept;
void Security_ToHex(const BYTE* data, DWORD len, char* out, DWORD outLen) noexcept;

// ============================================================================
// ============================================================================

#ifdef __cplusplus
#include <string>
#include <vector>

namespace Security {

    inline void Initialize(const std::string& hwid, const std::string& license) {
        Security_Initialize(hwid.c_str(), license.c_str());
    }

    inline std::string GenerateNonce() {
        char buf[64] = {0};
        Security_GenerateNonce(buf, sizeof(buf));
        return std::string(buf);
    }

    inline uint64_t GetTimestamp() {
        return Security_GetTimestamp();
    }

    inline std::string HMAC_SHA256(const std::string& key, const std::string& data) {
        char buf[128] = {0};
        Security_HMAC_SHA256(key.c_str(), data.c_str(), buf, sizeof(buf));
        return std::string(buf);
    }

    inline std::string SHA256(const std::string& data) {
        char buf[128] = {0};
        Security_SHA256_Hex(data.c_str(), buf, sizeof(buf));
        return std::string(buf);
    }

    inline std::string SignRequest(const std::string& payload, const std::string& nonce, uint64_t timestamp) {
        char buf[128] = {0};
        Security_SignRequest(payload.c_str(), nonce.c_str(), timestamp, buf, sizeof(buf));
        return std::string(buf);
    }

    inline std::string BuildSecurePayload(const std::string& jsonData) {
        char buf[8192] = {0};
        Security_BuildSecurePayload(jsonData.c_str(), buf, sizeof(buf));
        return std::string(buf);
    }

    inline bool VerifyServerResponse(const std::string& response, const std::string& signature) {
        return Security_VerifyServerResponse(response.c_str(), signature.c_str()) ? true : false;
    }

    inline void SetSessionToken(const std::string& token, uint64_t expiry) {
        Security_SetSessionToken(token.c_str(), expiry);
    }

    inline std::string GetSessionToken() {
        char buf[256] = {0};
        Security_GetSessionToken(buf, sizeof(buf));
        return std::string(buf);
    }

    inline bool IsSessionValid() {
        return Security_IsSessionValid() ? true : false;
    }

    inline std::string ToHex(const std::vector<uint8_t>& data) {
        char buf[512] = {0};
        Security_ToHex(data.data(), (DWORD)data.size(), buf, sizeof(buf));
        return std::string(buf);
    }

    inline std::string ToHex(const uint8_t* data, size_t len) {
        char buf[512] = {0};
        Security_ToHex(data, (DWORD)len, buf, sizeof(buf));
        return std::string(buf);
    }

    inline std::vector<uint8_t> FromHex(const std::string& hex) {
        std::vector<uint8_t> result;
        result.reserve(hex.length() / 2);
        for (size_t i = 0; i + 1 < hex.length(); i += 2) {
            char tmp[3] = { hex[i], hex[i+1], '\0' };
            result.push_back((uint8_t)strtoul(tmp, NULL, 16));
        }
        return result;
    }

    inline std::string Base64Encode(const std::vector<uint8_t>& data) {
        static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string result;
        int val = 0, valb = -6;
        for (uint8_t c : data) {
            val = (val << 8) + c;
            valb += 8;
            while (valb >= 0) {
                result.push_back(b64[(val >> valb) & 0x3F]);
                valb -= 6;
            }
        }
        if (valb > -6) result.push_back(b64[((val << 8) >> (valb + 8)) & 0x3F]);
        while (result.size() % 4) result.push_back('=');
        return result;
    }

    inline std::string Base64Encode(const std::string& data) {
        return Base64Encode(std::vector<uint8_t>(data.begin(), data.end()));
    }
}

#endif // __cplusplus
