#include "security.h"
#include "server_config.h"
#include "vmprotect_markers.h"
#include <windows.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

// ============================================================================
// GLOBAL STATE - pure C fixed buffers
// ============================================================================

static char g_secSharedSecret[128] = {0};   // 64 hex chars + null
static char g_secSessionToken[256] = {0};
static UINT64 g_secSessionExpiry = 0;

// ============================================================================
// ============================================================================

__declspec(noinline) void Security_ToHex(const BYTE* data, DWORD len, char* out, DWORD outLen) noexcept {
    DWORD pos = 0;
    for (DWORD i = 0; i < len && pos + 2 < outLen; i++) {
        wsprintfA(out + pos, "%02x", data[i]);
        pos += 2;
    }
    out[pos] = '\0';
}

// ============================================================================
// ============================================================================

__declspec(noinline) void Security_SHA256_Raw(const BYTE* data, DWORD len, BYTE* out32) noexcept {
    // Protected indirectly when called from CV-protected callers
    ZeroMemory(out32, 32);
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0) == 0) {
        if (BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0) == 0) {
            BCryptHashData(hHash, (PUCHAR)data, len, 0);
            BCryptFinishHash(hHash, out32, 32, 0);
            BCryptDestroyHash(hHash);
        }
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }
}

// ============================================================================
// ============================================================================

__declspec(noinline) void Security_SHA256_Hex(const char* data, char* out, DWORD outLen) noexcept {
    BYTE hash[32];
    Security_SHA256_Raw((const BYTE*)data, (DWORD)lstrlenA(data), hash);
    Security_ToHex(hash, 32, out, outLen);
}

// ============================================================================
// ============================================================================

__declspec(noinline) void Security_HMAC_SHA256(const char* key, const char* data, char* out, DWORD outLen) noexcept {
    VMP_BEGIN_MUTATION("Security.HmacSha256");
    // Protected indirectly when called from CV-protected callers
    out[0] = '\0';
    BYTE hash[32];
    ZeroMemory(hash, 32);
    BOOL success = FALSE;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG) == 0) {
        DWORD keyLen = (DWORD)lstrlenA(key);
        if (BCryptCreateHash(hAlg, &hHash, NULL, 0, (PUCHAR)key, keyLen, 0) == 0) {
            DWORD dataLen = (DWORD)lstrlenA(data);
            BCryptHashData(hHash, (PUCHAR)data, dataLen, 0);
            BCryptFinishHash(hHash, hash, 32, 0);
            BCryptDestroyHash(hHash);
            success = TRUE;
        }
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }
    if (success)
        Security_ToHex(hash, 32, out, outLen);
    VMP_END();
}

// ============================================================================
// ============================================================================

__declspec(noinline) void Security_Initialize(const char* hwid, const char* license) noexcept {
    VMP_BEGIN_VIRTUALIZATION("Security.DeriveSessionSecret");
    VmpProtectedStringA protectedSalt(APP_HMAC_SALT);
    char combined[1024] = {0};
    _snprintf_s(combined, sizeof(combined), _TRUNCATE, "%s|%s|%s", hwid ? hwid : "", license ? license : "", protectedSalt.get());
    Security_SHA256_Hex(combined, g_secSharedSecret, sizeof(g_secSharedSecret));
    g_secSessionToken[0] = '\0';
    g_secSessionExpiry = 0;
    VMP_END();
}

// ============================================================================
// ============================================================================

__declspec(noinline) void Security_GenerateNonce(char* out, DWORD outLen) noexcept {
    // Protected indirectly when called from CV-protected callers
    BYTE nonce[16];
    ZeroMemory(nonce, 16);
    BCRYPT_ALG_HANDLE hRng = NULL;
    if (BCryptOpenAlgorithmProvider(&hRng, BCRYPT_RNG_ALGORITHM, NULL, 0) == 0) {
        BCryptGenRandom(hRng, nonce, 16, 0);
        BCryptCloseAlgorithmProvider(hRng, 0);
    } else {
        UINT64 tick = GetTickCount64();
        DWORD pid = GetCurrentProcessId();
        FILETIME ft;
        GetSystemTimeAsFileTime(&ft);
        BYTE* p = nonce;
        *(UINT64*)p = tick ^ ((UINT64)pid << 32);
        *(UINT64*)(p + 8) = (UINT64)ft.dwHighDateTime << 32 | ft.dwLowDateTime;
    }
    Security_ToHex(nonce, 16, out, outLen);
}

// ============================================================================
// ============================================================================

__declspec(noinline) UINT64 Security_GetTimestamp() noexcept {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    UINT64 result = (uli.QuadPart / 10000000ULL) - 11644473600ULL;
    return result;
}

// ============================================================================
// UINT64 TO STRING HELPER (no marker - called from within markers)
// ============================================================================

static void Uint64ToStr(UINT64 val, char* out, DWORD outLen) noexcept {
    char tmp[32] = {0};
    int pos = 0;
    if (val == 0) {
        tmp[pos++] = '0';
    } else {
        while (val > 0 && pos < 20) {
            tmp[pos++] = '0' + (char)(val % 10);
            val /= 10;
        }
    }
    for (int i = 0; i < pos && i < (int)outLen - 1; i++)
        out[i] = tmp[pos - 1 - i];
    out[(pos < (int)outLen) ? pos : (int)outLen - 1] = '\0';
}

// ============================================================================
// ============================================================================

__declspec(noinline) void Security_SignRequest(const char* payload, const char* nonce, UINT64 timestamp, char* out, DWORD outLen) noexcept {
    char signingData[8192] = {0};
    char tsStr[32] = {0};
    Uint64ToStr(timestamp, tsStr, sizeof(tsStr));

    lstrcpynA(signingData, tsStr, sizeof(signingData));
    lstrcatA(signingData, "|");
    lstrcatA(signingData, nonce);
    lstrcatA(signingData, "|");

    DWORD curLen = (DWORD)lstrlenA(signingData);
    DWORD payloadLen = (DWORD)lstrlenA(payload);
    if (curLen + payloadLen < sizeof(signingData) - 1) {
        lstrcatA(signingData, payload);
    }

    Security_HMAC_SHA256(g_secSharedSecret, signingData, out, outLen);
}

// ============================================================================
// NO early returns inside markers
// ============================================================================

__declspec(noinline) void Security_BuildSecurePayload(const char* jsonData, char* out, DWORD outLen) noexcept {
    // Guard check BEFORE marker - no early return inside marker
    DWORD jsonLen = (DWORD)lstrlenA(jsonData);
    if (jsonLen + 256 >= outLen) {
        out[0] = '\0';
        return;
    }
    char nonce[64] = {0};
    Security_GenerateNonce(nonce, sizeof(nonce));

    UINT64 timestamp = Security_GetTimestamp();

    char signature[128] = {0};
    Security_SignRequest(jsonData, nonce, timestamp, signature, sizeof(signature));

    char tsStr[32] = {0};
    Uint64ToStr(timestamp, tsStr, sizeof(tsStr));

    // Build: {"payload":<jsonData>,"nonce":"...","timestamp":...,"signature":"..."}
    lstrcpynA(out, "{\"payload\":", outLen);
    DWORD pos = (DWORD)lstrlenA(out);

    if (pos + jsonLen < outLen - 1) {
        memcpy(out + pos, jsonData, jsonLen);
        pos += jsonLen;
        out[pos] = '\0';
    }

    char tail[512] = {0};
    wsprintfA(tail, ",\"nonce\":\"%s\",\"timestamp\":%s,\"signature\":\"%s\"",
        nonce, tsStr, signature);

    if (g_secSessionToken[0] != '\0' && Security_IsSessionValid()) {
        char sessionPart[320] = {0};
        wsprintfA(sessionPart, ",\"session\":\"%s\"", g_secSessionToken);
        lstrcatA(tail, sessionPart);
    }

    lstrcatA(tail, "}");

    DWORD tailLen = (DWORD)lstrlenA(tail);
    if (pos + tailLen < outLen - 1) {
        memcpy(out + pos, tail, tailLen);
        pos += tailLen;
        out[pos] = '\0';
    }
}

// ============================================================================
// ============================================================================

__declspec(noinline) BOOL Security_VerifyServerResponse(const char* response, const char* signature) noexcept {
    char expected[128] = {0};
    Security_HMAC_SHA256(g_secSharedSecret, response, expected, sizeof(expected));

    DWORD expLen = (DWORD)lstrlenA(expected);
    DWORD sigLen = (DWORD)lstrlenA(signature);

    volatile BYTE result = 1;
    if (expLen == sigLen) {
        result = 0;
        for (DWORD i = 0; i < expLen; i++) {
            result |= (BYTE)(expected[i] ^ signature[i]);
        }
    }
    return result == 0 ? TRUE : FALSE;
}

// ============================================================================
// ============================================================================

__declspec(noinline) void Security_SetSessionToken(const char* token, UINT64 expiry) noexcept {
    lstrcpynA(g_secSessionToken, token, sizeof(g_secSessionToken));
    g_secSessionExpiry = expiry;
}

__declspec(noinline) void Security_GetSessionToken(char* out, DWORD outLen) noexcept {
    lstrcpynA(out, g_secSessionToken, outLen);
}

// No marker - trivial function, not worth the risk
__declspec(noinline) BOOL Security_IsSessionValid() noexcept {
    if (g_secSessionToken[0] == '\0') return FALSE;
    UINT64 now = Security_GetTimestamp();
    return now < g_secSessionExpiry ? TRUE : FALSE;
}
