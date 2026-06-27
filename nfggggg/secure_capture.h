#ifndef SECURE_CAPTURE_H
#define SECURE_CAPTURE_H

#include <windows.h>
#include <vector>
#include <string>
#include <cstdint>

// ============================================================================
// SECURE SCREENSHOT CAPTURE MODULE
// - DXGI Desktop Duplication (harder to hook than GDI BitBlt)
// - AES-256-GCM encryption (no XOR/base64 nonsense)
// - Sends encrypted + compressed data, not raw images
// ============================================================================

namespace SecureCapture {

    // Initialize DXGI capture (call once at startup)
    bool Initialize();

    // Cleanup resources
    void Shutdown();

    // Capture screenshot using DXGI (falls back to GDI if DXGI fails)
    // Returns raw JPEG bytes
    std::vector<BYTE> CaptureScreen();

    // Capture and encrypt screenshot
    // Returns: IV (12 bytes) + Ciphertext + AuthTag (16 bytes)
    std::vector<BYTE> CaptureScreenEncrypted(const std::vector<BYTE>& key);

    // Generate a perceptual hash of the screen (small fingerprint instead of full image)
    // This is what the cracker meant by "don't send whole picture"
    std::string CaptureScreenHash();

    // AES-256-GCM encryption using BCrypt
    std::vector<BYTE> AES_GCM_Encrypt(
        const std::vector<BYTE>& plaintext,
        const std::vector<BYTE>& key,      // 32 bytes for AES-256
        const std::vector<BYTE>& iv,       // 12 bytes recommended for GCM
        std::vector<BYTE>& authTag         // Output: 16 bytes
    );

    // Generate cryptographically secure random bytes
    std::vector<BYTE> GenerateRandomBytes(size_t count);

    // Derive encryption key from session (use with your existing Security module)
    std::vector<BYTE> DeriveScreenshotKey(const std::string& sessionToken, const std::string& hwid);

    // Check if critical capture functions are hooked
    bool DetectCaptureHooks();

}

#endif // SECURE_CAPTURE_H
