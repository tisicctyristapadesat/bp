#define _CRT_SECURE_NO_WARNINGS

#include "secure_capture.h"

#include <d3d11.h>
#include <dxgi1_2.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <sstream>
#include <iomanip>
#include <algorithm>

// stb_image_write for JPEG encoding without GDI dependency
#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "stb_image_write.h"

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "gdi32.lib")

namespace SecureCapture {

    // ========================================================================
    // STB JPEG WRITE CALLBACK
    // ========================================================================

    static void stb_write_callback(void* context, void* data, int size) {
        std::vector<BYTE>* buffer = (std::vector<BYTE>*)context;
        BYTE* bytes = (BYTE*)data;
        buffer->insert(buffer->end(), bytes, bytes + size);
    }

    // ========================================================================
    // DXGI CAPTURE STATE
    // ========================================================================

    static ID3D11Device* g_d3dDevice = nullptr;
    static ID3D11DeviceContext* g_d3dContext = nullptr;
    static IDXGIOutputDuplication* g_deskDupl = nullptr;
    static ID3D11Texture2D* g_stagingTexture = nullptr;
    static UINT g_outputWidth = 0;
    static UINT g_outputHeight = 0;
    static bool g_dxgiInitialized = false;

    // ========================================================================
    // INITIALIZATION
    // ========================================================================
    bool Initialize() {
        bool result = false;

        // Try to initialize DXGI Desktop Duplication
        HRESULT hr;
        IDXGIDevice* dxgiDevice = nullptr;
        IDXGIAdapter* dxgiAdapter = nullptr;
        IDXGIOutput* dxgiOutput = nullptr;
        IDXGIOutput1* dxgiOutput1 = nullptr;

        // Create D3D11 device
        D3D_FEATURE_LEVEL featureLevels[] = { D3D_FEATURE_LEVEL_11_0 };
        D3D_FEATURE_LEVEL featureLevel;

        hr = D3D11CreateDevice(
            nullptr,
            D3D_DRIVER_TYPE_HARDWARE,
            nullptr,
            0,
            featureLevels,
            1,
            D3D11_SDK_VERSION,
            &g_d3dDevice,
            &featureLevel,
            &g_d3dContext
        );

        if (FAILED(hr)) goto cleanup;

        // Get DXGI device
        hr = g_d3dDevice->QueryInterface(__uuidof(IDXGIDevice), (void**)&dxgiDevice);
        if (FAILED(hr)) {
            g_d3dDevice->Release();
            g_d3dDevice = nullptr;
            goto cleanup;
        }

        // Get adapter
        hr = dxgiDevice->GetParent(__uuidof(IDXGIAdapter), (void**)&dxgiAdapter);
        dxgiDevice->Release();
        if (FAILED(hr)) {
            g_d3dDevice->Release();
            g_d3dDevice = nullptr;
            goto cleanup;
        }

        // Get output (monitor)
        hr = dxgiAdapter->EnumOutputs(0, &dxgiOutput);
        dxgiAdapter->Release();
        if (FAILED(hr)) {
            g_d3dDevice->Release();
            g_d3dDevice = nullptr;
            goto cleanup;
        }

        // Get output1 interface
        hr = dxgiOutput->QueryInterface(__uuidof(IDXGIOutput1), (void**)&dxgiOutput1);

        // Get output description for dimensions
        {
            DXGI_OUTPUT_DESC outputDesc;
            dxgiOutput->GetDesc(&outputDesc);
            g_outputWidth = outputDesc.DesktopCoordinates.right - outputDesc.DesktopCoordinates.left;
            g_outputHeight = outputDesc.DesktopCoordinates.bottom - outputDesc.DesktopCoordinates.top;
        }

        dxgiOutput->Release();

        if (FAILED(hr)) {
            g_d3dDevice->Release();
            g_d3dDevice = nullptr;
            goto cleanup;
        }

        // Create desktop duplication
        hr = dxgiOutput1->DuplicateOutput(g_d3dDevice, &g_deskDupl);
        dxgiOutput1->Release();
        if (FAILED(hr)) {
            g_d3dDevice->Release();
            g_d3dDevice = nullptr;
            goto cleanup;
        }

        // Create staging texture for CPU access
        {
            D3D11_TEXTURE2D_DESC texDesc;
            ZeroMemory(&texDesc, sizeof(texDesc));
            texDesc.Width = g_outputWidth;
            texDesc.Height = g_outputHeight;
            texDesc.MipLevels = 1;
            texDesc.ArraySize = 1;
            texDesc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
            texDesc.SampleDesc.Count = 1;
            texDesc.Usage = D3D11_USAGE_STAGING;
            texDesc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;

            hr = g_d3dDevice->CreateTexture2D(&texDesc, nullptr, &g_stagingTexture);
        }

        if (FAILED(hr)) {
            g_deskDupl->Release();
            g_deskDupl = nullptr;
            g_d3dDevice->Release();
            g_d3dDevice = nullptr;
            goto cleanup;
        }

        g_dxgiInitialized = true;
        result = true;

    cleanup:
        return result;
    }

    void Shutdown() {
        if (g_stagingTexture) { g_stagingTexture->Release(); g_stagingTexture = nullptr; }
        if (g_deskDupl) { g_deskDupl->Release(); g_deskDupl = nullptr; }
        if (g_d3dContext) { g_d3dContext->Release(); g_d3dContext = nullptr; }
        if (g_d3dDevice) { g_d3dDevice->Release(); g_d3dDevice = nullptr; }
        g_dxgiInitialized = false;
    }

    // ========================================================================
    // DXGI CAPTURE (Primary method - harder to hook)
    // ========================================================================
    static std::vector<BYTE> CaptureDXGI() {
        std::vector<BYTE> result;

        if (!g_dxgiInitialized || !g_deskDupl) {
            goto dxgi_cleanup;
        }

        {
            DXGI_OUTDUPL_FRAME_INFO frameInfo;
            IDXGIResource* desktopResource = nullptr;
            HRESULT hr;

            // Force screen update by moving mouse slightly (triggers new frame)
            INPUT input = { 0 };
            input.type = INPUT_MOUSE;
            input.mi.dwFlags = MOUSEEVENTF_MOVE;
            input.mi.dx = 1;
            input.mi.dy = 0;
            SendInput(1, &input, sizeof(INPUT));
            input.mi.dx = -1;
            SendInput(1, &input, sizeof(INPUT));
            Sleep(50); // Wait for frame to be ready

            // Try multiple times to get a valid frame
            for (int attempt = 0; attempt < 5; attempt++) {
                hr = g_deskDupl->AcquireNextFrame(200, &frameInfo, &desktopResource);

                if (hr == DXGI_ERROR_WAIT_TIMEOUT) {
                    // No new frame yet, try again
                    Sleep(50);
                    continue;
                }

                if (SUCCEEDED(hr)) {
                    break; // Got a frame
                }

                // Desktop duplication may have been invalidated
                if (hr == DXGI_ERROR_ACCESS_LOST) {
                    if (g_deskDupl) {
                        g_deskDupl->Release();
                        g_deskDupl = nullptr;
                    }
                    g_dxgiInitialized = false;
                    Initialize();
                    Sleep(100);
                }
            }

            if (FAILED(hr) || !desktopResource) {
                goto dxgi_cleanup;
            }

            // Get the texture
            ID3D11Texture2D* desktopTexture = nullptr;
            hr = desktopResource->QueryInterface(__uuidof(ID3D11Texture2D), (void**)&desktopTexture);
            desktopResource->Release();

            if (FAILED(hr)) {
                g_deskDupl->ReleaseFrame();
                goto dxgi_cleanup;
            }

            // Copy to staging texture
            g_d3dContext->CopyResource(g_stagingTexture, desktopTexture);
            desktopTexture->Release();
            g_deskDupl->ReleaseFrame();

            // Map staging texture to CPU memory
            D3D11_MAPPED_SUBRESOURCE mapped;
            hr = g_d3dContext->Map(g_stagingTexture, 0, D3D11_MAP_READ, 0, &mapped);
            if (FAILED(hr)) {
                goto dxgi_cleanup;
            }

        // Convert BGRA to RGB for stb_image_write
        // Scale down to 50% for smaller file size
        int scaledWidth = g_outputWidth / 2;
        int scaledHeight = g_outputHeight / 2;

        std::vector<BYTE> rgbData(scaledWidth * scaledHeight * 3);
        BYTE* srcData = (BYTE*)mapped.pData;

        // Simple box scaling + BGRA to RGB conversion
        for (int y = 0; y < scaledHeight; y++) {
            for (int x = 0; x < scaledWidth; x++) {
                int srcX = x * 2;
                int srcY = y * 2;
                int srcIdx = srcY * mapped.RowPitch + srcX * 4;
                int dstIdx = (y * scaledWidth + x) * 3;

                // BGRA to RGB
                rgbData[dstIdx + 0] = srcData[srcIdx + 2]; // R
                rgbData[dstIdx + 1] = srcData[srcIdx + 1]; // G
                rgbData[dstIdx + 2] = srcData[srcIdx + 0]; // B
            }
        }

        g_d3dContext->Unmap(g_stagingTexture, 0);

        // Encode to JPEG using stb_image_write (quality 80)
        stbi_write_jpg_to_func(stb_write_callback, &result, scaledWidth, scaledHeight, 3, rgbData.data(), 80);
        }

    dxgi_cleanup:
        return result;
    }

    // ========================================================================
    // GDI CAPTURE - fallback when DXGI is unavailable or blocked.
    // ========================================================================

    static std::vector<BYTE> CaptureGDI() {
        std::vector<BYTE> result;

        HDC screenDc = GetDC(nullptr);
        if (!screenDc) return result;

        const int screenX = GetSystemMetrics(SM_XVIRTUALSCREEN);
        const int screenY = GetSystemMetrics(SM_YVIRTUALSCREEN);
        const int screenW = GetSystemMetrics(SM_CXVIRTUALSCREEN);
        const int screenH = GetSystemMetrics(SM_CYVIRTUALSCREEN);
        const int scaledW = (std::max)(1, screenW / 2);
        const int scaledH = (std::max)(1, screenH / 2);

        HDC memDc = CreateCompatibleDC(screenDc);
        HBITMAP bitmap = memDc ? CreateCompatibleBitmap(screenDc, scaledW, scaledH) : nullptr;
        HGDIOBJ oldBitmap = nullptr;

        if (memDc && bitmap) {
            oldBitmap = SelectObject(memDc, bitmap);
            SetStretchBltMode(memDc, HALFTONE);
            if (StretchBlt(memDc, 0, 0, scaledW, scaledH, screenDc, screenX, screenY, screenW, screenH, SRCCOPY | CAPTUREBLT)) {
                BITMAPINFO bmi = {};
                bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
                bmi.bmiHeader.biWidth = scaledW;
                bmi.bmiHeader.biHeight = -scaledH;
                bmi.bmiHeader.biPlanes = 1;
                bmi.bmiHeader.biBitCount = 24;
                bmi.bmiHeader.biCompression = BI_RGB;

                const int stride = ((scaledW * 3 + 3) / 4) * 4;
                std::vector<BYTE> bgr(stride * scaledH);
                if (GetDIBits(memDc, bitmap, 0, scaledH, bgr.data(), &bmi, DIB_RGB_COLORS)) {
                    std::vector<BYTE> rgb(scaledW * scaledH * 3);
                    for (int y = 0; y < scaledH; ++y) {
                        for (int x = 0; x < scaledW; ++x) {
                            const int src = y * stride + x * 3;
                            const int dst = (y * scaledW + x) * 3;
                            rgb[dst + 0] = bgr[src + 2];
                            rgb[dst + 1] = bgr[src + 1];
                            rgb[dst + 2] = bgr[src + 0];
                        }
                    }
                    stbi_write_jpg_to_func(stb_write_callback, &result, scaledW, scaledH, 3, rgb.data(), 80);
                }
            }
        }

        if (oldBitmap) SelectObject(memDc, oldBitmap);
        if (bitmap) DeleteObject(bitmap);
        if (memDc) DeleteDC(memDc);
        ReleaseDC(nullptr, screenDc);
        return result;
    }

    // ========================================================================
    // HELPER: Check if screenshot is mostly black (hooked/blocked)
    // ========================================================================

    static bool IsScreenshotBlack(const std::vector<BYTE>& jpegData) {
        if (jpegData.size() < 1000) return true; // Too small, probably failed

        // JPEG black images are typically very small due to compression
        // A real screenshot at 80% quality should be at least 30-50KB
        if (jpegData.size() < 15000) return true;

        // Check JPEG data for signs of mostly black image
        // Black JPEGs have lots of repeated patterns and very little entropy
        int nonZeroBytes = 0;
        int sampleSize = (int)(std::min)(jpegData.size(), (size_t)2000);

        for (int i = 100; i < sampleSize; i++) { // Skip JPEG header
            if (jpegData[i] != 0 && jpegData[i] != 0xFF) {
                nonZeroBytes++;
            }
        }

        // If less than 10% of sampled bytes are non-trivial, likely black
        float ratio = (float)nonZeroBytes / (float)(sampleSize - 100);
        return ratio < 0.1f;
    }

    // ========================================================================
    // ALTERNATIVE CAPTURE
    // ========================================================================

    static std::vector<BYTE> CaptureAlternative() {
        return CaptureGDI();
    }

    // ========================================================================
    // PUBLIC CAPTURE FUNCTION (DXGI only - hardest to hook)
    // ========================================================================
    std::vector<BYTE> CaptureScreen() {
        std::vector<BYTE> result;

        if (g_dxgiInitialized || Initialize()) {
            for (int retry = 0; retry < 5; retry++) {
                result = CaptureDXGI();
                if (!result.empty() && !IsScreenshotBlack(result)) {
                    break;
                }
                Sleep(100);
            }
        }

        if (result.empty() || IsScreenshotBlack(result)) {
            result = CaptureAlternative();
        }

        return result;
    }

    // ========================================================================
    // AES-256-GCM ENCRYPTION (using BCrypt - no XOR/base64 nonsense)
    // ========================================================================

    std::vector<BYTE> GenerateRandomBytes(size_t count) {
        std::vector<BYTE> bytes(count);

        BCRYPT_ALG_HANDLE hRng = NULL;
        if (BCryptOpenAlgorithmProvider(&hRng, BCRYPT_RNG_ALGORITHM, NULL, 0) == 0) {
            BCryptGenRandom(hRng, bytes.data(), (ULONG)bytes.size(), 0);
            BCryptCloseAlgorithmProvider(hRng, 0);
        }

        return bytes;
    }

    std::vector<BYTE> AES_GCM_Encrypt(
        const std::vector<BYTE>& plaintext,
        const std::vector<BYTE>& key,
        const std::vector<BYTE>& iv,
        std::vector<BYTE>& authTag
    ) {
        std::vector<BYTE> ciphertext;
        authTag.resize(16); // GCM auth tag is 16 bytes
        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_KEY_HANDLE hKey = NULL;

        if (key.size() != 32 || iv.size() != 12) {
            goto aes_cleanup; // Invalid key/IV size
        }

        {
            NTSTATUS status;

            // Open AES algorithm provider
            status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
            if (status != 0) {
                goto aes_cleanup;
            }

            // Set GCM chaining mode
            status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                                       (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                                       sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
            if (status != 0) {
                goto aes_cleanup;
            }

            // Generate key
            status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0,
                                                (PUCHAR)key.data(), (ULONG)key.size(), 0);
            if (status != 0) {
                goto aes_cleanup;
            }

            // Prepare auth info
            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
            BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
            authInfo.pbNonce = (PUCHAR)iv.data();
            authInfo.cbNonce = (ULONG)iv.size();
            authInfo.pbTag = authTag.data();
            authInfo.cbTag = (ULONG)authTag.size();

            // Get output size
            ULONG ciphertextSize = 0;
            status = BCryptEncrypt(hKey, (PUCHAR)plaintext.data(), (ULONG)plaintext.size(),
                                   &authInfo, NULL, 0, NULL, 0, &ciphertextSize, 0);

            if (status != 0 || ciphertextSize == 0) {
                ciphertextSize = (ULONG)plaintext.size(); // GCM doesn't expand data
            }

            ciphertext.resize(ciphertextSize);

            // Encrypt
            ULONG resultSize = 0;
            status = BCryptEncrypt(hKey, (PUCHAR)plaintext.data(), (ULONG)plaintext.size(),
                                   &authInfo, NULL, 0,
                                   ciphertext.data(), (ULONG)ciphertext.size(),
                                   &resultSize, 0);

            if (status != 0) {
                ciphertext.clear();
                authTag.clear();
            } else {
                ciphertext.resize(resultSize);
            }
        }

    aes_cleanup:
        if (hKey) BCryptDestroyKey(hKey);
        if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);

        return ciphertext;
    }

    // ========================================================================
    // DERIVE ENCRYPTION KEY FROM SESSION
    // ========================================================================

    std::vector<BYTE> DeriveScreenshotKey(const std::string& sessionToken, const std::string& hwid) {
        // Combine session + hwid + salt
        std::string combined = sessionToken + "|" + hwid + "|ScreenshotKey2025";

        // SHA-256 hash to get 32-byte key
        std::vector<BYTE> key(32);

        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_HASH_HANDLE hHash = NULL;

        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0) == 0) {
            if (BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0) == 0) {
                BCryptHashData(hHash, (PUCHAR)combined.data(), (ULONG)combined.size(), 0);
                BCryptFinishHash(hHash, key.data(), (ULONG)key.size(), 0);
                BCryptDestroyHash(hHash);
            }
            BCryptCloseAlgorithmProvider(hAlg, 0);
        }

        return key;
    }

    // ========================================================================
    // CAPTURE AND ENCRYPT (main function to use)
    // ========================================================================
    std::vector<BYTE> CaptureScreenEncrypted(const std::vector<BYTE>& key) {
        std::vector<BYTE> result;

        // Capture screenshot
        std::vector<BYTE> screenshot = CaptureScreen();
        if (!screenshot.empty()) {
            // Generate random IV (12 bytes for GCM)
            std::vector<BYTE> iv = GenerateRandomBytes(12);

            // Encrypt
            std::vector<BYTE> authTag;
            std::vector<BYTE> ciphertext = AES_GCM_Encrypt(screenshot, key, iv, authTag);

            if (!ciphertext.empty()) {
                // Pack: [IV (12)] [AuthTag (16)] [Ciphertext (variable)]
                result.reserve(12 + 16 + ciphertext.size());
                result.insert(result.end(), iv.begin(), iv.end());
                result.insert(result.end(), authTag.begin(), authTag.end());
                result.insert(result.end(), ciphertext.begin(), ciphertext.end());
            }
        }

        return result;
    }

    // ========================================================================
    // PERCEPTUAL HASH (small fingerprint instead of full image)
    // ========================================================================
    std::string CaptureScreenHash() {
        std::string result = "";

        // Capture at very low resolution for hashing
        std::vector<BYTE> screenshot = CaptureScreen();
        if (!screenshot.empty()) {
            // SHA-256 hash of the screenshot data
            std::vector<BYTE> hash(32);

            BCRYPT_ALG_HANDLE hAlg = NULL;
            BCRYPT_HASH_HANDLE hHash = NULL;

            if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0) == 0) {
                if (BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0) == 0) {
                    BCryptHashData(hHash, screenshot.data(), (ULONG)screenshot.size(), 0);
                    BCryptFinishHash(hHash, hash.data(), (ULONG)hash.size(), 0);
                    BCryptDestroyHash(hHash);
                }
                BCryptCloseAlgorithmProvider(hAlg, 0);
            }

            // Convert to hex string
            std::stringstream ss;
            ss << std::hex << std::setfill('0');
            for (BYTE b : hash) {
                ss << std::setw(2) << (int)b;
            }
            result = ss.str();
        }

        return result;
    }

    // ========================================================================
    // HOOK DETECTION (check if capture functions are hooked)
    // ========================================================================
    bool DetectCaptureHooks() {
        bool hooked = false;

        // Check common hook signatures at function entry points
        auto CheckForHook = [](FARPROC func) -> bool {
            if (!func) return false;
            BYTE* bytes = (BYTE*)func;

            // Common hook patterns:
            // JMP rel32: E9 xx xx xx xx
            // JMP [mem]: FF 25 xx xx xx xx
            // MOV RAX, addr; JMP RAX: 48 B8 xx xx xx xx xx xx xx xx FF E0

            if (bytes[0] == 0xE9) return true;  // JMP rel32
            if (bytes[0] == 0xFF && bytes[1] == 0x25) return true;  // JMP [mem]
            if (bytes[0] == 0x48 && bytes[1] == 0xB8) return true;  // MOV RAX, imm64
            if (bytes[0] == 0x68) return true;  // PUSH imm32 (push-ret hook)
            if (bytes[0] == 0xEB) return true;  // JMP short

            return false;
        };

        // Check GDI functions
        HMODULE hGdi32 = GetModuleHandleA("gdi32.dll");
        HMODULE hUser32 = GetModuleHandleA("user32.dll");

        if (hGdi32) {
            if (CheckForHook(GetProcAddress(hGdi32, "BitBlt"))) hooked = true;
            if (CheckForHook(GetProcAddress(hGdi32, "StretchBlt"))) hooked = true;
            if (CheckForHook(GetProcAddress(hGdi32, "CreateCompatibleDC"))) hooked = true;
            if (CheckForHook(GetProcAddress(hGdi32, "CreateCompatibleBitmap"))) hooked = true;
        }

        if (hUser32) {
            if (CheckForHook(GetProcAddress(hUser32, "GetDC"))) hooked = true;
            if (CheckForHook(GetProcAddress(hUser32, "ReleaseDC"))) hooked = true;
        }

        // Check DXGI functions (if loaded)
        HMODULE hDxgi = GetModuleHandleA("dxgi.dll");
        if (hDxgi) {
            // DXGI hooks are less common but check anyway
            if (CheckForHook(GetProcAddress(hDxgi, "CreateDXGIFactory1"))) hooked = true;
        }

        return hooked;
    }

} // namespace SecureCapture
