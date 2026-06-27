#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include "net_client.h"
#include "string_obfuscation.h"
#include "server_config.h"
#include "vmprotect_markers.h"
#include <winhttp.h>
#include <thread>
#include <sstream>
#include <iostream>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ws2_32.lib")

namespace NetClient {

    std::wstring g_serverHost = APP_SERVER_HOST;
    int g_serverPort = APP_SERVER_PORT;
    bool g_serverTls = APP_SERVER_TLS != 0;
    bool g_connected = false;

    void Initialize() {
        // XOR32 decrypted at runtime
        g_serverHost = APP_SERVER_HOST;
        g_serverPort = APP_SERVER_PORT;
    }

    void Shutdown() {
    }

    std::string GetServerHost() {
        std::string host;
        host.reserve(g_serverHost.size());
        for (wchar_t ch : g_serverHost) {
            host.push_back(static_cast<char>(ch));
        }
        return host;
    }

    int GetServerPort() {
        return g_serverPort;
    }

    bool IsConnected() {
        return g_connected;
    }

    bool ExternalGet(const wchar_t* host, int port, const wchar_t* path, std::string& response, int timeoutMs, const wchar_t* bearerToken, bool useTls) {
        HINTERNET hSession = WinHttpOpen(L"NetClient", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) return false;

        DWORD timeout = timeoutMs;
        WinHttpSetOption(hSession, WINHTTP_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
        WinHttpSetOption(hSession, WINHTTP_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));
        WinHttpSetOption(hSession, WINHTTP_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));

        HINTERNET hConnect = WinHttpConnect(hSession, host, port, 0);
        if (!hConnect) { WinHttpCloseHandle(hSession); return false; }

        DWORD flags = (useTls || port == 443) ? WINHTTP_FLAG_SECURE : 0;
        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", path, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
        if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false; }
        if (bearerToken && *bearerToken) {
            std::wstring auth = L"X-Feature-API-Key: "; auth += bearerToken; auth += L"\r\n";
            WinHttpAddRequestHeaders(hRequest, auth.c_str(), -1, WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
        }

        bool success = false;
        if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
            if (WinHttpReceiveResponse(hRequest, NULL)) {
                DWORD status=0,size=sizeof(status); WinHttpQueryHeaders(hRequest,WINHTTP_QUERY_STATUS_CODE|WINHTTP_QUERY_FLAG_NUMBER,WINHTTP_HEADER_NAME_BY_INDEX,&status,&size,WINHTTP_NO_HEADER_INDEX);
                if (status < 200 || status >= 300) { WinHttpCloseHandle(hRequest);WinHttpCloseHandle(hConnect);WinHttpCloseHandle(hSession);return false; }
                DWORD dwSize = 0;
                DWORD dwDownloaded = 0;
                do {
                    if (WinHttpQueryDataAvailable(hRequest, &dwSize)) {
                        if (dwSize == 0) break;
                        if (response.size()+dwSize>1024*1024) break;
                        char* buf = new char[dwSize + 1];
                        if (WinHttpReadData(hRequest, buf, dwSize, &dwDownloaded)) {
                            buf[dwDownloaded] = '\0';
                            response += buf;
                        }
                        delete[] buf;
                    }
                } while (dwSize > 0);
                success = true;
            }
        }

        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return success;
    }

    bool Post(const char* endpoint, const std::string& json, std::string& response) {
        HINTERNET hSession = WinHttpOpen(L"NetClient", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) return false;

        HINTERNET hConnect = WinHttpConnect(hSession, g_serverHost.c_str(), g_serverPort, 0);
        if (!hConnect) { WinHttpCloseHandle(hSession); return false; }

        std::string ep_str(endpoint);
        std::wstring wep(ep_str.begin(), ep_str.end());

        // Use WINHTTP_FLAG_SECURE since we connect via HTTPS
        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", wep.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, g_serverTls ? WINHTTP_FLAG_SECURE : 0);
        if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false; }

        std::wstring headers = L"Content-Type: application/json\r\nX-Client-Type: app\r\nX-API-Key: ";
        VmpProtectedStringA protectedApiKey(APP_CLIENT_API_KEY);
        std::string apiKey=protectedApiKey.get(); headers.append(apiKey.begin(),apiKey.end()); headers += L"\r\n";
        bool success = false;

        if (WinHttpSendRequest(hRequest, headers.c_str(), -1, (LPVOID)json.c_str(), (DWORD)json.length(), (DWORD)json.length(), 0)) {
            if (WinHttpReceiveResponse(hRequest, NULL)) {
                DWORD status=0,statusSize=sizeof(status);WinHttpQueryHeaders(hRequest,WINHTTP_QUERY_STATUS_CODE|WINHTTP_QUERY_FLAG_NUMBER,WINHTTP_HEADER_NAME_BY_INDEX,&status,&statusSize,WINHTTP_NO_HEADER_INDEX);
                if(status<200||status>=300){g_connected=false;WinHttpCloseHandle(hRequest);WinHttpCloseHandle(hConnect);WinHttpCloseHandle(hSession);return false;}
                g_connected = true;
                success = true;
                DWORD dwSize = 0;
                DWORD dwDownloaded = 0;
                do {
                    if (WinHttpQueryDataAvailable(hRequest, &dwSize)) {
                        if (dwSize == 0) break;
                        char* buf = new char[dwSize + 1];
                        if (WinHttpReadData(hRequest, buf, dwSize, &dwDownloaded)) {
                            buf[dwDownloaded] = '\0';
                            response += buf;
                        }
                        delete[] buf;
                    }
                } while (dwSize > 0);
            } else {
                g_connected = false;
            }
        } else {
            g_connected = false;
        }

        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return success;
    }

    void PostAsync(const char* endpoint, const std::string& json) {
        std::string ep(endpoint);
        std::string body = json;
        std::thread([ep, body]() {
            std::string resp;
            Post(ep.c_str(), body, resp);
        }).detach();
    }

    bool PostMultipart(const char* endpoint, const std::vector<MultipartField>& fields, std::string& response) {
        std::string boundary = "----NetClientBoundary" + std::to_string(GetTickCount64());
        std::vector<char> fullBody;

        for (const auto& field : fields) {
            std::stringstream part;
            part << "--" << boundary << "\r\n";
            if (field.filename.empty()) {
                part << "Content-Disposition: form-data; name=\"" << field.name << "\"\r\n\r\n";
                part << field.value << "\r\n";
            } else {
                part << "Content-Disposition: form-data; name=\"" << field.name << "\"; filename=\"" << field.filename << "\"\r\n";
                part << "Content-Type: " << (field.contentType.empty() ? "application/octet-stream" : field.contentType) << "\r\n\r\n";
            }

            std::string header = part.str();
            fullBody.insert(fullBody.end(), header.begin(), header.end());
            if (!field.filename.empty() && !field.data.empty()) {
                fullBody.insert(fullBody.end(), field.data.begin(), field.data.end());
            }
            std::string afterPart = "\r\n";
            fullBody.insert(fullBody.end(), afterPart.begin(), afterPart.end());
        }

        std::string closing = "--" + boundary + "--\r\n";
        fullBody.insert(fullBody.end(), closing.begin(), closing.end());

        HINTERNET hSession = WinHttpOpen(L"NetClient", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) return false;

        HINTERNET hConnect = WinHttpConnect(hSession, g_serverHost.c_str(), g_serverPort, 0);
        if (!hConnect) { WinHttpCloseHandle(hSession); return false; }

        std::string ep_str(endpoint);
        std::wstring wep(ep_str.begin(), ep_str.end());

        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", wep.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, g_serverTls ? WINHTTP_FLAG_SECURE : 0);
        if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false; }

        std::string headersStr = "Content-Type: multipart/form-data; boundary=" + boundary + "\r\n";
        VmpProtectedStringA protectedApiKey(APP_CLIENT_API_KEY);
        headersStr += "X-API-Key: " + std::string(protectedApiKey.get()) + "\r\n";
        headersStr += "X-Client-Type: app\r\n";
        std::wstring headers(headersStr.begin(), headersStr.end());

        bool success = false;
        if (WinHttpSendRequest(hRequest, headers.c_str(), -1, (LPVOID)fullBody.data(), (DWORD)fullBody.size(), (DWORD)fullBody.size(), 0)) {
            if (WinHttpReceiveResponse(hRequest, NULL)) {
                DWORD status = 0, statusSize = sizeof(status);
                WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                    WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusSize, WINHTTP_NO_HEADER_INDEX);
                if (status < 200 || status >= 300) {
                    g_connected = false;
                    WinHttpCloseHandle(hRequest);
                    WinHttpCloseHandle(hConnect);
                    WinHttpCloseHandle(hSession);
                    return false;
                }
                g_connected = true;
                success = true;
                DWORD dwSize = 0, dwDownloaded = 0;
                do {
                    if (WinHttpQueryDataAvailable(hRequest, &dwSize) && dwSize > 0) {
                        char* buf = new char[dwSize + 1];
                        if (WinHttpReadData(hRequest, buf, dwSize, &dwDownloaded)) {
                            buf[dwDownloaded] = '\0';
                            response += buf;
                        }
                        delete[] buf;
                    }
                } while (dwSize > 0);
            }
        }

        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return success;
    }

    void PostMultipartAsync(const char* endpoint, const std::vector<MultipartField>& fields) {
        std::string ep(endpoint);
        auto f = fields;
        std::thread([ep, f]() {
            std::string resp;
            PostMultipart(ep.c_str(), f, resp);
        }).detach();
    }

    bool DownloadFile(const char* endpoint, const std::string& savePath) {
        HINTERNET hSession = WinHttpOpen(L"NetClient", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) return false;

        HINTERNET hConnect = WinHttpConnect(hSession, g_serverHost.c_str(), g_serverPort, 0);
        if (!hConnect) { WinHttpCloseHandle(hSession); return false; }

        std::string ep_str(endpoint);
        std::wstring wep(ep_str.begin(), ep_str.end());

        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", wep.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, g_serverTls ? WINHTTP_FLAG_SECURE : 0);
        if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false; }

        VmpProtectedStringA protectedApiKey(APP_CLIENT_API_KEY);
        std::wstring apiHeader=L"X-API-Key: "; std::string apiKey=protectedApiKey.get();apiHeader.append(apiKey.begin(),apiKey.end());apiHeader+=L"\r\n";
        WinHttpAddRequestHeaders(hRequest,apiHeader.c_str(),-1,WINHTTP_ADDREQ_FLAG_ADD|WINHTTP_ADDREQ_FLAG_REPLACE);

        bool success = false;
        if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
            if (WinHttpReceiveResponse(hRequest, NULL)) {
                DWORD status=0,statusSize=sizeof(status);WinHttpQueryHeaders(hRequest,WINHTTP_QUERY_STATUS_CODE|WINHTTP_QUERY_FLAG_NUMBER,WINHTTP_HEADER_NAME_BY_INDEX,&status,&statusSize,WINHTTP_NO_HEADER_INDEX);
                if(status<200||status>=300){WinHttpCloseHandle(hRequest);WinHttpCloseHandle(hConnect);WinHttpCloseHandle(hSession);return false;}
                HANDLE hFile = CreateFileA(savePath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                if (hFile != INVALID_HANDLE_VALUE) {
                    success = true;
                    DWORD dwSize = 0, dwDownloaded = 0, dwWritten = 0;
                    do {
                        if (WinHttpQueryDataAvailable(hRequest, &dwSize) && dwSize > 0) {
                            char* buf = new char[dwSize];
                            if (WinHttpReadData(hRequest, buf, dwSize, &dwDownloaded)) {
                                WriteFile(hFile, buf, dwDownloaded, &dwWritten, NULL);
                            }
                            delete[] buf;
                        }
                    } while (dwSize > 0);
                    CloseHandle(hFile);
                }
            }
        }

        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return success;
    }

    std::string GetLocalIPAddress() {
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            return "Unknown";
        }

        std::string ipAddress = "Unknown";
        char hostname[256];
        if (gethostname(hostname, sizeof(hostname)) == SOCKET_ERROR) {
            WSACleanup();
            return ipAddress;
        }

        struct hostent* host = gethostbyname(hostname);
        if (host != NULL) {
            for (int i = 0; host->h_addr_list[i] != NULL; i++) {
                struct in_addr addr;
                memcpy(&addr, host->h_addr_list[i], sizeof(struct in_addr));
                std::string ip = inet_ntoa(addr);

                if (ip.find("192.168.") == 0 || ip.find("10.") == 0 ||
                    (ip.find("172.") == 0 && std::stoi(ip.substr(4, 2)) >= 16 &&
                        std::stoi(ip.substr(4, 2)) <= 31)) {
                    ipAddress = ip;
                    break;
                }
            }
        }

        WSACleanup();
        return ipAddress;
    }
}
