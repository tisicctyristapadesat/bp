#ifndef HWID_H
#define HWID_H

#include <windows.h>
#include <string>

// HWID Collection Functions
std::string GetUserSID();
std::string GetGPU_HWID();
std::string GetCPU_HWID();
std::string GetDisk_HWID();
std::string GetPublicIP();
std::string GetUsername();
std::string GetComputerName();

// Server Communication
bool CheckBanStatus(bool& isBanned, std::string& message);
void SendLogToServer(const std::string& type, const std::string& message);

#endif // HWID_H
