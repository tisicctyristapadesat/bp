#include "crash_handler.h"

#include "app_control.h"
#include "net_client.h"
#include "vmprotect_markers.h"

#include <windows.h>
#include <sstream>

namespace {

void WriteCrashLog(PEXCEPTION_RECORD record, PCONTEXT context) {
    char executablePath[MAX_PATH]{};
    if (!GetModuleFileNameA(nullptr, executablePath, MAX_PATH)) return;

    char logPath[MAX_PATH]{};
    lstrcpynA(logPath, executablePath, MAX_PATH);
    char* extension = nullptr;
    for (char* cursor = logPath; *cursor; ++cursor) {
        if (*cursor == '.') extension = cursor;
    }
    if (extension) lstrcpynA(extension, "_crash.log", static_cast<int>(MAX_PATH - (extension - logPath)));
    else lstrcatA(logPath, "_crash.log");

    HANDLE file = CreateFileA(logPath, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return;

    const auto moduleBase = reinterpret_cast<DWORD_PTR>(GetModuleHandleW(nullptr));
    const auto crashAddress = reinterpret_cast<DWORD_PTR>(record->ExceptionAddress);
#ifdef _WIN64
    const DWORD_PTR instructionPointer = context->Rip;
    const DWORD_PTR stackPointer = context->Rsp;
#else
    const DWORD_PTR instructionPointer = context->Eip;
    const DWORD_PTR stackPointer = context->Esp;
#endif

    char buffer[2048]{};
    int length = wsprintfA(buffer,
        "=== CRASH REPORT ===\r\n"
        "Exception Code: 0x%08X\r\n"
        "Exception Addr: 0x%p\r\n"
        "Module Base:    0x%p\r\n"
        "Crash Offset:   0x%IX\r\n"
        "Instruction:    0x%p\r\n"
        "Stack:          0x%p\r\n",
        record->ExceptionCode, record->ExceptionAddress, reinterpret_cast<void*>(moduleBase),
        crashAddress - moduleBase, reinterpret_cast<void*>(instructionPointer),
        reinterpret_cast<void*>(stackPointer));

    DWORD written = 0;
    WriteFile(file, buffer, length, &written, nullptr);

    MEMORY_BASIC_INFORMATION memory{};
    if (VirtualQuery(record->ExceptionAddress, &memory, sizeof(memory))) {
        char modulePath[MAX_PATH]{};
        const auto crashModule = static_cast<HMODULE>(memory.AllocationBase);
        if (crashModule && GetModuleFileNameA(crashModule, modulePath, MAX_PATH)) {
            const auto crashModuleBase = reinterpret_cast<DWORD_PTR>(crashModule);
            length = wsprintfA(buffer, "Crash Module:   %s\r\nCrash Mod Off:  0x%IX\r\n",
                modulePath, crashAddress - crashModuleBase);
            WriteFile(file, buffer, length, &written, nullptr);
        }
    }

    static constexpr char footer[] = "=== END CRASH REPORT ===\r\n";
    WriteFile(file, footer, sizeof(footer) - 1, &written, nullptr);
    CloseHandle(file);
}

std::string EscapeJsonCrash(const char* value) {
    std::string out;
    for (const char* p = value; p && *p; ++p) {
        switch (*p) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\r': out += "\\r"; break;
        case '\n': out += "\\n"; break;
        case '\t': out += "\\t"; break;
        default: out += *p; break;
        }
    }
    return out;
}

void SendCrashReport(PEXCEPTION_RECORD record, PCONTEXT context) {
    if (!AppControl::Flags().crashReporting) return;

    const auto moduleBase = reinterpret_cast<DWORD_PTR>(GetModuleHandleW(nullptr));
    const auto crashAddress = reinterpret_cast<DWORD_PTR>(record->ExceptionAddress);
#ifdef _WIN64
    const DWORD_PTR instructionPointer = context->Rip;
    const DWORD_PTR stackPointer = context->Rsp;
#else
    const DWORD_PTR instructionPointer = context->Eip;
    const DWORD_PTR stackPointer = context->Esp;
#endif

    char exceptionCode[32]{};
    char exceptionAddress[64]{};
    char instruction[64]{};
    char stack[64]{};
    char offset[64]{};
    wsprintfA(exceptionCode, "0x%08X", record->ExceptionCode);
    wsprintfA(exceptionAddress, "0x%p", record->ExceptionAddress);
    wsprintfA(instruction, "0x%p", reinterpret_cast<void*>(instructionPointer));
    wsprintfA(stack, "0x%p", reinterpret_cast<void*>(stackPointer));
    wsprintfA(offset, "0x%IX", crashAddress - moduleBase);

    char modulePath[MAX_PATH]{};
    MEMORY_BASIC_INFORMATION memory{};
    if (VirtualQuery(record->ExceptionAddress, &memory, sizeof(memory))) {
        const auto crashModule = static_cast<HMODULE>(memory.AllocationBase);
        if (crashModule) GetModuleFileNameA(crashModule, modulePath, MAX_PATH);
    }

    std::stringstream json;
    json << "{"
         << AppControl::CommonIdentityJsonFields() << ","
         << "\"exceptionCode\":\"" << exceptionCode << "\","
         << "\"exceptionAddress\":\"" << exceptionAddress << "\","
         << "\"instructionPointer\":\"" << instruction << "\","
         << "\"stackPointer\":\"" << stack << "\","
         << "\"crashOffset\":\"" << offset << "\","
         << "\"module\":\"" << EscapeJsonCrash(modulePath) << "\""
         << "}";

    VmpProtectedStringA endpoint("/api/crash/report");
    std::string response;
    NetClient::Post(endpoint.get(), json.str(), response);
}

LONG WINAPI CrashHandler(PEXCEPTION_POINTERS exception) {
    WriteCrashLog(exception->ExceptionRecord, exception->ContextRecord);
    SendCrashReport(exception->ExceptionRecord, exception->ContextRecord);
    MessageBoxA(nullptr,
        "The application crashed.\n\nA crash log was saved next to the executable.",
        "Crash Report", MB_OK | MB_ICONERROR);
    return EXCEPTION_EXECUTE_HANDLER;
}

struct CrashHandlerInstaller {
    CrashHandlerInstaller() { InstallCrashHandler(); }
} g_crashHandlerInstaller;

} // namespace

void InstallCrashHandler() {
    SetUnhandledExceptionFilter(CrashHandler);
}
