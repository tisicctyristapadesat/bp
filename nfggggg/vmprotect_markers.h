#pragma once

// Release builds are marked for post-processing by VMProtect. Debug builds use
// no-op markers so they remain directly runnable without VMProtectSDK*.dll.
#if defined(ENABLE_VMPROTECT)
#include "VMProtectSDK.h"
#define VMP_BEGIN_MUTATION(name) VMProtectBeginMutation(name)
#define VMP_BEGIN_VIRTUALIZATION(name) VMProtectBeginVirtualization(name)
#define VMP_END() VMProtectEnd()
#else
#define VMP_BEGIN_MUTATION(name) ((void)0)
#define VMP_BEGIN_VIRTUALIZATION(name) ((void)0)
#define VMP_END() ((void)0)
#endif

#ifdef __cplusplus
class VmpProtectedStringA final {
public:
    explicit VmpProtectedStringA(const char* value)
#if defined(ENABLE_VMPROTECT)
        : value_(VMProtectDecryptStringA(value)) {}
#else
        : value_(value) {}
#endif
    ~VmpProtectedStringA() {
#if defined(ENABLE_VMPROTECT)
        if (value_) VMProtectFreeString(value_);
#endif
    }
    VmpProtectedStringA(const VmpProtectedStringA&) = delete;
    VmpProtectedStringA& operator=(const VmpProtectedStringA&) = delete;
    const char* get() const { return value_; }
private:
    const char* value_;
};

class VmpProtectedStringW final {
public:
    explicit VmpProtectedStringW(const wchar_t* value)
#if defined(ENABLE_VMPROTECT)
        : value_(VMProtectDecryptStringW(value)) {}
#else
        : value_(value) {}
#endif
    ~VmpProtectedStringW() {
#if defined(ENABLE_VMPROTECT)
        if (value_) VMProtectFreeString(value_);
#endif
    }
    VmpProtectedStringW(const VmpProtectedStringW&) = delete;
    VmpProtectedStringW& operator=(const VmpProtectedStringW&) = delete;
    const wchar_t* get() const { return value_; }
private:
    const wchar_t* value_;
};
#endif
