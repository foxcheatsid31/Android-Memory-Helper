#include "HookManager.hpp"
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <dlfcn.h>
#include <link.h>
#include <android/log.h>

#define LOG_TAG "MemoryHelper"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace MemoryHelper {

// Forward declaration of HookImpl
class HookManager::HookImpl {
public:
    struct HookEntry {
        uint64_t originalAddress;
        uint64_t hookAddress;
        HookType type;
        std::string moduleName;
        bool isActive;
        HookCallback callback;
        void* context;
        std::vector<uint8_t> originalBytes;
        uint64_t trampolineAddress;
    };
    
    explicit HookImpl(pid_t targetPid);
    ~HookImpl();
    
    HookInfo installHook(uint64_t address, HookCallback callback, HookType type, void* context);
    HookInfo installHook(const std::string& moduleName, const std::string& functionName, 
                         HookCallback callback, HookType type, void* context);
    bool removeHook(uint64_t hookAddress);
    void removeAllHooks();
    bool enableHook(uint64_t hookAddress);
    bool disableHook(uint64_t hookAddress);
    std::vector<HookInfo> getHooks() const;
    HookInfo findHookByOriginalAddress(uint64_t originalAddress) const;
    HookInfo findHookByHookAddress(uint64_t hookAddress) const;
    uint64_t getOriginalAddress(uint64_t hookAddress) const;
    void* getHookContext(uint64_t hookAddress) const;
    uint64_t callOriginal(uint64_t hookAddress, void* context);
    bool isHookInstalled(uint64_t address) const;
    pid_t getTargetPid() const;
    
private:
    pid_t mTargetPid;
    std::vector<HookEntry> mHooks;
    int mMemoryFd;
    
    // Helper functions
    uint64_t findModuleBase(const std::string& moduleName);
    uint64_t findFunctionAddress(const std::string& moduleName, const std::string& functionName);
    uint64_t createTrampoline(uint64_t address);
    bool writeMemory(uint64_t address, const void* data, size_t size);
    bool readMemory(uint64_t address, void* buffer, size_t size);
    uint64_t allocateMemory(size_t size);
    bool freeMemory(uint64_t address);
    
    // Hook implementation functions
    bool installInlineHook(HookEntry& entry);
    bool installDetourHook(HookEntry& entry);
    bool installBreakpointHook(HookEntry& entry);
    bool removeInlineHook(HookEntry& entry);
    bool removeDetourHook(HookEntry& entry);
    bool removeBreakpointHook(HookEntry& entry);
};

// HookManager implementation
HookManager::HookManager(pid_t targetPid) : mImpl(std::make_unique<HookImpl>(targetPid)) {
}

HookManager::~HookManager() {
}

HookManager::HookInfo HookManager::installHook(uint64_t address, HookCallback callback, HookType type, void* context) {
    return mImpl->installHook(address, callback, type, context);
}

HookManager::HookInfo HookManager::installHook(const std::string& moduleName, const std::string& functionName, 
                                               HookCallback callback, HookType type, void* context) {
    return mImpl->installHook(moduleName, functionName, callback, type, context);
}

bool HookManager::removeHook(uint64_t hookAddress) {
    return mImpl->removeHook(hookAddress);
}

void HookManager::removeAllHooks() {
    mImpl->removeAllHooks();
}

bool HookManager::enableHook(uint64_t hookAddress) {
    return mImpl->enableHook(hookAddress);
}

bool HookManager::disableHook(uint64_t hookAddress) {
    return mImpl->disableHook(hookAddress);
}

std::vector<HookManager::HookInfo> HookManager::getHooks() const {
    return mImpl->getHooks();
}

HookManager::HookInfo HookManager::findHookByOriginalAddress(uint64_t originalAddress) const {
    return mImpl->findHookByOriginalAddress(originalAddress);
}

HookManager::HookInfo HookManager::findHookByHookAddress(uint64_t hookAddress) const {
    return mImpl->findHookByHookAddress(hookAddress);
}

uint64_t HookManager::getOriginalAddress(uint64_t hookAddress) const {
    return mImpl->getOriginalAddress(hookAddress);
}

void* HookManager::getHookContext(uint64_t hookAddress) const {
    return mImpl->getHookContext(hookAddress);
}

uint64_t HookManager::callOriginal(uint64_t hookAddress, void* context) {
    return mImpl->callOriginal(hookAddress, context);
}

bool HookManager::isHookInstalled(uint64_t address) const {
    return mImpl->isHookInstalled(address);
}

pid_t HookManager::getTargetPid() const {
    return mImpl->getTargetPid();
}

// HookImpl implementation
HookManager::HookImpl::HookImpl(pid_t targetPid) : mTargetPid(targetPid) {
    // Open /proc/<pid>/mem for memory access
    if (mTargetPid != 0) {
        std::string memPath = "/proc/" + std::to_string(mTargetPid) + "/mem";
        mMemoryFd = open(memPath.c_str(), O_RDWR);
        if (mMemoryFd == -1) {
            LOGE("Failed to open %s", memPath.c_str());
        }
    } else {
        // For current process, we can use direct memory access
        mMemoryFd = -1;
    }
}

HookManager::HookImpl::~HookImpl() {
    removeAllHooks();
    if (mMemoryFd != -1) {
        close(mMemoryFd);
    }
}

HookManager::HookInfo HookManager::HookImpl::installHook(uint64_t address, HookCallback callback, HookType type, void* context) {
    HookInfo info = {};
    
    // Check if hook is already installed at this address
    if (isHookInstalled(address)) {
        LOGE("Hook already installed at address 0x%lx", address);
        return info;
    }
    
    HookEntry entry;
    entry.originalAddress = address;
    entry.hookAddress = address;
    entry.type = type;
    entry.isActive = false;
    entry.callback = callback;
    entry.context = context;
    entry.trampolineAddress = 0;
    
    // Read original bytes
    entry.originalBytes.resize(16); // Read 16 bytes for safety
    if (!readMemory(address, entry.originalBytes.data(), entry.originalBytes.size())) {
        LOGE("Failed to read memory at address 0x%lx", address);
        return info;
    }
    
    // Install the hook based on type
    bool success = false;
    switch (type) {
        case HookType::INLINE:
            success = installInlineHook(entry);
            break;
        case HookType::DETOUR:
            success = installDetourHook(entry);
            break;
        case HookType::BREAKPOINT:
            success = installBreakpointHook(entry);
            break;
    }
    
    if (success) {
        entry.isActive = true;
        mHooks.push_back(entry);
        
        // Fill HookInfo structure
        info.originalAddress = entry.originalAddress;
        info.hookAddress = entry.hookAddress;
        info.type = entry.type;
        info.moduleName = entry.moduleName;
        info.isActive = entry.isActive;
    }
    
    return info;
}

HookManager::HookInfo HookManager::HookImpl::installHook(const std::string& moduleName, const std::string& functionName, 
                                                          HookCallback callback, HookType type, void* context) {
    // Find function address in module
    uint64_t address = findFunctionAddress(moduleName, functionName);
    if (address == 0) {
        LOGE("Failed to find function %s in module %s", functionName.c_str(), moduleName.c_str());
        return HookInfo{};
    }
    
    return installHook(address, callback, type, context);
}

bool HookManager::HookImpl::removeHook(uint64_t hookAddress) {
    auto it = std::find_if(mHooks.begin(), mHooks.end(), [hookAddress](const HookEntry& entry) {
        return entry.hookAddress == hookAddress;
    });
    
    if (it == mHooks.end()) {
        return false;
    }
    
    // Remove the hook based on type
    bool success = false;
    switch (it->type) {
        case HookType::INLINE:
            success = removeInlineHook(*it);
            break;
        case HookType::DETOUR:
            success = removeDetourHook(*it);
            break;
        case HookType::BREAKPOINT:
            success = removeBreakpointHook(*it);
            break;
    }
    
    if (success) {
        mHooks.erase(it);
    }
    
    return success;
}

void HookManager::HookImpl::removeAllHooks() {
    while (!mHooks.empty()) {
        removeHook(mHooks.back().hookAddress);
    }
}

bool HookManager::HookImpl::enableHook(uint64_t hookAddress) {
    auto it = std::find_if(mHooks.begin(), mHooks.end(), [hookAddress](const HookEntry& entry) {
        return entry.hookAddress == hookAddress;
    });
    
    if (it == mHooks.end()) {
        return false;
    }
    
    // Enable the hook based on type
    bool success = false;
    switch (it->type) {
        case HookType::INLINE:
            success = installInlineHook(*it);
            break;
        case HookType::DETOUR:
            success = installDetourHook(*it);
            break;
        case HookType::BREAKPOINT:
            success = installBreakpointHook(*it);
            break;
    }
    
    if (success) {
        it->isActive = true;
    }
    
    return success;
}

bool HookManager::HookImpl::disableHook(uint64_t hookAddress) {
    auto it = std::find_if(mHooks.begin(), mHooks.end(), [hookAddress](const HookEntry& entry) {
        return entry.hookAddress == hookAddress;
    });
    
    if (it == mHooks.end()) {
        return false;
    }
    
    // Disable the hook based on type
    bool success = false;
    switch (it->type) {
        case HookType::INLINE:
            success = removeInlineHook(*it);
            break;
        case HookType::DETOUR:
            success = removeDetourHook(*it);
            break;
        case HookType::BREAKPOINT:
            success = removeBreakpointHook(*it);
            break;
    }
    
    if (success) {
        it->isActive = false;
    }
    
    return success;
}

std::vector<HookManager::HookInfo> HookManager::HookImpl::getHooks() const {
    std::vector<HookInfo> result;
    for (const auto& entry : mHooks) {
        HookInfo info;
        info.originalAddress = entry.originalAddress;
        info.hookAddress = entry.hookAddress;
        info.type = entry.type;
        info.moduleName = entry.moduleName;
        info.isActive = entry.isActive;
        result.push_back(info);
    }
    return result;
}

HookManager::HookInfo HookManager::HookImpl::findHookByOriginalAddress(uint64_t originalAddress) const {
    auto it = std::find_if(mHooks.begin(), mHooks.end(), [originalAddress](const HookEntry& entry) {
        return entry.originalAddress == originalAddress;
    });
    
    if (it == mHooks.end()) {
        return HookInfo{};
    }
    
    HookInfo info;
    info.originalAddress = it->originalAddress;
    info.hookAddress = it->hookAddress;
    info.type = it->type;
    info.moduleName = it->moduleName;
    info.isActive = it->isActive;
    return info;
}

HookManager::HookInfo HookManager::HookImpl::findHookByHookAddress(uint64_t hookAddress) const {
    auto it = std::find_if(mHooks.begin(), mHooks.end(), [hookAddress](const HookEntry& entry) {
        return entry.hookAddress == hookAddress;
    });
    
    if (it == mHooks.end()) {
        return HookInfo{};
    }
    
    HookInfo info;
    info.originalAddress = it->originalAddress;
    info.hookAddress = it->hookAddress;
    info.type = it->type;
    info.moduleName = it->moduleName;
    info.isActive = it->isActive;
    return info;
}

uint64_t HookManager::HookImpl::getOriginalAddress(uint64_t hookAddress) const {
    auto it = std::find_if(mHooks.begin(), mHooks.end(), [hookAddress](const HookEntry& entry) {
        return entry.hookAddress == hookAddress;
    });
    
    if (it == mHooks.end()) {
        return 0;
    }
    
    return it->originalAddress;
}

void* HookManager::HookImpl::getHookContext(uint64_t hookAddress) const {
    auto it = std::find_if(mHooks.begin(), mHooks.end(), [hookAddress](const HookEntry& entry) {
        return entry.hookAddress == hookAddress;
    });
    
    if (it == mHooks.end()) {
        return nullptr;
    }
    
    return it->context;
}

uint64_t HookManager::HookImpl::callOriginal(uint64_t hookAddress, void* context) {
    auto it = std::find_if(mHooks.begin(), mHooks.end(), [hookAddress](const HookEntry& entry) {
        return entry.hookAddress == hookAddress;
    });
    
    if (it == mHooks.end()) {
        return 0;
    }
    
    // Temporarily disable the hook
    bool wasActive = it->isActive;
    if (wasActive) {
        disableHook(hookAddress);
    }
    
    // Create a copy of the original bytes to restore
    std::vector<uint8_t> originalBytes = it->originalBytes;
    
    // Restore original bytes
    writeMemory(it->originalAddress, originalBytes.data(), originalBytes.size());
    
    // Execute the original function (simplified - in reality this would be more complex)
    // This is a placeholder for actual function execution
    uint64_t result = 0;
    
    // Restore hook
    if (wasActive) {
        enableHook(hookAddress);
    }
    
    return result;
}

bool HookManager::HookImpl::isHookInstalled(uint64_t address) const {
    return std::any_of(mHooks.begin(), mHooks.end(), [address](const HookEntry& entry) {
        return entry.originalAddress == address || entry.hookAddress == address;
    });
}

pid_t HookManager::HookImpl::getTargetPid() const {
    return mTargetPid;
}

// Helper functions
uint64_t HookManager::HookImpl::findModuleBase(const std::string& moduleName) {
    // This is a simplified implementation
    // In a real implementation, you would parse /proc/<pid>/maps or use dladdr
    
    // For current process
    if (mTargetPid == 0) {
        Dl_info info;
        if (dladdr((const void*)0x1000, &info) != 0) { // Try a common address
            // Check if the module name matches
            std::string dlName = info.dli_fname ? info.dli_fname : "";
            if (dlName.find(moduleName) != std::string::npos) {
                return (uint64_t)info.dli_fbase;
            }
        }
    }
    
    // For other processes, this would require parsing /proc/<pid>/maps
    // This is a placeholder implementation
    return 0;
}

uint64_t HookManager::HookImpl::findFunctionAddress(const std::string& moduleName, const std::string& functionName) {
    // This is a simplified implementation
    // In a real implementation, you would use dlsym for current process
    // or parse debug symbols for other processes
    
    // For current process
    if (mTargetPid == 0) {
        void* symbol = dlsym(RTLD_DEFAULT, functionName.c_str());
        if (symbol) {
            return (uint64_t)symbol;
        }
    }
    
    // For other processes, this would require symbol resolution
    // This is a placeholder implementation
    return 0;
}

uint64_t HookManager::HookImpl::createTrampoline(uint64_t address) {
    // Allocate memory for trampoline
    size_t trampolineSize = 32; // Size of trampoline code
    uint64_t trampolineAddress = allocateMemory(trampolineSize);
    if (trampolineAddress == 0) {
        LOGE("Failed to allocate memory for trampoline");
        return 0;
    }
    
    // Copy original bytes to trampoline
    if (!readMemory(address, (void*)trampolineAddress, 16)) {
        LOGE("Failed to read original bytes for trampoline");
        freeMemory(trampolineAddress);
        return 0;
    }
    
    // Add jump back to original function
    uint8_t jumpBack[] = {
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // MOV RAX, <address>
        0xFF, 0xE0 // JMP RAX
    };
    
    // Write the jump back address (original address + bytes copied)
    uint64_t jumpTarget = address + 16;
    memcpy(&jumpBack[2], &jumpTarget, sizeof(jumpTarget));
    
    // Write jump back to trampoline
    if (!writeMemory(trampolineAddress + 16, jumpBack, sizeof(jumpBack))) {
        LOGE("Failed to write jump back to trampoline");
        freeMemory(trampolineAddress);
        return 0;
    }
    
    return trampolineAddress;
}

bool HookManager::HookImpl::writeMemory(uint64_t address, const void* data, size_t size) {
    if (mTargetPid == 0) {
        // For current process, use direct memory access
        void* target = (void*)address;
        memcpy(target, data, size);
        return true;
    } else {
        // For other processes, use /proc/<pid>/mem
        if (mMemoryFd == -1) {
            LOGE("Memory file descriptor not open");
            return false;
        }
        
        off64_t offset = address;
        ssize_t written = pwrite64(mMemoryFd, data, size, offset);
        return written == size;
    }
}

bool HookManager::HookImpl::readMemory(uint64_t address, void* buffer, size_t size) {
    if (mTargetPid == 0) {
        // For current process, use direct memory access
        void* source = (void*)address;
        memcpy(buffer, source, size);
        return true;
    } else {
        // For other processes, use /proc/<pid>/mem
        if (mMemoryFd == -1) {
            LOGE("Memory file descriptor not open");
            return false;
        }
        
        off64_t offset = address;
        ssize_t read = pread64(mMemoryFd, buffer, size, offset);
        return read == size;
    }
}

uint64_t HookManager::HookImpl::allocateMemory(size_t size) {
    if (mTargetPid == 0) {
        // For current process, use mmap
        void* addr = mmap(nullptr, size, PROT_READ | PROT_WRITE | PROT_EXEC, 
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        return (addr == MAP_FAILED) ? 0 : (uint64_t)addr;
    } else {
        // For other processes, allocate memory in our process and copy
        void* localAddr = mmap(nullptr, size, PROT_READ | PROT_WRITE, 
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (localAddr == MAP_FAILED) {
            return 0;
        }
        
        // Find a suitable address in the target process
        // This is a simplified implementation - in reality, you would need to find
        // a suitable address that doesn't conflict with existing memory
        uint64_t targetAddr = 0x7f0000000000ULL; // Example address
        
        // Map the same address in the target process
        // This requires ptrace and other complex operations
        // For now, return 0 to indicate failure
        munmap(localAddr, size);
        return 0;
    }
}

bool HookManager::HookImpl::freeMemory(uint64_t address) {
    if (mTargetPid == 0) {
        // For current process, use munmap
        return munmap((void*)address, 4096) == 0; // 4096 is the page size
    } else {
        // For other processes, this would require complex operations
        return false;
    }
}

// Hook implementation functions
bool HookManager::HookImpl::installInlineHook(HookEntry& entry) {
    // Create trampoline
    entry.trampolineAddress = createTrampoline(entry.originalAddress);
    if (entry.trampolineAddress == 0) {
        return false;
    }
    
    // Create jump to trampoline
    uint8_t jumpToTrampoline[] = {
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // MOV RAX, <trampoline address>
        0xFF, 0xE0 // JMP RAX
    };
    
    // Write the trampoline address
    memcpy(&jumpToTrampoline[2], &entry.trampolineAddress, sizeof(entry.trampolineAddress));
    
    // Write jump to trampoline
    if (!writeMemory(entry.originalAddress, jumpToTrampoline, sizeof(jumpToTrampoline))) {
        LOGE("Failed to write jump to trampoline");
        freeMemory(entry.trampolineAddress);
        return false;
    }
    
    return true;
}

bool HookManager::HookImpl::installDetourHook(HookEntry& entry) {
    // Create trampoline
    entry.trampolineAddress = createTrampoline(entry.originalAddress);
    if (entry.trampolineAddress == 0) {
        return false;
    }
    
    // Create jump to our callback function
    // This is a simplified implementation - in reality, you would need to create
    // a proper function that can call the callback with the right context
    uint8_t jumpToCallback[] = {
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // MOV RAX, <callback address>
        0xFF, 0xE0 // JMP RAX
    };
    
    // Write the callback address
    memcpy(&jumpToCallback[2], &entry.callback, sizeof(entry.callback));
    
    // Write jump to callback
    if (!writeMemory(entry.originalAddress, jumpToCallback, sizeof(jumpToCallback))) {
        LOGE("Failed to write jump to callback");
        freeMemory(entry.trampolineAddress);
        return false;
    }
    
    return true;
}

bool HookManager::HookImpl::installBreakpointHook(HookEntry& entry) {
    // Write INT3 (0xCC) at the original address
    uint8_t breakpoint = 0xCC;
    if (!writeMemory(entry.originalAddress, &breakpoint, sizeof(breakpoint))) {
        LOGE("Failed to write breakpoint");
        return false;
    }
    
    return true;
}

bool HookManager::HookImpl::removeInlineHook(HookEntry& entry) {
    // Restore original bytes
    if (!writeMemory(entry.originalAddress, entry.originalBytes.data(), entry.originalBytes.size())) {
        LOGE("Failed to restore original bytes");
        return false;
    }
    
    // Free trampoline memory
    if (entry.trampolineAddress != 0) {
        freeMemory(entry.trampolineAddress);
        entry.trampolineAddress = 0;
    }
    
    return true;
}

bool HookManager::HookImpl::removeDetourHook(HookEntry& entry) {
    // Restore original bytes
    if (!writeMemory(entry.originalAddress, entry.originalBytes.data(), entry.originalBytes.size())) {
        LOGE("Failed to restore original bytes");
        return false;
    }
    
    // Free trampoline memory
    if (entry.trampolineAddress != 0) {
        freeMemory(entry.trampolineAddress);
        entry.trampolineAddress = 0;
    }
    
    return true;
}

bool HookManager::HookImpl::removeBreakpointHook(HookEntry& entry) {
    // Restore original bytes
    if (!writeMemory(entry.originalAddress, entry.originalBytes.data(), entry.originalBytes.size())) {
        LOGE("Failed to restore original bytes");
        return false;
    }
    
    return true;
}

} // namespace MemoryHelper