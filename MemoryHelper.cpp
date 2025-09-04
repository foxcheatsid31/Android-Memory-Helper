#include "MemoryHelper.hpp"
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <dlfcn.h>
#include <link.h>
#include <android/log.h>
#include <fstream>
#include <sstream>
#include <algorithm>

#define LOG_TAG "MemoryHelper"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace MemoryHelper {

// Forward declaration of MemoryHelperImpl
class MemoryHelper::MemoryHelperImpl {
public:
    explicit MemoryHelperImpl(pid_t targetPid);
    ~MemoryHelperImpl();
    
    // Memory reading functions
    bool readByte(uint64_t address, uint8_t* value);
    bool readWord(uint64_t address, uint16_t* value);
    bool readDword(uint64_t address, uint32_t* value);
    bool readQword(uint64_t address, uint64_t* value);
    bool readFloat(uint64_t address, float* value);
    bool readDouble(uint64_t address, double* value);
    std::string readString(uint64_t address, size_t maxLength);
    bool readMemory(uint64_t address, void* buffer, size_t size);
    std::vector<uint8_t> readBytes(uint64_t address, size_t size);
    
    // Memory writing functions
    bool writeByte(uint64_t address, uint8_t value);
    bool writeWord(uint64_t address, uint16_t value);
    bool writeDword(uint64_t address, uint32_t value);
    bool writeQword(uint64_t address, uint64_t value);
    bool writeFloat(uint64_t address, float value);
    bool writeDouble(uint64_t address, double value);
    bool writeString(uint64_t address, const std::string& str);
    bool writeMemory(uint64_t address, const void* buffer, size_t size);
    bool writeBytes(uint64_t address, const std::vector<uint8_t>& bytes);
    
    // Memory region functions
    std::vector<MemoryRegion> getMemoryRegions();
    std::vector<MemoryRegion> getMemoryRegions(const RegionFilter& filter);
    MemoryRegion findMemoryRegion(const std::string& name);
    MemoryRegion findMemoryRegion(uint64_t address);
    uint64_t allocateMemory(size_t size, const std::string& permissions);
    bool freeMemory(uint64_t address);
    bool protectMemory(uint64_t address, size_t size, const std::string& permissions);
    
    // Pattern scanning functions
    std::vector<uint64_t> findPattern(uint64_t startAddress, size_t size, 
                                     const std::vector<uint8_t>& pattern, 
                                     const std::vector<uint8_t>& mask);
    std::vector<uint64_t> findPatternInModule(const std::string& moduleName, 
                                             const std::vector<uint8_t>& pattern, 
                                             const std::vector<uint8_t>& mask);
    std::vector<uint64_t> findPatternInAllModules(const std::vector<uint8_t>& pattern, 
                                                  const std::vector<uint8_t>& mask);
    
    // Utility functions
    pid_t getTargetPid() const;
    bool isProcessRunning() const;
    bool isReadable(uint64_t address);
    bool isWritable(uint64_t address);
    bool isExecutable(uint64_t address);
    ModuleInfo getModuleForAddress(uint64_t address);
    uint64_t getModuleBase(const std::string& moduleName);
    size_t getModuleSize(const std::string& moduleName);
    
private:
    pid_t mTargetPid;
    int mMemoryFd;
    
    // Helper functions
    bool writeMemoryInternal(uint64_t address, const void* data, size_t size);
    bool readMemoryInternal(uint64_t address, void* buffer, size_t size);
    std::vector<MemoryRegion> readMemoryRegions();
    bool parsePermissions(const std::string& permStr, bool& readable, bool& writable, bool& executable);
    std::string formatPermissions(bool readable, bool writable, bool executable);
};

// MemoryHelper implementation
MemoryHelper::MemoryHelper(pid_t targetPid) : mImpl(std::make_unique<MemoryHelperImpl>(targetPid)) {
}

MemoryHelper::~MemoryHelper() {
}

// Memory reading functions
bool MemoryHelper::readByte(uint64_t address, uint8_t* value) {
    return mImpl->readByte(address, value);
}

bool MemoryHelper::readWord(uint64_t address, uint16_t* value) {
    return mImpl->readWord(address, value);
}

bool MemoryHelper::readDword(uint64_t address, uint32_t* value) {
    return mImpl->readDword(address, value);
}

bool MemoryHelper::readQword(uint64_t address, uint64_t* value) {
    return mImpl->readQword(address, value);
}

bool MemoryHelper::readFloat(uint64_t address, float* value) {
    return mImpl->readFloat(address, value);
}

bool MemoryHelper::readDouble(uint64_t address, double* value) {
    return mImpl->readDouble(address, value);
}

std::string MemoryHelper::readString(uint64_t address, size_t maxLength) {
    return mImpl->readString(address, maxLength);
}

bool MemoryHelper::readMemory(uint64_t address, void* buffer, size_t size) {
    return mImpl->readMemory(address, buffer, size);
}

std::vector<uint8_t> MemoryHelper::readBytes(uint64_t address, size_t size) {
    return mImpl->readBytes(address, size);
}

// Memory writing functions
bool MemoryHelper::writeByte(uint64_t address, uint8_t value) {
    return mImpl->writeByte(address, value);
}

bool MemoryHelper::writeWord(uint64_t address, uint16_t value) {
    return mImpl->writeWord(address, value);
}

bool MemoryHelper::writeDword(uint64_t address, uint32_t value) {
    return mImpl->writeDword(address, value);
}

bool MemoryHelper::writeQword(uint64_t address, uint64_t value) {
    return mImpl->writeQword(address, value);
}

bool MemoryHelper::writeFloat(uint64_t address, float value) {
    return mImpl->writeFloat(address, value);
}

bool MemoryHelper::writeDouble(uint64_t address, double value) {
    return mImpl->writeDouble(address, value);
}

bool MemoryHelper::writeString(uint64_t address, const std::string& str) {
    return mImpl->writeString(address, str);
}

bool MemoryHelper::writeMemory(uint64_t address, const void* buffer, size_t size) {
    return mImpl->writeMemory(address, buffer, size);
}

bool MemoryHelper::writeBytes(uint64_t address, const std::vector<uint8_t>& bytes) {
    return mImpl->writeBytes(address, bytes);
}

// Memory region functions
std::vector<MemoryHelper::MemoryRegion> MemoryHelper::getMemoryRegions() {
    return mImpl->getMemoryRegions();
}

std::vector<MemoryHelper::MemoryRegion> MemoryHelper::getMemoryRegions(const RegionFilter& filter) {
    return mImpl->getMemoryRegions(filter);
}

MemoryHelper::MemoryRegion MemoryHelper::findMemoryRegion(const std::string& name) {
    return mImpl->findMemoryRegion(name);
}

MemoryHelper::MemoryRegion MemoryHelper::findMemoryRegion(uint64_t address) {
    return mImpl->findMemoryRegion(address);
}

uint64_t MemoryHelper::allocateMemory(size_t size, const std::string& permissions) {
    return mImpl->allocateMemory(size, permissions);
}

bool MemoryHelper::freeMemory(uint64_t address) {
    return mImpl->freeMemory(address);
}

bool MemoryHelper::protectMemory(uint64_t address, size_t size, const std::string& permissions) {
    return mImpl->protectMemory(address, size, permissions);
}

// Pattern scanning functions
std::vector<uint64_t> MemoryHelper::findPattern(uint64_t startAddress, size_t size, 
                                                const std::vector<uint8_t>& pattern, 
                                                const std::vector<uint8_t>& mask) {
    return mImpl->findPattern(startAddress, size, pattern, mask);
}

std::vector<uint64_t> MemoryHelper::findPatternInModule(const std::string& moduleName, 
                                                        const std::vector<uint8_t>& pattern, 
                                                        const std::vector<uint8_t>& mask) {
    return mImpl->findPatternInModule(moduleName, pattern, mask);
}

std::vector<uint64_t> MemoryHelper::findPatternInAllModules(const std::vector<uint8_t>& pattern, 
                                                           const std::vector<uint8_t>& mask) {
    return mImpl->findPatternInAllModules(pattern, mask);
}

// Utility functions
pid_t MemoryHelper::getTargetPid() const {
    return mImpl->getTargetPid();
}

bool MemoryHelper::isProcessRunning() const {
    return mImpl->isProcessRunning();
}

bool MemoryHelper::isReadable(uint64_t address) {
    return mImpl->isReadable(address);
}

bool MemoryHelper::isWritable(uint64_t address) {
    return mImpl->isWritable(address);
}

bool MemoryHelper::isExecutable(uint64_t address) {
    return mImpl->isExecutable(address);
}

ModuleInfo MemoryHelper::getModuleForAddress(uint64_t address) {
    return mImpl->getModuleForAddress(address);
}

uint64_t MemoryHelper::getModuleBase(const std::string& moduleName) {
    return mImpl->getModuleBase(moduleName);
}

size_t MemoryHelper::getModuleSize(const std::string& moduleName) {
    return mImpl->getModuleSize(moduleName);
}

// MemoryHelperImpl implementation
MemoryHelper::MemoryHelperImpl::MemoryHelperImpl(pid_t targetPid) : mTargetPid(targetPid) {
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

MemoryHelper::MemoryHelperImpl::~MemoryHelperImpl() {
    if (mMemoryFd != -1) {
        close(mMemoryFd);
    }
}

// Memory reading functions
bool MemoryHelper::MemoryHelperImpl::readByte(uint64_t address, uint8_t* value) {
    return readMemoryInternal(address, value, sizeof(uint8_t));
}

bool MemoryHelper::MemoryHelperImpl::readWord(uint64_t address, uint16_t* value) {
    return readMemoryInternal(address, value, sizeof(uint16_t));
}

bool MemoryHelper::MemoryHelperImpl::readDword(uint64_t address, uint32_t* value) {
    return readMemoryInternal(address, value, sizeof(uint32_t));
}

bool MemoryHelper::MemoryHelperImpl::readQword(uint64_t address, uint64_t* value) {
    return readMemoryInternal(address, value, sizeof(uint64_t));
}

bool MemoryHelper::MemoryHelperImpl::readFloat(uint64_t address, float* value) {
    return readMemoryInternal(address, value, sizeof(float));
}

bool MemoryHelper::MemoryHelperImpl::readDouble(uint64_t address, double* value) {
    return readMemoryInternal(address, value, sizeof(double));
}

std::string MemoryHelper::MemoryHelperImpl::readString(uint64_t address, size_t maxLength) {
    std::vector<uint8_t> buffer(maxLength);
    if (!readMemoryInternal(address, buffer.data(), maxLength)) {
        return "";
    }
    
    // Find null terminator
    size_t length = 0;
    for (; length < maxLength; ++length) {
        if (buffer[length] == '\0') {
            break;
        }
    }
    
    return std::string(buffer.begin(), buffer.begin() + length);
}

bool MemoryHelper::MemoryHelperImpl::readMemory(uint64_t address, void* buffer, size_t size) {
    return readMemoryInternal(address, buffer, size);
}

std::vector<uint8_t> MemoryHelper::MemoryHelperImpl::readBytes(uint64_t address, size_t size) {
    std::vector<uint8_t> buffer(size);
    if (!readMemoryInternal(address, buffer.data(), size)) {
        return {};
    }
    return buffer;
}

// Memory writing functions
bool MemoryHelper::MemoryHelperImpl::writeByte(uint64_t address, uint8_t value) {
    return writeMemoryInternal(address, &value, sizeof(uint8_t));
}

bool MemoryHelper::MemoryHelperImpl::writeWord(uint64_t address, uint16_t value) {
    return writeMemoryInternal(address, &value, sizeof(uint16_t));
}

bool MemoryHelper::MemoryHelperImpl::writeDword(uint64_t address, uint32_t value) {
    return writeMemoryInternal(address, &value, sizeof(uint32_t));
}

bool MemoryHelper::MemoryHelperImpl::writeQword(uint64_t address, uint64_t value) {
    return writeMemoryInternal(address, &value, sizeof(uint64_t));
}

bool MemoryHelper::MemoryHelperImpl::writeFloat(uint64_t address, float value) {
    return writeMemoryInternal(address, &value, sizeof(float));
}

bool MemoryHelper::MemoryHelperImpl::writeDouble(uint64_t address, double value) {
    return writeMemoryInternal(address, &value, sizeof(double));
}

bool MemoryHelper::MemoryHelperImpl::writeString(uint64_t address, const std::string& str) {
    return writeMemoryInternal(address, str.data(), str.length() + 1); // +1 for null terminator
}

bool MemoryHelper::MemoryHelperImpl::writeMemory(uint64_t address, const void* buffer, size_t size) {
    return writeMemoryInternal(address, buffer, size);
}

bool MemoryHelper::MemoryHelperImpl::writeBytes(uint64_t address, const std::vector<uint8_t>& bytes) {
    return writeMemoryInternal(address, bytes.data(), bytes.size());
}

// Memory region functions
std::vector<MemoryHelper::MemoryRegion> MemoryHelper::MemoryHelperImpl::getMemoryRegions() {
    return getMemoryRegions([](const MemoryRegion&){ return true; });
}

std::vector<MemoryHelper::MemoryRegion> MemoryHelper::MemoryHelperImpl::getMemoryRegions(const RegionFilter& filter) {
    std::vector<MemoryRegion> regions = readMemoryRegions();
    regions.erase(std::remove_if(regions.begin(), regions.end(), 
        [&](const MemoryRegion& region) { return !filter(region); }), 
        regions.end());
    return regions;
}

MemoryHelper::MemoryRegion MemoryHelper::MemoryHelperImpl::findMemoryRegion(const std::string& name) {
    auto regions = getMemoryRegions([&](const MemoryRegion& region) {
        return region.name == name;
    });
    
    if (regions.empty()) {
        return MemoryRegion{};
    }
    return regions[0];
}

MemoryHelper::MemoryRegion MemoryHelper::MemoryHelperImpl::findMemoryRegion(uint64_t address) {
    auto regions = getMemoryRegions([&](const MemoryRegion& region) {
        return address >= region.start && address < region.end;
    });
    
    if (regions.empty()) {
        return MemoryRegion{};
    }
    return regions[0];
}

uint64_t MemoryHelper::MemoryHelperImpl::allocateMemory(size_t size, const std::string& permissions) {
    if (mTargetPid == 0) {
        // For current process, use mmap
        int prot = PROT_READ | PROT_WRITE;
        if (permissions.find('x') != std::string::npos) {
            prot |= PROT_EXEC;
        }
        
        void* addr = mmap(nullptr, size, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (addr == MAP_FAILED) {
            LOGE("Failed to allocate memory in current process");
            return 0;
        }
        
        return (uint64_t)addr;
    } else {
        // For other processes, allocate memory in our process and copy
        void* localAddr = mmap(nullptr, size, PROT_READ | PROT_WRITE, 
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (localAddr == MAP_FAILED) {
            LOGE("Failed to allocate memory in local process");
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
        LOGE("Memory allocation for other processes not fully implemented");
        return 0;
    }
}

bool MemoryHelper::MemoryHelperImpl::freeMemory(uint64_t address) {
    if (mTargetPid == 0) {
        // For current process, use munmap
        return munmap((void*)address, 4096) == 0; // 4096 is the page size
    } else {
        // For other processes, this would require complex operations
        LOGE("Memory freeing for other processes not fully implemented");
        return false;
    }
}

bool MemoryHelper::MemoryHelperImpl::protectMemory(uint64_t address, size_t size, const std::string& permissions) {
    if (mTargetPid == 0) {
        // For current process, use mprotect
        int prot = PROT_NONE;
        if (permissions.find('r') != std::string::npos) {
            prot |= PROT_READ;
        }
        if (permissions.find('w') != std::string::npos) {
            prot |= PROT_WRITE;
        }
        if (permissions.find('x') != std::string::npos) {
            prot |= PROT_EXEC;
        }
        
        return mprotect((void*)address, size, prot) == 0;
    } else {
        // For other processes, this would require complex operations
        LOGE("Memory protection for other processes not fully implemented");
        return false;
    }
}

// Pattern scanning functions
std::vector<uint64_t> MemoryHelper::MemoryHelperImpl::findPattern(uint64_t startAddress, size_t size, 
                                                                const std::vector<uint8_t>& pattern, 
                                                                const std::vector<uint8_t>& mask) {
    std::vector<uint64_t> results;
    
    if (pattern.size() != mask.size() || pattern.empty()) {
        LOGE("Invalid pattern or mask");
        return results;
    }
    
    // Read memory region
    std::vector<uint8_t> memory = readBytes(startAddress, size);
    if (memory.empty()) {
        LOGE("Failed to read memory for pattern scanning");
        return results;
    }
    
    // Search for pattern
    for (size_t i = 0; i <= memory.size() - pattern.size(); ++i) {
        bool match = true;
        for (size_t j = 0; j < pattern.size(); ++j) {
            if (mask[j] && memory[i + j] != pattern[j]) {
                match = false;
                break;
            }
        }
        
        if (match) {
            results.push_back(startAddress + i);
        }
    }
    
    return results;
}

std::vector<uint64_t> MemoryHelper::MemoryHelperImpl::findPatternInModule(const std::string& moduleName, 
                                                                        const std::vector<uint8_t>& pattern, 
                                                                        const std::vector<uint8_t>& mask) {
    // Get module base address and size
    uint64_t base = getModuleBase(moduleName);
    if (base == 0) {
        LOGE("Module not found: %s", moduleName.c_str());
        return {};
    }
    
    size_t size = getModuleSize(moduleName);
    if (size == 0) {
        LOGE("Failed to get module size for: %s", moduleName.c_str());
        return {};
    }
    
    return findPattern(base, size, pattern, mask);
}

std::vector<uint64_t> MemoryHelper::MemoryHelperImpl::findPatternInAllModules(const std::vector<uint8_t>& pattern, 
                                                                             const std::vector<uint8_t>& mask) {
    std::vector<uint64_t> allResults;
    
    // Get all modules
    std::vector<ModuleInfo> modules = ProcessParse::getModules(mTargetPid);
    
    for (const auto& module : modules) {
        std::vector<uint64_t> results = findPatternInModule(module.getName(), pattern, mask);
        allResults.insert(allResults.end(), results.begin(), results.end());
    }
    
    return allResults;
}

// Utility functions
pid_t MemoryHelper::MemoryHelperImpl::getTargetPid() const {
    return mTargetPid;
}

bool MemoryHelper::MemoryHelperImpl::isProcessRunning() const {
    return ProcessParse::isProcessRunning(mTargetPid);
}

bool MemoryHelper::MemoryHelperImpl::isReadable(uint64_t address) {
    MemoryRegion region = findMemoryRegion(address);
    return !region.name.empty() && region.isReadable;
}

bool MemoryHelper::MemoryHelperImpl::isWritable(uint64_t address) {
    MemoryRegion region = findMemoryRegion(address);
    return !region.name.empty() && region.isWritable;
}

bool MemoryHelper::MemoryHelperImpl::isExecutable(uint64_t address) {
    MemoryRegion region = findMemoryRegion(address);
    return !region.name.empty() && region.isExecutable;
}

ModuleInfo MemoryHelper::MemoryHelperImpl::getModuleForAddress(uint64_t address) {
    return ProcessParse::findModuleByAddress(mTargetPid, address);
}

uint64_t MemoryHelper::MemoryHelperImpl::getModuleBase(const std::string& moduleName) {
    return ProcessParse::getModuleBase(mTargetPid, moduleName);
}

size_t MemoryHelper::MemoryHelperImpl::getModuleSize(const std::string& moduleName) {
    auto modules = ProcessParse::getModules(mTargetPid, [&](const ModuleInfo& module) {
        return module.getName() == moduleName;
    });
    
    if (modules.empty()) {
        return 0;
    }
    return modules[0].getSize();
}

// Helper functions
bool MemoryHelper::MemoryHelperImpl::readMemoryInternal(uint64_t address, void* buffer, size_t size) {
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

bool MemoryHelper::MemoryHelperImpl::writeMemoryInternal(uint64_t address, const void* data, size_t size) {
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

std::vector<MemoryHelper::MemoryRegion> MemoryHelper::MemoryHelperImpl::readMemoryRegions() {
    std::vector<MemoryRegion> regions;
    
    std::string mapsPath = "/proc/" + std::to_string(mTargetPid) + "/maps";
    std::ifstream mapsFile(mapsPath);
    if (!mapsFile.is_open()) {
        LOGE("Failed to open %s", mapsPath.c_str());
        return regions;
    }
    
    std::string line;
    while (std::getline(mapsFile, line)) {
        std::istringstream iss(line);
        std::string addressRange, permissions, offset, dev, inode, pathname;
        
        iss >> addressRange >> permissions >> offset >> dev >> inode;
        std::getline(iss, pathname);
        
        // Trim whitespace from pathname
        pathname.erase(pathname.find_last_not_of(" \t\n\r\f\v") + 1);
        
        // Parse address range
        size_t dashPos = addressRange.find('-');
        if (dashPos != std::string::npos) {
            std::string startAddr = addressRange.substr(0, dashPos);
            std::string endAddr = addressRange.substr(dashPos + 1);
            
            uint64_t start = std::stoull(startAddr, nullptr, 16);
            uint64_t end = std::stoull(endAddr, nullptr, 16);
            
            // Parse permissions
            bool readable = false, writable = false, executable = false;
            parsePermissions(permissions, readable, writable, executable);
            
            // Create memory region
            MemoryRegion region;
            region.start = start;
            region.end = end;
            region.permissions = permissions;
            region.name = pathname;
            region.isReadable = readable;
            region.isWritable = writable;
            region.isExecutable = executable;
            
            regions.push_back(region);
        }
    }
    
    return regions;
}

bool MemoryHelper::MemoryHelperImpl::parsePermissions(const std::string& permStr, bool& readable, bool& writable, bool& executable) {
    readable = false;
    writable = false;
    executable = false;
    
    if (permStr.length() < 4) {
        return false;
    }
    
    // Parse each permission character
    for (char c : permStr) {
        if (c == 'r') {
            readable = true;
        } else if (c == 'w') {
            writable = true;
        } else if (c == 'x') {
            executable = true;
        }
    }
    
    return true;
}

std::string MemoryHelper::MemoryHelperImpl::formatPermissions(bool readable, bool writable, bool executable) {
    std::string perm;
    perm += readable ? 'r' : '-';
    perm += writable ? 'w' : '-';
    perm += executable ? 'x' : '-';
    return perm;
}

} // namespace MemoryHelper