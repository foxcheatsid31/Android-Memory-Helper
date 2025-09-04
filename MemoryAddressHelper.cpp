#include "MemoryAddressHelper.hpp"
#include <android/log.h>

#define LOG_TAG "MemoryHelper"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace MemoryHelper {

MemoryAddressHelper::MemoryAddressHelper(pid_t targetPid) 
    : mTargetPid(targetPid)
    , mProcessParse(std::make_unique<ProcessParse>())
    , mHookManager(std::make_unique<HookManager>(targetPid))
    , mMemoryHelper(std::make_unique<MemoryHelper>(targetPid))
{
}

MemoryAddressHelper::~MemoryAddressHelper() {
}

// ModuleInfo functionality
std::vector<ModuleInfo> MemoryAddressHelper::getModules() {
    return mProcessParse->getModules(mTargetPid);
}

std::vector<ModuleInfo> MemoryAddressHelper::getModules(const ProcessParse::ModuleFilter& filter) {
    return mProcessParse->getModules(mTargetPid, filter);
}

ModuleInfo MemoryAddressHelper::findModuleByName(const std::string& moduleName) {
    return mProcessParse->findModuleByName(mTargetPid, moduleName);
}

ModuleInfo MemoryAddressHelper::findModuleByAddress(uint64_t address) {
    return mProcessParse->findModuleByAddress(mTargetPid, address);
}

uint64_t MemoryAddressHelper::getModuleBase(const std::string& moduleName) {
    return mProcessParse->getModuleBase(mTargetPid, moduleName);
}

size_t MemoryAddressHelper::getModuleSize(const std::string& moduleName) {
    auto modules = mProcessParse->getModules(mTargetPid, [&](const ModuleInfo& module) {
        return module.getName() == moduleName;
    });
    
    if (modules.empty()) {
        return 0;
    }
    return modules[0].getSize();
}

// ProcessParse functionality
std::vector<ProcessParse::ProcessInfo> MemoryAddressHelper::getProcesses() {
    return mProcessParse->getProcesses();
}

std::vector<ProcessParse::ProcessInfo> MemoryAddressHelper::getProcesses(const ProcessParse::ProcessFilter& filter) {
    return mProcessParse->getProcesses(filter);
}

ProcessParse::ProcessInfo MemoryAddressHelper::getProcessInfo(pid_t pid) {
    return mProcessParse->getProcessInfo(pid);
}

bool MemoryAddressHelper::isProcessRunning(pid_t pid) {
    return mProcessParse->isProcessRunning(pid);
}

// HookManager functionality
HookManager::HookInfo MemoryAddressHelper::installHook(uint64_t address, HookManager::HookCallback callback, 
                                                      HookManager::HookType type, void* context) {
    return mHookManager->installHook(address, callback, type, context);
}

HookManager::HookInfo MemoryAddressHelper::installHook(const std::string& moduleName, const std::string& functionName, 
                                                      HookManager::HookCallback callback, 
                                                      HookManager::HookType type, void* context) {
    return mHookManager->installHook(moduleName, functionName, callback, type, context);
}

bool MemoryAddressHelper::removeHook(uint64_t hookAddress) {
    return mHookManager->removeHook(hookAddress);
}

void MemoryAddressHelper::removeAllHooks() {
    mHookManager->removeAllHooks();
}

bool MemoryAddressHelper::enableHook(uint64_t hookAddress) {
    return mHookManager->enableHook(hookAddress);
}

bool MemoryAddressHelper::disableHook(uint64_t hookAddress) {
    return mHookManager->disableHook(hookAddress);
}

std::vector<HookManager::HookInfo> MemoryAddressHelper::getHooks() {
    return mHookManager->getHooks();
}

HookManager::HookInfo MemoryAddressHelper::findHookByOriginalAddress(uint64_t originalAddress) {
    return mHookManager->findHookByOriginalAddress(originalAddress);
}

HookManager::HookInfo MemoryAddressHelper::findHookByHookAddress(uint64_t hookAddress) {
    return mHookManager->findHookByHookAddress(hookAddress);
}

uint64_t MemoryAddressHelper::getOriginalAddress(uint64_t hookAddress) {
    return mHookManager->getOriginalAddress(hookAddress);
}

void* MemoryAddressHelper::getHookContext(uint64_t hookAddress) {
    return mHookManager->getHookContext(hookAddress);
}

uint64_t MemoryAddressHelper::callOriginal(uint64_t hookAddress, void* context) {
    return mHookManager->callOriginal(hookAddress, context);
}

bool MemoryAddressHelper::isHookInstalled(uint64_t address) {
    return mHookManager->isHookInstalled(address);
}

// MemoryHelper functionality
bool MemoryAddressHelper::readByte(uint64_t address, uint8_t* value) {
    return mMemoryHelper->readByte(address, value);
}

bool MemoryAddressHelper::readWord(uint64_t address, uint16_t* value) {
    return mMemoryHelper->readWord(address, value);
}

bool MemoryAddressHelper::readDword(uint64_t address, uint32_t* value) {
    return mMemoryHelper->readDword(address, value);
}

bool MemoryAddressHelper::readQword(uint64_t address, uint64_t* value) {
    return mMemoryHelper->readQword(address, value);
}

bool MemoryAddressHelper::readFloat(uint64_t address, float* value) {
    return mMemoryHelper->readFloat(address, value);
}

bool MemoryAddressHelper::readDouble(uint64_t address, double* value) {
    return mMemoryHelper->readDouble(address, value);
}

std::string MemoryAddressHelper::readString(uint64_t address, size_t maxLength) {
    return mMemoryHelper->readString(address, maxLength);
}

bool MemoryAddressHelper::readMemory(uint64_t address, void* buffer, size_t size) {
    return mMemoryHelper->readMemory(address, buffer, size);
}

std::vector<uint8_t> MemoryAddressHelper::readBytes(uint64_t address, size_t size) {
    return mMemoryHelper->readBytes(address, size);
}

bool MemoryAddressHelper::writeByte(uint64_t address, uint8_t value) {
    return mMemoryHelper->writeByte(address, value);
}

bool MemoryAddressHelper::writeWord(uint64_t address, uint16_t value) {
    return mMemoryHelper->writeWord(address, value);
}

bool MemoryAddressHelper::writeDword(uint64_t address, uint32_t value) {
    return mMemoryHelper->writeDword(address, value);
}

bool MemoryAddressHelper::writeQword(uint64_t address, uint64_t value) {
    return mMemoryHelper->writeQword(address, value);
}

bool MemoryAddressHelper::writeFloat(uint64_t address, float value) {
    return mMemoryHelper->writeFloat(address, value);
}

bool MemoryAddressHelper::writeDouble(uint64_t address, double value) {
    return mMemoryHelper->writeDouble(address, value);
}

bool MemoryAddressHelper::writeString(uint64_t address, const std::string& str) {
    return mMemoryHelper->writeString(address, str);
}

bool MemoryAddressHelper::writeMemory(uint64_t address, const void* buffer, size_t size) {
    return mMemoryHelper->writeMemory(address, buffer, size);
}

bool MemoryAddressHelper::writeBytes(uint64_t address, const std::vector<uint8_t>& bytes) {
    return mMemoryHelper->writeBytes(address, bytes);
}

std::vector<MemoryHelper::MemoryRegion> MemoryAddressHelper::getMemoryRegions() {
    return mMemoryHelper->getMemoryRegions();
}

std::vector<MemoryHelper::MemoryRegion> MemoryAddressHelper::getMemoryRegions(const MemoryHelper::RegionFilter& filter) {
    return mMemoryHelper->getMemoryRegions(filter);
}

MemoryHelper::MemoryRegion MemoryAddressHelper::findMemoryRegion(const std::string& name) {
    return mMemoryHelper->findMemoryRegion(name);
}

MemoryHelper::MemoryRegion MemoryAddressHelper::findMemoryRegion(uint64_t address) {
    return mMemoryHelper->findMemoryRegion(address);
}

uint64_t MemoryAddressHelper::allocateMemory(size_t size, const std::string& permissions) {
    return mMemoryHelper->allocateMemory(size, permissions);
}

bool MemoryAddressHelper::freeMemory(uint64_t address) {
    return mMemoryHelper->freeMemory(address);
}

bool MemoryAddressHelper::protectMemory(uint64_t address, size_t size, const std::string& permissions) {
    return mMemoryHelper->protectMemory(address, size, permissions);
}

std::vector<uint64_t> MemoryAddressHelper::findPattern(uint64_t startAddress, size_t size, 
                                                     const std::vector<uint8_t>& pattern, 
                                                     const std::vector<uint8_t>& mask) {
    return mMemoryHelper->findPattern(startAddress, size, pattern, mask);
}

std::vector<uint64_t> MemoryAddressHelper::findPatternInModule(const std::string& moduleName, 
                                                            const std::vector<uint8_t>& pattern, 
                                                            const std::vector<uint8_t>& mask) {
    return mMemoryHelper->findPatternInModule(moduleName, pattern, mask);
}

std::vector<uint64_t> MemoryAddressHelper::findPatternInAllModules(const std::vector<uint8_t>& pattern, 
                                                               const std::vector<uint8_t>& mask) {
    return mMemoryHelper->findPatternInAllModules(pattern, mask);
}

// Utility functions
pid_t MemoryAddressHelper::getTargetPid() const {
    return mTargetPid;
}

bool MemoryAddressHelper::isProcessRunning() const {
    return mMemoryHelper->isProcessRunning();
}

bool MemoryAddressHelper::isReadable(uint64_t address) {
    return mMemoryHelper->isReadable(address);
}

bool MemoryAddressHelper::isWritable(uint64_t address) {
    return mMemoryHelper->isWritable(address);
}

bool MemoryAddressHelper::isExecutable(uint64_t address) {
    return mMemoryHelper->isExecutable(address);
}

ModuleInfo MemoryAddressHelper::getModuleForAddress(uint64_t address) {
    return mMemoryHelper->getModuleForAddress(address);
}

} // namespace MemoryHelper