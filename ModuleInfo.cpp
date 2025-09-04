#include "ModuleInfo.hpp"
#include <algorithm>

namespace MemoryHelper {

ModuleInfo::ModuleInfo(const std::string& name, uint64_t baseAddress, size_t size, pid_t processId)
    : mName(name)
    , mBaseAddress(baseAddress)
    , mSize(size)
    , mProcessId(processId)
{
}

const std::string& ModuleInfo::getName() const {
    return mName;
}

uint64_t ModuleInfo::getBaseAddress() const {
    return mBaseAddress;
}

size_t ModuleInfo::getSize() const {
    return mSize;
}

pid_t ModuleInfo::getProcessId() const {
    return mProcessId;
}

bool ModuleInfo::containsAddress(uint64_t address) const {
    return address >= mBaseAddress && address < (mBaseAddress + mSize);
}

} // namespace MemoryHelper