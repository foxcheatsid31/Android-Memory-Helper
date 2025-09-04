#ifndef MODULE_INFO_HPP
#define MODULE_INFO_HPP

/**
 * @file ModuleInfo.hpp
 * @author foxcheatsid@gmail.com
 * @version 1.0
 * @date 2023-2025
 * @copyright MIT License
 * 
 * @brief ModuleInfo class for Android 64-bit memory helper.
 * 
 * This class stores information about loaded modules in a process and provides
 * methods to access module details such as name, base address, size, and process ID.
 * Supports both internal and external processes with filtering capabilities.
 */

#include <string>
#include <vector>
#include <cstdint>
#include <sys/types.h>

namespace MemoryHelper {

/**
 * @class ModuleInfo
 * @brief Stores information about a loaded module in a process
 */
class ModuleInfo {
public:
    /**
     * @brief Constructor for ModuleInfo
     * @param name Name of the module
     * @param baseAddress Base address of the module in memory
     * @param size Size of the module in bytes
     * @param processId ID of the process that owns the module
     */
    ModuleInfo(const std::string& name, uint64_t baseAddress, size_t size, pid_t processId);
    
    /**
     * @brief Get the name of the module
     * @return Module name
     */
    const std::string& getName() const;
    
    /**
     * @brief Get the base address of the module
     * @return Base address of the module
     */
    uint64_t getBaseAddress() const;
    
    /**
     * @brief Get the size of the module
     * @return Size of the module in bytes
     */
    size_t getSize() const;
    
    /**
     * @brief Get the process ID that owns the module
     * @return Process ID
     */
    pid_t getProcessId() const;
    
    /**
     * @brief Check if the address is within this module
     * @param address Address to check
     * @return True if the address is within this module, false otherwise
     */
    bool containsAddress(uint64_t address) const;
    
private:
    std::string mName;
    uint64_t mBaseAddress;
    size_t mSize;
    pid_t mProcessId;
};

} // namespace MemoryHelper

#endif // MODULE_INFO_HPP