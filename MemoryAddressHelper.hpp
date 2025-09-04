#ifndef MEMORY_ADDRESS_HELPER_HPP
#define MEMORY_ADDRESS_HELPER_HPP

/**
 * @file MemoryAddressHelper.hpp
 * @author foxcheatsid@gmail.com
 * @version 1.0
 * @date 2023-2025
 * @copyright MIT License
 *
 * @brief Advanced memory helper for Android 64-bit
 * 
 * This header provides a unified interface for the memory helper, which includes:
 * - ModuleInfo: Stores information about loaded modules in a process
 * - ProcessParse: Handles process enumeration and information retrieval
 * - HookManager: Implements hooking mechanisms for functions in memory
 * - MemoryHelper: Provides memory reading/writing capabilities
 * 
 * The memory address helper supports both internal and external processes with filtering capabilities.
 */

#include "ModuleInfo.hpp"
#include "ProcessParse.hpp"
#include "HookManager.hpp"
#include "MemoryHelper.hpp"

namespace MemoryHelper {

/**
 * @class MemoryAddressHelper
 * @brief Unified interface for the memory address helper
 * 
 * This class provides a convenient interface to all the memory manipulation capabilities.
 * It combines the functionality of ModuleInfo, ProcessParse, HookManager, and MemoryHelper classes.
 */
class MemoryAddressHelper {
public:
    /**
     * @brief Constructor
     * @param targetPid Target process ID (0 for current process)
     */
    explicit MemoryAddressHelper(pid_t targetPid = 0);
    
    /**
     * @brief Destructor
     */
    ~MemoryAddressHelper();
    
    // ModuleInfo functionality
    /**
     * @brief Get a list of all loaded modules for the target process
     * @return Vector of ModuleInfo structures
     */
    std::vector<ModuleInfo> getModules();
    
    /**
     * @brief Get a list of loaded modules for the target process with custom filtering
     * @param filter Filter function to apply
     * @return Vector of ModuleInfo structures that match the filter
     */
    std::vector<ModuleInfo> getModules(const ProcessParse::ModuleFilter& filter);
    
    /**
     * @brief Find a module by name in the target process
     * @param moduleName Name of the module to find
     * @return ModuleInfo structure, or empty if not found
     */
    ModuleInfo findModuleByName(const std::string& moduleName);
    
    /**
     * @brief Find a module containing a specific address
     * @param address Address to search for
     * @return ModuleInfo structure, or empty if not found
     */
    ModuleInfo findModuleByAddress(uint64_t address);
    
    /**
     * @brief Get the base address of a module by name
     * @param moduleName Name of the module
     * @return Base address of the module, or 0 if not found
     */
    uint64_t getModuleBase(const std::string& moduleName);
    
    /**
     * @brief Get the size of a module by name
     * @param moduleName Name of the module
     * @return Size of the module, or 0 if not found
     */
    size_t getModuleSize(const std::string& moduleName);
    
    // ProcessParse functionality
    /**
     * @brief Get a list of all running processes
     * @return Vector of ProcessInfo structures
     */
    std::vector<ProcessParse::ProcessInfo> getProcesses();
    
    /**
     * @brief Get a list of running processes filtered by a custom filter function
     * @param filter Filter function to apply
     * @return Vector of ProcessInfo structures that match the filter
     */
    std::vector<ProcessParse::ProcessInfo> getProcesses(const ProcessParse::ProcessFilter& filter);
    
    /**
     * @brief Get process information by PID
     * @param pid Process ID to look up
     * @return ProcessInfo structure, or empty if not found
     */
    ProcessParse::ProcessInfo getProcessInfo(pid_t pid);
    
    /**
     * @brief Check if a process is running
     * @param pid Process ID to check
     * @return True if the process is running, false otherwise
     */
    bool isProcessRunning(pid_t pid);
    
    // HookManager functionality
    /**
     * @brief Install a hook at the specified address
     * @param address Address to hook
     * @param callback Callback function to execute when hooked
     * @param type Type of hook to install
     * @param context Context data to pass to the callback
     * @return HookInfo structure with hook details, or empty if failed
     */
    HookManager::HookInfo installHook(uint64_t address, HookManager::HookCallback callback, 
                                      HookManager::HookType type = HookManager::HookType::INLINE, 
                                      void* context = nullptr);
    
    /**
     * @brief Install a hook by function name in a module
     * @param moduleName Name of the module containing the function
     * @param functionName Name of the function to hook
     * @param callback Callback function to execute when hooked
     * @param type Type of hook to install
     * @param context Context data to pass to the callback
     * @return HookInfo structure with hook details, or empty if failed
     */
    HookManager::HookInfo installHook(const std::string& moduleName, const std::string& functionName, 
                                      HookManager::HookCallback callback, 
                                      HookManager::HookType type = HookManager::HookType::INLINE, 
                                      void* context = nullptr);
    
    /**
     * @brief Remove a hook
     * @param hookAddress Address where the hook is installed
     * @return True if the hook was successfully removed, false otherwise
     */
    bool removeHook(uint64_t hookAddress);
    
    /**
     * @brief Remove all hooks
     */
    void removeAllHooks();
    
    /**
     * @brief Enable a hook
     * @param hookAddress Address where the hook is installed
     * @return True if the hook was successfully enabled, false otherwise
     */
    bool enableHook(uint64_t hookAddress);
    
    /**
     * @brief Disable a hook
     * @param hookAddress Address where the hook is installed
     * @return True if the hook was successfully disabled, false otherwise
     */
    bool disableHook(uint64_t hookAddress);
    
    /**
     * @brief Get a list of all installed hooks
     * @return Vector of HookInfo structures
     */
    std::vector<HookManager::HookInfo> getHooks();
    
    /**
     * @brief Find a hook by the original address
     * @param originalAddress Original function address
     * @return HookInfo structure, or empty if not found
     */
    HookManager::HookInfo findHookByOriginalAddress(uint64_t originalAddress);
    
    /**
     * @brief Find a hook by the hook address
     * @param hookAddress Address where the hook is installed
     * @return HookInfo structure, or empty if not found
     */
    HookManager::HookInfo findHookByHookAddress(uint64_t hookAddress);
    
    /**
     * @brief Get the original function address for a hook
     * @param hookAddress Address where the hook is installed
     * @return Original function address, or 0 if not found
     */
    uint64_t getOriginalAddress(uint64_t hookAddress);
    
    /**
     * @brief Get the hook context
     * @param hookAddress Address where the hook is installed
     * @return Context data, or nullptr if not found
     */
    void* getHookContext(uint64_t hookAddress);
    
    /**
     * @brief Call the original function through a hook
     * @param hookAddress Address where the hook is installed
     * @param context Context data to pass to the original function
     * @return Return value from the original function
     */
    uint64_t callOriginal(uint64_t hookAddress, void* context = nullptr);
    
    /**
     * @brief Check if a hook is installed at the specified address
     * @param address Address to check
     * @return True if a hook is installed at the address, false otherwise
     */
    bool isHookInstalled(uint64_t address);
    
    // MemoryHelper functionality
    /**
     * @brief Read a byte from memory
     * @param address Address to read from
     * @param value Pointer to store the read value
     * @return True if the read was successful, false otherwise
     */
    bool readByte(uint64_t address, uint8_t* value);
    
    /**
     * @brief Read a word (16-bit) from memory
     * @param address Address to read from
     * @param value Pointer to store the read value
     * @return True if the read was successful, false otherwise
     */
    bool readWord(uint64_t address, uint16_t* value);
    
    /**
     * @brief Read a dword (32-bit) from memory
     * @param address Address to read from
     * @param value Pointer to store the read value
     * @return True if the read was successful, false otherwise
     */
    bool readDword(uint64_t address, uint32_t* value);
    
    /**
     * @brief Read a qword (64-bit) from memory
     * @param address Address to read from
     * @param value Pointer to store the read value
     * @return True if the read was successful, false otherwise
     */
    bool readQword(uint64_t address, uint64_t* value);
    
    /**
     * @brief Read a float from memory
     * @param address Address to read from
     * @param value Pointer to store the read value
     * @return True if the read was successful, false otherwise
     */
    bool readFloat(uint64_t address, float* value);
    
    /**
     * @brief Read a double from memory
     * @param address Address to read from
     * @param value Pointer to store the read value
     * @return True if the read was successful, false otherwise
     */
    bool readDouble(uint64_t address, double* value);
    
    /**
     * @brief Read a string from memory
     * @param address Address to read from
     * @param maxLength Maximum length of the string to read
     * @return The read string, or empty if failed
     */
    std::string readString(uint64_t address, size_t maxLength = 256);
    
    /**
     * @brief Read a block of memory
     * @param address Address to read from
     * @param buffer Buffer to store the read data
     * @param size Number of bytes to read
     * @return True if the read was successful, false otherwise
     */
    bool readMemory(uint64_t address, void* buffer, size_t size);
    
    /**
     * @brief Read a vector of bytes from memory
     * @param address Address to read from
     * @param size Number of bytes to read
     * @return Vector of bytes, empty if failed
     */
    std::vector<uint8_t> readBytes(uint64_t address, size_t size);
    
    /**
     * @brief Write a byte to memory
     * @param address Address to write to
     * @param value Value to write
     * @return True if the write was successful, false otherwise
     */
    bool writeByte(uint64_t address, uint8_t value);
    
    /**
     * @brief Write a word (16-bit) to memory
     * @param address Address to write to
     * @param value Value to write
     * @return True if the write was successful, false otherwise
     */
    bool writeWord(uint64_t address, uint16_t value);
    
    /**
     * @brief Write a dword (32-bit) to memory
     * @param address Address to write to
     * @param value Value to write
     * @return True if the write was successful, false otherwise
     */
    bool writeDword(uint64_t address, uint32_t value);
    
    /**
     * @brief Write a qword (64-bit) to memory
     * @param address Address to write to
     * @param value Value to write
     * @return True if the write was successful, false otherwise
     */
    bool writeQword(uint64_t address, uint64_t value);
    
    /**
     * @brief Write a float to memory
     * @param address Address to write to
     * @param value Value to write
     * @return True if the write was successful, false otherwise
     */
    bool writeFloat(uint64_t address, float value);
    
    /**
     * @brief Write a double to memory
     * @param address Address to write to
     * @param value Value to write
     * @return True if the write was successful, false otherwise
     */
    bool writeDouble(uint64_t address, double value);
    
    /**
     * @brief Write a string to memory
     * @param address Address to write to
     * @param str String to write
     * @return True if the write was successful, false otherwise
     */
    bool writeString(uint64_t address, const std::string& str);
    
    /**
     * @brief Write a block of memory
     * @param address Address to write to
     * @param buffer Buffer containing the data to write
     * @param size Number of bytes to write
     *  @return True if the write was successful, false otherwise
     */
    bool writeMemory(uint64_t address, const void* buffer, size_t size);
    
    /**
     * @brief Write a vector of bytes to memory
     * @param address Address to write to
     * @param bytes Vector of bytes to write
     * @return True if the write was successful, false otherwise
     */
    bool writeBytes(uint64_t address, const std::vector<uint8_t>& bytes);
    
    /**
     * @brief Get a list of all memory regions for the target process
     * @return Vector of MemoryRegion structures
     */
    std::vector<MemoryHelper::MemoryRegion> getMemoryRegions();
    
    /**
     * @brief Get a list of memory regions filtered by a custom filter function
     * @param filter Filter function to apply
     * @return Vector of MemoryRegion structures that match the filter
     */
    std::vector<MemoryHelper::MemoryRegion> getMemoryRegions(const MemoryHelper::RegionFilter& filter);
    
    /**
     * @brief Find a memory region by name
     * @param name Name of the region to find
     * @return MemoryRegion structure, or empty if not found
     */
    MemoryHelper::MemoryRegion findMemoryRegion(const std::string& name);
    
    /**
     * @brief Find a memory region containing a specific address
     * @param address Address to search for
     * @return MemoryRegion structure, or empty if not found
     */
    MemoryHelper::MemoryRegion findMemoryRegion(uint64_t address);
    
    /**
     * @brief Allocate memory in the target process
     * @param size Size of the memory block to allocate
     * @param permissions Memory permissions (e.g., "rwx")
     * @return Address of the allocated memory, or 0 if failed
     */
    uint64_t allocateMemory(size_t size, const std::string& permissions = "rwx");
    
    /**
     * @brief Free allocated memory in the target process
     * @param address Address of the memory to free
     * @return True if the memory was successfully freed, false otherwise
     */
    bool freeMemory(uint64_t address);
    
    /**
     * @brief Protect memory with specific permissions
     * @param address Address of the memory to protect
     * @param size Size of the memory block to protect
     * @param permissions New memory permissions (e.g., "rwx")
     * @return True if the memory protection was successfully changed, false otherwise
     */
    bool protectMemory(uint64_t address, size_t size, const std::string& permissions);
    
    /**
     * @brief Scan for a pattern in memory
     * @param startAddress Starting address to scan from
     * @param size Size of the memory region to scan
     * @param pattern Pattern to search for (supports wildcards with "?")
     * @param mask Pattern mask (1 = must match, 0 = wildcard)
     * @return Vector of addresses where the pattern was found
     */
    std::vector<uint64_t> findPattern(uint64_t startAddress, size_t size, 
                                      const std::vector<uint8_t>& pattern, 
                                      const std::vector<uint8_t>& mask);
    
    /**
     * @brief Scan for a pattern in a specific module
     * @param moduleName Name of the module to scan
     * @param pattern Pattern to search for (supports wildcards with "?")
     * @param mask Pattern mask (1 = must match, 0 = wildcard)
     * @return Vector of addresses where the pattern was found
     */
    std::vector<uint64_t> findPatternInModule(const std::string& moduleName, 
                                             const std::vector<uint8_t>& pattern, 
                                             const std::vector<uint8_t>& mask);
    
    /**
     * @brief Scan for a pattern in all modules
     * @param pattern Pattern to search for (supports wildcards with "?")
     * @param mask Pattern mask (1 = must match, 0 = wildcard)
     * @return Vector of addresses where the pattern was found
     */
    std::vector<uint64_t> findPatternInAllModules(const std::vector<uint8_t>& pattern, 
                                                  const std::vector<uint8_t>& mask);
    
    // Utility functions
    /**
     * @brief Get the target process ID
     * @return Process ID
     */
    pid_t getTargetPid() const;
    
    /**
     * @brief Check if the target process is running
     * @return True if the process is running, false otherwise
     */
    bool isProcessRunning() const;
    
    /**
     * @brief Check if an address is readable
     * @param address Address to check
     * @return True if the address is readable, false otherwise
     */
    bool isReadable(uint64_t address);
    
    /**
     * @brief Check if an address is writable
     * @param address Address to check
     * @return True if the address is writable, false otherwise
     */
    bool isWritable(uint64_t address);
    
    /**
     * @brief Check if an address is executable
     * @param address Address to check
     * @return True if the address is executable, false otherwise
     */
    bool isExecutable(uint64_t address);
    
    /**
     * @brief Get the module containing a specific address
     * @param address Address to search for
     * @return ModuleInfo structure, or empty if not found
     */
    ModuleInfo getModuleForAddress(uint64_t address);

private:
    pid_t mTargetPid;
    std::unique_ptr<ProcessParse> mProcessParse;
    std::unique_ptr<HookManager> mHookManager;
    std::unique_ptr<MemoryHelper> mMemoryHelper;
};

} // namespace MemoryHelper

#endif // MEMORY_ADDRESS_HELPER_HPP