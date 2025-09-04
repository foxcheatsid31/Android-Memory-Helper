#ifndef MEMORY_HELPER_HPP
#define MEMORY_HELPER_HPP

/**
 * @file MemoryHelper.hpp
 * @author foxcheatsid@gmail.com
 * @version 1.0
 * @date 2023-2025
 * @copyright MIT License
 * 
 * @brief MemoryHelper class for Android 64-bit memory helper.
 * 
 * This class provides comprehensive memory reading/writing capabilities for internal
 * and external processes. It supports various data types, memory region management,
 * pattern scanning, and memory allocation/protection operations. Includes filtering
 * capabilities and utility functions for memory manipulation.
 */

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <cstdint>
#include <sys/types.h>
#include "ProcessParse.hpp"

namespace MemoryHelper {

/**
 * @class MemoryHelper
 * @brief Provides memory reading/writing capabilities for internal and external processes
 */
class MemoryHelper {
public:
    /**
     * @brief Memory region information structure
     */
    struct MemoryRegion {
        uint64_t start;
        uint64_t end;
        std::string permissions;
        std::string name;
        bool isReadable;
        bool isWritable;
        bool isExecutable;
    };
    
    /**
     * @brief Filter function type for memory regions
     * @param region Memory region to check
     * @return True if the region matches the filter criteria
     */
    using RegionFilter = std::function<bool(const MemoryRegion&)>;
    
    /**
     * @brief Constructor
     * @param targetPid Target process ID (0 for current process)
     */
    explicit MemoryHelper(pid_t targetPid = 0);
    
    /**
     * @brief Destructor
     */
    ~MemoryHelper();
    
    // Memory reading functions
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
    
    // Memory writing functions
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
     * @return True if the write was successful, false otherwise
     */
    bool writeMemory(uint64_t address, const void* buffer, size_t size);
    
    /**
     * @brief Write a vector of bytes to memory
     * @param address Address to write to
     * @param bytes Vector of bytes to write
     * @return True if the write was successful, false otherwise
     */
    bool writeBytes(uint64_t address, const std::vector<uint8_t>& bytes);
    
    // Memory region functions
    /**
     * @brief Get a list of all memory regions for the target process
     * @return Vector of MemoryRegion structures
     */
    std::vector<MemoryRegion> getMemoryRegions();
    
    /**
     * @brief Get a list of memory regions filtered by a custom filter function
     * @param filter Filter function to apply
     * @return Vector of MemoryRegion structures that match the filter
     */
    std::vector<MemoryRegion> getMemoryRegions(const RegionFilter& filter);
    
    /**
     * @brief Find a memory region by name
     * @param name Name of the region to find
     * @return MemoryRegion structure, or empty if not found
     */
    MemoryRegion findMemoryRegion(const std::string& name);
    
    /**
     * @brief Find a memory region containing a specific address
     * @param address Address to search for
     * @return MemoryRegion structure, or empty if not found
     */
    MemoryRegion findMemoryRegion(uint64_t address);
    
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
    
    // Pattern scanning functions
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

private:
    class MemoryHelperImpl;
    std::unique_ptr<MemoryHelperImpl> mImpl;
    
    // Private constructor for internal use
    MemoryHelper(std::unique_ptr<MemoryHelperImpl> impl);
    
    // Helper function to parse memory permissions
    static bool parsePermissions(const std::string& permStr, bool& readable, bool& writable, bool& executable);
    
    // Helper function to format memory permissions
    static std::string formatPermissions(bool readable, bool writable, bool executable);
};

} // namespace MemoryHelper

#endif // MEMORY_HELPER_HPP
