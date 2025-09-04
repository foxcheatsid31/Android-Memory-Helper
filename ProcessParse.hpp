#ifndef PROCESS_PARSE_HPP
#define PROCESS_PARSE_HPP

/**
 * @file ProcessParse.hpp
 * @author foxcheatsid@gmail.com
 * @version 1.0
 * @date 2023-2025
 * @copyright MIT License
 * 
 * @brief ProcessParse class for Android 64-bit memory helper.
 * 
 * This class handles process enumeration and information retrieval from the Android
 * filesystem. It provides methods to get process information, filter processes,
 * and retrieve module information for specific processes. Supports both internal
 * and external processes with filtering capabilities.
 */

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <regex>
#include <sys/types.h>
#include "ModuleInfo.hpp"

namespace MemoryHelper {

/**
 * @class ProcessParse
 * @brief Handles process enumeration and information retrieval
 */
class ProcessParse {
public:
    /**
     * @brief Process information structure
     */
    struct ProcessInfo {
        pid_t pid;
        std::string name;
        std::string path;
        uid_t uid;
        bool isSystem;
    };
    
    /**
     * @brief Filter function type for processes
     * @param process Process information to check
     * @return True if the process matches the filter criteria
     */
    using ProcessFilter = std::function<bool(const ProcessInfo&)>;
    
    /**
     * @brief Filter function type for modules
     * @param module Module information to check
     * @return True if the module matches the filter criteria
     */
    using ModuleFilter = std::function<bool(const ModuleInfo&)>;
    
    /**
     * @brief Get a list of all running processes
     * @return Vector of ProcessInfo structures
     */
    static std::vector<ProcessInfo> getProcesses();
    
    /**
     * @brief Get a list of running processes filtered by a custom filter function
     * @param filter Filter function to apply
     * @return Vector of ProcessInfo structures that match the filter
     */
    static std::vector<ProcessInfo> getProcesses(const ProcessFilter& filter);
    
    /**
     * @brief Get process information by PID
     * @param pid Process ID to look up
     * @return ProcessInfo structure, or empty if not found
     */
    static ProcessInfo getProcessInfo(pid_t pid);
    
    /**
     * @brief Get a list of all loaded modules for a process
     * @param pid Process ID
     * @return Vector of ModuleInfo structures
     */
    static std::vector<ModuleInfo> getModules(pid_t pid);
    
    /**
     * @brief Get a list of loaded modules for a process with custom filtering
     * @param pid Process ID
     * @param filter Filter function to apply
     * @return Vector of ModuleInfo structures that match the filter
     */
    static std::vector<ModuleInfo> getModules(pid_t pid, const ModuleFilter& filter);
    
    /**
     * @brief Find a module by name in a process
     * @param pid Process ID
     * @param moduleName Name of the module to find
     * @return ModuleInfo structure, or empty if not found
     */
    static ModuleInfo findModuleByName(pid_t pid, const std::string& moduleName);
    
    /**
     * @brief Find a module containing a specific address
     * @param pid Process ID
     * @param address Address to search for
     * @return ModuleInfo structure, or empty if not found
     */
    static ModuleInfo findModuleByAddress(pid_t pid, uint64_t address);
    
    /**
     * @brief Get the base address of a module by name
     * @param pid Process ID
     * @param moduleName Name of the module
     * @return Base address of the module, or 0 if not found
     */
    static uint64_t getModuleBase(pid_t pid, const std::string& moduleName);
    
    /**
     * @brief Check if a process is running
     * @param pid Process ID to check
     * @return True if the process is running, false otherwise
     */
    static bool isProcessRunning(pid_t pid);
    
private:
    /**
     * @brief Read process information from /proc filesystem
     * @param pid Process ID
     * @return ProcessInfo structure
     */
    static ProcessInfo readProcessInfo(pid_t pid);
    
    /**
     * @brief Read module information from /proc filesystem
     * @param pid Process ID
     * @return Vector of ModuleInfo structures
     */
    static std::vector<ModuleInfo> readModules(pid_t pid);
};

} // namespace MemoryHelper

#endif // PROCESS_PARSE_HPP