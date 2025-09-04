#ifndef HOOK_MANAGER_HPP
#define HOOK_MANAGER_HPP

/**
 * @file HookManager.hpp
 * @author foxcheatsid@gmail.com
 * @version 1.0
 * @date 2023-2025
 * @copyright MIT License
 * 
 * @brief HookManager class for Android 64-bit memory helper.
 * 
 * This class implements hooking mechanisms for functions in memory, supporting
 * inline hooks, detour hooks, and breakpoint hooks. It provides methods to install,
 * remove, enable, and disable hooks for both internal and external processes.
 * Includes callback functionality and context management for custom hook behavior.
 */

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <cstdint>
#include <sys/types.h>
#include "ModuleInfo.hpp"

namespace MemoryHelper {

/**
 * @class HookManager
 * @brief Implements hooking mechanisms for functions in memory
 */
class HookManager {
public:
    /**
     * @brief Hook type enumeration
     */
    enum class HookType {
        INLINE,    // Inline hook (replaces first bytes of function)
        DETOUR,    // Detour hook (jumps to our function)
        BREAKPOINT // Breakpoint hook (int3 instruction)
    };
    
    /**
     * @brief Hook information structure
     */
    struct HookInfo {
        uint64_t originalAddress;  // Original function address
        uint64_t hookAddress;      // Address where the hook is installed
        HookType type;             // Type of hook
        std::string moduleName;    // Module name where the hook is installed
        bool isActive;             // Whether the hook is currently active
    };
    
    /**
     * @brief Hook callback function type
     * @param context Hook context data
     * @return Return value for the hooked function
     */
    using HookCallback = std::function<uint64_t(void* context)>;
    
    /**
     * @brief Constructor
     * @param targetPid Target process ID (0 for current process)
     */
    explicit HookManager(pid_t targetPid = 0);
    
    /**
     * @brief Destructor
     */
    ~HookManager();
    
    /**
     * @brief Install a hook at the specified address
     * @param address Address to hook
     * @param callback Callback function to execute when hooked
     * @param type Type of hook to install
     * @param context Context data to pass to the callback
     * @return HookInfo structure with hook details, or empty if failed
     */
    HookInfo installHook(uint64_t address, HookCallback callback, HookType type = HookType::INLINE, void* context = nullptr);
    
    /**
     * @brief Install a hook by function name in a module
     * @param moduleName Name of the module containing the function
     * @param functionName Name of the function to hook
     * @param callback Callback function to execute when hooked
     * @param type Type of hook to install
     * @param context Context data to pass to the callback
     * @return HookInfo structure with hook details, or empty if failed
     */
    HookInfo installHook(const std::string& moduleName, const std::string& functionName, 
                         HookCallback callback, HookType type = HookType::INLINE, void* context = nullptr);
    
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
    std::vector<HookInfo> getHooks() const;
    
    /**
     * @brief Find a hook by the original address
     * @param originalAddress Original function address
     * @return HookInfo structure, or empty if not found
     */
    HookInfo findHookByOriginalAddress(uint64_t originalAddress) const;
    
    /**
     * @brief Find a hook by the hook address
     * @param hookAddress Address where the hook is installed
     * @return HookInfo structure, or empty if not found
     */
    HookInfo findHookByHookAddress(uint64_t hookAddress) const;
    
    /**
     * @brief Get the original function address for a hook
     * @param hookAddress Address where the hook is installed
     * @return Original function address, or 0 if not found
     */
    uint64_t getOriginalAddress(uint64_t hookAddress) const;
    
    /**
     * @brief Get the hook context
     * @param hookAddress Address where the hook is installed
     * @return Context data, or nullptr if not found
     */
    void* getHookContext(uint64_t hookAddress) const;
    
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
    bool isHookInstalled(uint64_t address) const;
    
    /**
     * @brief Get the target process ID
     * @return Process ID
     */
    pid_t getTargetPid() const;
    
private:
    class HookImpl;
    std::unique_ptr<HookImpl> mImpl;
    
    // Private constructor for internal use
    HookManager(std::unique_ptr<HookImpl> impl);
    
    // Helper function to find module base address
    uint64_t findModuleBase(const std::string& moduleName);
    
    // Helper function to find function address in a module
    uint64_t findFunctionAddress(const std::string& moduleName, const std::string& functionName);
    
    // Helper function to create trampoline for inline hooks
    uint64_t createTrampoline(uint64_t address);
    
    // Helper function to write memory
    bool writeMemory(uint64_t address, const void* data, size_t size);
    
    // Helper function to read memory
    bool readMemory(uint64_t address, void* buffer, size_t size);
    
    // Helper function to allocate memory
    uint64_t allocateMemory(size_t size);
    
    // Helper function to free memory
    bool freeMemory(uint64_t address);
};

} // namespace MemoryHelper

#endif // HOOK_MANAGER_HPP