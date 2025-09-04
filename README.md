# Android Memory Helper

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/Platform-Android-blue.svg)](https://developer.android.com/)
[![Architecture](https://img.shields.io/badge/Architecture-64--bit-green.svg)](https://developer.android.com/guide/practices/supporting-arm64-v8a)
[![C++17](https://img.shields.io/badge/C++-17-orange.svg)](https://isocpp.org/)

A comprehensive, advanced memory address helper library for Android 64-bit applications, designed to work with both internal and external processes. This library provides powerful functionality for module information retrieval, process parsing, hook management, and memory manipulation.

## 🚀 Features

- **Module Information**: Retrieve detailed information about loaded modules in a process
- **Process Management**: Enumerate and filter processes with custom criteria
- **Function Hooking**: Install inline, detour, and breakpoint hooks on functions
- **Memory Operations**: Read and write various data types to memory
- **Pattern Scanning**: Search for patterns in memory with wildcard support
- **Memory Regions**: Manage memory regions and their permissions
- **Cross-Process Support**: Works with both internal and external processes
- **64-bit Android Support**: Optimized for Android 64-bit architecture (arm64-v8a, x86_64)

## 📦 Requirements

- Android NDK (Native Development Kit) r21 or later
- C++17 or later
- Android 64-bit target architecture (arm64-v8a, x86_64)
- Minimum Android API level 21 (Android 5.0 Lollipop)

## 🛠️ Installation

### Prerequisites

1. Install the Android NDK:
   ```bash
   # In Android Studio
   Tools > SDK Manager > SDK Tools > Android NDK (Side by side)
   
   # Or via command line
   sdkmanager "ndk;23.1.7779620"
   ```

2. Set up your environment:
   ```bash
   export ANDROID_NDK_HOME=$HOME/Library/Android/sdk/ndk/23.1.7779620  # macOS
   export ANDROID_NDK_HOME=$HOME/Android/Sdk/ndk/23.1.7779620       # Linux
   export ANDROID_NDK_HOME=$%APPDATA%\Local\Android\Sdk\ndk\23.1.7779620  # Windows
   ```

### Adding to Your Project

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/android-memory-helper.git
   cd android-memory-helper
   ```

2. Copy the source files to your project:
   ```bash
   cp -r include/* ${YOUR_PROJECT_PATH}/app/src/main/cpp/
   cp *.cpp ${YOUR_PROJECT_PATH}/app/src/main/cpp/
   ```

3. Update your `CMakeLists.txt`:
   ```cmake
   cmake_minimum_required(VERSION 3.18.1)
   
   add_library(memory-helper SHARED
       ModuleInfo.cpp
       ProcessParse.cpp
       HookManager.cpp
       MemoryHelper.cpp
       MemoryAddressHelper.cpp
   )
   
   target_include_directories(memory-helper PRIVATE ${CMAKE_SOURCE_DIR})
   
   # Link with required libraries
   target_link_libraries(memory-helper
       android
       log
   )
   ```

4. Link the library in your app module:
   ```cmake
   # In your app's CMakeLists.txt
   target_link_libraries(your-lib-name memory-helper)
   ```

## 💡 Usage Examples

### Basic Memory Operations

```cpp
#include "MemoryAddressHelper.hpp"

void basicExample() {
    // Create a memory helper for the current process
    MemoryAddressHelper helper;
    
    // Read a value from memory
    uint32_t value;
    if (helper.readDword(0x7f1234567890, &value)) {
        LOGI("Read value: %u", value);
    }
    
    // Write a value to memory
    helper.writeDword(0x7f1234567890, 0x12345678);
    
    // Read a string from memory
    std::string str = helper.readString(0x7f1234567890, 256);
    LOGI("Read string: %s", str.c_str());
}
```

### Hooking a Function

```cpp
#include "MemoryAddressHelper.hpp"

// Hook callback function
uint64_t hookCallback(void* context) {
    LOGI("Hook called with context: %p", context);
    
    // Call the original function
    MemoryAddressHelper* helper = reinterpret_cast<MemoryAddressHelper*>(context);
    uint64_t result = helper->callOriginal(originalAddress, context);
    
    // Modify the result if needed
    return result * 2;
}

void hookingExample() {
    // Create a memory helper for a target process
    MemoryAddressHelper helper(1234); // PID 1234
    
    // Find a function to hook by name in a module
    auto hookInfo = helper.installHook(
        "libexample.so", 
        "exampleFunction",
        hookCallback,
        HookManager::HookType::INLINE,
        &helper
    );
    
    if (hookInfo.originalAddress != 0) {
        LOGI("Hook installed at: 0x%lx", hookInfo.hookAddress);
    }
}
```

### Pattern Scanning

```cpp
#include "MemoryAddressHelper.hpp"

void patternScanningExample() {
    // Create a memory helper for a target process
    MemoryAddressHelper helper(1234); // PID 1234
    
    // Define pattern and mask (using 0 for wildcards)
    std::vector<uint8_t> pattern = {0x48, 0x8B, 0x??, 0x??, 0x??, 0x48, 0x83, 0xC4};
    std::vector<uint8_t> mask = {1, 1, 0, 0, 0, 1, 1, 1};
    
    // Scan for pattern in a specific module
    auto results = helper.findPatternInModule("libexample.so", pattern, mask);
    
    for (uint64_t address : results) {
        LOGI("Pattern found at: 0x%lx", address);
        
        // Read a dword from the found address
        uint32_t value;
        if (helper.readDword(address + 4, &value)) {
            LOGI("Value at address + 4: %u", value);
        }
    }
}
```

### Process Enumeration

```cpp
#include "MemoryAddressHelper.hpp"

void processEnumerationExample() {
    // Create a memory helper
    MemoryAddressHelper helper;
    
    // Get all processes
    auto processes = helper.getProcesses();
    
    // Filter processes by name
    auto filteredProcesses = helper.getProcesses([](const ProcessParse::ProcessInfo& process) {
        return process.name.find("example") != std::string::npos;
    });
    
    for (const auto& process : filteredProcesses) {
        LOGI("Process: %s (PID: %d, UID: %d)", 
             process.name.c_str(), process.pid, process.uid);
        
        // Get modules for this process
        auto modules = helper.getModules(process.pid);
        for (const auto& module : modules) {
            LOGI("  Module: %s (Base: 0x%lx, Size: %zu)", 
                 module.getName().c_str(), 
                 module.getBaseAddress(), 
                 module.getSize());
        }
    }
}
```

## 📚 API Reference

### MemoryAddressHelper

The main class that provides a unified interface for all memory manipulation capabilities.

#### Constructors

```cpp
MemoryAddressHelper(pid_t targetPid = 0);
```

Creates a memory address helper for the specified process. If `targetPid` is 0, it operates on the current process.

#### Module Information

```cpp
std::vector<ModuleInfo> getModules();
std::vector<ModuleInfo> getModules(const ProcessParse::ModuleFilter& filter);
ModuleInfo findModuleByName(const std::string& moduleName);
ModuleInfo findModuleByAddress(uint64_t address);
uint64_t getModuleBase(const std::string& moduleName);
size_t getModuleSize(const std::string& moduleName);
```

#### Process Information

```cpp
std::vector<ProcessParse::ProcessInfo> getProcesses();
std::vector<ProcessParse::ProcessInfo> getProcesses(const ProcessParse::ProcessFilter& filter);
ProcessParse::ProcessInfo getProcessInfo(pid_t pid);
bool isProcessRunning(pid_t pid);
```

#### Hook Management

```cpp
HookManager::HookInfo installHook(uint64_t address, HookManager::HookCallback callback, 
                                 HookManager::HookType type = HookManager::HookType::INLINE, 
                                 void* context = nullptr);
HookManager::HookInfo installHook(const std::string& moduleName, const std::string& functionName, 
                                 HookManager::HookCallback callback, 
                                 HookManager::HookType type = HookManager::HookType::INLINE, 
                                 void* context = nullptr);
bool removeHook(uint64_t hookAddress);
void removeAllHooks();
bool enableHook(uint64_t hookAddress);
bool disableHook(uint64_t hookAddress);
std::vector<HookManager::HookInfo> getHooks();
```

#### Memory Operations

```cpp
// Reading
bool readByte(uint64_t address, uint8_t* value);
bool readWord(uint64_t address, uint16_t* value);
bool readDword(uint64_t address, uint32_t* value);
bool readQword(uint64_t address, uint64_t* value);
bool readFloat(uint64_t address, float* value);
bool readDouble(uint64_t address, double* value);
std::string readString(uint64_t address, size_t maxLength = 256);
bool readMemory(uint64_t address, void* buffer, size_t size);
std::vector<uint8_t> readBytes(uint64_t address, size_t size);

// Writing
bool writeByte(uint64_t address, uint8_t value);
bool writeWord(uint64_t address, uint16_t value);
bool writeDword(uint64_t address, uint32_t value);
bool writeQword(uint64_t address, uint64_t value);
bool writeFloat(uint64_t address, float value);
bool writeDouble(uint64_t address, double value);
bool writeString(uint64_t address, const std::string& str);
bool writeMemory(uint64_t address, const void* buffer, size_t size);
bool writeBytes(uint64_t address, const std::vector<uint8_t>& bytes);
```

#### Memory Regions

```cpp
std::vector<MemoryHelper::MemoryRegion> getMemoryRegions();
std::vector<MemoryHelper::MemoryRegion> getMemoryRegions(const MemoryHelper::RegionFilter& filter);
MemoryHelper::MemoryRegion findMemoryRegion(const std::string& name);
MemoryHelper::MemoryRegion findMemoryRegion(uint64_t address);
uint64_t allocateMemory(size_t size, const std::string& permissions = "rwx");
bool freeMemory(uint64_t address);
bool protectMemory(uint64_t address, size_t size, const std::string& permissions);
```

#### Pattern Scanning

```cpp
std::vector<uint64_t> findPattern(uint64_t startAddress, size_t size, 
                                 const std::vector<uint8_t>& pattern, 
                                 const std::vector<uint8_t>& mask);
std::vector<uint64_t> findPatternInModule(const std::string& moduleName, 
                                        const std::vector<uint8_t>& pattern, 
                                        const std::vector<uint8_t>& mask);
std::vector<uint64_t> findPatternInAllModules(const std::vector<uint8_t>& pattern, 
                                             const std::vector<uint8_t>& mask);
```

## ⚠️ Limitations

- For external processes, root privileges may be required on some devices
- Hooking functions in other processes is complex and may not work in all scenarios
- Memory protection changes for external processes may require additional privileges
- Some devices may have additional security restrictions that limit functionality

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Inspired by various Android memory manipulation tools and libraries
- Thanks to the Android NDK team for providing the native development environment
- Special thanks to contributors and the open-source community

## 📞 Support
[![Telegram](https://t.me/saprdty)](https://t.me/saprdty)

If you encounter any issues or have questions, please file an issue on the GitHub repository.

## ☕ Buy me coffee
Thanks

---

Made with ❤️ by the foxcheatsid team