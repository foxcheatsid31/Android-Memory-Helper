#include "ProcessParse.hpp"
#include <dirent.h>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <regex>
#include <unistd.h>
#include <sys/stat.h>
#include <android/log.h>

#define LOG_TAG "MemoryHelper"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace MemoryHelper {

std::vector<ProcessParse::ProcessInfo> ProcessParse::getProcesses() {
    return getProcesses([](const ProcessInfo&){ return true; });
}

std::vector<ProcessParse::ProcessInfo> ProcessParse::getProcesses(const ProcessFilter& filter) {
    std::vector<ProcessInfo> processes;
    DIR* dir = opendir("/proc");
    if (!dir) {
        LOGE("Failed to open /proc directory");
        return processes;
    }
    
    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        // Check if the directory name is a number (PID)
        if (std::regex_match(entry->d_name, std::regex("\\d+"))) {
            pid_t pid = std::stoi(entry->d_name);
            ProcessInfo info = readProcessInfo(pid);
            if (!info.name.empty() && filter(info)) {
                processes.push_back(info);
            }
        }
    }
    
    closedir(dir);
    return processes;
}

ProcessParse::ProcessInfo ProcessParse::getProcessInfo(pid_t pid) {
    return readProcessInfo(pid);
}

std::vector<ModuleInfo> ProcessParse::getModules(pid_t pid) {
    return getModules(pid, [](const ModuleInfo&){ return true; });
}

std::vector<ModuleInfo> ProcessParse::getModules(pid_t pid, const ModuleFilter& filter) {
    std::vector<ModuleInfo> modules = readModules(pid);
    modules.erase(std::remove_if(modules.begin(), modules.end(), 
        [&](const ModuleInfo& module) { return !filter(module); }), 
        modules.end());
    return modules;
}

ModuleInfo ProcessParse::findModuleByName(pid_t pid, const std::string& moduleName) {
    auto modules = getModules(pid, [&](const ModuleInfo& module) {
        return module.getName() == moduleName;
    });
    
    if (modules.empty()) {
        return ModuleInfo("", 0, 0, pid);
    }
    return modules[0];
}

ModuleInfo ProcessParse::findModuleByAddress(pid_t pid, uint64_t address) {
    auto modules = getModules(pid, [&](const ModuleInfo& module) {
        return module.containsAddress(address);
    });
    
    if (modules.empty()) {
        return ModuleInfo("", 0, 0, pid);
    }
    return modules[0];
}

uint64_t ProcessParse::getModuleBase(pid_t pid, const std::string& moduleName) {
    ModuleInfo module = findModuleByName(pid, moduleName);
    return module.getBaseAddress();
}

bool ProcessParse::isProcessRunning(pid_t pid) {
    std::string path = "/proc/" + std::to_string(pid);
    struct stat st;
    return (stat(path.c_str(), &st) == 0);
}

ProcessParse::ProcessInfo ProcessParse::readProcessInfo(pid_t pid) {
    ProcessInfo info;
    info.pid = pid;
    
    std::string path = "/proc/" + std::to_string(pid);
    
    // Read process name from stat
    std::string statPath = path + "/stat";
    std::ifstream statFile(statPath);
    if (statFile.is_open()) {
        std::string line;
        std::getline(statFile, line);
        
        // Extract process name (between parentheses)
        size_t openParen = line.find('(');
        size_t closeParen = line.rfind(')');
        if (openParen != std::string::npos && closeParen != std::string::npos && closeParen > openParen) {
            info.name = line.substr(openParen + 1, closeParen - openParen - 1);
        }
    }
    
    // Read executable path from exe symlink
    std::string exePath = path + "/exe";
    char buffer[PATH_MAX];
    ssize_t len = readlink(exePath.c_str(), buffer, sizeof(buffer) - 1);
    if (len > 0) {
        buffer[len] = '\0';
        info.path = buffer;
    }
    
    // Read UID from status file
    std::string statusPath = path + "/status";
    std::ifstream statusFile(statusPath);
    if (statusFile.is_open()) {
        std::string line;
        while (std::getline(statusFile, line)) {
            if (line.find("Uid:") == 0) {
                std::istringstream iss(line);
                std::string label;
                iss >> label;
                iss >> info.uid;
                break;
            }
        }
    }
    
    // Check if it's a system process
    info.isSystem = (info.uid == 0);
    
    return info;
}

std::vector<ModuleInfo> ProcessParse::readModules(pid_t pid) {
    std::vector<ModuleInfo> modules;
    std::string path = "/proc/" + std::to_string(pid) + "/maps";
    
    std::ifstream mapsFile(path);
    if (!mapsFile.is_open()) {
        LOGE("Failed to open %s", path.c_str());
        return modules;
    }
    
    std::string line;
    std::string currentModuleName;
    uint64_t currentBase = 0;
    size_t currentSize = 0;
    
    while (std::getline(mapsFile, line)) {
        std::istringstream iss(line);
        std::string addressRange, permissions, offset, dev, inode, pathname;
        
        iss >> addressRange >> permissions >> offset >> dev >> inode;
        std::getline(iss, pathname);
        
        // Trim whitespace from pathname
        pathname.erase(pathname.find_last_not_of(" \t\n\r\f\v") + 1);
        
        if (!pathname.empty() && pathname[0] == '/') {
            // New module found
            if (!currentModuleName.empty()) {
                modules.emplace_back(currentModuleName, currentBase, currentSize, pid);
            }
            
            // Parse address range
            size_t dashPos = addressRange.find('-');
            if (dashPos != std::string::npos) {
                std::string startAddr = addressRange.substr(0, dashPos);
                std::string endAddr = addressRange.substr(dashPos + 1);
                
                currentBase = std::stoull(startAddr, nullptr, 16);
                uint64_t end = std::stoull(endAddr, nullptr, 16);
                currentSize = static_cast<size_t>(end - currentBase);
                currentModuleName = pathname;
            }
        }
    }
    
    // Add the last module
    if (!currentModuleName.empty()) {
        modules.emplace_back(currentModuleName, currentBase, currentSize, pid);
    }
    
    return modules;
}

} // namespace MemoryHelper