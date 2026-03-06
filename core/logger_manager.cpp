#include "logger_manager.h"
#include "hex_dump.h"
#include <cstdint>
#include <sys/stat.h>
#include <sstream>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <unistd.h>

std::string LoggerManager::get_log_directory() {
    // 越狱设备: 使用 /var/mobile/Documents/gumTVM/
    // 非越狱 (App沙盒): 使用 /tmp/gumTVM/ 或通过 NSHomeDirectory
    // 这里优先尝试 /tmp (两种环境都可写), 然后回退到 /var/tmp
    const char* dirs[] = {
        "/tmp/gumTVM/",
        "/var/tmp/gumTVM/",
        nullptr
    };

    for (int i = 0; dirs[i] != nullptr; i++) {
        std::string dir(dirs[i]);
        if (check_and_mkdir(dir)) {
            return dir;
        }
    }

    LOGE("Failed to find writable log directory, using /tmp/");
    return "/tmp/";
}

void LoggerManager::set_enable_to_file(bool enable, const std::string& file_name) {
    if (enable) {
        if (trace_file_name.empty()) {
            // 如果传入的是完整路径（以 / 开头），直接使用；否则拼接默认目录
            if (!file_name.empty() && file_name[0] == '/') {
                trace_file_name = file_name;
            } else {
                std::string trace_dir = get_log_directory();
                trace_file_name = trace_dir + file_name;
            }
            // 先设缓冲再 open（标准要求 pubsetbuf 在 open 之前调用）
            trace_out.rdbuf()->pubsetbuf(write_buf, sizeof(write_buf));
            trace_out.open(trace_file_name, std::ios::out);
            if (trace_out.is_open()) {
                LOGI("Trace file opened: %s (buf=256KB)", trace_file_name.c_str());
            } else {
                LOGE("Failed to open trace file: %s", trace_file_name.c_str());
            }
        }
    } else {
        if (trace_out.is_open()) {
            trace_out.flush();
            trace_out.close();
            LOGI("Trace file closed: %s", trace_file_name.c_str());
        }
    }
}

bool LoggerManager::check_and_mkdir(const std::string& path) {
    struct stat info;
    if (stat(path.c_str(), &info) == 0) {
        return (info.st_mode & S_IFDIR) != 0;
    }
    return mkdir(path.c_str(), 0755) == 0;
}

void LoggerManager::write_info(std::stringstream& line) {
    if (this->trace_out.is_open()) {
        this->trace_out << line.str();
    }
}

std::string LoggerManager::dump_reg_value(uint64_t regValue, const char* regName, size_t count) {
    std::stringstream regOutput;
    if (isValidAddress(regValue)) {
        size_t maxLen = 0x800;
        uint8_t buffer[0x801] = {};
        if (safeReadMemory(regValue, buffer, maxLen)) {
            if (is_ascii_printable_string(buffer, maxLen)) {
                regOutput << "String for " << regName << " at address 0x"
                          << std::hex << regValue << " : "
                          << std::string(reinterpret_cast<const char*>(buffer))
                          << "\n";
            } else {
                regOutput << "Hexdump for " << regName << " at address 0x"
                          << std::hex << regValue << ":\n";
                const HexDump hex_dump(buffer, count, regValue);
                regOutput << hex_dump;
            }
        }
    }
    return regOutput.str();
}

bool LoggerManager::isValidAddress(uint64_t address) {
    // iOS: 使用 mach_vm_region 检查地址是否映射
    vm_address_t addr = (vm_address_t)address;
    vm_size_t size = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object_name = MACH_PORT_NULL;

    kern_return_t kr = vm_region_64(
        mach_task_self(),
        &addr,
        &size,
        VM_REGION_BASIC_INFO_64,
        (vm_region_info_t)&info,
        &info_count,
        &object_name
    );

    if (kr != KERN_SUCCESS) {
        return false;
    }

    // 检查请求的地址是否在找到的区域内
    return address >= addr && address < (addr + size);
}

bool LoggerManager::is_ascii_printable_string(const uint8_t* data, size_t length) {
    if (data == nullptr) {
        return false;
    }

    bool hasNonSpaceChar = false;
    for (size_t i = 0; i < length; ++i) {
        if (data[i] == '\0') {
            return hasNonSpaceChar;
        }
        if (data[i] < 0x20 || data[i] > 0x7E) {
            return false;
        }
        if (data[i] != ' ') {
            hasNonSpaceChar = true;
        }
    }
    return hasNonSpaceChar;
}

bool LoggerManager::safeReadMemory(uint64_t address, uint8_t* buffer, size_t length) {
    // iOS: 使用 vm_read_overwrite 替代 process_vm_readv
    vm_size_t out_size = 0;
    kern_return_t kr = vm_read_overwrite(
        mach_task_self(),
        (vm_address_t)address,
        (vm_size_t)length,
        (vm_address_t)buffer,
        &out_size
    );

    return kr == KERN_SUCCESS && out_size == length;
}
