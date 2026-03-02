#ifndef GUMTVM_MACHO_UTILS_H
#define GUMTVM_MACHO_UTILS_H

#include "common.h"
#include <string>
#include <utility>
#include <vector>

struct MachOSectionInfo {
    uintptr_t addr;
    size_t size;
};

class MachOUtils {
public:
    MachOUtils() = delete;
    ~MachOUtils() = delete;

    // 获取指定模块的 __stubs 段范围（相当于 Android 的 PLT）
    static std::pair<size_t, size_t> get_stubs_range(const std::string& module_name);

    // 获取指定模块的 __stub_helper 段范围
    static std::pair<size_t, size_t> get_stub_helper_range(const std::string& module_name);

    // 通过模块名获取 Mach-O 镜像基址和 slide
    static bool get_image_info(const std::string& module_name, uintptr_t& base, intptr_t& slide);

private:
    // 在 Mach-O header 中查找指定 section
    static bool find_section(const struct mach_header_64* header, const char* segname,
                             const char* sectname, MachOSectionInfo& info);
};

#endif // GUMTVM_MACHO_UTILS_H
