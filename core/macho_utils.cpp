#include "macho_utils.h"
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <cstring>

bool MachOUtils::find_section(const struct mach_header_64* header, const char* segname,
                              const char* sectname, MachOSectionInfo& info) {
    const uint8_t* ptr = (const uint8_t*)header + sizeof(struct mach_header_64);

    for (uint32_t i = 0; i < header->ncmds; i++) {
        const struct load_command* cmd = (const struct load_command*)ptr;

        if (cmd->cmd == LC_SEGMENT_64) {
            const struct segment_command_64* seg = (const struct segment_command_64*)ptr;

            if (strcmp(seg->segname, segname) == 0) {
                const struct section_64* sect = (const struct section_64*)(ptr + sizeof(struct segment_command_64));

                for (uint32_t j = 0; j < seg->nsects; j++) {
                    if (strcmp(sect[j].sectname, sectname) == 0) {
                        info.addr = sect[j].addr;
                        info.size = sect[j].size;
                        return true;
                    }
                }
            }
        }
        ptr += cmd->cmdsize;
    }
    return false;
}

bool MachOUtils::get_image_info(const std::string& module_name, uintptr_t& base, intptr_t& slide) {
    uint32_t count = _dyld_image_count();

    for (uint32_t i = 0; i < count; i++) {
        const char* name = _dyld_get_image_name(i);
        if (name == nullptr) continue;

        // 匹配模块名（支持完整路径或只是文件名）
        const char* basename = strrchr(name, '/');
        basename = basename ? basename + 1 : name;

        if (module_name == basename || module_name == name) {
            const struct mach_header* header = _dyld_get_image_header(i);
            slide = _dyld_get_image_vmaddr_slide(i);
            base = (uintptr_t)header;
            return true;
        }
    }
    return false;
}

std::pair<size_t, size_t> MachOUtils::get_stubs_range(const std::string& module_name) {
    uintptr_t base = 0;
    intptr_t slide = 0;

    if (!get_image_info(module_name, base, slide)) {
        LOGE("Failed to find image: %s", module_name.c_str());
        return std::make_pair((size_t)0, (size_t)0);
    }

    const struct mach_header_64* header = (const struct mach_header_64*)base;
    MachOSectionInfo info = {};

    if (find_section(header, "__TEXT", "__stubs", info)) {
        return std::make_pair(info.addr, info.addr + info.size);
    }

    LOGW("__stubs section not found in: %s", module_name.c_str());
    return std::make_pair((size_t)0, (size_t)0);
}

std::pair<size_t, size_t> MachOUtils::get_stub_helper_range(const std::string& module_name) {
    uintptr_t base = 0;
    intptr_t slide = 0;

    if (!get_image_info(module_name, base, slide)) {
        return std::make_pair((size_t)0, (size_t)0);
    }

    const struct mach_header_64* header = (const struct mach_header_64*)base;
    MachOSectionInfo info = {};

    if (find_section(header, "__TEXT", "__stub_helper", info)) {
        return std::make_pair(info.addr, info.addr + info.size);
    }

    return std::make_pair((size_t)0, (size_t)0);
}
