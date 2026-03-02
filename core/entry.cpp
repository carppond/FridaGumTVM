#include "entry.h"
#include <frida-gum.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <string>
#include "common.h"
#include "instruction_tracer_manager.h"

// ==================== JSON 配置解析（轻量级，无第三方依赖） ====================

static std::string trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\n\r\"");
    size_t end = s.find_last_not_of(" \t\n\r\"");
    if (start == std::string::npos) return "";
    return s.substr(start, end - start + 1);
}

static std::string extract_json_value(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return "";

    pos = json.find(':', pos + search.length());
    if (pos == std::string::npos) return "";

    size_t start = json.find_first_not_of(" \t\n\r", pos + 1);
    if (start == std::string::npos) return "";

    if (json[start] == '"') {
        size_t end = json.find('"', start + 1);
        if (end == std::string::npos) return "";
        return json.substr(start + 1, end - start - 1);
    }

    // 数字或布尔值
    size_t end = json.find_first_of(",}\n", start);
    if (end == std::string::npos) end = json.length();
    return trim(json.substr(start, end - start));
}

static bool load_config_from_file(const char* path,
                                   std::string& module_name,
                                   uintptr_t& offset,
                                   std::string& trace_file) {
    std::ifstream file(path);
    if (!file.is_open()) return false;

    std::string json((std::istreambuf_iterator<char>(file)),
                      std::istreambuf_iterator<char>());
    file.close();

    module_name = extract_json_value(json, "target_module");
    trace_file = extract_json_value(json, "output_file");

    std::string offset_str = extract_json_value(json, "trace_offset");
    if (!offset_str.empty()) {
        if (offset_str.substr(0, 2) == "0x" || offset_str.substr(0, 2) == "0X") {
            offset = strtoull(offset_str.c_str(), nullptr, 16);
        } else {
            offset = strtoull(offset_str.c_str(), nullptr, 10);
        }
    }

    return !module_name.empty() && offset != 0;
}

// ==================== 配置文件搜索路径 ====================

static const char* config_search_paths[] = {
    "/tmp/gumTVM/trace_config.json",        // 通用路径
    "/var/mobile/gumTVM/trace_config.json",  // 越狱设备
    nullptr
};

static bool try_auto_config() {
    for (int i = 0; config_search_paths[i] != nullptr; i++) {
        std::string module_name;
        uintptr_t offset = 0;
        std::string trace_file;

        if (load_config_from_file(config_search_paths[i], module_name, offset, trace_file)) {
            LOGI("Config loaded from: %s", config_search_paths[i]);
            LOGI("  target_module: %s", module_name.c_str());
            LOGI("  trace_offset: 0x%lx", (unsigned long)offset);
            LOGI("  output_file: %s", trace_file.c_str());

            if (trace_file.empty()) {
                trace_file = "trace.txt";
            }

            auto instance = InstructionTracerManager::get_instance();
            if (!instance->init(module_name, offset)) {
                LOGE("Failed to init tracer for module: %s", module_name.c_str());
                return false;
            }
            instance->get_logger_manager()->set_enable_to_file(true, trace_file);
            bool ret = instance->run_attach();
            LOGI("Attach result: %s", ret ? "success" : "failed");
            return ret;
        }
    }
    return false;
}

// ==================== 自动启动（constructor，优先级低于 gum_init） ====================

__attribute__((constructor(102)))
static void gum_tvm_auto_start() {
    LOGI("gumTVM iOS tracer loaded, searching for config...");

    if (try_auto_config()) {
        LOGI("Auto-config succeeded, tracing started");
    } else {
        LOGI("No config found, waiting for gum_trace() call");
    }
}

// ==================== 导出的手动入口 ====================

extern "C"
__attribute__((visibility("default")))
void gum_trace(const char* module_name, uintptr_t offset, const char* trace_file_name) {
    LOGI("gum_trace called: module=%s offset=0x%lx file=%s",
         module_name, (unsigned long)offset, trace_file_name);

    auto instance = InstructionTracerManager::get_instance();
    if (!instance->init(std::string(module_name), offset)) {
        LOGE("init stalker failed for module: %s", module_name);
        return;
    }

    std::string file_name = trace_file_name ? trace_file_name : "trace.txt";
    instance->get_logger_manager()->set_enable_to_file(true, file_name);
    bool ret = instance->run_attach();
    LOGI("run_attach result: %s", ret ? "success" : "failed");
}
