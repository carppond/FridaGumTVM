#include "instruction_tracer_manager.h"

#include <dlfcn.h>
#include <cassert>
#include <cstring>

#include "common.h"
#include "custom_hook.h"
#include "instruction_callback.h"
#include "macho_utils.h"

InstructionTracerManager* InstructionTracerManager::get_instance() {
    static InstructionTracerManager instance;
    return &instance;
}

bool InstructionTracerManager::init(std::string module_name, uintptr_t offset) {
    this->trace_tid = 0;
    this->module_name = module_name;

    auto target_module = gum_process_find_module_by_name(module_name.c_str());
    if (target_module == nullptr) {
        LOGE("target module not found: %s", module_name.c_str());
        return false;
    }

    gum_module_ensure_initialized(target_module);
    auto target_range = gum_module_get_range(target_module);
    this->module_range.base = target_range->base_address;
    this->module_range.end = target_range->base_address + target_range->size;
    LOGI("target range: 0x%lx - 0x%lx", (unsigned long)this->module_range.base, (unsigned long)this->module_range.end);

    if (offset > target_range->size) {
        LOGE("offset 0x%lx out of range for module: %s (size: 0x%lx)",
             (unsigned long)offset, module_name.c_str(), (unsigned long)target_range->size);
        g_object_unref(target_module);
        return false;
    }

    this->target_trace_address = target_range->base_address + offset;
    LOGI("target trace address: 0x%lx (base + 0x%lx)",
         (unsigned long)this->target_trace_address, (unsigned long)offset);

    // iOS: 获取 __stubs 段范围（替代 Android 的 PLT）
    this->stubs_range = MachOUtils::get_stubs_range(module_name);
    this->stub_helper_range = MachOUtils::get_stub_helper_range(module_name);
    LOGI("__stubs range: 0x%lx - 0x%lx", (unsigned long)stubs_range.first, (unsigned long)stubs_range.second);
    LOGI("__stub_helper range: 0x%lx - 0x%lx", (unsigned long)stub_helper_range.first, (unsigned long)stub_helper_range.second);

    logger = std::make_unique<LoggerManager>(module_name, module_range);
    g_object_unref(target_module);
    return true;
}

InstructionTracerManager::InstructionTracerManager() {
    assert(gum_stalker_is_supported());
    m_stalker = gum_stalker_new();
    assert(m_stalker);
    // 信任阈值设为 0: 始终重新插桩，确保完整追踪
    gum_stalker_set_trust_threshold(m_stalker, 0);
    m_transformer = gum_stalker_transformer_make_from_callback(transform_callback, nullptr, nullptr);
    assert(m_transformer);

    // 获取 libgumTVM.dylib 自身基址，用于跨模块过滤
    Dl_info self_info;
    if (dladdr((void*)&InstructionTracerManager::get_instance, &self_info) && self_info.dli_fbase) {
        self_module_base = (uintptr_t)self_info.dli_fbase;
        LOGI("Self module base: 0x%lx (%s)", (unsigned long)self_module_base,
             self_info.dli_fname ? self_info.dli_fname : "unknown");
    }

    LOGI("Stalker initialized successfully");
}

InstructionTracerManager::~InstructionTracerManager() {
    g_object_unref(m_stalker);
    g_object_unref(m_transformer);
    g_object_unref(gum_interceptor);
    g_object_unref(common_invocation_listener);
}

bool InstructionTracerManager::run_attach() {
    gum_interceptor = gum_interceptor_obtain();
    gum_interceptor_begin_transaction(gum_interceptor);
    common_invocation_listener = gum_make_call_listener(
        hook_common_enter, hook_common_leave, this, NULL);
    auto ret = gum_interceptor_attach(gum_interceptor,
        (gpointer)target_trace_address,
        common_invocation_listener, nullptr, GUM_ATTACH_FLAGS_UNIGNORABLE);
    gum_interceptor_end_transaction(gum_interceptor);

    if (ret == GUM_ATTACH_OK) {
        LOGI("Interceptor attached at 0x%lx", (unsigned long)target_trace_address);
    } else {
        LOGE("Interceptor attach failed: %d", ret);
    }
    return ret == GUM_ATTACH_OK;
}

GumInvocationListener* InstructionTracerManager::get_common_invocation_listener() const {
    return common_invocation_listener;
}

GumInterceptor* InstructionTracerManager::get_gum_interceptor() const {
    return gum_interceptor;
}

LoggerManager* InstructionTracerManager::get_logger_manager() const {
    return logger.get();
}

void InstructionTracerManager::set_trace_tid(uint64_t trace_tid) {
    this->trace_tid = trace_tid;
}

uint64_t InstructionTracerManager::get_trace_tid() const {
    return this->trace_tid;
}

const std::string& InstructionTracerManager::get_module_name() const {
    return this->module_name;
}

void InstructionTracerManager::follow() {
    gum_stalker_follow_me(m_stalker, m_transformer, nullptr);
}

void InstructionTracerManager::follow(size_t thread_id) {
    gum_stalker_follow(m_stalker, thread_id, m_transformer, nullptr);
}

void InstructionTracerManager::unfollow() {
    gum_stalker_unfollow_me(m_stalker);
}

void InstructionTracerManager::unfollow(size_t thread_id) {
    gum_stalker_unfollow(m_stalker, thread_id);
}

bool InstructionTracerManager::is_address_in_module_range(uintptr_t addr) const {
    return addr >= this->module_range.base && addr <= this->module_range.end;
}

bool InstructionTracerManager::is_address_in_other_module_range(uintptr_t addr) const {
    for (const auto& [name, range] : trace_other_modules_range) {
        if (addr > range.first && addr < range.second) {
            return true;
        }
    }
    return false;
}

bool InstructionTracerManager::add_trace_other_module_entry(const std::string& name, bool status) {
    if (trace_other_modules.find(name) != trace_other_modules.end()) {
        return false;
    }
    auto result = trace_other_modules.emplace(name, status);
    return result.second;
}

bool InstructionTracerManager::add_trace_other_module_range_entry(
    const std::string& name, std::pair<size_t, size_t> range) {
    if (trace_other_modules_range.find(name) != trace_other_modules_range.end()) {
        return false;
    }
    auto result = trace_other_modules_range.emplace(name, std::move(range));
    return result.second;
}

std::map<std::string, bool>& InstructionTracerManager::get_trace_other_modules() {
    return trace_other_modules;
}

std::map<std::string, std::pair<size_t, size_t>>& InstructionTracerManager::get_trace_other_modules_range() {
    return trace_other_modules_range;
}

module_range_t InstructionTracerManager::get_module_range() const {
    return this->module_range;
}

void InstructionTracerManager::set_stubs_range(std::pair<size_t, size_t> range) {
    stubs_range = range;
}

std::pair<size_t, size_t> InstructionTracerManager::get_stubs_range() const {
    return this->stubs_range;
}

void InstructionTracerManager::set_stub_helper_range(std::pair<size_t, size_t> range) {
    stub_helper_range = range;
}

std::pair<size_t, size_t> InstructionTracerManager::get_stub_helper_range() const {
    return this->stub_helper_range;
}

// ==================== 智能跨模块追踪 ====================

bool InstructionTracerManager::is_system_library(const char* path) {
    if (path == nullptr) return true;

    static const char* system_prefixes[] = {
        "/usr/lib/",
        "/System/Library/",
        "/Developer/",
        "/usr/share/",
        nullptr
    };

    for (int i = 0; system_prefixes[i] != nullptr; i++) {
        if (strncmp(path, system_prefixes[i], strlen(system_prefixes[i])) == 0) {
            return true;
        }
    }
    return false;
}

void InstructionTracerManager::add_exclude_module(const std::string& name) {
    exclude_modules.insert(name);
    LOGI("Added exclude module: %s", name.c_str());
}

void InstructionTracerManager::add_include_module(const std::string& name) {
    include_modules.insert(name);
    LOGI("Added include module: %s", name.c_str());
}

// 模块名匹配: 支持文件名精确匹配 + 路径子串匹配
// 例如用户配置 "AnalyticsSDK" 能匹配:
//   /path/to/AnalyticsSDK.framework/AnalyticsSDK
//   /path/to/libAnalyticsSDK.dylib
static bool match_module_in_set(const std::set<std::string>& module_set,
                                 const std::string& mod_name,
                                 const char* module_path) {
    for (const auto& pattern : module_set) {
        // 精确匹配文件名
        if (mod_name == pattern) return true;
        // 子串匹配完整路径
        if (module_path && strstr(module_path, pattern.c_str()) != nullptr) return true;
        // 子串匹配文件名
        if (mod_name.find(pattern) != std::string::npos) return true;
    }
    return false;
}

bool InstructionTracerManager::should_trace_address(uintptr_t addr) {
    // 1. 快速路径: 主模块范围内 → 追踪
    if (is_address_in_module_range(addr)) {
        return true;
    }

    // 2. 查范围缓存 (O(log n), 无 dladdr 调用)
    auto* cached = find_module_for_address(addr);
    if (cached) {
        return cached->should_trace;
    }

    // 3. 缓存未命中 → 调 dladdr 获取模块信息
    Dl_info dl_info;
    if (!dladdr((void*)addr, &dl_info) || dl_info.dli_fbase == nullptr) {
        return false;
    }

    uintptr_t module_base = (uintptr_t)dl_info.dli_fbase;

    // 4. 可能同一模块的不同地址先后触发（base 已缓存但地址不在范围内的罕见情况）
    auto cache_it = module_trace_cache.find(module_base);
    if (cache_it != module_trace_cache.end()) {
        return cache_it->second.should_trace;
    }

    // 5. 全新模块 → 判断是否追踪
    const char* module_path = dl_info.dli_fname;
    std::string mod_name;
    if (module_path) {
        const char* last_slash = strrchr(module_path, '/');
        mod_name = last_slash ? (last_slash + 1) : module_path;
    }

    bool trace = false;

    if (self_module_base != 0 && module_base == self_module_base) {
        // 跳过自身
        trace = false;
    } else if (match_module_in_set(exclude_modules, mod_name, module_path)) {
        LOGI("Module excluded: %s (base=0x%lx)", mod_name.c_str(), (unsigned long)module_base);
        trace = false;
    } else if (match_module_in_set(include_modules, mod_name, module_path)) {
        LOGI("Module force-included: %s (base=0x%lx)", mod_name.c_str(), (unsigned long)module_base);
        trace = true;
    } else if (is_system_library(module_path)) {
        trace = false;
    } else {
        LOGI("Auto-tracing app module: %s (base=0x%lx path=%s)",
             mod_name.c_str(), (unsigned long)module_base, module_path);
        trace = true;
    }

    // 6. 获取模块范围并缓存（只在首次发现时调一次 gum API）
    uintptr_t module_end = module_base + 0x10000;  // 保守 fallback
    GumModule* gum_mod = gum_process_find_module_by_name(mod_name.c_str());
    if (gum_mod) {
        const GumMemoryRange* range = gum_module_get_range(gum_mod);
        module_end = range->base_address + range->size;
        g_object_unref(gum_mod);
    }

    module_trace_cache[module_base] = {module_base, module_end, mod_name, trace};
    return trace;
}

const InstructionTracerManager::CachedModuleInfo*
InstructionTracerManager::find_module_for_address(uintptr_t addr) {
    if (module_trace_cache.empty()) return nullptr;

    // upper_bound 找第一个 base > addr 的条目，往前退一步就是 base <= addr 的
    auto it = module_trace_cache.upper_bound(addr);
    if (it == module_trace_cache.begin()) return nullptr;

    --it;
    if (addr >= it->second.base && addr < it->second.end) {
        return &it->second;
    }
    return nullptr;
}

uintptr_t InstructionTracerManager::get_module_base_for_address(uintptr_t addr) {
    // 主模块（最常见）
    if (is_address_in_module_range(addr)) {
        return module_range.base;
    }

    // 范围缓存查找（O(log n)）
    auto* cached = find_module_for_address(addr);
    if (cached) {
        return cached->base;
    }

    // Fallback: dladdr（仅用于未缓存的跳转目标等罕见场景）
    Dl_info dl_info;
    if (dladdr((void*)addr, &dl_info) && dl_info.dli_fbase != nullptr) {
        return (uintptr_t)dl_info.dli_fbase;
    }

    return 0;
}
