#include "instruction_tracer_manager.h"

#include <dlfcn.h>
#include <cassert>

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
