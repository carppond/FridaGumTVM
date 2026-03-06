#ifndef GUMTVM_INSTRUCTION_TRACER_MANAGER_H
#define GUMTVM_INSTRUCTION_TRACER_MANAGER_H

#include <frida-gum.h>
#include <fstream>
#include <map>
#include <set>
#include <string>
#include "common.h"
#include "logger_manager.h"

struct _GumStalker;
typedef _GumStalker GumStalker;
struct _GumStalkerTransformer;
typedef _GumStalkerTransformer GumStalkerTransformer;

struct REG_LIST {
    int num = 0;
    arm64_reg regs[31] = {};
};

struct RegisterCounter {
    std::map<std::string, uint64_t> reg_counters;
    uint64_t global_counter = 0;

    uint64_t get_next_id(const std::string& reg_name) {
        return ++global_counter;
    }

    void reset() {
        reg_counters.clear();
        global_counter = 0;
    }
};

struct MemoryAddressCounter {
    uint64_t global_counter = 0;

    uint64_t get_next_id() {
        return ++global_counter;
    }

    void reset() {
        global_counter = 0;
    }
};

class InstructionTracerManager {
public:
    static InstructionTracerManager* get_instance();
    explicit InstructionTracerManager();
    ~InstructionTracerManager();

    [[nodiscard]] bool init(std::string module_name, uintptr_t offset);
    void follow();
    void follow(size_t thread_id);
    void unfollow();
    void unfollow(size_t thread_id);

    [[nodiscard]] bool is_address_in_module_range(uintptr_t addr) const;
    bool is_address_in_other_module_range(uintptr_t addr) const;
    bool add_trace_other_module_entry(const std::string& name, bool status);
    bool add_trace_other_module_range_entry(const std::string& name, std::pair<size_t, size_t> range);
    std::map<std::string, bool>& get_trace_other_modules();
    std::map<std::string, std::pair<size_t, size_t>>& get_trace_other_modules_range();

    // 智能跨模块追踪
    struct CachedModuleInfo {
        uintptr_t base;
        uintptr_t end;
        std::string name;
        bool should_trace;
    };

    bool should_trace_address(uintptr_t addr);
    void add_exclude_module(const std::string& name);
    void add_include_module(const std::string& name);
    static bool is_system_library(const char* path);
    // 通过范围缓存查找模块信息（O(log n)，无 dladdr）
    const CachedModuleInfo* find_module_for_address(uintptr_t addr);
    // 获取模块基址（优先缓存，fallback dladdr）
    uintptr_t get_module_base_for_address(uintptr_t addr);

    [[nodiscard]] module_range_t get_module_range() const;
    void set_stubs_range(std::pair<size_t, size_t> range);
    [[nodiscard]] std::pair<size_t, size_t> get_stubs_range() const;
    void set_stub_helper_range(std::pair<size_t, size_t> range);
    [[nodiscard]] std::pair<size_t, size_t> get_stub_helper_range() const;

    bool run_attach();
    [[nodiscard]] GumInvocationListener* get_common_invocation_listener() const;
    [[nodiscard]] GumInterceptor* get_gum_interceptor() const;
    [[nodiscard]] LoggerManager* get_logger_manager() const;

    void set_trace_tid(uint64_t trace_tid);
    [[nodiscard]] uint64_t get_trace_tid() const;

    // 获取模块名
    [[nodiscard]] const std::string& get_module_name() const;

    // write reg list
    REG_LIST write_reg_list;
    // 下一条 br 指令是 stub jmp 指令
    bool is_stub_jmp;
    // 寄存器计数器
    RegisterCounter reg_counter;
    // 模块切换追踪: 上一条指令所在模块基址
    uintptr_t last_module_base = 0;
    // 内存地址计数器
    MemoryAddressCounter mem_counter;

private:
    GumStalker* m_stalker;
    GumStalkerTransformer* m_transformer;
    GumEventSink* m_sink;
    GumInterceptor* gum_interceptor;
    GumInvocationListener* common_invocation_listener;
    std::unique_ptr<LoggerManager> logger;

    uintptr_t target_trace_address = 0;
    uint64_t trace_tid;
    std::string module_name;
    std::string symbol_name;
    module_range_t module_range;
    // iOS: __stubs 和 __stub_helper 范围（替代 Android 的 PLT）
    std::pair<size_t, size_t> stubs_range;
    std::pair<size_t, size_t> stub_helper_range;
    // 其他需要追踪的模块（手动添加）
    std::map<std::string, bool> trace_other_modules;
    std::map<std::string, std::pair<size_t, size_t>> trace_other_modules_range;

    // 智能跨模块追踪
    std::set<std::string> exclude_modules;   // 排除列表
    std::set<std::string> include_modules;   // 强制追踪列表（系统库）
    // 缓存: 模块基址 → 模块信息（含范围，用于 O(log n) 地址查找）
    std::map<uintptr_t, CachedModuleInfo> module_trace_cache;
    uintptr_t self_module_base = 0;  // libgumTVM.dylib 自身基址
};

#endif // GUMTVM_INSTRUCTION_TRACER_MANAGER_H
