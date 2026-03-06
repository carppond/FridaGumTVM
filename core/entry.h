#ifndef GUMTVM_ENTRY_H
#define GUMTVM_ENTRY_H

#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

// 导出的追踪入口函数
__attribute__((visibility("default")))
void gum_trace(const char* module_name, uintptr_t offset, const char* trace_file_name);

// 排除指定模块（不追踪该模块内部指令）
__attribute__((visibility("default")))
void gum_trace_exclude_module(const char* module_name);

// 强制追踪指定模块（即使是系统库也追踪）
__attribute__((visibility("default")))
void gum_trace_include_module(const char* module_name);

#ifdef __cplusplus
}
#endif

#endif // GUMTVM_ENTRY_H
