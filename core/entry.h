#ifndef GUMTVM_ENTRY_H
#define GUMTVM_ENTRY_H

#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

// 导出的追踪入口函数，可从外部调用
__attribute__((visibility("default")))
void gum_trace(const char* module_name, uintptr_t offset, const char* trace_file_name);

#ifdef __cplusplus
}
#endif

#endif // GUMTVM_ENTRY_H
