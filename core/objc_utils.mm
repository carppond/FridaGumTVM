#include "objc_utils.h"
#include "common.h"
#include <dlfcn.h>
#include <objc/runtime.h>
#include <objc/message.h>

std::string ObjCUtils::resolve_objc_method(uintptr_t address) {
    // 使用 dladdr 获取符号信息
    Dl_info info;
    if (!dladdr((void*)address, &info) || info.dli_sname == nullptr) {
        return "";
    }

    // ObjC 方法符号格式: +[ClassName methodName] 或 -[ClassName methodName]
    std::string sym_name(info.dli_sname);
    if (sym_name.length() > 2 &&
        (sym_name[0] == '+' || sym_name[0] == '-') &&
        sym_name[1] == '[') {
        return sym_name;
    }

    return sym_name;
}

std::string ObjCUtils::get_class_name(uintptr_t address) {
    if (address == 0) return "";

    // 尝试将地址作为 ObjC 对象获取类名
    // 注意: 这在不安全的地址上可能崩溃，需要先验证地址有效性
    @try {
        id obj = (__bridge id)(void*)address;
        Class cls = object_getClass(obj);
        if (cls != nil) {
            const char* name = class_getName(cls);
            if (name != nullptr) {
                return std::string(name);
            }
        }
    } @catch (...) {
        // 地址不是有效的 ObjC 对象
    }

    return "";
}
