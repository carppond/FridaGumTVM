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

std::string ObjCUtils::resolve_msg_send(uintptr_t self_ptr, uintptr_t sel_ptr) {
    if (self_ptr == 0 || sel_ptr == 0) return "";

    @try {
        // SEL 在 arm64 上就是 const char*
        const char* sel_name = (const char*)sel_ptr;
        if (sel_name == nullptr || sel_name[0] == '\0') return "";

        // 从 x0 获取类信息
        id obj = (__bridge id)(void*)self_ptr;
        Class cls = object_getClass(obj);
        if (cls == nil) return "";

        const char* class_name = class_getName(cls);
        if (class_name == nullptr) return "";

        // metaclass → 类方法 (+), 否则实例方法 (-)
        bool is_class_method = class_isMetaClass(cls);

        std::string result;
        result.reserve(128);
        result += is_class_method ? "+[" : "-[";
        result += class_name;
        result += " ";
        result += sel_name;
        result += "]";
        return result;
    } @catch (...) {
        return "";
    }
}
